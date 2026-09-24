#!/usr/bin/env bats
# End-to-end test on the wire. Builds a small network out of namespaces and
# drives the real scripts in the "server" namespace, then checks what
# packets can actually get through:
#
#   cli1 (alice) 192.0.2.2 ----- 192.0.2.1    srv    10.0.1.1 ----- 10.0.1.10 svc
#   cli2 (bob) 198.51.100.2 -- 198.51.100.1   (VPN)  203.0.113.1 -- 203.0.113.2 wan
#
# svc listens on tcp 443 (allowed service) and tcp 22 (not allowed); srv
# listens on 10.8.0.1:8080 (not in WG_INPUT_PORTS) and *:22 (its SSH).
# WireGuard runs in userspace (wireguard-go), so no kernel module is needed.
# The tests depend on each other and run in file order.
#
# Needs root, iproute2 with netns support, /dev/net/tun, wireguard-go,
# wireguard-tools, nft, python3, curl, argon2, jq, yq. Skipped otherwise.

bats_require_minimum_version 1.5.0
load test_helper

setup_file() {
    [[ "$(id -u)" == 0 ]] || skip "e2e needs root"
    local c
    for c in ip nft wg wg-quick wireguard-go python3 curl jq yq argon2 flock timeout; do
        command -v "$c" >/dev/null 2>&1 || skip "e2e needs $c"
    done
    [[ -c /dev/net/tun ]] || skip "e2e needs /dev/net/tun"

    local id
    id="$(printf '%04x%02x' "$((RANDOM))" "$(($$ % 256))")"
    export E2E_ID="$id"
    export NS_SRV="ztvpn-e2e-$id-srv" NS_CLI1="ztvpn-e2e-$id-cli1" NS_CLI2="ztvpn-e2e-$id-cli2"
    export NS_SVC="ztvpn-e2e-$id-svc" NS_WAN="ztvpn-e2e-$id-wan"
    # WireGuard interface names are global (wireguard-go's UAPI socket lives
    # in /var/run/wireguard), so they carry the run id too.
    export WG_IF_SRV="zs$id" WG_IF_CLI1="za$id" WG_IF_CLI2="zb$id"
    # Written first so teardown_file cleans up even if setup fails halfway.
    printf '%s\n' "$NS_SRV" "$NS_CLI1" "$NS_CLI2" "$NS_SVC" "$NS_WAN" >"$BATS_FILE_TMPDIR/netns"

    # Probe: namespaces work and wireguard-go can create a tun device in one.
    if ! ip netns add "$NS_SRV" 2>/dev/null; then
        skip "cannot create network namespaces"
    fi
    if ! WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD=1 ip netns exec "$NS_SRV" wireguard-go "zp$id" >/dev/null 2>&1 ||
        ! ip -n "$NS_SRV" link show "zp$id" >/dev/null 2>&1; then
        e2e_cleanup
        skip "wireguard-go cannot create a tun device"
    fi
    ip -n "$NS_SRV" link del "zp$id"
    rm -f "/var/run/wireguard/zp$id.sock"

    e2e_helpers
    e2e_topology

    # Sandbox for the scripts (same layout as ztvpn_sandbox, per file).
    local t="$BATS_FILE_TMPDIR/sb"
    export ZTVPN_ETC="$t/etc" ZTVPN_CONFIG="$t/etc/ztvpn.conf" ZTVPN_HOME="$t/opt"
    export ZTVPN_STATE_DIR="$t/state" ZTVPN_LOG_DIR="$t/log" ZTVPN_BACKUP_DIR="$t/backup"
    export WG_DIR="$t/wireguard" NO_COLOR=1
    export ZTVPN_SYSCTL_FILE="$t/sysctl.d/99-ztvpn.conf" SYSTEMD_UNIT_DIR="$t/systemd"
    export NFT_RULES_FILE="$t/etc/nftables.d/ztvpn.nft" NFTABLES_CONF="$t/etc/nftables.conf"
    export WG_INTERFACE="$WG_IF_SRV" EXTERNAL_INTERFACE="s1$id" VPN_ENDPOINT=192.0.2.1
    export SERVICES_SUBNET=10.0.1.0/24 ADMIN_ALLOWLIST=""
    unset SSH_CONNECTION SSH_CLIENT FULL_TUNNEL WG_INPUT_PORTS SERVICES_PORTS PUBLIC_TCP_PORTS \
        SSH_PORT SERVICES_NAT CLIENT_ALLOWED_IPS CLIENT_DNS VPN_SUBNET VPN_SERVER_IP WG_PORT WG_CONF \
        AUTHELIA_BACKEND AUTHELIA_LOG_FILE AUTHELIA_CONTAINER
    mkdir -p "$ZTVPN_ETC" "$ZTVPN_HOME" "$ZTVPN_STATE_DIR" "$WG_DIR"

    # systemd and Docker do not exist here; sysctl is set per namespace below.
    export STUB_BIN="$BATS_FILE_TMPDIR/bin"
    mkdir -p "$STUB_BIN"
    for c in systemctl sysctl; do printf '#!/bin/sh\nexit 0\n' >"$STUB_BIN/$c"; done
    printf '#!/bin/sh\necho "docker: not available" >&2\nexit 1\n' >"$STUB_BIN/docker"
    chmod +x "$STUB_BIN"/*

    export WG_QUICK_USERSPACE_IMPLEMENTATION=wireguard-go WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD=1
    export WG_CONF="$WG_DIR/$WG_IF_SRV.conf" CLIENTS="$BATS_FILE_TMPDIR/clients"
    mkdir -p "$CLIENTS"
}

teardown_file() {
    e2e_cleanup
}

# Kills everything running in the namespaces (wireguard-go, listeners) and
# deletes them. Safe to call more than once.
e2e_cleanup() {
    local ns pids id="${E2E_ID:-}"
    [[ -f "$BATS_FILE_TMPDIR/netns" ]] || return 0
    while IFS= read -r ns; do
        [[ -n "$ns" ]] || continue
        pids="$(ip netns pids "$ns" 2>/dev/null)" || continue
        # shellcheck disable=SC2086
        [[ -n "$pids" ]] && kill -9 $pids 2>/dev/null
        ip netns del "$ns" 2>/dev/null || true
    done <"$BATS_FILE_TMPDIR/netns"
    if [[ -n "$id" ]]; then
        rm -f "/var/run/wireguard/zs$id.sock" "/var/run/wireguard/za$id.sock" \
            "/var/run/wireguard/zb$id.sock" "/var/run/wireguard/zp$id.sock"
    fi
    return 0
}

e2e_topology() {
    local id="$E2E_ID" ns
    for ns in "$NS_CLI1" "$NS_CLI2" "$NS_SVC" "$NS_WAN"; do ip netns add "$ns"; done
    for ns in "$NS_SRV" "$NS_CLI1" "$NS_CLI2" "$NS_SVC" "$NS_WAN"; do ip -n "$ns" link set lo up; done
    # veth pairs: srv side "sX<id>", far side "cX<id>"
    local pair
    for pair in "1 $NS_CLI1 192.0.2.1/30 192.0.2.2/30" "2 $NS_CLI2 198.51.100.1/30 198.51.100.2/30" \
        "v $NS_SVC 10.0.1.1/24 10.0.1.10/24" "w $NS_WAN 203.0.113.1/30 203.0.113.2/30"; do
        # shellcheck disable=SC2086
        set -- $pair
        ip link add "s$1$id" netns "$NS_SRV" type veth peer name "c$1$id" netns "$2"
        ip -n "$NS_SRV" addr add "$3" dev "s$1$id"
        ip -n "$2" addr add "$4" dev "c$1$id"
        ip -n "$NS_SRV" link set "s$1$id" up
        ip -n "$2" link set "c$1$id" up
    done
    ip -n "$NS_SVC" route add default via 10.0.1.1
    ip -n "$NS_WAN" route add default via 203.0.113.1
    # Forwarding is per namespace; wireguard-setup.sh only writes the drop-in.
    ip netns exec "$NS_SRV" sh -c 'echo 1 >/proc/sys/net/ipv4/ip_forward'

    # Services network: 443 is an allowed service port, 22 is not.
    e2e_listen "$NS_SVC" 10.0.1.10 443
    e2e_listen "$NS_SVC" 10.0.1.10 22
    # "Internet" host behind srv, and srv's own SSH on every address.
    e2e_listen "$NS_WAN" 203.0.113.2 80
    e2e_listen "$NS_SRV" 0.0.0.0 22
}

# e2e_listen <ns> <addr> <port>: minimal HTTP listener, detached, killed
# with the namespace. (python -m http.server does a reverse DNS lookup
# before listen(), which stalls in a namespace without a resolver.)
e2e_listen() {
    ip netns exec "$1" setsid python3 "$BATS_FILE_TMPDIR/listen.py" "$2" "$3" </dev/null >/dev/null 2>&1 &
    wait_until 5 tcp_ok "$1" "$2" "$3"
}

# Python TCP listener and ICMP echo (no ping binary in minimal images).
e2e_helpers() {
    cat >"$BATS_FILE_TMPDIR/listen.py" <<'EOF'
import socket, sys

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((sys.argv[1], int(sys.argv[2])))
s.listen(16)
while True:
    c, _ = s.accept()
    try:
        c.settimeout(2)
        c.recv(4096)
        c.sendall(b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\ne2e-service-ok\n")
    except OSError:
        pass
    finally:
        c.close()
EOF
    cat >"$BATS_FILE_TMPDIR/icmp_ping.py" <<'EOF'
import os, select, socket, struct, sys, time

def csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF

dst, timeout = sys.argv[1], float(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
ident = (os.getpid() ^ int(time.time() * 1000)) & 0xFFFF
deadline, seq = time.time() + timeout, 0
while time.time() < deadline:
    seq += 1
    hdr = struct.pack("!BBHHH", 8, 0, 0, ident, seq)
    try:
        s.sendto(struct.pack("!BBHHH", 8, 0, csum(hdr + b"e2e"), ident, seq) + b"e2e", (dst, 0))
    except OSError:
        time.sleep(0.5)
        continue
    end = min(deadline, time.time() + 0.5)
    while time.time() < end:
        if not select.select([s], [], [], max(0, end - time.time()))[0]:
            break
        data, addr = s.recvfrom(1500)
        ihl = (data[0] & 0x0F) * 4
        t, _, _, rid, _ = struct.unpack("!BBHHH", data[ihl:ihl + 8])
        if t == 0 and rid == ident and addr[0] == dst:
            sys.exit(0)
sys.exit(1)
EOF
}

# --------------------------------------------------------------------------
# Helpers used by the tests
# --------------------------------------------------------------------------

# Runs a repo script (or any command) in the server namespace with stubs.
srv() { ip netns exec "$NS_SRV" env PATH="$STUB_BIN:$PATH" "$@"; }
script() { local s="$1"; shift; srv "$REPO_ROOT/scripts/$s" "$@"; }

# ping_ok <ns> <ip> [seconds]
ping_ok() { ip netns exec "$1" python3 "$BATS_FILE_TMPDIR/icmp_ping.py" "$2" "${3:-2}"; }
# tcp_ok <ns> <ip> <port>: TCP connect succeeds within 3s
tcp_ok() { ip netns exec "$1" timeout 3 bash -c 'exec 3<>"/dev/tcp/$0/$1"' "$2" "$3" 2>/dev/null; }
# https-port service check: the actual service content comes back
svc_ok() {
    [[ "$(ip netns exec "$1" curl --noproxy '*' -fsS --max-time 3 "http://10.0.1.10:443/" 2>/dev/null)" == e2e-service-ok ]]
}

# wait_until <seconds> <command...>
wait_until() {
    local end=$((SECONDS + $1))
    shift
    until "$@"; do
        ((SECONDS < end)) || return 1
        sleep 1
    done
}

# Brings a client up from the config add-user.sh produced.
# client_up <ns> <ifname> <client.conf> [endpoint]
client_up() {
    local conf="$CLIENTS/$2.conf"
    if [[ -n "${4:-}" ]]; then
        sed "s/^Endpoint = .*/Endpoint = $4/" "$3" >"$conf"
    else
        cp "$3" "$conf"
    fi
    chmod 600 "$conf"
    ip netns exec "$1" wg-quick up "$conf"
}

client_down() { ip netns exec "$1" wg-quick down "$CLIENTS/$2.conf"; }

server_peers() { srv wg show "$WG_IF_SRV" peers; }
handshake_of() { srv wg show "$WG_IF_SRV" latest-handshakes | awk -v k="$1" '$1 == k { print $2 }'; }
alice_pub() { cat "$BATS_FILE_TMPDIR/alice.pub"; }
bob_pub() { cat "$BATS_FILE_TMPDIR/bob.pub"; }
in_set() { srv nft -j list set inet ztvpn "$1" | jq -e --arg ip "$2" '[.nftables[].set? | select(.) | .elem // [] | .[] | if type == "object" then .elem.val else . end] | index($ip) != null' >/dev/null; }

# --------------------------------------------------------------------------
# Bring-up with the real scripts
# --------------------------------------------------------------------------

@test "e2e 1: wireguard-setup.sh writes the server config, wg-quick brings it up (userspace)" {
    run script setup/wireguard-setup.sh --no-start
    [ "$status" -eq 0 ]
    [ -f "$WG_CONF" ]
    [ "$(stat -c %a "$WG_CONF")" = 600 ]
    grep -qx 'Address = 10.8.0.1/24' "$WG_CONF"
    run ip netns exec "$NS_SRV" wg-quick up "$WG_CONF"
    [ "$status" -eq 0 ]
    ip -n "$NS_SRV" -4 addr show dev "$WG_IF_SRV" | grep -q 'inet 10.8.0.1/24'
    [ "$(srv wg show "$WG_IF_SRV" listen-port)" = 51820 ]
    [ "$(ip netns exec "$NS_SRV" cat /proc/sys/net/ipv4/ip_forward)" = 1 ]
    # Listener on the tunnel address, which only exists now.
    e2e_listen "$NS_SRV" 10.8.0.1 8080
}

@test "e2e 2: firewall-setup.sh --apply loads table inet ztvpn in the server namespace" {
    run script setup/firewall-setup.sh --apply
    [ "$status" -eq 0 ]
    srv nft list table inet ztvpn >/dev/null
    srv nft list chain inet ztvpn input | grep -q 'policy drop'
    srv nft list chain inet ztvpn wg_forward | grep -q 'oifname "'"$WG_IF_SRV"'" drop'
    [ -f "$NFT_RULES_FILE" ]
    # Nothing leaked into the namespace this test runs in.
    ! nft list table inet ztvpn 2>/dev/null | grep -q "$WG_IF_SRV" || false
}

@test "e2e 3: add-user.sh creates alice and bob; their generated configs connect" {
    run script management/add-user.sh alice alice@example.com
    [ "$status" -eq 0 ]
    grep -qx 'ip=10.8.0.2' <<<"$output"
    run script management/add-user.sh bob bob@example.com
    [ "$status" -eq 0 ]
    grep -qx 'ip=10.8.0.3' <<<"$output"

    local cdir="$ZTVPN_HOME/wireguard/clients"
    cp "$cdir/alice/public.key" "$BATS_FILE_TMPDIR/alice.pub"
    cp "$cdir/bob/public.key" "$BATS_FILE_TMPDIR/bob.pub"
    cp "$cdir/alice/alice.conf" "$BATS_FILE_TMPDIR/alice.conf"
    # The running interface got both peers through wg syncconf.
    server_peers | grep -qx "$(alice_pub)"
    server_peers | grep -qx "$(bob_pub)"

    grep -qx 'Endpoint = 192.0.2.1:51820' "$cdir/alice/alice.conf"
    run client_up "$NS_CLI1" "$WG_IF_CLI1" "$cdir/alice/alice.conf"
    [ "$status" -eq 0 ]
    # bob reaches the server over his own uplink
    run client_up "$NS_CLI2" "$WG_IF_CLI2" "$cdir/bob/bob.conf" 198.51.100.1:51820
    [ "$status" -eq 0 ]
    [ "$(yq '.users.alice.disabled' "$ZTVPN_HOME/authelia/users_database.yml")" = false ]
}

# --------------------------------------------------------------------------
# The security model on the wire
# --------------------------------------------------------------------------

@test "e2e a: both peers complete a handshake" {
    wait_until 10 ping_ok "$NS_CLI1" 10.8.0.1
    wait_until 10 ping_ok "$NS_CLI2" 10.8.0.1
    [ "$(handshake_of "$(alice_pub)")" -gt 0 ]
    [ "$(handshake_of "$(bob_pub)")" -gt 0 ]
    srv wg show "$WG_IF_SRV" endpoints | grep -q "^$(alice_pub)"$'\t'"192.0.2.2:"
    srv wg show "$WG_IF_SRV" endpoints | grep -q "^$(bob_pub)"$'\t'"198.51.100.2:"
}

@test "e2e b: alice reaches the service on 443, not port 22 on the same host" {
    svc_ok "$NS_CLI1"
    svc_ok "$NS_CLI2"
    # Port 22 is listening (checked from the server) but not allowed from the tunnel.
    tcp_ok "$NS_SRV" 10.0.1.10 22
    ! tcp_ok "$NS_CLI1" 10.0.1.10 22 || false
    ! ping_ok "$NS_CLI1" 10.0.1.10 1 || false
}

@test "e2e c: no client-to-client traffic (alice -> bob's tunnel IP)" {
    e2e_listen "$NS_CLI2" 10.8.0.3 8000
    ! ping_ok "$NS_CLI1" 10.8.0.3 2 || false
    ! tcp_ok "$NS_CLI1" 10.8.0.3 8000 || false
    ! ping_ok "$NS_CLI2" 10.8.0.2 2 || false
}

@test "e2e d: the server accepts ping but no other port from the tunnel" {
    tcp_ok "$NS_SRV" 10.8.0.1 8080
    ping_ok "$NS_CLI1" 10.8.0.1
    ! tcp_ok "$NS_CLI1" 10.8.0.1 8080 || false
    # SSH is open on the uplink (ADMIN_ALLOWLIST empty), not through the tunnel.
    tcp_ok "$NS_CLI1" 192.0.2.1 22
    ! tcp_ok "$NS_CLI1" 10.8.0.1 22 || false
}

@test "e2e e: FULL_TUNNEL=no: a client that routes more through the tunnel gets nothing forwarded" {
    # alice ignores the split-tunnel config and sends underlay/internet
    # destinations into the tunnel. The server must drop them.
    local srvpub
    srvpub="$(srv wg show "$WG_IF_SRV" public-key)"
    ip netns exec "$NS_CLI1" wg set "$WG_IF_CLI1" peer "$srvpub" \
        allowed-ips 10.8.0.0/24,10.0.1.0/24,198.51.100.0/30,203.0.113.0/30
    ip -n "$NS_CLI1" route add 198.51.100.0/30 dev "$WG_IF_CLI1"
    ip -n "$NS_CLI1" route add 203.0.113.0/30 dev "$WG_IF_CLI1"

    ! ping_ok "$NS_CLI1" 203.0.113.2 2 || false
    ! tcp_ok "$NS_CLI1" 203.0.113.2 80 || false
    ! ping_ok "$NS_CLI1" 198.51.100.2 2 || false

    # Control: with one accept rule in wg_forward the same packets do get
    # through, so the drop above really is the firewall's default drop.
    srv nft insert rule inet ztvpn wg_forward ip daddr 203.0.113.2 accept comment '"e2e-control"'
    tcp_ok "$NS_CLI1" 203.0.113.2 80
    local h
    h="$(srv nft -a list chain inet ztvpn wg_forward | awk '/e2e-control/ { print $NF }')"
    srv nft delete rule inet ztvpn wg_forward handle "$h"
    ! tcp_ok "$NS_CLI1" 203.0.113.2 80 || false

    ip -n "$NS_CLI1" route del 198.51.100.0/30 dev "$WG_IF_CLI1"
    ip -n "$NS_CLI1" route del 203.0.113.0/30 dev "$WG_IF_CLI1"
    ip netns exec "$NS_CLI1" wg set "$WG_IF_CLI1" peer "$srvpub" allowed-ips 10.8.0.0/24,10.0.1.0/24
}

@test "e2e f: threat-response compromised-device cuts alice off, bob keeps working, release restores" {
    run --separate-stderr script automation/threat-response.sh --type compromised-device --device alice
    [ "$status" -eq 0 ]
    [[ "$output" =~ ^INC- ]]
    in_set quarantine4 10.8.0.2
    ! server_peers | grep -qx "$(alice_pub)" || false
    ! grep -q '^# BEGIN PEER alice$' "$WG_CONF" || false
    ! svc_ok "$NS_CLI1" || false
    ! ping_ok "$NS_CLI1" 10.8.0.1 2 || false
    svc_ok "$NS_CLI2"

    run script automation/threat-response.sh release --device alice
    [ "$status" -eq 0 ]
    ! in_set quarantine4 10.8.0.2 || false
    server_peers | grep -qx "$(alice_pub)"
    # alice's client notices the dead session and handshakes again (<= ~15s).
    wait_until 40 ping_ok "$NS_CLI1" 10.8.0.1
    svc_ok "$NS_CLI1"
    svc_ok "$NS_CLI2"
}

@test "e2e g: threat-response brute-force blocks alice's uplink address, unblock restores" {
    tcp_ok "$NS_CLI1" 192.0.2.1 22
    run --separate-stderr script automation/threat-response.sh --type brute-force --ip 192.0.2.2 --duration 1m
    [ "$status" -eq 0 ]
    srv nft -j list set inet ztvpn blocklist4 |
        jq -e '[.nftables[].set? | select(.) | .elem[] | .elem | select(.val == "192.0.2.2") | .timeout] == [60]' >/dev/null

    # New connections from the blocked address are dropped.
    ! tcp_ok "$NS_CLI1" 192.0.2.1 22 || false
    ! ping_ok "$NS_CLI1" 192.0.2.1 1 || false
    if command -v conntrack >/dev/null 2>&1; then
        # Its established WireGuard flow was flushed as well.
        ! ping_ok "$NS_CLI1" 10.8.0.1 2 || false
    else
        # Without conntrack the established flow survives; the operator must be told.
        [[ "$stderr" == *"conntrack"* ]]
    fi
    # A fresh WireGuard session (new source port) cannot handshake.
    client_down "$NS_CLI1" "$WG_IF_CLI1"
    client_up "$NS_CLI1" "$WG_IF_CLI1" "$BATS_FILE_TMPDIR/alice.conf"
    ! ping_ok "$NS_CLI1" 10.8.0.1 4 || false
    [ "$(ip netns exec "$NS_CLI1" wg show "$WG_IF_CLI1" latest-handshakes | awk '{ print $2 }')" = 0 ]
    svc_ok "$NS_CLI2"

    run script automation/threat-response.sh unblock --ip 192.0.2.2
    [ "$status" -eq 0 ]
    ! in_set blocklist4 192.0.2.2 || false
    wait_until 20 ping_ok "$NS_CLI1" 10.8.0.1
    svc_ok "$NS_CLI1"
    tcp_ok "$NS_CLI1" 192.0.2.1 22
}

@test "e2e h: revoke-user.sh alice removes the live peer and disables the account" {
    svc_ok "$NS_CLI1"
    run script management/revoke-user.sh alice
    [ "$status" -eq 0 ]
    ! server_peers | grep -qx "$(alice_pub)" || false
    server_peers | grep -qx "$(bob_pub)"
    ! grep -q '^# BEGIN PEER alice$' "$WG_CONF" || false
    ! svc_ok "$NS_CLI1" || false
    ! ping_ok "$NS_CLI1" 10.8.0.1 2 || false
    svc_ok "$NS_CLI2"
    [ "$(yq '.users.alice.disabled' "$ZTVPN_HOME/authelia/users_database.yml")" = true ]
    [ "$(yq '.users.bob.disabled' "$ZTVPN_HOME/authelia/users_database.yml")" = false ]
}

@test "e2e i: security-audit.sh passes every firewall and WireGuard check on the live host" {
    run --separate-stderr script monitoring/security-audit.sh --json
    [ "$status" -eq 0 ]
    local failed
    failed="$(jq -r '.checks[] | select(.id | test("^(FW|WG)-")) | select(.status != "pass") | "\(.id) \(.status) \(.items)"' <<<"$output")"
    [ -z "$failed" ] || { echo "$failed"; false; }
    [ "$(jq '[.checks[] | select(.id | test("^(FW|WG)-"))] | length' <<<"$output")" -eq 8 ]
    [ "$(jq -r '.checks[] | select(.id == "ID-ORPHAN-PEERS") | .status' <<<"$output")" = pass ]
}

@test "e2e j: connection-monitor.sh reads the live wg dump, lists bob, flags an unmanaged peer" {
    run --separate-stderr script monitoring/connection-monitor.sh --once --json
    [ "$status" -eq 0 ]
    jq -e --arg k "$(bob_pub)" '.peers | length == 1 and .[0].name == "bob" and .[0].public_key == $k
        and .[0].ip == "10.8.0.3" and .[0].status == "active" and (.[0].endpoint | startswith("198.51.100.2:"))
        and .[0].rx_bytes > 0' <<<"$output" >/dev/null
    jq -e '.unknown_peers == 0 and .alerts == [] and .managed_peers_not_loaded == []' <<<"$output" >/dev/null

    # A peer added behind the tooling's back is reported.
    local rogue
    rogue="$(wg genkey | wg pubkey)"
    srv wg set "$WG_IF_SRV" peer "$rogue" allowed-ips 10.8.0.200/32
    run --separate-stderr script monitoring/connection-monitor.sh --once --json
    srv wg set "$WG_IF_SRV" peer "$rogue" remove
    [ "$status" -eq 1 ]
    jq -e '.unknown_peers == 1 and (.alerts | any(.source == "unknown-peer"))' <<<"$output" >/dev/null
}
