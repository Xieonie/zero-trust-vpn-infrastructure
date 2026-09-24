#!/usr/bin/env bats
# scripts/setup/firewall-setup.sh: rendering, validation, lockout
# protection and the apply/rollback flow. The live ruleset of the machine
# running the tests is never touched: apply tests use a stub nft, or a real
# nft inside a private network namespace (unshare -n).

load test_helper

FW="$BATS_TEST_DIRNAME/../scripts/setup/firewall-setup.sh"

setup() {
    ztvpn_sandbox
    unset SSH_CONNECTION ADMIN_ALLOWLIST FULL_TUNNEL EXTERNAL_INTERFACE WG_INPUT_PORTS \
        SERVICES_PORTS PUBLIC_TCP_PORTS SSH_PORT SERVICES_NAT
    export NFT_RULES_FILE="$BATS_TEST_TMPDIR/etc/nftables.d/ztvpn.nft"
    export NFTABLES_CONF="$BATS_TEST_TMPDIR/etc/nftables.conf"
    export NFT_LOG="$BATS_TEST_TMPDIR/nft.log"
}

render() {
    "$FW" --print 2>"$BATS_TEST_TMPDIR/stderr"
}

# Prints the body of one chain from a rendered ruleset on stdin.
chain() {
    awk -v c="chain $1 {" '$1 == "chain" && $0 ~ c { on = 1; next } on && /^\t}/ { exit } on { print }'
}

nft_check() {
    [[ "$(id -u)" == 0 ]] || skip "nft -c needs CAP_NET_ADMIN"
    command -v nft >/dev/null || skip "nft not installed"
    nft -c -f "$1"
}

# Stub nft that records its arguments. NFT_STUB_CHECK_RC controls "nft -c".
stub_nft() {
    mkdir -p "$BATS_TEST_TMPDIR/bin"
    cat >"$BATS_TEST_TMPDIR/bin/nft" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$NFT_LOG"
case "$*" in
    "-c -f "*) exit "${NFT_STUB_CHECK_RC:-0}" ;;
    "-f "*) exit 0 ;;
    "list ruleset") echo "table ip docker-stub {}"; exit 0 ;;
    *) exit 1 ;;
esac
EOF
    chmod +x "$BATS_TEST_TMPDIR/bin/nft"
    export PATH="$BATS_TEST_TMPDIR/bin:$PATH"
    : >"$NFT_LOG"
}

need_root() {
    [[ "$(id -u)" == 0 ]] || skip "apply needs root"
}

@test "--print renders a ruleset that nft accepts (defaults)" {
    render >"$BATS_TEST_TMPDIR/r.nft"
    grep -q '^table inet ztvpn {' "$BATS_TEST_TMPDIR/r.nft"
    grep -q '^delete table inet ztvpn$' "$BATS_TEST_TMPDIR/r.nft"
    nft_check "$BATS_TEST_TMPDIR/r.nft"
}

@test "only table inet ztvpn is touched, never the whole ruleset" {
    run render
    [ "$status" -eq 0 ]
    [[ "$output" != *"flush ruleset"* ]]
    [ "$(grep -c '^table ' <<<"$output")" -eq 2 ]
    ! grep -Eq '^table (ip|ip6) ' <<<"$output" || false
}

@test "contract sets exist with the right types and flags" {
    out="$(render)"
    grep -A3 'set blocklist4 {' <<<"$out" | grep -q 'type ipv4_addr'
    grep -A3 'set blocklist4 {' <<<"$out" | grep -q 'flags timeout'
    grep -A3 'set blocklist6 {' <<<"$out" | grep -q 'type ipv6_addr'
    grep -A3 'set blocklist6 {' <<<"$out" | grep -q 'flags timeout'
    grep -A2 'set quarantine4 {' <<<"$out" | grep -q 'type ipv4_addr'
}

@test "input: policy drop, blocklists after lo but before established, IPv4 and IPv6" {
    input="$(render | chain input)"
    grep -q 'policy drop;' <<<"$input"
    lo=$(grep -n 'iif "lo" accept' <<<"$input" | cut -d: -f1)
    est=$(grep -n 'ct state established,related accept' <<<"$input" | cut -d: -f1)
    b4=$(grep -n 'ip saddr @blocklist4 drop' <<<"$input" | cut -d: -f1)
    b6=$(grep -n 'ip6 saddr @blocklist6 drop' <<<"$input" | cut -d: -f1)
    ((lo < b4 && lo < b6 && b4 < est && b6 < est))
    grep -q 'udp dport 51820 accept' <<<"$input"
    grep -q 'nd-neighbor-solicit' <<<"$input"
    grep -q 'packet-too-big' <<<"$input"
    # No public TCP ports by default (the Docker proxy is bound to PROXY_BIND_ADDR)
    ! grep -q 'tcp dport { 80' <<<"$input" || false
    input="$(PUBLIC_TCP_PORTS=80,443 render | chain input)"
    grep -q 'tcp dport { 80, 443 } accept' <<<"$input"
}

@test "state: saved blocklist and quarantine entries are restored, expired ones are not" {
    load_lib
    mkdir -p "$(dirname "$FW_STATE_FILE")" "$QUARANTINE_DIR/mallory"
    now=$(date +%s)
    printf 'blocklist4 203.0.113.7 %s\nblocklist4 203.0.113.8 %s\nblocklist6 2001:db8::1 %s\nquarantine4 10.8.0.9 0\nblocklist4 bogus;x 0\n' \
        $((now + 600)) $((now - 5)) $((now + 60)) >"$FW_STATE_FILE"
    printf '{"ip":"10.8.0.7"}\n' >"$QUARANTINE_DIR/mallory/meta.json"
    run fw_restore_commands
    [ "$status" -eq 0 ]
    [[ "$output" == *"add element inet ztvpn blocklist4 { 203.0.113.7 timeout "* ]]
    [[ "$output" != *"203.0.113.8"* ]]
    [[ "$output" == *"blocklist6 { 2001:db8::1 timeout "* ]]
    [[ "$output" == *"quarantine4 { 10.8.0.9 }"* ]]
    [[ "$output" == *"quarantine4 { 10.8.0.7 }"* ]]
    [[ "$output" != *"bogus"* ]]
}

@test "wg input: IPv6 dropped, only VPN_SERVER_IP:WG_INPUT_PORTS and services, then drop" {
    wgin="$(render | chain wg_input)"
    grep -q 'meta nfproto ipv6 drop' <<<"$wgin"
    [ "$(tail -n1 <<<"$wgin" | tr -d '[:space:]')" = "drop" ]
    ! grep -q 'th dport' <<<"$wgin" || false

    wgin="$(WG_INPUT_PORTS=53 render | chain wg_input)"
    grep -q 'ip daddr 10.8.0.1 meta l4proto { tcp, udp } th dport { 53 } accept' <<<"$wgin"
}

@test "forward: base chain accepts (Docker), wg traffic goes to chains ending in drop, v4+v6" {
    out="$(render)"
    fwd="$(chain forward <<<"$out")"
    grep -q 'policy accept;' <<<"$fwd"
    grep -q 'iifname "wg0" jump wg_forward' <<<"$fwd"
    grep -q 'oifname "wg0" jump wg_forward_out' <<<"$fwd"
    grep -q 'ip saddr @blocklist4 drop' <<<"$fwd"
    grep -q 'ip6 saddr @blocklist6 drop' <<<"$fwd"
    for c in wg_forward wg_forward_out; do
        body="$(chain "$c" <<<"$out")"
        [ "$(tail -n1 <<<"$body" | tr -d '[:space:]')" = "drop" ]
        grep -q 'ip.* @quarantine4 drop' <<<"$body"
    done
    grep -q 'meta nfproto ipv6 drop' <<<"$(chain wg_forward <<<"$out")"
}

@test "FULL_TUNNEL=no: VPN clients reach only the services, no NAT" {
    out="$(render)"
    wgf="$(chain wg_forward <<<"$out")"
    # The only accepts: replies and the services rule.
    run grep 'accept' <<<"$wgf"
    [ "${#lines[@]}" -eq 2 ]
    [[ "${lines[0]}" == *"ct state established,related accept"* ]]
    [[ "${lines[1]}" == *"ct original ip daddr 10.0.1.0/24 ct original proto-dst { 443 } accept"* ]]
    grep -q 'oifname "wg0" drop' <<<"$wgf"
    [[ "$out" != *masquerade* ]]
    [[ "$out" != *"chain postrouting"* ]]
}

@test "FULL_TUNNEL=yes: internet egress and masquerade out of the external interface" {
    out="$(FULL_TUNNEL=yes EXTERNAL_INTERFACE=eth9 render)"
    grep -q 'oifname "eth9" accept' <<<"$(chain wg_forward <<<"$out")"
    grep -q '192.168.0.0/16' <<<"$(chain wg_forward <<<"$out")"
    grep -q 'ip saddr 10.8.0.0/24 oifname "eth9" masquerade' <<<"$out"
    printf '%s\n' "$out" >"$BATS_TEST_TMPDIR/r.nft"
    nft_check "$BATS_TEST_TMPDIR/r.nft"
}

@test "SERVICES_NAT=yes adds only the services masquerade" {
    out="$(SERVICES_NAT=yes EXTERNAL_INTERFACE=eth9 render)"
    grep -q 'ip saddr 10.8.0.0/24 ip daddr 10.0.1.0/24 oifname != "wg0" masquerade' <<<"$out"
    ! grep -q 'oifname "eth9" masquerade' <<<"$out" || false
}

@test "ADMIN_ALLOWLIST restricts SSH to the allowlisted v4/v6 sources" {
    out="$(ADMIN_ALLOWLIST='192.0.2.0/24, 198.51.100.7,2001:db8::/32' SSH_PORT=2222 render)"
    grep -q 'elements = { 192.0.2.0/24, 198.51.100.7 }' <<<"$out"
    grep -q 'elements = { 2001:db8::/32 }' <<<"$out"
    grep -q 'tcp dport 2222 ip saddr @admin4 accept' <<<"$out"
    grep -q 'tcp dport 2222 ip6 saddr @admin6 accept' <<<"$out"
    ! grep -q 'tcp dport 2222 accept' <<<"$out" || false
    grep -q 'tcp dport 2222 ct state new add @ssh_meter4' <<<"$out"
    printf '%s\n' "$out" >"$BATS_TEST_TMPDIR/r.nft"
    nft_check "$BATS_TEST_TMPDIR/r.nft"
}

@test "empty ADMIN_ALLOWLIST opens SSH with a warning" {
    out="$(render)"
    grep -q 'tcp dport 22 accept' <<<"$out"
    grep -q 'ADMIN_ALLOWLIST is empty' "$BATS_TEST_TMPDIR/stderr"
}

@test "values that could inject nft syntax are rejected" {
    run env ADMIN_ALLOWLIST='1.2.3.4 } ; flush ruleset ; {' "$FW" --print
    [ "$status" -ne 0 ]
    [[ "$output" == *"ADMIN_ALLOWLIST: invalid entry"* ]]
    run env WG_INTERFACE='wg0" accept #' "$FW" --print
    [ "$status" -ne 0 ]
    run env SERVICES_PORTS='443,22 accept' "$FW" --print
    [ "$status" -ne 0 ]
    run env FULL_TUNNEL=maybe "$FW" --print
    [ "$status" -ne 0 ]
    run env VPN_SERVER_IP=10.9.0.1 "$FW" --print
    [ "$status" -ne 0 ]
    run env FULL_TUNNEL=yes EXTERNAL_INTERFACE='eth0;x' "$FW" --print
    [ "$status" -ne 0 ]
}

@test "--confirm-timeout without --apply is refused" {
    run "$FW" --print --confirm-timeout 10
    [ "$status" -ne 0 ]
}

@test "apply refuses when the current SSH client is not in ADMIN_ALLOWLIST" {
    need_root
    stub_nft
    run env SSH_CONNECTION="203.0.113.9 50000 198.51.100.1 22" ADMIN_ALLOWLIST=192.0.2.0/24 "$FW" --apply
    [ "$status" -ne 0 ]
    [[ "$output" == *"lock you out"* ]]
    ! grep -q -- '-f' "$NFT_LOG" || false
    [ ! -e "$NFT_RULES_FILE" ]
}

@test "apply refuses when SSH arrives on a port other than SSH_PORT" {
    need_root
    stub_nft
    run env SSH_CONNECTION="192.0.2.5 50000 198.51.100.1 2200" "$FW" --apply
    [ "$status" -ne 0 ]
    [[ "$output" == *"lock you out"* ]]
}

@test "apply refuses SSH over the VPN unless the port is in WG_INPUT_PORTS" {
    need_root
    stub_nft
    run env SSH_CONNECTION="10.8.0.5 50000 10.8.0.1 22" "$FW" --apply </dev/null
    [ "$status" -ne 0 ]
    [[ "$output" == *"WG_INPUT_PORTS"* ]]

    run env SSH_CONNECTION="10.8.0.5 50000 10.8.0.1 22" WG_INPUT_PORTS=22 "$FW" --apply </dev/null
    [ "$status" -eq 0 ]
}

@test "apply with an allowlisted SSH client validates, backs up, applies and persists" {
    need_root
    stub_nft
    run env SSH_CONNECTION="192.0.2.5 50000 198.51.100.1 22" ADMIN_ALLOWLIST=192.0.2.0/24 "$FW" --apply </dev/null
    [ "$status" -eq 0 ]
    grep -q '^-c -f ' "$NFT_LOG"
    grep -q '^list ruleset$' "$NFT_LOG"
    grep -q '^-f .*/apply.nft$' "$NFT_LOG"
    [ -f "$NFT_RULES_FILE" ]
    [ "$(stat -c %a "$NFT_RULES_FILE")" = 600 ]
    grep -q '@admin4' "$NFT_RULES_FILE"
    grep -Fqx "include \"$NFT_RULES_FILE\"" "$NFTABLES_CONF"
    ls "$ZTVPN_BACKUP_DIR"/firewall/ruleset-*.nft

    # Re-running does not add the include twice.
    run env ADMIN_ALLOWLIST=192.0.2.0/24 "$FW" --apply </dev/null
    [ "$status" -eq 0 ]
    [ "$(grep -Fc "include \"$NFT_RULES_FILE\"" "$NFTABLES_CONF")" -eq 1 ]
}

@test "apply keeps an existing nftables.conf and appends the include" {
    need_root
    stub_nft
    mkdir -p "$(dirname "$NFTABLES_CONF")"
    printf '#!/usr/sbin/nft -f\nflush ruleset\ntable inet filter {\n}\n' >"$NFTABLES_CONF"
    run "$FW" --apply </dev/null
    [ "$status" -eq 0 ]
    grep -q '^table inet filter {' "$NFTABLES_CONF"
    grep -Fqx "include \"$NFT_RULES_FILE\"" "$NFTABLES_CONF"
    [[ "$output" == *"flush ruleset"* ]]
}

@test "nothing is applied or persisted when nft -c rejects the ruleset" {
    need_root
    stub_nft
    export NFT_STUB_CHECK_RC=1
    run "$FW" --apply </dev/null
    [ "$status" -ne 0 ]
    ! grep -q '^-f ' "$NFT_LOG" || false
    [ ! -e "$NFT_RULES_FILE" ]
    [ ! -e "$NFTABLES_CONF" ]
}

@test "--confirm-timeout rolls back and persists nothing without confirmation" {
    need_root
    stub_nft
    run "$FW" --apply --confirm-timeout 1 </dev/null
    [ "$status" -ne 0 ]
    [[ "$output" == *"rolled back"* ]]
    grep -q '^-f .*/apply.nft$' "$NFT_LOG"
    grep -q '^-f .*/rollback.nft$' "$NFT_LOG"
    [ ! -e "$NFT_RULES_FILE" ]
    head -n2 "$ZTVPN_STATE_DIR/firewall/rollback.nft" | grep -q '^delete table inet ztvpn$'
}

@test "--confirm-timeout keeps the rules when confirmed on stdin" {
    need_root
    stub_nft
    run bash -c 'echo | "$0" --apply --confirm-timeout 10' "$FW"
    [ "$status" -eq 0 ]
    [[ "$output" == *"Confirmed"* ]]
    ! grep -q 'rollback.nft' "$NFT_LOG" || false
    [ -f "$NFT_RULES_FILE" ]
}

@test "--confirm-timeout keeps the rules when the confirm file is touched" {
    need_root
    stub_nft
    (sleep 2; touch "$ZTVPN_STATE_DIR/firewall/confirm") &
    run "$FW" --apply --confirm-timeout 15 </dev/null
    [ "$status" -eq 0 ]
    ! grep -q 'rollback.nft' "$NFT_LOG" || false
    [ -f "$NFT_RULES_FILE" ]
}

@test "real nft in a private netns: apply, carry over blocklist/quarantine, roll back" {
    need_root
    command -v nft >/dev/null || skip "nft not installed"
    unshare -n true 2>/dev/null || skip "cannot create a network namespace"
    run unshare -n bash -c '
        set -e
        "$1" --apply </dev/null
        nft add element inet ztvpn blocklist4 "{ 203.0.113.7 timeout 1h }"
        nft add element inet ztvpn quarantine4 "{ 10.8.0.5 }"
        SSH_PORT=2222 "$1" --apply </dev/null
        nft list set inet ztvpn blocklist4 | grep -q 203.0.113.7
        nft list set inet ztvpn quarantine4 | grep -q 10.8.0.5
        nft list chain inet ztvpn input | grep -q "tcp dport 2222 accept"
        if SSH_PORT=2200 "$1" --apply --confirm-timeout 1 </dev/null; then exit 1; fi
        nft list chain inet ztvpn input | grep -q "tcp dport 2222 accept"
        ! nft list chain inet ztvpn input | grep -q "dport 2200" || false
        nft list set inet ztvpn quarantine4 | grep -q 10.8.0.5
        echo NETNS-OK
    ' _ "$FW"
    [ "$status" -eq 0 ]
    [[ "$output" == *NETNS-OK* ]]
}

@test "config-examples/firewall/ztvpn.nft.example matches the default rendering" {
    run env -i PATH="$PATH" ZTVPN_CONFIG=/nonexistent NO_COLOR=1 "$FW" --print
    [ "$status" -eq 0 ]
    diff <(printf '%s\n' "$output" | grep -v '^\[WARN\]') "$REPO_ROOT/config-examples/firewall/ztvpn.nft.example"
}

@test "firewall-setup.sh passes shellcheck" {
    command -v shellcheck >/dev/null || skip "shellcheck not installed"
    shellcheck -x -S warning "$FW"
}
