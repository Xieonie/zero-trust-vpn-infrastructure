#!/usr/bin/env bash
# Renders and applies the zero-trust-vpn nftables ruleset.
#
# Everything lives in ONE table, "inet ztvpn" (IPv4 + IPv6). Applying it
# deletes and recreates only that table in a single atomic nft transaction,
# so Docker's and fail2ban's tables are never touched.
#
# Policy (the firewall contract other scripts rely on):
#   input    policy drop. lo, established/related, blocklists, essential
#            ICMP/ICMPv6, udp $WG_PORT, SSH (ADMIN_ALLOWLIST only if set,
#            rate limited), PUBLIC_TCP_PORTS for a host-native reverse proxy.
#            From the WireGuard interface only VPN_SERVER_IP:WG_INPUT_PORTS
#            and SERVICES_SUBNET:SERVICES_PORTS.
#   forward  VPN clients reach SERVICES_SUBNET on SERVICES_PORTS (tcp) and,
#            with FULL_TUNNEL=yes, the internet. No client-to-client, no
#            IPv6, nothing else. Non-WireGuard forwarding (Docker bridges)
#            is left to Docker's own chains.
#   sets     blocklist4/blocklist6 (with timeout), quarantine4.
#   nat      masquerade VPN_SUBNET out of the external interface only when
#            FULL_TUNNEL=yes, and towards SERVICES_SUBNET only when
#            SERVICES_NAT=yes (see --help for why that is off by default).

set -Eeuo pipefail

# shellcheck source=scripts/lib/common.sh
source "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/../lib/common.sh"

# Local config keys (defaults; override in ztvpn.conf or the environment).
SSH_PORT="${SSH_PORT:-22}"
FULL_TUNNEL="${FULL_TUNNEL:-no}"
PUBLIC_TCP_PORTS="${PUBLIC_TCP_PORTS-}"
SERVICES_PORTS="${SERVICES_PORTS:-443}"
WG_INPUT_PORTS="${WG_INPUT_PORTS:-}"
SERVICES_NAT="${SERVICES_NAT:-no}"
NFT_RULES_FILE="${NFT_RULES_FILE:-/etc/nftables.d/ztvpn.nft}"
NFTABLES_CONF="${NFTABLES_CONF:-/etc/nftables.conf}"
FIREWALL_STATE_DIR="${FIREWALL_STATE_DIR:-$ZTVPN_STATE_DIR/firewall}"
LOG_FILE="${LOG_FILE:-$ZTVPN_LOG_DIR/firewall-setup.log}"

[[ "$NFT_TABLE" =~ ^[a-z][a-z0-9_]*$ ]] || die "Invalid NFT_TABLE: $NFT_TABLE"

usage() {
    cat <<EOF
Usage: $(basename "$0") [--print | --apply [--confirm-timeout N] | --restore-state]

Render the nftables ruleset "table inet $NFT_TABLE" from ztvpn.conf.

  --print               Print the ruleset on stdout (default, needs no root)
  --apply               Validate (nft -c), back up the live ruleset, apply the
                        table atomically, write $NFT_RULES_FILE,
                        include it from $NFTABLES_CONF and enable
                        nftables.service. Other tables (Docker, fail2ban)
                        are not touched. Current blocklist/quarantine
                        entries are carried over.
  --confirm-timeout N   With --apply: roll the table back after N seconds
                        unless you confirm by pressing Enter or by running
                        "touch $FIREWALL_STATE_DIR/confirm" (e.g. from a
                        second SSH session). Nothing is persisted before
                        confirmation. Recommended when working over SSH.
  --restore-state       Re-add saved blocklist/quarantine entries (from
                        $FW_STATE_FILE and active quarantine records) to the
                        running table. Runs at boot via
                        ztvpn-firewall-state.service, which --apply installs.
  -h, --help            Show this help

Settings (ztvpn.conf or environment):
  WG_INTERFACE=$WG_INTERFACE WG_PORT=$WG_PORT VPN_SUBNET=$VPN_SUBNET VPN_SERVER_IP=$VPN_SERVER_IP
  SERVICES_SUBNET=$SERVICES_SUBNET SERVICES_PORTS=$SERVICES_PORTS (tcp)
  WG_INPUT_PORTS=${WG_INPUT_PORTS:-<none>} (tcp+udp on VPN_SERVER_IP, e.g. 53 for a tunnel DNS)
  SSH_PORT=$SSH_PORT ADMIN_ALLOWLIST=${ADMIN_ALLOWLIST:-<empty: SSH open to all, rate limited>}
  PUBLIC_TCP_PORTS=${PUBLIC_TCP_PORTS:-<none>} (host-native reverse proxy; Docker-published
    ports are DNATed and handled by Docker's chains instead)
  FULL_TUNNEL=$FULL_TUNNEL (yes: VPN clients may reach the internet, masqueraded
    out of EXTERNAL_INTERFACE=${EXTERNAL_INTERFACE:-<auto>}; private ranges stay blocked)
  SERVICES_NAT=$SERVICES_NAT (yes: masquerade VPN traffic to SERVICES_SUBNET. Leave "no"
    and give remote service hosts a route to VPN_SUBNET via this host instead:
    NAT hides the client address, so Authelia's "vpn" network rules no longer match)
  NFT_RULES_FILE=$NFT_RULES_FILE NFTABLES_CONF=$NFTABLES_CONF

Blocking an address (expires by itself):
  nft add element inet $NFT_TABLE blocklist4 "{ 203.0.113.7 timeout 1h }"
EOF
}

# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------

validate_iface() {
    [[ "$1" =~ ^[A-Za-z0-9_.-]{1,15}$ ]]
}

validate_port() {
    [[ "$1" =~ ^[1-9][0-9]{0,4}$ ]] && (($1 <= 65535))
}

# Minimal IPv6 syntax check; nft -c does the exact parsing later.
validate_ipv6ish() {
    local addr="${1%/*}" bits
    [[ "$addr" == *:* && "$addr" =~ ^[0-9A-Fa-f:.]+$ && ${#addr} -le 45 ]] || return 1
    if [[ "$1" == */* ]]; then
        bits="${1#*/}"
        [[ "$bits" =~ ^[0-9]{1,3}$ ]] && ((bits <= 128)) || return 1
    fi
}

# Prints the ports of a CSV list as "a, b, c", dies on invalid entries.
port_list() {
    local name="$1" csv="$2" p out=()
    while IFS= read -r p; do
        validate_port "$p" || die "$name: invalid port '$p'"
        out+=("$p")
    done < <(split_csv "$csv")
    local IFS=','
    printf '%s' "${out[*]}" | sed 's/,/, /g'
}

ADMIN4=()
ADMIN6=()

validate_settings() {
    validate_iface "$WG_INTERFACE" || die "Invalid WG_INTERFACE: $WG_INTERFACE"
    validate_port "$WG_PORT" || die "Invalid WG_PORT: $WG_PORT"
    validate_port "$SSH_PORT" || die "Invalid SSH_PORT: $SSH_PORT"
    validate_cidr "$VPN_SUBNET" || die "Invalid VPN_SUBNET: $VPN_SUBNET"
    validate_ipv4 "$VPN_SERVER_IP" || die "Invalid VPN_SERVER_IP: $VPN_SERVER_IP"
    ip_in_cidr "$VPN_SERVER_IP" "$VPN_SUBNET" || die "VPN_SERVER_IP $VPN_SERVER_IP is not inside $VPN_SUBNET"
    validate_cidr "$SERVICES_SUBNET" || die "Invalid SERVICES_SUBNET: $SERVICES_SUBNET"
    [[ "$FULL_TUNNEL" == yes || "$FULL_TUNNEL" == no ]] || die "FULL_TUNNEL must be yes or no"
    [[ "$SERVICES_NAT" == yes || "$SERVICES_NAT" == no ]] || die "SERVICES_NAT must be yes or no"
    [[ -n "$SERVICES_PORTS" ]] || die "SERVICES_PORTS must not be empty"
    port_list SERVICES_PORTS "$SERVICES_PORTS" >/dev/null
    port_list PUBLIC_TCP_PORTS "$PUBLIC_TCP_PORTS" >/dev/null
    port_list WG_INPUT_PORTS "$WG_INPUT_PORTS" >/dev/null

    local e
    ADMIN4=()
    ADMIN6=()
    while IFS= read -r e; do
        if validate_ipv4 "$e" || validate_cidr "$e"; then
            ADMIN4+=("$e")
        elif validate_ipv6ish "$e"; then
            ADMIN6+=("$e")
        else
            die "ADMIN_ALLOWLIST: invalid entry '$e'"
        fi
    done < <(split_csv "$ADMIN_ALLOWLIST")

    if [[ "$FULL_TUNNEL" == yes || "$SERVICES_NAT" == yes ]]; then
        EXT_IF="$(detect_external_interface)"
        [[ -n "$EXT_IF" ]] || die "Cannot detect the external interface; set EXTERNAL_INTERFACE"
        validate_iface "$EXT_IF" || die "Invalid EXTERNAL_INTERFACE: $EXT_IF"
    fi
}

# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------

join_set() {
    local IFS=','
    printf '%s' "$*" | sed 's/,/, /g'
}

render_ruleset() {
    local wg="$WG_INTERFACE"
    local svc_ports pub_ports wgin_ports
    svc_ports="$(port_list SERVICES_PORTS "$SERVICES_PORTS")"
    pub_ports="$(port_list PUBLIC_TCP_PORTS "$PUBLIC_TCP_PORTS")"
    wgin_ports="$(port_list WG_INPUT_PORTS "$WG_INPUT_PORTS")"

    cat <<EOF
#!/usr/sbin/nft -f
# Generated by scripts/setup/firewall-setup.sh. Do not edit: change
# ztvpn.conf and re-run "firewall-setup.sh --apply".
#
# Only "table inet $NFT_TABLE" is replaced; Docker and fail2ban keep their
# own tables. The first line makes the delete safe when the table is absent.
table inet $NFT_TABLE
delete table inet $NFT_TABLE

table inet $NFT_TABLE {
	# Addresses blocked by threat-response (entries expire by themselves):
	#   nft add element inet $NFT_TABLE blocklist4 "{ 203.0.113.7 timeout 1h }"
	set blocklist4 {
		type ipv4_addr
		flags timeout
	}

	set blocklist6 {
		type ipv6_addr
		flags timeout
	}

	# VPN client addresses whose input and forwarded traffic is dropped.
	set quarantine4 {
		type ipv4_addr
	}
EOF
    if ((${#ADMIN4[@]})); then
        printf '\n\tset admin4 {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\telements = { %s }\n\t}\n' "$(join_set "${ADMIN4[@]}")"
    fi
    if ((${#ADMIN6[@]})); then
        printf '\n\tset admin6 {\n\t\ttype ipv6_addr\n\t\tflags interval\n\t\telements = { %s }\n\t}\n' "$(join_set "${ADMIN6[@]}")"
    fi
    cat <<EOF

	# Per-source SSH connection rate limiting.
	set ssh_meter4 {
		type ipv4_addr
		size 65535
		flags dynamic,timeout
		timeout 10m
	}

	set ssh_meter6 {
		type ipv6_addr
		size 65535
		flags dynamic,timeout
		timeout 10m
	}

	chain input {
		type filter hook input priority filter; policy drop;

		iif "lo" accept
		# Blocked and quarantined sources are dropped before the
		# established rule, so blocking also cuts connections that are
		# already open (threat-response never blocks ADMIN_ALLOWLIST).
		iifname "$wg" ip saddr @quarantine4 drop
		ip saddr @blocklist4 drop
		ip6 saddr @blocklist6 drop
		ct state established,related accept
		ct state invalid drop

		# Everything arriving through the tunnel is decided in wg_input.
		iifname "$wg" jump wg_input

		# Essential ICMP. Errors belonging to known connections are
		# already accepted as "related" above.
		ip protocol icmp icmp type echo-request limit rate 10/second burst 20 packets accept
		ip6 nexthdr icmpv6 icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem } accept
		ip6 nexthdr icmpv6 icmpv6 type echo-request limit rate 10/second burst 20 packets accept
		ip6 nexthdr icmpv6 icmpv6 type { nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } ip6 hoplimit 255 accept
		ip6 saddr fe80::/10 icmpv6 type { mld-listener-query, mld-listener-report, mld2-listener-report } accept

		# WireGuard
		udp dport $WG_PORT accept

		# SSH
		tcp dport $SSH_PORT ct state new add @ssh_meter4 { ip saddr limit rate over 10/minute burst 10 packets } drop
		tcp dport $SSH_PORT ct state new add @ssh_meter6 { ip6 saddr limit rate over 10/minute burst 10 packets } drop
EOF
    if ((${#ADMIN4[@]} + ${#ADMIN6[@]})); then
        ((${#ADMIN4[@]})) && printf '\t\ttcp dport %s ip saddr @admin4 accept\n' "$SSH_PORT"
        ((${#ADMIN6[@]})) && printf '\t\ttcp dport %s ip6 saddr @admin6 accept\n' "$SSH_PORT"
    else
        printf '\t\t# ADMIN_ALLOWLIST is empty: SSH is open to everyone (rate limited).\n'
        printf '\t\ttcp dport %s accept\n' "$SSH_PORT"
    fi
    if [[ -n "$pub_ports" ]]; then
        printf '\n\t\t# Reverse proxy listening on the host itself\n'
        printf '\t\ttcp dport { %s } accept\n' "$pub_ports"
    fi
    cat <<EOF
	}

	# Traffic from VPN clients to this host.
	chain wg_input {
		meta nfproto ipv6 drop
		ip saddr != $VPN_SUBNET drop
		ip daddr $VPN_SERVER_IP icmp type echo-request limit rate 10/second burst 20 packets accept
EOF
    if [[ -n "$wgin_ports" ]]; then
        printf '\t\tip daddr %s meta l4proto { tcp, udp } th dport { %s } accept\n' "$VPN_SERVER_IP" "$wgin_ports"
    fi
    cat <<EOF
		# The reverse proxy, when it listens on a local address in SERVICES_SUBNET
		ip daddr $SERVICES_SUBNET tcp dport { $svc_ports } accept
		drop
	}

	# Policy accept on purpose: Docker routes its bridge networks (and the
	# DNAT of published ports) through this hook and filters them in its own
	# tables. A drop policy here would break every container. All traffic
	# from or to the WireGuard interface is handled in the wg_* chains,
	# which end in an explicit drop, for IPv4 and IPv6.
	chain forward {
		type filter hook forward priority filter; policy accept;

		ip saddr @blocklist4 drop
		ip6 saddr @blocklist6 drop
		iifname "$wg" jump wg_forward
		oifname "$wg" jump wg_forward_out
	}

	# From VPN clients.
	chain wg_forward {
		ip saddr @quarantine4 drop
		ct state established,related accept
		ct state invalid drop
		meta nfproto ipv6 drop
		ip saddr != $VPN_SUBNET drop
		# No client-to-client traffic
		oifname "$wg" drop
		# Services. "ct original" matches the address the client dialled,
		# also when Docker DNATs it to a container.
		meta l4proto tcp ct original ip daddr $SERVICES_SUBNET ct original proto-dst { $svc_ports } accept
EOF
    if [[ "$FULL_TUNNEL" == yes ]]; then
        cat <<EOF
		# FULL_TUNNEL=yes: internet only, no private or special ranges
		ip daddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/3 } drop
		oifname "$EXT_IF" accept
EOF
    fi
    cat <<EOF
		drop
	}

	# To VPN clients: only replies, nothing may open connections to them.
	chain wg_forward_out {
		ip daddr @quarantine4 drop
		ct state established,related accept
		drop
	}
EOF
    if [[ "$FULL_TUNNEL" == yes || "$SERVICES_NAT" == yes ]]; then
        printf '\n\tchain postrouting {\n\t\ttype nat hook postrouting priority srcnat; policy accept;\n\n'
        if [[ "$FULL_TUNNEL" == yes ]]; then
            printf '\t\tip saddr %s oifname "%s" masquerade\n' "$VPN_SUBNET" "$EXT_IF"
        fi
        if [[ "$SERVICES_NAT" == yes ]]; then
            printf '\t\tip saddr %s ip daddr %s oifname != "%s" masquerade\n' "$VPN_SUBNET" "$SERVICES_SUBNET" "$wg"
        fi
        printf '\t}\n'
    fi
    printf '}\n'
}

# --------------------------------------------------------------------------
# Apply
# --------------------------------------------------------------------------

# Refuses to continue if the current SSH session would be cut off.
check_ssh_lockout() {
    [[ -n "${SSH_CONNECTION:-}" ]] || return 0
    local client _cport server sport
    read -r client _cport server sport <<<"$SSH_CONNECTION"
    [[ -n "$client" ]] || return 0

    if [[ "$client" != *:* ]] && ip_in_cidr "$client" "$VPN_SUBNET"; then
        split_csv "$WG_INPUT_PORTS" | grep -Fqx -- "$sport" ||
            die "You are connected over the VPN ($client -> $server:$sport) but port $sport is not in WG_INPUT_PORTS; applying would lock you out"
        return 0
    fi
    [[ "$sport" == "$SSH_PORT" ]] ||
        die "Your SSH session uses port $sport but SSH_PORT=$SSH_PORT; applying would lock you out"
    [[ -n "$ADMIN_ALLOWLIST" ]] || return 0

    if [[ "$client" == *:* ]]; then
        # No IPv6 prefix matcher in the lib: exact addresses are verified,
        # prefixes only produce a warning.
        ((${#ADMIN6[@]})) ||
            die "Your SSH client $client is IPv6 but ADMIN_ALLOWLIST has no IPv6 entries; applying would lock you out"
        printf '%s\n' "${ADMIN6[@]}" | grep -Fqx -- "$client" ||
            warn "Could not verify that $client is inside the IPv6 ADMIN_ALLOWLIST prefixes; make sure it is"
        return 0
    fi
    ip_in_list "$client" "$ADMIN_ALLOWLIST" ||
        die "Your SSH client $client is not in ADMIN_ALLOWLIST ($ADMIN_ALLOWLIST); applying would lock you out"
}

# Prints "add element" commands for the new table: what is live now plus
# what was saved (e.g. entries lost by a reboot or an nftables reload).
carry_over_elements() {
    local set addr secs
    while read -r set addr secs; do
        _fw_valid_elem "$set" "$addr" || continue
        [[ "$secs" =~ ^[0-9]+$ ]] || continue
        if [[ "$set" == quarantine4 ]]; then
            printf 'add element inet %s %s { %s }\n' "$NFT_TABLE" "$set" "$addr"
        elif ((secs > 0)); then
            printf 'add element inet %s %s { %s timeout %ss }\n' "$NFT_TABLE" "$set" "$addr" "$secs"
        fi
    done < <(fw_list_dynamic)
    fw_restore_commands
}

install_state_unit() {
    local unit="$SYSTEMD_UNIT_DIR/ztvpn-firewall-state.service"
    local self
    self="$(readlink -f "${BASH_SOURCE[0]}")"
    mkdir -p "$SYSTEMD_UNIT_DIR"
    atomic_write "$unit" 644 <<EOF
[Unit]
Description=Restore zero-trust-vpn blocklist and quarantine entries
After=nftables.service
Requires=nftables.service

[Service]
Type=oneshot
ExecStart=$self --restore-state

[Install]
WantedBy=multi-user.target
EOF
    if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
        if systemctl daemon-reload && systemctl enable ztvpn-firewall-state.service >/dev/null 2>&1; then
            info "ztvpn-firewall-state.service enabled (restores blocklist/quarantine at boot)"
        else
            warn "Could not enable ztvpn-firewall-state.service; enable it manually"
        fi
    else
        warn "MANUAL: no systemd; run '$self --restore-state' after nftables loads at boot"
    fi
}

persist() {
    local rendered="$1"
    mkdir -p "$(dirname "$NFT_RULES_FILE")"
    atomic_write "$NFT_RULES_FILE" 600 <"$rendered"
    info "Wrote $NFT_RULES_FILE"

    local inc="include \"$NFT_RULES_FILE\""
    if [[ ! -f "$NFTABLES_CONF" ]]; then
        printf '#!/usr/sbin/nft -f\n\n%s\n' "$inc" | atomic_write "$NFTABLES_CONF" 755
        info "Created $NFTABLES_CONF"
    elif ! grep -Fqx "$inc" "$NFTABLES_CONF"; then
        { cat "$NFTABLES_CONF"; printf '\n# zero-trust-vpn\n%s\n' "$inc"; } | atomic_write "$NFTABLES_CONF" 755
        info "Added include to $NFTABLES_CONF"
    fi
    if grep -Eq '^[[:space:]]*flush[[:space:]]+ruleset' "$NFTABLES_CONF"; then
        warn "$NFTABLES_CONF contains 'flush ruleset': fine at boot, but never 'systemctl restart/reload nftables' on a running Docker host (it wipes Docker's rules). Re-run this script instead."
    fi

    if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
        systemctl enable nftables.service >/dev/null 2>&1 &&
            info "nftables.service enabled (loads the ruleset at boot)" ||
            warn "Could not enable nftables.service; enable it manually"
    else
        warn "MANUAL: systemd not available; make sure $NFTABLES_CONF is loaded at boot"
    fi
}

post_apply_checks() {
    if [[ -r /proc/sys/net/ipv4/ip_forward && "$(</proc/sys/net/ipv4/ip_forward)" != 1 ]]; then
        warn "net.ipv4.ip_forward is 0: VPN clients cannot reach services (wireguard-setup.sh sets it)"
    fi
    if nft list chain ip filter FORWARD 2>/dev/null | grep -q 'policy drop'; then
        warn "Docker set the iptables FORWARD policy to drop, which also drops routed VPN traffic that is not DNATed to a container. Set \"ip-forward-no-drop\": true in /etc/docker/daemon.json (Docker >= 28) if clients must reach SERVICES_SUBNET hosts or the internet."
    fi
    local addr found=0
    while read -r addr; do
        ip_in_cidr "${addr%/*}" "$SERVICES_SUBNET" && found=1
    done < <(ip -4 -o addr show 2>/dev/null | awk '{print $4}')
    if ((found == 0)) && [[ "$SERVICES_NAT" != yes ]]; then
        warn "No local address in SERVICES_SUBNET $SERVICES_SUBNET: hosts there need a route to $VPN_SUBNET via this server (or set SERVICES_NAT=yes)"
    fi
}

# The watcher runs in its own session (setsid), so its process group id is
# its pid; killing the group also ends the pending sleep.
stop_watcher() {
    [[ -n "$1" ]] || return 0
    kill -- "-$1" 2>/dev/null || kill "$1" 2>/dev/null || true
}

do_apply() {
    local timeout="$1"
    require_root
    require_cmd nft jq
    check_ssh_lockout

    (umask 077; mkdir -p "$FIREWALL_STATE_DIR" "$ZTVPN_BACKUP_DIR/firewall")
    local rendered="$FIREWALL_STATE_DIR/ztvpn.nft.new"
    local applyfile="$FIREWALL_STATE_DIR/apply.nft"
    local rollback="$FIREWALL_STATE_DIR/rollback.nft"
    local confirm="$FIREWALL_STATE_DIR/confirm"
    local ts
    ts="$(date +%Y%m%d-%H%M%S)-$$"

    render_ruleset | atomic_write "$rendered" 600
    nft -c -f "$rendered" || die "Generated ruleset failed validation (nft -c); nothing was changed"

    local backup="$ZTVPN_BACKUP_DIR/firewall/ruleset-$ts.nft"
    nft list ruleset | atomic_write "$backup" 600 || die "Could not back up the current ruleset"
    info "Backed up current ruleset to $backup"

    # Rollback = previous ztvpn table, or no ztvpn table at all.
    {
        printf 'table inet %s\ndelete table inet %s\n' "$NFT_TABLE" "$NFT_TABLE"
        nft list table inet "$NFT_TABLE" 2>/dev/null || true
    } | atomic_write "$rollback" 600

    { cat "$rendered"; carry_over_elements; } | atomic_write "$applyfile" 600
    nft -c -f "$applyfile" || die "Ruleset with carried-over set elements failed validation; nothing was changed"

    rm -f "$confirm"
    local watcher=""
    if ((timeout > 0)); then
        # Independent of this shell, so the rollback still happens if the
        # SSH session dies because the new rules cut it off.
        setsid bash -c 'sleep "$1"; [ -e "$2" ] || nft -f "$3"' _ "$((timeout + 5))" "$confirm" "$rollback" \
            </dev/null >/dev/null 2>&1 &
        watcher=$!
    fi

    if ! nft -f "$applyfile"; then
        stop_watcher "$watcher"
        die "nft failed to apply the ruleset; the previous ruleset is still active"
    fi
    info "Applied table inet $NFT_TABLE"

    if ((timeout > 0)); then
        warn "Open a NEW SSH session now to check you still get in. Press Enter here or run 'touch $confirm' within ${timeout}s, otherwise the previous rules are restored."
        local deadline=$((SECONDS + timeout)) ok=0 _line
        trap '' HUP
        while ((SECONDS < deadline)); do
            if [[ -e "$confirm" ]]; then ok=1; break; fi
            if read -r -t 1 _line 2>/dev/null; then ok=1; break; fi
            sleep 1
        done
        if ((ok)); then
            touch "$confirm"
            stop_watcher "$watcher"
            info "Confirmed"
        else
            stop_watcher "$watcher"
            nft -f "$rollback" || die "Rollback FAILED; restore manually with: nft -f $rollback"
            die "Not confirmed within ${timeout}s: rolled back to the previous ztvpn table. Nothing was persisted."
        fi
    fi

    persist "$rendered"
    install_state_unit
    fw_save_state || warn "Could not save blocklist/quarantine state to $FW_STATE_FILE"
    rm -f "$rendered" "$confirm"
    post_apply_checks
    success "Firewall active: table inet $NFT_TABLE"
}

# --------------------------------------------------------------------------

ACTION=print
CONFIRM_TIMEOUT=0
while (($#)); do
    case "$1" in
        --print) ACTION=print; shift ;;
        --apply) ACTION=apply; shift ;;
        --restore-state) ACTION=restore; shift ;;
        --confirm-timeout)
            [[ $# -ge 2 && "$2" =~ ^[0-9]{1,4}$ ]] || die "--confirm-timeout needs a number of seconds"
            CONFIRM_TIMEOUT="$2"; shift 2 ;;
        -h | --help) usage; exit 0 ;;
        *) die "Unknown option: $1 (see --help)" ;;
    esac
done

EXT_IF=""
validate_settings
if [[ -z "$ADMIN_ALLOWLIST" ]]; then
    warn "ADMIN_ALLOWLIST is empty: SSH (port $SSH_PORT) is reachable from everywhere, only rate limited"
fi

case "$ACTION" in
    print)
        ((CONFIRM_TIMEOUT == 0)) || die "--confirm-timeout only makes sense with --apply"
        render_ruleset
        ;;
    apply) do_apply "$CONFIRM_TIMEOUT" ;;
    restore)
        require_root
        require_cmd nft jq
        nft list table inet "$NFT_TABLE" >/dev/null 2>&1 || die "table inet $NFT_TABLE is not loaded"
        fw_restore_state || die "Could not restore saved set entries"
        success "Restored saved blocklist/quarantine entries"
        ;;
esac
