#!/usr/bin/env bash
# Sets up the WireGuard server interface.
#
# Writes the server key pair (only if missing), the [Interface] section of
# $WG_CONF (existing peers are kept), an IPv4 forwarding sysctl drop-in and
# enables wg-quick@<interface>. Forwarding/NAT rules are NOT set here: they
# live in nftables (scripts/setup/firewall-setup.sh). Peers are managed by
# scripts/management/add-user.sh and revoke-user.sh.

set -Eeuo pipefail

# shellcheck source=scripts/lib/common.sh
source "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/../lib/common.sh"

ZTVPN_SYSCTL_FILE="${ZTVPN_SYSCTL_FILE:-/etc/sysctl.d/99-ztvpn.conf}"
LOG_FILE="${LOG_FILE:-$ZTVPN_LOG_DIR/wireguard-setup.log}"

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Configure the WireGuard server interface $WG_INTERFACE.

  - server key pair: $WG_SERVER_KEY / $WG_SERVER_PUBKEY (created if missing)
  - $WG_CONF: [Interface] Address=$VPN_SERVER_IP/${VPN_SUBNET#*/}, ListenPort=$WG_PORT;
    existing [Peer] sections are preserved
  - $ZTVPN_SYSCTL_FILE: net.ipv4.ip_forward=1
  - systemctl enable --now wg-quick@$WG_INTERFACE (reload if already running)

Options:
  --force       Generate a new server key pair (old one is backed up to
                $ZTVPN_BACKUP_DIR). Every client config must be re-issued.
  --no-start    Do not enable/start/reload the systemd unit
  -h, --help    Show this help

Settings (ztvpn.conf or environment): WG_INTERFACE, WG_PORT, VPN_SUBNET,
VPN_SERVER_IP, WG_DIR, WG_CONF, WG_SERVER_KEY, WG_SERVER_PUBKEY.
EOF
}

FORCE=0
START=1
while (($#)); do
    case "$1" in
        --force) FORCE=1; shift ;;
        --no-start) START=0; shift ;;
        -h | --help) usage; exit 0 ;;
        *) die "Unknown option: $1 (see --help)" ;;
    esac
done

require_root
require_cmd wg flock

[[ "$WG_INTERFACE" =~ ^[A-Za-z0-9_=+.-]{1,15}$ ]] || die "Invalid WG_INTERFACE: $WG_INTERFACE"
[[ "$WG_PORT" =~ ^[1-9][0-9]{0,4}$ ]] && ((WG_PORT <= 65535)) || die "Invalid WG_PORT: $WG_PORT"
validate_cidr "$VPN_SUBNET" || die "Invalid VPN_SUBNET: $VPN_SUBNET"
ip_in_cidr "$VPN_SERVER_IP" "$VPN_SUBNET" || die "VPN_SERVER_IP $VPN_SERVER_IP is not inside $VPN_SUBNET"
PREFIX="${VPN_SUBNET#*/}"
((PREFIX <= 30)) || die "VPN_SUBNET $VPN_SUBNET is too small"

ztvpn_lock wg

# --------------------------------------------------------------------------
# Server key pair
# --------------------------------------------------------------------------
(umask 077; mkdir -p "$WG_DIR" "$(dirname "$WG_SERVER_KEY")" "$(dirname "$WG_CONF")")
chmod 700 "$WG_DIR"

if [[ -s "$WG_SERVER_KEY" && "$FORCE" == 1 ]]; then
    backup="$ZTVPN_BACKUP_DIR/wireguard-$(date +%Y%m%d-%H%M%S)"
    (umask 077; mkdir -p "$backup")
    cp -a "$WG_SERVER_KEY" "$backup/"
    [[ -f "$WG_SERVER_PUBKEY" ]] && cp -a "$WG_SERVER_PUBKEY" "$backup/"
    [[ -f "$WG_CONF" ]] && cp -a "$WG_CONF" "$backup/"
    rm -f "$WG_SERVER_KEY"
    warn "Old server keys backed up to $backup. All client configs must be re-issued."
fi

if [[ ! -s "$WG_SERVER_KEY" ]]; then
    (umask 077; wg genkey >"$WG_SERVER_KEY.tmp" && mv -f "$WG_SERVER_KEY.tmp" "$WG_SERVER_KEY")
    success "Generated server private key $WG_SERVER_KEY"
else
    info "Keeping existing server key $WG_SERVER_KEY"
fi
chmod 600 "$WG_SERVER_KEY"

pubkey="$(wg pubkey <"$WG_SERVER_KEY")" || die "$WG_SERVER_KEY is not a valid WireGuard private key"
if [[ ! -f "$WG_SERVER_PUBKEY" || "$(<"$WG_SERVER_PUBKEY")" != "$pubkey" ]]; then
    printf '%s\n' "$pubkey" | atomic_write "$WG_SERVER_PUBKEY" 644
fi

# --------------------------------------------------------------------------
# wg0.conf: regenerate [Interface], keep every peer
# --------------------------------------------------------------------------
peers=""
old_address=""
if [[ -f "$WG_CONF" ]]; then
    old_address="$(awk -F'=' '/^[[:space:]]*\[Peer\]/ { exit } /^[[:space:]]*Address[[:space:]]*=/ { gsub(/[[:space:]]/, "", $2); print $2; exit }' "$WG_CONF")"
    if grep -Eq '^[[:space:]]*(PostUp|PostDown|PreUp|PreDown|DNS)[[:space:]]*=' "$WG_CONF"; then
        warn "Dropping PostUp/PostDown/DNS lines from $WG_CONF: forwarding and NAT are handled by nftables"
    fi
    # Everything from the first peer (managed "# BEGIN PEER" block or a
    # hand-written [Peer]) to the end of the file is kept verbatim.
    peers="$(awk '
        /^# BEGIN PEER / || /^[[:space:]]*\[Peer\][[:space:]]*$/ { keep = 1 }
        keep { print }
    ' "$WG_CONF")"
fi

new_conf="$(
    cat <<EOF
# Managed by scripts/setup/wireguard-setup.sh. The [Interface] section is
# regenerated on every run; peers are added/removed by the management
# scripts between "# BEGIN PEER" / "# END PEER" markers.
# No PostUp/PostDown: forwarding and NAT live in nftables (table inet ztvpn).
[Interface]
Address = $VPN_SERVER_IP/$PREFIX
ListenPort = $WG_PORT
PrivateKey = $(<"$WG_SERVER_KEY")
EOF
    if [[ -n "$peers" ]]; then
        printf '\n%s\n' "$peers"
    fi
)"

conf_changed=0
if [[ ! -f "$WG_CONF" ]] || [[ "$(<"$WG_CONF")" != "$new_conf" ]]; then
    printf '%s\n' "$new_conf" | atomic_write "$WG_CONF" 600
    conf_changed=1
    success "Wrote $WG_CONF ($(grep -c '^# BEGIN PEER ' "$WG_CONF" || true) managed peer(s) kept)"
else
    info "$WG_CONF is up to date"
fi
chmod 600 "$WG_CONF"

# --------------------------------------------------------------------------
# Forwarding
# --------------------------------------------------------------------------
mkdir -p "$(dirname "$ZTVPN_SYSCTL_FILE")"
atomic_write "$ZTVPN_SYSCTL_FILE" 644 <<'EOF'
# Managed by scripts/setup/wireguard-setup.sh
# Route between the WireGuard tunnel and the services network. What may be
# forwarded is decided by nftables (table inet ztvpn), default drop.
net.ipv4.ip_forward = 1
# IPv6 forwarding is deliberately not enabled: the tunnel is IPv4 only
# (VPN_SUBNET), and net.ipv6.conf.all.forwarding=1 would also stop the host
# from accepting router advertisements on its uplink.
EOF
sysctl -p "$ZTVPN_SYSCTL_FILE" >&2 || die "Applying $ZTVPN_SYSCTL_FILE failed"

# --------------------------------------------------------------------------
# Service
# --------------------------------------------------------------------------
unit="wg-quick@$WG_INTERFACE"

# Older versions of this project wrote a full unit into an override.conf,
# which duplicates ExecStart and breaks the unit. Move it aside.
legacy_override="$SYSTEMD_UNIT_DIR/$unit.service.d/override.conf"
if [[ -f "$legacy_override" ]] && grep -q '^ExecStart=/usr/bin/wg-quick up' "$legacy_override"; then
    (umask 077; mkdir -p "$ZTVPN_BACKUP_DIR")
    mv "$legacy_override" "$ZTVPN_BACKUP_DIR/$unit-override.conf.$(date +%s)"
    rmdir "$(dirname "$legacy_override")" 2>/dev/null || true
    warn "Removed broken legacy $legacy_override"
    ((START)) && systemctl daemon-reload
fi

if ((START)); then
    require_cmd systemctl
    if systemctl is-active --quiet "$unit"; then
        systemctl enable "$unit"
        if ((conf_changed)); then
            # wg-quick's ExecReload runs "wg syncconf" on the stripped config:
            # peers and keys are updated without dropping sessions. An Address
            # change still needs a restart.
            systemctl reload "$unit"
            success "Reloaded $unit"
            if [[ -n "$old_address" && "$old_address" != "$VPN_SERVER_IP/$PREFIX" ]]; then
                warn "Interface address changed ($old_address -> $VPN_SERVER_IP/$PREFIX): run 'systemctl restart $unit'"
            fi
        fi
    else
        systemctl enable --now "$unit"
        success "Enabled and started $unit"
    fi
else
    info "Not starting $unit (--no-start)"
fi

info "Server public key: $pubkey"
info "Clients connect to $VPN_ENDPOINT:$WG_PORT"
