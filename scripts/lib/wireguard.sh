# shellcheck shell=bash
# WireGuard peer management. Sourced by common.sh.
#
# Peers in $WG_CONF are wrapped in exact markers so they can be found and
# removed without regex matching on names:
#
#   # BEGIN PEER alice--laptop
#   [Peer]
#   ...
#   # END PEER alice--laptop

wg_peer_exists() {
    local name="$1"
    [[ -f "$WG_CONF" ]] || return 1
    awk -v m="# BEGIN PEER $name" '$0 == m { found = 1; exit } END { exit !found }' "$WG_CONF"
}

# Prints "name ip pubkey" for every managed peer.
wg_list_peers() {
    [[ -f "$WG_CONF" ]] || return 0
    awk '
        /^# BEGIN PEER / { name = substr($0, 14); ip = ""; key = ""; next }
        /^# END PEER /   { if (name != "") print name, ip, key; name = ""; next }
        name != "" && /^[[:space:]]*PublicKey[[:space:]]*=/ { sub(/^[^=]*=[[:space:]]*/, ""); key = $0 }
        name != "" && /^[[:space:]]*AllowedIPs[[:space:]]*=/ {
            sub(/^[^=]*=[[:space:]]*/, ""); split($0, a, /[[:space:]]*,[[:space:]]*/); ip = a[1]; sub(/\/32$/, "", ip)
        }
    ' "$WG_CONF"
}

wg_peer_ip() {
    local name="$1" n ip _k
    while read -r n ip _k; do
        [[ "$n" == "$name" ]] && { printf '%s\n' "$ip"; return 0; }
    done < <(wg_list_peers)
    return 1
}

wg_peer_by_ip() {
    local want="$1" n ip _k
    while read -r n ip _k; do
        [[ "$ip" == "$want" ]] && { printf '%s\n' "$n"; return 0; }
    done < <(wg_list_peers)
    return 1
}

# Every tunnel IP in use, from any [Peer] or [Interface] Address line,
# managed or not, so hand-added peers are never double-assigned.
_wg_used_ips() {
    printf '%s\n' "$VPN_SERVER_IP"
    [[ -f "$WG_CONF" ]] || return 0
    awk '
        /^[[:space:]]*(AllowedIPs|Address)[[:space:]]*=/ {
            sub(/^[^=]*=[[:space:]]*/, "")
            n = split($0, a, /[[:space:]]*,[[:space:]]*/)
            for (i = 1; i <= n; i++) { ip = a[i]; sub(/\/[0-9]+$/, "", ip); print ip }
        }
    ' "$WG_CONF"
}

wg_next_free_ip() {
    validate_cidr "$VPN_SUBNET" || { error "Invalid VPN_SUBNET: $VPN_SUBNET"; return 1; }
    local bits="${VPN_SUBNET#*/}" base first last i candidate
    local -A used=()
    while IFS= read -r i; do [[ -n "$i" ]] && used["$i"]=1; done < <(_wg_used_ips)

    base=$(($(ip_to_int "${VPN_SUBNET%/*}") & ((0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF)))
    first=$((base + 1))
    last=$((base + (1 << (32 - bits)) - 2))
    for ((i = first; i <= last; i++)); do
        candidate="$(int_to_ip "$i")"
        [[ -z "${used[$candidate]:-}" ]] && { printf '%s\n' "$candidate"; return 0; }
    done
    error "No free address left in $VPN_SUBNET"
    return 1
}

wg_ip_in_use() {
    local ip="$1" u
    while IFS= read -r u; do
        [[ "$u" == "$ip" ]] && return 0
    done < <(_wg_used_ips)
    return 1
}

# wg_add_peer <name> <pubkey> <ip> [psk-file]
wg_add_peer() {
    local name="$1" pubkey="$2" ip="$3" pskfile="${4:-}"
    validate_peer_name "$name" || { error "Invalid peer name: $name"; return 1; }
    [[ "$pubkey" =~ ^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$ ]] || { error "Invalid WireGuard public key"; return 1; }
    ip_in_cidr "$ip" "$VPN_SUBNET" || { error "$ip is not inside $VPN_SUBNET"; return 1; }
    [[ -f "$WG_CONF" ]] || { error "$WG_CONF does not exist, run wireguard-setup.sh first"; return 1; }
    wg_peer_exists "$name" && { error "Peer $name already exists"; return 1; }
    wg_ip_in_use "$ip" && { error "$ip is already assigned"; return 1; }

    {
        cat "$WG_CONF"
        printf '\n# BEGIN PEER %s\n[Peer]\nPublicKey = %s\n' "$name" "$pubkey"
        [[ -n "$pskfile" ]] && printf 'PresharedKey = %s\n' "$(<"$pskfile")"
        printf 'AllowedIPs = %s/32\n# END PEER %s\n' "$ip" "$name"
    } | atomic_write "$WG_CONF" 600
}

wg_remove_peer() {
    local name="$1"
    wg_peer_exists "$name" || return 1
    # wg_add_peer writes one blank line before each block; drop it together
    # with the block so add followed by remove restores the file exactly.
    awk -v b="# BEGIN PEER $name" -v e="# END PEER $name" '
        $0 == b { skip = 1; pending = 0; next }
        skip && $0 == e { skip = 0; next }
        skip { next }
        /^[[:space:]]*$/ { if (pending) print ""; pending = 1; next }
        { if (pending) print ""; pending = 0; print }
        END { if (pending) print "" }
    ' "$WG_CONF" | atomic_write "$WG_CONF" 600
}

# Applies $WG_CONF to the running interface without dropping sessions.
wg_apply() {
    if ip link show "$WG_INTERFACE" >/dev/null 2>&1; then
        wg syncconf "$WG_INTERFACE" <(wg-quick strip "$WG_CONF")
    else
        warn "Interface $WG_INTERFACE is not up; changes apply on next start"
    fi
}

# Prints the client config for a peer on stdout.
# wg_render_client_config <privkey-file> <ip> [psk-file]
wg_render_client_config() {
    local keyfile="$1" ip="$2" pskfile="${3:-}"
    local server_pub
    server_pub="$(<"$WG_SERVER_PUBKEY")" || { error "Missing $WG_SERVER_PUBKEY"; return 1; }
    printf '[Interface]\nPrivateKey = %s\nAddress = %s/32\n' "$(<"$keyfile")" "$ip"
    [[ -n "$CLIENT_DNS" ]] && printf 'DNS = %s\n' "$CLIENT_DNS"
    printf '\n[Peer]\nPublicKey = %s\n' "$server_pub"
    [[ -n "$pskfile" ]] && printf 'PresharedKey = %s\n' "$(<"$pskfile")"
    printf 'Endpoint = %s:%s\nAllowedIPs = %s\nPersistentKeepalive = %s\n' \
        "$VPN_ENDPOINT" "$WG_PORT" "$CLIENT_ALLOWED_IPS" "$WG_KEEPALIVE"
}

# Creates keys, registers the peer and writes the client config.
# Prints the assigned IP. wg_provision_peer <name> [ip]
wg_provision_peer() {
    local name="$1" ip="${2:-}" dir
    validate_peer_name "$name" || { error "Invalid peer name: $name"; return 1; }
    dir="$WG_CLIENTS_DIR/$name"
    [[ -e "$dir" ]] && { error "Client directory $dir already exists"; return 1; }
    wg_peer_exists "$name" && { error "Peer $name already exists"; return 1; }
    if [[ -z "$ip" ]]; then
        ip="$(wg_next_free_ip)" || return 1
    fi

    (
        umask 077
        mkdir -p "$dir"
        wg genkey >"$dir/private.key"
        wg pubkey <"$dir/private.key" >"$dir/public.key"
        wg genpsk >"$dir/preshared.key"
    ) || return 1

    if ! wg_add_peer "$name" "$(<"$dir/public.key")" "$ip" "$dir/preshared.key"; then
        rm -rf "$dir"
        return 1
    fi
    wg_render_client_config "$dir/private.key" "$ip" "$dir/preshared.key" | atomic_write "$dir/$name.conf" 600
    printf '%s\n' "$ip"
}

# Removes the peer from the server and the running interface and deletes
# its key material (after archiving it for the audit trail).
wg_deprovision_peer() {
    local name="$1" archive_dir="${2:-}"
    local removed=1
    local pub=""
    [[ -f "$WG_CLIENTS_DIR/$name/public.key" ]] && pub="$(<"$WG_CLIENTS_DIR/$name/public.key")"
    if [[ -z "$pub" ]]; then
        local n _ip k
        while read -r n _ip k; do [[ "$n" == "$name" ]] && pub="$k"; done < <(wg_list_peers)
    fi
    if wg_remove_peer "$name"; then removed=0; fi
    if [[ -n "$pub" ]] && ip link show "$WG_INTERFACE" >/dev/null 2>&1; then
        wg set "$WG_INTERFACE" peer "$pub" remove || true
    fi
    if [[ -d "$WG_CLIENTS_DIR/$name" ]]; then
        if [[ -n "$archive_dir" ]]; then
            (umask 077; mkdir -p "$archive_dir" && cp -a "$WG_CLIENTS_DIR/$name" "$archive_dir/")
        fi
        rm -rf "${WG_CLIENTS_DIR:?}/$name"
        removed=0
    fi
    return "$removed"
}

# All peers belonging to a user: "<user>" and "<user>--<device>".
wg_user_peers() {
    local user="$1" n _ip _k
    while read -r n _ip _k; do
        [[ "$n" == "$user" || "$n" == "$user--"* ]] && printf '%s\n' "$n"
    done < <(wg_list_peers)
    return 0
}
