#!/usr/bin/env bash
# Enrols additional devices of an existing user as WireGuard peers
# "<user>--<device>" and keeps the device inventory.
set -Eeuo pipefail

# shellcheck source=scripts/lib/common.sh
source "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/../lib/common.sh"

usage() {
    cat <<EOF
Usage: $(basename "$0") <command> [options]

Commands:
  enroll --user U --device D [--type T] [--ip IP] [--cert] [--qr] [--dry-run]
         Create WireGuard peer "U--D" for an existing Authelia user.
         --type   laptop | desktop | phone | tablet (default: laptop)
         --ip     fixed tunnel address inside $VPN_SUBNET (default: next free)
         --cert   also issue a client certificate (CN = U--D)
         --qr     write a QR code PNG of the client config (needs qrencode)
         --dry-run  validate and show what would happen, change nothing
  remove --user U --device D [--reason R]
         Remove the peer, revoke its certificate, mark it revoked in the inventory.
  list   [--user U] [--json]
         List inventory entries.
  show   --user U --device D
         Print the inventory entry and peer state as JSON (no key material).

Inventory: $DEVICE_INVENTORY
EOF
}

need_value() { [[ $# -ge 2 && -n "$2" ]] || die "Option $1 requires a value"; }

COMMAND="${1:-}"
[[ -n "$COMMAND" ]] || { usage >&2; exit 1; }
shift
case "$COMMAND" in
    -h|--help|help) usage; exit 0 ;;
    enroll|remove|list|show) ;;
    *) die "Unknown command: $COMMAND (see --help)" ;;
esac

USERNAME="" DEVICE="" DEVICE_TYPE="laptop" FIXED_IP="" REASON="cessationOfOperation"
WANT_CERT=0 WANT_QR=0 DRY_RUN=0 JSON=0
while (($#)); do
    case "$1" in
        -h|--help) usage; exit 0 ;;
        --user)   need_value "$@"; USERNAME="$2"; shift 2 ;;
        --device) need_value "$@"; DEVICE="$2"; shift 2 ;;
        --type)   need_value "$@"; DEVICE_TYPE="$2"; shift 2 ;;
        --ip)     need_value "$@"; FIXED_IP="$2"; shift 2 ;;
        --reason) need_value "$@"; REASON="$2"; shift 2 ;;
        --cert)   WANT_CERT=1; shift ;;
        --qr)     WANT_QR=1; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        --json)   JSON=1; shift ;;
        *) die "Unknown option: $1 (see --help)" ;;
    esac
done

check_user() {
    [[ -n "$USERNAME" ]] || die "--user is required"
    validate_username "$USERNAME" && [[ "$USERNAME" != *--* ]] || die "Invalid username: $USERNAME"
}
check_device() {
    [[ -n "$DEVICE" ]] || die "--device is required"
    validate_device_name "$DEVICE" || die "Invalid device name: $DEVICE"
    PEER="$USERNAME--$DEVICE"
    validate_peer_name "$PEER" || die "Invalid peer name: $PEER"
}

# --------------------------------------------------------------------------
# Inventory helpers (candidates for the shared lib)
# --------------------------------------------------------------------------

inventory_init() {
    [[ -f "$DEVICE_INVENTORY" ]] && return 0
    mkdir -p "$(dirname "$DEVICE_INVENTORY")"
    printf '{"devices": []}\n' | atomic_write "$DEVICE_INVENTORY" 600
}

# inventory_edit <constant jq program> [jq --arg ...]
inventory_edit() {
    local prog="$1" out
    shift
    out="$(jq "$@" "$prog" "$DEVICE_INVENTORY")" || return 1
    printf '%s\n' "$out" | atomic_write "$DEVICE_INVENTORY" 600
}

inventory_read() {
    if [[ -f "$DEVICE_INVENTORY" ]]; then
        jq -e '.devices | type == "array"' "$DEVICE_INVENTORY" >/dev/null ||
            die "$DEVICE_INVENTORY is not a valid inventory"
        cat "$DEVICE_INVENTORY"
    else
        printf '{"devices": []}\n'
    fi
}

audit() {
    (umask 027; mkdir -p "$ZTVPN_LOG_DIR" &&
        printf '%s %s actor=%s %s\n' "$(date -Iseconds)" "$1" "${SUDO_USER:-$(id -un)}" "$2" \
            >>"$ZTVPN_LOG_DIR/audit.log") || warn "Could not write audit log"
}

# --------------------------------------------------------------------------
# enroll
# --------------------------------------------------------------------------

COMMITTED=0 PEER_ATTEMPTED=0 CERT_ATTEMPTED=0 QR_FILE=""

enroll_rollback() {
    local rc=$?
    ((COMMITTED)) && return 0
    set +e
    ((rc == 0)) && rc=1
    ((PEER_ATTEMPTED || CERT_ATTEMPTED)) && warn "Rolling back enrolment of $PEER"
    [[ -n "$QR_FILE" ]] && rm -f "$QR_FILE"
    if ((CERT_ATTEMPTED)); then
        pki_revoke "$PEER" cessationOfOperation
        case $? in
            0|2) rm -f "$PKI_CLIENTS_DIR/$PEER.key" "$PKI_CLIENTS_DIR/$PEER.crt" ;;
            *) error "Rollback: could not revoke certificate $PEER; revoke it manually" ;;
        esac
    fi
    if ((PEER_ATTEMPTED)) && { wg_peer_exists "$PEER" || [[ -e "$WG_CLIENTS_DIR/$PEER" ]]; }; then
        wg_deprovision_peer "$PEER" || error "Rollback: could not remove peer $PEER"
        wg_apply || error "Rollback: could not apply $WG_CONF"
    fi
    exit "$rc"
}

cmd_enroll() {
    check_user
    check_device
    case "$DEVICE_TYPE" in
        laptop|desktop|phone|tablet) ;;
        *) die "Invalid device type: $DEVICE_TYPE (laptop, desktop, phone, tablet)" ;;
    esac
    if [[ -n "$FIXED_IP" ]]; then
        validate_ipv4 "$FIXED_IP" || die "Invalid IP address: $FIXED_IP"
        ip_in_cidr "$FIXED_IP" "$VPN_SUBNET" || die "$FIXED_IP is not inside VPN_SUBNET $VPN_SUBNET"
        local bits="${VPN_SUBNET#*/}" n base
        n="$(ip_to_int "$FIXED_IP")"
        base=$(($(ip_to_int "${VPN_SUBNET%/*}") & ((0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF)))
        if ((n == base || n == base + (1 << (32 - bits)) - 1)); then
            die "$FIXED_IP is the network or broadcast address of $VPN_SUBNET"
        fi
    fi

    require_root
    require_cmd wg jq yq openssl flock
    require_yq || exit 1
    ((WANT_QR)) && require_cmd qrencode
    [[ -f "$WG_CONF" ]] || die "$WG_CONF not found; run wireguard-setup.sh first"
    [[ "$(cat "$WG_SERVER_PUBKEY" 2>/dev/null)" =~ ^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$ ]] ||
        die "Server public key $WG_SERVER_PUBKEY is missing or invalid"
    if ((WANT_CERT)); then
        pki_ca_exists || die "No CA at $PKI_CA_DIR; run pki-setup.sh first"
        ((${#PEER} <= 64)) || die "Certificate name $PEER is longer than 64 characters"
    fi

    # A dry run takes no locks: taking one creates a lock file.
    if ((!DRY_RUN)); then
        ztvpn_lock users
        ztvpn_lock wg
        ((WANT_CERT)) && ztvpn_lock pki
        ztvpn_lock inventory
    fi

    case "$AUTHELIA_BACKEND" in
        file)
            authelia_user_exists "$USERNAME" ||
                die "No Authelia user $USERNAME; create it with add-user.sh first"
            [[ "$(authelia_user_field "$USERNAME" disabled)" != true ]] ||
                die "Authelia user $USERNAME is disabled"
            ;;
        ldap) warn "AUTHELIA_BACKEND=ldap: cannot verify that $USERNAME exists in the directory" ;;
        *) die "Unsupported AUTHELIA_BACKEND: $AUTHELIA_BACKEND" ;;
    esac
    wg_peer_exists "$PEER" && die "Peer $PEER already exists"
    [[ -e "$WG_CLIENTS_DIR/$PEER" ]] && die "$WG_CLIENTS_DIR/$PEER already exists"
    if [[ -n "$(inventory_read | jq -r --arg id "$PEER" '.devices[] | select(.id == $id and .status == "active") | .id')" ]]; then
        die "Device $PEER is already active in the inventory"
    fi
    if ((WANT_CERT)) && [[ -n "$(pki_valid_serials "$PEER")" ]]; then
        die "A valid certificate for $PEER already exists; revoke it first"
    fi

    local ip="$FIXED_IP"
    if [[ -n "$ip" ]]; then
        if wg_ip_in_use "$ip"; then
            local owner
            owner="$(wg_peer_by_ip "$ip" || true)"
            die "$ip is already in use${owner:+ by peer $owner}"
        fi
    else
        ip="$(wg_next_free_ip)" || die "No free address in $VPN_SUBNET"
    fi

    if ((DRY_RUN)); then
        info "DRY RUN: would create peer $PEER ($DEVICE_TYPE) with $ip in $WG_CONF"
        ((WANT_CERT)) && info "DRY RUN: would issue client certificate CN=$PEER"
        ((WANT_QR)) && info "DRY RUN: would write QR code $WG_CLIENTS_DIR/$PEER/$PEER.png"
        info "DRY RUN: would add $PEER to $DEVICE_INVENTORY"
        printf 'peer=%s\nip=%s\ndry_run=1\n' "$PEER" "$ip"
        return 0
    fi

    trap enroll_rollback EXIT
    PEER_ATTEMPTED=1
    ip="$(wg_provision_peer "$PEER" "$ip")"
    validate_ipv4 "$ip" || die "Peer provisioning returned an invalid address"
    wg_apply
    success "WireGuard peer $PEER added with $ip"

    local cert=""
    if ((WANT_CERT)); then
        CERT_ATTEMPTED=1
        cert="$(pki_issue client "$PEER")"
        success "Client certificate issued: $cert"
    fi

    local conf="$WG_CLIENTS_DIR/$PEER/$PEER.conf"
    if ((WANT_QR)); then
        QR_FILE="$WG_CLIENTS_DIR/$PEER/$PEER.png"
        (umask 077; qrencode -t PNG -r "$conf" -o "$QR_FILE")
        chmod 600 "$QR_FILE"
    fi

    local expiry=""
    [[ -n "$cert" ]] && expiry="$(openssl x509 -in "$cert" -noout -enddate | sed 's/^notAfter=//')"

    inventory_init
    # Replace an old revoked entry with the same id instead of duplicating it.
    inventory_edit '.devices |= (map(select(.id != $id)) + [{
            id: $id, username: $user, device_name: $dev, device_type: $type, peer: $id,
            ip_address: $ip, public_key: $pub,
            certificate: (if $cert == "" then null else $cert end),
            certificate_expiry: (if $exp == "" then null else $exp end),
            enrolled_date: $ts, status: "active"}])' \
        --arg id "$PEER" --arg user "$USERNAME" --arg dev "$DEVICE" --arg type "$DEVICE_TYPE" \
        --arg ip "$ip" --arg pub "$(<"$WG_CLIENTS_DIR/$PEER/public.key")" \
        --arg cert "$cert" --arg exp "$expiry" --arg ts "$(date -Iseconds)"

    audit enroll-device "user=$USERNAME peer=$PEER ip=$ip type=$DEVICE_TYPE cert=$WANT_CERT"
    COMMITTED=1
    trap - EXIT
    success "Device $PEER enrolled"
    printf 'peer=%s\nip=%s\nclient_config=%s\n' "$PEER" "$ip" "$conf"
    [[ -n "$cert" ]] && printf 'cert=%s\n' "$cert"
    [[ -n "$QR_FILE" ]] && printf 'qr=%s\n' "$QR_FILE"
    return 0
}

# --------------------------------------------------------------------------
# remove
# --------------------------------------------------------------------------

cmd_remove() {
    check_user
    check_device
    case "$REASON" in
        unspecified|keyCompromise|affiliationChanged|superseded|cessationOfOperation|certificateHold) ;;
        *) die "Invalid CRL reason: $REASON" ;;
    esac
    require_root
    require_cmd wg jq openssl flock
    ztvpn_lock wg
    ztvpn_lock pki
    ztvpn_lock inventory

    local -a failures=()
    local found=0 archive rc f
    archive="$ZTVPN_BACKUP_DIR/revoked/$PEER-$(date +%Y%m%dT%H%M%S)"

    if wg_peer_exists "$PEER" || [[ -e "$WG_CLIENTS_DIR/$PEER" ]]; then
        found=1
        (umask 077; mkdir -p "$archive")
        chmod 700 "$ZTVPN_BACKUP_DIR/revoked"
        if wg_deprovision_peer "$PEER" "$archive/wireguard"; then
            success "WireGuard peer $PEER removed"
        else
            failures+=("remove WireGuard peer $PEER")
        fi
        wg_apply || failures+=("apply $WG_CONF")
    fi

    if [[ -f "$PKI_CA_DIR/index.txt" ]]; then
        rc=0
        pki_revoke "$PEER" "$REASON" || rc=$?
        case "$rc" in
            0) found=1; success "Certificates for $PEER revoked" ;;
            2) ;;
            *) failures+=("revoke certificate $PEER") ;;
        esac
        for f in "$PKI_CLIENTS_DIR/$PEER.key" "$PKI_CLIENTS_DIR/$PEER.crt"; do
            [[ -f "$f" ]] || continue
            found=1
            (umask 077; mkdir -p "$archive/certs" && mv -f "$f" "$archive/certs/") ||
                failures+=("archive $f")
        done
    fi

    if [[ -f "$DEVICE_INVENTORY" ]] &&
        jq -e --arg id "$PEER" 'any(.devices[]; .id == $id and .status != "revoked")' "$DEVICE_INVENTORY" >/dev/null; then
        found=1
        inventory_edit '.devices |= map(if .id == $id then .status = "revoked" | .revoked_date = $ts | .revoke_reason = $r else . end)' \
            --arg id "$PEER" --arg ts "$(date -Iseconds)" --arg r "$REASON" ||
            failures+=("update $DEVICE_INVENTORY")
    fi

    ((found)) || die "Nothing found for device $PEER"
    if ((${#failures[@]})); then
        audit remove-device "user=$USERNAME peer=$PEER result=partial"
        error "Removal of $PEER INCOMPLETE. Failed steps:"
        for f in "${failures[@]}"; do error "  - $f"; done
        exit 1
    fi
    audit remove-device "user=$USERNAME peer=$PEER reason=$REASON result=ok"
    success "Device $PEER removed"
}

# --------------------------------------------------------------------------
# list / show
# --------------------------------------------------------------------------

cmd_list() {
    [[ -z "$USERNAME" ]] || check_user
    require_cmd jq
    local filter='.devices | map(select($u == "" or .username == $u))'
    if ((JSON)); then
        inventory_read | jq --arg u "$USERNAME" "$filter"
    else
        inventory_read | jq -r --arg u "$USERNAME" "$filter"' | (["ID","USER","TYPE","IP","STATUS","ENROLLED"] | @tsv),
            (.[] | [.id, .username, (.device_type // "-"), (.ip_address // "-"), .status, (.enrolled_date // "-")] | @tsv)'
    fi
}

cmd_show() {
    check_user
    check_device
    require_cmd jq
    local entry live_ip=""
    entry="$(inventory_read | jq --arg id "$PEER" '.devices | map(select(.id == $id)) | last')"
    live_ip="$(wg_peer_ip "$PEER" || true)"
    [[ "$entry" != null || -n "$live_ip" ]] || die "Unknown device $PEER"
    jq -n --argjson e "$entry" --arg ip "$live_ip" --arg peer "$PEER" \
        '($e // {id: $peer, status: "not-in-inventory"}) + {wireguard_peer_present: ($ip != ""), wireguard_ip: (if $ip == "" then null else $ip end)}'
}

case "$COMMAND" in
    enroll) cmd_enroll ;;
    remove) cmd_remove ;;
    list)   cmd_list ;;
    show)   cmd_show ;;
esac
