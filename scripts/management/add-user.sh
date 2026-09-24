#!/usr/bin/env bash
# Creates a VPN user: Authelia account, WireGuard peer and optionally a
# client certificate and a QR code of the client config.
#
# All-or-nothing: if any step fails, everything created so far is removed
# again (peer, certificate, account, onboarding file).
set -Eeuo pipefail

# shellcheck source=scripts/lib/common.sh
source "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/../lib/common.sh"

usage() {
    cat <<EOF
Usage: $(basename "$0") <username> <email> [options]

Creates the Authelia account (file backend) with a random one-time password
and provisions a WireGuard peer for the user.

Options:
  --name "Display Name"  Display name (default: the username)
  --groups g1,g2         Extra groups on top of DEFAULT_USER_GROUPS ($DEFAULT_USER_GROUPS)
                         Allowed: $KNOWN_GROUPS
  --admin                Also add the user to "admins"
  --device <name>        Name the first device; peer becomes "<user>--<name>"
  --cert                 Issue a client certificate (CN = peer name)
  --qr                   Write a QR code PNG of the client config (needs qrencode)
  --no-vpn               Only create the account, no WireGuard peer
  -h, --help             Show this help

The one-time password is written to a 0600 file under
$ZTVPN_SECRETS_DIR/onboarding/ and only its path is printed. Nothing is
emailed; hand the file and the client config to the user over a secure channel.

Output (stdout) is key=value lines: user, peer, ip, client_config, cert, qr, onboarding.
EOF
}

USERNAME="" EMAIL="" DISPLAY_NAME="" EXTRA_GROUPS="" DEVICE=""
ADMIN=0 WANT_CERT=0 WANT_QR=0 WANT_VPN=1

positional=()
while (($#)); do
    case "$1" in
        -h|--help) usage; exit 0 ;;
        --name)    need_value "$@"; DISPLAY_NAME="$2"; shift 2 ;;
        --groups)  need_value "$@"; EXTRA_GROUPS="$2"; shift 2 ;;
        --device)  need_value "$@"; DEVICE="$2"; shift 2 ;;
        --admin)   ADMIN=1; shift ;;
        --cert)    WANT_CERT=1; shift ;;
        --qr)      WANT_QR=1; shift ;;
        --no-vpn)  WANT_VPN=0; shift ;;
        --) shift; positional+=("$@"); break ;;
        -*) die "Unknown option: $1 (see --help)" ;;
        *)  positional+=("$1"); shift ;;
    esac
done
((${#positional[@]} == 2)) || { usage >&2; exit 1; }
USERNAME="${positional[0]}"
EMAIL="${positional[1]}"
DISPLAY_NAME="${DISPLAY_NAME:-$USERNAME}"

# --------------------------------------------------------------------------
# Validation (nothing is touched before all of this passed)
# --------------------------------------------------------------------------

# "--" separates user and device in peer names, so it may not appear in a username.
validate_username "$USERNAME" && [[ "$USERNAME" != *--* ]] || die "Invalid username: $USERNAME"
validate_email "$EMAIL" || die "Invalid email: $EMAIL"
validate_display_name "$DISPLAY_NAME" || die "Invalid display name"
if [[ -n "$DEVICE" ]]; then
    validate_device_name "$DEVICE" || die "Invalid device name: $DEVICE"
fi
if ((!WANT_VPN)); then
    [[ -z "$DEVICE" ]] || die "--device needs a WireGuard peer; drop --no-vpn"
    ((!WANT_QR)) || die "--qr needs a WireGuard peer; drop --no-vpn"
fi

declare -a GROUPS_LIST=()
declare -A seen=()
while IFS= read -r g; do
    validate_group "$g" || die "Invalid group name: $g"
    is_known_group "$g" || die "Unknown group: $g (allowed: $KNOWN_GROUPS)"
    [[ -n "${seen[$g]:-}" ]] && continue
    seen[$g]=1
    GROUPS_LIST+=("$g")
done < <(split_csv "$DEFAULT_USER_GROUPS"; split_csv "$EXTRA_GROUPS"; ((ADMIN)) && echo admins)
GROUPS_CSV="$(IFS=,; printf '%s' "${GROUPS_LIST[*]}")"

PEER="$USERNAME${DEVICE:+--$DEVICE}"
validate_peer_name "$PEER" || die "Invalid peer name: $PEER"
CERT_CN="$PEER"

require_root
require_cmd jq yq openssl flock
require_yq || exit 1
[[ "$AUTHELIA_BACKEND" == file ]] && require_cmd argon2
((WANT_VPN)) && require_cmd wg
((WANT_QR)) && require_cmd qrencode

if ((WANT_VPN)); then
    [[ -f "$WG_CONF" ]] || die "$WG_CONF not found; run wireguard-setup.sh first"
    [[ "$(cat "$WG_SERVER_PUBKEY" 2>/dev/null)" =~ ^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$ ]] ||
        die "Server public key $WG_SERVER_PUBKEY is missing or invalid"
fi
if ((WANT_CERT)); then
    pki_ca_exists || die "No CA at $PKI_CA_DIR; run pki-setup.sh first"
    ((${#CERT_CN} <= 64)) || die "Certificate name $CERT_CN is longer than 64 characters"
fi

# --------------------------------------------------------------------------
# Helpers (candidates for the shared lib)
# --------------------------------------------------------------------------

# --------------------------------------------------------------------------
# Transaction
# --------------------------------------------------------------------------

COMMITTED=0 USER_CREATED=0 PEER_ATTEMPTED=0 CERT_ATTEMPTED=0 INVENTORY_ADDED=0
QR_FILE="" ONBOARDING_FILE=""

rollback() {
    local rc=$?
    ((COMMITTED)) && return 0
    set +e
    ((rc == 0)) && rc=1
    if ((USER_CREATED || PEER_ATTEMPTED || CERT_ATTEMPTED)); then
        warn "Rolling back partial creation of $USERNAME"
    fi
    [[ -n "$ONBOARDING_FILE" ]] && rm -f "$ONBOARDING_FILE"
    [[ -n "$QR_FILE" ]] && rm -f "$QR_FILE"
    if ((INVENTORY_ADDED)); then
        inventory_edit '.devices |= map(select(.id != $id))' --arg id "$PEER" ||
            error "Rollback: could not remove $PEER from $DEVICE_INVENTORY"
    fi
    if ((CERT_ATTEMPTED)); then
        pki_revoke "$CERT_CN" cessationOfOperation
        case $? in
            0|2) rm -f "$PKI_CLIENTS_DIR/$CERT_CN.key" "$PKI_CLIENTS_DIR/$CERT_CN.crt" ;;
            *) error "Rollback: could not revoke certificate $CERT_CN; revoke it manually" ;;
        esac
    fi
    if ((PEER_ATTEMPTED)); then
        if wg_peer_exists "$PEER" || [[ -e "$WG_CLIENTS_DIR/$PEER" ]]; then
            wg_deprovision_peer "$PEER" || error "Rollback: could not remove peer $PEER"
            wg_apply || error "Rollback: could not apply $WG_CONF"
        fi
    fi
    if ((USER_CREATED)); then
        authelia_delete_user "$USERNAME" || error "Rollback: could not delete Authelia user $USERNAME"
    fi
    exit "$rc"
}

ztvpn_lock users
((WANT_VPN)) && ztvpn_lock wg
((WANT_CERT)) && ztvpn_lock pki
((WANT_VPN)) && ztvpn_lock inventory

# Checks that need the locks.
if [[ "$AUTHELIA_BACKEND" == file ]]; then
    authelia_user_exists "$USERNAME" && die "Authelia user $USERNAME already exists (use device-enrollment.sh to add devices)"
fi
if ((WANT_VPN)); then
    [[ -z "$(wg_user_peers "$USERNAME")" ]] || die "WireGuard peers for $USERNAME already exist (use device-enrollment.sh)"
    [[ ! -e "$WG_CLIENTS_DIR/$PEER" ]] || die "$WG_CLIENTS_DIR/$PEER already exists"
fi
if ((WANT_CERT)) && [[ -n "$(pki_valid_serials "$CERT_CN")" ]]; then
    die "A valid certificate for $CERT_CN already exists; revoke it first"
fi

trap rollback EXIT

# 1. Account
PASSWORD=""
case "$AUTHELIA_BACKEND" in
    file)
        PASSWORD="$(gen_password 20)"
        HASH="$(printf '%s\n' "$PASSWORD" | authelia_hash_password)"
        authelia_add_user "$USERNAME" "$DISPLAY_NAME" "$EMAIL" "$HASH" "$GROUPS_CSV"
        USER_CREATED=1
        unset HASH
        success "Authelia user $USERNAME created (groups: $GROUPS_CSV)"
        ;;
    ldap)
        warn "MANUAL: AUTHELIA_BACKEND=ldap; create $USERNAME in the directory with groups $GROUPS_CSV"
        ;;
    *) die "Unsupported AUTHELIA_BACKEND: $AUTHELIA_BACKEND" ;;
esac

# 2. WireGuard peer
IP="" CLIENT_CONF=""
if ((WANT_VPN)); then
    PEER_ATTEMPTED=1
    IP="$(wg_provision_peer "$PEER")"
    validate_ipv4 "$IP" || die "Peer provisioning returned an invalid address"
    CLIENT_CONF="$WG_CLIENTS_DIR/$PEER/$PEER.conf"
    wg_apply
    success "WireGuard peer $PEER added with $IP"
fi

# 3. Client certificate
CERT=""
if ((WANT_CERT)); then
    CERT_ATTEMPTED=1
    CERT="$(pki_issue client "$CERT_CN")"
    success "Client certificate issued: $CERT"
fi

# 4. QR code (file read by qrencode itself, the key never hits argv)
if ((WANT_QR)); then
    QR_FILE="$WG_CLIENTS_DIR/$PEER/$PEER.png"
    (umask 077; qrencode -t PNG -r "$CLIENT_CONF" -o "$QR_FILE")
    chmod 600 "$QR_FILE"
fi

# 5. Device inventory
if ((WANT_VPN)); then
    inventory_init
    inventory_edit '.devices += [{
            id: $id, username: $user, device_name: (if $dev == "" then null else $dev end),
            device_type: "unknown", peer: $id, ip_address: $ip, public_key: $pub,
            certificate: (if $cert == "" then null else $cert end),
            enrolled_date: $ts, status: "active"}]' \
        --arg id "$PEER" --arg user "$USERNAME" --arg dev "$DEVICE" --arg ip "$IP" \
        --arg pub "$(<"$WG_CLIENTS_DIR/$PEER/public.key")" --arg cert "$CERT" --arg ts "$(date -Iseconds)"
    INVENTORY_ADDED=1
fi

# 6. Onboarding file with the one-time credentials
if [[ -n "$PASSWORD" ]]; then
    (umask 077; mkdir -p "$ZTVPN_SECRETS_DIR/onboarding")
    chmod 700 "$ZTVPN_SECRETS_DIR/onboarding"
    ONBOARDING_FILE="$ZTVPN_SECRETS_DIR/onboarding/$USERNAME-$(date +%Y%m%dT%H%M%S).txt"
    {
        printf 'Zero Trust VPN onboarding for %s\n\n' "$USERNAME"
        printf 'Login:              https://%s\n' "$AUTH_DOMAIN"
        printf 'Username:           %s\n' "$USERNAME"
        printf 'One-time password:  %s\n' "$PASSWORD"
        printf '\nEnrol a second factor (TOTP or WebAuthn) at first login. Password resets:\nscripts/management/user-account.sh reset-password %s\n' "$USERNAME"
        [[ -n "$CLIENT_CONF" ]] && printf 'WireGuard config:   %s\n' "$CLIENT_CONF"
        [[ -n "$QR_FILE" ]] && printf 'WireGuard QR code:  %s\n' "$QR_FILE"
        [[ -n "$CERT" ]] && printf 'Client certificate: %s (key: %s)\n' "$CERT" "$PKI_CLIENTS_DIR/$CERT_CN.key"
        printf '\nDeliver over a secure channel and delete this file afterwards.\n'
    } | atomic_write "$ONBOARDING_FILE" 600
fi
unset PASSWORD

audit add-user "user=$USERNAME peer=${IP:+$PEER} ip=$IP groups=$GROUPS_CSV cert=$WANT_CERT backend=$AUTHELIA_BACKEND"
COMMITTED=1
trap - EXIT

success "User $USERNAME created"
printf 'user=%s\n' "$USERNAME"
if ((WANT_VPN)); then
    printf 'peer=%s\nip=%s\nclient_config=%s\n' "$PEER" "$IP" "$CLIENT_CONF"
fi
[[ -n "$CERT" ]] && printf 'cert=%s\n' "$CERT"
[[ -n "$QR_FILE" ]] && printf 'qr=%s\n' "$QR_FILE"
[[ -n "$ONBOARDING_FILE" ]] && printf 'onboarding=%s\n' "$ONBOARDING_FILE"
exit 0
