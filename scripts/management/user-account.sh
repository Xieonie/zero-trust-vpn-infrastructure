#!/usr/bin/env bash
# Account maintenance for the Authelia file backend: password resets and
# enabling/disabling accounts. The scripts are the only writer of the users
# database (Authelia mounts it read-only), so this is also how users get a
# new password: the portal's own reset and change flows are disabled.
set -Eeuo pipefail

# shellcheck source=scripts/lib/common.sh
source "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/../lib/common.sh"

LOG_FILE="$ZTVPN_LOG_DIR/user-management.log"

usage() {
    cat <<EOF
Usage: $(basename "$0") <command> <username>

Commands:
  reset-password <user>   Set a new random password. It is written to a 0600
                          file under \$ZTVPN_SECRETS_DIR/onboarding/ and only
                          the path is printed.
  enable <user>           Re-enable a disabled account. VPN peers and
                          certificates removed by revoke-user.sh are not
                          restored; enrol devices again with add-user.sh
                          --no-vpn / device-enrollment.sh.
  disable <user>          Disable the account without touching VPN peers or
                          certificates (use revoke-user.sh to remove all access).
  show <user>             Print account state as JSON (no password hash).

Only for AUTHELIA_BACKEND=file. Authelia picks up the change through its
file watcher; existing sessions of a disabled user end at the next
authentication refresh (refresh_interval in configuration.yml).

Options:
  -h, --help              Show this help
EOF
}

(($# >= 1)) || { usage >&2; exit 1; }
case "$1" in
    -h|--help|help) usage; exit 0 ;;
    reset-password|enable|disable|show) COMMAND="$1" ;;
    *) die "Unknown command: $1 (see --help)" ;;
esac
shift
(($# == 1)) || { usage >&2; exit 1; }
USERNAME="$1"

validate_username "$USERNAME" || die "Invalid username: $USERNAME"
[[ "$AUTHELIA_BACKEND" == file ]] ||
    die "AUTHELIA_BACKEND=$AUTHELIA_BACKEND: manage accounts in the directory"
require_yq

if [[ "$COMMAND" == show ]]; then
    authelia_user_exists "$USERNAME" || die "Authelia user $USERNAME not found"
    U="$USERNAME" yq -o=json '.users[strenv(U)] | del(.password)' "$AUTHELIA_USERS_DB"
    exit 0
fi

require_root
ztvpn_lock users
authelia_user_exists "$USERNAME" || die "Authelia user $USERNAME not found"

case "$COMMAND" in
    reset-password)
        password="$(gen_password 24)"
        hash="$(printf '%s\n' "$password" | authelia_hash_password)" || die "Hashing failed"
        (umask 077; mkdir -p "$ZTVPN_SECRETS_DIR/onboarding")
        chmod 700 "$ZTVPN_SECRETS_DIR/onboarding"
        file="$ZTVPN_SECRETS_DIR/onboarding/$USERNAME-password-$(date +%Y%m%dT%H%M%S).txt"
        {
            printf 'New password for %s\n\n' "$USERNAME"
            printf 'Login:     https://%s\n' "$AUTH_DOMAIN"
            printf 'Username:  %s\n' "$USERNAME"
            printf 'Password:  %s\n' "$password"
            printf '\nDeliver over a secure channel and delete this file afterwards.\n'
        } | atomic_write "$file" 600
        unset password
        if ! authelia_set_password_hash "$USERNAME" "$hash"; then
            rm -f "$file"
            die "Could not update the password of $USERNAME"
        fi
        audit reset-password "user=$USERNAME"
        success "Password of $USERNAME reset"
        printf 'onboarding=%s\n' "$file"
        ;;
    enable)
        authelia_set_disabled "$USERNAME" false || die "Could not enable $USERNAME"
        audit enable-user "user=$USERNAME"
        success "Account $USERNAME enabled"
        ;;
    disable)
        authelia_set_disabled "$USERNAME" true || die "Could not disable $USERNAME"
        audit disable-user "user=$USERNAME"
        success "Account $USERNAME disabled (VPN peers and certificates unchanged)"
        ;;
esac
