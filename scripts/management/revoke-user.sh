#!/usr/bin/env bash
# Removes every kind of access a user has: Authelia account, all WireGuard
# peers ("<user>" and "<user>--<device>") and all client certificates.
#
# Every step runs even if an earlier one failed; failures are collected and
# reported at the end with a non-zero exit code.
set -Eeuo pipefail

# shellcheck source=scripts/lib/common.sh
source "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/../lib/common.sh"

usage() {
    cat <<EOF
Usage: $(basename "$0") <username> [options]

Revokes all access of <username>:
  * Authelia account disabled (file backend) or LDAP_DISABLE_HOOK run (ldap)
  * all WireGuard peers of the user removed from $WG_CONF and the live
    interface; key material archived under \$ZTVPN_BACKUP_DIR/revoked/
  * all client certificates with CN <user> or <user>--<device> revoked, CRL regenerated
  * device inventory entries marked revoked, audit log line written

Matching is exact: revoking "bob" never touches "bobby".

Options:
  --reason <r>       CRL reason: unspecified, keyCompromise, affiliationChanged,
                     superseded, cessationOfOperation (default), certificateHold
  --keep-account     Leave the Authelia account enabled (only revoke VPN/certs)
  --delete-account   Delete the account from the users database instead of disabling it
  -h, --help         Show this help

Exit codes: 0 all done, 1 at least one step failed, 2 done but a manual step
remains (e.g. disabling a directory account on the ldap backend).
EOF
}

REASON="cessationOfOperation" ACCOUNT_MODE="disable" USERNAME=""

need_value() { [[ $# -ge 2 && -n "$2" ]] || die "Option $1 requires a value"; }

positional=()
while (($#)); do
    case "$1" in
        -h|--help) usage; exit 0 ;;
        --reason) need_value "$@"; REASON="$2"; shift 2 ;;
        --keep-account)
            [[ "$ACCOUNT_MODE" == delete ]] && die "--keep-account and --delete-account are exclusive"
            ACCOUNT_MODE=keep; shift ;;
        --delete-account)
            [[ "$ACCOUNT_MODE" == keep ]] && die "--keep-account and --delete-account are exclusive"
            ACCOUNT_MODE=delete; shift ;;
        --) shift; positional+=("$@"); break ;;
        -*) die "Unknown option: $1 (see --help)" ;;
        *) positional+=("$1"); shift ;;
    esac
done
((${#positional[@]} == 1)) || { usage >&2; exit 1; }
USERNAME="${positional[0]}"

validate_username "$USERNAME" && [[ "$USERNAME" != *--* ]] || die "Invalid username: $USERNAME"
case "$REASON" in
    unspecified|keyCompromise|affiliationChanged|superseded|cessationOfOperation|certificateHold) ;;
    *) die "Invalid CRL reason: $REASON" ;;
esac

require_root
require_cmd jq yq openssl flock
require_yq || exit 1

FAILURES=()
MANUAL=()
FOUND=0
fail() { error "$*"; FAILURES+=("$*"); }

audit() {
    (umask 027; mkdir -p "$ZTVPN_LOG_DIR" &&
        printf '%s %s actor=%s %s\n' "$(date -Iseconds)" "$1" "${SUDO_USER:-$(id -un)}" "$2" \
            >>"$ZTVPN_LOG_DIR/audit.log") || warn "Could not write audit log"
}

ztvpn_lock users
ztvpn_lock wg
ztvpn_lock pki
ztvpn_lock inventory

TS="$(date +%Y%m%dT%H%M%S)"
ARCHIVE="$ZTVPN_BACKUP_DIR/revoked/$USERNAME-$TS"
(umask 077; mkdir -p "$ARCHIVE") || fail "Cannot create archive directory $ARCHIVE"
chmod 700 "$ZTVPN_BACKUP_DIR/revoked" "$ARCHIVE" 2>/dev/null || true

# --------------------------------------------------------------------------
# 1. Account
# --------------------------------------------------------------------------
revoke_account() {
    if [[ "$ACCOUNT_MODE" == keep ]]; then
        info "Keeping the account of $USERNAME (--keep-account)"
        return 0
    fi
    case "$AUTHELIA_BACKEND" in
        file)
            if ! authelia_user_exists "$USERNAME"; then
                info "No Authelia account for $USERNAME in $AUTHELIA_USERS_DB"
                return 0
            fi
            FOUND=1
            if [[ "$ACCOUNT_MODE" == delete ]]; then
                # Keep a copy of the entry for the audit trail.
                U="$USERNAME" yq '.users[strenv(U)]' "$AUTHELIA_USERS_DB" \
                    | atomic_write "$ARCHIVE/authelia-user.yml" 600 || true
                if authelia_delete_user "$USERNAME"; then
                    success "Authelia account $USERNAME deleted"
                else
                    fail "Could not delete Authelia account $USERNAME"
                fi
            elif authelia_set_disabled "$USERNAME" true; then
                success "Authelia account $USERNAME disabled (open sessions end within Authelia's refresh_interval)"
            else
                fail "Could not disable Authelia account $USERNAME"
            fi
            ;;
        ldap)
            FOUND=1
            if [[ -n "${LDAP_DISABLE_HOOK:-}" ]]; then
                if [[ ! -x "$LDAP_DISABLE_HOOK" ]]; then
                    fail "LDAP_DISABLE_HOOK $LDAP_DISABLE_HOOK is not executable"
                elif "$LDAP_DISABLE_HOOK" "$USERNAME" "$ACCOUNT_MODE"; then
                    success "Directory account $USERNAME handled by $LDAP_DISABLE_HOOK"
                else
                    fail "LDAP_DISABLE_HOOK failed for $USERNAME"
                fi
            else
                warn "AUTHELIA_BACKEND=ldap and no LDAP_DISABLE_HOOK configured"
                MANUAL+=("Disable (or remove from all groups) the directory account $USERNAME; Authelia still accepts its logins")
            fi
            ;;
        *) fail "Unsupported AUTHELIA_BACKEND: $AUTHELIA_BACKEND" ;;
    esac
}

# --------------------------------------------------------------------------
# 2. WireGuard peers
# --------------------------------------------------------------------------
declare -A PEERS=()
revoke_peers() {
    local p d name
    while IFS= read -r p; do [[ -n "$p" ]] && PEERS["$p"]=1; done < <(wg_user_peers "$USERNAME")
    # Client directories without a server entry still hold keys.
    if [[ -d "$WG_CLIENTS_DIR" ]]; then
        for d in "$WG_CLIENTS_DIR"/*/; do
            [[ -d "$d" ]] || continue
            name="$(basename "$d")"
            [[ "$name" == "$USERNAME" || "$name" == "$USERNAME--"* ]] && PEERS["$name"]=1
        done
    fi
    if ((${#PEERS[@]} == 0)); then
        info "No WireGuard peers for $USERNAME"
        return 0
    fi
    FOUND=1
    for p in "${!PEERS[@]}"; do
        if wg_deprovision_peer "$p" "$ARCHIVE/wireguard"; then
            success "WireGuard peer $p removed"
        else
            fail "Could not remove WireGuard peer $p"
        fi
    done
    if [[ -f "$WG_CONF" ]]; then
        wg_apply || fail "Could not apply $WG_CONF to $WG_INTERFACE"
    fi
}

# --------------------------------------------------------------------------
# 3. Certificates
# --------------------------------------------------------------------------
revoke_certs() {
    if [[ ! -f "$PKI_CA_DIR/index.txt" ]]; then
        info "No CA database at $PKI_CA_DIR; no certificates to revoke"
        return 0
    fi
    declare -A names=(["$USERNAME"]=1)
    local p cn rc f
    for p in "${!PEERS[@]}"; do names["$p"]=1; done
    # Every valid CN in the CA database that belongs to the user.
    while IFS= read -r cn; do
        [[ "$cn" == "$USERNAME" || "$cn" == "$USERNAME--"* ]] && names["$cn"]=1
    done < <(awk -F'\t' '$1 == "V" { n = split($6, a, "/"); for (i = 1; i <= n; i++) if (a[i] ~ /^CN=/) print substr(a[i], 4) }' \
        "$PKI_CA_DIR/index.txt")

    for cn in "${!names[@]}"; do
        rc=0
        pki_revoke "$cn" "$REASON" || rc=$?
        case "$rc" in
            0) FOUND=1; success "Certificates for $cn revoked ($REASON)" ;;
            2) ;;
            *) fail "Could not revoke certificates for $cn" ;;
        esac
        # Take the key material out of the live directory.
        for f in "$PKI_CLIENTS_DIR/$cn.key" "$PKI_CLIENTS_DIR/$cn.crt"; do
            [[ -f "$f" ]] || continue
            FOUND=1
            if ! (umask 077; mkdir -p "$ARCHIVE/certs" && mv -f "$f" "$ARCHIVE/certs/"); then
                fail "Could not move $f to $ARCHIVE/certs"
            fi
        done
    done
}

# --------------------------------------------------------------------------
# 4. Inventory
# --------------------------------------------------------------------------
revoke_inventory() {
    [[ -f "$DEVICE_INVENTORY" ]] || return 0
    local out
    if ! out="$(jq --arg u "$USERNAME" --arg ts "$(date -Iseconds)" --arg r "$REASON" '
            .devices |= map(if .username == $u and .status != "revoked"
                            then .status = "revoked" | .revoked_date = $ts | .revoke_reason = $r
                            else . end)' "$DEVICE_INVENTORY")"; then
        fail "Could not update $DEVICE_INVENTORY"
        return 0
    fi
    printf '%s\n' "$out" | atomic_write "$DEVICE_INVENTORY" 600 || fail "Could not write $DEVICE_INVENTORY"
}

log "Revoking access of $USERNAME (reason: $REASON)"
revoke_account
revoke_peers
revoke_certs
revoke_inventory
# Nothing archived (e.g. a re-run): do not leave an empty directory behind.
rmdir "$ARCHIVE" 2>/dev/null && ARCHIVE="(nothing archived)"

if ((FOUND == 0 && ${#FAILURES[@]} == 0)); then
    audit revoke-user "user=$USERNAME result=not-found"
    die "Nothing found for $USERNAME: no account, peers or certificates"
fi

if ((${#FAILURES[@]})); then
    audit revoke-user "user=$USERNAME reason=$REASON account=$ACCOUNT_MODE result=partial failures=${#FAILURES[@]}"
    error "Revocation of $USERNAME INCOMPLETE. Failed steps:"
    for f in "${FAILURES[@]}"; do error "  - $f"; done
    for f in "${MANUAL[@]}"; do warn "  MANUAL: $f"; done
    exit 1
fi
if ((${#MANUAL[@]})); then
    audit revoke-user "user=$USERNAME reason=$REASON account=$ACCOUNT_MODE result=manual-pending"
    warn "Revocation of $USERNAME done except for manual steps:"
    for f in "${MANUAL[@]}"; do warn "  MANUAL: $f"; done
    exit 2
fi
audit revoke-user "user=$USERNAME reason=$REASON account=$ACCOUNT_MODE result=ok archive=$ARCHIVE"
success "All access of $USERNAME revoked; key material archive: $ARCHIVE"
