#!/usr/bin/env bash
# Reconciles VPN access with the directory (LDAP / Active Directory).
#
# With AUTHELIA_BACKEND=ldap Authelia already authenticates against the
# directory, so there is nothing to copy. What can drift is VPN access:
# WireGuard peers (and, with the file backend, Authelia file users) that
# belong to people who have since been removed or disabled in the
# directory. This script finds those and, with --apply, revokes them.
#
# The default is a dry run. An LDAP error never counts as "user missing".

set -Eeuo pipefail
# shellcheck source=scripts/lib/common.sh
source "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/../lib/common.sh"

LOG_FILE="${LOG_FILE:-$ZTVPN_LOG_DIR/user-sync.log}"
LDAP_URI="${LDAP_URI:-}"
LDAP_BASE_DN="${LDAP_BASE_DN:-}"
LDAP_BIND_DN="${LDAP_BIND_DN:-}"
LDAP_BIND_PASSWORD_FILE="${LDAP_BIND_PASSWORD_FILE:-$ZTVPN_SECRETS_DIR/ldap_bind_password}"
# openldap | ad
LDAP_FLAVOR="${LDAP_FLAVOR:-openldap}"
LDAP_USER_FILTER="${LDAP_USER_FILTER:-}"
# Optional DN of a group whose members may use the VPN (checked via memberOf).
LDAP_REQUIRED_GROUP="${LDAP_REQUIRED_GROUP:-}"
# Optional CA bundle for the directory's TLS certificate.
LDAP_CA_CERT="${LDAP_CA_CERT:-}"
LDAP_TIMEOUT="${LDAP_TIMEOUT:-15}"
SYNC_MAX_REVOKE="${SYNC_MAX_REVOKE:-5}"
# Comma separated local accounts that are not in the directory on purpose
# (e.g. a break-glass admin). They are reported but never revoked.
SYNC_IGNORE_USERS="${SYNC_IGNORE_USERS:-}"

usage() {
    cat <<EOF
Usage: $(basename "$0") [--apply] [--force] [--max-revoke N] [--json]

Checks every VPN identity against the directory:
  * owners of WireGuard peers in $WG_CONF
  * users in $AUTHELIA_USERS_DB (only when AUTHELIA_BACKEND=file)
A user that is missing, disabled/locked, or not in LDAP_REQUIRED_GROUP loses VPN access:
peers removed (archived under $ZTVPN_BACKUP_DIR/user-sync), client certificates revoked,
Authelia file account disabled.

  --apply          Actually revoke. Without it nothing is changed (dry run).
  --max-revoke N   Refuse to revoke more than N users in one run (default $SYNC_MAX_REVOKE)
  --force          Ignore --max-revoke
  --json           Print results as JSON
  -h, --help       Show this help

Configuration (ztvpn.conf):
  LDAP_URI                 ldaps://host[:port] or ldap://host (StartTLS is then required)
  LDAP_BASE_DN             Search base for users
  LDAP_BIND_DN             Bind DN (empty = anonymous bind)
  LDAP_BIND_PASSWORD_FILE  File with the bind password, mode 0600 (default $LDAP_BIND_PASSWORD_FILE)
  LDAP_FLAVOR              openldap (uid, pwdAccountLockedTime) or ad (sAMAccountName,
                           userAccountControl bit 2 = disabled)
  LDAP_USER_FILTER         Extra filter ANDed into the search, e.g. (objectClass=inetOrgPerson)
  LDAP_REQUIRED_GROUP      Group DN required in memberOf (optional)
  LDAP_CA_CERT             CA bundle for the directory certificate (optional)
  SYNC_IGNORE_USERS        Comma separated local accounts that are never revoked
EOF
}

# --------------------------------------------------------------------------
# LDAP
# --------------------------------------------------------------------------

WORK=""
PWFILE=""
LDAP_ARGS=()
UID_ATTR=""

# RFC 4515 escaping for a value inside a filter.
ldap_escape() {
    local v="$1"
    v="${v//\\/\\5c}"
    v="${v//\*/\\2a}"
    v="${v//(/\\28}"
    v="${v//)/\\29}"
    printf '%s' "$v"
}

validate_ldap_config() {
    [[ -n "$LDAP_URI" ]] || die "LDAP_URI is not set"
    [[ "$LDAP_URI" =~ ^ldaps?://[A-Za-z0-9.-]+(:[0-9]{1,5})?/?$ ]] ||
        die "LDAP_URI must be a single ldaps://host[:port] or ldap://host[:port] URI"
    [[ -n "$LDAP_BASE_DN" && "$LDAP_BASE_DN" =~ ^[[:print:]]+$ ]] || die "LDAP_BASE_DN is not set or invalid"
    [[ -z "$LDAP_BIND_DN" || "$LDAP_BIND_DN" =~ ^[[:print:]]+$ ]] || die "LDAP_BIND_DN is invalid"
    [[ "$LDAP_TIMEOUT" =~ ^[1-9][0-9]{0,2}$ ]] || die "LDAP_TIMEOUT is invalid"
    case "${LDAPTLS_REQCERT:-}" in
        never | allow) die "LDAPTLS_REQCERT=${LDAPTLS_REQCERT} disables certificate verification; refusing" ;;
    esac
    case "$LDAP_FLAVOR" in
        openldap) UID_ATTR=uid; : "${LDAP_USER_FILTER:=(objectClass=person)}" ;;
        ad) UID_ATTR=sAMAccountName; : "${LDAP_USER_FILTER:=(&(objectCategory=person)(objectClass=user))}" ;;
        *) die "LDAP_FLAVOR must be openldap or ad" ;;
    esac
    [[ "$LDAP_USER_FILTER" == \(*\) && "$LDAP_USER_FILTER" != *$'\n'* ]] || die "LDAP_USER_FILTER must be a parenthesised filter"
    if [[ -n "$LDAP_CA_CERT" ]]; then
        [[ -f "$LDAP_CA_CERT" ]] || die "LDAP_CA_CERT $LDAP_CA_CERT not found"
        export LDAPTLS_CACERT="$LDAP_CA_CERT"
    fi
    export LDAPTLS_REQCERT=demand

    LDAP_ARGS=(-LLL -x -H "$LDAP_URI" -o ldif-wrap=no -o "nettimeout=$LDAP_TIMEOUT" -l "$LDAP_TIMEOUT")
    # Plain ldap:// is only accepted with mandatory StartTLS.
    [[ "$LDAP_URI" == ldap://* ]] && LDAP_ARGS+=(-ZZ)

    if [[ -n "$LDAP_BIND_DN" ]]; then
        local f="$LDAP_BIND_PASSWORD_FILE" perms owner
        [[ -f "$f" ]] || die "Bind password file $f not found"
        perms="$(stat -c %a "$f")"
        owner="$(stat -c %u "$f")"
        (((8#$perms & 8#077) == 0)) || die "Bind password file $f must not be group/world accessible (mode $perms)"
        [[ "$owner" == 0 || "$owner" == "$(id -u)" ]] || die "Bind password file $f has an unexpected owner"
        # ldapsearch -y uses the file byte for byte; drop a trailing newline.
        local pw
        pw="$(<"$f")"
        [[ -n "$pw" ]] || die "Bind password file $f is empty"
        PWFILE="$WORK/bindpw"
        printf '%s' "$pw" >"$PWFILE"
        unset pw
        LDAP_ARGS+=(-D "$LDAP_BIND_DN" -y "$PWFILE")
    else
        warn "LDAP_BIND_DN is empty, using an anonymous bind"
    fi
}

# Reads -LLL LDIF on stdin; prints "<entry>\t<attr-lowercase>\t<value>".
# Folded lines are joined and "attr:: base64" values decoded.
LDIF_ENTRY=0
_ldif_emit() {
    local l="$1" attr val
    [[ "$l" == *:* ]] || return 0
    attr="${l%%:*}"
    val="${l#*:}"
    attr="${attr%%;*}"
    [[ "${attr,,}" == dn ]] && LDIF_ENTRY=$((LDIF_ENTRY + 1))
    if [[ "$val" == :* ]]; then
        val="$(printf '%s' "${val#:}" | tr -d ' ' | base64 -d 2>/dev/null)" || {
            warn "Undecodable base64 value for attribute $attr"
            return 0
        }
    elif [[ "$val" == \<* ]]; then
        return 0
    else
        val="${val# }"
    fi
    val="${val//[$'\t\r\n']/ }"
    printf '%s\t%s\t%s\n' "$LDIF_ENTRY" "${attr,,}" "$val"
}

parse_ldif() {
    local line logical=""
    LDIF_ENTRY=0
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%$'\r'}"
        if [[ "$line" == " "* && -n "$logical" ]]; then
            logical+="${line:1}"
            continue
        fi
        [[ -n "$logical" ]] && _ldif_emit "$logical"
        logical="$line"
    done
    [[ -n "$logical" ]] && _ldif_emit "$logical"
    return 0
}

# Prints one of: active, missing, disabled, not-in-group, ambiguous.
# Returns 1 if the directory could not be queried.
ldap_user_status() {
    local user="$1" filter out rc=0
    filter="(&${LDAP_USER_FILTER}(${UID_ATTR}=$(ldap_escape "$user")))"
    local -a attrs
    if [[ "$LDAP_FLAVOR" == ad ]]; then
        attrs=(sAMAccountName userAccountControl memberOf)
    else
        attrs=(uid pwdAccountLockedTime memberOf)
    fi
    out="$(ldapsearch "${LDAP_ARGS[@]}" -b "$LDAP_BASE_DN" -s sub "$filter" "${attrs[@]}" 2>"$WORK/ldap.err")" || rc=$?
    if ((rc != 0)); then
        error "ldapsearch failed for $user (exit $rc): $(head -c 300 "$WORK/ldap.err" | tr '\n' ' ')"
        return 1
    fi

    local parsed
    parsed="$(parse_ldif <<<"$out")"
    # Entries whose naming attribute equals the user (case-insensitive,
    # AD compares sAMAccountName that way).
    local -a entries
    mapfile -t entries < <(awk -F'\t' -v a="${UID_ATTR,,}" -v u="${user,,}" '$2 == a && tolower($3) == u { print $1 }' <<<"$parsed" | sort -u)
    if ((${#entries[@]} == 0)); then
        echo missing
        return 0
    fi
    if ((${#entries[@]} > 1)); then
        echo ambiguous
        return 0
    fi
    local e="${entries[0]}"
    if [[ "$LDAP_FLAVOR" == ad ]]; then
        local uac
        uac="$(awk -F'\t' -v e="$e" '$1 == e && $2 == "useraccountcontrol" { print $3; exit }' <<<"$parsed")"
        if [[ ! "$uac" =~ ^[0-9]+$ ]]; then
            error "No readable userAccountControl for $user; treating as error"
            return 1
        fi
        ((uac & 2)) && { echo disabled; return 0; }
    else
        if awk -F'\t' -v e="$e" '$1 == e && $2 == "pwdaccountlockedtime" && $3 != "" { f = 1 } END { exit !f }' <<<"$parsed"; then
            echo disabled
            return 0
        fi
    fi
    if [[ -n "$LDAP_REQUIRED_GROUP" ]]; then
        if ! awk -F'\t' -v e="$e" -v g="${LDAP_REQUIRED_GROUP,,}" '$1 == e && $2 == "memberof" && tolower($3) == g { f = 1 } END { exit !f }' <<<"$parsed"; then
            echo not-in-group
            return 0
        fi
    fi
    echo active
}

# --------------------------------------------------------------------------
# Revocation (library functions, no shelling out to other scripts)
# --------------------------------------------------------------------------

revoke_access() {
    local user="$1" archive="$2" p rc ok=0
    local -a peers
    mapfile -t peers < <(wg_user_peers "$user")
    for p in "${peers[@]}"; do
        [[ -n "$p" ]] || continue
        if wg_deprovision_peer "$p" "$archive"; then
            info "Removed peer $p (archived in $archive)"
        else
            error "Could not remove peer $p"
            ok=1
        fi
    done
    if pki_ca_exists; then
        for p in "${peers[@]}" "$user"; do
            [[ -n "$p" ]] || continue
            rc=0
            pki_revoke "$p" cessationOfOperation >/dev/null 2>&1 || rc=$?
            case "$rc" in
                0) info "Revoked client certificate(s) CN=$p" ;;
                2) ;;
                *) error "Revoking certificates for $p failed"; ok=1 ;;
            esac
        done
    fi
    if [[ "$AUTHELIA_BACKEND" == file ]] && authelia_user_exists "$user"; then
        if authelia_set_disabled "$user" true; then
            info "Disabled Authelia account $user"
        else
            ok=1
        fi
    fi
    return "$ok"
}

# --------------------------------------------------------------------------

main() {
    local apply=0 force=0 json=0
    while (($#)); do
        case "$1" in
            --apply) apply=1; shift ;;
            --dry-run) apply=0; shift ;;
            --force) force=1; shift ;;
            --max-revoke) SYNC_MAX_REVOKE="${2:-}"; shift 2 || die "--max-revoke needs a value" ;;
            --json) json=1; shift ;;
            -h | --help) usage; exit 0 ;;
            *) usage >&2; die "Unknown option: $1" ;;
        esac
    done
    [[ "$SYNC_MAX_REVOKE" =~ ^[0-9]+$ ]] || die "Invalid --max-revoke"
    require_cmd ldapsearch jq base64
    ((apply == 0)) || require_root

    WORK="$(mktemp -d)"
    # shellcheck disable=SC2064
    trap "rm -rf '$WORK'" EXIT
    validate_ldap_config

    # Collect identities: "user<TAB>source"
    local -A sources=()
    local n _ip _k u
    while read -r n _ip _k; do
        [[ -n "$n" ]] || continue
        u="${n%%--*}"
        sources["$u"]+="wireguard,"
    done < <(wg_list_peers)
    if [[ "$AUTHELIA_BACKEND" == file ]]; then
        require_yq || die "yq is required for AUTHELIA_BACKEND=file"
        while IFS= read -r u; do
            [[ -n "$u" ]] && sources["$u"]+="authelia,"
        done < <(authelia_list_users)
    fi

    local -a results=()
    local -a to_revoke=()
    local errors=0 status
    for u in "${!sources[@]}"; do
        if ! validate_username "$u"; then
            warn "Skipping identity with an invalid name (not sent to LDAP): $(printf '%q' "$u")"
            results+=("$u"$'\t'invalid-name$'\t'"${sources[$u]%,}"$'\t'none)
            errors=1
            continue
        fi
        if split_csv "$SYNC_IGNORE_USERS" | grep -qxF -- "$u"; then
            results+=("$u"$'\t'ignored$'\t'"${sources[$u]%,}"$'\t'none)
            continue
        fi
        if ! status="$(ldap_user_status "$u")"; then
            results+=("$u"$'\t'ldap-error$'\t'"${sources[$u]%,}"$'\t'none)
            errors=1
            continue
        fi
        case "$status" in
            missing | disabled | not-in-group)
                to_revoke+=("$u")
                results+=("$u"$'\t'"$status"$'\t'"${sources[$u]%,}"$'\t'"$( ((apply)) && echo revoke || echo would-revoke)")
                ;;
            ambiguous)
                warn "More than one directory entry matches $u; not touching it"
                results+=("$u"$'\t'ambiguous$'\t'"${sources[$u]%,}"$'\t'none)
                errors=1
                ;;
            *)
                results+=("$u"$'\t'"$status"$'\t'"${sources[$u]%,}"$'\t'none)
                ;;
        esac
    done

    if ((apply && ${#to_revoke[@]} > 0)); then
        if ((${#to_revoke[@]} > SYNC_MAX_REVOKE && !force)); then
            die "${#to_revoke[@]} users would lose access (limit $SYNC_MAX_REVOKE). Check the directory settings, then rerun with --force or --max-revoke"
        fi
        ztvpn_lock users
        ztvpn_lock wg
        ztvpn_lock pki
        local archive
        archive="$ZTVPN_BACKUP_DIR/user-sync/$(date -u +%Y%m%dT%H%M%SZ)"
        for u in "${to_revoke[@]}"; do
            if revoke_access "$u" "$archive"; then
                success "Revoked VPN access of $u"
            else
                error "Revoking $u was incomplete"
                errors=1
            fi
        done
    elif ((${#to_revoke[@]} > 0)); then
        warn "Dry run: ${#to_revoke[@]} user(s) would lose VPN access: ${to_revoke[*]}. Rerun with --apply."
    else
        info "All VPN identities are active in the directory"
    fi

    if ((json)); then
        if ((${#results[@]})); then
            printf '%s\n' "${results[@]}" | jq -R 'split("\t") | {user: .[0], status: .[1], sources: (.[2] | split(",")), action: .[3]}' | jq -s --argjson applied "$apply" '{applied: ($applied == 1), results: .}'
        else
            jq -n --argjson applied "$apply" '{applied: ($applied == 1), results: []}'
        fi
    else
        printf '%-24s %-13s %-20s %s\n' USER STATUS SOURCES ACTION
        if ((${#results[@]})); then
            local r
            for r in "${results[@]}"; do
                IFS=$'\t' read -r u status n _k <<<"$r"
                printf '%-24s %-13s %-20s %s\n' "$(printf '%q' "$u")" "$status" "$n" "$_k"
            done | sort
        fi
    fi
    return "$errors"
}

main "$@"
