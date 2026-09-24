#!/usr/bin/env bash
# Checks and renews X.509 certificates issued by the zero-trust-vpn CA.
#
# WireGuard does not use X.509 at all, so nothing here touches wg0. The
# certificates matter for the TLS terminator (reverse proxy in front of
# Authelia) and for optional client certificates.
#
#   check  lists CA, server and client certificates with days left.
#          Exit 0 = all fine, 1 = something within --days, 2 = something
#          within --critical days or expired.
#   renew  reissues server certificates within --days (same CN and SANs,
#          new key), revokes the superseded serial and reloads the TLS
#          terminator. Client certificates are only reported unless
#          --reissue-clients is given. The CA is never regenerated.

set -Eeuo pipefail
# shellcheck source=scripts/lib/common.sh
source "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/../lib/common.sh"

LOG_FILE="${LOG_FILE:-$ZTVPN_LOG_DIR/cert-renewal.log}"
# TLS terminator that serves the server certificates: the compose service
# in $COMPOSE_DIR, or an explicit container name if not run via compose.
TLS_PROXY_CONTAINER="${TLS_PROXY_CONTAINER:-}"
CERT_WARN_DAYS="${CERT_WARN_DAYS:-30}"
CERT_CRITICAL_DAYS="${CERT_CRITICAL_DAYS:-7}"
CERT_CA_WARN_DAYS="${CERT_CA_WARN_DAYS:-180}"

usage() {
    cat <<EOF
Usage: $(basename "$0") check [--days N] [--critical N]
       $(basename "$0") renew [--days N] [--dry-run] [--reissue-clients] [--no-reload]

check               List certificates and days left.
                    Exit 0 ok, 1 warning (<= --days), 2 critical (<= --critical or expired).
renew               Reissue server certificates expiring within --days with the same
                    CN/SANs and a new key; the old key and certificate are backed up
                    first and restored if issuing fails; the old serial is revoked
                    (superseded) and the TLS terminator (compose service $TLS_PROXY_SERVICE,
                    or TLS_PROXY_CONTAINER) is reloaded with SIGHUP.

Options:
  --days N            Renewal/warning threshold in days (default $CERT_WARN_DAYS)
  --critical N        Critical threshold in days (default $CERT_CRITICAL_DAYS)
  --dry-run           Show what renew would do, change nothing
  --reissue-clients   Also reissue expiring client certificates. The new private key is
                      generated here and stays in $PKI_CLIENTS_DIR until you hand it to
                      the user; prefer having users submit a CSR instead.
  --no-reload         Do not signal the TLS terminator after renewing
  -h, --help          Show this help

The CA certificate is only reported (warning within $CERT_CA_WARN_DAYS days); a CA rollover
is a manual, planned operation and is never automated.
EOF
}

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

cert_serial() {
    local s
    s="$(openssl x509 -in "$1" -noout -serial 2>/dev/null)" || return 1
    printf '%s\n' "${s#serial=}"
}

# Status letter (V/R/E) of a serial in the CA database, empty if unknown.
db_status() {
    local serial="$1"
    [[ -f "$PKI_CA_DIR/index.txt" ]] || return 0
    awk -F'\t' -v s="$serial" 'toupper($4) == toupper(s) { print $1; exit }' "$PKI_CA_DIR/index.txt"
}

# Serial exactly as written in index.txt (and thus the newcerts file name).
db_serial() {
    awk -F'\t' -v s="$1" 'toupper($4) == toupper(s) { print $4; exit }' "$PKI_CA_DIR/index.txt"
}

# Revokes one specific serial (pki_revoke would revoke every cert with the
# CN, including the one we just issued).
revoke_serial() {
    local serial="$1" reason="$2" dbs
    dbs="$(db_serial "$serial")"
    [[ -n "$dbs" && -f "$PKI_CA_DIR/newcerts/$dbs.pem" ]] || { error "Serial $serial not in CA database"; return 1; }
    local -a passin
    mapfile -t passin < <(_pki_passin)
    openssl ca -config "$PKI_CA_CNF" "${passin[@]}" \
        -revoke "$PKI_CA_DIR/newcerts/$dbs.pem" -crl_reason "$reason" || return 1
    pki_gen_crl
}

# SANs of an existing server cert in pki_issue argument form, minus the CN
# (pki_issue adds DNS:<name> itself).
cert_sans() {
    local crt="$1" name="$2" line entry
    line="$(openssl x509 -in "$crt" -noout -ext subjectAltName 2>/dev/null | sed -n '2p')" || true
    local -a entries
    IFS=',' read -ra entries <<<"$line"
    for entry in "${entries[@]}"; do
        entry="${entry#"${entry%%[![:space:]]*}"}"
        case "$entry" in
            DNS:*)
                [[ "${entry#DNS:}" == "$name" ]] || printf '%s\n' "${entry#DNS:}" ;;
            "IP Address:"*)
                printf '%s\n' "${entry#IP Address:}" ;;
            "") ;;
            *) error "Unsupported SAN in $crt: $entry"; return 1 ;;
        esac
    done
}

classify() {
    local days="$1" warn="$2" crit="$3"
    if ((days < 0)); then
        echo expired
    elif ((days <= crit)); then
        echo critical
    elif ((days <= warn)); then
        echo warning
    else
        echo ok
    fi
}

# Emits "kind<TAB>name<TAB>path" for every certificate we manage.
list_certs() {
    local f
    [[ -f "$PKI_CA_CERT" ]] && printf 'ca\tca\t%s\n' "$PKI_CA_CERT"
    for f in "$PKI_SERVER_DIR"/*.crt; do
        [[ -f "$f" ]] && printf 'server\t%s\t%s\n' "$(basename "$f" .crt)" "$f"
    done
    for f in "$PKI_CLIENTS_DIR"/*.crt; do
        [[ -f "$f" ]] && printf 'client\t%s\t%s\n' "$(basename "$f" .crt)" "$f"
    done
    return 0
}

# --------------------------------------------------------------------------
# check
# --------------------------------------------------------------------------

cmd_check() {
    [[ -f "$PKI_CA_CERT" ]] || die "No CA certificate at $PKI_CA_CERT"
    local worst=0 kind name path days status serial dbst enddate
    printf '%-7s %-32s %6s  %-9s %s\n' KIND NAME DAYS STATUS EXPIRES
    while IFS=$'\t' read -r kind name path; do
        if ! days="$(pki_days_left "$path")"; then
            printf '%-7s %-32s %6s  %-9s %s\n' "$kind" "$name" "-" unreadable "-"
            worst=2
            continue
        fi
        enddate="$(openssl x509 -in "$path" -noout -enddate)"
        enddate="${enddate#notAfter=}"
        serial="$(cert_serial "$path")"
        dbst=""
        [[ "$kind" != ca ]] && dbst="$(db_status "$serial")"
        if [[ "$dbst" == R ]]; then
            status=revoked
        elif [[ "$kind" == ca ]]; then
            status="$(classify "$days" "$CERT_CA_WARN_DAYS" "$CERT_WARN_DAYS")"
        else
            status="$(classify "$days" "$CERT_WARN_DAYS" "$CERT_CRITICAL_DAYS")"
        fi
        printf '%-7s %-32s %6s  %-9s %s\n' "$kind" "$name" "$days" "$status" "$enddate"
        case "$status" in
            expired | critical) worst=2 ;;
            warning) ((worst < 1)) && worst=1 ;;
        esac
    done < <(list_certs)
    case "$worst" in
        0) info "All certificates are outside the $CERT_WARN_DAYS day window" ;;
        1) warn "Some certificates expire within $CERT_WARN_DAYS days" ;;
        2) error "Some certificates are expired or expire within $CERT_CRITICAL_DAYS days" ;;
    esac
    return "$worst"
}

# --------------------------------------------------------------------------
# renew
# --------------------------------------------------------------------------

BACKUP_ROOT=""

backup_pair() {
    local kind="$1" name="$2" dir="$3"
    local dest="$BACKUP_ROOT/$kind"
    (umask 077; mkdir -p "$dest") || return 1
    install -m 600 "$dir/$name.crt" "$dest/$name.crt" || return 1
    if [[ -f "$dir/$name.key" ]]; then
        install -m 600 "$dir/$name.key" "$dest/$name.key" || return 1
    fi
}

restore_pair() {
    local kind="$1" name="$2" dir="$3"
    local src="$BACKUP_ROOT/$kind"
    install -m 644 "$src/$name.crt" "$dir/$name.crt" || return 1
    if [[ -f "$src/$name.key" ]]; then
        install -m 600 "$src/$name.key" "$dir/$name.key" || return 1
    fi
}

# renew_one <server|client> <name> <path> <days-left>
renew_one() {
    local kind="$1" name="$2" path="$3" days="$4" dir old_serial san_list
    local -a sans=()
    if [[ "$kind" == server ]]; then
        dir="$PKI_SERVER_DIR"
        san_list="$(cert_sans "$path" "$name")" || return 1
        [[ -n "$san_list" ]] && mapfile -t sans <<<"$san_list"
    else
        dir="$PKI_CLIENTS_DIR"
    fi
    old_serial="$(cert_serial "$path")" || { error "Cannot read $path"; return 1; }

    if ((DRY_RUN)); then
        info "[dry-run] would reissue $kind certificate $name (${days}d left${sans[*]:+, SANs: ${sans[*]}}) and revoke serial $old_serial"
        return 0
    fi

    backup_pair "$kind" "$name" "$dir" || { error "Backup of $name failed; not renewing"; return 1; }
    if ! pki_issue "$kind" "$name" "$PKI_CERT_DAYS" "${sans[@]}" >/dev/null; then
        error "Issuing new $kind certificate for $name failed; restoring previous key and certificate"
        restore_pair "$kind" "$name" "$dir" || error "Restore failed, backup is in $BACKUP_ROOT/$kind"
        return 1
    fi
    if ! pki_verify "$dir/$name.crt"; then
        error "New certificate for $name does not verify; restoring previous key and certificate"
        restore_pair "$kind" "$name" "$dir" || error "Restore failed, backup is in $BACKUP_ROOT/$kind"
        return 1
    fi
    if ! revoke_serial "$old_serial" superseded; then
        warn "Renewed $name but could not revoke old serial $old_serial; revoke it manually"
    fi
    success "Renewed $kind certificate $name (new expiry: $(openssl x509 -in "$dir/$name.crt" -noout -enddate | cut -d= -f2))"
    return 0
}

reload_tls_terminator() {
    if ! command -v docker >/dev/null 2>&1; then
        warn "docker not found; reload the TLS terminator manually to pick up the new certificates"
        return 1
    fi
    local running target
    local -a kill_cmd
    if [[ -n "$TLS_PROXY_CONTAINER" ]]; then
        target="container $TLS_PROXY_CONTAINER"
        running="$(docker inspect -f '{{.State.Running}}' "$TLS_PROXY_CONTAINER" 2>/dev/null || true)"
        [[ "$running" == true ]] || running=""
        kill_cmd=(docker kill -s SIGHUP "$TLS_PROXY_CONTAINER")
    elif [[ -f "$COMPOSE_FILE_PATH" ]]; then
        target="compose service $TLS_PROXY_SERVICE"
        local -a compose=(docker compose -f "$COMPOSE_FILE_PATH" --project-directory "$(dirname "$COMPOSE_FILE_PATH")")
        running="$("${compose[@]}" ps -q --status running "$TLS_PROXY_SERVICE" 2>/dev/null || true)"
        kill_cmd=("${compose[@]}" kill -s SIGHUP "$TLS_PROXY_SERVICE")
    else
        warn "No $COMPOSE_FILE_PATH and no TLS_PROXY_CONTAINER set; reload the TLS terminator manually"
        return 1
    fi
    if [[ -z "$running" ]]; then
        info "The $target is not running; it will load the new certificates on start"
        return 0
    fi
    if "${kill_cmd[@]}" >/dev/null; then
        success "Sent SIGHUP (reload) to the $target"
    else
        error "Could not reload the $target; reload it manually"
        return 1
    fi
}

cmd_renew() {
    pki_ca_exists || die "No CA at $PKI_CA_DIR"
    if ((!DRY_RUN)); then
        require_root
        ztvpn_lock pki
        BACKUP_ROOT="$ZTVPN_BACKUP_DIR/certificates/$(date -u +%Y%m%dT%H%M%SZ)-$$"
    fi

    local kind name path days serial failed=0 renewed_server=0
    local -a pending_clients=()
    while IFS=$'\t' read -r kind name path; do
        days="$(pki_days_left "$path")" || { error "Cannot read $path"; failed=1; continue; }
        if [[ "$kind" == ca ]]; then
            if ((days <= CERT_CA_WARN_DAYS)); then
                warn "CA certificate expires in $days days. Plan a CA rollover manually; it is never regenerated automatically."
            fi
            continue
        fi
        ((days <= CERT_WARN_DAYS)) || continue
        serial="$(cert_serial "$path")"
        [[ "$(db_status "$serial")" == R ]] && continue
        [[ "$name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || { error "Skipping unexpected file name $path"; failed=1; continue; }

        if [[ "$kind" == server ]]; then
            if renew_one server "$name" "$path" "$days"; then
                ((DRY_RUN)) || renewed_server=1
            else
                failed=1
            fi
        elif ((REISSUE_CLIENTS)); then
            if renew_one client "$name" "$path" "$days"; then
                ((DRY_RUN)) || warn "New private key for client $name is in $PKI_CLIENTS_DIR/$name.key; deliver it securely to the user and delete it from this server"
            else
                failed=1
            fi
        else
            pending_clients+=("$name (${days}d)")
        fi
    done < <(list_certs)

    if ((${#pending_clients[@]})); then
        warn "Client certificates expiring within $CERT_WARN_DAYS days (not reissued): ${pending_clients[*]}"
        warn "Have the users submit a new CSR, or rerun with --reissue-clients"
    fi

    if ((renewed_server)); then
        if ((NO_RELOAD)); then
            warn "--no-reload given; reload the TLS terminator yourself"
        else
            reload_tls_terminator || failed=1
        fi
    fi
    [[ -n "$BACKUP_ROOT" && -d "$BACKUP_ROOT" ]] && info "Previous keys and certificates backed up in $BACKUP_ROOT"
    return "$failed"
}

# --------------------------------------------------------------------------

DRY_RUN=0
REISSUE_CLIENTS=0
NO_RELOAD=0

main() {
    local cmd="${1:-}"
    case "$cmd" in
        -h | --help) usage; exit 0 ;;
        check | renew) shift ;;
        "") usage >&2; exit 1 ;;
        *) usage >&2; die "Unknown command: $cmd" ;;
    esac
    while (($#)); do
        case "$1" in
            --days) CERT_WARN_DAYS="${2:-}"; shift 2 || die "--days needs a value" ;;
            --critical) CERT_CRITICAL_DAYS="${2:-}"; shift 2 || die "--critical needs a value" ;;
            --dry-run) DRY_RUN=1; shift ;;
            --reissue-clients) REISSUE_CLIENTS=1; shift ;;
            --no-reload) NO_RELOAD=1; shift ;;
            -h | --help) usage; exit 0 ;;
            *) die "Unknown option: $1" ;;
        esac
    done
    [[ "$CERT_WARN_DAYS" =~ ^[0-9]{1,4}$ ]] || die "Invalid --days: $CERT_WARN_DAYS"
    [[ "$CERT_CRITICAL_DAYS" =~ ^[0-9]{1,4}$ ]] || die "Invalid --critical: $CERT_CRITICAL_DAYS"
    [[ "$CERT_CA_WARN_DAYS" =~ ^[0-9]{1,5}$ ]] || die "Invalid CERT_CA_WARN_DAYS: $CERT_CA_WARN_DAYS"
    [[ -z "$TLS_PROXY_CONTAINER" || "$TLS_PROXY_CONTAINER" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || die "Invalid TLS_PROXY_CONTAINER"
    [[ "$TLS_PROXY_SERVICE" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || die "Invalid TLS_PROXY_SERVICE"
    ((CERT_CRITICAL_DAYS <= CERT_WARN_DAYS)) || die "--critical must not exceed --days"
    require_cmd openssl

    local rc=0
    if [[ "$cmd" == check ]]; then
        cmd_check || rc=$?
    else
        cmd_renew || rc=$?
    fi
    exit "$rc"
}

main "$@"
