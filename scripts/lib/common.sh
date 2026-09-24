# shellcheck shell=bash
# Shared library for all zero-trust-vpn scripts.
#
# Single source of truth for paths, network layout and naming. Every script
# sources this file instead of defining its own defaults, so the setup,
# management, automation and monitoring scripts agree on where keys, CA,
# WireGuard peers and Authelia users live.
#
# Rules for everything in here:
#   * Log output goes to stderr only, so $(...) captures stay clean.
#   * Functions return non-zero on failure instead of calling exit, except die().
#   * Untrusted values never get interpolated into sed/awk/yq/jq programs.

[[ -n "${ZTVPN_COMMON_LOADED:-}" ]] && return 0
ZTVPN_COMMON_LOADED=1

ZTVPN_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ZTVPN_REPO_ROOT="$(cd "$ZTVPN_LIB_DIR/../.." && pwd)"
export ZTVPN_REPO_ROOT

# --------------------------------------------------------------------------
# Logging
# --------------------------------------------------------------------------

if [[ -t 2 && -z "${NO_COLOR:-}" ]]; then
    _C_RED=$'\033[0;31m' _C_GREEN=$'\033[0;32m' _C_YELLOW=$'\033[1;33m'
    _C_BLUE=$'\033[0;34m' _C_RESET=$'\033[0m'
else
    _C_RED='' _C_GREEN='' _C_YELLOW='' _C_BLUE='' _C_RESET=''
fi

# Optional per-script log file; set LOG_FILE before sourcing or afterwards.
_ztvpn_log_to_file() {
    [[ -n "${LOG_FILE:-}" ]] || return 0
    local dir
    dir="$(dirname "$LOG_FILE")"
    [[ -d "$dir" ]] || mkdir -p "$dir" 2>/dev/null || return 0
    printf '%s [%s] %s\n' "$(date -Iseconds)" "$1" "$2" >>"$LOG_FILE" 2>/dev/null || true
}

log()     { printf '%s[%s]%s %s\n' "$_C_GREEN" "$(date '+%F %T')" "$_C_RESET" "$*" >&2; _ztvpn_log_to_file INFO "$*"; }
info()    { printf '%s[INFO]%s %s\n' "$_C_BLUE" "$_C_RESET" "$*" >&2; _ztvpn_log_to_file INFO "$*"; }
warn()    { printf '%s[WARN]%s %s\n' "$_C_YELLOW" "$_C_RESET" "$*" >&2; _ztvpn_log_to_file WARN "$*"; }
error()   { printf '%s[ERROR]%s %s\n' "$_C_RED" "$_C_RESET" "$*" >&2; _ztvpn_log_to_file ERROR "$*"; }
success() { printf '%s[OK]%s %s\n' "$_C_GREEN" "$_C_RESET" "$*" >&2; _ztvpn_log_to_file INFO "$*"; }
die()     { error "$*"; exit 1; }

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

# Loads KEY=VALUE lines without executing anything. Only variables that are
# not already set in the environment are assigned, so env overrides config.
# Refuses files that a non-root user could have modified, because the
# values end up in commands run as root.
ztvpn_load_config() {
    local file="$1" line key value
    [[ -f "$file" ]] || return 0

    if [[ "${ZTVPN_SKIP_CONFIG_OWNER_CHECK:-0}" != "1" ]]; then
        local owner perms
        owner="$(stat -c %u "$file")"
        perms="$(stat -c %a "$file")"
        if [[ "$owner" != "0" && "$owner" != "$(id -u)" ]]; then
            die "Refusing to load $file: owned by uid $owner"
        fi
        if (( 8#$perms & 8#022 )); then
            die "Refusing to load $file: group/world writable (mode $perms)"
        fi
    fi

    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line#"${line%%[![:space:]]*}"}"
        [[ -z "$line" || "$line" == \#* ]] && continue
        [[ "$line" =~ ^(export[[:space:]]+)?([A-Z_][A-Z0-9_]*)=(.*)$ ]] || {
            warn "Ignoring malformed line in $file: $line"
            continue
        }
        key="${BASH_REMATCH[2]}"
        value="${BASH_REMATCH[3]}"
        # Strip one level of matching quotes, no expansion of any kind.
        if [[ "$value" =~ ^\"(.*)\"$ || "$value" =~ ^\'(.*)\'$ ]]; then
            value="${BASH_REMATCH[1]}"
        else
            value="${value%%[[:space:]]#*}"
            value="${value%"${value##*[![:space:]]}"}"
        fi
        [[ -n "${!key+x}" ]] && continue
        printf -v "$key" '%s' "$value"
    done <"$file"
}

ZTVPN_ETC="${ZTVPN_ETC:-/etc/zero-trust-vpn}"
ZTVPN_CONFIG="${ZTVPN_CONFIG:-$ZTVPN_ETC/ztvpn.conf}"
ztvpn_load_config "$ZTVPN_CONFIG"

# Base directories
ZTVPN_HOME="${ZTVPN_HOME:-/opt/zero-trust-vpn}"
ZTVPN_SECRETS_DIR="${ZTVPN_SECRETS_DIR:-$ZTVPN_ETC/secrets}"
ZTVPN_STATE_DIR="${ZTVPN_STATE_DIR:-/var/lib/zero-trust-vpn}"
ZTVPN_LOG_DIR="${ZTVPN_LOG_DIR:-/var/log/zero-trust-vpn}"
ZTVPN_BACKUP_DIR="${ZTVPN_BACKUP_DIR:-/var/backups/zero-trust-vpn}"
ZTVPN_REPORT_DIR="${ZTVPN_REPORT_DIR:-$ZTVPN_STATE_DIR/reports}"
SYSTEMD_UNIT_DIR="${SYSTEMD_UNIT_DIR:-/etc/systemd/system}"

# Kept for the docker-compose .env, which uses these names.
CONFIG_PATH="${CONFIG_PATH:-$ZTVPN_HOME}"
CERTS_PATH="${CERTS_PATH:-$ZTVPN_HOME/certificates}"

# Naming
DOMAIN="${DOMAIN:-example.com}"
AUTH_DOMAIN="${AUTH_DOMAIN:-auth.$DOMAIN}"
VPN_ENDPOINT="${VPN_ENDPOINT:-vpn.$DOMAIN}"

# Network layout. VPN_SUBNET is the only tunnel subnet; everything else
# (Authelia "vpn" network, firewall, NAT) is derived from it.
VPN_SUBNET="${VPN_SUBNET:-10.8.0.0/24}"
VPN_SERVER_IP="${VPN_SERVER_IP:-10.8.0.1}"
SERVICES_SUBNET="${SERVICES_SUBNET:-10.0.1.0/24}"
PROXY_BIND_ADDR="${PROXY_BIND_ADDR:-}"
EXTERNAL_INTERFACE="${EXTERNAL_INTERFACE:-}"
# What clients route through the tunnel. Split tunnel by default.
CLIENT_ALLOWED_IPS="${CLIENT_ALLOWED_IPS:-$VPN_SUBNET, $SERVICES_SUBNET}"
# Empty means no DNS line in client configs (no resolver is shipped).
CLIENT_DNS="${CLIENT_DNS:-}"

# WireGuard
WG_INTERFACE="${WG_INTERFACE:-wg0}"
WG_PORT="${WG_PORT:-51820}"
WG_DIR="${WG_DIR:-/etc/wireguard}"
WG_CONF="${WG_CONF:-$WG_DIR/$WG_INTERFACE.conf}"
WG_SERVER_KEY="${WG_SERVER_KEY:-$WG_DIR/server_private.key}"
WG_SERVER_PUBKEY="${WG_SERVER_PUBKEY:-$WG_DIR/server_public.key}"
WG_CLIENTS_DIR="${WG_CLIENTS_DIR:-$ZTVPN_HOME/wireguard/clients}"
WG_KEEPALIVE="${WG_KEEPALIVE:-25}"

# PKI
PKI_DIR="${PKI_DIR:-$CERTS_PATH}"
PKI_CA_DIR="${PKI_CA_DIR:-$PKI_DIR/ca}"
PKI_CA_CERT="${PKI_CA_CERT:-$PKI_CA_DIR/ca.crt}"
PKI_CA_KEY="${PKI_CA_KEY:-$PKI_CA_DIR/private/ca.key}"
PKI_CA_CNF="${PKI_CA_CNF:-$PKI_CA_DIR/openssl.cnf}"
PKI_CA_PASSFILE="${PKI_CA_PASSFILE:-$ZTVPN_SECRETS_DIR/ca.pass}"
PKI_SERVER_DIR="${PKI_SERVER_DIR:-$PKI_DIR/server}"
PKI_CLIENTS_DIR="${PKI_CLIENTS_DIR:-$PKI_DIR/clients}"
PKI_CRL="${PKI_CRL:-$PKI_DIR/crl/ca.crl}"
PKI_CRL_URL="${PKI_CRL_URL:-}"
PKI_ORG="${PKI_ORG:-Zero Trust VPN}"
PKI_COUNTRY="${PKI_COUNTRY:-}"
PKI_CA_DAYS="${PKI_CA_DAYS:-3650}"
PKI_CERT_DAYS="${PKI_CERT_DAYS:-365}"
# "ec:<curve>" or "rsa:<bits>"
PKI_CA_KEY_ALG="${PKI_CA_KEY_ALG:-ec:secp384r1}"
PKI_KEY_ALG="${PKI_KEY_ALG:-ec:prime256v1}"

# Authelia
AUTHELIA_DIR="${AUTHELIA_DIR:-$ZTVPN_HOME/authelia}"
AUTHELIA_USERS_DB="${AUTHELIA_USERS_DB:-$AUTHELIA_DIR/users_database.yml}"
AUTHELIA_SECRETS_DIR="${AUTHELIA_SECRETS_DIR:-$AUTHELIA_DIR/secrets}"
# file | ldap
AUTHELIA_BACKEND="${AUTHELIA_BACKEND:-file}"
AUTHELIA_IMAGE="${AUTHELIA_IMAGE:-authelia/authelia:4.39}"
# Groups every new VPN user gets. Must match access-control rules.
DEFAULT_USER_GROUPS="${DEFAULT_USER_GROUPS:-users,vpn-users}"
KNOWN_GROUPS="${KNOWN_GROUPS:-admins,security,it-support,employees,remote-workers,contractors,guests,users,vpn-users,monitoring}"

# Inventory and runtime state
DEVICE_INVENTORY="${DEVICE_INVENTORY:-$ZTVPN_STATE_DIR/device-inventory.json}"
QUARANTINE_DIR="${QUARANTINE_DIR:-$ZTVPN_STATE_DIR/quarantine}"

# nftables (scripts/setup/firewall-setup.sh renders "table inet $NFT_TABLE")
NFT_TABLE="${NFT_TABLE:-ztvpn}"
FW_STATE_FILE="${FW_STATE_FILE:-$ZTVPN_STATE_DIR/firewall/dynamic-sets}"

# Compose deployment. Containers are addressed by compose service name;
# set AUTHELIA_CONTAINER only if Authelia runs outside this compose project.
COMPOSE_DIR="${COMPOSE_DIR:-$ZTVPN_HOME}"
COMPOSE_FILE_PATH="${COMPOSE_FILE_PATH:-$COMPOSE_DIR/docker-compose.yml}"
AUTHELIA_SERVICE="${AUTHELIA_SERVICE:-authelia}"
AUTHELIA_CONTAINER="${AUTHELIA_CONTAINER:-}"
AUTHELIA_CONFIG="${AUTHELIA_CONFIG:-$AUTHELIA_DIR/configuration.yml}"
TLS_PROXY_SERVICE="${TLS_PROXY_SERVICE:-nginx}"

# Admin addresses that automated blocking must never touch
ADMIN_ALLOWLIST="${ADMIN_ALLOWLIST:-}"

# --------------------------------------------------------------------------
# Generic helpers
# --------------------------------------------------------------------------

require_root() {
    [[ "$(id -u)" -eq 0 ]] || die "This script must be run as root"
}

require_cmd() {
    local missing=() c
    for c in "$@"; do
        command -v "$c" >/dev/null 2>&1 || missing+=("$c")
    done
    ((${#missing[@]} == 0)) || die "Missing required command(s): ${missing[*]}"
}

# Serialises mutations of shared state (wg0.conf, users DB, CA database).
# Usage: ztvpn_lock <name>   (lock is released when the script exits)
ztvpn_lock() {
    local name="$1" dir="${ZTVPN_STATE_DIR}/locks"
    mkdir -p "$dir"
    local fd
    exec {fd}>"$dir/$name.lock"
    flock -w 60 "$fd" || die "Could not acquire lock $name"
}

# Writes stdin to a file atomically with the given mode.
atomic_write() {
    local dest="$1" mode="${2:-600}" tmp
    tmp="$(mktemp "$(dirname "$dest")/.$(basename "$dest").XXXXXX")"
    if ! cat >"$tmp"; then
        rm -f "$tmp"
        return 1
    fi
    chmod "$mode" "$tmp"
    mv -f "$tmp" "$dest"
}

gen_password() {
    local len="${1:-24}" out=''
    while ((${#out} < len)); do
        out+="$(openssl rand -base64 48 | tr -dc 'A-Za-z0-9')"
    done
    printf '%s\n' "${out:0:len}"
}

gen_secret() {
    openssl rand -hex "${1:-32}"
}

split_csv() {
    local IFS=','
    local -a parts
    read -ra parts <<<"$1"
    local p
    for p in "${parts[@]}"; do
        p="${p//[[:space:]]/}"
        [[ -n "$p" ]] && printf '%s\n' "$p"
    done
    return 0
}

# --------------------------------------------------------------------------
# Validation. Everything that reaches a config file goes through these.
# --------------------------------------------------------------------------

# Lowercase, starts with a letter, no dots (dots would be regex wildcards
# in any legacy tool and make "a.b" ambiguous with peer names).
# "--" is reserved as the user/device separator in peer names.
validate_username() {
    [[ "$1" =~ ^[a-z][a-z0-9_-]{1,31}$ && "$1" != *--* && "$1" != *- ]]
}

validate_device_name() {
    [[ "$1" =~ ^[a-z0-9][a-z0-9_-]{0,31}$ && "$1" != *--* && "$1" != *- ]]
}

# Peer names are "<user>" or "<user>--<device>".
validate_peer_name() {
    [[ "$1" =~ ^[a-z][a-z0-9_-]{1,31}(--[a-z0-9][a-z0-9_-]{0,31})?$ ]]
}

validate_email() {
    [[ "$1" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$ ]] && ((${#1} <= 254))
}

validate_group() {
    [[ "$1" =~ ^[a-z][a-z0-9_-]{0,31}$ ]]
}

validate_display_name() {
    [[ -n "$1" && ${#1} -le 64 && "$1" != *$'\n'* && "$1" =~ ^[[:print:]]+$ ]]
}

validate_ipv4() {
    local ip="$1" o
    [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
    for o in "${BASH_REMATCH[@]:1}"; do
        [[ "$o" =~ ^(0|[1-9][0-9]*)$ ]] && ((o <= 255)) || return 1
    done
}

validate_cidr() {
    local ip="${1%/*}" bits="${1#*/}"
    [[ "$1" == */* ]] && validate_ipv4 "$ip" && [[ "$bits" =~ ^[0-9]+$ ]] && ((bits <= 32))
}

ip_to_int() {
    local IFS=.
    local -a o
    read -ra o <<<"$1"
    printf '%u\n' $(((o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3]))
}

int_to_ip() {
    local n="$1"
    printf '%d.%d.%d.%d\n' $(((n >> 24) & 255)) $(((n >> 16) & 255)) $(((n >> 8) & 255)) $((n & 255))
}

ip_in_cidr() {
    local ip="$1" cidr="$2" bits net mask
    validate_ipv4 "$ip" && validate_cidr "$cidr" || return 1
    bits="${cidr#*/}"
    net="$(ip_to_int "${cidr%/*}")"
    mask=$(((0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF))
    ((($(ip_to_int "$ip") & mask) == (net & mask)))
}

# Exact membership test against a comma separated list of IPs/CIDRs.
ip_in_list() {
    local ip="$1" entry
    while IFS= read -r entry; do
        if [[ "$entry" == */* ]]; then
            ip_in_cidr "$ip" "$entry" && return 0
        elif [[ "$entry" == "$ip" ]]; then
            return 0
        fi
    done < <(split_csv "$2")
    return 1
}

detect_external_interface() {
    if [[ -n "$EXTERNAL_INTERFACE" ]]; then
        printf '%s\n' "$EXTERNAL_INTERFACE"
        return 0
    fi
    ip -o -4 route show to default 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "dev") { print $(i + 1); exit }}'
}

# --------------------------------------------------------------------------
# Shared script plumbing
# --------------------------------------------------------------------------

need_value() { [[ $# -ge 2 && -n "$2" ]] || die "Option $1 requires a value"; }

is_known_group() {
    local g
    while IFS= read -r g; do [[ "$g" == "$1" ]] && return 0; done < <(split_csv "$KNOWN_GROUPS")
    return 1
}

# Append-only audit trail of administrative actions. audit <action> <k=v ...>
audit() {
    (umask 027; mkdir -p "$ZTVPN_LOG_DIR" &&
        printf '%s %s actor=%s %s\n' "$(date -Iseconds)" "$1" "${SUDO_USER:-$(id -un)}" "$2" \
            >>"$ZTVPN_LOG_DIR/audit.log") || warn "Could not write audit log"
}

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

# Address nginx publishes on: PROXY_BIND_ADDR, or the first local IPv4
# address inside SERVICES_SUBNET. Fails if neither exists.
proxy_bind_addr() {
    if [[ -n "$PROXY_BIND_ADDR" ]]; then
        validate_ipv4 "$PROXY_BIND_ADDR" && ip_in_cidr "$PROXY_BIND_ADDR" "$SERVICES_SUBNET" || {
            error "PROXY_BIND_ADDR $PROXY_BIND_ADDR is not an IPv4 address inside $SERVICES_SUBNET"
            return 1
        }
        printf '%s\n' "$PROXY_BIND_ADDR"
        return 0
    fi
    local addr
    while read -r addr; do
        addr="${addr%/*}"
        if ip_in_cidr "$addr" "$SERVICES_SUBNET"; then
            printf '%s\n' "$addr"
            return 0
        fi
    done < <(ip -o -4 addr show 2>/dev/null | awk '{print $4}')
    error "No local address inside SERVICES_SUBNET ($SERVICES_SUBNET); set PROXY_BIND_ADDR"
    return 1
}

# shellcheck source=scripts/lib/wireguard.sh
source "$ZTVPN_LIB_DIR/wireguard.sh"
# shellcheck source=scripts/lib/authelia.sh
source "$ZTVPN_LIB_DIR/authelia.sh"
# shellcheck source=scripts/lib/pki.sh
source "$ZTVPN_LIB_DIR/pki.sh"
# shellcheck source=scripts/lib/firewall.sh
source "$ZTVPN_LIB_DIR/firewall.sh"
