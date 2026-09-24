#!/usr/bin/env bash
# One-shot installer for the zero-trust-vpn host. Safe to re-run: every
# step keeps existing keys, CA, peers, users and secrets.
#
#   1. packages (Debian/Ubuntu): WireGuard tools, nftables, openssl, jq,
#      argon2, qrencode, Docker Engine + compose plugin, yq v4
#   2. directories (root owned) and /etc/zero-trust-vpn/ztvpn.conf
#   3. pki-setup.sh, firewall-setup.sh, wireguard-setup.sh, authelia-setup.sh
#   4. docker-compose.yml + .env into $COMPOSE_DIR, "docker compose up -d"

set -Eeuo pipefail

SCRIPT_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Install and configure the zero-trust-vpn server on Debian or Ubuntu.
Settings come from /etc/zero-trust-vpn/ztvpn.conf, which is created from
config-examples/ztvpn.conf.example on the first run. Set at least DOMAIN,
AUTH_DOMAIN and VPN_ENDPOINT there, then run this script again.

Options:
  --skip-packages       Do not install packages (they must already be present)
  --skip-docker         Do not install Docker, do not validate the Authelia
                        config in a container and do not start the stack
                        (docker-compose.yml and .env are still written)
  --non-interactive     Never prompt; apt runs with DEBIAN_FRONTEND=noninteractive
  --admin-user NAME     First Authelia admin (see authelia-setup.sh)
  --admin-email EMAIL   E-mail of the first admin
  -h, --help            Show this help

Steps run: pki-setup.sh, firewall-setup.sh, wireguard-setup.sh,
authelia-setup.sh (all in scripts/setup/). Each can be re-run on its own.
EOF
}

SKIP_PACKAGES=0
SKIP_DOCKER=0
NON_INTERACTIVE=0
AUTHELIA_ARGS=()

while (($#)); do
    case "$1" in
        --skip-packages) SKIP_PACKAGES=1; shift ;;
        --skip-docker) SKIP_DOCKER=1; shift ;;
        --non-interactive) NON_INTERACTIVE=1; shift ;;
        --admin-user | --admin-email)
            [[ $# -ge 2 ]] || { printf 'ERROR: %s needs a value\n' "$1" >&2; exit 2; }
            AUTHELIA_ARGS+=("$1" "$2")
            shift 2
            ;;
        -h | --help) usage; exit 0 ;;
        *) printf 'ERROR: unknown option: %s (see --help)\n' "$1" >&2; exit 2 ;;
    esac
done

[[ "$(id -u)" -eq 0 ]] || { printf 'ERROR: this script must be run as root\n' >&2; exit 1; }

# The config has to exist before the library is loaded, because the library
# reads it once at load time (and so does every step script).
_conf="${ZTVPN_CONFIG:-${ZTVPN_ETC:-/etc/zero-trust-vpn}/ztvpn.conf}"
CONFIG_CREATED=0
if [[ ! -e "$_conf" ]]; then
    install -d -m 755 -o root -g root "$(dirname "$_conf")"
    install -m 600 -o root -g root "$REPO_DIR/config-examples/ztvpn.conf.example" "$_conf"
    CONFIG_CREATED=1
fi

# shellcheck source=scripts/lib/common.sh
source "$SCRIPT_DIR/../lib/common.sh"

LOG_FILE="${LOG_FILE:-$ZTVPN_LOG_DIR/initial-setup.log}"
ZTVPN_OS_RELEASE="${ZTVPN_OS_RELEASE:-/etc/os-release}"
# Pinned yq release; override both together to use another version.
YQ_VERSION="${YQ_VERSION:-v4.44.3}"
YQ_SHA256_amd64="${YQ_SHA256_amd64:-a2c097180dd884a8d50c956ee16a9cec070f30a7947cf4ebf87d5f36213e9ed7}"
YQ_SHA256_arm64="${YQ_SHA256_arm64:-0e7e1524f68d91b3ff9b089872d185940ab0fa020a5a9052046ef10547023156}"

((CONFIG_CREATED)) && success "Created $ZTVPN_CONFIG from the example (mode 600)"
((NON_INTERACTIVE)) && export DEBIAN_FRONTEND=noninteractive

# --------------------------------------------------------------------------
# Checks
# --------------------------------------------------------------------------

# Reads one KEY from os-release without sourcing it.
os_field() {
    local key="$1" line v
    while IFS= read -r line; do
        [[ "$line" == "$key="* ]] || continue
        v="${line#*=}"
        v="${v#\"}"; v="${v%\"}"
        printf '%s\n' "$v"
        return 0
    done <"$ZTVPN_OS_RELEASE"
}

OS_ID=""
OS_CODENAME=""
check_os() {
    [[ -r "$ZTVPN_OS_RELEASE" ]] || die "Cannot read $ZTVPN_OS_RELEASE"
    OS_ID="$(os_field ID)"
    OS_CODENAME="$(os_field VERSION_CODENAME)"
    case "$OS_ID" in
        debian | ubuntu) info "Detected $OS_ID ${OS_CODENAME:-?}" ;;
        *)
            ((SKIP_PACKAGES)) || die "Unsupported OS '$OS_ID' (Debian or Ubuntu only); install packages yourself and use --skip-packages"
            warn "Unsupported OS '$OS_ID'; continuing because --skip-packages was given"
            ;;
    esac
}

validate_hostname() {
    [[ ${#1} -le 253 && "$1" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$ ]]
}

check_settings() {
    validate_hostname "$DOMAIN" || die "Invalid DOMAIN in $ZTVPN_CONFIG: $DOMAIN"
    validate_hostname "$AUTH_DOMAIN" || die "Invalid AUTH_DOMAIN: $AUTH_DOMAIN"
    validate_hostname "$VPN_ENDPOINT" || validate_ipv4 "$VPN_ENDPOINT" || die "Invalid VPN_ENDPOINT: $VPN_ENDPOINT"
    local v example=""
    local -a sans=()
    mapfile -t sans < <(split_csv "${PKI_SERVER_SANS:-}")
    for v in "$DOMAIN" "$AUTH_DOMAIN" "$VPN_ENDPOINT" "${sans[@]}"; do
        [[ "$v" == example.com || "$v" == *.example.com ]] && example="$v"
    done
    if [[ -n "$example" ]]; then
        if ((NON_INTERACTIVE)) || [[ ! -t 0 ]]; then
            die "$example is a placeholder. Edit $ZTVPN_CONFIG (DOMAIN, AUTH_DOMAIN, VPN_ENDPOINT, PKI_SERVER_SANS) and run again."
        fi
        local answer=""
        read -r -p "$example is a placeholder. Continue with the example values (test install only)? [y/N] " answer
        [[ "$answer" == [yY] ]] || die "Edit $ZTVPN_CONFIG and run again."
    fi
    # nginx is published only on this address (Docker ports bypass nftables).
    PROXY_ADDR="$(proxy_bind_addr)" ||
        die "Give this host an address in SERVICES_SUBNET or set PROXY_BIND_ADDR in $ZTVPN_CONFIG"
}

# --------------------------------------------------------------------------
# Packages
# --------------------------------------------------------------------------

install_packages() {
    [[ "$OS_CODENAME" =~ ^[a-z]+$ ]] || die "Could not determine VERSION_CODENAME from $ZTVPN_OS_RELEASE"
    info "Installing base packages"
    apt-get update
    apt-get install -y --no-install-recommends \
        wireguard-tools nftables conntrack openssl jq argon2 qrencode \
        ca-certificates curl iproute2 util-linux
    ((SKIP_DOCKER)) || install_docker
    install_yq
}

install_docker() {
    if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
        info "Docker and the compose plugin are already installed"
        return 0
    fi
    info "Installing Docker Engine from download.docker.com ($OS_ID $OS_CODENAME)"
    local arch
    arch="$(dpkg --print-architecture)"
    install -d -m 755 /etc/apt/keyrings
    curl -fsSL "https://download.docker.com/linux/$OS_ID/gpg" -o /etc/apt/keyrings/docker.asc
    chmod 644 /etc/apt/keyrings/docker.asc
    printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/%s %s stable\n' \
        "$arch" "$OS_ID" "$OS_CODENAME" >/etc/apt/sources.list.d/docker.list
    apt-get update
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    systemctl enable --now docker
    docker compose version >/dev/null || die "docker compose plugin is not working"
}

install_yq() {
    if require_yq 2>/dev/null; then
        info "yq v4 already installed"
        return 0
    fi
    local arch sha tmp
    arch="$(dpkg --print-architecture)"
    case "$arch" in
        amd64) sha="$YQ_SHA256_amd64" ;;
        arm64) sha="$YQ_SHA256_arm64" ;;
        *) die "No pinned yq checksum for $arch; install mikefarah/yq v4 manually" ;;
    esac
    [[ "$sha" =~ ^[0-9a-f]{64}$ ]] || die "Invalid YQ_SHA256_$arch"
    info "Installing yq $YQ_VERSION ($arch) from GitHub"
    tmp="$(mktemp)"
    if ! curl -fsSL "https://github.com/mikefarah/yq/releases/download/$YQ_VERSION/yq_linux_$arch" -o "$tmp"; then
        rm -f "$tmp"
        die "Downloading yq failed"
    fi
    if ! printf '%s  %s\n' "$sha" "$tmp" | sha256sum -c --status; then
        rm -f "$tmp"
        die "yq download does not match the pinned SHA-256; not installing it"
    fi
    install -m 755 -o root -g root "$tmp" /usr/local/bin/yq
    rm -f "$tmp"
    hash -r
    require_yq || die "yq installed to /usr/local/bin but another yq comes first in PATH"
}

# --------------------------------------------------------------------------
# Directories
# --------------------------------------------------------------------------

create_dirs() {
    install -d -m 755 -o root -g root "$ZTVPN_ETC" "$ZTVPN_HOME" "$COMPOSE_DIR"
    install -d -m 700 -o root -g root "$ZTVPN_SECRETS_DIR" "$ZTVPN_BACKUP_DIR" "$WG_DIR" "$WG_CLIENTS_DIR"
    install -d -m 750 -o root -g root "$ZTVPN_STATE_DIR" "$ZTVPN_REPORT_DIR" "$ZTVPN_LOG_DIR"
    chmod 600 "$ZTVPN_CONFIG"

    # Earlier versions chowned the whole tree to a "vpn" service user. Root
    # writes keys into these directories, so they must not be user-owned.
    local foreign
    foreign="$(find "$ZTVPN_ETC" "$WG_DIR" "$PKI_DIR" "$AUTHELIA_DIR" "$WG_CLIENTS_DIR" "$COMPOSE_DIR" \
        -xdev -maxdepth 2 ! -user root -print 2>/dev/null | head -n 5 || true)"
    if [[ -n "$foreign" ]]; then
        warn "Files not owned by root below the install paths (fix with chown -R root:root):"
        warn "$foreign"
    fi
}

# --------------------------------------------------------------------------
# Setup steps
# --------------------------------------------------------------------------

run_step() {
    local name="$1" script="$SCRIPT_DIR/$1"
    shift
    [[ -f "$script" ]] || die "Required step $script is missing"
    log "==> $name $*"
    bash "$script" "$@" || die "$name failed; fix the problem and re-run $0"
}

# --------------------------------------------------------------------------
# Compose deployment
# --------------------------------------------------------------------------

detect_tz() {
    if [[ -n "${TZ:-}" ]]; then
        printf '%s\n' "$TZ"
    elif [[ -L /etc/localtime && "$(readlink /etc/localtime)" == */zoneinfo/* ]]; then
        local z
        z="$(readlink /etc/localtime)"
        printf '%s\n' "${z#*/zoneinfo/}"
    else
        printf 'UTC\n'
    fi
}

# nginx templates/snippets referenced by docker-compose.yml. Files edited
# locally are kept (with a warning), new ones are added.
deploy_nginx() {
    local src="$ZTVPN_REPO_ROOT/config-examples/nginx" dest="$CONFIG_PATH/nginx" f rel
    if [[ ! -d "$src" ]]; then
        warn "No config-examples/nginx in this checkout: populate $dest/templates and $dest/snippets before starting nginx"
        return 0
    fi
    install -d -m 755 -o root -g root "$dest"
    while IFS= read -r -d '' f; do
        rel="${f#"$src"/}"
        install -d -m 755 -o root -g root "$(dirname "$dest/$rel")"
        if [[ ! -e "$dest/$rel" ]]; then
            install -m 644 -o root -g root "$f" "$dest/$rel"
        elif ! cmp -s "$f" "$dest/$rel"; then
            warn "$dest/$rel differs from $f; keeping the local version"
        fi
    done < <(find "$src" -type f -print0)
}

deploy_compose() {
    local src="$ZTVPN_REPO_ROOT/config-examples/docker/docker-compose.yml"
    local dest="$COMPOSE_DIR/docker-compose.yml"
    [[ -f "$src" ]] || die "Missing $src"

    if [[ -f "$dest" ]] && ! cmp -s "$src" "$dest"; then
        local bdir="$ZTVPN_BACKUP_DIR/compose"
        (umask 077; mkdir -p "$bdir")
        cp -a "$dest" "$bdir/docker-compose.yml.$(date +%Y%m%d-%H%M%S)"
        info "Previous $dest backed up to $bdir"
    fi
    install -m 644 -o root -g root "$src" "$dest"
    deploy_nginx

    # Only non-secret settings: every secret is a file under
    # $AUTHELIA_SECRETS_DIR that compose mounts and Authelia reads via *_FILE.
    local tz key value
    tz="$(detect_tz)"
    local -a pairs=(
        COMPOSE_PROJECT_NAME zero-trust-vpn
        TZ "$tz"
        DOMAIN "$DOMAIN"
        AUTH_DOMAIN "$AUTH_DOMAIN"
        VPN_SUBNET "$VPN_SUBNET"
        PROXY_BIND_ADDR "$PROXY_ADDR"
        CONFIG_PATH "$CONFIG_PATH"
        CERTS_PATH "$CERTS_PATH"
        AUTHELIA_DIR "$AUTHELIA_DIR"
        AUTHELIA_SECRETS_DIR "$AUTHELIA_SECRETS_DIR"
        AUTHELIA_IMAGE "$AUTHELIA_IMAGE"
    )
    # Only needed for the "monitoring" profile.
    [[ -n "${GRAFANA_ADMIN_PASSWORD_FILE:-}" ]] && pairs+=(GRAFANA_ADMIN_PASSWORD_FILE "$GRAFANA_ADMIN_PASSWORD_FILE")
    local i env_content="# Generated by scripts/setup/initial-setup.sh from $ZTVPN_CONFIG. Do not edit;
# change ztvpn.conf and re-run. Contains no secrets (see $AUTHELIA_SECRETS_DIR)."
    for ((i = 0; i < ${#pairs[@]}; i += 2)); do
        key="${pairs[i]}" value="${pairs[i + 1]}"
        # Compose interpolates $ and treats quotes/spaces specially; only
        # allow plain values so nothing can be smuggled into the stack.
        [[ "$value" =~ ^[A-Za-z0-9_./:@,+-]+$ ]] || die "Value of $key is not allowed in .env: '$value'"
        env_content+=$'\n'"$key=$value"
    done
    printf '%s\n' "$env_content" | atomic_write "$COMPOSE_DIR/.env" 600
    success "Wrote $dest and $COMPOSE_DIR/.env"

    if ((SKIP_DOCKER)); then
        info "--skip-docker: not starting the stack. Later: docker compose --project-directory $COMPOSE_DIR up -d"
        return 0
    fi
    require_cmd docker
    docker compose --project-directory "$COMPOSE_DIR" -f "$dest" config --quiet ||
        die "docker compose rejected $dest"
    docker compose --project-directory "$COMPOSE_DIR" -f "$dest" up -d --remove-orphans
    success "Container stack started"
}

# --------------------------------------------------------------------------

main() {
    log "Zero Trust VPN setup starting (config: $ZTVPN_CONFIG)"
    check_os
    check_settings
    if ((SKIP_PACKAGES)); then
        info "--skip-packages: not installing packages"
    else
        install_packages
    fi
    require_cmd wg openssl jq argon2 flock
    require_yq || die "Install mikefarah/yq v4 (or run without --skip-packages)"
    create_dirs

    run_step pki-setup.sh
    # Firewall before WireGuard: IP forwarding is only switched on once the
    # default-drop forwarding policy is in place.
    local -a fw_args=(--apply)
    # Over an interactive (SSH) session let the firewall roll itself back
    # unless the operator confirms they can still reach the host.
    if ((!NON_INTERACTIVE)) && [[ -t 0 ]]; then
        fw_args+=(--confirm-timeout 120)
    fi
    run_step firewall-setup.sh "${fw_args[@]}"
    run_step wireguard-setup.sh
    local -a auth_args=("${AUTHELIA_ARGS[@]}")
    ((SKIP_DOCKER)) || auth_args+=(--validate)
    run_step authelia-setup.sh "${auth_args[@]}"
    deploy_compose

    success "Setup finished"
    info "Server certificate: $PKI_SERVER_DIR/$AUTH_DOMAIN.crt, CA: $PKI_CA_CERT"
    info "WireGuard public key: $WG_SERVER_PUBKEY (endpoint $VPN_ENDPOINT:$WG_PORT)"
    info "Admin credentials (if a new admin was created): $ZTVPN_SECRETS_DIR/onboarding/"
    info "Next: add users with $ZTVPN_REPO_ROOT/scripts/management/add-user.sh"
}

main
