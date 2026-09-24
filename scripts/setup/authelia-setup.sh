#!/usr/bin/env bash
# Prepares everything Authelia needs on the host:
#
#   $AUTHELIA_DIR/configuration.yml      copied from config-examples/authelia
#   $AUTHELIA_SECRETS_DIR/<name>         one random secret per file (0600)
#   $AUTHELIA_USERS_DB                   file backend user database
#   first admin user                     random password, argon2id hash;
#                                        the password goes to an onboarding
#                                        file, never to the terminal
#
# The container itself is defined in docker-compose.yml (deployed by
# initial-setup.sh). This script does not start anything.

set -Eeuo pipefail

# shellcheck source=scripts/lib/common.sh
source "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/../lib/common.sh"

LOG_FILE="${LOG_FILE:-$ZTVPN_LOG_DIR/authelia-setup.log}"
CONFIG_TEMPLATE="$ZTVPN_REPO_ROOT/config-examples/authelia/configuration.yml"
ONBOARDING_DIR="$ZTVPN_SECRETS_DIR/onboarding"
# smtp_password is only needed when SMTP is configured; create it by hand.
SECRET_NAMES=(jwt_secret session_secret storage_encryption_key postgres_password redis_password)
ADMIN_GROUPS="admins,users,vpn-users"

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Prepare Authelia configuration, secrets and the first admin user.

Options:
  --admin-user NAME     Admin to create (default: "admin", only created when
                        the database has no member of "admins" yet)
  --admin-email EMAIL   Admin e-mail (default: \$ADMIN_EMAIL or admin@\$DOMAIN)
  --admin-name NAME     Admin display name (default: the user name)
  --force               Replace $AUTHELIA_DIR/configuration.yml with the
                        template even if it was edited (old file is backed up).
                        Secrets and users are never replaced.
  --validate            Run "authelia validate-config" in $AUTHELIA_IMAGE
                        (needs docker)
  -h, --help            Show this help

Files:
  config    $AUTHELIA_DIR/configuration.yml
  secrets   $AUTHELIA_SECRETS_DIR/{$(IFS=,; echo "${SECRET_NAMES[*]}")}
  users     $AUTHELIA_USERS_DB   (backend: $AUTHELIA_BACKEND)
  admin pw  $ONBOARDING_DIR/authelia-<user>.txt
EOF
}

ADMIN_USER=""
ADMIN_EMAIL="${ADMIN_EMAIL:-}"
ADMIN_NAME=""
FORCE=0
VALIDATE=0

while (($#)); do
    case "$1" in
        --admin-user | --admin-email | --admin-name)
            [[ $# -ge 2 ]] || die "$1 needs a value"
            case "$1" in
                --admin-user) ADMIN_USER="$2" ;;
                --admin-email) ADMIN_EMAIL="$2" ;;
                --admin-name) ADMIN_NAME="$2" ;;
            esac
            shift 2
            ;;
        --force) FORCE=1; shift ;;
        --validate) VALIDATE=1; shift ;;
        -h | --help) usage; exit 0 ;;
        *) die "Unknown option: $1 (see --help)" ;;
    esac
done

require_root
require_cmd openssl flock
[[ "$AUTHELIA_BACKEND" == file || "$AUTHELIA_BACKEND" == ldap ]] || die "Invalid AUTHELIA_BACKEND: $AUTHELIA_BACKEND"
[[ -f "$CONFIG_TEMPLATE" ]] || die "Template $CONFIG_TEMPLATE is missing"

explicit_admin=0
[[ -n "$ADMIN_USER" ]] && explicit_admin=1
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@$DOMAIN}"
ADMIN_NAME="${ADMIN_NAME:-$ADMIN_USER}"
validate_username "$ADMIN_USER" || die "Invalid admin user name: $ADMIN_USER"
validate_email "$ADMIN_EMAIL" || die "Invalid admin e-mail: $ADMIN_EMAIL"
validate_display_name "$ADMIN_NAME" || die "Invalid admin display name"

ztvpn_lock users

# --------------------------------------------------------------------------
# Directories and secrets
# --------------------------------------------------------------------------
mkdir -p "$AUTHELIA_DIR"
chmod 755 "$AUTHELIA_DIR"
(umask 077; mkdir -p "$AUTHELIA_SECRETS_DIR" "$ONBOARDING_DIR")
chmod 700 "$AUTHELIA_SECRETS_DIR" "$ONBOARDING_DIR"

created=0
for name in "${SECRET_NAMES[@]}"; do
    f="$AUTHELIA_SECRETS_DIR/$name"
    if [[ -s "$f" ]]; then
        chmod 600 "$f"
        continue
    fi
    gen_secret 32 | atomic_write "$f" 600
    created=$((created + 1))
done
if ((created)); then
    success "Generated $created secret(s) in $AUTHELIA_SECRETS_DIR"
else
    info "All secrets already present in $AUTHELIA_SECRETS_DIR (not rotated)"
fi

# --------------------------------------------------------------------------
# configuration.yml
# --------------------------------------------------------------------------
config="$AUTHELIA_DIR/configuration.yml"
if [[ ! -f "$config" ]]; then
    install -m 644 "$CONFIG_TEMPLATE" "$config"
    success "Installed $config"
elif cmp -s "$CONFIG_TEMPLATE" "$config"; then
    info "$config matches the template"
elif ((FORCE)); then
    backup_dir="$ZTVPN_BACKUP_DIR/authelia"
    (umask 077; mkdir -p "$backup_dir")
    backup="$backup_dir/configuration.yml.$(date +%Y%m%d-%H%M%S)"
    cp -a "$config" "$backup"
    install -m 644 "$CONFIG_TEMPLATE" "$config"
    success "Replaced $config with the template (previous version: $backup)"
else
    warn "$config differs from the template; keeping local edits (use --force to replace)"
fi

# --------------------------------------------------------------------------
# Users and first admin
# --------------------------------------------------------------------------
if [[ "$AUTHELIA_BACKEND" == ldap ]]; then
    info "AUTHELIA_BACKEND=ldap: users and groups are managed in the directory, no local admin created"
    if ! grep -q '^[[:space:]]*ldap:' "$config"; then
        warn "MANUAL: merge config-examples/authelia/configuration.ldap.yml into $config"
    fi
    if [[ ! -s "$AUTHELIA_SECRETS_DIR/ldap_password" ]]; then
        warn "MANUAL: write the LDAP bind password to $AUTHELIA_SECRETS_DIR/ldap_password (mode 600)"
    fi
else
    require_cmd yq jq argon2
    require_yq || exit 1
    authelia_init_users_db
    chmod 600 "$AUTHELIA_USERS_DB"

    existing_admins="$(yq '.users | to_entries | map(select((.value.groups // []) | contains(["admins"]))) | .[].key' "$AUTHELIA_USERS_DB")"
    if authelia_user_exists "$ADMIN_USER"; then
        info "Authelia user $ADMIN_USER already exists; not changing it"
    elif ((!explicit_admin)) && [[ -n "$existing_admins" ]]; then
        info "Admin(s) already present: $(tr '\n' ' ' <<<"$existing_admins")"
    else
        password="$(gen_password 24)"
        hash="$(printf '%s\n' "$password" | authelia_hash_password)" || die "Hashing the admin password failed"
        authelia_add_user "$ADMIN_USER" "$ADMIN_NAME" "$ADMIN_EMAIL" "$hash" "$ADMIN_GROUPS" ||
            die "Could not add $ADMIN_USER to $AUTHELIA_USERS_DB"
        onboarding="$ONBOARDING_DIR/authelia-$ADMIN_USER.txt"
        atomic_write "$onboarding" 600 <<EOF
Authelia administrator account
Portal:   https://$AUTH_DOMAIN
User:     $ADMIN_USER
Password: $password

Log in, register a second factor (TOTP or WebAuthn) and change the
password. Then delete this file.
EOF
        unset password
        success "Created Authelia admin $ADMIN_USER (groups: $ADMIN_GROUPS)"
        info "One-time credentials written to $onboarding"
        if [[ "$ADMIN_EMAIL" == *@example.com ]]; then
            warn "Admin e-mail is $ADMIN_EMAIL; set a real address (--admin-email) for password resets"
        fi
    fi
fi

# --------------------------------------------------------------------------
# Optional validation with the real Authelia binary
# --------------------------------------------------------------------------
if ((VALIDATE)); then
    require_cmd docker
    info "Validating $config with $AUTHELIA_IMAGE"
    # Same variables docker-compose.yml passes to the container: the
    # template filter fills in the domain, secrets are read from files.
    docker_args=(
        run --rm --network none
        -v "$AUTHELIA_DIR:/config:ro"
        -e X_AUTHELIA_CONFIG_FILTERS=template
        -e "DOMAIN=$DOMAIN"
        -e "AUTH_DOMAIN=$AUTH_DOMAIN"
        -e "VPN_SUBNET=$VPN_SUBNET"
        -e AUTHELIA_IDENTITY_VALIDATION_RESET_PASSWORD_JWT_SECRET_FILE=/secrets/jwt_secret
        -e AUTHELIA_SESSION_SECRET_FILE=/secrets/session_secret
        -e AUTHELIA_STORAGE_ENCRYPTION_KEY_FILE=/secrets/storage_encryption_key
        -e AUTHELIA_STORAGE_POSTGRES_PASSWORD_FILE=/secrets/postgres_password
        -e AUTHELIA_SESSION_REDIS_PASSWORD_FILE=/secrets/redis_password
        -v "$AUTHELIA_SECRETS_DIR:/secrets:ro"
    )
    if [[ "$AUTHELIA_BACKEND" == ldap ]]; then
        docker_args+=(-e AUTHELIA_AUTHENTICATION_BACKEND_LDAP_PASSWORD_FILE=/secrets/ldap_password)
    fi
    docker_args+=("$AUTHELIA_IMAGE" authelia validate-config --config /config/configuration.yml)
    docker "${docker_args[@]}" >&2 || die "Authelia rejected $config"
    success "Authelia configuration is valid"
fi
