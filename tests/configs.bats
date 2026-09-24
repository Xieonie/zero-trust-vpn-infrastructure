#!/usr/bin/env bats
# Static and tool-based checks of config-examples/. Docker-based checks
# (compose config, Authelia validate-config, nginx -t) are skipped when
# docker or the pinned images are not available; they never pull images.

load test_helper

CE="$BATS_TEST_DIRNAME/../config-examples"
COMPOSE="$CE/docker/docker-compose.yml"
AUTHELIA_CFG="$CE/authelia/configuration.yml"

KNOWN_GROUPS="admins security it-support employees remote-workers contractors guests users vpn-users monitoring"
SECRET_NAMES="jwt_secret session_secret storage_encryption_key postgres_password redis_password"

need_docker() {
    command -v docker >/dev/null || skip "docker not installed"
    docker info >/dev/null 2>&1 || skip "docker daemon not reachable"
}

need_image() {
    docker image inspect "$1" >/dev/null 2>&1 || skip "image $1 not present locally"
}

# Secret files as authelia-setup.sh creates them (hex + newline, 0600).
make_secrets() {
    local d="$1" n
    mkdir -p "$d"
    for n in $SECRET_NAMES ldap_password; do
        (umask 077; openssl rand -hex 32 >"$d/$n")
    done
}

authelia_validate() {
    local cfgdir="$1" secdir="$2"
    shift 2
    docker run --rm --network none \
        -v "$cfgdir:/config:ro" -v "$secdir:/secrets:ro" \
        -e X_AUTHELIA_CONFIG_FILTERS=template \
        -e DOMAIN=example.com -e AUTH_DOMAIN=auth.example.com -e VPN_SUBNET=10.8.0.0/24 \
        -e AUTHELIA_IDENTITY_VALIDATION_RESET_PASSWORD_JWT_SECRET_FILE=/secrets/jwt_secret \
        -e AUTHELIA_SESSION_SECRET_FILE=/secrets/session_secret \
        -e AUTHELIA_STORAGE_ENCRYPTION_KEY_FILE=/secrets/storage_encryption_key \
        -e AUTHELIA_STORAGE_POSTGRES_PASSWORD_FILE=/secrets/postgres_password \
        -e AUTHELIA_SESSION_REDIS_PASSWORD_FILE=/secrets/redis_password \
        "$@" authelia/authelia:4.39 authelia validate-config --config /config/configuration.yml
}

# --------------------------------------------------------------------------
# Files that must (not) exist
# --------------------------------------------------------------------------

@test "obsolete examples are gone" {
    [ ! -e "$CE/firewall/iptables-rules.sh" ]
    [ ! -e "$CE/authelia/access-control.yml" ]
    run find "$CE/pki" -name '*.conf'
    [ -z "$output" ]
    [ -f "$CE/pki/README.md" ]
}

# --------------------------------------------------------------------------
# Generic
# --------------------------------------------------------------------------

@test "every YAML file parses" {
    local f n=0
    while IFS= read -r f; do
        yq '.' "$f" >/dev/null || { echo "invalid YAML: $f"; return 1; }
        n=$((n + 1))
    done < <(find "$CE" -name '*.yml' -o -name '*.yaml')
    ((n >= 4))
}

@test "pfSense example is well-formed XML without the direct Authelia rule" {
    if command -v xmllint >/dev/null; then
        xmllint --noout "$CE/firewall/pfsense-rules.xml"
    else
        python3 -c 'import sys, xml.dom.minidom as m; m.parse(sys.argv[1])' "$CE/firewall/pfsense-rules.xml"
    fi
    ! grep -q '<port>9091</port>' "$CE/firewall/pfsense-rules.xml" || false
    grep -q '<address>10.8.0.0/24</address>' "$CE/firewall/pfsense-rules.xml"
    grep -q 'import function' "$CE/firewall/pfsense-rules.xml"
}

@test "the only tunnel subnet used anywhere is 10.8.0.0/24" {
    # Allowed 10/8 addresses: tunnel 10.8.0.x, services 10.0.1.x and the
    # RFC1918 block itself in the full-tunnel drop list.
    run bash -c "grep -rhoE '\\b10\\.[0-9]+\\.[0-9]+\\.[0-9]+(/[0-9]+)?' '$CE' | sort -u |
        grep -vE '^10\\.8\\.0\\.[0-9]+(/(24|32))?\$' | grep -vE '^10\\.0\\.1\\.[0-9]+(/24)?\$' | grep -vx '10.0.0.0/8'"
    [ -z "$output" ]
    grep -q '^VPN_SUBNET=10.8.0.0/24$' "$CE/docker/.env.example"
}

@test "no secrets are passed through \${...} variables" {
    run grep -rnE '\$\{?[A-Z_]*(PASSWORD|SECRET|TOKEN|ENCRYPTION_KEY)[A-Z_]*\}?' "$CE" \
        --include='*.yml' --include='*.yaml' --include='*.template' --include='*.conf' --include='*.example'
    # Only *_FILE paths and the secrets directory may mention them.
    run grep -vE '_FILE|SECRETS_DIR' <<<"$output"
    [ -z "$output" ]
    # .env.example: no secret-looking keys with values
    ! grep -E '^[A-Z_]*(PASSWORD|SECRET|TOKEN|KEY)[A-Z_]*=' "$CE/docker/.env.example" | grep -vE '^[A-Z_]*(_FILE|SECRETS_DIR)=' || false
}

# --------------------------------------------------------------------------
# docker-compose.yml
# --------------------------------------------------------------------------

@test "compose: no obsolete version key, no :latest, every image pinned" {
    [ "$(yq 'has("version")' "$COMPOSE")" = false ]
    ! grep -q ':latest' "$COMPOSE" || false
    run yq '.services[].image' "$COMPOSE"
    [ "$status" -eq 0 ]
    local img
    for img in "${lines[@]}"; do
        [[ "$img" == *:* ]] || { echo "unpinned: $img"; return 1; }
        [[ "$img" != *:latest ]]
    done
}

@test "compose: only nginx publishes ports, and only 80/443" {
    [ "$(yq '[.services | to_entries[] | select(.value.ports) | .key] | join(",")' "$COMPOSE")" = nginx ]
    [ "$(yq '.services.nginx.ports | join(",")' "$COMPOSE")" = "80:80,443:443" ]
    [ "$(yq '[.services[] | select(.network_mode == "host")] | length' "$COMPOSE")" = 0 ]
}

@test "compose: removed services stay removed" {
    local s
    for s in wg-easy fail2ban backup wireguard-exporter node-exporter promtail; do
        [ "$(S="$s" yq '.services | has(strenv(S))' "$COMPOSE")" = false ]
    done
    ! grep -q -- '--web.enable-lifecycle' "$COMPOSE" || false
    ! grep -q 'admin123' "$COMPOSE" || false
}

@test "compose: Authelia reads every secret from a file, config dir read-only" {
    local v
    for v in AUTHELIA_IDENTITY_VALIDATION_RESET_PASSWORD_JWT_SECRET_FILE AUTHELIA_SESSION_SECRET_FILE \
        AUTHELIA_STORAGE_ENCRYPTION_KEY_FILE AUTHELIA_STORAGE_POSTGRES_PASSWORD_FILE \
        AUTHELIA_SESSION_REDIS_PASSWORD_FILE; do
        [[ "$(V="$v" yq '.services.authelia.environment[strenv(V)]' "$COMPOSE")" == /secrets/* ]]
    done
    [ "$(yq '.services.authelia.environment.X_AUTHELIA_CONFIG_FILTERS' "$COMPOSE")" = template ]
    yq '.services.authelia.volumes[]' "$COMPOSE" | grep -qx '${AUTHELIA_DIR:?set AUTHELIA_DIR in .env}:/config:ro'
    yq '.services.authelia.volumes[]' "$COMPOSE" | grep -q ':/secrets:ro$'
    [ "$(yq '.services.postgres.environment.POSTGRES_PASSWORD_FILE' "$COMPOSE")" = /run/secrets/postgres_password ]
    [ "$(yq '.services.grafana.environment.GF_SECURITY_ADMIN_PASSWORD__FILE' "$COMPOSE")" = /run/secrets/grafana_admin_password ]
    [ "$(yq '.services.authelia.depends_on.postgres.condition' "$COMPOSE")" = service_healthy ]
    [ "$(yq '.services.authelia.depends_on.redis.condition' "$COMPOSE")" = service_healthy ]
    ! grep -q 'curl' <<<"$(yq '.services.authelia.healthcheck.test' "$COMPOSE")" || false
    # nginx gets the server certificates only, never the CA directory
    yq '.services.nginx.volumes[]' "$COMPOSE" | grep -q '/server:/etc/nginx/certs:ro$'
}

@test "compose: .env.example has exactly the variables the compose file uses" {
    local used env
    used="$(grep -oE '\$\{[A-Z_]+' "$COMPOSE" | tr -d '${' | sort -u)"
    env="$(grep -oE '^#?[A-Z_]+=' "$CE/docker/.env.example" | tr -d '#=' | sort -u)"
    diff <(printf '%s\n' "$used") <(printf '%s\n' "$env")
}

@test "compose: docker compose config accepts the file with .env.example" {
    need_docker
    docker compose version >/dev/null 2>&1 || skip "compose plugin missing"
    cp "$CE/docker/.env.example" "$BATS_TEST_TMPDIR/.env"
    docker compose --project-directory "$BATS_TEST_TMPDIR" -f "$COMPOSE" config --quiet
    docker compose --project-directory "$BATS_TEST_TMPDIR" -f "$COMPOSE" --profile monitoring config --quiet
    # The redis password never appears in the rendered command line
    run docker compose --project-directory "$BATS_TEST_TMPDIR" -f "$COMPOSE" config
    [[ "$output" == *'cat /run/secrets/redis_password'* ]]
    [[ "$output" != *"--requirepass"* ]]
}

# --------------------------------------------------------------------------
# Authelia
# --------------------------------------------------------------------------

@test "authelia: no secrets and no legacy keys in configuration.yml" {
    local p
    for p in .jwt_secret .session.secret .storage.encryption_key .storage.postgres.password \
        .session.redis.password .notifier.smtp.password .authentication_backend.ldap.password \
        .server.host .server.port .default_redirection_url .session.domain; do
        [ "$(yq "$p" "$AUTHELIA_CFG")" = null ] || { echo "found $p"; return 1; }
    done
    ! grep -q '\${' "$AUTHELIA_CFG" || false
}

@test "authelia: default deny, no bypass, every rule limited to the vpn network" {
    [ "$(yq '.access_control.default_policy' "$AUTHELIA_CFG")" = deny ]
    [ "$(yq '[.access_control.rules[] | select(.policy == "bypass")] | length' "$AUTHELIA_CFG")" = 0 ]
    [ "$(yq '[.access_control.rules[] | select(((.networks // []) | join(",")) != "vpn")] | length' "$AUTHELIA_CFG")" = 0 ]
    [ "$(yq '.access_control.networks | length' "$AUTHELIA_CFG")" = 1 ]
    [ "$(yq '.access_control.networks[0].name' "$AUTHELIA_CFG")" = vpn ]
    [ "$(yq '.access_control.networks[0].networks[0]' "$AUTHELIA_CFG")" = '{{ env "VPN_SUBNET" }}' ]
}

@test "authelia: rules only use the known groups, and only valid rule keys" {
    local g
    while IFS= read -r g; do
        [[ " $KNOWN_GROUPS " == *" ${g#group:} "* ]] || { echo "unknown subject $g"; return 1; }
    done < <(yq '.access_control.rules[].subject | .. | select(tag == "!!str")' "$AUTHELIA_CFG")
    run yq '[.access_control.rules[] | keys | .[]] | unique | .[]' "$AUTHELIA_CFG"
    local k
    for k in "${lines[@]}"; do
        [[ " domain domain_regex policy subject networks resources methods query " == *" $k "* ]] ||
            { echo "invalid rule key $k"; return 1; }
    done
}

@test "authelia: file backend is watched and refreshed so disabled users are cut off" {
    [ "$(yq '.authentication_backend.file.path' "$AUTHELIA_CFG")" = /config/users_database.yml ]
    [ "$(yq '.authentication_backend.file.watch' "$AUTHELIA_CFG")" = true ]
    [ "$(yq '.authentication_backend.refresh_interval' "$AUTHELIA_CFG")" != null ]
    [ "$(yq '.authentication_backend.file.password.argon2.variant' "$AUTHELIA_CFG")" = argon2id ]
}

@test "authelia: users_database.yml example has users and no password hashes" {
    [ "$(yq '.users | type' "$CE/authelia/users_database.yml")" = '!!map' ]
    ! grep -v '^#' "$CE/authelia/users_database.yml" | grep -q 'argon2' || false
}

@test "authelia: validate-config accepts configuration.yml" {
    need_docker
    need_image authelia/authelia:4.39
    mkdir -p "$BATS_TEST_TMPDIR/cfg"
    cp "$AUTHELIA_CFG" "$CE/authelia/users_database.yml" "$BATS_TEST_TMPDIR/cfg/"
    make_secrets "$BATS_TEST_TMPDIR/sec"
    run authelia_validate "$BATS_TEST_TMPDIR/cfg" "$BATS_TEST_TMPDIR/sec"
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" == *"without errors"* ]]
    [[ "$output" != *"level=warn"* ]]
}

@test "authelia: validate-config fails without the secret files (no silent defaults)" {
    need_docker
    need_image authelia/authelia:4.39
    mkdir -p "$BATS_TEST_TMPDIR/cfg" "$BATS_TEST_TMPDIR/empty"
    cp "$AUTHELIA_CFG" "$BATS_TEST_TMPDIR/cfg/"
    run authelia_validate "$BATS_TEST_TMPDIR/cfg" "$BATS_TEST_TMPDIR/empty"
    [ "$status" -ne 0 ]
}

@test "authelia: the LDAP variant validates when swapped in" {
    need_docker
    need_image authelia/authelia:4.39
    mkdir -p "$BATS_TEST_TMPDIR/ldap"
    yq eval-all 'select(fileIndex == 0).authentication_backend = select(fileIndex == 1).authentication_backend | select(fileIndex == 0)' \
        "$AUTHELIA_CFG" "$CE/authelia/configuration.ldap.yml" >"$BATS_TEST_TMPDIR/ldap/configuration.yml"
    [ "$(yq '.authentication_backend.ldap.address' "$BATS_TEST_TMPDIR/ldap/configuration.yml")" = 'ldaps://ldap.example.com:636' ]
    [ "$(yq '.authentication_backend.file' "$BATS_TEST_TMPDIR/ldap/configuration.yml")" = null ]
    make_secrets "$BATS_TEST_TMPDIR/sec"
    run authelia_validate "$BATS_TEST_TMPDIR/ldap" "$BATS_TEST_TMPDIR/sec" \
        -e AUTHELIA_AUTHENTICATION_BACKEND_LDAP_PASSWORD_FILE=/secrets/ldap_password
    echo "$output"
    [ "$status" -eq 0 ]
}

# --------------------------------------------------------------------------
# nginx
# --------------------------------------------------------------------------

@test "nginx: every app server is VPN-only and uses Authelia forward auth" {
    local t
    for t in "$CE"/nginx/templates/*.conf.template; do
        [[ "$t" == */default.conf.template ]] && continue
        grep -q 'include /etc/nginx/conf.d/vpn-only.inc;' "$t"
        [[ "$t" == */auth.conf.template ]] && continue
        grep -q 'include /etc/nginx/snippets/authelia-location.conf;' "$t"
        grep -q 'include /etc/nginx/snippets/authelia-authrequest.conf;' "$t"
    done
    grep -q 'http://authelia:9091/api/authz/auth-request' "$CE/nginx/snippets/authelia-location.conf"
    grep -q 'error_page 401 =302 $redirection_url;' "$CE/nginx/snippets/authelia-authrequest.conf"
    # X-Forwarded-For is set by nginx, never taken from the client
    ! grep -rq 'proxy_add_x_forwarded_for' "$CE/nginx" || false
}

@test "nginx: nginx -t accepts the rendered templates" {
    need_docker
    need_image nginx:1.27-alpine
    local certs="$BATS_TEST_TMPDIR/certs"
    mkdir -p "$certs"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 \
        -subj /CN=auth.example.com -keyout "$certs/auth.example.com.key" \
        -out "$certs/auth.example.com.crt" 2>/dev/null
    run docker run --rm --network none \
        -e DOMAIN=example.com -e AUTH_DOMAIN=auth.example.com -e VPN_SUBNET=10.8.0.0/24 \
        -e 'NGINX_ENVSUBST_FILTER=^(DOMAIN|AUTH_DOMAIN|VPN_SUBNET)$' \
        -v "$CE/nginx/templates:/etc/nginx/templates:ro" \
        -v "$CE/nginx/snippets:/etc/nginx/snippets:ro" \
        -v "$certs:/etc/nginx/certs:ro" \
        nginx:1.27-alpine sh -c '/docker-entrypoint.sh nginx -t && cat /etc/nginx/conf.d/vpn-only.inc /etc/nginx/conf.d/grafana.conf'
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" == *"test is successful"* ]]
    [[ "$output" == *"allow 10.8.0.0/24;"* ]]
    [[ "$output" == *"server_name grafana.example.com;"* ]]
    # nginx's own variables survived envsubst
    [[ "$output" == *'proxy_pass $upstream_app;'* ]]
}

# --------------------------------------------------------------------------
# WireGuard
# --------------------------------------------------------------------------

@test "wireguard: server example has no PostUp/PostDown/DNS and uses the peer markers" {
    local f="$CE/wireguard/wg0.conf.example"
    ! grep -Eq '^[[:space:]]*(PostUp|PostDown|PreUp|PreDown|DNS)[[:space:]]*=' "$f" || false
    grep -q '^Address = 10.8.0.1/24$' "$f"
    grep -q '^# BEGIN PEER alice--laptop$' "$f"
    grep -q '^# END PEER alice--laptop$' "$f"
    grep -q '^PresharedKey = ' "$f"
    ! grep -qi 'certificate-based' "$f" || false
}

@test "wireguard: client template is split tunnel with a preshared key" {
    local f="$CE/wireguard/client-template.conf"
    grep -q '^AllowedIPs = 10.8.0.0/24, 10.0.1.0/24$' "$f"
    grep -q '^PresharedKey = ' "$f"
    ! grep -Eq '^[[:space:]]*(DNS|PostUp|PostDown)[[:space:]]*=' "$f" || false
}
