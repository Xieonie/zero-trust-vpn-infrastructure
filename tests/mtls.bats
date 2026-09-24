#!/usr/bin/env bats
# Opt-in mutual TLS at nginx (MTLS=yes): snippet rendering, compose mounts,
# CRL reload hook, and real TLS handshakes against nginx:1.27-alpine with a
# CA, server/client certificates and CRL from scripts/lib/pki.sh. The docker
# tests are skipped when docker, the image or curl is missing; they never
# pull images.

bats_require_minimum_version 1.5.0
load test_helper

CE="$BATS_TEST_DIRNAME/../config-examples"
COMPOSE="$CE/docker/docker-compose.yml"
NGINX_IMAGE="nginx:1.27-alpine"

setup() {
    ztvpn_sandbox
    load_lib
    CONTAINER=""
}

teardown() {
    if [[ -n "$CONTAINER" ]]; then
        docker logs "$CONTAINER" >"$BATS_TEST_TMPDIR/nginx.log" 2>&1 || true
        docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    fi
}

need_docker() {
    command -v docker >/dev/null || skip "docker not installed"
    docker info >/dev/null 2>&1 || skip "docker daemon not reachable"
    docker image inspect "$NGINX_IMAGE" >/dev/null 2>&1 || skip "image $NGINX_IMAGE not present locally"
}

need_compose() {
    docker compose version >/dev/null 2>&1 || skip "compose plugin missing"
}

# Recording docker stub for the reload hook tests.
stub_docker() {
    export STUB_LOG="$BATS_TEST_TMPDIR/docker.calls"
    mkdir -p "$BATS_TEST_TMPDIR/bin"
    cat >"$BATS_TEST_TMPDIR/bin/docker" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$STUB_LOG"
case "$*" in
    *" ps -q --status running "*) [[ "${DOCKER_RUNNING:-}" == true ]] && echo 0123456789ab ;;
    inspect*) echo "${DOCKER_RUNNING:-false}" ;;
    *kill*) [[ -n "${DOCKER_KILL_FAIL:-}" ]] && exit 1 ;;
esac
exit 0
EOF
    chmod +x "$BATS_TEST_TMPDIR/bin/docker"
    export PATH="$BATS_TEST_TMPDIR/bin:$PATH"
    : >"$STUB_LOG"
}

# CA, a server certificate for all served names and two client certificates.
mtls_pki() {
    pki_init_ca 2>/dev/null
    pki_issue server auth.example.com 365 '*.example.com' >/dev/null 2>&1
    pki_issue client alice >/dev/null 2>&1
    pki_issue client mallory >/dev/null 2>&1
}

# $CONFIG_PATH/nginx as initial-setup.sh deploys it, snippet for MTLS=$1.
deploy_nginx_config() {
    mkdir -p "$CONFIG_PATH/nginx"
    cp -r "$CE/nginx/templates" "$CE/nginx/snippets" "$CONFIG_PATH/nginx/"
    mtls_snippet "$1" >"$MTLS_SNIPPET"
}

# The nginx volumes of docker-compose.yml as "docker run -v" arguments,
# resolved with this sandbox's CONFIG_PATH and CERTS_PATH.
compose_nginx_volumes() {
    local d="$BATS_TEST_TMPDIR/compose"
    mkdir -p "$d"
    printf '%s\n' DOMAIN=example.com AUTH_DOMAIN=auth.example.com VPN_SUBNET=10.8.0.0/24 \
        PROXY_BIND_ADDR=127.0.0.1 "CONFIG_PATH=$CONFIG_PATH" "CERTS_PATH=$CERTS_PATH" \
        "AUTHELIA_DIR=$AUTHELIA_DIR" "AUTHELIA_SECRETS_DIR=$AUTHELIA_SECRETS_DIR" >"$d/.env"
    docker compose --project-directory "$d" -f "$COMPOSE" config --format json |
        jq -r '.services.nginx.volumes[] | select(.type == "bind") | "-v", "\(.source):\(.target)\(if .read_only then ":ro" else "" end)"'
}

# A test-only server that uses the same snippet and needs no Authelia.
test_server_conf() {
    cat >"$BATS_TEST_TMPDIR/zz-mtls-test.conf" <<'EOF'
server {
    listen 443 ssl;
    server_name mtls-test.example.com;
    include /etc/nginx/snippets/mtls.conf;
    location / {
        default_type text/plain;
        return 200 "ok $ssl_client_s_dn\n";
    }
}
EOF
}

# Starts nginx with the deployed templates/snippets and the compose mounts.
start_nginx() {
    local -a vols
    mapfile -t vols < <(compose_nginx_volumes)
    ((${#vols[@]} >= 10))
    test_server_conf
    CONTAINER="ztvpn-mtls-test-$$-${BATS_TEST_NUMBER}"
    docker run -d --name "$CONTAINER" -p 127.0.0.1::443 \
        -e DOMAIN=example.com -e AUTH_DOMAIN=auth.example.com -e VPN_SUBNET=10.8.0.0/24 \
        -e 'NGINX_ENVSUBST_FILTER=^(DOMAIN|AUTH_DOMAIN|VPN_SUBNET)$' \
        "${vols[@]}" -v "$BATS_TEST_TMPDIR/zz-mtls-test.conf:/etc/nginx/conf.d/zz-mtls-test.conf:ro" \
        "$NGINX_IMAGE" >/dev/null
    PORT="$(docker port "$CONTAINER" 443/tcp | head -n 1)"
    PORT="${PORT##*:}"
    [[ "$PORT" =~ ^[0-9]+$ ]]
    local i
    for i in $(seq 1 40); do
        [[ "$(req mtls-test.example.com | tail -n 1)" == 403 ]] && return 0
        sleep 0.25
    done
    docker logs "$CONTAINER" >&2
    return 1
}

# req <host> [curl options]: prints the body, then the status code as the last line.
req() {
    local host="$1"
    shift
    curl -sS --noproxy '*' --max-time 5 --cacert "$PKI_CA_CERT" \
        --resolve "$host:$PORT:127.0.0.1" -w '\n%{http_code}\n' "$@" "https://$host:$PORT/" 2>/dev/null || echo 000
}

as() { printf '%s\n' --cert "$PKI_CLIENTS_DIR/$1.crt" --key "$PKI_CLIENTS_DIR/$1.key"; }

# Polls until "req <host> <args>" answers with <code>.
wait_for_code() {
    local code="$1" i
    shift
    for i in $(seq 1 40); do
        [[ "$(req "$@" | tail -n 1)" == "$code" ]] && return 0
        sleep 0.25
    done
    req "$@" >&2
    return 1
}

# --------------------------------------------------------------------------
# Rendering and static checks
# --------------------------------------------------------------------------

@test "snippet: MTLS=yes enforces CA, CRL and no session resumption; MTLS=no is only comments" {
    run mtls_snippet yes
    [ "$status" -eq 0 ]
    grep -qx 'ssl_client_certificate /etc/nginx/client-ca/ca.crt;' <<<"$output"
    grep -qx 'ssl_crl                /etc/nginx/crl/ca.crl;' <<<"$output"
    grep -qx 'ssl_verify_client      on;' <<<"$output"
    grep -qx 'ssl_verify_depth       1;' <<<"$output"
    grep -qx 'ssl_session_cache      off;' <<<"$output"
    grep -q '^error_page 496 = @ztvpn_mtls_missing;$' <<<"$output"
    grep -q '^error_page 495 = @ztvpn_mtls_invalid;$' <<<"$output"
    # nginx variables survive, the snippet is not an envsubst template
    [[ "$output" == *'($ssl_client_verify)'* ]]

    run mtls_snippet no
    [ "$status" -eq 0 ]
    [ -z "$(grep -v '^#' <<<"$output")" ]
    [[ "$output" == *"NOT requested or checked"* ]]
    # The shipped example is exactly the MTLS=no rendering
    diff <(mtls_snippet no) "$CE/nginx/snippets/mtls.conf"

    run mtls_snippet maybe
    [ "$status" -ne 0 ]
}

@test "templates: every HTTPS server includes the snippet, the port 80 server does not" {
    local t servers includes
    for t in "$CE"/nginx/templates/*.conf.template; do
        servers="$(grep -c 'listen 443 ssl' "$t" || true)"
        includes="$(grep -c 'include /etc/nginx/snippets/mtls.conf;' "$t" || true)"
        [ "$servers" = "$includes" ] || { echo "$t: $servers TLS servers, $includes includes"; return 1; }
    done
    # The plain HTTP server (redirect + /healthz) has no TLS and no snippet
    awk '/listen 80 default_server/ { on = 1 } on && /^}/ { exit } on' "$CE/nginx/templates/default.conf.template" >"$BATS_TEST_TMPDIR/http"
    grep -q 'location = /healthz' "$BATS_TEST_TMPDIR/http"
    ! grep -q mtls "$BATS_TEST_TMPDIR/http" || false
}

@test "compose: nginx gets ca.crt as a file and the crl dir, never the CA directory or key" {
    local vols
    vols="$(yq '.services.nginx.volumes[]' "$COMPOSE")"
    grep -qx '${CERTS_PATH}/ca/ca.crt:/etc/nginx/client-ca/ca.crt:ro' <<<"$vols"
    grep -qx '${CERTS_PATH}/crl:/etc/nginx/crl:ro' <<<"$vols"
    ! grep -Eq '/ca(/private)?(/)?:' <<<"$vols" || false
    ! grep -q 'private' <<<"$vols" || false
    ! grep -q 'clients' <<<"$vols" || false
    # Every nginx mount is read-only; the healthcheck still uses plain HTTP
    [ "$(yq '[.services.nginx.volumes[] | select(test(":ro$") | not)] | length' "$COMPOSE")" = 0 ]
    [ "$(yq '.services.nginx.healthcheck.test[-1]' "$COMPOSE")" = http://127.0.0.1/healthz ]
}

# --------------------------------------------------------------------------
# CRL -> proxy reload hook and PKCS#12 export (no docker needed)
# --------------------------------------------------------------------------

@test "pki_gen_crl reloads the proxy only with MTLS=yes and a deployment, never fails on reload errors" {
    stub_docker
    pki_init_ca 2>/dev/null
    pki_gen_crl 2>/dev/null
    [ ! -s "$STUB_LOG" ]

    MTLS=yes
    # No compose file and no TLS_PROXY_CONTAINER: nothing to reload
    pki_gen_crl 2>/dev/null
    [ ! -s "$STUB_LOG" ]

    touch "$COMPOSE_FILE_PATH"
    DOCKER_RUNNING=true pki_gen_crl 2>/dev/null
    grep -qx "compose -f $COMPOSE_FILE_PATH --project-directory $(dirname "$COMPOSE_FILE_PATH") kill -s SIGHUP nginx" "$STUB_LOG"

    # Revocation goes through pki_gen_crl as well
    : >"$STUB_LOG"
    pki_issue client alice >/dev/null 2>&1
    DOCKER_RUNNING=true pki_revoke alice keyCompromise 2>/dev/null
    [ "$(grep -c 'kill -s SIGHUP' "$STUB_LOG")" -eq 1 ]

    # A failed reload is a warning, the new CRL is still in place
    before="$(openssl crl -in "$PKI_CRL" -noout -crlnumber)"
    DOCKER_RUNNING=true DOCKER_KILL_FAIL=1 run pki_gen_crl
    [ "$status" -eq 0 ]
    [[ "$output" == *"still enforces the previous one"* ]]
    [ "$(openssl crl -in "$PKI_CRL" -noout -crlnumber)" != "$before" ]

    # The caller may take over reloading
    : >"$STUB_LOG"
    PKI_CRL_RELOAD=no DOCKER_RUNNING=true pki_gen_crl 2>/dev/null
    [ ! -s "$STUB_LOG" ]

    # Explicit container name
    TLS_PROXY_CONTAINER=edge DOCKER_RUNNING=true pki_gen_crl 2>/dev/null
    grep -qx 'kill -s SIGHUP edge' "$STUB_LOG"
}

@test "tls_proxy_reload: stopped proxy is fine, missing docker or deployment is reported" {
    stub_docker
    touch "$COMPOSE_FILE_PATH"
    DOCKER_RUNNING=false run tls_proxy_reload
    [ "$status" -eq 0 ]
    [[ "$output" == *"not running"* ]]
    ! grep -q kill "$STUB_LOG" || false
    rm "$COMPOSE_FILE_PATH"
    run tls_proxy_reload
    [ "$status" -eq 1 ]
    TLS_PROXY_SERVICE='bad;name' run tls_proxy_reload
    [ "$status" -eq 1 ]
    PATH=/nonexistent run tls_proxy_reload
    [ "$status" -eq 1 ]
}

@test "pki_export_p12: password from stdin, 0600, compat mode uses 3DES" {
    pki_init_ca 2>/dev/null
    pki_issue client alice >/dev/null 2>&1
    run pki_export_p12 alice <<<'s3cret-pass'
    [ "$status" -eq 0 ]
    [ "$output" = "$PKI_CLIENTS_DIR/alice.p12" ]
    [ "$(stat -c %a "$PKI_CLIENTS_DIR/alice.p12")" = 600 ]
    openssl pkcs12 -in "$PKI_CLIENTS_DIR/alice.p12" -passin pass:s3cret-pass -info -noout 2>&1 | grep -q 'AES-256'
    PKI_P12_COMPAT=yes pki_export_p12 alice <<<'s3cret-pass' >/dev/null
    openssl pkcs12 -in "$PKI_CLIENTS_DIR/alice.p12" -passin pass:s3cret-pass -info -noout 2>&1 | grep -q '3-KeyTripleDES'
    run pki_export_p12 nobody <<<'x'
    [ "$status" -ne 0 ]
    run pki_export_p12 '../alice' <<<'x'
    [ "$status" -ne 0 ]
    [ -z "$(find "$PKI_CLIENTS_DIR" -name '.*')" ]
}

# --------------------------------------------------------------------------
# nginx
# --------------------------------------------------------------------------

@test "nginx -t accepts the templates with the MTLS=yes and MTLS=no snippet and the compose mounts" {
    need_docker
    need_compose
    mtls_pki
    local -a vols
    local mode
    for mode in yes no; do
        deploy_nginx_config "$mode"
        mapfile -t vols < <(compose_nginx_volumes)
        run docker run --rm --network none \
            -e DOMAIN=example.com -e AUTH_DOMAIN=auth.example.com -e VPN_SUBNET=10.8.0.0/24 \
            -e 'NGINX_ENVSUBST_FILTER=^(DOMAIN|AUTH_DOMAIN|VPN_SUBNET)$' \
            "${vols[@]}" "$NGINX_IMAGE" sh -c '/docker-entrypoint.sh nginx -t && nginx -T 2>/dev/null >/tmp/T &&
                grep -c "include /etc/nginx/snippets/mtls.conf;" /tmp/T; grep -c "^ssl_verify_client *on;" /tmp/T; true'
        echo "$output"
        [ "$status" -eq 0 ]
        [[ "$output" == *"test is successful"* ]]
        # default reject server + auth + grafana + prometheus + alertmanager
        [ "${lines[-2]}" -eq 5 ]
        if [[ "$mode" == yes ]]; then
            [ "${lines[-1]}" -eq 1 ]
        else
            [ "${lines[-1]}" -eq 0 ]
        fi
    done
}

@test "handshake: only non-revoked client certificates of this CA get through (MTLS=yes)" {
    need_docker
    need_compose
    command -v curl >/dev/null || skip "curl not installed"
    mtls_pki
    deploy_nginx_config yes
    start_nginx

    # No certificate
    run req mtls-test.example.com
    [ "${lines[-1]}" = 403 ]
    [[ "$output" == *"Client certificate required"* ]]
    # The real portal server (auth.conf.template) enforces it too
    run req auth.example.com
    [ "${lines[-1]}" = 403 ]
    [[ "$output" == *"Client certificate required"* ]]

    # Valid certificate
    mapfile -t alice < <(as alice)
    run req mtls-test.example.com "${alice[@]}"
    [ "${lines[-1]}" = 200 ]
    [[ "$output" == *"ok CN=alice"* ]]

    # Certificate with the same name from another CA
    local o="$BATS_TEST_TMPDIR/other"
    mkdir -p "$o"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 \
        -subj '/CN=Other CA' -addext basicConstraints=critical,CA:true -keyout "$o/ca.key" -out "$o/ca.crt" 2>/dev/null
    openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj "/CN=alice/O=$PKI_ORG" \
        -keyout "$o/alice.key" -out "$o/alice.csr" 2>/dev/null
    openssl x509 -req -in "$o/alice.csr" -CA "$o/ca.crt" -CAkey "$o/ca.key" -CAcreateserial -days 1 \
        -extfile <(printf 'extendedKeyUsage = clientAuth\n') -out "$o/alice.crt" 2>/dev/null
    run req mtls-test.example.com --cert "$o/alice.crt" --key "$o/alice.key"
    [ "${lines[-1]}" = 403 ]
    [[ "$output" == *"Client certificate rejected"* ]]

    # Revocation: pki_revoke regenerates the CRL and, with MTLS=yes, reloads
    # the running proxy itself (SIGHUP via tls_proxy_reload).
    mapfile -t mallory < <(as mallory)
    run req mtls-test.example.com "${mallory[@]}"
    [ "${lines[-1]}" = 200 ]
    local sess="$BATS_TEST_TMPDIR/mallory.sess"
    printf 'GET / HTTP/1.1\r\nHost: mtls-test.example.com\r\nConnection: close\r\n\r\n' |
        timeout 10 openssl s_client -connect "127.0.0.1:$PORT" -servername mtls-test.example.com \
            -CAfile "$PKI_CA_CERT" -cert "$PKI_CLIENTS_DIR/mallory.crt" -key "$PKI_CLIENTS_DIR/mallory.key" \
            -ign_eof -sess_out "$sess" >/dev/null 2>&1 || true
    MTLS=yes TLS_PROXY_CONTAINER="$CONTAINER" pki_revoke mallory keyCompromise 2>"$BATS_TEST_TMPDIR/revoke.err"
    grep -q 'Sent SIGHUP' "$BATS_TEST_TMPDIR/revoke.err"
    wait_for_code 403 mtls-test.example.com "${mallory[@]}"
    run req mtls-test.example.com "${mallory[@]}"
    [[ "$output" == *"certificate revoked"* ]]
    run req mtls-test.example.com "${alice[@]}"
    [ "${lines[-1]}" = 200 ]
    # A TLS session from before the revocation cannot be resumed to get in
    if [[ -s "$sess" ]]; then
        run bash -c "printf 'GET / HTTP/1.1\r\nHost: mtls-test.example.com\r\nConnection: close\r\n\r\n' |
            timeout 10 openssl s_client -connect 127.0.0.1:$PORT -servername mtls-test.example.com \
            -CAfile '$PKI_CA_CERT' -ign_eof -sess_in '$sess' 2>&1"
        [[ "$output" != *"Reused,"* ]]
        [[ "$output" != *"HTTP/1.1 200"* ]]
    fi

    # Expired CRL: nginx rejects everybody; "cert-renewal.sh renew" issues a
    # fresh CRL and reloads, and alice gets in again.
    # Written to a new file and renamed like pki_gen_crl does: nginx 1.27
    # caches CRLs across reloads by inode and mtime, so an in-place rewrite
    # within the same second would not be picked up.
    openssl ca -config "$PKI_CA_CNF" -passin "file:$PKI_CA_PASSFILE" -gencrl \
        -crl_lastupdate 20200101000000Z -crl_nextupdate 20200102000000Z -out "$PKI_CRL.new" 2>/dev/null
    mv -f "$PKI_CRL.new" "$PKI_CRL"
    docker kill -s SIGHUP "$CONTAINER" >/dev/null
    wait_for_code 403 mtls-test.example.com "${alice[@]}"
    run req mtls-test.example.com "${alice[@]}"
    [[ "$output" == *"CRL has expired"* ]]
    MTLS=yes TLS_PROXY_CONTAINER="$CONTAINER" run "$REPO_ROOT/scripts/automation/cert-renewal.sh" renew
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" == *"CRL regenerated (was: expired)"* ]]
    wait_for_code 200 mtls-test.example.com "${alice[@]}"

    # The plain HTTP health check is unaffected
    run docker exec "$CONTAINER" wget -q -O- http://127.0.0.1/healthz
    [ "$status" -eq 0 ]
    [ "$output" = ok ]
}

@test "handshake: MTLS=no requests no client certificate" {
    need_docker
    need_compose
    command -v curl >/dev/null || skip "curl not installed"
    mtls_pki
    deploy_nginx_config no
    # start_nginx waits for a 403, which MTLS=no never gives on the test server
    local -a vols
    mapfile -t vols < <(compose_nginx_volumes)
    test_server_conf
    CONTAINER="ztvpn-mtls-test-$$-${BATS_TEST_NUMBER}"
    docker run -d --name "$CONTAINER" -p 127.0.0.1::443 \
        -e DOMAIN=example.com -e AUTH_DOMAIN=auth.example.com -e VPN_SUBNET=10.8.0.0/24 \
        -e 'NGINX_ENVSUBST_FILTER=^(DOMAIN|AUTH_DOMAIN|VPN_SUBNET)$' \
        "${vols[@]}" -v "$BATS_TEST_TMPDIR/zz-mtls-test.conf:/etc/nginx/conf.d/zz-mtls-test.conf:ro" \
        "$NGINX_IMAGE" >/dev/null
    PORT="$(docker port "$CONTAINER" 443/tcp | head -n 1)"
    PORT="${PORT##*:}"
    wait_for_code 200 mtls-test.example.com
    run req mtls-test.example.com
    [[ "$output" == "ok "* ]]
    # The portal is still VPN-only (deny for this non-VPN address), no certificate message
    run req auth.example.com
    [ "${lines[-1]}" = 403 ]
    [[ "$output" != *"Client certificate"* ]]
}
