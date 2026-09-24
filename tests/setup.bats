#!/usr/bin/env bats
# Tests for scripts/setup/*.sh. System commands (systemctl, sysctl, docker,
# apt-get, curl) are replaced by stubs that record their arguments.

bats_require_minimum_version 1.5.0
load test_helper

SETUP="$REPO_ROOT/scripts/setup"

setup() {
    ztvpn_sandbox
    export ZTVPN_SYSCTL_FILE="$BATS_TEST_TMPDIR/sysctl.d/99-ztvpn.conf"
    export SYSTEMD_UNIT_DIR="$BATS_TEST_TMPDIR/systemd"
    CALLS="$BATS_TEST_TMPDIR/calls"
    export CALLS
    : >"$CALLS"
    mkdir -p "$BATS_TEST_TMPDIR/bin"
    local c
    for c in systemctl sysctl docker apt-get curl; do
        cat >"$BATS_TEST_TMPDIR/bin/$c" <<'EOF'
#!/usr/bin/env bash
printf '%s %s\n' "$(basename "$0")" "$*" >>"$CALLS"
if [[ "$(basename "$0")" == systemctl && "$1" == is-active ]]; then
    [[ -e "$CALLS.active" ]] && exit 0 || exit 3
fi
exit 0
EOF
        chmod +x "$BATS_TEST_TMPDIR/bin/$c"
    done
    export PATH="$BATS_TEST_TMPDIR/bin:$PATH"
}

sha() { sha256sum "$1" | cut -d' ' -f1; }

# Loads the library with the sandbox paths (in the test shell).
lib() { load_lib; }

# --------------------------------------------------------------------------
# pki-setup.sh
# --------------------------------------------------------------------------

@test "pki-setup: creates encrypted CA and a proper server cert, nothing on stdout" {
    run --separate-stderr "$SETUP/pki-setup.sh" --san 10.0.1.5
    [ "$status" -eq 0 ]
    [ -z "$output" ]
    lib
    grep -q 'ENCRYPTED PRIVATE KEY' "$PKI_CA_KEY"
    [ "$(stat -c %a "$PKI_CA_KEY")" = 400 ]
    [ "$(stat -c %a "$PKI_CA_PASSFILE")" = 600 ]
    crt="$PKI_SERVER_DIR/auth.example.com.crt"
    [ "$(stat -c %a "$PKI_SERVER_DIR/auth.example.com.key")" = 600 ]
    text="$(openssl x509 -in "$crt" -noout -text)"
    [[ "$text" == *"DNS:auth.example.com, DNS:vpn.example.com, IP Address:10.0.1.5"* ]]
    [[ "$text" == *"TLS Web Server Authentication"* ]]
    [[ "$text" == *"Digital Signature"* ]]
    [[ "$text" == *"CA:FALSE"* ]]
    pki_verify "$crt"
    [ -f "$PKI_CRL" ]
    # The old generated helper scripts are gone.
    [ -z "$(find "$ZTVPN_HOME" -name '*.sh')" ]
}

@test "pki-setup: re-run keeps CA, serial state and server cert (incl. earlier --san)" {
    "$SETUP/pki-setup.sh" --san 10.0.1.5
    lib
    ca="$(sha "$PKI_CA_CERT")" key="$(sha "$PKI_CA_KEY")" srv="$(sha "$PKI_SERVER_DIR/auth.example.com.crt")"
    entries="$(wc -l <"$PKI_CA_DIR/index.txt")"
    run "$SETUP/pki-setup.sh"
    [ "$status" -eq 0 ]
    [[ "$output" == *"keeping it"* ]]
    [ "$(sha "$PKI_CA_CERT")" = "$ca" ]
    [ "$(sha "$PKI_CA_KEY")" = "$key" ]
    [ "$(sha "$PKI_SERVER_DIR/auth.example.com.crt")" = "$srv" ]
    [ "$(wc -l <"$PKI_CA_DIR/index.txt")" -eq "$entries" ]
}

@test "pki-setup: new SAN or --reissue issues a new server cert from the same CA" {
    "$SETUP/pki-setup.sh"
    lib
    ca="$(sha "$PKI_CA_CERT")"
    s1="$(openssl x509 -in "$PKI_SERVER_DIR/auth.example.com.crt" -noout -serial)"
    "$SETUP/pki-setup.sh" --san extra.example.com
    s2="$(openssl x509 -in "$PKI_SERVER_DIR/auth.example.com.crt" -noout -serial)"
    [ "$s1" != "$s2" ]
    openssl x509 -in "$PKI_SERVER_DIR/auth.example.com.crt" -noout -ext subjectAltName | grep -q 'DNS:extra.example.com'
    "$SETUP/pki-setup.sh" --reissue
    s3="$(openssl x509 -in "$PKI_SERVER_DIR/auth.example.com.crt" -noout -serial)"
    [ "$s3" != "$s2" ]
    [ "$(sha "$PKI_CA_CERT")" = "$ca" ]
    # serial numbers keep increasing (not reset by re-runs)
    [ "$(grep -c '^V' "$PKI_CA_DIR/index.txt")" -eq 3 ]
}

@test "pki-setup: --force backs up the old CA before replacing it" {
    "$SETUP/pki-setup.sh"
    lib
    old="$(sha "$PKI_CA_CERT")"
    run "$SETUP/pki-setup.sh" --force
    [ "$status" -eq 0 ]
    [ "$(sha "$PKI_CA_CERT")" != "$old" ]
    backup="$(find "$ZTVPN_BACKUP_DIR" -maxdepth 1 -name 'pki-*' | head -n1)"
    [ -n "$backup" ]
    [ "$(sha "$backup/ca/ca.crt")" = "$old" ]
    [ -f "$backup/ca/private/ca.key" ]
    [ -f "$backup/ca.pass" ]
    [ "$(stat -c %a "$backup")" = 700 ]
    pki_verify "$PKI_SERVER_DIR/auth.example.com.crt"
}

@test "pki-setup: incomplete CA is refused unless --force" {
    "$SETUP/pki-setup.sh"
    lib
    rm "$PKI_CA_CERT"
    run "$SETUP/pki-setup.sh"
    [ "$status" -ne 0 ]
    [[ "$output" == *"Incomplete CA"* ]]
    run "$SETUP/pki-setup.sh" --force
    [ "$status" -eq 0 ]
    pki_ca_exists
}

@test "pki-setup: --write-config only rewrites openssl.cnf" {
    run "$SETUP/pki-setup.sh" --write-config
    [ "$status" -ne 0 ]
    "$SETUP/pki-setup.sh"
    lib
    ca="$(sha "$PKI_CA_CERT")"
    rm "$PKI_CA_CNF"
    run "$SETUP/pki-setup.sh" --write-config
    [ "$status" -eq 0 ]
    [ -f "$PKI_CA_CNF" ]
    [ "$(sha "$PKI_CA_CERT")" = "$ca" ]
}

@test "pki-setup: rejects malicious SANs and names" {
    run "$SETUP/pki-setup.sh" --san 'x,DNS:evil.com'
    [ "$status" -ne 0 ]
    AUTH_DOMAIN='auth/CN=evil' run "$SETUP/pki-setup.sh"
    [ "$status" -ne 0 ]
    PKI_ORG='Evil/CN=x' run "$SETUP/pki-setup.sh"
    [ "$status" -ne 0 ]
    [ ! -e "$ZTVPN_HOME/certificates/ca/ca.crt" ]
}

# --------------------------------------------------------------------------
# wireguard-setup.sh
# --------------------------------------------------------------------------

@test "wireguard-setup: keys, config, sysctl drop-in and unit" {
    run --separate-stderr "$SETUP/wireguard-setup.sh"
    [ "$status" -eq 0 ]
    [ -z "$output" ]
    lib
    [ "$(stat -c %a "$WG_SERVER_KEY")" = 600 ]
    [ "$(stat -c %a "$WG_SERVER_PUBKEY")" = 644 ]
    [ "$(stat -c %a "$WG_CONF")" = 600 ]
    [ "$(stat -c %a "$WG_DIR")" = 700 ]
    [ "$(wg pubkey <"$WG_SERVER_KEY")" = "$(<"$WG_SERVER_PUBKEY")" ]
    # private key never printed
    [[ "$stderr" != *"$(<"$WG_SERVER_KEY")"* ]]
    grep -qx 'Address = 10.8.0.1/24' "$WG_CONF"
    grep -qx 'ListenPort = 51820' "$WG_CONF"
    ! grep -Eq '^(DNS|PostUp|PostDown)' "$WG_CONF" || false
    wg-quick strip "$WG_CONF" >/dev/null
    grep -qx 'net.ipv4.ip_forward = 1' "$ZTVPN_SYSCTL_FILE"
    ! grep -Eq '^net\.ipv6' "$ZTVPN_SYSCTL_FILE" || false
    grep -qx "sysctl -p $ZTVPN_SYSCTL_FILE" "$CALLS"
    grep -qx 'systemctl enable --now wg-quick@wg0' "$CALLS"
    ! grep -q 'ufw\|iptables' "$CALLS" || false
    # no helper scripts generated
    [ -z "$(find "$BATS_TEST_TMPDIR" -name 'wg-add-client*' -o -name 'wg-remove-client*')" ]
}

@test "wireguard-setup: re-run keeps key and peers, drops PostUp, reloads running unit" {
    "$SETUP/wireguard-setup.sh"
    lib
    key="$(sha "$WG_SERVER_KEY")"
    wg_provision_peer alice >/dev/null
    wg_provision_peer bob--phone >/dev/null
    # a hand-added peer and a legacy PostUp line
    printf '\n[Peer]\nPublicKey = %s\nAllowedIPs = 10.8.0.50/32\n' "$(wg genkey | wg pubkey)" >>"$WG_CONF"
    sed -i 's/^ListenPort.*/&\nPostUp = iptables -A FORWARD -i %i -j ACCEPT/' "$WG_CONF"
    touch "$CALLS.active"
    : >"$CALLS"
    run "$SETUP/wireguard-setup.sh"
    [ "$status" -eq 0 ]
    [ "$(sha "$WG_SERVER_KEY")" = "$key" ]
    [ "$(wg_list_peers | wc -l)" -eq 2 ]
    wg_peer_exists alice
    wg_peer_exists bob--phone
    grep -q 'AllowedIPs = 10.8.0.50/32' "$WG_CONF"
    ! grep -q '^PostUp' "$WG_CONF" || false
    [ "$(grep -c '^\[Interface\]' "$WG_CONF")" -eq 1 ]
    wg-quick strip "$WG_CONF" >/dev/null
    grep -qx 'systemctl reload wg-quick@wg0' "$CALLS"
    ! grep -q 'restart' "$CALLS" || false
    # unchanged config -> no reload
    : >"$CALLS"
    "$SETUP/wireguard-setup.sh"
    ! grep -q 'reload' "$CALLS" || false
}

@test "wireguard-setup: --force rotates the key and backs up the old one" {
    "$SETUP/wireguard-setup.sh"
    lib
    old="$(<"$WG_SERVER_KEY")"
    "$SETUP/wireguard-setup.sh" --force
    [ "$(<"$WG_SERVER_KEY")" != "$old" ]
    [ "$(wg pubkey <"$WG_SERVER_KEY")" = "$(<"$WG_SERVER_PUBKEY")" ]
    grep -rqx -- "$old" "$ZTVPN_BACKUP_DIR"
}

@test "wireguard-setup: rejects inconsistent network settings" {
    VPN_SERVER_IP=10.9.0.1 run "$SETUP/wireguard-setup.sh"
    [ "$status" -ne 0 ]
    [[ "$output" == *"not inside"* ]]
    WG_PORT=70000 run "$SETUP/wireguard-setup.sh"
    [ "$status" -ne 0 ]
    [ ! -e "$WG_DIR/server_private.key" ]
}

@test "wireguard-setup: moves the broken legacy override.conf aside" {
    d="$SYSTEMD_UNIT_DIR/wg-quick@wg0.service.d"
    mkdir -p "$d"
    printf '[Service]\nExecStart=/usr/bin/wg-quick up %%I\nProtectSystem=strict\n' >"$d/override.conf"
    run "$SETUP/wireguard-setup.sh"
    [ "$status" -eq 0 ]
    [ ! -e "$d/override.conf" ]
    grep -qx 'systemctl daemon-reload' "$CALLS"
}

# --------------------------------------------------------------------------
# authelia-setup.sh
# --------------------------------------------------------------------------

@test "authelia-setup: secrets, config and first admin with argon2id hash" {
    run --separate-stderr "$SETUP/authelia-setup.sh" --admin-user root-admin --admin-email ops@corp.test
    [ "$status" -eq 0 ]
    [ -z "$output" ]
    lib
    [ "$(stat -c %a "$AUTHELIA_SECRETS_DIR")" = 700 ]
    for s in jwt_secret session_secret storage_encryption_key postgres_password redis_password; do
        [ "$(stat -c %a "$AUTHELIA_SECRETS_DIR/$s")" = 600 ]
        [ "$(wc -c <"$AUTHELIA_SECRETS_DIR/$s")" -ge 32 ]
        [[ "$stderr" != *"$(<"$AUTHELIA_SECRETS_DIR/$s")"* ]]
    done
    [ "$(cat "$AUTHELIA_SECRETS_DIR"/* | sort -u | wc -l)" -eq 5 ]
    cmp "$REPO_ROOT/config-examples/authelia/configuration.yml" "$AUTHELIA_DIR/configuration.yml"
    [ "$(stat -c %a "$AUTHELIA_USERS_DB")" = 600 ]

    hash="$(authelia_user_field root-admin password)"
    [[ "$hash" == '$argon2id$v=19$m=65536,t=3,p=4$'* ]]
    [ "$(authelia_user_groups root-admin | paste -sd,)" = "admins,users,vpn-users" ]
    [ "$(authelia_user_field root-admin email)" = "ops@corp.test" ]

    onboarding="$ZTVPN_SECRETS_DIR/onboarding/authelia-root-admin.txt"
    [ "$(stat -c %a "$onboarding")" = 600 ]
    [[ "$stderr" == *"$onboarding"* ]]
    pw="$(awk '$1 == "Password:" { print $2 }' "$onboarding")"
    [ "${#pw}" -eq 24 ]
    [[ "$stderr" != *"$pw"* ]]
    # the stored hash really is the hash of the onboarding password
    salt_b64="$(cut -d'$' -f5 <<<"$hash")"
    while (( ${#salt_b64} % 4 )); do salt_b64+='='; done
    salt="$(base64 -d <<<"$salt_b64")"
    [ "$(printf '%s' "$pw" | argon2 "$salt" -id -t 3 -k 65536 -p 4 -l 32 -e)" = "$hash" ]
    # no generated helper scripts or unit files
    [ -z "$(find "$ZTVPN_HOME" "$BATS_TEST_TMPDIR/systemd" -name '*.sh' -o -name '*.service' 2>/dev/null)" ]
}

@test "authelia-setup: re-run changes nothing, default admin only when no admin exists" {
    "$SETUP/authelia-setup.sh"
    lib
    authelia_user_exists admin
    before="$(cat "$AUTHELIA_SECRETS_DIR"/* | sha256sum)"
    hash="$(authelia_user_field admin password)"
    rm "$ZTVPN_SECRETS_DIR/onboarding/authelia-admin.txt"
    run "$SETUP/authelia-setup.sh"
    [ "$status" -eq 0 ]
    [ "$(cat "$AUTHELIA_SECRETS_DIR"/* | sha256sum)" = "$before" ]
    [ "$(authelia_user_field admin password)" = "$hash" ]
    [ ! -e "$ZTVPN_SECRETS_DIR/onboarding/authelia-admin.txt" ]
    [ "$(authelia_list_users | wc -l)" -eq 1 ]
    # a missing secret is re-created, existing ones stay
    rm "$AUTHELIA_SECRETS_DIR/redis_password"
    jwt="$(<"$AUTHELIA_SECRETS_DIR/jwt_secret")"
    "$SETUP/authelia-setup.sh"
    [ -s "$AUTHELIA_SECRETS_DIR/redis_password" ]
    [ "$(<"$AUTHELIA_SECRETS_DIR/jwt_secret")" = "$jwt" ]
}

@test "authelia-setup: local config edits survive unless --force (with backup)" {
    "$SETUP/authelia-setup.sh"
    lib
    echo '# local edit' >>"$AUTHELIA_DIR/configuration.yml"
    run "$SETUP/authelia-setup.sh"
    [ "$status" -eq 0 ]
    grep -q '# local edit' "$AUTHELIA_DIR/configuration.yml"
    run "$SETUP/authelia-setup.sh" --force
    [ "$status" -eq 0 ]
    ! grep -q '# local edit' "$AUTHELIA_DIR/configuration.yml" || false
    grep -rq '# local edit' "$ZTVPN_BACKUP_DIR/authelia"
}

@test "authelia-setup: --validate runs authelia validate-config without secrets on the command line" {
    run "$SETUP/authelia-setup.sh" --validate
    [ "$status" -eq 0 ]
    lib
    line="$(grep '^docker ' "$CALLS")"
    [[ "$line" == *"authelia validate-config --config /config/configuration.yml"* ]]
    [[ "$line" == *"$AUTHELIA_IMAGE"* ]]
    for s in "$AUTHELIA_SECRETS_DIR"/*; do
        [[ "$line" != *"$(<"$s")"* ]]
    done
}

@test "authelia-setup: rejects invalid admin input and ldap backend skips local users" {
    run "$SETUP/authelia-setup.sh" --admin-user 'Bad;rm'
    [ "$status" -ne 0 ]
    run "$SETUP/authelia-setup.sh" --admin-user alice --admin-email 'a"b@x'
    [ "$status" -ne 0 ]
    AUTHELIA_BACKEND=ldap run "$SETUP/authelia-setup.sh"
    [ "$status" -eq 0 ]
    [ ! -e "$ZTVPN_HOME/authelia/users_database.yml" ]
}

# --------------------------------------------------------------------------
# initial-setup.sh
# --------------------------------------------------------------------------

# Copy of the repo so a stub firewall-setup.sh can be dropped in.
fake_repo() {
    FAKE="$BATS_TEST_TMPDIR/repo"
    mkdir -p "$FAKE"
    cp -a "$REPO_ROOT/scripts" "$REPO_ROOT/config-examples" "$FAKE/"
    cat >"$FAKE/scripts/setup/firewall-setup.sh" <<'EOF'
#!/usr/bin/env bash
printf 'firewall-setup %s\n' "$*" >>"$CALLS"
EOF
    printf 'ID=debian\nVERSION_CODENAME=bookworm\n' >"$BATS_TEST_TMPDIR/os-release"
    export ZTVPN_OS_RELEASE="$BATS_TEST_TMPDIR/os-release"
    export COMPOSE_DIR="$ZTVPN_HOME"
}

write_config() {
    printf 'DOMAIN=corp.test\nAUTH_DOMAIN=auth.corp.test\nVPN_ENDPOINT=vpn.corp.test\nTZ=Europe/Berlin\nPROXY_BIND_ADDR=10.0.1.1\n' >"$ZTVPN_CONFIG"
    chmod 600 "$ZTVPN_CONFIG"
}

@test "initial-setup: --help works and touches nothing" {
    run "$SETUP/initial-setup.sh" --help
    [ "$status" -eq 0 ]
    [[ "$output" == *"--skip-packages"* ]]
    [ ! -e "$ZTVPN_CONFIG" ]
    run "$SETUP/initial-setup.sh" --bogus
    [ "$status" -eq 2 ]
}

@test "initial-setup: installs example config then refuses placeholder domain" {
    fake_repo
    run "$FAKE/scripts/setup/initial-setup.sh" --skip-packages --skip-docker --non-interactive
    [ "$status" -ne 0 ]
    [[ "$output" == *"placeholder"* ]]
    [ "$(stat -c %a "$ZTVPN_CONFIG")" = 600 ]
    cmp "$REPO_ROOT/config-examples/ztvpn.conf.example" "$ZTVPN_CONFIG"
    [ ! -e "$ZTVPN_HOME/certificates/ca/ca.crt" ]
}

@test "initial-setup: fails clearly when firewall-setup.sh is missing" {
    fake_repo
    write_config
    rm "$FAKE/scripts/setup/firewall-setup.sh"
    run "$FAKE/scripts/setup/initial-setup.sh" --skip-packages --skip-docker --non-interactive
    [ "$status" -ne 0 ]
    [[ "$output" == *"firewall-setup.sh is missing"* ]]
    ! grep -q 'wg-quick' "$CALLS" || false
}

@test "initial-setup: sandboxed run with --skip-packages --skip-docker, then re-run" {
    fake_repo
    write_config
    run "$FAKE/scripts/setup/initial-setup.sh" --skip-packages --skip-docker --non-interactive \
        --admin-user boss --admin-email boss@corp.test
    echo "$output"
    [ "$status" -eq 0 ]
    lib
    # steps ran, firewall before forwarding/WireGuard
    grep -qx 'firewall-setup --apply' "$CALLS"
    fw="$(grep -n '^firewall-setup' "$CALLS" | cut -d: -f1)"
    sc="$(grep -n '^sysctl -p' "$CALLS" | cut -d: -f1)"
    [ -n "$fw" ] && [ -n "$sc" ] && [ "$fw" -lt "$sc" ]
    grep -qx 'systemctl enable --now wg-quick@wg0' "$CALLS"
    ! grep -q '^docker\|^apt-get\|^curl' "$CALLS" || false
    [ -f "$PKI_SERVER_DIR/auth.corp.test.crt" ]
    openssl x509 -in "$PKI_SERVER_DIR/auth.corp.test.crt" -noout -ext subjectAltName | grep -q 'DNS:vpn.corp.test'
    [ -f "$WG_CONF" ]
    authelia_user_exists boss
    # directories root-owned with tight modes
    [ "$(stat -c %U:%a "$ZTVPN_SECRETS_DIR")" = root:700 ]
    [ "$(stat -c %U:%a "$ZTVPN_STATE_DIR")" = root:750 ]
    [ "$(stat -c %U:%a "$WG_CLIENTS_DIR")" = root:700 ]
    # compose deployment
    cmp "$REPO_ROOT/config-examples/docker/docker-compose.yml" "$COMPOSE_DIR/docker-compose.yml"
    env="$COMPOSE_DIR/.env"
    [ "$(stat -c %a "$env")" = 600 ]
    grep -qx 'DOMAIN=corp.test' "$env"
    grep -qx 'AUTH_DOMAIN=auth.corp.test' "$env"
    grep -qx 'TZ=Europe/Berlin' "$env"
    grep -qx "AUTHELIA_DIR=$AUTHELIA_DIR" "$env"
    grep -qx "CERTS_PATH=$CERTS_PATH" "$env"
    grep -qx "PROXY_BIND_ADDR=10.0.1.1" "$env"
    for s in "$AUTHELIA_SECRETS_DIR"/* "$PKI_CA_PASSFILE"; do
        ! grep -qF "$(<"$s")" "$env" || false
    done
    ! grep -qi 'password\|secret=' "$env" || false

    ca="$(sha "$PKI_CA_CERT")" wgkey="$(sha "$WG_SERVER_KEY")"
    run "$FAKE/scripts/setup/initial-setup.sh" --skip-packages --skip-docker --non-interactive
    [ "$status" -eq 0 ]
    [ "$(sha "$PKI_CA_CERT")" = "$ca" ]
    [ "$(sha "$WG_SERVER_KEY")" = "$wgkey" ]
    [ "$(authelia_list_users | wc -l)" -eq 1 ]
}

@test "initial-setup: snippets/mtls.conf is generated from MTLS on every run" {
    fake_repo
    write_config
    run "$FAKE/scripts/setup/initial-setup.sh" --skip-packages --skip-docker --non-interactive
    [ "$status" -eq 0 ]
    lib
    snip="$CONFIG_PATH/nginx/snippets/mtls.conf"
    [ "$snip" = "$MTLS_SNIPPET" ]
    [ "$(stat -c %U:%a "$snip")" = root:644 ]
    cmp "$snip" "$REPO_ROOT/config-examples/nginx/snippets/mtls.conf"
    ! grep -q '^ssl_verify_client' "$snip" || false
    grep -q 'include /etc/nginx/snippets/mtls.conf;' "$CONFIG_PATH/nginx/templates/auth.conf.template"
    [[ "$output" == *"MTLS=no: nginx does not check client certificates"* ]]

    # MTLS=yes: regenerated (a local edit is not kept), no "differs" warning
    printf 'MTLS=yes\n' >>"$ZTVPN_CONFIG"
    echo '# local edit' >>"$snip"
    run "$FAKE/scripts/setup/initial-setup.sh" --skip-packages --skip-docker --non-interactive
    [ "$status" -eq 0 ]
    [[ "$output" != *"mtls.conf differs"* ]]
    ! grep -q 'local edit' "$snip" || false
    grep -qx 'ssl_verify_client      on;' "$snip"
    grep -qx 'ssl_client_certificate /etc/nginx/client-ca/ca.crt;' "$snip"
    grep -qx 'ssl_crl                /etc/nginx/crl/ca.crl;' "$snip"
    # compose mounts exactly these host files
    [ "$PKI_CA_CERT" = "$CERTS_PATH/ca/ca.crt" ]
    [ "$PKI_CRL" = "$CERTS_PATH/crl/ca.crl" ]

    # A locally kept template whose HTTPS server lacks the include would
    # silently skip the client certificate check: refused.
    printf 'server {\n    listen 443 ssl;\n    server_name app.corp.test;\n}\n' >"$CONFIG_PATH/nginx/templates/app.conf.template"
    run "$FAKE/scripts/setup/initial-setup.sh" --skip-packages --skip-docker --non-interactive
    [ "$status" -ne 0 ]
    [[ "$output" == *"app.conf.template"* ]]
    rm "$CONFIG_PATH/nginx/templates/app.conf.template"

    sed -i 's/^MTLS=yes$/MTLS=no/' "$ZTVPN_CONFIG"
    run "$FAKE/scripts/setup/initial-setup.sh" --skip-packages --skip-docker --non-interactive
    [ "$status" -eq 0 ]
    cmp "$snip" "$REPO_ROOT/config-examples/nginx/snippets/mtls.conf"

    before="$(sha "$snip")"
    sed -i 's/^MTLS=no$/MTLS=on/' "$ZTVPN_CONFIG"
    run "$FAKE/scripts/setup/initial-setup.sh" --skip-packages --skip-docker --non-interactive
    [ "$status" -ne 0 ]
    [[ "$output" == *"MTLS"*"must be yes or no"* ]]
    sed -i 's/^MTLS=on$/MTLS=yes/' "$ZTVPN_CONFIG"
    PKI_CRL="$BATS_TEST_TMPDIR/elsewhere.crl" run "$FAKE/scripts/setup/initial-setup.sh" --skip-packages --skip-docker --non-interactive
    [ "$status" -ne 0 ]
    [[ "$output" == *"MTLS=yes needs"* ]]
    [ "$(sha "$snip")" = "$before" ]
}

@test "initial-setup: rejects values that would be unsafe in .env" {
    fake_repo
    write_config
    TZ='Europe/Berlin $(id)' run "$FAKE/scripts/setup/initial-setup.sh" --skip-packages --skip-docker --non-interactive
    [ "$status" -ne 0 ]
    [[ "$output" == *"not allowed in .env"* ]]
}

@test "initial-setup: refuses to deploy without a proxy address in SERVICES_SUBNET" {
    fake_repo
    write_config
    sed -i '/^PROXY_BIND_ADDR=/d' "$ZTVPN_CONFIG"
    printf 'SERVICES_SUBNET=203.0.113.0/24\n' >>"$ZTVPN_CONFIG"
    run "$FAKE/scripts/setup/initial-setup.sh" --skip-packages --skip-docker --non-interactive
    [ "$status" -ne 0 ]
    [[ "$output" == *"PROXY_BIND_ADDR"* ]]
    [ ! -e "$PKI_CA_CERT" ]
}
