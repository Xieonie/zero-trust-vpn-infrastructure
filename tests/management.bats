#!/usr/bin/env bats
# Tests for scripts/management/*.sh

load test_helper

bats_require_minimum_version 1.5.0

ADD="$BATS_TEST_DIRNAME/../scripts/management/add-user.sh"
REVOKE="$BATS_TEST_DIRNAME/../scripts/management/revoke-user.sh"
DEVICE="$BATS_TEST_DIRNAME/../scripts/management/device-enrollment.sh"
POLICY="$BATS_TEST_DIRNAME/../scripts/management/policy-update.sh"

setup() {
    ztvpn_sandbox
    ztvpn_fake_wg_server
    STUBS="$BATS_TEST_TMPDIR/bin"
    CALLS="$BATS_TEST_TMPDIR/calls"
    mkdir -p "$STUBS"
    : >"$CALLS"
    export STUBS CALLS
    # No interface in the sandbox: "ip link show wg0" must fail.
    stub ip 'exit 1'
    stub systemctl 'exit 0'
    # qrencode: only accept the config via -r <file>, never on argv.
    stub qrencode 'out=""; while (($#)); do case "$1" in -o) out="$2"; shift 2 ;; *) shift ;; esac; done
[[ -n "$out" ]] && printf "PNG" >"$out"'
    export PATH="$STUBS:$PATH"
    load_lib
}

# stub <name> <body>: fake command that logs its argv to $CALLS.
stub() {
    printf '#!/usr/bin/env bash\nprintf "%%s %%s\\n" %q "$*" >>"$CALLS"\n%s\n' "$1" "$2" >"$STUBS/$1"
    chmod +x "$STUBS/$1"
}

# Value of key=value line in $output (stdout only when --separate-stderr).
kv() {
    sed -n "s/^$1=//p" <<<"$output"
}

with_ca() {
    pki_init_ca >/dev/null 2>&1
}

sandbox_snapshot() {
    (cd "$BATS_TEST_TMPDIR" && find etc opt state log backup wireguard -exec sh -c \
        'for f; do if [ -f "$f" ]; then printf "%s %s\n" "$f" "$(sha256sum <"$f" | cut -c1-64)"; else printf "%s dir\n" "$f"; fi; done' _ {} + \
        2>/dev/null | sort)
}

minimal_authelia_config() {
    mkdir -p "$AUTHELIA_DIR"
    cat >"$AUTHELIA_DIR/configuration.yml" <<'EOF'
# Minimal Authelia config for tests
server:
  address: 'tcp://0.0.0.0:9091/'
identity_validation:
  reset_password:
    jwt_secret: 'a_very_important_secret_with_enough_length_0123456789'
authentication_backend:
  file:
    path: /config/users_database.yml
access_control:
  default_policy: deny
  networks:
    - name: vpn
      networks:
        - 10.8.0.0/24
    - name: internal
      networks:
        - 10.0.1.0/24
  rules:
    # auth portal
    - domain: 'auth.example.com'
      policy: bypass
    - domain: '*.example.com'
      policy: two_factor
      subject:
        - 'group:admins'
      networks:
        - vpn
session:
  secret: 'insecure_session_secret_0123456789abcdef'
  cookies:
    - domain: 'example.com'
      authelia_url: 'https://auth.example.com'
storage:
  encryption_key: 'you_must_generate_a_random_string_of_more_than_twenty_chars'
  local:
    path: /tmp/db.sqlite3
notifier:
  filesystem:
    filename: /tmp/notification.txt
EOF
    chmod 600 "$AUTHELIA_DIR/configuration.yml"
}

# --------------------------------------------------------------------------
# add-user.sh
# --------------------------------------------------------------------------

@test "add-user: two users get distinct single-line IPs and a valid server config" {
    run --separate-stderr "$ADD" alice alice@example.com --name "Alice A"
    [ "$status" -eq 0 ]
    ip1="$(kv ip)"
    onboarding="$(kv onboarding)"
    conf1="$(kv client_config)"
    run --separate-stderr "$ADD" carol carol@example.com
    [ "$status" -eq 0 ]
    ip2="$(kv ip)"

    [ "$ip1" = "10.8.0.2" ]
    [ "$ip2" = "10.8.0.3" ]
    [ "$(printf '%s' "$ip1" | wc -l)" -eq 0 ]
    wg_peer_exists alice
    wg_peer_exists carol
    run wg-quick strip "$WG_CONF"
    [ "$status" -eq 0 ]
    run wg-quick strip "$conf1"
    [ "$status" -eq 0 ]
    grep -q "^PublicKey = $(<"$WG_SERVER_PUBKEY")$" "$conf1"
    [ "$(stat -c %a "$conf1")" = "600" ]

    # Account with default groups, password only in the 0600 onboarding file.
    [ "$(authelia_user_field alice displayname)" = "Alice A" ]
    [ "$(authelia_user_field alice disabled)" = "false" ]
    [ "$(authelia_user_groups alice | paste -sd, -)" = "users,vpn-users" ]
    [[ "$(authelia_user_field alice password)" == '$argon2id$'* ]]
    [[ "$onboarding" == "$ZTVPN_SECRETS_DIR/onboarding/alice-"*.txt ]]
    [ "$(stat -c %a "$onboarding")" = "600" ]
    [ "$(stat -c %a "$ZTVPN_SECRETS_DIR/onboarding")" = "700" ]
    pw="$(sed -n 's/^One-time password: *//p' "$onboarding")"
    [ "${#pw}" -eq 20 ]
    ! grep -rqF -- "$pw" "$ZTVPN_LOG_DIR" "$AUTHELIA_USERS_DB"

    # Nothing secret on stdout.
    ! grep -q PrivateKey <<<"$output"
    jq -e '.devices | length == 2' "$DEVICE_INVENTORY"
    [ "$(stat -c %a "$DEVICE_INVENTORY")" = "600" ]
}

@test "add-user: never prints the password" {
    run "$ADD" alice alice@example.com
    [ "$status" -eq 0 ]
    onboarding="$(sed -n 's/^onboarding=//p' <<<"$output")"
    pw="$(sed -n 's/^One-time password: *//p' "$onboarding")"
    [[ "$output" != *"$pw"* ]]
}

@test "add-user: --admin and --groups are merged with the default groups" {
    run "$ADD" dave dave@example.com --admin --groups employees,remote-workers --device laptop
    [ "$status" -eq 0 ]
    [ "$(authelia_user_groups dave | paste -sd, -)" = "users,vpn-users,employees,remote-workers,admins" ]
    wg_peer_exists dave--laptop
    ! wg_peer_exists dave
}

@test "add-user: invalid names, emails and groups are rejected and nothing is created" {
    before="$(sha256sum "$WG_CONF")"
    for args in \
        "Bob bob@example.com" \
        "bob--x bob@example.com" \
        'bo"b bob@example.com' \
        "bob bob@" \
        "bob bob@example.com --groups wheel" \
        "bob bob@example.com --groups administrators" \
        "bob bob@example.com --groups users,Bad" \
        "bob bob@example.com --device Bad/dev" \
        "bob bob@example.com --no-vpn --qr" \
        "bob"; do
        # shellcheck disable=SC2086
        run "$ADD" $args
        [ "$status" -ne 0 ]
    done
    run "$ADD" bob bob@example.com --name $'Bob\nInjected: x'
    [ "$status" -ne 0 ]
    [ ! -e "$AUTHELIA_USERS_DB" ] || ! authelia_user_exists bob
    [ "$(sha256sum "$WG_CONF")" = "$before" ]
    [ ! -e "$WG_CLIENTS_DIR/bob" ]
    [ ! -e "$DEVICE_INVENTORY" ]
    [ -z "$(ls -A "$ZTVPN_SECRETS_DIR/onboarding" 2>/dev/null)" ]
}

@test "add-user: existing user is refused without side effects" {
    "$ADD" alice alice@example.com >/dev/null 2>&1
    before="$(sha256sum "$WG_CONF" "$AUTHELIA_USERS_DB")"
    run "$ADD" alice other@example.com --device phone
    [ "$status" -ne 0 ]
    [ "$(sha256sum "$WG_CONF" "$AUTHELIA_USERS_DB")" = "$before" ]
}

@test "add-user: failing certificate issuance rolls back account and peer" {
    with_ca
    "$ADD" alice alice@example.com >/dev/null 2>&1
    # wg_remove_peer leaves the blank separator line, so compare content.
    wg_before="$(grep -v '^$' "$WG_CONF")"
    peers_before="$(wg_list_peers)"
    inv_before="$(jq -S . "$DEVICE_INVENTORY")"
    # Break the CA passphrase so "openssl ca" fails after user + peer exist.
    chmod 600 "$PKI_CA_PASSFILE"
    echo wrong-passphrase >"$PKI_CA_PASSFILE"

    run "$ADD" carol carol@example.com --cert --device laptop
    [ "$status" -ne 0 ]
    [[ "$output" == *"Rolling back"* ]]
    ! authelia_user_exists carol
    authelia_user_exists alice
    ! wg_peer_exists carol--laptop
    [ ! -e "$WG_CLIENTS_DIR/carol--laptop" ]
    [ "$(wg_list_peers)" = "$peers_before" ]
    [ "$(grep -v '^$' "$WG_CONF")" = "$wg_before" ]
    [ "$(jq -S . "$DEVICE_INVENTORY")" = "$inv_before" ]
    [ -z "$(pki_valid_serials carol--laptop)" ]
    [ ! -e "$PKI_CLIENTS_DIR/carol--laptop.key" ]
    [ -z "$(ls "$ZTVPN_SECRETS_DIR/onboarding" | grep carol || true)" ]
}

@test "add-user: --cert issues a client cert and --qr writes a private PNG via file input" {
    with_ca
    run --separate-stderr "$ADD" erin erin@example.com --cert --qr
    [ "$status" -eq 0 ]
    cert="$(kv cert)"
    qr="$(kv qr)"
    [ "$cert" = "$PKI_CLIENTS_DIR/erin.crt" ]
    pki_verify "$cert"
    [ "$(stat -c %a "$qr")" = "600" ]
    grep -q "^qrencode .*-r $WG_CLIENTS_DIR/erin/erin.conf" "$CALLS"
    ! grep -q PrivateKey "$CALLS"
}

@test "add-user: never sends mail" {
    stub sendmail 'exit 0'
    stub mail 'exit 0'
    run "$ADD" alice alice@example.com
    [ "$status" -eq 0 ]
    ! grep -Eq '^(sendmail|mail) ' "$CALLS"
}

# --------------------------------------------------------------------------
# revoke-user.sh
# --------------------------------------------------------------------------

setup_bob_family() {
    with_ca
    "$ADD" bob bob@example.com --cert >/dev/null 2>&1
    "$ADD" bobby bobby@example.com --cert >/dev/null 2>&1
    "$DEVICE" enroll --user bob --device laptop --cert >/dev/null 2>&1
    wg_peer_exists bob
    wg_peer_exists bob--laptop
    wg_peer_exists bobby
}

@test "revoke-user: bob loses everything, bobby is untouched" {
    setup_bob_family
    bob_serials="$(pki_valid_serials bob; pki_valid_serials bob--laptop)"
    bobby_serial="$(pki_valid_serials bobby)"
    bobby_ip="$(wg_peer_ip bobby)"
    [ "$(printf '%s\n' "$bob_serials" | wc -l)" -eq 2 ]

    run "$REVOKE" bob --reason affiliationChanged
    [ "$status" -eq 0 ]

    ! wg_peer_exists bob
    ! wg_peer_exists bob--laptop
    [ ! -e "$WG_CLIENTS_DIR/bob" ]
    [ ! -e "$WG_CLIENTS_DIR/bob--laptop" ]
    wg_peer_exists bobby
    [ "$(wg_peer_ip bobby)" = "$bobby_ip" ]
    [ -d "$WG_CLIENTS_DIR/bobby" ]
    run wg-quick strip "$WG_CONF"
    [ "$status" -eq 0 ]

    [ "$(authelia_user_field bob disabled)" = "true" ]
    [ "$(authelia_user_field bobby disabled)" = "false" ]

    crl="$(openssl crl -in "$PKI_CRL" -noout -text)"
    for s in $bob_serials; do
        [[ "$crl" == *"$s"* ]]
    done
    [[ "$crl" != *"$bobby_serial"* ]]
    [[ "$crl" == *"Affiliation Changed"* ]]
    [ -z "$(pki_valid_serials bob)" ]
    [ -z "$(pki_valid_serials bob--laptop)" ]
    [ "$(pki_valid_serials bobby)" = "$bobby_serial" ]
    pki_verify "$PKI_CLIENTS_DIR/bobby.crt"
    [ ! -e "$PKI_CLIENTS_DIR/bob.key" ]

    [ "$(jq -r '.devices[] | select(.username == "bob") | .status' "$DEVICE_INVENTORY" | sort -u)" = "revoked" ]
    [ "$(jq -r '.devices[] | select(.username == "bobby") | .status' "$DEVICE_INVENTORY")" = "active" ]

    archive="$(ls -d "$ZTVPN_BACKUP_DIR"/revoked/bob-*)"
    [ "$(stat -c %a "$archive")" = "700" ]
    [ -f "$archive/wireguard/bob--laptop/public.key" ]
    [ -f "$archive/certs/bob.key" ]
    grep -q 'revoke-user .*user=bob .*result=ok' "$ZTVPN_LOG_DIR/audit.log"
}

@test "revoke-user: continues past failures and reports them" {
    setup_bob_family
    chmod 600 "$PKI_CA_PASSFILE"
    echo wrong-passphrase >"$PKI_CA_PASSFILE"
    run "$REVOKE" bob
    [ "$status" -eq 1 ]
    [[ "$output" == *"INCOMPLETE"* ]]
    [[ "$output" == *"Could not revoke certificates for bob"* ]]
    # The other steps still happened.
    ! wg_peer_exists bob
    ! wg_peer_exists bob--laptop
    [ "$(authelia_user_field bob disabled)" = "true" ]
    wg_peer_exists bobby
    grep -q 'user=bob .*result=partial' "$ZTVPN_LOG_DIR/audit.log"
}

@test "revoke-user: ldap backend without hook reports a manual step, never fakes it" {
    "$ADD" frank frank@example.com >/dev/null 2>&1
    stub ldapmodify 'exit 0'
    AUTHELIA_BACKEND=ldap run "$REVOKE" frank
    [ "$status" -eq 2 ]
    [[ "$output" == *"MANUAL"* ]]
    ! wg_peer_exists frank
    ! grep -q '^ldapmodify' "$CALLS"
    ! grep -rq userAccountControl "$BATS_TEST_TMPDIR" --exclude-dir=bin
}

@test "revoke-user: ldap backend calls the configured disable hook" {
    "$ADD" frank frank@example.com >/dev/null 2>&1
    stub ldap-disable 'exit 0'
    AUTHELIA_BACKEND=ldap LDAP_DISABLE_HOOK="$STUBS/ldap-disable" run "$REVOKE" frank
    [ "$status" -eq 0 ]
    grep -qx 'ldap-disable frank disable' "$CALLS"
}

@test "revoke-user: unknown and invalid users" {
    run "$REVOKE" nobody
    [ "$status" -ne 0 ]
    [[ "$output" == *"Nothing found"* ]]
    run "$REVOKE" 'bob*'
    [ "$status" -ne 0 ]
    run "$REVOKE" bob --reason 'evil; rm -rf /'
    [ "$status" -ne 0 ]
    run "$REVOKE" bob --keep-account --delete-account
    [ "$status" -ne 0 ]
}

@test "revoke-user: --delete-account removes the entry, --keep-account leaves it" {
    "$ADD" gina gina@example.com >/dev/null 2>&1
    "$ADD" hank hank@example.com >/dev/null 2>&1
    run "$REVOKE" gina --delete-account
    [ "$status" -eq 0 ]
    ! authelia_user_exists gina
    run "$REVOKE" hank --keep-account
    [ "$status" -eq 0 ]
    [ "$(authelia_user_field hank disabled)" = "false" ]
    ! wg_peer_exists hank
}

# --------------------------------------------------------------------------
# device-enrollment.sh
# --------------------------------------------------------------------------

@test "device enroll: requires an existing, enabled Authelia user" {
    run "$DEVICE" enroll --user ghost --device laptop
    [ "$status" -ne 0 ]
    [[ "$output" == *"add-user.sh"* ]]
    ! wg_peer_exists ghost--laptop
    "$ADD" alice alice@example.com >/dev/null 2>&1
    authelia_set_disabled alice true
    run "$DEVICE" enroll --user alice --device laptop
    [ "$status" -ne 0 ]
    ! wg_peer_exists alice--laptop
}

@test "device enroll: --ip collisions and foreign subnets are rejected" {
    "$ADD" alice alice@example.com >/dev/null 2>&1
    used="$(wg_peer_ip alice)"
    before="$(sha256sum <"$WG_CONF")"
    for ip in "$used" 10.8.0.1 10.0.2.5 10.8.0.255 10.8.0.0 999.1.1.1 '10.8.0.7/32'; do
        run "$DEVICE" enroll --user alice --device phone --type phone --ip "$ip"
        [ "$status" -ne 0 ]
    done
    [ "$(sha256sum <"$WG_CONF")" = "$before" ]
    [ ! -e "$WG_CLIENTS_DIR/alice--phone" ]

    run --separate-stderr "$DEVICE" enroll --user alice --device phone --type phone --ip 10.8.0.50
    [ "$status" -eq 0 ]
    [ "$(kv ip)" = "10.8.0.50" ]
    [ "$(wg_peer_ip alice--phone)" = "10.8.0.50" ]
    run wg-quick strip "$WG_CLIENTS_DIR/alice--phone/alice--phone.conf"
    [ "$status" -eq 0 ]
    run "$DEVICE" enroll --user alice --device phone
    [ "$status" -ne 0 ]
}

@test "device enroll: --dry-run writes nothing" {
    with_ca
    "$ADD" alice alice@example.com >/dev/null 2>&1
    before="$(sandbox_snapshot)"
    run --separate-stderr "$DEVICE" enroll --user alice --device tablet --type tablet --cert --qr --dry-run
    [ "$status" -eq 0 ]
    [ "$(kv dry_run)" = "1" ]
    [ "$(kv ip)" = "10.8.0.3" ]
    [ "$(sandbox_snapshot)" = "$before" ]
    ! grep -q '^qrencode' "$CALLS"
}

@test "device enroll/list/show/remove keep a valid inventory" {
    with_ca
    "$ADD" alice alice@example.com >/dev/null 2>&1
    run "$DEVICE" enroll --user alice --device laptop --type desktop --cert
    [ "$status" -eq 0 ]
    jq -e . "$DEVICE_INVENTORY" >/dev/null
    [ "$(stat -c %a "$DEVICE_INVENTORY")" = "600" ]
    [ "$(jq -r '.devices[] | select(.id == "alice--laptop") | .device_type' "$DEVICE_INVENTORY")" = "desktop" ]
    [ "$(jq -r '.devices[] | select(.id == "alice--laptop") | .certificate_expiry' "$DEVICE_INVENTORY")" != "null" ]

    run --separate-stderr "$DEVICE" list --user alice
    [ "$status" -eq 0 ]
    [[ "$output" == *"alice--laptop"*"active"* ]]
    run --separate-stderr "$DEVICE" show --user alice --device laptop
    [ "$status" -eq 0 ]
    [ "$(jq -r .wireguard_peer_present <<<"$output")" = "true" ]
    [[ "$output" != *"PrivateKey"* ]]

    serial="$(pki_valid_serials alice--laptop)"
    run "$DEVICE" remove --user alice --device laptop --reason keyCompromise
    [ "$status" -eq 0 ]
    ! wg_peer_exists alice--laptop
    wg_peer_exists alice
    [ -z "$(pki_valid_serials alice--laptop)" ]
    openssl crl -in "$PKI_CRL" -noout -text | grep -q "$serial"
    [ "$(jq -r '.devices[] | select(.id == "alice--laptop") | .status' "$DEVICE_INVENTORY")" = "revoked" ]
    [ "$(jq -r '.devices[] | select(.id == "alice") | .status' "$DEVICE_INVENTORY")" = "active" ]
    jq -e . "$DEVICE_INVENTORY" >/dev/null

    # Re-enrolling the same name replaces the revoked entry.
    run "$DEVICE" enroll --user alice --device laptop
    [ "$status" -eq 0 ]
    [ "$(jq '[.devices[] | select(.id == "alice--laptop")] | length' "$DEVICE_INVENTORY")" -eq 1 ]
}

@test "device enroll: hostile names never reach the inventory or configs" {
    "$ADD" alice alice@example.com >/dev/null 2>&1
    for dev in 'lap"top' 'a b' '../x' '-x' '$(id)' 'LAPTOP' "$(printf 'x\ny')"; do
        run "$DEVICE" enroll --user alice --device "$dev"
        [ "$status" -ne 0 ]
    done
    run "$DEVICE" enroll --user alice --device laptop --type 'laptop"}'
    [ "$status" -ne 0 ]
    [ "$(jq '.devices | length' "$DEVICE_INVENTORY")" -eq 1 ]
}

@test "management scripts write nothing into the git checkout" {
    touch "$BATS_TEST_TMPDIR/marker"
    with_ca
    "$ADD" alice alice@example.com --cert >/dev/null 2>&1
    "$DEVICE" enroll --user alice --device phone --cert >/dev/null 2>&1
    pub="$(<"$WG_CLIENTS_DIR/alice--phone/public.key")"
    "$REVOKE" alice >/dev/null 2>&1
    run find "$REPO_ROOT" -path "$REPO_ROOT/.git" -prune -o -newer "$BATS_TEST_TMPDIR/marker" \
        \( -name '*.key' -o -name '*.crt' -o -name '*.pem' -o -name '*.json' -o -name '*.conf' \
           -o -name '*.png' -o -name '*.txt' -o -name '*.ldif' -o -name '*.yml' \) -print
    [ -z "$output" ]
    ! grep -rqF --exclude-dir=.git -- "$pub" "$REPO_ROOT"
    [ -z "$(find /tmp -maxdepth 1 -newer "$BATS_TEST_TMPDIR/marker" -name '*alice*' 2>/dev/null)" ]
}

# --------------------------------------------------------------------------
# policy-update.sh
# --------------------------------------------------------------------------

@test "policy: add-rule and remove-rule persist in the live config" {
    minimal_authelia_config
    export AUTHELIA_VALIDATE=yq
    run "$POLICY" add-rule --domain app.example.com --policy one_factor \
        --subject group:employees --subject user:alice --network vpn --resource '^/api/.*$' --position 1
    [ "$status" -eq 0 ]
    [ "$(yq '.access_control.rules[1].domain' "$AUTHELIA_DIR/configuration.yml")" = "app.example.com" ]
    [ "$(yq '.access_control.rules[1].subject | join(",")' "$AUTHELIA_DIR/configuration.yml")" = "group:employees,user:alice" ]
    [ "$(yq '.access_control.rules[1].resources[0]' "$AUTHELIA_DIR/configuration.yml")" = '^/api/.*$' ]
    [ "$(yq '.access_control.rules | length' "$AUTHELIA_DIR/configuration.yml")" -eq 3 ]
    grep -q '# auth portal' "$AUTHELIA_DIR/configuration.yml"
    [ "$(stat -c %a "$AUTHELIA_DIR/configuration.yml")" = "600" ]
    [ -n "$(ls "$ZTVPN_BACKUP_DIR/policy")" ]

    run --separate-stderr "$POLICY" list-rules
    [ "$status" -eq 0 ]
    [[ "${lines[2]}" == 1*app.example.com*one_factor* ]]

    run "$POLICY" remove-rule --domain app.example.com
    [ "$status" -eq 0 ]
    [ "$(yq '.access_control.rules | length' "$AUTHELIA_DIR/configuration.yml")" -eq 2 ]
    run "$POLICY" remove-rule --domain app.example.com
    [ "$status" -ne 0 ]
    run "$POLICY" remove-rule --index 0
    [ "$status" -eq 0 ]
    [ "$(yq '.access_control.rules[0].domain' "$AUTHELIA_DIR/configuration.yml")" = '*.example.com' ]
    run "$POLICY" remove-rule --index 5
    [ "$status" -ne 0 ]
}

@test "policy: remove-rule matches templated domains of the shipped config" {
    mkdir -p "$AUTHELIA_DIR"
    cp "$REPO_ROOT/config-examples/authelia/configuration.yml" "$AUTHELIA_DIR/configuration.yml"
    export AUTHELIA_VALIDATE=yq DOMAIN=corp.example
    n="$(yq '.access_control.rules | length' "$AUTHELIA_DIR/configuration.yml")"
    tmpl="$(yq '[.access_control.rules[].domain | select(tag == "!!str")][0]' "$AUTHELIA_DIR/configuration.yml")"
    [[ "$tmpl" == *'{{ env "DOMAIN" }}'* ]] || skip "shipped config has no templated domains"
    real="${tmpl//'{{ env "DOMAIN" }}'/corp.example}"
    run "$POLICY" remove-rule --domain "$real"
    [ "$status" -eq 0 ]
    [ "$(yq '.access_control.rules | length' "$AUTHELIA_DIR/configuration.yml")" -eq $((n - 1)) ]
    run "$POLICY" validate
    [ "$status" -eq 0 ]
}

@test "policy: add-rule is injection-safe and validates its inputs" {
    minimal_authelia_config
    export AUTHELIA_VALIDATE=yq
    evil='x" | .access_control.default_policy = "bypass" | "'
    run "$POLICY" add-rule --domain app.example.com --policy deny --resource "$evil"
    [ "$status" -eq 0 ]
    [ "$(yq '.access_control.default_policy' "$AUTHELIA_DIR/configuration.yml")" = "deny" ]
    [ "$(yq '.access_control.rules[-1].resources[0]' "$AUTHELIA_DIR/configuration.yml")" = "$evil" ]

    cfg="$(sha256sum <"$AUTHELIA_DIR/configuration.yml")"
    for args in \
        '--domain a.example.com" --policy deny' \
        '--domain app.example.com --policy bypass' \
        '--domain app.example.com --policy deny --subject group:administrators' \
        '--domain app.example.com --policy deny --subject group:admins"]' \
        '--domain app.example.com --policy deny --network dmz' \
        '--domain app.example.com --policy deny --resource (' \
        '--domain app.example.com --policy deny --position 99'; do
        # shellcheck disable=SC2086
        run "$POLICY" add-rule $args
        [ "$status" -ne 0 ]
    done
    [ "$(sha256sum <"$AUTHELIA_DIR/configuration.yml")" = "$cfg" ]
}

@test "policy: failed validation rolls the change back" {
    minimal_authelia_config
    # docker stub: validate-config fails once the config mentions bad.example.com
    stub docker "if [[ \$1 == run ]] && grep -q bad.example.com '$AUTHELIA_DIR/configuration.yml'; then exit 1; fi; exit 0"
    export AUTHELIA_VALIDATE=docker
    cfg="$(sha256sum <"$AUTHELIA_DIR/configuration.yml")"
    run "$POLICY" add-rule --domain bad.example.com --policy deny
    [ "$status" -ne 0 ]
    [[ "$output" == *"restored"* ]]
    [ "$(sha256sum <"$AUTHELIA_DIR/configuration.yml")" = "$cfg" ]
    grep -q '^docker run --rm --network none -v .*authelia validate-config' "$CALLS"

    run "$POLICY" add-rule --domain good.example.com --policy deny --restart
    [ "$status" -eq 0 ]
    grep -qx 'docker restart authelia' "$CALLS"
}

@test "policy: real Authelia rejects an RE2-incompatible regex and the change is rolled back" {
    command -v docker >/dev/null && docker info >/dev/null 2>&1 || skip "docker not available"
    docker image inspect authelia/authelia:4.39 >/dev/null 2>&1 || skip "authelia image not pulled"
    rm -f "$STUBS/docker"
    minimal_authelia_config
    printf 'users: {}\n' >"$AUTHELIA_USERS_DB"
    export AUTHELIA_VALIDATE=docker
    run "$POLICY" validate
    [ "$status" -eq 0 ]
    cfg="$(sha256sum <"$AUTHELIA_DIR/configuration.yml")"
    run "$POLICY" add-rule --domain app.example.com --policy deny --resource '^/(?=admin)'
    [ "$status" -ne 0 ]
    [ "$(sha256sum <"$AUTHELIA_DIR/configuration.yml")" = "$cfg" ]
    run "$POLICY" add-rule --domain app.example.com --policy deny --resource '^/admin'
    [ "$status" -eq 0 ]
}

@test "policy: set-groups validates groups and keeps base groups unless --exact" {
    "$ADD" alice alice@example.com --no-vpn >/dev/null 2>&1
    export AUTHELIA_VALIDATE=yq
    minimal_authelia_config
    db="$(sha256sum <"$AUTHELIA_USERS_DB")"
    for g in wheel admin standard 'admins,guest' 'Admins'; do
        run "$POLICY" set-groups alice "$g"
        [ "$status" -ne 0 ]
    done
    run "$POLICY" add-group alice limited
    [ "$status" -ne 0 ]
    [ "$(sha256sum <"$AUTHELIA_USERS_DB")" = "$db" ]

    run --separate-stderr "$POLICY" set-groups alice employees,monitoring
    [ "$status" -eq 0 ]
    [ "$output" = "employees,monitoring,users,vpn-users" ]
    run --separate-stderr "$POLICY" set-groups alice contractors --exact
    [ "$status" -eq 0 ]
    [ "$output" = "contractors" ]
    run --separate-stderr "$POLICY" add-group alice vpn-users
    [ "$status" -eq 0 ]
    [ "$output" = "contractors,vpn-users" ]
    run --separate-stderr "$POLICY" remove-group alice contractors
    [ "$status" -eq 0 ]
    [ "$output" = "vpn-users" ]
    run "$POLICY" set-groups ghost users
    [ "$status" -ne 0 ]
}

@test "policy: backup and restore" {
    minimal_authelia_config
    export AUTHELIA_VALIDATE=yq
    run --separate-stderr "$POLICY" backup
    [ "$status" -eq 0 ]
    bdir="$output"
    [ -f "$bdir/configuration.yml" ]
    [ "$(stat -c %a "$bdir")" = "700" ]
    cfg="$(sha256sum <"$AUTHELIA_DIR/configuration.yml")"
    "$POLICY" add-rule --domain new.example.com --policy deny 2>/dev/null
    [ "$(sha256sum <"$AUTHELIA_DIR/configuration.yml")" != "$cfg" ]
    run "$POLICY" restore "$(basename "$bdir")"
    [ "$status" -eq 0 ]
    [ "$(sha256sum <"$AUTHELIA_DIR/configuration.yml")" = "$cfg" ]
    run "$POLICY" restore /etc
    [ "$status" -ne 0 ]
}
