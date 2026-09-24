#!/usr/bin/env bats

load test_helper

setup() {
    ztvpn_sandbox
}

@test "config loader assigns values without executing them" {
    cat >"$ZTVPN_CONFIG" <<'CONF'
# comment
VPN_SUBNET=10.20.0.0/24
DOMAIN="corp.example"
EVIL=$(touch /tmp/ztvpn-pwned)
TRAILING=value # comment
CONF
    chmod 600 "$ZTVPN_CONFIG"
    rm -f /tmp/ztvpn-pwned
    load_lib
    [ "$VPN_SUBNET" = "10.20.0.0/24" ]
    [ "$DOMAIN" = "corp.example" ]
    [ "$EVIL" = '$(touch /tmp/ztvpn-pwned)' ]
    [ "$TRAILING" = "value" ]
    [ ! -e /tmp/ztvpn-pwned ]
}

@test "environment overrides config file" {
    printf 'VPN_SUBNET=10.20.0.0/24\n' >"$ZTVPN_CONFIG"
    chmod 600 "$ZTVPN_CONFIG"
    export VPN_SUBNET=10.30.0.0/24
    load_lib
    [ "$VPN_SUBNET" = "10.30.0.0/24" ]
}

@test "config loader refuses world-writable file" {
    printf 'A=1\n' >"$ZTVPN_CONFIG"
    chmod 666 "$ZTVPN_CONFIG"
    run bash -c "source '$REPO_ROOT/scripts/lib/common.sh'"
    [ "$status" -ne 0 ]
    [[ "$output" == *"world writable"* ]]
}

@test "defaults are the canonical layout" {
    load_lib
    [ "$VPN_SUBNET" = "10.8.0.0/24" ]
    [ "$VPN_SERVER_IP" = "10.8.0.1" ]
    [ "$PKI_CA_KEY" = "$ZTVPN_HOME/certificates/ca/private/ca.key" ]
    [ "$AUTHELIA_USERS_DB" = "$ZTVPN_HOME/authelia/users_database.yml" ]
}

@test "log output goes to stderr only" {
    load_lib
    out="$(log hello; info a; warn b; success c)"
    [ -z "$out" ]
}

@test "username validation rejects injection and prefix tricks" {
    load_lib
    validate_username alice
    validate_username bob-smith
    ! validate_username 'Bob'
    ! validate_username 'a'
    ! validate_username 'bob.smith'
    ! validate_username 'bob/../x'
    ! validate_username 'bob"x'
    ! validate_username "$(printf 'bob\nx')"
    ! validate_username '-rf'
    ! validate_username 'bob--x'
    ! validate_username 'bob-'
}

@test "add then remove restores wg0.conf byte for byte" {
    load_lib
    ztvpn_fake_wg_server
    wg_add_peer alice "$(wg genkey | wg pubkey)" 10.8.0.2
    cp "$WG_CONF" "$BATS_TEST_TMPDIR/before"
    wg_add_peer bob "$(wg genkey | wg pubkey)" 10.8.0.3
    wg_remove_peer bob
    cmp "$WG_CONF" "$BATS_TEST_TMPDIR/before"
    wg_remove_peer alice
    wg_add_peer carol "$(wg genkey | wg pubkey)" 10.8.0.4
    wg_remove_peer carol
    run wg-quick strip "$WG_CONF"
    [ "$status" -eq 0 ]
}

@test "email and IP validation" {
    load_lib
    validate_email alice@example.com
    ! validate_email 'a@b'
    ! validate_email 'a" b@example.com'
    validate_ipv4 10.8.0.1
    ! validate_ipv4 10.8.0.256
    ! validate_ipv4 010.8.0.1
    validate_cidr 10.8.0.0/24
    ! validate_cidr 10.8.0.0/33
    ip_in_cidr 10.8.0.77 10.8.0.0/24
    ! ip_in_cidr 10.9.0.1 10.8.0.0/24
    ip_in_list 192.0.2.5 "198.51.100.1, 192.0.2.0/28"
    ! ip_in_list 192.0.2.50 "198.51.100.1, 192.0.2.0/28"
}

@test "wg_next_free_ip skips server and assigned addresses" {
    load_lib
    ztvpn_fake_wg_server
    [ "$(wg_next_free_ip)" = "10.8.0.2" ]
    wg_add_peer alice "$(wg genkey | wg pubkey)" 10.8.0.2
    wg_add_peer bob "$(wg genkey | wg pubkey)" 10.8.0.3
    [ "$(wg_next_free_ip)" = "10.8.0.4" ]
    wg_remove_peer alice
    [ "$(wg_next_free_ip)" = "10.8.0.2" ]
}

@test "wg_next_free_ip returns a single clean line" {
    load_lib
    ztvpn_fake_wg_server
    wg_add_peer alice "$(wg genkey | wg pubkey)" 10.8.0.2
    ip="$(wg_next_free_ip)"
    [ "$(printf '%s' "$ip" | wc -l)" -eq 0 ]
    validate_ipv4 "$ip"
}

@test "wg_add_peer rejects duplicates, bad keys, foreign subnets" {
    load_lib
    ztvpn_fake_wg_server
    key="$(wg genkey | wg pubkey)"
    wg_add_peer alice "$key" 10.8.0.2
    run wg_add_peer alice "$(wg genkey | wg pubkey)" 10.8.0.3
    [ "$status" -ne 0 ]
    run wg_add_peer carol "$(wg genkey | wg pubkey)" 10.8.0.2
    [ "$status" -ne 0 ]
    run wg_add_peer dave 'not-a-key' 10.8.0.4
    [ "$status" -ne 0 ]
    run wg_add_peer erin "$(wg genkey | wg pubkey)" 10.9.0.4
    [ "$status" -ne 0 ]
}

@test "removing bob leaves bobby and bob--laptop untouched" {
    load_lib
    ztvpn_fake_wg_server
    wg_add_peer bob "$(wg genkey | wg pubkey)" 10.8.0.2
    wg_add_peer bobby "$(wg genkey | wg pubkey)" 10.8.0.3
    wg_add_peer bob--laptop "$(wg genkey | wg pubkey)" 10.8.0.4
    wg_remove_peer bob
    ! wg_peer_exists bob
    wg_peer_exists bobby
    wg_peer_exists bob--laptop
    [ "$(wg_peer_ip bobby)" = "10.8.0.3" ]
    run wg-quick strip "$WG_CONF"
    [ "$status" -eq 0 ]
}

@test "wg_user_peers matches the user and their devices only" {
    load_lib
    ztvpn_fake_wg_server
    wg_add_peer bob "$(wg genkey | wg pubkey)" 10.8.0.2
    wg_add_peer bobby "$(wg genkey | wg pubkey)" 10.8.0.3
    wg_add_peer bob--phone "$(wg genkey | wg pubkey)" 10.8.0.4
    run wg_user_peers bob
    [ "$output" = "$(printf 'bob\nbob--phone')" ]
}

@test "wg_provision_peer writes a valid client config with private files" {
    load_lib
    ztvpn_fake_wg_server
    ip="$(wg_provision_peer alice--laptop)"
    [ "$ip" = "10.8.0.2" ]
    conf="$WG_CLIENTS_DIR/alice--laptop/alice--laptop.conf"
    [ "$(stat -c %a "$conf")" = "600" ]
    [ "$(stat -c %a "$WG_CLIENTS_DIR/alice--laptop/private.key")" = "600" ]
    grep -q "^Address = 10.8.0.2/32$" "$conf"
    grep -q "^PublicKey = $(<"$WG_DIR/server_public.key")$" "$conf"
    grep -q "^PresharedKey = " "$conf"
    ! grep -q '^DNS' "$conf"
    run wg-quick strip "$conf"
    [ "$status" -eq 0 ]
    run wg-quick strip "$WG_CONF"
    [ "$status" -eq 0 ]
    [ "$(stat -c %a "$WG_CONF")" = "600" ]
}

@test "wg_deprovision_peer removes server entry and key material" {
    load_lib
    ztvpn_fake_wg_server
    wg_provision_peer alice >/dev/null
    wg_deprovision_peer alice "$BATS_TEST_TMPDIR/archive"
    ! wg_peer_exists alice
    [ ! -e "$WG_CLIENTS_DIR/alice" ]
    [ -f "$BATS_TEST_TMPDIR/archive/alice/public.key" ]
}

@test "authelia user db: add, disable, groups, injection-safe" {
    load_lib
    hash="$(printf 'S3cret-pass\n' | authelia_hash_password)"
    [[ "$hash" == '$argon2id$v=19$m=65536,t=3,p=4$'* ]]
    authelia_add_user alice 'Alice "A" Smith' alice@example.com "$hash" users,vpn-users
    authelia_user_exists alice
    [ "$(authelia_user_field alice displayname)" = 'Alice "A" Smith' ]
    [ "$(authelia_user_field alice disabled)" = "false" ]
    run authelia_user_groups alice
    [ "$output" = "$(printf 'users\nvpn-users')" ]

    authelia_set_disabled alice true
    [ "$(authelia_user_field alice disabled)" = "true" ]

    authelia_add_group alice admins
    authelia_remove_group alice users
    run authelia_user_groups alice
    [ "$output" = "$(printf 'vpn-users\nadmins')" ]

    run authelia_add_user bob 'x" | .users.alice.groups=["admins"] | .y="' bob@example.com "$hash" users
    [ "$status" -eq 0 ]
    [ "$(authelia_user_field bob displayname)" = 'x" | .users.alice.groups=["admins"] | .y="' ]

    run authelia_add_user alice Alice alice@example.com "$hash" users
    [ "$status" -ne 0 ]
    run authelia_add_user 'evil"' Evil evil@example.com "$hash" users
    [ "$status" -ne 0 ]
    [ "$(stat -c %a "$AUTHELIA_USERS_DB")" = "600" ]
}

@test "argon2 hash verifies against the exact password without newline" {
    load_lib
    hash="$(printf 'pw123456\n' | authelia_hash_password)"
    salt_b64="$(cut -d'$' -f5 <<<"$hash")"
    # Recompute with the same salt and compare.
    salt="$(python3 -c 'import base64,sys; s=sys.argv[1]; print(base64.b64decode(s + "=" * (-len(s) % 4)).decode())' "$salt_b64")"
    again="$(printf '%s' pw123456 | argon2 "$salt" -id -t 3 -k 65536 -p 4 -l 32 -e)"
    [ "$again" = "$hash" ]
}

@test "Authelia itself accepts the generated hash" {
    command -v docker >/dev/null && docker info >/dev/null 2>&1 || skip "docker not available"
    load_lib
    hash="$(printf 'Corr3ct-Horse\n' | authelia_hash_password)"
    run docker run --rm "$AUTHELIA_IMAGE" authelia crypto hash validate --password 'Corr3ct-Horse' -- "$hash"
    [ "$status" -eq 0 ]
    [[ "$output" == *"password matches"* ]]
    run docker run --rm "$AUTHELIA_IMAGE" authelia crypto hash validate --password $'Corr3ct-Horse\n' -- "$hash"
    [[ "$output" != *"password matches"* ]]
}

@test "IPs of quarantined peers are not handed out again" {
    load_lib
    ztvpn_fake_wg_server
    mkdir -p "$QUARANTINE_DIR/mallory"
    printf '{"ip":"10.8.0.2","public_key":"x"}\n' >"$QUARANTINE_DIR/mallory/meta.json"
    [ "$(wg_next_free_ip)" = "10.8.0.3" ]
    wg_ip_in_use 10.8.0.2
    mv "$QUARANTINE_DIR/mallory" "$QUARANTINE_DIR/mallory.released-20260101T000000Z"
    [ "$(wg_next_free_ip)" = "10.8.0.2" ]
}
