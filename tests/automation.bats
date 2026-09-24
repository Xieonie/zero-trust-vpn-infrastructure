#!/usr/bin/env bats
# Tests for scripts/automation: cert-renewal.sh, threat-response.sh, user-sync.sh

bats_require_minimum_version 1.5.0
load test_helper

CERT="$REPO_ROOT/scripts/automation/cert-renewal.sh"
THREAT="$REPO_ROOT/scripts/automation/threat-response.sh"
SYNC="$REPO_ROOT/scripts/automation/user-sync.sh"

setup() {
    ztvpn_sandbox
    export STUB_LOG="$BATS_TEST_TMPDIR/calls"
    mkdir -p "$BATS_TEST_TMPDIR/bin" "$STUB_LOG"
    export PATH="$BATS_TEST_TMPDIR/bin:$PATH"
    unset SSH_CONNECTION SSH_CLIENT ADMIN_ALLOWLIST SLACK_WEBHOOK NOTIFICATION_EMAIL
    # Generic recording stubs; behaviour tweaked through env vars.
    stub nft 'if [[ -n "${NFT_FAIL:-}" && "$*" == *"$NFT_FAIL"* ]]; then echo "nft: failed" >&2; exit 1; fi'
    stub docker 'case "$*" in
  inspect*) echo "${DOCKER_RUNNING:-false}" ;;
  compose*" ps -q --status running "*) [[ "${DOCKER_RUNNING:-}" == true ]] && echo 0123456789ab ;;
esac
exit 0'
    stub curl 'for a in "$@"; do [[ "$a" == /dev/fd/* ]] && cat "$a" >>"$STUB_LOG/curl.cfg"; done
cat >>"$STUB_LOG/curl.data"
exit "${CURL_EXIT:-0}"'
    stub sendmail 'cat >>"$STUB_LOG/sendmail.data"; exit "${SENDMAIL_EXIT:-0}"'
}

# stub <name> <body>: records "$*" to $STUB_LOG/<name>, then runs body.
stub() {
    cat >"$BATS_TEST_TMPDIR/bin/$1" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >>"\$STUB_LOG/$1"
$2
EOF
    chmod +x "$BATS_TEST_TMPDIR/bin/$1"
}

calls() { cat "$STUB_LOG/$1" 2>/dev/null || true; }

# ==========================================================================
# cert-renewal.sh
# ==========================================================================

@test "cert check: cert expiring in 5 days is critical, exit 2, never 'valid'" {
    load_lib
    pki_init_ca 2>/dev/null
    pki_issue server vpn.example.com 5 >/dev/null 2>&1
    run "$CERT" check
    [ "$status" -eq 2 ]
    [[ "$output" == *"vpn.example.com"*"critical"* ]]
    [[ "$output" != *"valid"* ]]
}

@test "cert check: warning window exits 1, healthy exits 0" {
    load_lib
    pki_init_ca 2>/dev/null
    pki_issue server ok.example.com 300 >/dev/null 2>&1
    run "$CERT" check
    [ "$status" -eq 0 ]
    pki_issue client alice 20 >/dev/null 2>&1
    run "$CERT" check
    [ "$status" -eq 1 ]
    [[ "$output" == *"alice"*"warning"* ]]
    run "$CERT" check --days 10
    [ "$status" -eq 0 ]
}

@test "cert renew: same SANs, old serial revoked as superseded, proxy reloaded via HUP, no wg" {
    load_lib
    pki_init_ca 2>/dev/null
    pki_issue server vpn.example.com 5 auth.example.com 10.8.0.1 >/dev/null 2>&1
    old_serial="$(openssl x509 -in "$PKI_SERVER_DIR/vpn.example.com.crt" -noout -serial | cut -d= -f2)"
    old_key="$(sha256sum <"$PKI_SERVER_DIR/vpn.example.com.key")"
    stub wg 'exit 1'
    stub systemctl 'exit 1'
    touch "$ZTVPN_HOME/docker-compose.yml"
    DOCKER_RUNNING=true run "$CERT" renew
    [ "$status" -eq 0 ]
    crt="$PKI_SERVER_DIR/vpn.example.com.crt"
    [ "$(pki_days_left "$crt")" -gt 300 ]
    openssl x509 -in "$crt" -noout -ext subjectAltName | grep -q 'DNS:vpn.example.com, DNS:auth.example.com, IP Address:10.8.0.1'
    [ "$(sha256sum <"$PKI_SERVER_DIR/vpn.example.com.key")" != "$old_key" ]
    pki_verify "$crt"
    grep -P "^R\t[^\t]*\t[^\t]*,superseded\t$old_serial\t" "$PKI_CA_DIR/index.txt"
    calls docker | grep -qx "compose -f $ZTVPN_HOME/docker-compose.yml --project-directory $ZTVPN_HOME kill -s SIGHUP nginx"
    [ -z "$(calls wg)" ]
    [ -z "$(calls systemctl)" ]
    backup="$(find "$ZTVPN_BACKUP_DIR/certificates" -name vpn.example.com.key)"
    [ "$(stat -c %a "$backup")" = "600" ]
    [ "$(sha256sum <"$backup")" = "$old_key" ]
}

@test "cert renew: explicit TLS_PROXY_CONTAINER is signalled, stopped proxy is left alone" {
    load_lib
    pki_init_ca 2>/dev/null
    pki_issue server vpn.example.com 5 >/dev/null 2>&1
    DOCKER_RUNNING=true TLS_PROXY_CONTAINER=edge-proxy run "$CERT" renew
    [ "$status" -eq 0 ]
    calls docker | grep -qx 'kill -s SIGHUP edge-proxy'
    pki_issue server vpn.example.com 5 >/dev/null 2>&1
    : >"$STUB_LOG/docker"
    DOCKER_RUNNING=false TLS_PROXY_CONTAINER=edge-proxy run "$CERT" renew
    [ "$status" -eq 0 ]
    ! calls docker | grep -q kill || false
    [[ "$output" == *"not running"* ]]
}

@test "cert renew: signing failure keeps the old key and certificate" {
    load_lib
    pki_init_ca 2>/dev/null
    pki_issue server vpn.example.com 5 >/dev/null 2>&1
    before="$(cat "$PKI_SERVER_DIR/vpn.example.com.key" "$PKI_SERVER_DIR/vpn.example.com.crt" | sha256sum)"
    chmod 600 "$PKI_CA_PASSFILE"
    echo wrong-passphrase >"$PKI_CA_PASSFILE"
    DOCKER_RUNNING=true TLS_PROXY_CONTAINER=proxy run "$CERT" renew
    [ "$status" -ne 0 ]
    [ "$(cat "$PKI_SERVER_DIR/vpn.example.com.key" "$PKI_SERVER_DIR/vpn.example.com.crt" | sha256sum)" = "$before" ]
    ! calls docker | grep -q kill || false
    [[ "$output" != *"Renewed"* ]]
}

@test "cert renew: client keys are not regenerated without --reissue-clients" {
    load_lib
    pki_init_ca 2>/dev/null
    pki_issue client alice 5 >/dev/null 2>&1
    before="$(sha256sum <"$PKI_CLIENTS_DIR/alice.key")"
    run "$CERT" renew
    [ "$status" -eq 0 ]
    [ "$(sha256sum <"$PKI_CLIENTS_DIR/alice.key")" = "$before" ]
    [[ "$output" == *"alice"*"--reissue-clients"* ]]

    run "$CERT" renew --reissue-clients
    [ "$status" -eq 0 ]
    [ "$(sha256sum <"$PKI_CLIENTS_DIR/alice.key")" != "$before" ]
    [[ "$output" == *"deliver it securely"* ]]
    [ "$(pki_valid_serials alice | wc -l)" -eq 1 ]
}

@test "cert renew: CA near expiry only warns, dry-run changes nothing" {
    export PKI_CA_DAYS=100
    load_lib
    pki_init_ca 2>/dev/null
    pki_issue server vpn.example.com 5 >/dev/null 2>&1
    ca_before="$(sha256sum <"$PKI_CA_CERT")"
    idx_before="$(sha256sum <"$PKI_CA_DIR/index.txt")"
    run "$CERT" renew --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"never regenerated automatically"* ]]
    [[ "$output" == *"would reissue server certificate vpn.example.com"* ]]
    [ "$(sha256sum <"$PKI_CA_CERT")" = "$ca_before" ]
    [ "$(sha256sum <"$PKI_CA_DIR/index.txt")" = "$idx_before" ]
    [ ! -d "$ZTVPN_BACKUP_DIR/certificates" ]
}

@test "cert renewal rejects bad arguments" {
    run "$CERT" check --days abc
    [ "$status" -ne 0 ]
    run "$CERT" frobnicate
    [ "$status" -ne 0 ]
}

# ==========================================================================
# threat-response.sh
# ==========================================================================

@test "threat: refuses to block allowlisted, SSH caller, loopback and server IPs" {
    ADMIN_ALLOWLIST=198.51.100.0/24 run "$THREAT" --type brute-force --ip 198.51.100.7
    [ "$status" -ne 0 ]
    [[ "$output" == *"ADMIN_ALLOWLIST"* ]]
    SSH_CONNECTION="203.0.113.50 51515 192.0.2.1 22" run "$THREAT" --type brute-force --ip 203.0.113.50
    [ "$status" -ne 0 ]
    [[ "$output" == *"SSH session"* ]]
    run "$THREAT" --type brute-force --ip 127.0.0.1
    [ "$status" -ne 0 ]
    run "$THREAT" --type brute-force --ip 10.8.0.1
    [ "$status" -ne 0 ]
    ADMIN_ALLOWLIST=2001:db8::1 run "$THREAT" --type brute-force --ip 2001:db8::1
    [ "$status" -ne 0 ]
    THREAT_PROTECT_PRIVATE=yes run "$THREAT" --type brute-force --ip 192.168.1.5
    [ "$status" -ne 0 ]
    [ -z "$(calls nft)" ]
    [ ! -d "$ZTVPN_STATE_DIR/incidents" ] || [ -z "$(ls -A "$ZTVPN_STATE_DIR/incidents")" ]
}

@test "threat: invalid input is rejected before anything runs" {
    for args in "--type brute-force --ip 1.2.3.4;id" "--type brute-force --ip 256.1.1.1" \
        "--type brute-force --ip 1.2.3.4 --duration 0h" "--type brute-force --ip 1.2.3.4 --duration forever" \
        "--type brute-force --ip 1.2.3.4 --duration 400d" "--type bogus --ip 1.2.3.4" \
        "--type compromised-user --user Bob;x" "--type brute-force" "--type compromised-user" \
        "--type brute-force --ip 1:2:3:4:5:6:7:8:9"; do
        # shellcheck disable=SC2086
        run "$THREAT" $args
        [ "$status" -ne 0 ]
    done
    [ -z "$(calls nft)" ]
}

@test "threat: brute-force adds nft set element with timeout, clean incident id and record" {
    run --separate-stderr "$THREAT" --type brute-force --ip 203.0.113.9 --duration 2h --reason "ssh scan"
    [ "$status" -eq 0 ]
    [[ "$output" =~ ^INC-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{6}$ ]]
    [ "$(calls nft)" = "add element inet ztvpn blocklist4 { 203.0.113.9 timeout 2h }" ]
    rec="$ZTVPN_STATE_DIR/incidents/$output.json"
    [ "$(stat -c %a "$rec")" = "600" ]
    [ "$(jq -r .id "$rec")" = "$output" ]
    [ "$(jq -r .status "$rec")" = "contained" ]
    [ "$(jq -r '.actions[0].status' "$rec")" = "ok" ]
    [ "$(jq -r .reason "$rec")" = "ssh scan" ]
    ! grep -rq iptables "$THREAT" || false
}

@test "threat: IPv6 goes to blocklist6, unblock deletes the element" {
    run "$THREAT" --type brute-force --ip 2001:db8::bad
    [ "$status" -eq 0 ]
    calls nft | grep -qx 'add element inet ztvpn blocklist6 { 2001:db8::bad timeout 1h }'
    run "$THREAT" unblock --ip 203.0.113.9
    [ "$status" -eq 0 ]
    calls nft | grep -qx 'delete element inet ztvpn blocklist4 { 203.0.113.9 }'
}

@test "threat: dry-run touches nothing" {
    run "$THREAT" --type brute-force --ip 203.0.113.9 --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"dry-run"* ]]
    [ -z "$(calls nft)" ]
    [ ! -d "$ZTVPN_STATE_DIR/incidents" ]
}

@test "threat: compromised-user runs every action even if one fails" {
    ztvpn_fake_wg_server
    load_lib
    authelia_add_user alice "Alice" alice@example.com '$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA' users,vpn-users
    wg_provision_peer alice--laptop >/dev/null
    wg_provision_peer alice--phone >/dev/null
    wg_provision_peer bob >/dev/null
    # Quarantine (nft) fails; disabling, peer removal and cert revocation must still happen.
    NFT_FAIL=quarantine4 run --separate-stderr "$THREAT" --type compromised-user --user alice
    [ "$status" -eq 1 ]
    id="$output"
    [[ "$id" =~ ^INC-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{6}$ ]]
    [ "$(yq '.users.alice.disabled' "$AUTHELIA_USERS_DB")" = "true" ]
    ! wg_peer_exists alice--laptop || false
    ! wg_peer_exists alice--phone || false
    wg_peer_exists bob
    [ -f "$ZTVPN_STATE_DIR/quarantine/alice--laptop/peer.conf" ]
    rec="$ZTVPN_STATE_DIR/incidents/$id.json"
    [ "$(jq -r .status "$rec")" = "partial" ]
    [ "$(jq '[.actions[] | select(.action == "quarantine-ip" and .status == "failed")] | length' "$rec")" -eq 2 ]
    [ "$(jq '[.actions[] | select(.action == "remove-peer" and .status == "ok")] | length' "$rec")" -eq 2 ]
    [ "$(jq -r '.actions[] | select(.action == "disable-user") | .status' "$rec")" = "ok" ]
}

@test "threat: compromised-device quarantines and removes peer; release restores it" {
    ztvpn_fake_wg_server
    load_lib
    ip="$(wg_provision_peer carol--laptop)"
    pub="$(<"$WG_CLIENTS_DIR/carol--laptop/public.key")"
    run --separate-stderr "$THREAT" --type compromised-device --user carol --device laptop
    [ "$status" -eq 0 ]
    calls nft | grep -qx "add element inet ztvpn quarantine4 { $ip }"
    ! wg_peer_exists carol--laptop || false
    [ ! -e "$WG_CLIENTS_DIR/carol--laptop" ]
    [ "$(jq -r .public_key "$ZTVPN_STATE_DIR/quarantine/carol--laptop/meta.json")" = "$pub" ]

    run "$THREAT" release --device carol--laptop
    [ "$status" -eq 0 ]
    wg_peer_exists carol--laptop
    [ "$(wg_peer_ip carol--laptop)" = "$ip" ]
    grep -q "PresharedKey" "$WG_CONF"
    [ -f "$WG_CLIENTS_DIR/carol--laptop/private.key" ]
    calls nft | grep -qx "delete element inet ztvpn quarantine4 { $ip }"
}

@test "threat: compromised-device by unknown peer fails cleanly" {
    ztvpn_fake_wg_server
    run "$THREAT" --type compromised-device --device ghost--pc
    [ "$status" -ne 0 ]
    [ -z "$(calls nft)" ]
}

@test "threat: notifications only with --notify; failures are reported" {
    export SLACK_WEBHOOK=https://hooks.example.com/services/T0/B0/xyz
    run --separate-stderr "$THREAT" --type brute-force --ip 203.0.113.10
    [ "$status" -eq 0 ]
    [ -z "$(calls curl)" ]

    run --separate-stderr "$THREAT" --type brute-force --ip 203.0.113.11 --notify
    [ "$status" -eq 0 ]
    id="$output"
    jq -e --arg id "$id" '.text | contains($id)' "$STUB_LOG/curl.data"
    grep -q 'url = "https://hooks.example.com/services/T0/B0/xyz"' "$STUB_LOG/curl.cfg"
    ! calls curl | grep -q hooks.example.com || false
    [ "$(jq -r '.notifications[0].result' "$ZTVPN_STATE_DIR/incidents/$id.json")" = "sent" ]

    CURL_EXIT=22 NOTIFICATION_EMAIL=soc@example.com SENDMAIL_EXIT=1 \
        run --separate-stderr "$THREAT" --type brute-force --ip 203.0.113.12 --notify
    [ "$status" -eq 1 ]
    id="$output"
    [[ "$stderr" == *"Slack notification failed"* ]]
    [[ "$stderr" == *"Email notification failed"* ]]
    [ "$(jq -r '[.notifications[].result] | join(",")' "$ZTVPN_STATE_DIR/incidents/$id.json")" = "failed,failed" ]
    calls sendmail | grep -qx -- '-oi -- soc@example.com'
}

# ==========================================================================
# user-sync.sh
# ==========================================================================

ldap_setup() {
    ztvpn_fake_wg_server
    export AUTHELIA_BACKEND=ldap
    export LDAP_URI=ldaps://ldap.example.com
    export LDAP_BASE_DN="ou=people,dc=example,dc=com"
    export LDAP_BIND_DN="cn=vpn-sync,dc=example,dc=com"
    export LDAP_BIND_PASSWORD_FILE="$BATS_TEST_TMPDIR/bindpw"
    printf 's3cret\n' >"$LDAP_BIND_PASSWORD_FILE"
    chmod 600 "$LDAP_BIND_PASSWORD_FILE"
    export LDIF_DIR="$BATS_TEST_TMPDIR/ldif"
    mkdir -p "$LDIF_DIR"
    # alice: active, attributes base64 encoded and folded
    printf 'dn:: %s\nuid:: %s\ncn: Alice\n\n' "$(printf 'uid=alice,ou=people,dc=example,dc=com' | base64 -w0)" "$(printf alice | base64)" >"$LDIF_DIR/alice"
    # bob: locked via ppolicy, base64 value
    printf 'dn: uid=bob,ou=people,dc=example,dc=com\nuid: bob\npwdAccountLockedTime:: %s\n\n' "$(printf 000001010000Z | base64)" >"$LDIF_DIR/bob"
    # carol: no entry (missing)
    stub ldapsearch 'pw=""; prev=""; for a in "$@"; do [[ "$prev" == -y ]] && pw="$(od -An -c "$a" | tr -s " ")"; prev="$a"; done
printf "%s\n" "$pw" >>"$STUB_LOG/ldap.pw"
[[ -n "${LDAP_EXIT:-}" ]] && { echo "ldap_sasl_bind(SIMPLE): Can'\''t contact LDAP server (-1)" >&2; exit "$LDAP_EXIT"; }
for a in "$@"; do
  if [[ "$a" =~ \((uid|sAMAccountName)=([a-z0-9_-]+)\)\)$ ]]; then
    f="$LDIF_DIR/${BASH_REMATCH[2]}"; [[ -f "$f" ]] && cat "$f"
  fi
done
exit 0'
    load_lib
    wg_provision_peer alice--laptop >/dev/null
    wg_provision_peer bob--phone >/dev/null
    wg_provision_peer carol >/dev/null
}

@test "user-sync: dry run by default, finds missing and locked users" {
    ldap_setup
    run --separate-stderr "$SYNC"
    [ "$status" -eq 0 ]
    [[ "$output" == *"alice"*"active"*"none"* ]]
    [[ "$output" == *"bob"*"disabled"*"would-revoke"* ]]
    [[ "$output" == *"carol"*"missing"*"would-revoke"* ]]
    wg_peer_exists bob--phone
    wg_peer_exists carol
    # bind password passed via -y without the trailing newline, never via -w
    [ "$(head -n1 "$STUB_LOG/ldap.pw")" = " s 3 c r e t" ]
    ! calls ldapsearch | grep -q -- ' -w ' || false
    calls ldapsearch | grep -q -- '-H ldaps://ldap.example.com'
    ! calls ldapsearch | grep -q -- '-ZZ' || false
}

@test "user-sync: --apply revokes only directory-disabled/missing users" {
    ldap_setup
    run --separate-stderr "$SYNC" --apply --json
    [ "$status" -eq 0 ]
    echo "$output" | jq -e '.applied == true'
    echo "$output" | jq -e '.results | map(select(.action == "revoke")) | map(.user) | sort == ["bob","carol"]'
    wg_peer_exists alice--laptop
    ! wg_peer_exists bob--phone || false
    ! wg_peer_exists carol || false
    [ -n "$(find "$ZTVPN_BACKUP_DIR/user-sync" -name private.key -path '*bob--phone*')" ]
}

@test "user-sync: SYNC_IGNORE_USERS are never revoked" {
    ldap_setup
    SYNC_IGNORE_USERS=carol run --separate-stderr "$SYNC" --apply
    [ "$status" -eq 0 ]
    [[ "$output" == *"carol"*"ignored"* ]]
    wg_peer_exists carol
    ! wg_peer_exists bob--phone || false
}

@test "user-sync: refuses to mass-revoke beyond --max-revoke" {
    ldap_setup
    run "$SYNC" --apply --max-revoke 1
    [ "$status" -ne 0 ]
    wg_peer_exists bob--phone
    wg_peer_exists carol
}

@test "user-sync: LDAP errors never count as missing users" {
    ldap_setup
    LDAP_EXIT=255 run --separate-stderr "$SYNC" --apply
    [ "$status" -ne 0 ]
    [[ "$output" == *"ldap-error"* ]]
    wg_peer_exists bob--phone
    wg_peer_exists carol
}

@test "user-sync: TLS enforced, insecure settings refused" {
    ldap_setup
    LDAP_URI=ldap://ldap.example.com run "$SYNC"
    [ "$status" -eq 0 ]
    calls ldapsearch | grep -q -- '-ZZ'
    : >"$STUB_LOG/ldapsearch"
    LDAP_URI=http://ldap.example.com run "$SYNC"
    [ "$status" -ne 0 ]
    LDAP_URI="ldaps://a.example.com ldap://b.example.com" run "$SYNC"
    [ "$status" -ne 0 ]
    LDAPTLS_REQCERT=never run "$SYNC"
    [ "$status" -ne 0 ]
    chmod 644 "$LDAP_BIND_PASSWORD_FILE"
    run "$SYNC"
    [ "$status" -ne 0 ]
    [[ "$output" == *"group/world"* ]]
    [ -z "$(calls ldapsearch)" ]
}

@test "user-sync: hostile names from the users DB never reach the LDAP filter" {
    ldap_setup
    export AUTHELIA_BACKEND=file
    mkdir -p "$AUTHELIA_DIR"
    printf 'users:\n  "x*)(uid=*":\n    disabled: false\n    displayname: evil\n    password: x\n    email: e@example.com\n' >"$AUTHELIA_USERS_DB"
    run --separate-stderr "$SYNC"
    [ "$status" -ne 0 ]
    [[ "$output" == *"invalid-name"* ]]
    ! calls ldapsearch | grep -qF '*)(uid=*' || false
    wg_peer_exists alice--laptop
}

@test "user-sync: Active Directory userAccountControl disabled bit" {
    ldap_setup
    export LDAP_FLAVOR=ad
    printf 'dn: CN=Alice,OU=Users,DC=example,DC=com\nsAMAccountName: Alice\nuserAccountControl: 512\n\n' >"$LDIF_DIR/alice"
    printf 'dn: CN=Bob,OU=Users,DC=example,DC=com\nsAMAccountName: bob\nuserAccountControl: 514\n\n' >"$LDIF_DIR/bob"
    run --separate-stderr "$SYNC" --json
    [ "$status" -eq 0 ]
    echo "$output" | jq -e '.results[] | select(.user == "alice") | .status == "active"'
    echo "$output" | jq -e '.results[] | select(.user == "bob") | .status == "disabled"'
    calls ldapsearch | grep -q '(sAMAccountName=alice)'
}
