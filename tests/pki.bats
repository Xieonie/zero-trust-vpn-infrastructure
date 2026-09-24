#!/usr/bin/env bats

load test_helper

setup() {
    ztvpn_sandbox
    load_lib
}

@test "CA is created with encrypted key and refuses re-init" {
    pki_init_ca
    [ -f "$PKI_CA_CERT" ]
    grep -q 'ENCRYPTED PRIVATE KEY' "$PKI_CA_KEY"
    [ "$(stat -c %a "$PKI_CA_KEY")" = "400" ]
    [ "$(stat -c %a "$PKI_CA_PASSFILE")" = "600" ]
    [ -f "$PKI_CRL" ]
    openssl x509 -in "$PKI_CA_CERT" -noout -text | grep -q 'CA:TRUE, pathlen:0'
    before="$(sha256sum "$PKI_CA_CERT")"
    run pki_init_ca
    [ "$status" -ne 0 ]
    [ "$(sha256sum "$PKI_CA_CERT")" = "$before" ]
}

@test "server cert has SAN, serverAuth and verifies" {
    pki_init_ca
    crt="$(pki_issue server vpn.example.com 90 auth.example.com 10.8.0.1)"
    text="$(openssl x509 -in "$crt" -noout -text)"
    [[ "$text" == *"DNS:vpn.example.com, DNS:auth.example.com, IP Address:10.8.0.1"* ]]
    [[ "$text" == *"TLS Web Server Authentication"* ]]
    [[ "$text" == *"Digital Signature"* ]]
    [[ "$text" == *"CA:FALSE"* ]]
    pki_verify "$crt"
    [ "$(stat -c %a "$PKI_SERVER_DIR/vpn.example.com.key")" = "600" ]
}

@test "client cert has clientAuth only" {
    pki_init_ca
    crt="$(pki_issue client alice)"
    text="$(openssl x509 -in "$crt" -noout -text)"
    [[ "$text" == *"TLS Web Client Authentication"* ]]
    [[ "$text" != *"Server Authentication"* ]]
    pki_verify "$crt"
}

@test "renewal with same CN works and revocation is exact" {
    pki_init_ca
    pki_issue client bob >/dev/null
    cp "$PKI_CLIENTS_DIR/bob.crt" "$BATS_TEST_TMPDIR/bob-old.crt"
    pki_issue client bob >/dev/null
    pki_issue client bobby >/dev/null
    [ "$(pki_valid_serials bob | wc -l)" -eq 2 ]
    pki_revoke bob
    [ "$(pki_valid_serials bob | wc -l)" -eq 0 ]
    [ "$(pki_valid_serials bobby | wc -l)" -eq 1 ]
    ! pki_verify "$PKI_CLIENTS_DIR/bob.crt"
    ! pki_verify "$BATS_TEST_TMPDIR/bob-old.crt"
    pki_verify "$PKI_CLIENTS_DIR/bobby.crt"
}

@test "revoking unknown name returns 2" {
    pki_init_ca
    run pki_revoke nobody
    [ "$status" -eq 2 ]
}

@test "invalid names and SANs are rejected" {
    pki_init_ca
    run pki_issue client '../../etc/x'
    [ "$status" -ne 0 ]
    run pki_issue client 'a/CN=evil'
    [ "$status" -ne 0 ]
    run pki_issue server vpn.example.com 30 'bad san,DNS:evil'
    [ "$status" -ne 0 ]
}

@test "days left is computed" {
    pki_init_ca
    crt="$(pki_issue client carol 10)"
    d="$(pki_days_left "$crt")"
    [ "$d" -ge 9 ] && [ "$d" -le 10 ]
}
