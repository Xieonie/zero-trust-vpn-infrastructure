#!/usr/bin/env bats
# Tests for scripts/monitoring: connection-monitor.sh, security-audit.sh, compliance-check.sh

bats_require_minimum_version 1.5.0
load test_helper

MON="$REPO_ROOT/scripts/monitoring/connection-monitor.sh"
AUDIT="$REPO_ROOT/scripts/monitoring/security-audit.sh"
COMP="$REPO_ROOT/scripts/monitoring/compliance-check.sh"

setup() {
    ztvpn_sandbox
    export STUB_LOG="$BATS_TEST_TMPDIR/calls"
    mkdir -p "$BATS_TEST_TMPDIR/bin" "$STUB_LOG"
    export PATH="$BATS_TEST_TMPDIR/bin:$PATH"
    REAL_WG="$(command -v wg)"
    REAL_NFT="$(command -v nft || true)"
    export REAL_WG REAL_NFT
    export WG_DUMP="$BATS_TEST_TMPDIR/wg.dump"
    export DOCKER_LOGS="$BATS_TEST_TMPDIR/docker.logs"
    export DOCKER_PS="$BATS_TEST_TMPDIR/docker.ps"
    export NFT_JSON="$BATS_TEST_TMPDIR/nft.json"
    : >"$DOCKER_LOGS" >"$DOCKER_PS"
    stub wg 'if [[ "$1" == show && "${3:-}" == dump ]]; then cat "$WG_DUMP"; exit; fi; exec "$REAL_WG" "$@"'
    stub docker 'case " $* " in *" logs "*) cat "$DOCKER_LOGS" ;; *" ps "*) cat "$DOCKER_PS" ;; esac'
    stub nft 'if [[ -f "$NFT_JSON" ]]; then cat "$NFT_JSON"; else echo "Error: No such file or directory" >&2; exit 1; fi'
    mkdir -p "$ZTVPN_HOME/proc/sys/net/ipv6/conf/all"
    echo 0 >"$ZTVPN_HOME/proc/sys/net/ipv6/conf/all/forwarding"
    export ZTVPN_PROC_DIR="$ZTVPN_HOME/proc"
    touch "$ZTVPN_HOME/docker-compose.yml"
}

stub() {
    cat >"$BATS_TEST_TMPDIR/bin/$1" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >>"\$STUB_LOG/$1"
$2
EOF
    chmod +x "$BATS_TEST_TMPDIR/bin/$1"
}

calls() { cat "$STUB_LOG/$1" 2>/dev/null || true; }

# Writes a dump: interface line + "pubkey endpoint allowed handshake rx tx" per peer.
write_dump() {
    printf 'SERVERPRIV\tSERVERPUB\t51820\toff\n' >"$WG_DUMP"
    while (($#)); do
        printf '%s\t(none)\t%s\t%s\t%s\t%s\t%s\t25\n' "$1" "$2" "$3" "$4" "$5" "$6" >>"$WG_DUMP"
        shift 6
    done
}

# ==========================================================================
# connection-monitor.sh
# ==========================================================================

@test "monitor: names managed peers, flags unknown peers, large raw counters are fine" {
    ztvpn_fake_wg_server
    load_lib
    wg_provision_peer alice--laptop >/dev/null
    apub="$(<"$WG_CLIENTS_DIR/alice--laptop/public.key")"
    rogue="$(wg genkey | wg pubkey)"
    now="$(date +%s)"
    write_dump "$apub" 198.51.100.4:40000 10.8.0.2/32 "$((now - 30))" 97214464000 95078 \
        "$rogue" 203.0.113.66:5555 10.8.0.99/32 "$((now - 5000))" 1024 2048
    run --separate-stderr "$MON" --once --json
    [ "$status" -eq 1 ]
    echo "$output" | jq -e '.peers[] | select(.name == "alice--laptop") | .status == "active" and .rx_bytes == 97214464000 and .ip == "10.8.0.2"'
    echo "$output" | jq -e '.unknown_peers == 1'
    echo "$output" | jq -e '.peers[] | select(.managed | not) | .status == "stale"'
    echo "$output" | jq -e '[.alerts[] | select(.source == "unknown-peer")] | length == 1'
    grep -q "unknown-peer" "$ZTVPN_LOG_DIR/alerts.log"
}

@test "monitor: malformed human-readable counters are skipped, not a crash" {
    ztvpn_fake_wg_server
    printf 'PRIV\tPUB\t51820\toff\nPEERKEY\t(none)\t1.2.3.4:1\t10.8.0.5/32\t0\t92.84 KiB\t1.5 MiB\t25\n' >"$WG_DUMP"
    run --separate-stderr "$MON" --once --json
    [ "$status" -eq 0 ]
    [[ "$stderr" == *"malformed"* ]]
    echo "$output" | jq -e '.peers == []'
}

@test "monitor: never-connected peer and managed peer missing from interface" {
    ztvpn_fake_wg_server
    load_lib
    wg_provision_peer bob >/dev/null
    wg_provision_peer carol >/dev/null
    write_dump "$(<"$WG_CLIENTS_DIR/bob/public.key")" "(none)" 10.8.0.2/32 0 0 0
    run --separate-stderr "$MON" --json
    [ "$status" -eq 0 ]
    echo "$output" | jq -e '.peers[0].status == "never" and .peers[0].handshake_age == null'
    echo "$output" | jq -e '.managed_peers_not_loaded == ["carol"]'
}

@test "monitor: transfer spike against previous sample" {
    ztvpn_fake_wg_server
    load_lib
    wg_provision_peer dave >/dev/null
    pub="$(<"$WG_CLIENTS_DIR/dave/public.key")"
    now="$(date +%s)"
    mkdir -p "$ZTVPN_STATE_DIR/monitor"
    jq -n --arg k "$pub" --argjson ts "$((now - 10))" '{ts: $ts, peers: {($k): {rx: 1000, tx: 1000}}}' >"$ZTVPN_STATE_DIR/monitor/wg-sample.json"
    write_dump "$pub" 198.51.100.9:1 10.8.0.2/32 "$now" 5000000000 2000
    run --separate-stderr "$MON" --json
    [ "$status" -eq 1 ]
    echo "$output" | jq -e '[.alerts[] | select(.source == "traffic-spike")] | length == 1'
    # The new sample replaces the old one: a second run shows no spike.
    run --separate-stderr "$MON" --json
    [ "$status" -eq 0 ]
    [ "$(jq -r --arg k "$pub" '.peers[$k].rx' "$ZTVPN_STATE_DIR/monitor/wg-sample.json")" = "5000000000" ]
}

@test "monitor: counts failed 1FA/2FA logins from docker logs within the window" {
    ztvpn_fake_wg_server
    write_dump
    cat >"$DOCKER_LOGS" <<'EOF'
time="2026-09-24T10:00:00Z" level=error msg="Unsuccessful 1FA authentication attempt by user 'bob'" method=POST path=/api/firstfactor remote_ip=203.0.113.7
time="2026-09-24T10:00:01Z" level=error msg="Unsuccessful 1FA authentication attempt by user 'bob'" method=POST path=/api/firstfactor remote_ip=203.0.113.7
time="2026-09-24T10:00:02Z" level=error msg="Unsuccessful 1FA authentication attempt by user 'eve'" method=POST path=/api/firstfactor remote_ip=198.51.100.3
time="2026-09-24T10:00:03Z" level=error msg="Unsuccessful TOTP authentication attempt by user 'bob'" method=POST path=/api/secondfactor/totp remote_ip=203.0.113.7
time="2026-09-24T10:00:04Z" level=info msg="Successful 1FA authentication attempt made by user 'alice'"
EOF
    MONITOR_AUTH_FAIL_THRESHOLD=3 run --separate-stderr "$MON" --json --window 15m
    [ "$status" -eq 1 ]
    echo "$output" | jq -e '.auth.failed_1fa == 3 and .auth.failed_2fa == 1'
    echo "$output" | jq -e '.auth.by_ip["203.0.113.7"] == 3'
    echo "$output" | jq -e '[.alerts[] | select(.source == "auth-failures")] | length == 1'
    calls docker | grep -qx "compose -f $ZTVPN_HOME/docker-compose.yml --project-directory $ZTVPN_HOME logs --no-color --no-log-prefix --since 15m authelia"
    : >"$STUB_LOG/docker"
    AUTHELIA_CONTAINER=auth run --separate-stderr "$MON" --json --window 15m
    calls docker | grep -qx 'logs --since 15m auth'
}

@test "monitor: zero failures is a clean 0, not a double value" {
    ztvpn_fake_wg_server
    write_dump
    echo 'time="2026-09-24T10:00:04Z" level=info msg="all good"' >"$DOCKER_LOGS"
    run --separate-stderr "$MON" --json
    [ "$status" -eq 0 ]
    echo "$output" | jq -e '.auth.failed_1fa == 0 and .auth.failed_2fa == 0 and .auth.by_ip == {}'
}

@test "monitor: no Authelia log source is reported as unavailable, not zero" {
    ztvpn_fake_wg_server
    write_dump
    rm "$ZTVPN_HOME/docker-compose.yml"
    run --separate-stderr "$MON" --json
    [ "$status" -eq 0 ]
    echo "$output" | jq -e '.auth == null'
    run --separate-stderr "$MON"
    [[ "$output" == *"Failed logins: unavailable"* ]]
}

@test "monitor: AUTHELIA_LOG_FILE is filtered by time window" {
    ztvpn_fake_wg_server
    write_dump
    old="$(date -u -d '-2 hours' +%FT%TZ)"
    new="$(date -u -d '-1 minute' +%FT%TZ)"
    export AUTHELIA_LOG_FILE="$BATS_TEST_TMPDIR/authelia.log"
    {
        printf '{"level":"error","msg":"Unsuccessful 1FA authentication attempt by user '"'"'x'"'"'","remote_ip":"203.0.113.1","time":"%s"}\n' "$old"
        printf '{"level":"error","msg":"Unsuccessful 1FA authentication attempt by user '"'"'x'"'"'","remote_ip":"203.0.113.1","time":"%s"}\n' "$new"
    } >"$AUTHELIA_LOG_FILE"
    run --separate-stderr "$MON" --json --window 10m
    [ "$status" -eq 0 ]
    echo "$output" | jq -e '.auth.failed_1fa == 1 and .auth.by_ip["203.0.113.1"] == 1'
    [ -z "$(calls docker)" ]
}

@test "monitor: threat-response is only called with --respond" {
    ztvpn_fake_wg_server
    write_dump
    for i in 1 2 3; do
        echo "time=\"2026-09-24T10:00:0${i}Z\" level=error msg=\"Unsuccessful 1FA authentication attempt by user 'bob'\" remote_ip=203.0.113.7" >>"$DOCKER_LOGS"
    done
    export THREAT_RESPONSE="$BATS_TEST_TMPDIR/bin/threat"
    stub threat 'echo INC-x'
    MONITOR_AUTH_FAIL_THRESHOLD=3 run --separate-stderr "$MON" --json
    [ "$status" -eq 1 ]
    [ -z "$(calls threat)" ]
    MONITOR_AUTH_FAIL_THRESHOLD=3 run --separate-stderr "$MON" --json --respond
    [ "$status" -eq 1 ]
    [[ "$(calls threat)" == "--type brute-force --ip 203.0.113.7 --duration 1h --reason connection-monitor: 3 failed logins" ]]
}

@test "monitor: wg failure is an error, bad options rejected" {
    stub wg 'echo "Unable to access interface: No such device" >&2; exit 1'
    run "$MON" --once
    [ "$status" -eq 2 ]
    run "$MON" --window 5x
    [ "$status" -eq 2 ]
}

# ==========================================================================
# security-audit.sh
# ==========================================================================

# Mirrors the shipped design: input policy drop, forward policy accept
# (Docker needs it) with wg0 traffic sent to chains that end in drop.
good_nft() {
    cat >"$NFT_JSON" <<'EOF'
{"nftables":[{"metainfo":{"version":"1.0.9"}},{"table":{"family":"inet","name":"ztvpn","handle":1}},
{"set":{"family":"inet","name":"blocklist4","table":"ztvpn","type":"ipv4_addr","handle":4,"flags":["timeout"]}},
{"set":{"family":"inet","name":"blocklist6","table":"ztvpn","type":"ipv6_addr","handle":5,"flags":["timeout"]}},
{"set":{"family":"inet","name":"quarantine4","table":"ztvpn","type":"ipv4_addr","handle":6}},
{"chain":{"family":"inet","table":"ztvpn","name":"input","handle":1,"type":"filter","hook":"input","prio":0,"policy":"drop"}},
{"chain":{"family":"inet","table":"ztvpn","name":"forward","handle":2,"type":"filter","hook":"forward","prio":0,"policy":"accept"}},
{"chain":{"family":"inet","table":"ztvpn","name":"wg_forward","handle":3}},
{"chain":{"family":"inet","table":"ztvpn","name":"wg_forward_out","handle":4}},
{"rule":{"family":"inet","table":"ztvpn","chain":"forward","handle":10,"expr":[{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"wg0"}},{"jump":{"target":"wg_forward"}}]}},
{"rule":{"family":"inet","table":"ztvpn","chain":"forward","handle":11,"expr":[{"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"wg0"}},{"jump":{"target":"wg_forward_out"}}]}},
{"rule":{"family":"inet","table":"ztvpn","chain":"wg_forward","handle":12,"expr":[{"match":{"op":"in","left":{"ct":{"key":"state"}},"right":["established","related"]}},{"accept":null}]}},
{"rule":{"family":"inet","table":"ztvpn","chain":"wg_forward","handle":13,"expr":[{"drop":null}]}},
{"rule":{"family":"inet","table":"ztvpn","chain":"wg_forward_out","handle":14,"expr":[{"drop":null}]}}]}
EOF
}

good_host() {
    ztvpn_fake_wg_server
    load_lib
    pki_init_ca 2>/dev/null
    pki_issue server vpn.example.com 200 >/dev/null 2>&1
    good_nft
    printf 'vpn-nginx\t0.0.0.0:443->443/tcp, [::]:443->443/tcp\nauthelia\t127.0.0.1:9091->9091/tcp\n' >"$DOCKER_PS"
    mkdir -p "$AUTHELIA_SECRETS_DIR"
    chmod 700 "$AUTHELIA_SECRETS_DIR"
    (umask 077; gen_secret >"$AUTHELIA_SECRETS_DIR/jwt_secret")
    cat >"$AUTHELIA_DIR/configuration.yml" <<'EOF'
access_control:
  default_policy: deny
  rules:
    - domain: "app.example.com"
      policy: two_factor
      subject: ["group:vpn-users"]
EOF
    authelia_add_user alice Alice alice@example.com '$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA' users,vpn-users
    wg_provision_peer alice--laptop >/dev/null
    rm -f "$WG_CLIENTS_DIR/alice--laptop/private.key"
}

@test "audit: clean host has no findings and exits 0" {
    good_host
    run --separate-stderr "$AUDIT" --json
    [ "$status" -eq 0 ]
    echo "$output" | jq -e '.summary.failed == 0'
    echo "$output" | jq -e '.summary.passed > 20'
    echo "$output" | jq -e '[.checks[] | select(.id == "FW-POLICY")][0].status == "pass"'
}

@test "audit: findings are counted and exit non-zero" {
    good_host
    chmod 644 "$WG_SERVER_KEY"
    chmod 644 "$AUTHELIA_SECRETS_DIR/jwt_secret"
    printf 'PostUp = iptables -A FORWARD -i wg0 -j ACCEPT\n' >>"$WG_CONF"
    printf '\n[Peer]\nPublicKey = %s\nAllowedIPs = 0.0.0.0/0\n' "$(wg genkey | wg pubkey)" >>"$WG_CONF"
    jq '(.nftables[] | select(.chain.hook == "input") | .chain.policy) = "accept"
        | del(.nftables[] | select(.rule.handle == 13))' "$NFT_JSON" >"$NFT_JSON.new"
    mv "$NFT_JSON.new" "$NFT_JSON"
    printf 'vpn-nginx\t0.0.0.0:443->443/tcp\nauthelia\t0.0.0.0:9091->9091/tcp, :::9091->9091/tcp\n' >"$DOCKER_PS"
    cat >"$AUTHELIA_DIR/configuration.yml" <<'EOF'
jwt_secret: inline-secret
access_control:
  default_policy: one_factor
  networks:
    - name: vpn
      networks: ["10.8.0.0/24"]
  rules:
    - domain: "*.example.com"
      policy: bypass
      networks: ["vpn"]
EOF
    authelia_set_disabled alice true
    run --separate-stderr "$AUDIT" --json
    [ "$status" -eq 1 ]
    failed="$(echo "$output" | jq -r '[.checks[] | select(.status == "fail") | .id] | sort | join(" ")')"
    [ "$failed" = "AUTH-BYPASS AUTH-DEFAULT-DENY AUTH-INLINE-SECRETS FILE-AUTHELIA-SECRETS FILE-WG-KEY FW-POLICY ID-ORPHAN-PEERS NET-DOCKER-PORTS WG-ALLOWEDIPS WG-HOOKS WG-UNMANAGED" ]
    echo "$output" | jq -e '.summary.failed == 11'
    echo "$output" | jq -e '.summary.by_severity == {critical: 1, high: 8, medium: 2, low: 0, info: 0}'
    echo "$output" | jq -e '.checks[] | select(.id == "WG-HOOKS") | .severity == "high"'
    echo "$output" | jq -e '.checks[] | select(.id == "NET-DOCKER-PORTS") | .items == ["authelia publishes 0.0.0.0:9091 (9091/tcp)", "authelia publishes :::9091 (9091/tcp)"]'
    # Items never contain secret values
    [[ "$output" != *"inline-secret"* ]]

    run --separate-stderr "$AUDIT"
    [ "$status" -eq 1 ]
    [[ "$output" == *"failed: 11"* ]]
    [[ "$output" == *"critical 1, high 8, medium 2"* ]]
    [[ "$output" != *"✅"* ]]
}

@test "audit: --fail-on controls the exit code" {
    good_host
    printf '\n[Peer]\nPublicKey = %s\nAllowedIPs = 10.8.0.50/32\n' "$(wg genkey | wg pubkey)" >>"$WG_CONF"
    run --separate-stderr "$AUDIT" --json
    [ "$status" -eq 0 ]
    echo "$output" | jq -e '.summary.by_severity.medium == 1'
    run "$AUDIT" --fail-on medium
    [ "$status" -eq 1 ]
    run "$AUDIT" --fail-on bogus
    [ "$status" -eq 2 ]
}

@test "audit: the shipped nftables example passes the firewall checks" {
    example="$REPO_ROOT/config-examples/firewall/ztvpn.nft.example"
    [ -f "$example" ] || skip "no nftables example"
    [ -n "$REAL_NFT" ] || skip "nft not installed"
    unshare -n sh -c "'$REAL_NFT' -f '$example' && '$REAL_NFT' -j list table inet ztvpn" >"$NFT_JSON" 2>/dev/null ||
        skip "cannot load nftables rules in a network namespace here"
    echo 1 >"$ZTVPN_PROC_DIR/sys/net/ipv6/conf/all/forwarding"
    run --separate-stderr "$AUDIT" --json --fail-on none
    [ "$status" -eq 0 ]
    echo "$output" | jq -e '[.checks[] | select(.id | startswith("FW-")) | .status] | all(. == "pass")'
}

@test "audit: missing firewall table and unencrypted CA key are critical" {
    good_host
    rm -f "$NFT_JSON"
    echo 1 >"$ZTVPN_PROC_DIR/sys/net/ipv6/conf/all/forwarding"
    chmod 600 "$PKI_CA_KEY"
    openssl pkey -in "$PKI_CA_KEY" -passin "file:$PKI_CA_PASSFILE" -out "$BATS_TEST_TMPDIR/plain.key"
    cp "$BATS_TEST_TMPDIR/plain.key" "$PKI_CA_KEY"
    run --separate-stderr "$AUDIT" --json --fail-on critical
    [ "$status" -eq 1 ]
    echo "$output" | jq -e '.checks[] | select(.id == "FW-TABLE") | .status == "fail"'
    echo "$output" | jq -e '.checks[] | select(.id == "FW-IPV6") | .status == "fail"'
    echo "$output" | jq -e '.checks[] | select(.id == "PKI-CA-KEY-ENCRYPTED") | .status == "fail"'
    echo "$output" | jq -e '.checks[] | select(.id == "FILE-CA-KEY") | .status == "fail"'
}

check_of() {
    jq -c --arg id "$1" '.checks[] | select(.id == $id)' <<<"$output"
}

@test "audit: MTLS=no is reported as not enforcing client certificates" {
    good_host
    run --separate-stderr "$AUDIT" --json
    [ "$status" -eq 0 ]
    c="$(check_of PROXY-MTLS)"
    jq -e '.status == "pass" and .severity == "info"' <<<"$c"
    jq -e '.items[0] | test("does not request or check client certificates")' <<<"$c"
    run --separate-stderr "$AUDIT" --verbose
    [[ "$output" == *"[PASS] PROXY-MTLS"*"MTLS=no: nginx does not request or check client certificates"* ]]
}

@test "audit: MTLS=yes checks the generated snippet and treats a stale CRL as high/critical" {
    good_host
    export MTLS=yes
    # No snippet deployed
    run --separate-stderr "$AUDIT" --json
    [ "$status" -eq 1 ]
    jq -e '.status == "fail" and .severity == "high" and (.items[0] | test("does not exist"))' <<<"$(check_of PROXY-MTLS)"

    mkdir -p "$(dirname "$MTLS_SNIPPET")"
    mtls_snippet yes >"$MTLS_SNIPPET"
    run --separate-stderr "$AUDIT" --json
    [ "$status" -eq 0 ]
    jq -e '.status == "pass"' <<<"$(check_of PROXY-MTLS)"
    jq -e '.status == "pass"' <<<"$(check_of PKI-CRL)"

    # Verification switched to optional, or only mentioned in a comment
    sed -i 's/^ssl_verify_client .*/ssl_verify_client      optional; # ssl_verify_client on;/' "$MTLS_SNIPPET"
    run --separate-stderr "$AUDIT" --json
    [ "$status" -eq 1 ]
    jq -e '.status == "fail" and (.items | any(test("ssl_verify_client on")))' <<<"$(check_of PROXY-MTLS)"
    mtls_snippet no >"$MTLS_SNIPPET"
    run --separate-stderr "$AUDIT" --json
    jq -e '.status == "fail" and (.items | length) == 4' <<<"$(check_of PROXY-MTLS)"
    mtls_snippet yes >"$MTLS_SNIPPET"

    # A deployed template with an HTTPS server that skips the snippet
    mkdir -p "$CONFIG_PATH/nginx/templates"
    printf 'server {\n    listen 443 ssl;\n}\n' >"$CONFIG_PATH/nginx/templates/app.conf.template"
    run --separate-stderr "$AUDIT" --json
    [ "$status" -eq 1 ]
    jq -e '.status == "fail" and (.items | length) == 1 and (.items[0] | test("app.conf.template"))' <<<"$(check_of PROXY-MTLS)"
    cp "$REPO_ROOT"/config-examples/nginx/templates/* "$CONFIG_PATH/nginx/templates/"
    rm "$CONFIG_PATH/nginx/templates/app.conf.template"
    run --separate-stderr "$AUDIT" --json
    jq -e '.status == "pass"' <<<"$(check_of PROXY-MTLS)"

    # CRL close to nextUpdate: medium without MTLS, high with it
    openssl ca -config "$PKI_CA_CNF" -passin "file:$PKI_CA_PASSFILE" -gencrl -crldays 3 -out "$PKI_CRL" 2>/dev/null
    MTLS=no run --separate-stderr "$AUDIT" --json
    jq -e '.status == "fail" and .severity == "medium"' <<<"$(check_of PKI-CRL)"
    run --separate-stderr "$AUDIT" --json
    [ "$status" -eq 1 ]
    jq -e '.status == "fail" and .severity == "high" and (.items[0] | test("cert-renewal.sh renew"))' <<<"$(check_of PKI-CRL)"

    # A world-readable .p12 is a key leak
    pki_issue client alice >/dev/null 2>&1
    echo pass | pki_export_p12 alice >/dev/null
    chmod 644 "$PKI_CLIENTS_DIR/alice.p12"
    run --separate-stderr "$AUDIT" --json
    jq -e '.status == "fail" and (.items[0] | test("alice.p12 mode 644"))' <<<"$(check_of FILE-PKI-KEYS)"
}

# ==========================================================================
# compliance-check.sh
# ==========================================================================

all_pass_audit() {
    local ids="FILE-WG-KEY FILE-WG-CONF FILE-CA-PASS FILE-AUTHELIA-USERS FILE-WG-CLIENTS FILE-WG-CLIENT-KEYS-ON-SERVER PKI-CA-KEY-ENCRYPTED FILE-CA-KEY FILE-PKI-KEYS FILE-AUTHELIA-SECRETS FILE-CONFIG PKI-CA-EXPIRY PKI-SERVER-EXPIRY PKI-CHAIN PKI-CLIENT-EXPIRY PKI-CRL WG-HOOKS WG-UNMANAGED WG-ALLOWEDIPS WG-PSK FW-TABLE FW-POLICY FW-SETS FW-IPV6 NET-DOCKER-PORTS AUTH-DEFAULT-DENY AUTH-BYPASS AUTH-INLINE-SECRETS ID-ORPHAN-PEERS ID-IDLE-ACCOUNTS ID-UNKNOWN-GROUPS"
    printf '%s\n' $ids | jq -R '{id: ., status: "pass", severity: "high", title: ., items: []}' |
        jq -s '{generated: "2026-01-01T00:00:00Z", host: "test", checks: .}'
}

@test "compliance: organisational controls stay MANUAL even when policy documents exist" {
    mkdir -p "$ZTVPN_HOME/docs"
    for f in access-control-policy logging-policy monitoring-policy privileged-access incident-response; do
        echo "# $f" >"$ZTVPN_HOME/docs/$f.md"
    done
    all_pass_audit >"$BATS_TEST_TMPDIR/audit.json"
    run --separate-stderr "$COMP" --audit-json "$BATS_TEST_TMPDIR/audit.json" --json
    [ "$status" -eq 0 ]
    for c in A.8.2 A.8.15 A.8.16 T1 T3 T5 T7; do
        echo "$output" | jq -e --arg c "$c" '.controls[] | select(.id == $c) | .status == "MANUAL"'
    done
    # Only controls with automated evidence can pass.
    echo "$output" | jq -e '[.controls[] | select(.status == "PASS" and (.evidence | length) == 0)] | length == 0'
    echo "$output" | jq -e '.summary.MANUAL == 7 and .summary.FAIL == 0'
}

@test "compliance: exit code is the FAIL count, skipped checks are NOT_EVALUATED" {
    all_pass_audit | jq '(.checks[] | select(.id == "FW-POLICY")) |= (.status = "fail" | .items = ["input hook: policy is not drop"])
        | (.checks[] | select(.id == "ID-ORPHAN-PEERS")) |= (.status = "skip")' >"$BATS_TEST_TMPDIR/audit.json"
    run --separate-stderr "$COMP" --audit-json "$BATS_TEST_TMPDIR/audit.json" --json
    # FW-POLICY is mapped to A.5.15, A.8.20 and T6
    [ "$status" -eq 3 ]
    echo "$output" | jq -e '[.controls[] | select(.status == "FAIL") | .id] == ["A.5.15", "A.8.20", "T6"]'
    echo "$output" | jq -e '.controls[] | select(.id == "A.5.18") | .status == "NOT_EVALUATED"'
    report="$(ls "$ZTVPN_STATE_DIR/reports"/compliance-all-*.json)"
    [ "$(stat -c %a "$report")" = "600" ]
    jq -e '.summary.FAIL == 3' "$report"
}

@test "compliance: framework filter, unknown framework, and end-to-end with security-audit" {
    all_pass_audit >"$BATS_TEST_TMPDIR/audit.json"
    run --separate-stderr "$COMP" --framework nist-800-207 --audit-json "$BATS_TEST_TMPDIR/audit.json" --json
    [ "$status" -eq 0 ]
    echo "$output" | jq -e '[.controls[].framework] | unique == ["nist-800-207"]'
    run "$COMP" --framework soc2
    [ "$status" -eq 125 ]
    [[ "$output" == *"Unknown framework"* ]]

    good_host
    run --separate-stderr "$COMP" --json
    [ "$status" -eq 0 ]
    echo "$output" | jq -e '.summary.FAIL == 0 and .summary.PASS > 0'
}
