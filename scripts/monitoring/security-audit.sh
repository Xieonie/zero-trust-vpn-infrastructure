#!/usr/bin/env bash
# Technical security audit of a zero-trust-vpn host.
#
# Every check inspects real state and records pass, fail (with severity
# and the offending items) or skip (component not present / not readable).
# Nothing is reported as passing without having been checked.
#
# Check IDs are stable; compliance-check.sh maps them to controls.

set -Eeuo pipefail
# shellcheck source=scripts/lib/common.sh
source "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/../lib/common.sh"

# Host ports that may be published on all interfaces.
AUDIT_PUBLIC_PORTS="${AUDIT_PUBLIC_PORTS:-80,443,$WG_PORT}"
ZTVPN_PROC_DIR="${ZTVPN_PROC_DIR:-/proc}"

usage() {
    cat <<EOF
Usage: $(basename "$0") [--json] [--fail-on SEVERITY] [--verbose]

  --json            Print results as JSON on stdout
  --fail-on SEV     Exit 1 if any finding has at least this severity:
                    info, low, medium, high (default), critical, or none
  --verbose         Also list passed checks in text output
  -h, --help        Show this help

Exit codes: 0 no findings at/above --fail-on, 1 findings, 2 usage/runtime error.
EOF
}

fatal() { error "$*"; exit 2; }

sev_rank() {
    case "$1" in
        info) echo 0 ;; low) echo 1 ;; medium) echo 2 ;; high) echo 3 ;; critical) echo 4 ;;
        none) echo 99 ;; *) return 1 ;;
    esac
}

RESULTS=""

# record <id> <pass|fail|skip> <severity> <title> [item ...]
record() {
    local id="$1" status="$2" sev="$3" title="$4"
    shift 4
    local items='[]'
    if (($#)); then
        items="$(printf '%s\n' "$@" | jq -R . | jq -sc .)"
    fi
    jq -nc --arg id "$id" --arg status "$status" --arg sev "$sev" --arg title "$title" --argjson items "$items" \
        '{id: $id, status: $status, severity: $sev, title: $title, items: $items}' >>"$RESULTS"
}

# pass/fail helper: result <id> <severity> <title> [items...] -> fail if items given
result() {
    local id="$1" sev="$2" title="$3"
    shift 3
    if (($#)); then
        record "$id" fail "$sev" "$title" "$@"
    else
        record "$id" pass "$sev" "$title"
    fi
}

perm_of() { stat -c %a "$1"; }
# True if the file grants anything beyond the bits in <allowed> (octal).
perm_exceeds() {
    local p
    p="$(perm_of "$1")"
    (((8#$p & ~8#$2 & 8#7777) != 0))
}

# --------------------------------------------------------------------------
# File permissions
# --------------------------------------------------------------------------

audit_files() {
    local -a bad
    local f

    for f in "$WG_SERVER_KEY:FILE-WG-KEY:WireGuard server private key is 0600 and root-owned" \
        "$WG_CONF:FILE-WG-CONF:WireGuard server config (contains the private key) is 0600" \
        "$PKI_CA_PASSFILE:FILE-CA-PASS:CA key passphrase file is 0600" \
        "$AUTHELIA_USERS_DB:FILE-AUTHELIA-USERS:Authelia users database (password hashes) is 0600"; do
        local path="${f%%:*}" rest="${f#*:}"
        local id="${rest%%:*}" title="${rest#*:}"
        if [[ ! -e "$path" ]]; then
            record "$id" skip high "$title" "$path not found"
            continue
        fi
        bad=()
        perm_exceeds "$path" 600 && bad+=("$path mode $(perm_of "$path")")
        [[ "$(stat -c %u "$path")" == 0 || "$(stat -c %u "$path")" == "$(id -u)" ]] || bad+=("$path owned by uid $(stat -c %u "$path")")
        result "$id" high "$title" "${bad[@]}"
    done

    if [[ -d "$WG_CLIENTS_DIR" ]]; then
        bad=()
        while IFS= read -r f; do
            bad+=("$f mode $(perm_of "$f")")
        done < <(find "$WG_CLIENTS_DIR" -mindepth 1 \( -type f -perm /077 \) -o \( -type d -perm /077 \) 2>/dev/null)
        result FILE-WG-CLIENTS high "Client key material under $WG_CLIENTS_DIR is not group/world accessible" "${bad[@]}"
        local n
        n="$(find "$WG_CLIENTS_DIR" -name private.key -type f 2>/dev/null | wc -l)"
        if ((n > 0)); then
            record FILE-WG-CLIENT-KEYS-ON-SERVER fail info "Client private keys are not kept on the server" \
                "$n client private key(s) in $WG_CLIENTS_DIR; deliver and delete them"
        else
            record FILE-WG-CLIENT-KEYS-ON-SERVER pass info "Client private keys are not kept on the server"
        fi
    else
        record FILE-WG-CLIENTS skip high "Client key material under $WG_CLIENTS_DIR is not group/world accessible" "$WG_CLIENTS_DIR not found"
        record FILE-WG-CLIENT-KEYS-ON-SERVER skip info "Client private keys are not kept on the server" "$WG_CLIENTS_DIR not found"
    fi

    if [[ -f "$PKI_CA_KEY" ]]; then
        if grep -q -- '-----BEGIN ENCRYPTED PRIVATE KEY-----' "$PKI_CA_KEY"; then
            record PKI-CA-KEY-ENCRYPTED pass critical "CA private key is encrypted"
        else
            record PKI-CA-KEY-ENCRYPTED fail critical "CA private key is encrypted" "$PKI_CA_KEY is not encrypted"
        fi
        bad=()
        perm_exceeds "$PKI_CA_KEY" 400 && bad+=("$PKI_CA_KEY mode $(perm_of "$PKI_CA_KEY")")
        perm_exceeds "$(dirname "$PKI_CA_KEY")" 700 && bad+=("$(dirname "$PKI_CA_KEY") mode $(perm_of "$(dirname "$PKI_CA_KEY")")")
        result FILE-CA-KEY high "CA private key is 0400 in a 0700 directory" "${bad[@]}"
    else
        record PKI-CA-KEY-ENCRYPTED skip critical "CA private key is encrypted" "$PKI_CA_KEY not found"
        record FILE-CA-KEY skip high "CA private key is 0400 in a 0700 directory" "$PKI_CA_KEY not found"
    fi

    bad=()
    for f in "$PKI_SERVER_DIR"/*.key "$PKI_CLIENTS_DIR"/*.key; do
        [[ -f "$f" ]] || continue
        perm_exceeds "$f" 600 && bad+=("$f mode $(perm_of "$f")")
    done
    result FILE-PKI-KEYS high "Certificate private keys are 0600" "${bad[@]}"

    if [[ -d "$AUTHELIA_SECRETS_DIR" ]]; then
        bad=()
        perm_exceeds "$AUTHELIA_SECRETS_DIR" 700 && bad+=("$AUTHELIA_SECRETS_DIR mode $(perm_of "$AUTHELIA_SECRETS_DIR")")
        while IFS= read -r f; do
            bad+=("$f mode $(perm_of "$f")")
        done < <(find "$AUTHELIA_SECRETS_DIR" -mindepth 1 -perm /077 2>/dev/null)
        result FILE-AUTHELIA-SECRETS high "Authelia secret files are not group/world accessible" "${bad[@]}"
    else
        record FILE-AUTHELIA-SECRETS skip high "Authelia secret files are not group/world accessible" "$AUTHELIA_SECRETS_DIR not found"
    fi

    if [[ -f "$ZTVPN_CONFIG" ]]; then
        bad=()
        perm_exceeds "$ZTVPN_CONFIG" 755 && bad+=("$ZTVPN_CONFIG mode $(perm_of "$ZTVPN_CONFIG")")
        result FILE-CONFIG high "ztvpn.conf is not group/world writable" "${bad[@]}"
    else
        record FILE-CONFIG skip high "ztvpn.conf is not group/world writable" "$ZTVPN_CONFIG not found"
    fi
}

# --------------------------------------------------------------------------
# PKI
# --------------------------------------------------------------------------

db_status() {
    local serial
    serial="$(openssl x509 -in "$1" -noout -serial 2>/dev/null)" || return 0
    serial="${serial#serial=}"
    [[ -f "$PKI_CA_DIR/index.txt" ]] || return 0
    awk -F'\t' -v s="$serial" 'toupper($4) == toupper(s) { print $1; exit }' "$PKI_CA_DIR/index.txt"
}

max_sev() {
    if (($(sev_rank "$1") >= $(sev_rank "$2"))); then echo "$1"; else echo "$2"; fi
}

audit_pki() {
    if [[ ! -f "$PKI_CA_CERT" ]]; then
        local id
        for id in PKI-CA-EXPIRY PKI-SERVER-EXPIRY PKI-CLIENT-EXPIRY PKI-CHAIN PKI-CRL; do
            record "$id" skip high "PKI check" "$PKI_CA_CERT not found"
        done
        return 0
    fi
    local days sev
    days="$(pki_days_left "$PKI_CA_CERT")" || days=-1
    if ((days < 0)); then
        record PKI-CA-EXPIRY fail critical "CA certificate is valid for more than 180 days" "CA expired"
    elif ((days <= 90)); then
        record PKI-CA-EXPIRY fail high "CA certificate is valid for more than 180 days" "CA expires in $days days"
    elif ((days <= 180)); then
        record PKI-CA-EXPIRY fail medium "CA certificate is valid for more than 180 days" "CA expires in $days days"
    else
        record PKI-CA-EXPIRY pass medium "CA certificate is valid for more than 180 days"
    fi

    local f name st
    local -a srv_items=() chain_items=() cli_items=()
    local srv_sev=medium
    for f in "$PKI_SERVER_DIR"/*.crt; do
        [[ -f "$f" ]] || continue
        name="$(basename "$f" .crt)"
        st="$(db_status "$f")"
        days="$(pki_days_left "$f")" || { srv_items+=("$name: unreadable"); srv_sev=high; continue; }
        if ((days < 0)); then
            srv_items+=("$name expired"); srv_sev="$(max_sev "$srv_sev" critical)"
        elif ((days <= 7)); then
            srv_items+=("$name expires in $days days"); srv_sev="$(max_sev "$srv_sev" high)"
        elif ((days <= 30)); then
            srv_items+=("$name expires in $days days")
        fi
        if ! pki_verify "$f"; then
            chain_items+=("$name does not verify against the CA and CRL${st:+ (CA db status $st)}")
        fi
    done
    result PKI-SERVER-EXPIRY "$srv_sev" "Server certificates are valid for more than 30 days" "${srv_items[@]}"
    result PKI-CHAIN high "Server certificates chain to the CA and are not revoked" "${chain_items[@]}"

    for f in "$PKI_CLIENTS_DIR"/*.crt; do
        [[ -f "$f" ]] || continue
        [[ "$(db_status "$f")" == R ]] && continue
        days="$(pki_days_left "$f")" || continue
        ((days < 0)) && cli_items+=("$(basename "$f" .crt) expired but not revoked")
    done
    result PKI-CLIENT-EXPIRY low "No expired, unrevoked client certificates are lying around" "${cli_items[@]}"

    if [[ ! -f "$PKI_CRL" ]]; then
        record PKI-CRL fail high "CRL exists, is signed by the CA and is current" "$PKI_CRL not found"
        return 0
    fi
    local next next_epoch now
    sev=medium
    local -a crl_items=()
    if ! openssl crl -in "$PKI_CRL" -CAfile "$PKI_CA_CERT" -noout >/dev/null 2>&1; then
        crl_items+=("CRL signature does not verify against the CA"); sev=high
    fi
    next="$(openssl crl -in "$PKI_CRL" -noout -nextupdate 2>/dev/null)" || next=""
    next="${next#nextUpdate=}"
    now="$(date +%s)"
    if next_epoch="$(date -d "$next" +%s 2>/dev/null)" && [[ -n "$next" ]]; then
        if ((next_epoch < now)); then
            crl_items+=("CRL expired at $next; clients checking it will fail"); sev=high
        elif ((next_epoch - now < 7 * 86400)); then
            crl_items+=("CRL nextUpdate $next is less than 7 days away; run pki_gen_crl")
        fi
    else
        crl_items+=("CRL has no readable nextUpdate"); sev=high
    fi
    result PKI-CRL "$sev" "CRL exists, is signed by the CA and is current" "${crl_items[@]}"
}

# --------------------------------------------------------------------------
# WireGuard
# --------------------------------------------------------------------------

audit_wireguard() {
    if [[ ! -f "$WG_CONF" ]]; then
        local id
        for id in WG-HOOKS WG-UNMANAGED WG-ALLOWEDIPS WG-PSK; do
            record "$id" skip high "WireGuard check" "$WG_CONF not found"
        done
        return 0
    fi
    local -a items=()
    local line sev=low
    while IFS= read -r line; do
        items+=("$line")
        [[ "$line" =~ ip6?tables ]] && sev=high
    done < <(grep -E '^[[:space:]]*(PreUp|PostUp|PreDown|PostDown)[[:space:]]*=' "$WG_CONF" || true)
    result WG-HOOKS "$sev" "wg config has no Pre/PostUp hooks (firewall lives in nftables)" "${items[@]}"

    items=()
    local n
    n="$(awk '/^# BEGIN PEER / { m = 1 } /^# END PEER / { m = 0 } /^[[:space:]]*\[Peer\]/ && !m { c++ } END { print c + 0 }' "$WG_CONF")"
    ((n > 0)) && items+=("$n [Peer] section(s) without BEGIN/END PEER markers (not managed by the tooling)")
    result WG-UNMANAGED medium "All peers are managed (have BEGIN/END PEER markers)" "${items[@]}"

    items=()
    local -A used=()
    local entry
    while IFS= read -r entry; do
        [[ -n "$entry" ]] || continue
        if [[ "$entry" != */32 ]] || ! ip_in_cidr "${entry%/32}" "$VPN_SUBNET"; then
            items+=("AllowedIPs $entry is not a single address in $VPN_SUBNET")
        elif [[ -n "${used[$entry]:-}" ]]; then
            items+=("AllowedIPs $entry assigned to more than one peer")
        fi
        used["$entry"]=1
    done < <(awk '
        /^[[:space:]]*\[/ { peer = ($0 ~ /\[Peer\]/) }
        peer && /^[[:space:]]*AllowedIPs[[:space:]]*=/ {
            sub(/^[^=]*=[[:space:]]*/, "")
            n = split($0, a, /[[:space:]]*,[[:space:]]*/)
            for (i = 1; i <= n; i++) print a[i]
        }' "$WG_CONF")
    result WG-ALLOWEDIPS high "Every peer is limited to one /32 inside VPN_SUBNET" "${items[@]}"

    items=()
    while IFS= read -r n; do
        [[ -n "$n" ]] && items+=("$n has no PresharedKey")
    done < <(awk '
        /^# BEGIN PEER / { name = substr($0, 14); psk = 0; next }
        /^# END PEER / { if (name != "" && !psk) print name; name = ""; next }
        name != "" && /^[[:space:]]*PresharedKey[[:space:]]*=/ { psk = 1 }' "$WG_CONF")
    result WG-PSK low "Managed peers use a preshared key" "${items[@]}"
}

# --------------------------------------------------------------------------
# Firewall
# --------------------------------------------------------------------------

# Forwarding is safe if the forward hook defaults to drop, or if traffic
# from and to the WireGuard interface is sent (jump/goto) to chains whose
# last rule is an unconditional drop. The latter is the shipped design,
# because a drop policy on the forward hook would break Docker. Prints
# "ok" or the reason.
FORWARD_JQ='
    (.nftables | map(select(.chain) | .chain)) as $chains
    | (.nftables | map(select(.rule) | .rule)) as $rules
    | ($chains | map(select(.hook == "forward"))) as $fwd
    | def target($dir):
        [$rules[] | select(.chain as $c | $fwd | any(.name == $c))
         | select(any(.expr[]; (.match.left.meta.key? == $dir) and (.match.right? == $ifn) and (.match.op? == "==")))
         | .expr[] | (.jump.target? // .goto.target? // empty)];
      def ends_in_drop($t): ([$rules[] | select(.chain == $t)] | last | .expr) == [{"drop": null}];
    if ($fwd | length) == 0 then "no forward base chain"
    elif all($fwd[]; .policy == "drop") then "ok"
    else
      [("iifname", "oifname") as $d | target($d) as $t
       | if ($t | length) == 0 then "policy accept and no \($d) \($ifn) jump to a default-drop chain"
         elif all($t[]; ends_in_drop(.)) then empty
         else "\($d) \($ifn) chain \($t | join(",")) does not end in drop" end]
      | if length == 0 then "ok" else join("; ") end
    end'

audit_firewall() {
    local ruleset fwd6=0
    [[ "$(cat "$ZTVPN_PROC_DIR/sys/net/ipv6/conf/all/forwarding" 2>/dev/null || echo 0)" == 1 ]] && fwd6=1

    if ! command -v nft >/dev/null 2>&1; then
        local id
        for id in FW-TABLE FW-POLICY FW-SETS FW-IPV6; do record "$id" skip critical "Firewall check" "nft not installed"; done
        return 0
    fi
    if ! ruleset="$(nft -j list table inet "$NFT_TABLE" 2>/dev/null)" || ! jq -e '.nftables' >/dev/null 2>&1 <<<"$ruleset"; then
        record FW-TABLE fail critical "nftables table inet $NFT_TABLE is loaded" "table inet $NFT_TABLE not found"
        record FW-POLICY skip critical "Input and forward base chains default to drop" "no table"
        record FW-SETS skip medium "Blocklist and quarantine sets exist" "no table"
        if ((fwd6)); then
            record FW-IPV6 fail high "IPv6 forwarding is covered by the firewall" "IPv6 forwarding is enabled and no inet $NFT_TABLE table filters it"
        else
            record FW-IPV6 pass high "IPv6 forwarding is covered by the firewall"
        fi
        return 0
    fi
    record FW-TABLE pass critical "nftables table inet $NFT_TABLE is loaded"

    local -a items=()
    local pol
    pol="$(jq -r '[.nftables[] | select(.chain) | .chain | select(.hook == "input")] | if length == 0 then "missing" else (map(.policy // "accept") | if all(. == "drop") then "drop" else "policy is not drop" end) end' <<<"$ruleset")"
    [[ "$pol" == drop ]] || items+=("input hook: $pol")
    pol="$(jq -r --arg ifn "$WG_INTERFACE" "$FORWARD_JQ" <<<"$ruleset")"
    [[ "$pol" == ok ]] || items+=("forward hook: $pol")
    result FW-POLICY critical "Input and forward base chains default to drop" "${items[@]}"

    items=()
    local set want_timeout
    for set in blocklist4:1 blocklist6:1 quarantine4:0; do
        want_timeout="${set#*:}" set="${set%:*}"
        if ! jq -e --arg s "$set" '.nftables[] | select(.set) | .set | select(.name == $s)' >/dev/null <<<"$ruleset"; then
            items+=("set $set missing")
        elif ((want_timeout)) && ! jq -e --arg s "$set" '[.nftables[] | select(.set) | .set | select(.name == $s) | .flags // [] | if type == "array" then .[] else . end] | any(. == "timeout")' >/dev/null <<<"$ruleset"; then
            items+=("set $set lacks the timeout flag (blocks would never expire)")
        fi
    done
    result FW-SETS medium "Blocklist and quarantine sets exist" "${items[@]}"

    items=()
    if ((fwd6)); then
        pol="$(jq -r --arg ifn "$WG_INTERFACE" "$FORWARD_JQ" <<<"$ruleset")"
        [[ "$pol" == ok ]] || items+=("IPv6 forwarding is enabled and inet $NFT_TABLE does not default-drop forwarded $WG_INTERFACE traffic ($pol)")
    fi
    result FW-IPV6 high "IPv6 forwarding is covered by the firewall" "${items[@]}"
}

# --------------------------------------------------------------------------
# Docker published ports
# --------------------------------------------------------------------------

audit_docker() {
    local out
    if ! command -v docker >/dev/null 2>&1 || ! out="$(docker ps --format '{{.Names}}\t{{.Ports}}' 2>/dev/null)"; then
        record NET-DOCKER-PORTS skip high "Containers publish only 80/443/WireGuard on all interfaces" "docker not available"
        return 0
    fi
    local -a items=()
    local name ports p host addr port
    while IFS=$'\t' read -r name ports; do
        [[ -n "$ports" ]] || continue
        local -a maps
        IFS=',' read -ra maps <<<"$ports"
        for p in "${maps[@]}"; do
            p="${p# }"
            [[ "$p" == *"->"* ]] || continue
            host="${p%%->*}"
            addr="${host%:*}" port="${host##*:}"
            case "$addr" in
                0.0.0.0 | "[::]" | :: | "") ;;
                *) continue ;;
            esac
            if [[ "$port" =~ ^[0-9]+$ ]] && ip_port_allowed "$port"; then
                continue
            fi
            items+=("$name publishes ${addr:-*}:$port (${p##*->})")
        done
    done <<<"$out"
    local -a uniq=()
    if ((${#items[@]})); then mapfile -t uniq < <(printf '%s\n' "${items[@]}" | LC_ALL=C sort -u); fi
    result NET-DOCKER-PORTS high "Containers publish only 80/443/WireGuard on all interfaces" "${uniq[@]}"
}

ip_port_allowed() {
    local a
    while IFS= read -r a; do
        [[ "$a" == "$1" ]] && return 0
    done < <(split_csv "$AUDIT_PUBLIC_PORTS")
    return 1
}

# --------------------------------------------------------------------------
# Authelia
# --------------------------------------------------------------------------

audit_authelia() {
    local cfg
    if [[ ! -f "$AUTHELIA_CONFIG" ]] || ! command -v yq >/dev/null 2>&1 || ! cfg="$(yq -o=json '.' "$AUTHELIA_CONFIG" 2>/dev/null)"; then
        local id
        for id in AUTH-DEFAULT-DENY AUTH-BYPASS AUTH-INLINE-SECRETS; do
            record "$id" skip high "Authelia configuration check" "$AUTHELIA_CONFIG not found or not parseable"
        done
    else
        local pol
        pol="$(jq -r '.access_control.default_policy // "unset"' <<<"$cfg")"
        if [[ "$pol" == deny ]]; then
            record AUTH-DEFAULT-DENY pass high "Authelia access_control.default_policy is deny"
        else
            record AUTH-DEFAULT-DENY fail high "Authelia access_control.default_policy is deny" "default_policy is $pol"
        fi

        local -a items=()
        mapfile -t items < <(jq -r '
            (.access_control.rules // []) | to_entries[]
            | select(.value.policy == "bypass")
            | select(((.value.networks // []) | length) > 0 or ([.value.domain] | flatten | any(. == "*")))
            | "rule #\(.key) bypasses authentication for \([.value.domain] | flatten | join(",")) from networks \((.value.networks // []) | join(","))"' <<<"$cfg")
        result AUTH-BYPASS high "No bypass rules based on network location or for all domains" "${items[@]}"

        items=()
        mapfile -t items < <(jq -r '
            [["jwt_secret"], ["identity_validation","reset_password","jwt_secret"], ["session","secret"],
             ["storage","encryption_key"], ["storage","postgres","password"], ["session","redis","password"],
             ["authentication_backend","ldap","password"], ["notifier","smtp","password"]][] as $p
            | select((getpath($p) // "") | type == "string" and length > 0)
            | ($p | join(".")) + " is set inline; use a secret file (AUTHELIA_*_FILE)"' <<<"$cfg")
        result AUTH-INLINE-SECRETS medium "Authelia secrets are not stored inline in configuration.yml" "${items[@]}"
    fi

    # Identity checks against the users database and the WireGuard peers.
    if [[ "$AUTHELIA_BACKEND" != file ]]; then
        record ID-ORPHAN-PEERS skip high "Every VPN peer belongs to an enabled account" "AUTHELIA_BACKEND=$AUTHELIA_BACKEND; run automation/user-sync.sh"
        record ID-IDLE-ACCOUNTS skip low "Enabled accounts have a VPN device" "AUTHELIA_BACKEND=$AUTHELIA_BACKEND"
        record ID-UNKNOWN-GROUPS skip low "Users only have known groups" "AUTHELIA_BACKEND=$AUTHELIA_BACKEND"
        return 0
    fi
    local users
    if [[ ! -f "$AUTHELIA_USERS_DB" ]] || ! command -v yq >/dev/null 2>&1 || ! users="$(yq -o=json '.users // {}' "$AUTHELIA_USERS_DB" 2>/dev/null)"; then
        record ID-ORPHAN-PEERS skip high "Every VPN peer belongs to an enabled account" "$AUTHELIA_USERS_DB not found or not parseable"
        record ID-IDLE-ACCOUNTS skip low "Enabled accounts have a VPN device" "$AUTHELIA_USERS_DB not found"
        record ID-UNKNOWN-GROUPS skip low "Users only have known groups" "$AUTHELIA_USERS_DB not found"
        return 0
    fi
    local -A owners=()
    local -a orphans=() idle=() badgroups=()
    local n _ip _k u state
    while read -r n _ip _k; do
        [[ -n "$n" ]] || continue
        u="${n%%--*}"
        owners["$u"]=1
        state="$(jq -r --arg u "$u" 'if has($u) then (if .[$u].disabled == true then "disabled" else "enabled" end) else "missing" end' <<<"$users")"
        [[ "$state" == enabled ]] || orphans+=("peer $n: account $u is $state")
    done < <(wg_list_peers)
    result ID-ORPHAN-PEERS high "Every VPN peer belongs to an enabled account" "${orphans[@]}"

    while IFS= read -r u; do
        [[ -n "$u" && -z "${owners[$u]:-}" ]] && idle+=("$u is enabled but has no VPN peer")
    done < <(jq -r 'to_entries[] | select(.value.disabled != true) | .key' <<<"$users")
    result ID-IDLE-ACCOUNTS low "Enabled accounts have a VPN device" "${idle[@]}"

    local known_json
    known_json="$(split_csv "$KNOWN_GROUPS" | jq -R . | jq -sc .)"
    mapfile -t badgroups < <(jq -r --argjson known "$known_json" '
        to_entries[] | .key as $u | (.value.groups // [])[] | select(. as $g | $known | any(. == $g) | not)
        | "\($u) has unknown group \(.)"' <<<"$users")
    result ID-UNKNOWN-GROUPS low "Users only have known groups" "${badgroups[@]}"
}

# --------------------------------------------------------------------------

main() {
    local json=0 fail_on=high verbose=0
    while (($#)); do
        case "$1" in
            --json) json=1; shift ;;
            --fail-on) fail_on="${2:-}"; shift 2 || fatal "--fail-on needs a value" ;;
            --verbose) verbose=1; shift ;;
            -h | --help) usage; exit 0 ;;
            *) usage >&2; fatal "Unknown option: $1" ;;
        esac
    done
    local threshold
    threshold="$(sev_rank "$fail_on")" || fatal "Invalid --fail-on: $fail_on"
    [[ "$NFT_TABLE" =~ ^[a-z][a-z0-9_]*$ ]] || fatal "Invalid NFT_TABLE"
    require_cmd jq openssl

    local work
    work="$(mktemp -d)"
    # shellcheck disable=SC2064
    trap "rm -rf '$work'" EXIT
    RESULTS="$work/results.ndjson"
    : >"$RESULTS"

    audit_files
    audit_pki
    audit_wireguard
    audit_firewall
    audit_docker
    audit_authelia

    local report
    report="$(jq -s --arg at "$(date -u +%FT%TZ)" --arg host "${HOSTNAME:-$(uname -n)}" --arg fail_on "$fail_on" '
        {generated: $at, host: $host, fail_on: $fail_on,
         summary: {checks: length,
                   passed: map(select(.status == "pass")) | length,
                   failed: map(select(.status == "fail")) | length,
                   skipped: map(select(.status == "skip")) | length,
                   by_severity: (reduce (.[] | select(.status == "fail")) as $r
                        ({critical: 0, high: 0, medium: 0, low: 0, info: 0}; .[$r.severity] += 1))},
         checks: .}' "$RESULTS")"

    if ((json)); then
        printf '%s\n' "$report"
    else
        jq -r --argjson verbose "$verbose" '
            (.checks[] | select(.status != "pass" or $verbose == 1)
             | "\(if .status == "fail" then "[" + (.severity | ascii_upcase) + "]" elif .status == "skip" then "[SKIP]" else "[PASS]" end) \(.id): \(.title)"
               + (if (.items | length) > 0 then "\n" + (.items | map("    - " + .) | join("\n")) else "" end)),
            "",
            "Checks: \(.summary.checks)  passed: \(.summary.passed)  failed: \(.summary.failed)  skipped: \(.summary.skipped)",
            "Findings by severity: critical \(.summary.by_severity.critical), high \(.summary.by_severity.high), medium \(.summary.by_severity.medium), low \(.summary.by_severity.low), info \(.summary.by_severity.info)"' <<<"$report"
    fi

    local worst
    worst="$(jq -r '[.checks[] | select(.status == "fail") | {"info":0,"low":1,"medium":2,"high":3,"critical":4}[.severity]] | max // -1' <<<"$report")"
    if ((worst >= threshold)); then
        exit 1
    fi
    exit 0
}

main "$@"
