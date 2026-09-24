#!/usr/bin/env bash
# Reports WireGuard peer state and failed Authelia logins, raises alerts.
#
# Data comes from "wg show <if> dump" (raw byte counters and epoch
# handshakes, no unit parsing) and from Authelia's log within a time
# window. Alerts go to $ZTVPN_LOG_DIR/alerts.log. With --respond, source
# IPs with too many failed logins are handed to threat-response.sh.

set -Eeuo pipefail
# shellcheck source=scripts/lib/common.sh
source "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/../lib/common.sh"

ALERT_LOG="${ALERT_LOG:-$ZTVPN_LOG_DIR/alerts.log}"
MONITOR_STATE="${MONITOR_STATE:-$ZTVPN_STATE_DIR/monitor/wg-sample.json}"
# Authelia logs: a file, an explicit container, or the compose service.
AUTHELIA_LOG_FILE="${AUTHELIA_LOG_FILE:-}"
# A handshake younger than this means the peer is connected.
MONITOR_ACTIVE_SECS="${MONITOR_ACTIVE_SECS:-180}"
# Average bytes/second per direction between two samples that counts as a spike.
MONITOR_SPIKE_BPS="${MONITOR_SPIKE_BPS:-12500000}"
# Failed logins from one source IP within the window that raise an alert.
MONITOR_AUTH_FAIL_THRESHOLD="${MONITOR_AUTH_FAIL_THRESHOLD:-10}"
MONITOR_BLOCK_DURATION="${MONITOR_BLOCK_DURATION:-1h}"
THREAT_RESPONSE="${THREAT_RESPONSE:-$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/../automation/threat-response.sh}"

usage() {
    cat <<EOF
Usage: $(basename "$0") [--once | --watch SECONDS] [--window 10m] [--json] [--respond]

  --once          One sample (default). Exit 0 = no alerts, 1 = alerts, 2 = error.
  --watch N       Sample every N seconds until interrupted (window defaults to N seconds).
  --window W      Look-back for failed Authelia logins, e.g. 300s, 10m, 1h (default 10m).
  --json          Print the report as JSON.
  --respond       Pass source IPs with >= $MONITOR_AUTH_FAIL_THRESHOLD failed logins to
                  threat-response.sh --type brute-force (blocked for $MONITOR_BLOCK_DURATION).
  -h, --help      Show this help

Reported: peers (name from $WG_CONF), handshake age, transfer, peers on $WG_INTERFACE that are
not in $WG_CONF (alert), managed peers missing from the interface, transfer spikes against
the previous sample ($MONITOR_STATE), failed 1FA/2FA logins from
AUTHELIA_LOG_FILE, container AUTHELIA_CONTAINER, or compose service $AUTHELIA_SERVICE.
EOF
}

fatal() { error "$*"; exit 2; }

window_seconds() {
    [[ "$1" =~ ^([1-9][0-9]{0,6})([smh])$ ]] || return 1
    case "${BASH_REMATCH[2]}" in
        s) echo "${BASH_REMATCH[1]}" ;;
        m) echo $((BASH_REMATCH[1] * 60)) ;;
        h) echo $((BASH_REMATCH[1] * 3600)) ;;
    esac
}

human() {
    numfmt --to=iec-i --suffix=B "$1" 2>/dev/null || printf '%sB' "$1"
}

ALERTS=()
alert() {
    local sev="$1" src="$2" msg="$3"
    ALERTS+=("$sev"$'\t'"$src"$'\t'"$msg")
    mkdir -p "$(dirname "$ALERT_LOG")"
    printf '%s %s connection-monitor/%s %s\n' "$(date -Iseconds)" "${sev^^}" "$src" "$msg" >>"$ALERT_LOG"
    warn "ALERT [$sev] $msg"
}

# --------------------------------------------------------------------------
# WireGuard
# --------------------------------------------------------------------------

PEERS_NDJSON=""

collect_wireguard() {
    local dump now
    dump="$(wg show "$WG_INTERFACE" dump 2>&1)" || fatal "wg show $WG_INTERFACE dump failed: $dump"
    now="$(date +%s)"

    local -A name_of=() managed_ip=() seen=()
    local n ip k
    while read -r n ip k; do
        [[ -n "$k" ]] || continue
        name_of["$k"]="$n"
        managed_ip["$k"]="$ip"
    done < <(wg_list_peers)

    local -A prev_rx=() prev_tx=()
    local prev_ts=0
    if [[ -f "$MONITOR_STATE" ]] && jq -e . "$MONITOR_STATE" >/dev/null 2>&1; then
        prev_ts="$(jq -r '.ts // 0' "$MONITOR_STATE")"
        while IFS=$'\t' read -r k n ip; do
            prev_rx["$k"]="$n"
            prev_tx["$k"]="$ip"
        done < <(jq -r '.peers // {} | to_entries[] | [.key, (.value.rx|tostring), (.value.tx|tostring)] | @tsv' "$MONITOR_STATE")
    fi
    [[ "$prev_ts" =~ ^[0-9]+$ ]] || prev_ts=0
    local dt=$((now - prev_ts))

    local line pub _psk endpoint allowed hs rx tx _ka name age status rrate trate first=1
    : >"$PEERS_NDJSON"
    local -a sample=()
    while IFS=$'\t' read -r pub _psk endpoint allowed hs rx tx _ka; do
        if ((first)); then
            first=0 # interface line: private key, public key, port, fwmark
            continue
        fi
        [[ -n "$pub" ]] || continue
        if [[ ! "$hs" =~ ^[0-9]+$ || ! "$rx" =~ ^[0-9]+$ || ! "$tx" =~ ^[0-9]+$ ]]; then
            warn "Skipping malformed dump line for peer ${pub:0:8}..."
            continue
        fi
        seen["$pub"]=1
        name="${name_of[$pub]:-}"
        if ((hs == 0)); then
            age=-1 status=never
        else
            age=$((now - hs))
            if ((age <= MONITOR_ACTIVE_SECS)); then status=active; else status=stale; fi
        fi
        if [[ -z "$name" ]]; then
            alert high unknown-peer "Peer ${pub} (allowed-ips $allowed, endpoint $endpoint) is on $WG_INTERFACE but not in $WG_CONF"
        fi

        rrate=null trate=null
        local prx="${prev_rx[$pub]:-}" ptx="${prev_tx[$pub]:-}"
        if ((prev_ts > 0 && dt > 0)) && [[ "$prx" =~ ^[0-9]+$ && "$ptx" =~ ^[0-9]+$ ]]; then
            local drx=$((rx - prx)) dtx=$((tx - ptx))
            ((drx < 0)) && drx=$rx
            ((dtx < 0)) && dtx=$tx
            rrate=$((drx / dt)) trate=$((dtx / dt))
            if ((rrate > MONITOR_SPIKE_BPS || trate > MONITOR_SPIKE_BPS)); then
                alert medium traffic-spike "Peer ${name:-$pub}: rx $(human "$rrate")/s tx $(human "$trate")/s over ${dt}s (threshold $(human "$MONITOR_SPIKE_BPS")/s)"
            fi
        fi
        sample+=("$pub"$'\t'"$rx"$'\t'"$tx")
        jq -nc --arg name "$name" --arg pub "$pub" --arg ip "${managed_ip[$pub]:-${allowed%%/*}}" \
            --arg endpoint "$endpoint" --arg allowed "$allowed" --arg status "$status" \
            --argjson hs "$hs" --argjson age "$age" --argjson rx "$rx" --argjson tx "$tx" \
            --argjson rrate "$rrate" --argjson trate "$trate" \
            '{name: (if $name == "" then null else $name end), public_key: $pub, ip: $ip, endpoint: $endpoint,
              allowed_ips: $allowed, managed: ($name != ""), status: $status, latest_handshake: $hs,
              handshake_age: (if $age < 0 then null else $age end), rx_bytes: $rx, tx_bytes: $tx,
              rx_rate: $rrate, tx_rate: $trate}' >>"$PEERS_NDJSON"
    done <<<"$dump"

    for k in "${!name_of[@]}"; do
        [[ -n "${seen[$k]:-}" ]] && continue
        MISSING_PEERS+=("${name_of[$k]}")
    done
    if ((${#MISSING_PEERS[@]})); then
        warn "Managed peers not loaded on $WG_INTERFACE: ${MISSING_PEERS[*]} (run wg syncconf)"
    fi

    mkdir -p "$(dirname "$MONITOR_STATE")"
    {
        if ((${#sample[@]})); then printf '%s\n' "${sample[@]}"; fi
    } | jq -R 'split("\t") | {key: .[0], value: {rx: (.[1] | tonumber), tx: (.[2] | tonumber)}}' |
        jq -s --argjson ts "$now" '{ts: $ts, peers: from_entries}' | atomic_write "$MONITOR_STATE" 600
}

# --------------------------------------------------------------------------
# Authelia
# --------------------------------------------------------------------------

AUTH_JSON=null
AUTH_FAIL_RE='Unsuccessful (1FA|2FA|TOTP|WebAuthn|Duo) authentication attempt'

# Prints Authelia failure log lines from the window; returns 1 if no source.
auth_failure_lines() {
    local window="$1" secs="$2"
    if [[ -n "$AUTHELIA_LOG_FILE" ]]; then
        [[ -r "$AUTHELIA_LOG_FILE" ]] || { warn "Cannot read $AUTHELIA_LOG_FILE"; return 1; }
        local cutoff line ts epoch
        cutoff=$(($(date +%s) - secs))
        grep -E "$AUTH_FAIL_RE" "$AUTHELIA_LOG_FILE" | while IFS= read -r line; do
            if [[ "$line" =~ time[\"]?[=:][\"]?([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+(Z|[+-][0-9:]+)?) ]]; then
                ts="${BASH_REMATCH[1]}"
                epoch="$(date -d "$ts" +%s 2>/dev/null)" || continue
                ((epoch >= cutoff)) && printf '%s\n' "$line"
            fi
        done
        return 0
    fi
    command -v docker >/dev/null 2>&1 || { warn "docker not available, cannot read Authelia logs"; return 1; }
    local out
    local -a cmd
    if [[ -n "$AUTHELIA_CONTAINER" ]]; then
        cmd=(docker logs --since "$window" "$AUTHELIA_CONTAINER")
    elif [[ -f "$COMPOSE_FILE_PATH" ]]; then
        cmd=(docker compose -f "$COMPOSE_FILE_PATH" --project-directory "$(dirname "$COMPOSE_FILE_PATH")"
            logs --no-color --no-log-prefix --since "$window" "$AUTHELIA_SERVICE")
    else
        warn "No AUTHELIA_LOG_FILE, AUTHELIA_CONTAINER or $COMPOSE_FILE_PATH; cannot read Authelia logs"
        return 1
    fi
    out="$("${cmd[@]}" 2>&1)" || {
        warn "${cmd[*]} failed: ${out:0:200}"
        return 1
    }
    grep -E "$AUTH_FAIL_RE" <<<"$out" || true
}

collect_auth() {
    local window="$1" secs="$2" lines f1 f2
    if ! lines="$(auth_failure_lines "$window" "$secs")"; then
        AUTH_JSON=null
        return 0
    fi
    f1="$(grep -c 'Unsuccessful 1FA authentication attempt' <<<"$lines" || true)"
    f2="$(grep -cE 'Unsuccessful (2FA|TOTP|WebAuthn|Duo) authentication attempt' <<<"$lines" || true)"
    local -A by_ip=()
    local line ipaddr count
    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        if [[ "$line" =~ remote_ip[\"]?[=:][\"]?([0-9A-Fa-f.:]+) ]]; then
            ipaddr="${BASH_REMATCH[1]}"
            count="${by_ip[$ipaddr]:-0}"
            by_ip["$ipaddr"]=$((count + 1))
        fi
    done <<<"$lines"

    local by_ip_json='{}' k
    if ((${#by_ip[@]})); then
        by_ip_json="$(for k in "${!by_ip[@]}"; do printf '%s\t%s\n' "$k" "${by_ip[$k]}"; done |
            jq -R 'split("\t") | {key: .[0], value: (.[1] | tonumber)}' | jq -sc from_entries)"
    fi
    AUTH_JSON="$(jq -nc --arg src "${AUTHELIA_LOG_FILE:-docker:${AUTHELIA_CONTAINER:-compose/$AUTHELIA_SERVICE}}" --arg window "$window" \
        --argjson f1 "$f1" --argjson f2 "$f2" --argjson by_ip "$by_ip_json" \
        '{source: $src, window: $window, failed_1fa: $f1, failed_2fa: $f2, by_ip: $by_ip}')"

    for k in "${!by_ip[@]}"; do
        count="${by_ip[$k]}"
        ((count >= MONITOR_AUTH_FAIL_THRESHOLD)) || continue
        alert high auth-failures "$count failed Authelia logins from $k within $window"
        if ((RESPOND)); then
            if validate_ipv4 "$k" || [[ "$k" == *:* ]]; then
                if "$THREAT_RESPONSE" --type brute-force --ip "$k" --duration "$MONITOR_BLOCK_DURATION" \
                    --reason "connection-monitor: $count failed logins" >/dev/null; then
                    info "Handed $k to threat-response (blocked for $MONITOR_BLOCK_DURATION)"
                else
                    error "threat-response did not block $k"
                fi
            fi
        fi
    done
}

# --------------------------------------------------------------------------

RESPOND=0
MISSING_PEERS=()

run_once() {
    local window="$1" json="$2" secs
    secs="$(window_seconds "$window")"
    ALERTS=()
    MISSING_PEERS=()
    AUTH_JSON=null
    collect_wireguard
    collect_auth "$window" "$secs"

    local alerts_json='[]' missing_json='[]'
    if ((${#ALERTS[@]})); then
        alerts_json="$(printf '%s\n' "${ALERTS[@]}" | jq -R 'split("\t") | {severity: .[0], source: .[1], message: .[2]}' | jq -sc .)"
    fi
    if ((${#MISSING_PEERS[@]})); then
        missing_json="$(printf '%s\n' "${MISSING_PEERS[@]}" | jq -R . | jq -sc .)"
    fi

    if ((json)); then
        jq -s --arg iface "$WG_INTERFACE" --arg at "$(date -u +%FT%TZ)" --argjson auth "$AUTH_JSON" \
            --argjson alerts "$alerts_json" --argjson missing "$missing_json" \
            '{generated: $at, interface: $iface, peers: ., unknown_peers: (map(select(.managed | not)) | length),
              managed_peers_not_loaded: $missing, auth: $auth, alerts: $alerts}' "$PEERS_NDJSON"
    else
        printf '%-28s %-15s %-10s %10s %12s %12s\n' PEER IP STATUS HANDSHAKE RX TX
        local name ip status age rx tx
        while IFS=$'\t' read -r name ip status age rx tx; do
            [[ "$age" == null ]] && age=never || age="${age}s"
            printf '%-28s %-15s %-10s %10s %12s %12s\n' "$name" "$ip" "$status" "$age" "$(human "$rx")" "$(human "$tx")"
        done < <(jq -r '[(.name // "UNKNOWN(\(.public_key[0:8]))"), .ip, .status, (.handshake_age // "null" | tostring), .rx_bytes, .tx_bytes] | @tsv' "$PEERS_NDJSON")
        if ((${#MISSING_PEERS[@]})); then
            printf 'Managed peers not loaded on %s: %s\n' "$WG_INTERFACE" "${MISSING_PEERS[*]}"
        fi
        if [[ "$AUTH_JSON" == null ]]; then
            printf 'Failed logins: unavailable (no Authelia log source)\n'
        else
            jq -r '"Failed logins in last \(.window): 1FA=\(.failed_1fa) 2FA=\(.failed_2fa)"' <<<"$AUTH_JSON"
        fi
        printf 'Alerts: %d\n' "${#ALERTS[@]}"
    fi
    ((${#ALERTS[@]} == 0))
}

main() {
    local watch=0 window="" json=0
    while (($#)); do
        case "$1" in
            --once) watch=0; shift ;;
            --watch) watch="${2:-}"; shift 2 || fatal "--watch needs a value" ;;
            --window) window="${2:-}"; shift 2 || fatal "--window needs a value" ;;
            --json) json=1; shift ;;
            --respond) RESPOND=1; shift ;;
            -h | --help) usage; exit 0 ;;
            *) usage >&2; fatal "Unknown option: $1" ;;
        esac
    done
    [[ "$watch" =~ ^[0-9]{1,5}$ ]] || fatal "Invalid --watch interval"
    if [[ -z "$window" ]]; then
        if ((watch > 0)); then window="${watch}s"; else window=10m; fi
    fi
    window_seconds "$window" >/dev/null || fatal "Invalid --window: $window"
    local v
    for v in MONITOR_ACTIVE_SECS MONITOR_SPIKE_BPS MONITOR_AUTH_FAIL_THRESHOLD; do
        [[ "${!v}" =~ ^[0-9]+$ ]] || fatal "Invalid $v"
    done
    [[ -z "$AUTHELIA_CONTAINER" || "$AUTHELIA_CONTAINER" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || fatal "Invalid AUTHELIA_CONTAINER"
    [[ "$AUTHELIA_SERVICE" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || fatal "Invalid AUTHELIA_SERVICE"
    require_cmd wg jq

    local work
    work="$(mktemp -d)"
    # shellcheck disable=SC2064
    trap "rm -rf '$work'" EXIT
    PEERS_NDJSON="$work/peers.ndjson"

    if ((watch == 0)); then
        run_once "$window" "$json" || exit 1
        exit 0
    fi
    while :; do
        run_once "$window" "$json" || true
        sleep "$watch"
    done
}

main "$@"
