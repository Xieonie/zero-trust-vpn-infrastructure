#!/usr/bin/env bash
# Automated containment actions for the zero-trust-vpn stack.
#
# Every action is independent: one failing does not skip the others, and
# the incident record says exactly what happened. Blocks are nftables set
# elements with a timeout, so they expire on their own. Addresses on the
# allowlist (admins, the VPN server, loopback, the SSH session running this
# script) are never blocked.

set -Eeuo pipefail
# shellcheck source=scripts/lib/common.sh
source "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/../lib/common.sh"

LOG_FILE="${LOG_FILE:-$ZTVPN_LOG_DIR/threat-response.log}"
INCIDENT_DIR="${INCIDENT_DIR:-$ZTVPN_STATE_DIR/incidents}"
NFT_TABLE="${NFT_TABLE:-ztvpn}"
# Also protect RFC1918 ranges from blocking (yes/no).
THREAT_PROTECT_PRIVATE="${THREAT_PROTECT_PRIVATE:-no}"
THREAT_MAX_BLOCK="${THREAT_MAX_BLOCK:-30d}"
SLACK_WEBHOOK="${SLACK_WEBHOOK:-}"
NOTIFICATION_EMAIL="${NOTIFICATION_EMAIL:-}"
NOTIFY_TIMEOUT="${NOTIFY_TIMEOUT:-10}"

usage() {
    cat <<EOF
Usage:
  $(basename "$0") [respond] --type TYPE [--ip IP] [--user USER] [--device DEVICE]
                   [--duration 1h] [--reason TEXT] [--notify] [--dry-run]
  $(basename "$0") unblock --ip IP
  $(basename "$0") release --device PEER | --ip TUNNEL_IP

Types and actions:
  brute-force          --ip required. Adds IP to the nftables blocklist with a timeout.
  suspicious-traffic   --ip required. External IP: blocklist with timeout. Tunnel IP of a
                       peer: add it to quarantine4 (traffic dropped, peer kept).
  compromised-device   --device (peer name "user--device", or device name with --user) or
                       --ip (tunnel IP). Adds the peer IP to quarantine4, removes the peer
                       from $WG_CONF and the running interface (config archived under
                       $QUARANTINE_DIR for 'release'), revokes a client cert named like the peer.
  compromised-user     --user required. Disables the Authelia account, quarantines and
                       removes all of the user's peers, revokes the user's client certs
                       (keyCompromise). --ip additionally blocks that source address.

Options:
  --duration D   Block lifetime, e.g. 30m, 1h, 7d (default 1h, max $THREAT_MAX_BLOCK)
  --reason TEXT  Free text stored in the incident record
  --notify       Send Slack (SLACK_WEBHOOK) and/or email (NOTIFICATION_EMAIL via sendmail)
  --dry-run      Validate and print the plan, change nothing
  -h, --help     Show this help

Never blocked: ADMIN_ALLOWLIST, VPN_SERVER_IP, loopback, this host's addresses, the IP of the
SSH session running the script, and RFC1918 ranges if THREAT_PROTECT_PRIVATE=yes.
Prints the incident id on stdout. Exit 0 if all actions succeeded, 1 otherwise.
EOF
}

# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------

validate_ipv6() {
    local ip="$1" g n=0 dbl=0
    [[ "$ip" == *:* && ${#ip} -le 39 && "$ip" =~ ^[0-9A-Fa-f:]+$ ]] || return 1
    [[ "$ip" == *:::* ]] && return 1
    if [[ "$ip" == *::* ]]; then
        dbl=1
        [[ "${ip#*::}" == *::* ]] && return 1
    fi
    local -a groups
    IFS=':' read -ra groups <<<"${ip//::/:}"
    for g in "${groups[@]}"; do
        [[ -z "$g" ]] && continue
        [[ "$g" =~ ^[0-9A-Fa-f]{1,4}$ ]] || return 1
        n=$((n + 1))
    done
    # Single leading/trailing colons are only allowed as part of "::".
    [[ "$ip" == :* && "$ip" != ::* ]] && return 1
    [[ "$ip" == *: && "$ip" != *:: ]] && return 1
    if ((dbl)); then ((n <= 7)); else ((n == 8)); fi
}

duration_seconds() {
    local d="$1" n unit
    [[ "$d" =~ ^([1-9][0-9]{0,5})([smhd])$ ]] || return 1
    n="${BASH_REMATCH[1]}" unit="${BASH_REMATCH[2]}"
    case "$unit" in
        s) echo "$n" ;;
        m) echo $((n * 60)) ;;
        h) echo $((n * 3600)) ;;
        d) echo $((n * 86400)) ;;
    esac
}

caller_ips() {
    local f
    for f in "${SSH_CONNECTION:-}" "${SSH_CLIENT:-}"; do
        [[ -n "$f" ]] && printf '%s\n' "${f%% *}"
    done
    return 0
}

local_ips() {
    command -v ip >/dev/null 2>&1 || return 0
    ip -o addr show 2>/dev/null | awk '{ sub(/\/.*/, "", $4); print $4 }'
}

# Prints the reason an IP is protected, returns 1 if it may be blocked.
protected_reason() {
    local ip="$1" c
    if validate_ipv4 "$ip"; then
        ip_in_cidr "$ip" 127.0.0.0/8 && { echo loopback; return 0; }
        ip_in_cidr "$ip" 0.0.0.0/8 && { echo "unspecified address"; return 0; }
        [[ "$ip" == 255.255.255.255 ]] && { echo broadcast; return 0; }
        [[ "$ip" == "$VPN_SERVER_IP" ]] && { echo VPN_SERVER_IP; return 0; }
        [[ -n "$ADMIN_ALLOWLIST" ]] && ip_in_list "$ip" "$ADMIN_ALLOWLIST" && { echo ADMIN_ALLOWLIST; return 0; }
        if [[ "$THREAT_PROTECT_PRIVATE" == yes ]] && ip_in_list "$ip" "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"; then
            echo "RFC1918 (THREAT_PROTECT_PRIVATE=yes)"
            return 0
        fi
    else
        local lc="${ip,,}"
        [[ "$lc" == ::1 || "$lc" == :: ]] && { echo loopback; return 0; }
        local e
        while IFS= read -r e; do
            [[ "${e,,}" == "$lc" ]] && { echo ADMIN_ALLOWLIST; return 0; }
        done < <(split_csv "$ADMIN_ALLOWLIST")
    fi
    while IFS= read -r c; do
        [[ -n "$c" && "${c,,}" == "${ip,,}" ]] && { echo "caller's SSH session"; return 0; }
    done < <(caller_ips)
    while IFS= read -r c; do
        [[ -n "$c" && "${c,,}" == "${ip,,}" ]] && { echo "address of this host"; return 0; }
    done < <(local_ips)
    return 1
}

# --------------------------------------------------------------------------
# Incident record
# --------------------------------------------------------------------------

INCIDENT_ID=""
ACTIONS_FILE=""
FAILED=0

# record_action <action> <target> <status> <detail>
record_action() {
    jq -nc --arg a "$1" --arg t "$2" --arg s "$3" --arg d "$4" --arg at "$(date -u +%FT%TZ)" \
        '{action: $a, target: $t, status: $s, detail: $d, at: $at}' >>"$ACTIONS_FILE"
    case "$3" in
        ok) success "$1 $2: $4" ;;
        planned) info "[dry-run] $1 $2: $4" ;;
        failed) error "$1 $2 FAILED: $4"; FAILED=1 ;;
        *) warn "$1 $2 ($3): $4" ;;
    esac
}

# run_action <action> <target> <function> [args...]
# The function must report its own errors via "|| return 1"; errexit is
# not in effect inside an if condition, so it cannot be relied on there.
run_action() {
    local action="$1" target="$2" fn="$3"
    shift 3
    local out rc=0
    if ((DRY_RUN)); then
        record_action "$action" "$target" planned "$("${fn}_plan" "$@")"
        return 0
    fi
    out="$("$fn" "$@" 2>"$ACTIONS_FILE.err")" || rc=$?
    local err
    err="$(tail -n 3 "$ACTIONS_FILE.err" | tr '\n' ' ')"
    cat "$ACTIONS_FILE.err" >&2
    if ((rc == 0)); then
        record_action "$action" "$target" ok "${out:-done}"
    else
        record_action "$action" "$target" failed "${out:+$out; }${err:-exit $rc}"
    fi
}

# --------------------------------------------------------------------------
# Actions (each returns non-zero on failure, prints a one-line summary)
# --------------------------------------------------------------------------

nft_set_for() {
    if validate_ipv4 "$1"; then echo blocklist4; else echo blocklist6; fi
}

block_ip_plan() { echo "nft add element inet $NFT_TABLE $(nft_set_for "$1") { $1 timeout $2 }"; }
block_ip() {
    local ip="$1" dur="$2" set
    set="$(nft_set_for "$ip")"
    nft add element inet "$NFT_TABLE" "$set" "{ $ip timeout $dur }" || return 1
    # Established flows are accepted before the blocklist; drop them too.
    if command -v conntrack >/dev/null 2>&1; then
        conntrack -D -s "$ip" >/dev/null 2>&1 || true
    fi
    echo "added to $set, expires after $dur"
}

unblock_ip() {
    local ip="$1" set
    set="$(nft_set_for "$ip")"
    nft delete element inet "$NFT_TABLE" "$set" "{ $ip }" || return 1
    echo "removed from $set"
}

quarantine_ip_plan() { echo "nft add element inet $NFT_TABLE quarantine4 { $1 }"; }
quarantine_ip() {
    nft add element inet "$NFT_TABLE" quarantine4 "{ $1 }" || return 1
    echo "added to quarantine4"
}

# Saves the peer's block from WG_CONF plus metadata, then removes the peer
# from the config and the running interface (client dir archived as well).
remove_peer_plan() { echo "archive peer $1 to $QUARANTINE_DIR/$1 and remove it from $WG_CONF and $WG_INTERFACE"; }
remove_peer() {
    local peer="$1" qdir="$QUARANTINE_DIR/$1" n ip key
    wg_peer_exists "$peer" || { echo "peer $peer not in $WG_CONF"; return 1; }
    while read -r n ip key; do
        [[ "$n" == "$peer" ]] && break
    done < <(wg_list_peers)
    [[ "$n" == "$peer" ]] || return 1
    (umask 077; mkdir -p "$qdir") || return 1
    awk -v b="# BEGIN PEER $peer" -v e="# END PEER $peer" '
        $0 == b { on = 1 } on { print } on && $0 == e { exit }
    ' "$WG_CONF" | atomic_write "$qdir/peer.conf" 600 || return 1
    jq -n --arg peer "$peer" --arg ip "$ip" --arg key "$key" --arg inc "$INCIDENT_ID" \
        --arg at "$(date -u +%FT%TZ)" '{peer: $peer, ip: $ip, public_key: $key, incident: $inc, quarantined_at: $at}' |
        atomic_write "$qdir/meta.json" 600 || return 1
    rm -rf "${qdir:?}/client"
    wg_deprovision_peer "$peer" "$qdir/archive" || return 1
    if [[ -d "$qdir/archive/$peer" ]]; then
        mv "$qdir/archive/$peer" "$qdir/client" && rmdir "$qdir/archive"
    fi
    echo "removed from $WG_CONF (and from $WG_INTERFACE if it is up); archived in $qdir"
}

revoke_cert_plan() { echo "revoke client certificates with CN=$1 (keyCompromise)"; }
revoke_cert() {
    local rc=0
    pki_ca_exists || { echo "no CA configured, nothing to revoke"; return 0; }
    pki_revoke "$1" keyCompromise >/dev/null || rc=$?
    case "$rc" in
        0) echo "revoked, CRL regenerated" ;;
        2) echo "no valid certificate with CN=$1" ;;
        *) return 1 ;;
    esac
}

disable_user_plan() { echo "set disabled=true for $1 in $AUTHELIA_USERS_DB"; }
disable_user() {
    if [[ "$AUTHELIA_BACKEND" != file ]]; then
        echo "AUTHELIA_BACKEND=$AUTHELIA_BACKEND: disable the account in the directory manually"
        return 1
    fi
    authelia_set_disabled "$1" true || return 1
    echo "disabled in $AUTHELIA_USERS_DB (takes effect at Authelia's next user refresh; existing sessions are not terminated)"
}

# --------------------------------------------------------------------------
# Notifications
# --------------------------------------------------------------------------

NOTIFY_RESULTS=()

notify() {
    local subject="$1" body="$2"
    if [[ -z "$SLACK_WEBHOOK" && -z "$NOTIFICATION_EMAIL" ]]; then
        warn "--notify given but neither SLACK_WEBHOOK nor NOTIFICATION_EMAIL is configured"
        NOTIFY_RESULTS+=("none:not configured")
        FAILED=1
        return 0
    fi
    if [[ -n "$SLACK_WEBHOOK" ]]; then
        if [[ ! "$SLACK_WEBHOOK" =~ ^https://[A-Za-z0-9./_-]+$ ]]; then
            error "SLACK_WEBHOOK is not a plain https URL; not sending"
            NOTIFY_RESULTS+=("slack:failed invalid url")
            FAILED=1
        elif jq -nc --arg text "$subject"$'\n'"$body" '{text: $text}' |
            curl -fsS --max-time "$NOTIFY_TIMEOUT" -H 'Content-Type: application/json' \
                --data-binary @- -K <(printf 'url = "%s"\n' "$SLACK_WEBHOOK") >/dev/null; then
            NOTIFY_RESULTS+=("slack:sent")
        else
            error "Slack notification failed"
            NOTIFY_RESULTS+=("slack:failed")
            FAILED=1
        fi
    fi
    if [[ -n "$NOTIFICATION_EMAIL" ]]; then
        if ! validate_email "$NOTIFICATION_EMAIL"; then
            error "NOTIFICATION_EMAIL is invalid; not sending"
            NOTIFY_RESULTS+=("email:failed invalid address")
            FAILED=1
        elif ! command -v sendmail >/dev/null 2>&1; then
            error "sendmail not found; email notification not sent"
            NOTIFY_RESULTS+=("email:failed no sendmail")
            FAILED=1
        elif printf 'To: %s\nSubject: %s\nContent-Type: text/plain; charset=utf-8\n\n%s\n' \
            "$NOTIFICATION_EMAIL" "$subject" "$body" | timeout "$NOTIFY_TIMEOUT" sendmail -oi -- "$NOTIFICATION_EMAIL"; then
            NOTIFY_RESULTS+=("email:sent")
        else
            error "Email notification failed"
            NOTIFY_RESULTS+=("email:failed")
            FAILED=1
        fi
    fi
}

# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

DRY_RUN=0
NOTIFY=0

# Resolves --device/--user/--ip to a managed peer name.
resolve_peer() {
    local user="$1" device="$2" ip="$3" peer=""
    if [[ -n "$device" ]]; then
        if [[ -n "$user" && "$device" != *--* ]]; then
            peer="$user--$device"
        else
            peer="$device"
        fi
        validate_peer_name "$peer" || die "Invalid device/peer name: $peer"
    elif [[ -n "$ip" ]]; then
        peer="$(wg_peer_by_ip "$ip")" || die "No managed peer has tunnel IP $ip"
    fi
    [[ -n "$peer" ]] || die "compromised-device needs --device or --ip"
    wg_peer_exists "$peer" || die "Peer $peer does not exist in $WG_CONF"
    printf '%s\n' "$peer"
}

check_blockable() {
    local ip="$1" why
    if why="$(protected_reason "$ip")"; then
        die "Refusing to block $ip: protected ($why)"
    fi
}

cmd_unblock() {
    local ip="$1"
    [[ -n "$ip" ]] || die "unblock needs --ip"
    validate_ipv4 "$ip" || validate_ipv6 "$ip" || die "Invalid IP: $ip"
    require_cmd nft
    unblock_ip "$ip" >/dev/null || die "Could not remove $ip (not blocked or table missing)"
    success "Unblocked $ip"
}

cmd_release() {
    local peer="$1" ip="$2"
    require_cmd nft
    if [[ -z "$peer" && -n "$ip" ]]; then
        validate_ipv4 "$ip" || die "Invalid IP: $ip"
        local m
        for m in "$QUARANTINE_DIR"/*/meta.json; do
            [[ -f "$m" ]] || continue
            [[ "$(jq -r .ip "$m")" == "$ip" ]] && peer="$(jq -r .peer "$m")"
        done
        if [[ -z "$peer" ]]; then
            # Quarantined only (suspicious-traffic), peer was kept.
            nft delete element inet "$NFT_TABLE" quarantine4 "{ $ip }" || die "Could not remove $ip from quarantine4"
            success "Released $ip from quarantine4"
            return 0
        fi
    fi
    validate_peer_name "$peer" || die "Invalid peer name: $peer"
    local qdir="$QUARANTINE_DIR/$peer"
    [[ -f "$qdir/meta.json" && -f "$qdir/peer.conf" ]] || die "No quarantine record for $peer in $QUARANTINE_DIR"

    ztvpn_lock wg
    local pip pkey psk=""
    pip="$(jq -r .ip "$qdir/meta.json")"
    pkey="$(jq -r .public_key "$qdir/meta.json")"
    validate_ipv4 "$pip" || die "Corrupt quarantine record for $peer"
    wg_peer_exists "$peer" && die "Peer $peer already exists in $WG_CONF"
    local pskfile
    pskfile="$(mktemp)"
    # shellcheck disable=SC2064
    trap "rm -f '$pskfile'" EXIT
    awk -F' = ' '$1 == "PresharedKey" { print $2 }' "$qdir/peer.conf" >"$pskfile"
    [[ -s "$pskfile" ]] && psk="$pskfile"
    # The active quarantine record reserves the IP; retire it first so the
    # peer can take its own address back, and reinstate it on failure.
    local released
    released="$qdir.released-$(date -u +%Y%m%dT%H%M%SZ)"
    mv "$qdir" "$released"
    if ! wg_add_peer "$peer" "$pkey" "$pip" "$psk"; then
        mv "$released" "$qdir"
        die "Could not restore peer $peer"
    fi
    if [[ -d "$released/client" && ! -e "$WG_CLIENTS_DIR/$peer" ]]; then
        mkdir -p "$WG_CLIENTS_DIR"
        cp -a "$released/client" "$WG_CLIENTS_DIR/$peer"
    fi
    wg_apply || warn "Could not apply $WG_CONF to $WG_INTERFACE"
    nft delete element inet "$NFT_TABLE" quarantine4 "{ $pip }" || warn "$pip was not in quarantine4"
    success "Released $peer ($pip). Its keys were in quarantine; re-enroll the device if compromise is confirmed."
}

main() {
    local sub=respond
    case "${1:-}" in
        respond | unblock | release) sub="$1"; shift ;;
    esac

    local type="" ip="" user="" device="" duration=1h reason=""
    while (($#)); do
        case "$1" in
            --type) type="${2:-}"; shift 2 || die "--type needs a value" ;;
            --ip) ip="${2:-}"; shift 2 || die "--ip needs a value" ;;
            --user) user="${2:-}"; shift 2 || die "--user needs a value" ;;
            --device) device="${2:-}"; shift 2 || die "--device needs a value" ;;
            --duration) duration="${2:-}"; shift 2 || die "--duration needs a value" ;;
            --reason) reason="${2:-}"; shift 2 || die "--reason needs a value" ;;
            --notify) NOTIFY=1; shift ;;
            --dry-run) DRY_RUN=1; shift ;;
            -h | --help) usage; exit 0 ;;
            *) usage >&2; die "Unknown argument: $1" ;;
        esac
    done
    [[ "$NFT_TABLE" =~ ^[a-z][a-z0-9_]*$ ]] || die "Invalid NFT_TABLE"

    ((DRY_RUN)) || require_root
    case "$sub" in
        unblock) cmd_unblock "$ip"; return ;;
        release) cmd_release "$device" "$ip"; return ;;
    esac

    # ---- validation, before anything is touched ----
    case "$type" in
        brute-force | suspicious-traffic | compromised-device | compromised-user) ;;
        "") die "--type is required" ;;
        *) die "Unknown --type: $type" ;;
    esac
    if [[ -n "$ip" ]]; then
        validate_ipv4 "$ip" || validate_ipv6 "$ip" || die "Invalid IP: $ip"
    fi
    [[ -z "$user" ]] || validate_username "$user" || die "Invalid username: $user"
    [[ -z "$device" ]] || validate_peer_name "$device" || validate_device_name "$device" || die "Invalid device: $device"
    local secs max
    secs="$(duration_seconds "$duration")" || die "Invalid --duration: $duration (use e.g. 30m, 1h, 7d)"
    max="$(duration_seconds "$THREAT_MAX_BLOCK")" || die "Invalid THREAT_MAX_BLOCK"
    ((secs <= max)) || die "--duration $duration exceeds THREAT_MAX_BLOCK=$THREAT_MAX_BLOCK"
    validate_display_name "${reason:-x}" || die "Invalid --reason (printable, max 64 chars)"

    local peer="" tunnel_ip=""
    case "$type" in
        brute-force)
            [[ -n "$ip" ]] || die "brute-force needs --ip"
            check_blockable "$ip"
            ;;
        suspicious-traffic)
            [[ -n "$ip" ]] || die "suspicious-traffic needs --ip"
            if validate_ipv4 "$ip" && ip_in_cidr "$ip" "$VPN_SUBNET"; then
                [[ "$ip" == "$VPN_SERVER_IP" ]] && die "Refusing to quarantine VPN_SERVER_IP"
                tunnel_ip="$ip"
            else
                check_blockable "$ip"
            fi
            ;;
        compromised-device)
            local by_ip=""
            if validate_ipv4 "${ip:-x}" && ip_in_cidr "$ip" "$VPN_SUBNET"; then
                by_ip="$ip"
            fi
            peer="$(resolve_peer "$user" "$device" "$by_ip")"
            tunnel_ip="$(wg_peer_ip "$peer")" || die "Peer $peer has no tunnel IP"
            if [[ -n "$ip" && -z "$by_ip" ]]; then
                check_blockable "$ip"
            fi
            ;;
        compromised-user)
            [[ -n "$user" ]] || die "compromised-user needs --user"
            if [[ "$AUTHELIA_BACKEND" == file ]]; then
                authelia_user_exists "$user" || warn "User $user not found in $AUTHELIA_USERS_DB"
            fi
            [[ -z "$ip" ]] || check_blockable "$ip"
            ;;
    esac
    require_cmd jq nft openssl

    # ---- incident setup ----
    INCIDENT_ID="INC-$(date -u +%Y%m%dT%H%M%SZ)-$(openssl rand -hex 3)"
    [[ "$INCIDENT_ID" =~ ^INC-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{6}$ ]] || die "Could not generate incident id"
    local work
    work="$(mktemp -d)"
    # shellcheck disable=SC2064
    trap "rm -rf '$work'" EXIT
    ACTIONS_FILE="$work/actions.ndjson"
    : >"$ACTIONS_FILE"

    if ((!DRY_RUN)); then
        (umask 077; mkdir -p "$INCIDENT_DIR" "$QUARANTINE_DIR")
        case "$type" in
            compromised-device) ztvpn_lock wg; ztvpn_lock pki ;;
            compromised-user) ztvpn_lock users; ztvpn_lock wg; ztvpn_lock pki ;;
        esac
    fi
    log "Incident $INCIDENT_ID: $type${ip:+ ip=$ip}${user:+ user=$user}${peer:+ peer=$peer}"

    # ---- actions; each one runs regardless of the others ----
    case "$type" in
        brute-force)
            run_action block-ip "$ip" block_ip "$ip" "$duration"
            ;;
        suspicious-traffic)
            if [[ -n "$tunnel_ip" ]]; then
                run_action quarantine-ip "$tunnel_ip" quarantine_ip "$tunnel_ip"
            else
                run_action block-ip "$ip" block_ip "$ip" "$duration"
            fi
            ;;
        compromised-device)
            run_action quarantine-ip "$tunnel_ip" quarantine_ip "$tunnel_ip"
            run_action remove-peer "$peer" remove_peer "$peer"
            run_action revoke-cert "$peer" revoke_cert "$peer"
            if [[ -n "$ip" && "$ip" != "$tunnel_ip" ]]; then
                run_action block-ip "$ip" block_ip "$ip" "$duration"
            fi
            ;;
        compromised-user)
            run_action disable-user "$user" disable_user "$user"
            local p pip
            local -a peers=()
            mapfile -t peers < <(wg_user_peers "$user")
            for p in "${peers[@]}"; do
                [[ -n "$p" ]] || continue
                if pip="$(wg_peer_ip "$p")"; then
                    run_action quarantine-ip "$pip" quarantine_ip "$pip"
                fi
                run_action remove-peer "$p" remove_peer "$p"
                run_action revoke-cert "$p" revoke_cert "$p"
            done
            ((${#peers[@]})) || info "User $user has no WireGuard peers"
            local -A seen=()
            for p in "${peers[@]}"; do seen["$p"]=1; done
            if [[ -z "${seen[$user]:-}" ]]; then
                run_action revoke-cert "$user" revoke_cert "$user"
            fi
            if [[ -n "$ip" ]]; then
                run_action block-ip "$ip" block_ip "$ip" "$duration"
            fi
            ;;
    esac

    local summary
    summary="$(jq -r '"\(.action) \(.target): \(.status)"' "$ACTIONS_FILE")"

    if ((DRY_RUN)); then
        info "Dry run: nothing was changed and no incident record was written"
        return 0
    fi

    if ((NOTIFY)); then
        notify "[ztvpn] $type incident $INCIDENT_ID" "Host: ${HOSTNAME:-$(uname -n)}
${reason:+Reason: $reason
}$summary"
    fi

    local notes_json='[]'
    if ((${#NOTIFY_RESULTS[@]})); then
        notes_json="$(printf '%s\n' "${NOTIFY_RESULTS[@]}" | jq -R 'split(":") | {channel: .[0], result: (.[1:] | join(":"))}' | jq -sc .)"
    fi
    jq -s --arg id "$INCIDENT_ID" --arg type "$type" --arg ip "$ip" --arg user "$user" --arg peer "$peer" \
        --arg reason "$reason" --arg duration "$duration" --arg operator "${SUDO_USER:-${USER:-unknown}}" \
        --arg caller "$(caller_ips | head -n1)" --arg created "$(date -u +%FT%TZ)" \
        --argjson notifications "$notes_json" --argjson failed "$FAILED" \
        '{id: $id, type: $type, created: $created, operator: $operator, caller_ip: $caller,
          targets: {ip: $ip, user: $user, peer: $peer}, block_duration: $duration, reason: $reason,
          status: (if $failed == 1 then "partial" else "contained" end),
          actions: ., notifications: $notifications}' \
        "$ACTIONS_FILE" | atomic_write "$INCIDENT_DIR/$INCIDENT_ID.json" 600
    info "Incident record: $INCIDENT_DIR/$INCIDENT_ID.json"
    printf '%s\n' "$INCIDENT_ID"
    return "$FAILED"
}

main "$@"
