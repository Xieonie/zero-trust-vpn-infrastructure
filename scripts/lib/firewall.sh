# shellcheck shell=bash
# Dynamic firewall state (blocklists, quarantine) that must survive a
# reboot or a ruleset reload. Sourced by common.sh.
#
# The nft sets are the live state; $FW_STATE_FILE is their durable copy:
#   <set> <address> <absolute expiry epoch, 0 = permanent>
# threat-response saves after every change; firewall-setup restores after
# loading the table (also at boot via ztvpn-firewall-state.service).

FW_DYNAMIC_SETS=(blocklist4 blocklist6 quarantine4)

# Prints "<set> <addr> <remaining seconds or 0>" for the live sets.
fw_list_dynamic() {
    local set json
    for set in "${FW_DYNAMIC_SETS[@]}"; do
        json="$(nft -j list set inet "$NFT_TABLE" "$set" 2>/dev/null)" || continue
        jq -r --arg set "$set" '
            .nftables[] | select(.set) | .set.elem // [] | .[]
            | if type == "object" and .elem then [.elem.val, (.elem.expires // .elem.timeout // 0)]
              else [., 0] end
            | select(.[0] | type == "string")
            | "\($set) \(.[0]) \(.[1])"' <<<"$json"
    done
}

_fw_valid_elem() {
    local set="$1" addr="$2"
    case "$set" in
        blocklist4|quarantine4) validate_ipv4 "$addr" ;;
        blocklist6) [[ "$addr" == *:* && "$addr" =~ ^[0-9A-Fa-f:.]+$ && ${#addr} -le 45 ]] ;;
        *) return 1 ;;
    esac
}

# Writes the live sets to $FW_STATE_FILE. Timeouts become absolute epochs
# so a restore after downtime only re-adds what has not expired.
fw_save_state() {
    local now set addr secs out=""
    now="$(date +%s)"
    while read -r set addr secs; do
        _fw_valid_elem "$set" "$addr" || continue
        [[ "$secs" =~ ^[0-9]+$ ]] || continue
        if [[ "$set" == quarantine4 ]]; then
            out+="$set $addr 0"$'\n'
        elif ((secs > 0)); then
            out+="$set $addr $((now + secs))"$'\n'
        fi
    done < <(fw_list_dynamic)
    mkdir -p "$(dirname "$FW_STATE_FILE")"
    printf '%s' "$out" | atomic_write "$FW_STATE_FILE" 600
}

# Prints nft "add element" commands for everything in $FW_STATE_FILE that
# has not expired, plus the tunnel IPs of active quarantine records.
fw_restore_commands() {
    local now set addr exp meta qname
    now="$(date +%s)"
    if [[ -f "$FW_STATE_FILE" ]]; then
        while read -r set addr exp; do
            _fw_valid_elem "$set" "$addr" || continue
            [[ "$exp" =~ ^[0-9]+$ ]] || continue
            if ((exp == 0)); then
                [[ "$set" == quarantine4 ]] && printf 'add element inet %s %s { %s }\n' "$NFT_TABLE" "$set" "$addr"
            elif ((exp > now)); then
                printf 'add element inet %s %s { %s timeout %ss }\n' "$NFT_TABLE" "$set" "$addr" "$((exp - now))"
            fi
        done <"$FW_STATE_FILE"
    fi
    for meta in "$QUARANTINE_DIR"/*/meta.json; do
        [[ -f "$meta" ]] || continue
        qname="$(basename "$(dirname "$meta")")"
        [[ "$qname" == *.* ]] && continue
        addr="$(jq -r '.ip // empty' "$meta" 2>/dev/null)"
        validate_ipv4 "$addr" && printf 'add element inet %s quarantine4 { %s }\n' "$NFT_TABLE" "$addr"
    done
    return 0
}

# Loads the saved state into the running table.
fw_restore_state() {
    local cmds
    cmds="$(fw_restore_commands)"
    [[ -n "$cmds" ]] || return 0
    nft -f - <<<"$cmds"
}
