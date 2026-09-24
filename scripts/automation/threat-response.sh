#!/bin/bash

# Zero Trust VPN Infrastructure - Automated Threat Response Script
# This script provides automated responses to detected security threats
# including device isolation, user suspension, and incident escalation

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
CONFIG_DIR="$PROJECT_ROOT/config-examples"
INCIDENT_LOG_DIR="/var/log/zero-trust-vpn/incidents"
QUARANTINE_DIR="$PROJECT_ROOT/quarantine"
NOTIFICATION_CONFIG="$PROJECT_ROOT/config/notifications.conf"

# Threat response configuration
THREAT_LEVELS=("LOW" "MEDIUM" "HIGH" "CRITICAL")
AUTO_RESPONSE_ENABLED=true
QUARANTINE_DURATION=3600  # 1 hour default
ESCALATION_THRESHOLD="HIGH"
NOTIFICATION_ENABLED=true

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" >> "$INCIDENT_LOG_DIR/threat-response.log"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1" >> "$INCIDENT_LOG_DIR/threat-response.log"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1" >> "$INCIDENT_LOG_DIR/threat-response.log"
}

info() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] INFO: $1${NC}"
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] INFO: $1" >> "$INCIDENT_LOG_DIR/threat-response.log"
}

critical() {
    echo -e "${PURPLE}[$(date +'%Y-%m-%d %H:%M:%S')] CRITICAL: $1${NC}"
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] CRITICAL: $1" >> "$INCIDENT_LOG_DIR/threat-response.log"
}

# Display usage information
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Zero Trust VPN Automated Threat Response Script

OPTIONS:
    --threat-type TYPE      Type of threat detected
    --threat-level LEVEL    Threat severity (LOW, MEDIUM, HIGH, CRITICAL)
    --source-ip IP          Source IP address of threat
    --user USER             Username associated with threat
    --device DEVICE         Device ID associated with threat
    --evidence FILE         Path to evidence file
    --action ACTION         Specific action to take
    --manual                Disable automatic response
    --dry-run               Show what would be done without executing
    --escalate              Force escalation regardless of level
    --notify                Send notifications
    -v, --verbose           Enable verbose output
    -h, --help              Show this help message

THREAT TYPES:
    brute-force             Brute force attack detected
    malware                 Malware detected on device
    data-exfiltration       Suspicious data transfer
    unauthorized-access     Unauthorized access attempt
    policy-violation        Security policy violation
    anomalous-behavior      Unusual user/device behavior
    certificate-compromise  Certificate compromise detected

THREAT LEVELS:
    LOW                     Minor security concern
    MEDIUM                  Moderate security threat
    HIGH                    Serious security threat
    CRITICAL                Immediate security emergency

ACTIONS:
    isolate-device          Isolate specific device
    suspend-user            Suspend user account
    revoke-certificate      Revoke device certificate
    block-ip                Block source IP address
    quarantine              Place in quarantine
    escalate                Escalate to security team
    investigate             Start investigation process

EXAMPLES:
    $0 --threat-type brute-force --threat-level HIGH --source-ip 192.168.1.100
    $0 --threat-type malware --device laptop-001 --action isolate-device
    $0 --threat-type policy-violation --user john.doe --action suspend-user --notify

EOF
}

# Parse command line arguments
parse_args() {
    THREAT_TYPE=""
    THREAT_LEVEL=""
    SOURCE_IP=""
    USERNAME=""
    DEVICE_ID=""
    EVIDENCE_FILE=""
    SPECIFIC_ACTION=""
    MANUAL_MODE=false
    DRY_RUN=false
    FORCE_ESCALATE=false
    SEND_NOTIFICATIONS=false
    VERBOSE=false

    while [[ $# -gt 0 ]]; do
        case $1 in
            --threat-type)
                THREAT_TYPE="$2"
                shift 2
                ;;
            --threat-level)
                THREAT_LEVEL="$2"
                shift 2
                ;;
            --source-ip)
                SOURCE_IP="$2"
                shift 2
                ;;
            --user)
                USERNAME="$2"
                shift 2
                ;;
            --device)
                DEVICE_ID="$2"
                shift 2
                ;;
            --evidence)
                EVIDENCE_FILE="$2"
                shift 2
                ;;
            --action)
                SPECIFIC_ACTION="$2"
                shift 2
                ;;
            --manual)
                MANUAL_MODE=true
                shift
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --escalate)
                FORCE_ESCALATE=true
                shift
                ;;
            --notify)
                SEND_NOTIFICATIONS=true
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                error "Unknown option: $1"
                exit 1
                ;;
        esac
    done

    # Validate required parameters
    if [[ -z "$THREAT_TYPE" ]]; then
        error "Threat type is required. Use --threat-type"
        exit 1
    fi

    if [[ -z "$THREAT_LEVEL" ]]; then
        warn "Threat level not specified, defaulting to MEDIUM"
        THREAT_LEVEL="MEDIUM"
    fi

    # Validate threat level
    if [[ ! " ${THREAT_LEVELS[@]} " =~ " $THREAT_LEVEL " ]]; then
        error "Invalid threat level: $THREAT_LEVEL"
        error "Valid levels: ${THREAT_LEVELS[*]}"
        exit 1
    fi
}

# Initialize threat response environment
init_threat_response() {
    log "Initializing threat response system..."

    # Create necessary directories
    mkdir -p "$INCIDENT_LOG_DIR" "$QUARANTINE_DIR"

    # Check prerequisites
    local required_commands=("jq" "wg" "iptables" "systemctl")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            error "Required command not found: $cmd"
            exit 1
        fi
    done

    # Load notification configuration if available
    if [[ -f "$NOTIFICATION_CONFIG" ]]; then
        source "$NOTIFICATION_CONFIG"
    fi
}

# Create incident record
create_incident_record() {
    local incident_id="INC-$(date +%Y%m%d%H%M%S)-$$"
    local incident_file="$INCIDENT_LOG_DIR/incident_${incident_id}.json"

    log "Creating incident record: $incident_id"

    cat > "$incident_file" << EOF
{
    "incident_id": "$incident_id",
    "timestamp": "$(date -Iseconds)",
    "threat_type": "$THREAT_TYPE",
    "threat_level": "$THREAT_LEVEL",
    "source_ip": "$SOURCE_IP",
    "username": "$USERNAME",
    "device_id": "$DEVICE_ID",
    "evidence_file": "$EVIDENCE_FILE",
    "status": "active",
    "actions_taken": [],
    "escalated": false,
    "resolved": false,
    "created_by": "automated-threat-response"
}
EOF

    echo "$incident_id"
}

# Update incident record
update_incident_record() {
    local incident_id="$1"
    local action="$2"
    local status="$3"
    local incident_file="$INCIDENT_LOG_DIR/incident_${incident_id}.json"

    if [[ -f "$incident_file" ]]; then
        jq --arg action "$action" --arg status "$status" --arg timestamp "$(date -Iseconds)" \
           '.actions_taken += [{"action": $action, "timestamp": $timestamp, "status": $status}]' \
           "$incident_file" > "$incident_file.tmp" && mv "$incident_file.tmp" "$incident_file"
    fi
}

# Isolate device from network
isolate_device() {
    local device_id="$1"
    local incident_id="$2"

    critical "ISOLATING DEVICE: $device_id"

    if [[ "$DRY_RUN" == "true" ]]; then
        info "DRY RUN: Would isolate device $device_id"
        return 0
    fi

    # Get device IP from inventory
    local device_ip=""
    if [[ -f "$PROJECT_ROOT/device-inventory.json" ]]; then
        device_ip=$(jq -r ".devices[] | select(.id == \"$device_id\") | .ip_address" "$PROJECT_ROOT/device-inventory.json" 2>/dev/null || echo "")
    fi

    if [[ -n "$device_ip" ]]; then
        # Block device IP in iptables
        iptables -I INPUT -s "$device_ip" -j DROP
        iptables -I FORWARD -s "$device_ip" -j DROP
        iptables -I OUTPUT -d "$device_ip" -j DROP

        log "Device $device_id ($device_ip) isolated via iptables"
        update_incident_record "$incident_id" "isolate-device" "success"

        # Remove from WireGuard if connected
        if wg show wg0 peers | grep -q "$device_ip"; then
            # This would require the device's public key to remove properly
            warn "Device may still be connected via WireGuard - manual intervention required"
        fi
    else
        error "Could not find IP address for device: $device_id"
        update_incident_record "$incident_id" "isolate-device" "failed"
        return 1
    fi

    # Move device to quarantine in inventory
    if [[ -f "$PROJECT_ROOT/device-inventory.json" ]]; then
        jq "(.devices[] | select(.id == \"$device_id\") | .status) = \"quarantined\"" \
           "$PROJECT_ROOT/device-inventory.json" > "$PROJECT_ROOT/device-inventory.json.tmp" && \
           mv "$PROJECT_ROOT/device-inventory.json.tmp" "$PROJECT_ROOT/device-inventory.json"

        jq "(.devices[] | select(.id == \"$device_id\") | .quarantine_reason) = \"$THREAT_TYPE\"" \
           "$PROJECT_ROOT/device-inventory.json" > "$PROJECT_ROOT/device-inventory.json.tmp" && \
           mv "$PROJECT_ROOT/device-inventory.json.tmp" "$PROJECT_ROOT/device-inventory.json"

        jq "(.devices[] | select(.id == \"$device_id\") | .quarantine_timestamp) = \"$(date -Iseconds)\"" \
           "$PROJECT_ROOT/device-inventory.json" > "$PROJECT_ROOT/device-inventory.json.tmp" && \
           mv "$PROJECT_ROOT/device-inventory.json.tmp" "$PROJECT_ROOT/device-inventory.json"
    fi

    log "Device $device_id successfully isolated"
}

# Suspend user account
suspend_user() {
    local username="$1"
    local incident_id="$2"

    critical "SUSPENDING USER: $username"

    if [[ "$DRY_RUN" == "true" ]]; then
        info "DRY RUN: Would suspend user $username"
        return 0
    fi

    # Disable user in Authelia
    local authelia_config="$CONFIG_DIR/authelia/users_database.yml"
    if [[ -f "$authelia_config" ]]; then
        # Add disabled flag to user
        yq eval ".users.\"$username\".disabled = true" -i "$authelia_config"
        yq eval ".users.\"$username\".disabled_reason = \"$THREAT_TYPE\"" -i "$authelia_config"
        yq eval ".users.\"$username\".disabled_timestamp = \"$(date -Iseconds)\"" -i "$authelia_config"

        log "User $username disabled in Authelia"
        update_incident_record "$incident_id" "suspend-user" "success"

        # Restart Authelia to apply changes
        if systemctl is-active --quiet authelia; then
            systemctl reload authelia || systemctl restart authelia
            log "Authelia configuration reloaded"
        fi
    else
        error "Authelia configuration not found"
        update_incident_record "$incident_id" "suspend-user" "failed"
        return 1
    fi

    # Isolate all devices owned by the user
    if [[ -f "$PROJECT_ROOT/device-inventory.json" ]]; then
        local user_devices=$(jq -r ".devices[] | select(.username == \"$username\") | .id" "$PROJECT_ROOT/device-inventory.json")
        while IFS= read -r device; do
            if [[ -n "$device" ]]; then
                log "Isolating device $device owned by suspended user"
                isolate_device "$device" "$incident_id"
            fi
        done <<< "$user_devices"
    fi

    log "User $username successfully suspended"
}

# Revoke device certificate
revoke_certificate() {
    local device_id="$1"
    local incident_id="$2"

    critical "REVOKING CERTIFICATE: $device_id"

    if [[ "$DRY_RUN" == "true" ]]; then
        info "DRY RUN: Would revoke certificate for device $device_id"
        return 0
    fi

    # Find certificate for device
    local cert_dir="$PROJECT_ROOT/certificates/clients"
    local device_cert_dir=""

    if [[ -d "$cert_dir" ]]; then
        device_cert_dir=$(find "$cert_dir" -name "*$device_id*" -type d | head -1)
    fi

    if [[ -n "$device_cert_dir" && -f "$device_cert_dir/client.crt" ]]; then
        # Add certificate to CRL
        local crl_dir="$PROJECT_ROOT/certificates/crl"
        mkdir -p "$crl_dir"

        # Revoke certificate
        openssl ca -revoke "$device_cert_dir/client.crt" \
                   -keyfile "$PROJECT_ROOT/certificates/ca/ca.key" \
                   -cert "$PROJECT_ROOT/certificates/ca/ca.crt" \
                   -config "$PROJECT_ROOT/config-examples/pki/ca.conf" 2>/dev/null || true

        # Generate new CRL
        openssl ca -gencrl -out "$crl_dir/crl.pem" \
                   -keyfile "$PROJECT_ROOT/certificates/ca/ca.key" \
                   -cert "$PROJECT_ROOT/certificates/ca/ca.crt" \
                   -config "$PROJECT_ROOT/config-examples/pki/ca.conf" 2>/dev/null || true

        log "Certificate revoked for device $device_id"
        update_incident_record "$incident_id" "revoke-certificate" "success"

        # Move certificate to quarantine
        local quarantine_cert_dir="$QUARANTINE_DIR/certificates/$(basename "$device_cert_dir")"
        mkdir -p "$(dirname "$quarantine_cert_dir")"
        mv "$device_cert_dir" "$quarantine_cert_dir"
        log "Certificate moved to quarantine"
    else
        error "Certificate not found for device: $device_id"
        update_incident_record "$incident_id" "revoke-certificate" "failed"
        return 1
    fi
}

# Block source IP address
block_source_ip() {
    local source_ip="$1"
    local incident_id="$2"

    critical "BLOCKING SOURCE IP: $source_ip"

    if [[ "$DRY_RUN" == "true" ]]; then
        info "DRY RUN: Would block IP $source_ip"
        return 0
    fi

    # Add IP to iptables DROP rule
    iptables -I INPUT -s "$source_ip" -j DROP
    iptables -I FORWARD -s "$source_ip" -j DROP

    log "Source IP $source_ip blocked"
    update_incident_record "$incident_id" "block-ip" "success"

    # Add to persistent blocklist
    local blocklist_file="$PROJECT_ROOT/config/blocked-ips.txt"
    echo "$source_ip # Blocked: $(date) - Threat: $THREAT_TYPE" >> "$blocklist_file"

    # Save iptables rules
    if command -v iptables-save &> /dev/null; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    fi
}

# Send notification
send_notification() {
    local incident_id="$1"
    local message="$2"

    if [[ "$SEND_NOTIFICATIONS" != "true" && "$NOTIFICATION_ENABLED" != "true" ]]; then
        return 0
    fi

    log "Sending notification for incident: $incident_id"

    # Email notification (if configured)
    if [[ -n "${NOTIFICATION_EMAIL:-}" ]]; then
        echo "$message" | mail -s "Zero Trust VPN Security Alert - $incident_id" "$NOTIFICATION_EMAIL" 2>/dev/null || true
    fi

    # Slack notification (if configured)
    if [[ -n "${SLACK_WEBHOOK_URL:-}" ]]; then
        curl -X POST -H 'Content-type: application/json' \
             --data "{\"text\":\"🚨 Security Alert: $message\"}" \
             "$SLACK_WEBHOOK_URL" 2>/dev/null || true
    fi

    # Syslog notification
    logger -p security.alert "Zero Trust VPN Security Alert [$incident_id]: $message"
}

# Escalate incident
escalate_incident() {
    local incident_id="$1"

    critical "ESCALATING INCIDENT: $incident_id"

    # Update incident record
    local incident_file="$INCIDENT_LOG_DIR/incident_${incident_id}.json"
    if [[ -f "$incident_file" ]]; then
        jq '.escalated = true | .escalation_timestamp = "$(date -Iseconds)"' \
           "$incident_file" > "$incident_file.tmp" && mv "$incident_file.tmp" "$incident_file"
    fi

    # Send escalation notification
    local escalation_message="CRITICAL SECURITY INCIDENT ESCALATED
Incident ID: $incident_id
Threat Type: $THREAT_TYPE
Threat Level: $THREAT_LEVEL
Source IP: $SOURCE_IP
User: $USERNAME
Device: $DEVICE_ID
Timestamp: $(date)

Immediate attention required!"

    send_notification "$incident_id" "$escalation_message"
    log "Incident $incident_id escalated to security team"
}

# Determine appropriate response actions
determine_response_actions() {
    local actions=()

    # Automatic response based on threat type and level
    case "$THREAT_TYPE" in
        "brute-force")
            if [[ -n "$SOURCE_IP" ]]; then
                actions+=("block-ip")
            fi
            if [[ "$THREAT_LEVEL" == "HIGH" || "$THREAT_LEVEL" == "CRITICAL" ]]; then
                actions+=("escalate")
            fi
            ;;
        "malware")
            if [[ -n "$DEVICE_ID" ]]; then
                actions+=("isolate-device" "revoke-certificate")
            fi
            if [[ -n "$USERNAME" ]]; then
                actions+=("suspend-user")
            fi
            actions+=("escalate")
            ;;
        "data-exfiltration")
            if [[ -n "$DEVICE_ID" ]]; then
                actions+=("isolate-device")
            fi
            if [[ -n "$USERNAME" ]]; then
                actions+=("suspend-user")
            fi
            actions+=("escalate")
            ;;
        "unauthorized-access")
            if [[ -n "$SOURCE_IP" ]]; then
                actions+=("block-ip")
            fi
            if [[ -n "$DEVICE_ID" ]]; then
                actions+=("isolate-device")
            fi
            if [[ "$THREAT_LEVEL" == "HIGH" || "$THREAT_LEVEL" == "CRITICAL" ]]; then
                actions+=("escalate")
            fi
            ;;
        "policy-violation")
            if [[ -n "$USERNAME" && ("$THREAT_LEVEL" == "HIGH" || "$THREAT_LEVEL" == "CRITICAL") ]]; then
                actions+=("suspend-user")
            fi
            ;;
        "certificate-compromise")
            if [[ -n "$DEVICE_ID" ]]; then
                actions+=("revoke-certificate" "isolate-device")
            fi
            actions+=("escalate")
            ;;
        *)
            warn "Unknown threat type, using default response"
            if [[ "$THREAT_LEVEL" == "HIGH" || "$THREAT_LEVEL" == "CRITICAL" ]]; then
                actions+=("escalate")
            fi
            ;;
    esac

    # Force escalation if requested or threat level is critical
    if [[ "$FORCE_ESCALATE" == "true" || "$THREAT_LEVEL" == "CRITICAL" ]]; then
        actions+=("escalate")
    fi

    # Use specific action if provided
    if [[ -n "$SPECIFIC_ACTION" ]]; then
        actions=("$SPECIFIC_ACTION")
    fi

    echo "${actions[@]}"
}

# Execute response actions
execute_response_actions() {
    local incident_id="$1"
    local actions=("$@")

    log "Executing response actions for incident: $incident_id"

    for action in "${actions[@]:1}"; do  # Skip first element (incident_id)
        case "$action" in
            "isolate-device")
                if [[ -n "$DEVICE_ID" ]]; then
                    isolate_device "$DEVICE_ID" "$incident_id"
                else
                    warn "Cannot isolate device: Device ID not provided"
                fi
                ;;
            "suspend-user")
                if [[ -n "$USERNAME" ]]; then
                    suspend_user "$USERNAME" "$incident_id"
                else
                    warn "Cannot suspend user: Username not provided"
                fi
                ;;
            "revoke-certificate")
                if [[ -n "$DEVICE_ID" ]]; then
                    revoke_certificate "$DEVICE_ID" "$incident_id"
                else
                    warn "Cannot revoke certificate: Device ID not provided"
                fi
                ;;
            "block-ip")
                if [[ -n "$SOURCE_IP" ]]; then
                    block_source_ip "$SOURCE_IP" "$incident_id"
                else
                    warn "Cannot block IP: Source IP not provided"
                fi
                ;;
            "escalate")
                escalate_incident "$incident_id"
                ;;
            *)
                warn "Unknown action: $action"
                ;;
        esac
    done
}

# Main threat response execution
main() {
    init_threat_response

    log "=== THREAT RESPONSE INITIATED ==="
    log "Threat Type: $THREAT_TYPE"
    log "Threat Level: $THREAT_LEVEL"
    log "Source IP: ${SOURCE_IP:-N/A}"
    log "Username: ${USERNAME:-N/A}"
    log "Device ID: ${DEVICE_ID:-N/A}"

    # Create incident record
    local incident_id=$(create_incident_record)
    log "Incident ID: $incident_id"

    # Determine response actions
    local response_actions
    if [[ "$MANUAL_MODE" == "true" ]]; then
        log "Manual mode enabled - no automatic actions will be taken"
        response_actions=()
    else
        response_actions=($(determine_response_actions))
        log "Planned actions: ${response_actions[*]}"
    fi

    # Execute response actions
    if [[ ${#response_actions[@]} -gt 0 ]]; then
        execute_response_actions "$incident_id" "${response_actions[@]}"
    else
        log "No automatic actions determined for this threat"
    fi

    # Send notification
    local notification_message="Security threat detected and processed
Incident ID: $incident_id
Threat: $THREAT_TYPE ($THREAT_LEVEL)
Actions taken: ${response_actions[*]:-None}
Time: $(date)"

    send_notification "$incident_id" "$notification_message"

    log "=== THREAT RESPONSE COMPLETED ==="
    log "Incident record: $INCIDENT_LOG_DIR/incident_${incident_id}.json"
}

# Parse arguments and run main function
parse_args "$@"
main