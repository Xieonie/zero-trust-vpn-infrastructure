#!/bin/bash

# Zero Trust VPN - User Revocation Script
# This script revokes access for a user by:
# 1. Disabling LDAP account
# 2. Revoking WireGuard client certificates
# 3. Removing client configurations
# 4. Adding to certificate revocation list
# 5. Logging the revocation event

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="/opt/zero-trust-vpn/config"
CERT_DIR="/opt/zero-trust-vpn/certificates"
LOG_FILE="/var/log/zero-trust-vpn/user-management.log"
WG_CONFIG="/etc/wireguard/wg0.conf"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Error handling
error_exit() {
    echo -e "${RED}ERROR: $1${NC}" >&2
    log "ERROR: $1"
    exit 1
}

# Warning function
warning() {
    echo -e "${YELLOW}WARNING: $1${NC}"
    log "WARNING: $1"
}

# Success function
success() {
    echo -e "${GREEN}SUCCESS: $1${NC}"
    log "SUCCESS: $1"
}

# Usage function
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Revoke access for a Zero Trust VPN user

OPTIONS:
    -u, --username USERNAME     Username to revoke (required)
    -r, --reason REASON        Reason for revocation (required)
    -d, --device DEVICE        Specific device to revoke (optional)
    -f, --force               Force revocation without confirmation
    -h, --help                Show this help message

EXAMPLES:
    $0 --username john.doe --reason "Employee terminated"
    $0 --username jane.smith --device laptop --reason "Device lost"
    $0 -u admin -r "Security incident" --force

EOF
}

# Parse command line arguments
USERNAME=""
REASON=""
DEVICE=""
FORCE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -u|--username)
            USERNAME="$2"
            shift 2
            ;;
        -r|--reason)
            REASON="$2"
            shift 2
            ;;
        -d|--device)
            DEVICE="$2"
            shift 2
            ;;
        -f|--force)
            FORCE=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            error_exit "Unknown option: $1"
            ;;
    esac
done

# Validate required parameters
if [[ -z "$USERNAME" ]]; then
    error_exit "Username is required. Use -u or --username"
fi

if [[ -z "$REASON" ]]; then
    error_exit "Reason is required. Use -r or --reason"
fi

# Validate username format
if [[ ! "$USERNAME" =~ ^[a-zA-Z0-9._-]+$ ]]; then
    error_exit "Invalid username format. Use only alphanumeric characters, dots, underscores, and hyphens"
fi

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    error_exit "This script must be run as root"
fi

# Create log directory if it doesn't exist
mkdir -p "$(dirname "$LOG_FILE")"

log "Starting user revocation process for: $USERNAME"

# Function to check if user exists in LDAP
check_user_exists() {
    local username="$1"
    
    if ! ldapsearch -x -H "${LDAP_URL:-ldap://localhost:389}" \
        -D "${LDAP_ADMIN_DN:-cn=admin,dc=example,dc=com}" \
        -w "${LDAP_ADMIN_PASSWORD:-admin}" \
        -b "${LDAP_BASE_DN:-dc=example,dc=com}" \
        "(uid=$username)" uid >/dev/null 2>&1; then
        return 1
    fi
    return 0
}

# Function to disable LDAP user account
disable_ldap_user() {
    local username="$1"
    
    log "Disabling LDAP account for user: $username"
    
    # Create LDIF file to disable account
    local ldif_file="/tmp/disable_${username}.ldif"
    cat > "$ldif_file" << EOF
dn: uid=${username},ou=users,${LDAP_BASE_DN:-dc=example,dc=com}
changetype: modify
replace: userAccountControl
userAccountControl: 514
-
replace: description
description: Account disabled - ${REASON} - $(date)
EOF

    # Apply LDIF changes
    if ldapmodify -x -H "${LDAP_URL:-ldap://localhost:389}" \
        -D "${LDAP_ADMIN_DN:-cn=admin,dc=example,dc=com}" \
        -w "${LDAP_ADMIN_PASSWORD:-admin}" \
        -f "$ldif_file"; then
        success "LDAP account disabled for user: $username"
        rm -f "$ldif_file"
    else
        warning "Failed to disable LDAP account for user: $username"
        rm -f "$ldif_file"
        return 1
    fi
}

# Function to revoke WireGuard client configuration
revoke_wireguard_client() {
    local username="$1"
    local device="$2"
    
    if [[ -n "$device" ]]; then
        local client_name="${username}-${device}"
    else
        local client_name="$username"
    fi
    
    log "Revoking WireGuard client configuration: $client_name"
    
    # Remove client configuration from server config
    if [[ -f "$WG_CONFIG" ]]; then
        # Create backup
        cp "$WG_CONFIG" "${WG_CONFIG}.backup.$(date +%Y%m%d_%H%M%S)"
        
        # Remove client peer section
        if [[ -n "$device" ]]; then
            # Remove specific device
            sed -i "/# Client: ${username}-${device}/,/^$/d" "$WG_CONFIG"
        else
            # Remove all configurations for user
            sed -i "/# Client: ${username}/,/^$/d" "$WG_CONFIG"
        fi
        
        # Restart WireGuard to apply changes
        if systemctl is-active --quiet wg-quick@wg0; then
            systemctl restart wg-quick@wg0
            success "WireGuard configuration updated and service restarted"
        fi
    fi
    
    # Remove client configuration files
    local client_config_dir="/etc/wireguard/clients"
    if [[ -n "$device" ]]; then
        rm -f "${client_config_dir}/${username}-${device}.conf"
        rm -f "${client_config_dir}/${username}-${device}.png"
    else
        rm -f "${client_config_dir}/${username}"*.conf
        rm -f "${client_config_dir}/${username}"*.png
    fi
}

# Function to revoke certificates
revoke_certificates() {
    local username="$1"
    local device="$2"
    
    if [[ -n "$device" ]]; then
        local cert_name="${username}-${device}"
    else
        local cert_name="$username"
    fi
    
    log "Revoking certificates for: $cert_name"
    
    local ca_dir="$CERT_DIR/ca"
    local crl_dir="$CERT_DIR/crl"
    
    # Find and revoke certificates
    if [[ -n "$device" ]]; then
        # Revoke specific device certificate
        local cert_file="$CERT_DIR/clients/${username}-${device}.crt"
        if [[ -f "$cert_file" ]]; then
            openssl ca -config "$ca_dir/ca.conf" -revoke "$cert_file"
        fi
    else
        # Revoke all certificates for user
        for cert_file in "$CERT_DIR/clients/${username}"*.crt; do
            if [[ -f "$cert_file" ]]; then
                openssl ca -config "$ca_dir/ca.conf" -revoke "$cert_file"
            fi
        done
    fi
    
    # Generate new CRL
    openssl ca -config "$ca_dir/ca.conf" -gencrl -out "$crl_dir/ca.crl"
    
    # Update CRL distribution
    if [[ -f "$crl_dir/ca.crl" ]]; then
        # Copy CRL to web server directory if configured
        if [[ -d "/var/www/html/crl" ]]; then
            cp "$crl_dir/ca.crl" "/var/www/html/crl/"
        fi
        success "Certificate revocation list updated"
    fi
}

# Function to update access control lists
update_access_control() {
    local username="$1"
    
    log "Updating access control lists for user: $username"
    
    # Add to revoked users list
    local revoked_list="/opt/zero-trust-vpn/config/revoked_users.txt"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $username - $REASON" >> "$revoked_list"
    
    # Update Authelia configuration if needed
    # This would typically involve updating user groups or policies
    
    # Notify monitoring systems
    if command -v curl >/dev/null 2>&1; then
        # Send webhook notification (customize URL and payload)
        curl -X POST "${WEBHOOK_URL:-http://localhost:8080/webhook}" \
            -H "Content-Type: application/json" \
            -d "{\"event\":\"user_revoked\",\"username\":\"$username\",\"reason\":\"$REASON\",\"timestamp\":\"$(date -Iseconds)\"}" \
            >/dev/null 2>&1 || true
    fi
}

# Function to cleanup user data
cleanup_user_data() {
    local username="$1"
    local device="$2"
    
    log "Cleaning up user data for: $username"
    
    if [[ -n "$device" ]]; then
        # Remove specific device data
        rm -f "$CERT_DIR/clients/${username}-${device}".{crt,key,csr}
        rm -f "/etc/wireguard/clients/${username}-${device}".{conf,png}
    else
        # Remove all user data
        rm -f "$CERT_DIR/clients/${username}"-*.{crt,key,csr}
        rm -f "/etc/wireguard/clients/${username}"-*.{conf,png}
    fi
    
    # Archive user data for audit purposes
    local archive_dir="/opt/zero-trust-vpn/archive/revoked"
    mkdir -p "$archive_dir"
    
    local archive_file="$archive_dir/${username}_$(date +%Y%m%d_%H%M%S).tar.gz"
    if [[ -n "$device" ]]; then
        tar -czf "$archive_file" -C "$CERT_DIR/clients" "${username}-${device}".* 2>/dev/null || true
    else
        tar -czf "$archive_file" -C "$CERT_DIR/clients" "${username}"-* 2>/dev/null || true
    fi
    
    success "User data archived to: $archive_file"
}

# Function to send notification
send_notification() {
    local username="$1"
    local reason="$2"
    
    log "Sending revocation notification for user: $username"
    
    # Email notification (if configured)
    if command -v mail >/dev/null 2>&1 && [[ -n "${ADMIN_EMAIL:-}" ]]; then
        cat << EOF | mail -s "VPN Access Revoked: $username" "$ADMIN_EMAIL"
VPN access has been revoked for the following user:

Username: $username
Device: ${DEVICE:-All devices}
Reason: $reason
Timestamp: $(date)
Revoked by: $(whoami)

This is an automated notification from the Zero Trust VPN system.
EOF
    fi
    
    # Slack notification (if configured)
    if [[ -n "${SLACK_WEBHOOK_URL:-}" ]]; then
        curl -X POST "$SLACK_WEBHOOK_URL" \
            -H "Content-Type: application/json" \
            -d "{\"text\":\"🚫 VPN Access Revoked\\n**User:** $username\\n**Device:** ${DEVICE:-All devices}\\n**Reason:** $reason\\n**Time:** $(date)\"}" \
            >/dev/null 2>&1 || true
    fi
}

# Main execution
main() {
    echo "Zero Trust VPN - User Revocation"
    echo "================================"
    echo
    echo "Username: $USERNAME"
    echo "Device: ${DEVICE:-All devices}"
    echo "Reason: $REASON"
    echo
    
    # Check if user exists
    if ! check_user_exists "$USERNAME"; then
        error_exit "User '$USERNAME' not found in LDAP directory"
    fi
    
    # Confirmation prompt
    if [[ "$FORCE" != "true" ]]; then
        echo -e "${YELLOW}WARNING: This will revoke access for user '$USERNAME'${NC}"
        if [[ -n "$DEVICE" ]]; then
            echo -e "${YELLOW}Device '$DEVICE' will be revoked${NC}"
        else
            echo -e "${YELLOW}ALL devices for this user will be revoked${NC}"
        fi
        echo
        read -p "Are you sure you want to continue? (yes/no): " confirm
        
        if [[ "$confirm" != "yes" ]]; then
            echo "Revocation cancelled"
            exit 0
        fi
    fi
    
    echo
    echo "Starting revocation process..."
    
    # Disable LDAP account
    disable_ldap_user "$USERNAME"
    
    # Revoke WireGuard configuration
    revoke_wireguard_client "$USERNAME" "$DEVICE"
    
    # Revoke certificates
    revoke_certificates "$USERNAME" "$DEVICE"
    
    # Update access control
    update_access_control "$USERNAME"
    
    # Cleanup user data
    cleanup_user_data "$USERNAME" "$DEVICE"
    
    # Send notifications
    send_notification "$USERNAME" "$REASON"
    
    echo
    success "User revocation completed successfully"
    log "User revocation completed for: $USERNAME (Device: ${DEVICE:-All}) - Reason: $REASON"
    
    echo
    echo "Summary:"
    echo "- LDAP account disabled"
    echo "- WireGuard configuration removed"
    echo "- Certificates revoked"
    echo "- Access control updated"
    echo "- User data archived"
    echo "- Notifications sent"
    echo
    echo "The user '$USERNAME' no longer has access to the VPN."
}

# Run main function
main "$@"