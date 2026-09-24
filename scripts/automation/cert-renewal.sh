#!/bin/bash
# Certificate Renewal Script for Zero Trust VPN Infrastructure
# Automates the renewal of PKI certificates for WireGuard and authentication

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="/var/log/zero-trust-vpn/cert-renewal.log"
CONFIG_FILE="/etc/zero-trust-vpn/cert-renewal.conf"
PKI_DIR="/etc/zero-trust-vpn/pki"
BACKUP_DIR="/var/backups/zero-trust-vpn/certificates"

# Certificate validity thresholds (days)
WARNING_THRESHOLD=30
CRITICAL_THRESHOLD=7
RENEWAL_THRESHOLD=30

# Notification settings
NOTIFICATION_EMAIL="${NOTIFICATION_EMAIL:-admin@localhost}"
SLACK_WEBHOOK="${SLACK_WEBHOOK:-}"

# Colors for output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [CERT-RENEWAL] $1" | tee -a "$LOG_FILE"
}

# Create necessary directories
mkdir -p "$(dirname "$LOG_FILE")" "$BACKUP_DIR"

# Load configuration
load_config() {
    if [ -f "$CONFIG_FILE" ]; then
        source "$CONFIG_FILE"
    else
        # Default configuration
        CA_KEY="${PKI_DIR}/ca/ca.key"
        CA_CERT="${PKI_DIR}/ca/ca.crt"
        SERVER_KEY="${PKI_DIR}/server/server.key"
        SERVER_CERT="${PKI_DIR}/server/server.crt"
        CLIENT_DIR="${PKI_DIR}/clients"
        CRL_FILE="${PKI_DIR}/crl/crl.pem"
        
        # Certificate validity periods
        CA_VALIDITY_DAYS=3650      # 10 years
        SERVER_VALIDITY_DAYS=365   # 1 year
        CLIENT_VALIDITY_DAYS=90    # 3 months
        
        # OpenSSL configuration files
        CA_CONFIG="${PKI_DIR}/ca/ca.conf"
        SERVER_CONFIG="${PKI_DIR}/server/server.conf"
        CLIENT_CONFIG="${PKI_DIR}/clients/client.conf"
    fi
}

# Check certificate expiration
check_cert_expiration() {
    local cert_file="$1"
    local cert_name="$2"
    
    if [ ! -f "$cert_file" ]; then
        log "WARNING: Certificate file not found: $cert_file"
        return 1
    fi
    
    local expiry_date=$(openssl x509 -in "$cert_file" -noout -enddate | cut -d= -f2)
    local expiry_epoch=$(date -d "$expiry_date" +%s)
    local current_epoch=$(date +%s)
    local days_until_expiry=$(( (expiry_epoch - current_epoch) / 86400 ))
    
    log "Certificate $cert_name expires in $days_until_expiry days ($expiry_date)"
    
    if [ $days_until_expiry -le $CRITICAL_THRESHOLD ]; then
        log "CRITICAL: Certificate $cert_name expires in $days_until_expiry days!"
        send_notification "CRITICAL" "Certificate $cert_name expires in $days_until_expiry days!"
        return 2
    elif [ $days_until_expiry -le $WARNING_THRESHOLD ]; then
        log "WARNING: Certificate $cert_name expires in $days_until_expiry days"
        send_notification "WARNING" "Certificate $cert_name expires in $days_until_expiry days"
        return 1
    fi
    
    return 0
}

# Send notification
send_notification() {
    local level="$1"
    local message="$2"
    
    log "Sending notification: $level - $message"
    
    # Email notification
    if [ -n "$NOTIFICATION_EMAIL" ] && command -v mail &> /dev/null; then
        echo "$message" | mail -s "Zero Trust VPN Certificate Alert: $level" "$NOTIFICATION_EMAIL"
    fi
    
    # Slack notification
    if [ -n "$SLACK_WEBHOOK" ] && command -v curl &> /dev/null; then
        local color="warning"
        case "$level" in
            "CRITICAL") color="danger" ;;
            "SUCCESS") color="good" ;;
        esac
        
        curl -X POST -H 'Content-type: application/json' \
            --data "{\"text\":\"Zero Trust VPN Certificate Alert\",\"attachments\":[{\"color\":\"$color\",\"text\":\"$message\"}]}" \
            "$SLACK_WEBHOOK" &>/dev/null || true
    fi
    
    # System log
    logger -t cert-renewal "$level: $message"
}

# Backup certificate
backup_certificate() {
    local cert_file="$1"
    local cert_name="$2"
    
    if [ -f "$cert_file" ]; then
        local backup_file="$BACKUP_DIR/${cert_name}-$(date +%Y%m%d-%H%M%S).crt"
        cp "$cert_file" "$backup_file"
        log "Backed up certificate $cert_name to $backup_file"
    fi
}

# Generate CA certificate
generate_ca_certificate() {
    log "Generating new CA certificate..."
    
    # Backup existing CA if it exists
    if [ -f "$CA_CERT" ]; then
        backup_certificate "$CA_CERT" "ca"
    fi
    
    # Generate CA private key
    openssl genrsa -out "$CA_KEY" 4096
    chmod 600 "$CA_KEY"
    
    # Generate CA certificate
    openssl req -new -x509 -days "$CA_VALIDITY_DAYS" \
        -key "$CA_KEY" \
        -out "$CA_CERT" \
        -config "$CA_CONFIG" \
        -extensions v3_ca
    
    chmod 644 "$CA_CERT"
    
    log "CA certificate generated successfully"
    send_notification "SUCCESS" "New CA certificate generated"
}

# Generate server certificate
generate_server_certificate() {
    log "Generating new server certificate..."
    
    # Backup existing server certificate if it exists
    if [ -f "$SERVER_CERT" ]; then
        backup_certificate "$SERVER_CERT" "server"
    fi
    
    # Generate server private key
    openssl genrsa -out "$SERVER_KEY" 2048
    chmod 600 "$SERVER_KEY"
    
    # Generate certificate signing request
    local server_csr="${PKI_DIR}/server/server.csr"
    openssl req -new -key "$SERVER_KEY" -out "$server_csr" -config "$SERVER_CONFIG"
    
    # Sign server certificate with CA
    openssl x509 -req -in "$server_csr" \
        -CA "$CA_CERT" \
        -CAkey "$CA_KEY" \
        -CAcreateserial \
        -out "$SERVER_CERT" \
        -days "$SERVER_VALIDITY_DAYS" \
        -extensions v3_req \
        -extfile "$SERVER_CONFIG"
    
    chmod 644 "$SERVER_CERT"
    rm -f "$server_csr"
    
    log "Server certificate generated successfully"
    send_notification "SUCCESS" "New server certificate generated"
}

# Generate client certificate
generate_client_certificate() {
    local client_name="$1"
    local client_email="${2:-}"
    
    log "Generating client certificate for: $client_name"
    
    local client_key="${CLIENT_DIR}/${client_name}.key"
    local client_cert="${CLIENT_DIR}/${client_name}.crt"
    local client_csr="${CLIENT_DIR}/${client_name}.csr"
    
    # Backup existing client certificate if it exists
    if [ -f "$client_cert" ]; then
        backup_certificate "$client_cert" "$client_name"
    fi
    
    # Generate client private key
    openssl genrsa -out "$client_key" 2048
    chmod 600 "$client_key"
    
    # Create client-specific config
    local client_config="${CLIENT_DIR}/${client_name}.conf"
    cp "$CLIENT_CONFIG" "$client_config"
    
    # Add client-specific information
    if [ -n "$client_email" ]; then
        sed -i "s/CLIENT_EMAIL/$client_email/g" "$client_config"
    fi
    sed -i "s/CLIENT_NAME/$client_name/g" "$client_config"
    
    # Generate certificate signing request
    openssl req -new -key "$client_key" -out "$client_csr" -config "$client_config"
    
    # Sign client certificate with CA
    openssl x509 -req -in "$client_csr" \
        -CA "$CA_CERT" \
        -CAkey "$CA_KEY" \
        -CAcreateserial \
        -out "$client_cert" \
        -days "$CLIENT_VALIDITY_DAYS" \
        -extensions v3_req \
        -extfile "$client_config"
    
    chmod 644 "$client_cert"
    rm -f "$client_csr" "$client_config"
    
    log "Client certificate generated for: $client_name"
    send_notification "SUCCESS" "New client certificate generated for $client_name"
}

# Revoke certificate
revoke_certificate() {
    local cert_file="$1"
    local reason="${2:-unspecified}"
    
    log "Revoking certificate: $cert_file (reason: $reason)"
    
    if [ ! -f "$cert_file" ]; then
        log "ERROR: Certificate file not found: $cert_file"
        return 1
    fi
    
    # Add certificate to CRL
    openssl ca -revoke "$cert_file" \
        -keyfile "$CA_KEY" \
        -cert "$CA_CERT" \
        -config "$CA_CONFIG" \
        -crl_reason "$reason"
    
    # Generate updated CRL
    openssl ca -gencrl \
        -keyfile "$CA_KEY" \
        -cert "$CA_CERT" \
        -config "$CA_CONFIG" \
        -out "$CRL_FILE"
    
    log "Certificate revoked and CRL updated"
    send_notification "WARNING" "Certificate revoked: $(basename "$cert_file")"
}

# Check all certificates
check_all_certificates() {
    log "=== Checking all certificates ==="
    
    local renewal_needed=false
    
    # Check CA certificate
    if check_cert_expiration "$CA_CERT" "CA"; then
        local ca_status=$?
        if [ $ca_status -eq 2 ]; then
            log "CA certificate requires immediate renewal"
            renewal_needed=true
        fi
    fi
    
    # Check server certificate
    if check_cert_expiration "$SERVER_CERT" "Server"; then
        local server_status=$?
        if [ $server_status -eq 2 ] || [ $server_status -eq 1 ]; then
            log "Server certificate requires renewal"
            renewal_needed=true
        fi
    fi
    
    # Check client certificates
    if [ -d "$CLIENT_DIR" ]; then
        for client_cert in "$CLIENT_DIR"/*.crt; do
            if [ -f "$client_cert" ]; then
                local client_name=$(basename "$client_cert" .crt)
                if check_cert_expiration "$client_cert" "Client-$client_name"; then
                    local client_status=$?
                    if [ $client_status -eq 2 ] || [ $client_status -eq 1 ]; then
                        log "Client certificate $client_name requires renewal"
                        renewal_needed=true
                    fi
                fi
            fi
        done
    fi
    
    if [ "$renewal_needed" = true ]; then
        log "Certificate renewal required"
        return 1
    else
        log "All certificates are valid"
        return 0
    fi
}

# Renew certificates that are expiring soon
renew_expiring_certificates() {
    log "=== Renewing expiring certificates ==="
    
    # Check and renew server certificate
    local server_expiry_days=$(get_days_until_expiry "$SERVER_CERT")
    if [ $server_expiry_days -le $RENEWAL_THRESHOLD ]; then
        log "Renewing server certificate (expires in $server_expiry_days days)"
        generate_server_certificate
        restart_services
    fi
    
    # Check and renew client certificates
    if [ -d "$CLIENT_DIR" ]; then
        for client_cert in "$CLIENT_DIR"/*.crt; do
            if [ -f "$client_cert" ]; then
                local client_name=$(basename "$client_cert" .crt)
                local client_expiry_days=$(get_days_until_expiry "$client_cert")
                
                if [ $client_expiry_days -le $RENEWAL_THRESHOLD ]; then
                    log "Renewing client certificate $client_name (expires in $client_expiry_days days)"
                    generate_client_certificate "$client_name"
                fi
            fi
        done
    fi
}

# Get days until certificate expiry
get_days_until_expiry() {
    local cert_file="$1"
    
    if [ ! -f "$cert_file" ]; then
        echo "0"
        return
    fi
    
    local expiry_date=$(openssl x509 -in "$cert_file" -noout -enddate | cut -d= -f2)
    local expiry_epoch=$(date -d "$expiry_date" +%s)
    local current_epoch=$(date +%s)
    local days_until_expiry=$(( (expiry_epoch - current_epoch) / 86400 ))
    
    echo "$days_until_expiry"
}

# Restart services after certificate renewal
restart_services() {
    log "Restarting services after certificate renewal..."
    
    # Restart WireGuard
    if systemctl is-active --quiet wg-quick@wg0; then
        systemctl restart wg-quick@wg0
        log "Restarted WireGuard service"
    fi
    
    # Restart Authelia
    if systemctl is-active --quiet authelia; then
        systemctl restart authelia
        log "Restarted Authelia service"
    fi
    
    # Restart Docker containers if using Docker
    if command -v docker &> /dev/null; then
        if docker ps --format "{{.Names}}" | grep -q "wireguard"; then
            docker restart wireguard
            log "Restarted WireGuard container"
        fi
        
        if docker ps --format "{{.Names}}" | grep -q "authelia"; then
            docker restart authelia
            log "Restarted Authelia container"
        fi
    fi
    
    log "Service restart completed"
}

# Generate certificate report
generate_report() {
    local report_file="/var/log/zero-trust-vpn/certificate-report-$(date +%Y%m%d).txt"
    
    log "Generating certificate report: $report_file"
    
    cat > "$report_file" << EOF
Certificate Status Report
Generated: $(date)
========================

CA Certificate:
$(openssl x509 -in "$CA_CERT" -noout -subject -issuer -dates 2>/dev/null || echo "Not found")

Server Certificate:
$(openssl x509 -in "$SERVER_CERT" -noout -subject -issuer -dates 2>/dev/null || echo "Not found")

Client Certificates:
EOF
    
    if [ -d "$CLIENT_DIR" ]; then
        for client_cert in "$CLIENT_DIR"/*.crt; do
            if [ -f "$client_cert" ]; then
                local client_name=$(basename "$client_cert" .crt)
                echo "$client_name:" >> "$report_file"
                openssl x509 -in "$client_cert" -noout -subject -dates >> "$report_file" 2>/dev/null || echo "Error reading certificate" >> "$report_file"
                echo "" >> "$report_file"
            fi
        done
    fi
    
    log "Certificate report generated: $report_file"
}

# Usage information
usage() {
    cat << EOF
Usage: $0 [OPTIONS] <action>

Certificate renewal script for Zero Trust VPN infrastructure.

Actions:
    check           Check all certificate expiration dates
    renew           Renew certificates that are expiring soon
    generate-ca     Generate new CA certificate
    generate-server Generate new server certificate
    generate-client Generate new client certificate
    revoke          Revoke a certificate
    report          Generate certificate status report

Options:
    -c, --config FILE       Configuration file path
    -t, --threshold DAYS    Renewal threshold in days (default: 30)
    -f, --force             Force renewal without confirmation
    -n, --client-name NAME  Client name for certificate generation
    -e, --email EMAIL       Client email for certificate generation
    -r, --reason REASON     Revocation reason
    -h, --help              Show this help message

Examples:
    $0 check                                    # Check all certificates
    $0 renew                                    # Renew expiring certificates
    $0 generate-client -n john.doe -e john@company.com
    $0 revoke -n john.doe -r "Employee terminated"
    $0 report                                   # Generate status report
EOF
}

# Main function
main() {
    local action=""
    local force=false
    local client_name=""
    local client_email=""
    local revoke_reason="unspecified"
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -c|--config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            -t|--threshold)
                RENEWAL_THRESHOLD="$2"
                shift 2
                ;;
            -f|--force)
                force=true
                shift
                ;;
            -n|--client-name)
                client_name="$2"
                shift 2
                ;;
            -e|--email)
                client_email="$2"
                shift 2
                ;;
            -r|--reason)
                revoke_reason="$2"
                shift 2
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            check|renew|generate-ca|generate-server|generate-client|revoke|report)
                action="$1"
                shift
                ;;
            *)
                echo "Unknown option: $1" >&2
                usage >&2
                exit 1
                ;;
        esac
    done
    
    # Validate action
    if [ -z "$action" ]; then
        echo "Error: No action specified" >&2
        usage >&2
        exit 1
    fi
    
    # Load configuration
    load_config
    
    log "=== Certificate Renewal Script Started ==="
    log "Action: $action"
    
    # Execute action
    case "$action" in
        check)
            check_all_certificates
            ;;
        renew)
            renew_expiring_certificates
            ;;
        generate-ca)
            if [ "$force" = false ]; then
                echo -e "${RED}WARNING: Generating a new CA certificate will invalidate all existing certificates!${NC}"
                read -p "Are you sure you want to continue? (yes/no): " -r
                if [ "$REPLY" != "yes" ]; then
                    echo "CA generation cancelled"
                    exit 0
                fi
            fi
            generate_ca_certificate
            ;;
        generate-server)
            generate_server_certificate
            restart_services
            ;;
        generate-client)
            if [ -z "$client_name" ]; then
                echo "Error: Client name required for certificate generation" >&2
                exit 1
            fi
            generate_client_certificate "$client_name" "$client_email"
            ;;
        revoke)
            if [ -z "$client_name" ]; then
                echo "Error: Client name required for certificate revocation" >&2
                exit 1
            fi
            local client_cert="${CLIENT_DIR}/${client_name}.crt"
            revoke_certificate "$client_cert" "$revoke_reason"
            ;;
        report)
            generate_report
            ;;
        *)
            echo "Error: Unknown action: $action" >&2
            exit 1
            ;;
    esac
    
    log "=== Certificate Renewal Script Completed ==="
}

# Error handling
trap 'log "ERROR: Certificate renewal failed at line $LINENO"' ERR

# Execute main function
main "$@"