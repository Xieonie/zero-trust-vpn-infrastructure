#!/bin/bash

# Zero Trust VPN Infrastructure - Device Enrollment Script
# This script handles the enrollment of new devices into the Zero Trust VPN
# It creates certificates, WireGuard configurations, and updates access policies

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
CONFIG_DIR="$PROJECT_ROOT/config-examples"
CERT_DIR="$PROJECT_ROOT/certificates"
WG_CONFIG_DIR="/etc/wireguard"
AUTHELIA_CONFIG="$CONFIG_DIR/authelia/users_database.yml"

# Default values
DEFAULT_DEVICE_TYPE="laptop"
DEFAULT_ACCESS_LEVEL="standard"
DEFAULT_CERT_DAYS="365"

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
    exit 1
}

info() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] INFO: $1${NC}"
}

# Display usage information
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Zero Trust VPN Device Enrollment Script

OPTIONS:
    -u, --user USER         Username for the device owner (required)
    -d, --device DEVICE     Device name/identifier (required)
    -t, --type TYPE         Device type (laptop, mobile, server) [default: $DEFAULT_DEVICE_TYPE]
    -l, --level LEVEL       Access level (admin, standard, limited) [default: $DEFAULT_ACCESS_LEVEL]
    -e, --email EMAIL       User email address (required)
    -i, --ip IP             Assign specific IP address (optional)
    --cert-days DAYS        Certificate validity in days [default: $DEFAULT_CERT_DAYS]
    --dry-run               Show what would be done without making changes
    -h, --help              Show this help message

EXAMPLES:
    $0 -u john.doe -d laptop-work -e john.doe@company.com
    $0 -u jane.smith -d mobile-iphone -t mobile -l admin -e jane.smith@company.com
    $0 -u server-01 -d prod-server -t server -l limited -e admin@company.com --cert-days 730

EOF
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -u|--user)
                USERNAME="$2"
                shift 2
                ;;
            -d|--device)
                DEVICE_NAME="$2"
                shift 2
                ;;
            -t|--type)
                DEVICE_TYPE="$2"
                shift 2
                ;;
            -l|--level)
                ACCESS_LEVEL="$2"
                shift 2
                ;;
            -e|--email)
                USER_EMAIL="$2"
                shift 2
                ;;
            -i|--ip)
                ASSIGNED_IP="$2"
                shift 2
                ;;
            --cert-days)
                CERT_DAYS="$2"
                shift 2
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                error "Unknown option: $1"
                ;;
        esac
    done

    # Set defaults
    DEVICE_TYPE="${DEVICE_TYPE:-$DEFAULT_DEVICE_TYPE}"
    ACCESS_LEVEL="${ACCESS_LEVEL:-$DEFAULT_ACCESS_LEVEL}"
    CERT_DAYS="${CERT_DAYS:-$DEFAULT_CERT_DAYS}"
    DRY_RUN="${DRY_RUN:-false}"

    # Validate required parameters
    if [[ -z "${USERNAME:-}" ]]; then
        error "Username is required. Use -u or --user"
    fi

    if [[ -z "${DEVICE_NAME:-}" ]]; then
        error "Device name is required. Use -d or --device"
    fi

    if [[ -z "${USER_EMAIL:-}" ]]; then
        error "User email is required. Use -e or --email"
    fi

    # Validate device type
    if [[ ! "$DEVICE_TYPE" =~ ^(laptop|mobile|server|iot)$ ]]; then
        error "Invalid device type. Must be: laptop, mobile, server, or iot"
    fi

    # Validate access level
    if [[ ! "$ACCESS_LEVEL" =~ ^(admin|standard|limited)$ ]]; then
        error "Invalid access level. Must be: admin, standard, or limited"
    fi
}

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."

    # Check if running as root or with sudo
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root or with sudo"
    fi

    # Check required commands
    local required_commands=("openssl" "wg" "qrencode" "yq")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            error "Required command not found: $cmd"
        fi
    done

    # Check directory structure
    if [[ ! -d "$CERT_DIR" ]]; then
        warn "Certificate directory not found, creating: $CERT_DIR"
        mkdir -p "$CERT_DIR"/{ca,server,clients,crl}
    fi

    # Check if CA exists
    if [[ ! -f "$CERT_DIR/ca/ca.crt" ]]; then
        error "CA certificate not found. Run pki-setup.sh first."
    fi
}

# Generate next available IP address
get_next_ip() {
    local base_ip="10.0.2"
    local start_range=10
    local end_range=254

    if [[ -n "${ASSIGNED_IP:-}" ]]; then
        echo "$ASSIGNED_IP"
        return
    fi

    # Check existing WireGuard configurations
    for i in $(seq $start_range $end_range); do
        local test_ip="$base_ip.$i"
        if ! grep -r "$test_ip" "$WG_CONFIG_DIR" &>/dev/null && \
           ! grep -r "$test_ip" "$CERT_DIR/clients" &>/dev/null; then
            echo "$test_ip"
            return
        fi
    done

    error "No available IP addresses in range $base_ip.$start_range-$end_range"
}

# Generate client certificate
generate_certificate() {
    local client_ip="$1"
    local cert_dir="$CERT_DIR/clients/$USERNAME-$DEVICE_NAME"

    log "Generating certificate for $USERNAME-$DEVICE_NAME..."

    if [[ "$DRY_RUN" == "true" ]]; then
        info "DRY RUN: Would generate certificate in $cert_dir"
        return
    fi

    mkdir -p "$cert_dir"

    # Generate private key
    openssl genrsa -out "$cert_dir/client.key" 2048

    # Generate certificate signing request
    cat > "$cert_dir/client.conf" << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = State
L = City
O = Zero Trust VPN
OU = Client Certificates
CN = $USERNAME-$DEVICE_NAME
emailAddress = $USER_EMAIL

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names
extendedKeyUsage = clientAuth

[alt_names]
DNS.1 = $USERNAME-$DEVICE_NAME
IP.1 = $client_ip
EOF

    # Generate CSR
    openssl req -new -key "$cert_dir/client.key" -out "$cert_dir/client.csr" -config "$cert_dir/client.conf"

    # Sign certificate with CA
    openssl x509 -req -in "$cert_dir/client.csr" \
        -CA "$CERT_DIR/ca/ca.crt" \
        -CAkey "$CERT_DIR/ca/ca.key" \
        -CAcreateserial \
        -out "$cert_dir/client.crt" \
        -days "$CERT_DAYS" \
        -extensions v3_req \
        -extfile "$cert_dir/client.conf"

    # Set appropriate permissions
    chmod 600 "$cert_dir/client.key"
    chmod 644 "$cert_dir/client.crt"

    log "Certificate generated successfully"
}

# Generate WireGuard configuration
generate_wireguard_config() {
    local client_ip="$1"
    local wg_dir="$CERT_DIR/clients/$USERNAME-$DEVICE_NAME"

    log "Generating WireGuard configuration..."

    if [[ "$DRY_RUN" == "true" ]]; then
        info "DRY RUN: Would generate WireGuard config for IP $client_ip"
        return
    fi

    # Generate WireGuard keys
    local private_key=$(wg genkey)
    local public_key=$(echo "$private_key" | wg pubkey)
    local preshared_key=$(wg genpsk)

    # Save keys
    echo "$private_key" > "$wg_dir/private.key"
    echo "$public_key" > "$wg_dir/public.key"
    echo "$preshared_key" > "$wg_dir/preshared.key"

    # Set permissions
    chmod 600 "$wg_dir"/*.key

    # Generate client configuration
    cat > "$wg_dir/wg0-client.conf" << EOF
[Interface]
# Client: $USERNAME-$DEVICE_NAME
# Device Type: $DEVICE_TYPE
# Access Level: $ACCESS_LEVEL
# Generated: $(date)
PrivateKey = $private_key
Address = $client_ip/24
DNS = 10.0.1.1

# Security settings
PostUp = echo "Connected to Zero Trust VPN" | logger
PreDown = echo "Disconnecting from Zero Trust VPN" | logger

[Peer]
# Zero Trust VPN Server
PublicKey = $(cat "$CERT_DIR/server/public.key" 2>/dev/null || echo "SERVER_PUBLIC_KEY_PLACEHOLDER")
PresharedKey = $preshared_key
Endpoint = vpn.example.com:51820
AllowedIPs = 10.0.1.0/24, 10.0.2.0/24
PersistentKeepalive = 25
EOF

    # Generate QR code for mobile devices
    if [[ "$DEVICE_TYPE" == "mobile" ]]; then
        qrencode -t ansiutf8 < "$wg_dir/wg0-client.conf" > "$wg_dir/qr-code.txt"
        qrencode -t png -o "$wg_dir/qr-code.png" < "$wg_dir/wg0-client.conf"
        log "QR code generated for mobile device"
    fi

    # Update server configuration
    update_server_config "$public_key" "$preshared_key" "$client_ip"

    log "WireGuard configuration generated successfully"
}

# Update server WireGuard configuration
update_server_config() {
    local public_key="$1"
    local preshared_key="$2"
    local client_ip="$3"

    log "Updating server WireGuard configuration..."

    if [[ "$DRY_RUN" == "true" ]]; then
        info "DRY RUN: Would add peer to server config"
        return
    fi

    # Add peer to server configuration
    cat >> "$WG_CONFIG_DIR/wg0.conf" << EOF

# Client: $USERNAME-$DEVICE_NAME ($DEVICE_TYPE)
# Access Level: $ACCESS_LEVEL
# Added: $(date)
[Peer]
PublicKey = $public_key
PresharedKey = $preshared_key
AllowedIPs = $client_ip/32
EOF

    # Restart WireGuard if running
    if systemctl is-active --quiet wg-quick@wg0; then
        systemctl restart wg-quick@wg0
        log "WireGuard service restarted"
    fi
}

# Update Authelia user database
update_authelia_config() {
    log "Updating Authelia user database..."

    if [[ "$DRY_RUN" == "true" ]]; then
        info "DRY RUN: Would update Authelia config for user $USERNAME"
        return
    fi

    # Check if user already exists
    if yq eval ".users | has(\"$USERNAME\")" "$AUTHELIA_CONFIG" | grep -q "true"; then
        warn "User $USERNAME already exists in Authelia database"
        return
    fi

    # Generate password hash (user will need to change this)
    local temp_password="ChangeMe123!"
    local password_hash=$(echo -n "$temp_password" | argon2 "$(openssl rand -base64 32)" -e -id -k 65536 -t 3 -p 4)

    # Add user to Authelia database
    yq eval ".users.\"$USERNAME\" = {
        \"displayname\": \"$USERNAME\",
        \"password\": \"$password_hash\",
        \"email\": \"$USER_EMAIL\",
        \"groups\": [\"$ACCESS_LEVEL\"]
    }" -i "$AUTHELIA_CONFIG"

    log "User added to Authelia database with temporary password: $temp_password"
    warn "User must change password on first login!"
}

# Create device inventory entry
create_device_inventory() {
    local client_ip="$1"
    local inventory_file="$PROJECT_ROOT/device-inventory.json"

    log "Creating device inventory entry..."

    if [[ "$DRY_RUN" == "true" ]]; then
        info "DRY RUN: Would create inventory entry"
        return
    fi

    # Create inventory file if it doesn't exist
    if [[ ! -f "$inventory_file" ]]; then
        echo '{"devices": []}' > "$inventory_file"
    fi

    # Add device entry
    local device_entry=$(cat << EOF
{
    "id": "$USERNAME-$DEVICE_NAME",
    "username": "$USERNAME",
    "device_name": "$DEVICE_NAME",
    "device_type": "$DEVICE_TYPE",
    "access_level": "$ACCESS_LEVEL",
    "email": "$USER_EMAIL",
    "ip_address": "$client_ip",
    "enrolled_date": "$(date -Iseconds)",
    "certificate_expiry": "$(date -d "+$CERT_DAYS days" -Iseconds)",
    "status": "active"
}
EOF
    )

    # Add to inventory
    jq ".devices += [$device_entry]" "$inventory_file" > "$inventory_file.tmp" && mv "$inventory_file.tmp" "$inventory_file"

    log "Device inventory updated"
}

# Generate enrollment summary
generate_summary() {
    local client_ip="$1"
    local summary_file="$CERT_DIR/clients/$USERNAME-$DEVICE_NAME/enrollment-summary.txt"

    cat > "$summary_file" << EOF
Zero Trust VPN Device Enrollment Summary
========================================

Device Information:
- User: $USERNAME
- Device: $DEVICE_NAME
- Type: $DEVICE_TYPE
- Access Level: $ACCESS_LEVEL
- Email: $USER_EMAIL
- IP Address: $client_ip
- Enrollment Date: $(date)

Certificate Information:
- Validity: $CERT_DAYS days
- Expires: $(date -d "+$CERT_DAYS days")

Files Generated:
- Certificate: client.crt
- Private Key: client.key
- WireGuard Config: wg0-client.conf
$(if [[ "$DEVICE_TYPE" == "mobile" ]]; then echo "- QR Code: qr-code.png"; fi)

Next Steps:
1. Provide the WireGuard configuration to the user
2. User should install WireGuard client
3. User must change Authelia password on first login
4. Test connectivity and access to authorized resources

Security Notes:
- Private keys are stored securely with restricted permissions
- Certificate will expire on $(date -d "+$CERT_DAYS days")
- Access is limited based on assigned access level: $ACCESS_LEVEL
- All connections are logged and monitored

EOF

    if [[ "$DRY_RUN" != "true" ]]; then
        log "Enrollment summary saved to: $summary_file"
    fi
}

# Main enrollment process
main() {
    log "Starting device enrollment for $USERNAME-$DEVICE_NAME..."

    check_prerequisites

    local client_ip=$(get_next_ip)
    info "Assigned IP address: $client_ip"

    generate_certificate "$client_ip"
    generate_wireguard_config "$client_ip"
    update_authelia_config
    create_device_inventory "$client_ip"
    generate_summary "$client_ip"

    if [[ "$DRY_RUN" == "true" ]]; then
        info "DRY RUN completed - no changes were made"
    else
        log "Device enrollment completed successfully!"
        log "Configuration files are located in: $CERT_DIR/clients/$USERNAME-$DEVICE_NAME"
        
        if [[ "$DEVICE_TYPE" == "mobile" ]]; then
            log "QR code for mobile setup:"
            cat "$CERT_DIR/clients/$USERNAME-$DEVICE_NAME/qr-code.txt"
        fi
    fi
}

# Parse arguments and run main function
parse_args "$@"
main