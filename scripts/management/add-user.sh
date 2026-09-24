#!/bin/bash

# Zero Trust VPN User Management Script
# Adds new users to the VPN with proper authentication and device enrollment

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

# Source environment variables
if [[ -f "$PROJECT_ROOT/.env" ]]; then
    source "$PROJECT_ROOT/.env"
else
    echo "Error: .env file not found. Run initial-setup.sh first."
    exit 1
fi

# Default values
CONFIG_PATH="${CONFIG_PATH:-/opt/zero-trust-vpn}"
CERTS_PATH="${CERTS_PATH:-$CONFIG_PATH/certificates}"
VPN_SUBNET="${VPN_SUBNET:-10.10.0.0/24}"
VPN_SERVER_IP="${VPN_SERVER_IP:-10.10.0.1}"
VPN_PORT="${VPN_PORT:-51820}"
DNS_SERVERS="${DNS_SERVERS:-1.1.1.1,8.8.8.8}"
DOMAIN="${DOMAIN:-vpn.example.com}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging functions
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# Show usage
show_usage() {
    echo "Usage: $0 <username> <email> [options]"
    echo ""
    echo "Arguments:"
    echo "  username    Username for the new VPN user"
    echo "  email       Email address for the user"
    echo ""
    echo "Options:"
    echo "  --admin     Grant admin privileges"
    echo "  --group     Specify user group (default: users)"
    echo "  --help, -h  Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 john john@example.com"
    echo "  $0 admin admin@example.com --admin"
    echo "  $0 dev dev@example.com --group developers"
}

# Validate input
validate_input() {
    local username="$1"
    local email="$2"
    
    # Validate username
    if [[ ! "$username" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        error "Invalid username. Use only alphanumeric characters, hyphens, and underscores."
        exit 1
    fi
    
    if [[ ${#username} -lt 3 || ${#username} -gt 32 ]]; then
        error "Username must be between 3 and 32 characters."
        exit 1
    fi
    
    # Validate email
    if [[ ! "$email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        error "Invalid email address format."
        exit 1
    fi
    
    # Check if user already exists
    if [[ -f "$CONFIG_PATH/wireguard/clients/${username}.conf" ]]; then
        error "User '$username' already exists."
        exit 1
    fi
}

# Get next available IP address
get_next_ip() {
    local base_ip="${VPN_SUBNET%/*}"
    local base_octets=(${base_ip//./ })
    local network_base="${base_octets[0]}.${base_octets[1]}.${base_octets[2]}"
    
    # Start from .2 (server is .1)
    for i in {2..254}; do
        local test_ip="${network_base}.${i}"
        
        # Check if IP is already in use
        if ! grep -r "Address = ${test_ip}" "$CONFIG_PATH/wireguard/clients/" 2>/dev/null; then
            echo "$test_ip"
            return 0
        fi
    done
    
    error "No available IP addresses in subnet $VPN_SUBNET"
    exit 1
}

# Generate WireGuard key pair
generate_wireguard_keys() {
    local username="$1"
    local client_dir="$CONFIG_PATH/wireguard/clients"
    
    mkdir -p "$client_dir"
    
    # Generate private key
    local private_key=$(wg genkey)
    echo "$private_key" > "$client_dir/${username}_private.key"
    
    # Generate public key
    local public_key=$(echo "$private_key" | wg pubkey)
    echo "$public_key" > "$client_dir/${username}_public.key"
    
    # Set permissions
    chmod 600 "$client_dir/${username}_private.key"
    chmod 644 "$client_dir/${username}_public.key"
    
    echo "$private_key:$public_key"
}

# Generate client certificate
generate_client_certificate() {
    local username="$1"
    local email="$2"
    
    log "Generating client certificate for $username..."
    
    # Create certificate request
    openssl req -new \
        -key "$CERTS_PATH/clients/${username}_private.key" \
        -out "$CERTS_PATH/clients/${username}.csr" \
        -subj "/C=US/ST=State/L=City/O=Organization/OU=VPN/CN=${username}/emailAddress=${email}"
    
    # Sign certificate
    openssl x509 -req \
        -in "$CERTS_PATH/clients/${username}.csr" \
        -CA "$CERTS_PATH/ca/ca.crt" \
        -CAkey "$CERTS_PATH/ca/ca.key" \
        -CAcreateserial \
        -out "$CERTS_PATH/clients/${username}.crt" \
        -days 365 \
        -extensions v3_req \
        -extfile <(cat << EOF
[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
email.1 = ${email}
EOF
)
    
    # Set permissions
    chmod 644 "$CERTS_PATH/clients/${username}.crt"
    
    # Clean up CSR
    rm "$CERTS_PATH/clients/${username}.csr"
    
    log "✓ Client certificate generated"
}

# Create WireGuard client configuration
create_client_config() {
    local username="$1"
    local email="$2"
    local user_group="$3"
    local is_admin="$4"
    
    log "Creating WireGuard configuration for $username..."
    
    # Generate keys
    local keys=$(generate_wireguard_keys "$username")
    local private_key="${keys%:*}"
    local public_key="${keys#*:}"
    
    # Get IP address
    local client_ip=$(get_next_ip)
    
    # Get server public key
    local server_public_key=$(cat /etc/wireguard/server_public.key)
    
    # Create client configuration
    cat > "$CONFIG_PATH/wireguard/clients/${username}.conf" << EOF
[Interface]
PrivateKey = $private_key
Address = $client_ip/32
DNS = ${DNS_SERVERS//,/ }

# Client information
# Username: $username
# Email: $email
# Group: $user_group
# Admin: $is_admin
# Created: $(date)

[Peer]
PublicKey = $server_public_key
Endpoint = $DOMAIN:$VPN_PORT
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF
    
    # Set permissions
    chmod 600 "$CONFIG_PATH/wireguard/clients/${username}.conf"
    
    # Add peer to server configuration
    add_peer_to_server "$username" "$public_key" "$client_ip"
    
    log "✓ Client configuration created"
    log "  IP Address: $client_ip"
    log "  Public Key: $public_key"
}

# Add peer to server configuration
add_peer_to_server() {
    local username="$1"
    local public_key="$2"
    local client_ip="$3"
    
    log "Adding peer to server configuration..."
    
    # Add peer to WireGuard server config
    cat >> /etc/wireguard/wg0.conf << EOF

# Client: $username
[Peer]
PublicKey = $public_key
AllowedIPs = $client_ip/32
EOF
    
    # Reload WireGuard configuration if service is running
    if systemctl is-active --quiet wg-quick@wg0; then
        wg syncconf wg0 <(wg-quick strip wg0)
        log "✓ WireGuard configuration reloaded"
    fi
}

# Add user to Authelia database
add_user_to_authelia() {
    local username="$1"
    local email="$2"
    local user_group="$3"
    local is_admin="$4"
    
    log "Adding user to Authelia database..."
    
    # Generate password hash (user will need to change this)
    local temp_password=$(openssl rand -hex 8)
    local password_hash=$(docker run --rm authelia/authelia:latest authelia hash-password "$temp_password" | grep 'Password hash:' | cut -d' ' -f3)
    
    # Create users database if it doesn't exist
    local users_db="$CONFIG_PATH/authelia/users_database.yml"
    if [[ ! -f "$users_db" ]]; then
        cat > "$users_db" << EOF
users:
EOF
    fi
    
    # Determine groups
    local groups="users"
    if [[ "$is_admin" == "true" ]]; then
        groups="users,admins"
    elif [[ "$user_group" != "users" ]]; then
        groups="users,$user_group"
    fi
    
    # Add user to database
    cat >> "$users_db" << EOF
  $username:
    displayname: "$username"
    password: "$password_hash"
    email: "$email"
    groups:
      - ${groups//,/
      - }
EOF
    
    log "✓ User added to Authelia database"
    log "  Temporary password: $temp_password"
    warning "User must change password on first login"
}

# Generate QR code for mobile setup
generate_qr_code() {
    local username="$1"
    
    log "Generating QR code for mobile setup..."
    
    # Check if qrencode is installed
    if ! command -v qrencode &> /dev/null; then
        warning "qrencode not installed. Installing..."
        apt update && apt install -y qrencode
    fi
    
    # Generate QR code
    qrencode -t ansiutf8 < "$CONFIG_PATH/wireguard/clients/${username}.conf"
    
    # Save QR code to file
    qrencode -t png -o "$CONFIG_PATH/wireguard/clients/${username}_qr.png" < "$CONFIG_PATH/wireguard/clients/${username}.conf"
    
    log "✓ QR code generated"
    log "  QR code image: $CONFIG_PATH/wireguard/clients/${username}_qr.png"
}

# Send welcome email
send_welcome_email() {
    local username="$1"
    local email="$2"
    local temp_password="$3"
    
    if [[ -z "${SMTP_HOST:-}" ]]; then
        warning "SMTP not configured. Skipping email notification."
        return 0
    fi
    
    log "Sending welcome email..."
    
    # Create email content
    local email_content="Subject: Welcome to Zero Trust VPN

Hello $username,

Your VPN account has been created successfully.

Login Details:
- Username: $username
- Temporary Password: $temp_password
- Authentication URL: https://${AUTH_DOMAIN:-auth.$DOMAIN}

Please log in and change your password immediately.

Your WireGuard configuration file is attached.

Best regards,
VPN Administrator"
    
    # Send email (simplified - in production, use proper SMTP client)
    echo "$email_content" | mail -s "VPN Account Created" -a "$CONFIG_PATH/wireguard/clients/${username}.conf" "$email" 2>/dev/null || {
        warning "Failed to send email. Please send configuration manually."
    }
    
    log "✓ Welcome email sent"
}

# Create user documentation
create_user_documentation() {
    local username="$1"
    local email="$2"
    local client_ip="$3"
    
    log "Creating user documentation..."
    
    cat > "$CONFIG_PATH/wireguard/clients/${username}_info.txt" << EOF
VPN User Information
===================

User Details:
- Username: $username
- Email: $email
- IP Address: $client_ip
- Created: $(date)

Configuration Files:
- WireGuard Config: ${username}.conf
- QR Code: ${username}_qr.png
- Certificate: ${username}.crt

Setup Instructions:
1. Download WireGuard client for your device
2. Import the configuration file or scan the QR code
3. Connect to the VPN
4. Access https://${AUTH_DOMAIN:-auth.$DOMAIN} to set up 2FA

Security Notes:
- Keep your private key secure
- Enable 2FA for enhanced security
- Report any suspicious activity immediately

Support:
- Email: ${ADMIN_EMAIL:-admin@example.com}
- Documentation: https://github.com/Xieonie/zero-trust-vpn-infrastructure
EOF
    
    log "✓ User documentation created"
}

# Log user creation
log_user_creation() {
    local username="$1"
    local email="$2"
    local user_group="$3"
    local is_admin="$4"
    local client_ip="$5"
    
    local log_entry="$(date '+%Y-%m-%d %H:%M:%S') - User created: $username ($email) - IP: $client_ip - Group: $user_group - Admin: $is_admin"
    echo "$log_entry" >> "$CONFIG_PATH/logs/user_management.log"
    
    # Send notification to admin
    if [[ -n "${ADMIN_EMAIL:-}" ]]; then
        echo "New VPN user created: $username ($email)" | mail -s "VPN User Created" "${ADMIN_EMAIL}" 2>/dev/null || true
    fi
}

# Main function
main() {
    local username="$1"
    local email="$2"
    local user_group="${3:-users}"
    local is_admin="${4:-false}"
    
    log "Creating VPN user: $username"
    
    # Validate input
    validate_input "$username" "$email"
    
    # Create necessary directories
    mkdir -p "$CONFIG_PATH/wireguard/clients"
    mkdir -p "$CONFIG_PATH/authelia"
    mkdir -p "$CONFIG_PATH/logs"
    mkdir -p "$CERTS_PATH/clients"
    
    # Get client IP
    local client_ip=$(get_next_ip)
    
    # Create client configuration
    create_client_config "$username" "$email" "$user_group" "$is_admin"
    
    # Generate client certificate
    if [[ -f "$CERTS_PATH/ca/ca.crt" ]]; then
        # Generate client private key first
        openssl genrsa -out "$CERTS_PATH/clients/${username}_private.key" 2048
        chmod 600 "$CERTS_PATH/clients/${username}_private.key"
        
        generate_client_certificate "$username" "$email"
    else
        warning "CA certificate not found. Skipping client certificate generation."
    fi
    
    # Add user to Authelia
    add_user_to_authelia "$username" "$email" "$user_group" "$is_admin"
    
    # Generate QR code
    generate_qr_code "$username"
    
    # Create documentation
    create_user_documentation "$username" "$email" "$client_ip"
    
    # Log creation
    log_user_creation "$username" "$email" "$user_group" "$is_admin" "$client_ip"
    
    # Send welcome email
    local temp_password=$(grep -A 10 "^  $username:" "$CONFIG_PATH/authelia/users_database.yml" | grep "password:" | cut -d'"' -f2 | head -1)
    send_welcome_email "$username" "$email" "$temp_password"
    
    log "User '$username' created successfully!"
    echo ""
    echo "User Information:"
    echo "================"
    echo "Username: $username"
    echo "Email: $email"
    echo "IP Address: $client_ip"
    echo "Group: $user_group"
    echo "Admin: $is_admin"
    echo ""
    echo "Files created:"
    echo "=============="
    echo "- Configuration: $CONFIG_PATH/wireguard/clients/${username}.conf"
    echo "- QR Code: $CONFIG_PATH/wireguard/clients/${username}_qr.png"
    echo "- Documentation: $CONFIG_PATH/wireguard/clients/${username}_info.txt"
    echo ""
    echo "Next steps:"
    echo "==========="
    echo "1. Send configuration file to user"
    echo "2. User should change temporary password"
    echo "3. User should set up 2FA"
    echo "4. Test VPN connection"
}

# Parse command line arguments
if [[ $# -lt 2 ]]; then
    show_usage
    exit 1
fi

USERNAME="$1"
EMAIL="$2"
shift 2

USER_GROUP="users"
IS_ADMIN="false"

while [[ $# -gt 0 ]]; do
    case $1 in
        --admin)
            IS_ADMIN="true"
            USER_GROUP="admins"
            shift
            ;;
        --group)
            USER_GROUP="$2"
            shift 2
            ;;
        --help|-h)
            show_usage
            exit 0
            ;;
        *)
            error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Check if running as root or VPN user
if [[ $EUID -ne 0 && $(whoami) != "${VPN_USER:-vpn}" ]]; then
    error "This script must be run as root or the VPN user"
    exit 1
fi

main "$USERNAME" "$EMAIL" "$USER_GROUP" "$IS_ADMIN"