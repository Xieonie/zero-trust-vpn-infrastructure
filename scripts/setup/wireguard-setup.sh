#!/bin/bash

# Zero Trust VPN - WireGuard Setup Script
# This script sets up and configures WireGuard VPN server with security best practices

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
CONFIG_DIR="/etc/wireguard"
CERT_DIR="/opt/zero-trust-vpn/certificates"
LOG_FILE="/var/log/zero-trust-vpn/wireguard-setup.log"

# Default values
WG_INTERFACE="wg0"
WG_PORT="51820"
WG_NETWORK="10.8.0.0/24"
WG_SERVER_IP="10.8.0.1"
DNS_SERVERS="1.1.1.1,1.0.0.1"
EXTERNAL_INTERFACE=""
SERVER_PUBLIC_IP=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
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

# Info function
info() {
    echo -e "${BLUE}INFO: $1${NC}"
    log "INFO: $1"
}

# Usage function
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Set up WireGuard VPN server for Zero Trust infrastructure

OPTIONS:
    -i, --interface INTERFACE    WireGuard interface name (default: wg0)
    -p, --port PORT             WireGuard listen port (default: 51820)
    -n, --network NETWORK       VPN network CIDR (default: 10.8.0.0/24)
    -s, --server-ip IP          Server IP within VPN network (default: 10.8.0.1)
    -d, --dns DNS               DNS servers (default: 1.1.1.1,1.0.0.1)
    -e, --external-interface IF  External network interface (auto-detect if not specified)
    -a, --server-address ADDR   Public server address/IP
    -f, --force                 Force overwrite existing configuration
    -h, --help                  Show this help message

EXAMPLES:
    $0                          # Use default settings
    $0 --port 51821 --network 10.9.0.0/24
    $0 --server-address vpn.example.com --dns 8.8.8.8,8.8.4.4

EOF
}

# Parse command line arguments
FORCE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -i|--interface)
            WG_INTERFACE="$2"
            shift 2
            ;;
        -p|--port)
            WG_PORT="$2"
            shift 2
            ;;
        -n|--network)
            WG_NETWORK="$2"
            shift 2
            ;;
        -s|--server-ip)
            WG_SERVER_IP="$2"
            shift 2
            ;;
        -d|--dns)
            DNS_SERVERS="$2"
            shift 2
            ;;
        -e|--external-interface)
            EXTERNAL_INTERFACE="$2"
            shift 2
            ;;
        -a|--server-address)
            SERVER_PUBLIC_IP="$2"
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

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    error_exit "This script must be run as root"
fi

# Create log directory
mkdir -p "$(dirname "$LOG_FILE")"

log "Starting WireGuard setup with interface: $WG_INTERFACE, port: $WG_PORT, network: $WG_NETWORK"

# Function to detect external interface
detect_external_interface() {
    if [[ -z "$EXTERNAL_INTERFACE" ]]; then
        EXTERNAL_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
        if [[ -z "$EXTERNAL_INTERFACE" ]]; then
            error_exit "Could not detect external network interface. Please specify with --external-interface"
        fi
        info "Detected external interface: $EXTERNAL_INTERFACE"
    fi
}

# Function to detect server public IP
detect_server_ip() {
    if [[ -z "$SERVER_PUBLIC_IP" ]]; then
        # Try to detect public IP
        SERVER_PUBLIC_IP=$(curl -s ifconfig.me 2>/dev/null || curl -s ipinfo.io/ip 2>/dev/null || echo "")
        if [[ -z "$SERVER_PUBLIC_IP" ]]; then
            warning "Could not detect public IP. You'll need to set it manually in client configs."
            SERVER_PUBLIC_IP="YOUR_SERVER_IP"
        else
            info "Detected public IP: $SERVER_PUBLIC_IP"
        fi
    fi
}

# Function to install WireGuard
install_wireguard() {
    info "Installing WireGuard..."
    
    # Detect OS and install accordingly
    if command -v apt-get >/dev/null 2>&1; then
        # Debian/Ubuntu
        apt-get update
        apt-get install -y wireguard wireguard-tools qrencode iptables-persistent
    elif command -v yum >/dev/null 2>&1; then
        # CentOS/RHEL
        yum install -y epel-release
        yum install -y wireguard-tools qrencode iptables-services
    elif command -v dnf >/dev/null 2>&1; then
        # Fedora
        dnf install -y wireguard-tools qrencode iptables-services
    else
        error_exit "Unsupported operating system. Please install WireGuard manually."
    fi
    
    success "WireGuard installed successfully"
}

# Function to generate server keys
generate_server_keys() {
    info "Generating WireGuard server keys..."
    
    local server_private_key_file="$CONFIG_DIR/${WG_INTERFACE}_private.key"
    local server_public_key_file="$CONFIG_DIR/${WG_INTERFACE}_public.key"
    
    if [[ -f "$server_private_key_file" && "$FORCE" != "true" ]]; then
        warning "Server keys already exist. Use --force to overwrite."
        return 0
    fi
    
    # Generate private key
    wg genkey > "$server_private_key_file"
    chmod 600 "$server_private_key_file"
    
    # Generate public key
    wg pubkey < "$server_private_key_file" > "$server_public_key_file"
    chmod 644 "$server_public_key_file"
    
    success "Server keys generated successfully"
}

# Function to create server configuration
create_server_config() {
    info "Creating WireGuard server configuration..."
    
    local config_file="$CONFIG_DIR/${WG_INTERFACE}.conf"
    local private_key
    private_key=$(cat "$CONFIG_DIR/${WG_INTERFACE}_private.key")
    
    if [[ -f "$config_file" && "$FORCE" != "true" ]]; then
        warning "Configuration file already exists. Use --force to overwrite."
        return 0
    fi
    
    # Create configuration file
    cat > "$config_file" << EOF
# WireGuard Server Configuration
# Generated on $(date)
# Interface: $WG_INTERFACE
# Network: $WG_NETWORK

[Interface]
# Server private key
PrivateKey = $private_key

# Server IP address within VPN network
Address = $WG_SERVER_IP/$(echo $WG_NETWORK | cut -d'/' -f2)

# Port to listen on
ListenPort = $WG_PORT

# DNS servers for clients
DNS = $DNS_SERVERS

# Post-up script to configure routing and firewall
PostUp = iptables -A FORWARD -i %i -j ACCEPT
PostUp = iptables -A FORWARD -o %i -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o $EXTERNAL_INTERFACE -j MASQUERADE
PostUp = ip6tables -A FORWARD -i %i -j ACCEPT
PostUp = ip6tables -A FORWARD -o %i -j ACCEPT
PostUp = ip6tables -t nat -A POSTROUTING -o $EXTERNAL_INTERFACE -j MASQUERADE

# Post-down script to clean up routing and firewall
PostDown = iptables -D FORWARD -i %i -j ACCEPT
PostDown = iptables -D FORWARD -o %i -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o $EXTERNAL_INTERFACE -j MASQUERADE
PostDown = ip6tables -D FORWARD -i %i -j ACCEPT
PostDown = ip6tables -D FORWARD -o %i -j ACCEPT
PostDown = ip6tables -t nat -D POSTROUTING -o $EXTERNAL_INTERFACE -j MASQUERADE

# Security and performance settings
SaveConfig = false

# Client configurations will be added below
# Each client gets a [Peer] section

EOF
    
    chmod 600 "$config_file"
    success "Server configuration created: $config_file"
}

# Function to configure firewall
configure_firewall() {
    info "Configuring firewall rules..."
    
    # Enable IP forwarding
    echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
    echo 'net.ipv6.conf.all.forwarding=1' >> /etc/sysctl.conf
    sysctl -p
    
    # Configure iptables rules
    iptables -A INPUT -p udp --dport "$WG_PORT" -j ACCEPT
    iptables -A FORWARD -i "$WG_INTERFACE" -j ACCEPT
    iptables -A FORWARD -o "$WG_INTERFACE" -j ACCEPT
    iptables -t nat -A POSTROUTING -o "$EXTERNAL_INTERFACE" -j MASQUERADE
    
    # Configure ip6tables rules
    ip6tables -A INPUT -p udp --dport "$WG_PORT" -j ACCEPT
    ip6tables -A FORWARD -i "$WG_INTERFACE" -j ACCEPT
    ip6tables -A FORWARD -o "$WG_INTERFACE" -j ACCEPT
    ip6tables -t nat -A POSTROUTING -o "$EXTERNAL_INTERFACE" -j MASQUERADE
    
    # Save iptables rules
    if command -v iptables-save >/dev/null 2>&1; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
    fi
    
    # Configure UFW if present
    if command -v ufw >/dev/null 2>&1; then
        ufw allow "$WG_PORT"/udp
        ufw --force enable
    fi
    
    success "Firewall configured successfully"
}

# Function to create systemd service
create_systemd_service() {
    info "Configuring systemd service..."
    
    # Enable and start WireGuard service
    systemctl enable wg-quick@"$WG_INTERFACE"
    
    # Create custom service file with additional security
    cat > "/etc/systemd/system/wg-quick@${WG_INTERFACE}.service.d/override.conf" << EOF
[Unit]
Description=WireGuard via wg-quick(8) for %I
After=network-online.target nss-lookup.target
Wants=network-online.target nss-lookup.target
PartOf=wg-quick.target
Documentation=man:wg-quick(8)
Documentation=man:wg(8)
Documentation=https://www.wireguard.com/
Documentation=https://www.wireguard.com/quickstart/

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/wg-quick up %I
ExecStop=/usr/bin/wg-quick down %I
ExecReload=/bin/bash -c 'exec /usr/bin/wg syncconf %I <(exec /usr/bin/wg-quick strip %I)'
Environment=WG_ENDPOINT_RESOLUTION_RETRIES=infinity

# Security settings
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/etc/wireguard
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes

[Install]
WantedBy=multi-user.target
EOF
    
    mkdir -p "/etc/systemd/system/wg-quick@${WG_INTERFACE}.service.d"
    systemctl daemon-reload
    
    success "Systemd service configured"
}

# Function to create client directory structure
create_client_structure() {
    info "Creating client directory structure..."
    
    local client_dir="$CONFIG_DIR/clients"
    mkdir -p "$client_dir"
    chmod 700 "$client_dir"
    
    # Create client template
    cat > "$client_dir/client-template.conf" << EOF
# WireGuard Client Configuration Template
# Replace placeholders with actual values

[Interface]
PrivateKey = CLIENT_PRIVATE_KEY
Address = CLIENT_IP_ADDRESS/32
DNS = $DNS_SERVERS

[Peer]
PublicKey = $(cat "$CONFIG_DIR/${WG_INTERFACE}_public.key")
Endpoint = $SERVER_PUBLIC_IP:$WG_PORT
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF
    
    success "Client directory structure created"
}

# Function to create management scripts
create_management_scripts() {
    info "Creating management scripts..."
    
    local scripts_dir="/usr/local/bin"
    
    # Create add-client script
    cat > "$scripts_dir/wg-add-client" << 'EOF'
#!/bin/bash
# WireGuard client addition script

set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <client-name> [client-ip]"
    exit 1
fi

CLIENT_NAME="$1"
WG_INTERFACE="wg0"
CONFIG_DIR="/etc/wireguard"
CLIENT_DIR="$CONFIG_DIR/clients"

# Generate next available IP
if [[ $# -lt 2 ]]; then
    NETWORK=$(grep "Address" "$CONFIG_DIR/$WG_INTERFACE.conf" | cut -d'=' -f2 | xargs | cut -d'/' -f1)
    SUBNET=$(echo "$NETWORK" | cut -d'.' -f1-3)
    
    # Find next available IP
    for i in {2..254}; do
        IP="$SUBNET.$i"
        if ! grep -q "$IP" "$CONFIG_DIR/$WG_INTERFACE.conf"; then
            CLIENT_IP="$IP"
            break
        fi
    done
else
    CLIENT_IP="$2"
fi

# Generate client keys
CLIENT_PRIVATE_KEY=$(wg genkey)
CLIENT_PUBLIC_KEY=$(echo "$CLIENT_PRIVATE_KEY" | wg pubkey)

# Get server public key
SERVER_PUBLIC_KEY=$(cat "$CONFIG_DIR/${WG_INTERFACE}_public.key")
SERVER_ENDPOINT=$(grep "ListenPort" "$CONFIG_DIR/$WG_INTERFACE.conf" | cut -d'=' -f2 | xargs)

# Create client config
cat > "$CLIENT_DIR/$CLIENT_NAME.conf" << EOL
[Interface]
PrivateKey = $CLIENT_PRIVATE_KEY
Address = $CLIENT_IP/32
DNS = 1.1.1.1, 1.0.0.1

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = YOUR_SERVER_IP:$SERVER_ENDPOINT
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOL

# Add peer to server config
cat >> "$CONFIG_DIR/$WG_INTERFACE.conf" << EOL

# Client: $CLIENT_NAME
[Peer]
PublicKey = $CLIENT_PUBLIC_KEY
AllowedIPs = $CLIENT_IP/32
EOL

# Generate QR code
qrencode -t ansiutf8 < "$CLIENT_DIR/$CLIENT_NAME.conf"
qrencode -o "$CLIENT_DIR/$CLIENT_NAME.png" < "$CLIENT_DIR/$CLIENT_NAME.conf"

echo "Client $CLIENT_NAME added with IP $CLIENT_IP"
echo "Configuration saved to: $CLIENT_DIR/$CLIENT_NAME.conf"
echo "QR code saved to: $CLIENT_DIR/$CLIENT_NAME.png"
echo "Restart WireGuard to apply changes: systemctl restart wg-quick@$WG_INTERFACE"
EOF
    
    chmod +x "$scripts_dir/wg-add-client"
    
    # Create remove-client script
    cat > "$scripts_dir/wg-remove-client" << 'EOF'
#!/bin/bash
# WireGuard client removal script

set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <client-name>"
    exit 1
fi

CLIENT_NAME="$1"
WG_INTERFACE="wg0"
CONFIG_DIR="/etc/wireguard"
CLIENT_DIR="$CONFIG_DIR/clients"

# Remove client files
rm -f "$CLIENT_DIR/$CLIENT_NAME.conf"
rm -f "$CLIENT_DIR/$CLIENT_NAME.png"

# Remove peer from server config
sed -i "/# Client: $CLIENT_NAME/,/^$/d" "$CONFIG_DIR/$WG_INTERFACE.conf"

echo "Client $CLIENT_NAME removed"
echo "Restart WireGuard to apply changes: systemctl restart wg-quick@$WG_INTERFACE"
EOF
    
    chmod +x "$scripts_dir/wg-remove-client"
    
    success "Management scripts created"
}

# Function to start WireGuard service
start_wireguard() {
    info "Starting WireGuard service..."
    
    # Start and enable the service
    systemctl start wg-quick@"$WG_INTERFACE"
    systemctl enable wg-quick@"$WG_INTERFACE"
    
    # Verify service is running
    if systemctl is-active --quiet wg-quick@"$WG_INTERFACE"; then
        success "WireGuard service started successfully"
    else
        error_exit "Failed to start WireGuard service"
    fi
    
    # Show interface status
    info "WireGuard interface status:"
    wg show "$WG_INTERFACE"
}

# Function to create monitoring configuration
create_monitoring_config() {
    info "Creating monitoring configuration..."
    
    # Create log rotation configuration
    cat > "/etc/logrotate.d/wireguard" << EOF
/var/log/zero-trust-vpn/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 root root
    postrotate
        systemctl reload rsyslog > /dev/null 2>&1 || true
    endscript
}
EOF
    
    # Create monitoring script
    cat > "/usr/local/bin/wg-monitor" << 'EOF'
#!/bin/bash
# WireGuard monitoring script

WG_INTERFACE="wg0"
LOG_FILE="/var/log/zero-trust-vpn/wireguard-monitor.log"

# Check if interface is up
if ! ip link show "$WG_INTERFACE" >/dev/null 2>&1; then
    echo "$(date): WireGuard interface $WG_INTERFACE is down" >> "$LOG_FILE"
    systemctl restart wg-quick@"$WG_INTERFACE"
fi

# Log connection statistics
echo "$(date): $(wg show "$WG_INTERFACE" | grep -c peer) peers connected" >> "$LOG_FILE"
EOF
    
    chmod +x "/usr/local/bin/wg-monitor"
    
    # Create cron job for monitoring
    echo "*/5 * * * * root /usr/local/bin/wg-monitor" > /etc/cron.d/wireguard-monitor
    
    success "Monitoring configuration created"
}

# Function to display setup summary
display_summary() {
    echo
    echo "============================================="
    echo "WireGuard Setup Complete!"
    echo "============================================="
    echo
    echo "Configuration Details:"
    echo "  Interface: $WG_INTERFACE"
    echo "  Port: $WG_PORT"
    echo "  Network: $WG_NETWORK"
    echo "  Server IP: $WG_SERVER_IP"
    echo "  Public IP: $SERVER_PUBLIC_IP"
    echo "  DNS Servers: $DNS_SERVERS"
    echo
    echo "Files Created:"
    echo "  Server Config: $CONFIG_DIR/${WG_INTERFACE}.conf"
    echo "  Private Key: $CONFIG_DIR/${WG_INTERFACE}_private.key"
    echo "  Public Key: $CONFIG_DIR/${WG_INTERFACE}_public.key"
    echo "  Client Directory: $CONFIG_DIR/clients/"
    echo
    echo "Management Commands:"
    echo "  Add Client: wg-add-client <name> [ip]"
    echo "  Remove Client: wg-remove-client <name>"
    echo "  Show Status: wg show $WG_INTERFACE"
    echo "  Restart Service: systemctl restart wg-quick@$WG_INTERFACE"
    echo
    echo "Next Steps:"
    echo "1. Update SERVER_PUBLIC_IP in client configurations"
    echo "2. Add clients using: wg-add-client <client-name>"
    echo "3. Configure firewall rules if needed"
    echo "4. Set up monitoring and alerting"
    echo
    echo "Security Recommendations:"
    echo "- Regularly rotate server keys"
    echo "- Monitor connection logs"
    echo "- Use certificate-based authentication"
    echo "- Implement network segmentation"
    echo
}

# Main execution
main() {
    echo "Zero Trust VPN - WireGuard Setup"
    echo "================================="
    echo
    
    # Detect network configuration
    detect_external_interface
    detect_server_ip
    
    # Install WireGuard
    if ! command -v wg >/dev/null 2>&1; then
        install_wireguard
    else
        info "WireGuard already installed"
    fi
    
    # Create configuration directory
    mkdir -p "$CONFIG_DIR"
    chmod 700 "$CONFIG_DIR"
    
    # Generate keys and configuration
    generate_server_keys
    create_server_config
    
    # Configure system
    configure_firewall
    create_systemd_service
    create_client_structure
    create_management_scripts
    create_monitoring_config
    
    # Start service
    start_wireguard
    
    # Display summary
    display_summary
    
    log "WireGuard setup completed successfully"
}

# Run main function
main "$@"