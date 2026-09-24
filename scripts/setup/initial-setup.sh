#!/bin/bash

# Zero Trust VPN Infrastructure Initial Setup Script
# Configures the complete Zero Trust VPN environment with WireGuard and Authelia

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
VPN_USER="${VPN_USER:-vpn}"
VPN_GROUP="${VPN_GROUP:-vpn}"
VPN_UID="${VPN_UID:-2000}"
VPN_GID="${VPN_GID:-2000}"

# Network Configuration
VPN_SUBNET="10.10.0.0/24"
VPN_SERVER_IP="10.10.0.1"
VPN_PORT="${VPN_PORT:-51820}"
DNS_SERVERS="${DNS_SERVERS:-1.1.1.1,8.8.8.8}"

# Paths
CONFIG_PATH="/opt/zero-trust-vpn"
CERTS_PATH="$CONFIG_PATH/certificates"
LOGS_PATH="/var/log/zero-trust-vpn"

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

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root for system configuration"
        exit 1
    fi
}

# Check system requirements
check_requirements() {
    log "Checking system requirements..."
    
    # Check OS
    if [[ ! -f /etc/os-release ]]; then
        error "Cannot determine operating system"
        exit 1
    fi
    
    source /etc/os-release
    if [[ "$ID" != "ubuntu" && "$ID" != "debian" ]]; then
        warning "This script is optimized for Ubuntu/Debian. Proceed with caution."
    fi
    
    # Check kernel version for WireGuard support
    local kernel_version=$(uname -r | cut -d. -f1-2)
    local major=$(echo $kernel_version | cut -d. -f1)
    local minor=$(echo $kernel_version | cut -d. -f2)
    
    if [[ $major -lt 5 || ($major -eq 5 && $minor -lt 6) ]]; then
        warning "Kernel version $kernel_version may not have native WireGuard support"
    fi
    
    # Check available disk space
    local available_space=$(df / | awk 'NR==2 {print $4}')
    local required_space=2097152  # 2GB in KB
    
    if [[ $available_space -lt $required_space ]]; then
        error "Insufficient disk space. At least 2GB required."
        exit 1
    fi
    
    # Check if Docker is installed
    if ! command -v docker &> /dev/null; then
        log "Installing Docker..."
        install_docker
    fi
    
    # Check if Docker Compose is installed
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        log "Installing Docker Compose..."
        install_docker_compose
    fi
    
    log "✓ System requirements check passed"
}

# Install Docker
install_docker() {
    log "Installing Docker..."
    
    # Remove old versions
    apt remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true
    
    # Install dependencies
    apt update
    apt install -y apt-transport-https ca-certificates curl gnupg lsb-release
    
    # Add Docker GPG key
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
    
    # Add Docker repository
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
    
    # Install Docker
    apt update
    apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    
    # Start and enable Docker
    systemctl start docker
    systemctl enable docker
    
    log "✓ Docker installed successfully"
}

# Install Docker Compose
install_docker_compose() {
    log "Installing Docker Compose..."
    
    # Download Docker Compose
    curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    
    # Make executable
    chmod +x /usr/local/bin/docker-compose
    
    # Create symlink
    ln -sf /usr/local/bin/docker-compose /usr/bin/docker-compose
    
    log "✓ Docker Compose installed successfully"
}

# Install WireGuard
install_wireguard() {
    log "Installing WireGuard..."
    
    # Update package list
    apt update
    
    # Install WireGuard
    apt install -y wireguard wireguard-tools
    
    # Enable IP forwarding
    echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
    echo 'net.ipv6.conf.all.forwarding=1' >> /etc/sysctl.conf
    sysctl -p
    
    log "✓ WireGuard installed successfully"
}

# Create VPN user and group
create_vpn_user() {
    log "Creating VPN user and group..."
    
    # Create group if it doesn't exist
    if ! getent group "$VPN_GROUP" &>/dev/null; then
        groupadd -g "$VPN_GID" "$VPN_GROUP"
        log "✓ Created group: $VPN_GROUP (GID: $VPN_GID)"
    else
        info "Group $VPN_GROUP already exists"
    fi
    
    # Create user if it doesn't exist
    if ! getent passwd "$VPN_USER" &>/dev/null; then
        useradd -u "$VPN_UID" -g "$VPN_GID" -d "/home/$VPN_USER" -m -s /bin/bash "$VPN_USER"
        log "✓ Created user: $VPN_USER (UID: $VPN_UID)"
    else
        info "User $VPN_USER already exists"
    fi
    
    # Add user to docker group
    usermod -aG docker "$VPN_USER"
    
    log "✓ VPN user configuration completed"
}

# Create directory structure
create_directories() {
    log "Creating directory structure..."
    
    # Create main directories
    mkdir -p "$CONFIG_PATH"/{wireguard,authelia,nginx,monitoring}
    mkdir -p "$CERTS_PATH"/{ca,server,clients,crl}
    mkdir -p "$LOGS_PATH"
    mkdir -p /etc/wireguard
    
    # Set ownership
    chown -R "$VPN_UID:$VPN_GID" "$CONFIG_PATH"
    chown -R "$VPN_UID:$VPN_GID" "$LOGS_PATH"
    chown -R root:root /etc/wireguard
    
    # Set permissions
    chmod -R 750 "$CONFIG_PATH"
    chmod -R 700 "$CERTS_PATH"
    chmod -R 755 "$LOGS_PATH"
    chmod 700 /etc/wireguard
    
    log "✓ Directory structure created"
    log "  Config path: $CONFIG_PATH"
    log "  Certificates: $CERTS_PATH"
    log "  Logs: $LOGS_PATH"
}

# Generate server keys
generate_server_keys() {
    log "Generating WireGuard server keys..."
    
    # Generate private key
    wg genkey | tee /etc/wireguard/server_private.key | wg pubkey > /etc/wireguard/server_public.key
    
    # Set permissions
    chmod 600 /etc/wireguard/server_private.key
    chmod 644 /etc/wireguard/server_public.key
    
    # Store keys in variables
    SERVER_PRIVATE_KEY=$(cat /etc/wireguard/server_private.key)
    SERVER_PUBLIC_KEY=$(cat /etc/wireguard/server_public.key)
    
    log "✓ Server keys generated"
    log "  Public key: $SERVER_PUBLIC_KEY"
}

# Configure WireGuard server
configure_wireguard_server() {
    log "Configuring WireGuard server..."
    
    # Get primary network interface
    local primary_interface=$(ip route | grep default | awk '{print $5}' | head -1)
    
    if [[ -z "$primary_interface" ]]; then
        error "Could not determine primary network interface"
        exit 1
    fi
    
    # Create server configuration
    cat > /etc/wireguard/wg0.conf << EOF
[Interface]
PrivateKey = $SERVER_PRIVATE_KEY
Address = $VPN_SERVER_IP/24
ListenPort = $VPN_PORT
SaveConfig = false

# Enable IP forwarding and NAT
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o $primary_interface -j MASQUERADE; ip6tables -A FORWARD -i %i -j ACCEPT; ip6tables -t nat -A POSTROUTING -o $primary_interface -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o $primary_interface -j MASQUERADE; ip6tables -D FORWARD -i %i -j ACCEPT; ip6tables -t nat -D POSTROUTING -o $primary_interface -j MASQUERADE

# Client configurations will be added here
EOF
    
    # Set permissions
    chmod 600 /etc/wireguard/wg0.conf
    
    log "✓ WireGuard server configured"
}

# Configure firewall
configure_firewall() {
    log "Configuring firewall..."
    
    # Install UFW if not present
    if ! command -v ufw &> /dev/null; then
        apt install -y ufw
    fi
    
    # Reset UFW to defaults
    ufw --force reset
    
    # Set default policies
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow SSH
    ufw allow ssh
    
    # Allow WireGuard
    ufw allow "$VPN_PORT/udp"
    
    # Allow HTTP and HTTPS for Authelia
    ufw allow 80/tcp
    ufw allow 443/tcp
    
    # Allow Authelia port
    ufw allow 9091/tcp
    
    # Enable UFW
    ufw --force enable
    
    log "✓ Firewall configured"
    ufw status
}

# Set up PKI infrastructure
setup_pki() {
    log "Setting up PKI infrastructure..."
    
    # Run PKI setup script
    "$SCRIPT_DIR/pki-setup.sh"
    
    log "✓ PKI infrastructure configured"
}

# Create environment configuration
create_environment_config() {
    log "Creating environment configuration..."
    
    # Generate secrets
    local jwt_secret=$(openssl rand -hex 32)
    local session_secret=$(openssl rand -hex 32)
    local storage_key=$(openssl rand -hex 32)
    local redis_password=$(openssl rand -hex 16)
    
    # Create .env file
    cat > "$PROJECT_ROOT/.env" << EOF
# Zero Trust VPN Configuration
# Generated by initial-setup.sh on $(date)

# Network Configuration
VPN_SUBNET=$VPN_SUBNET
VPN_SERVER_IP=$VPN_SERVER_IP
VPN_PORT=$VPN_PORT
DNS_SERVERS=$DNS_SERVERS

# User Configuration
VPN_USER=$VPN_USER
VPN_GROUP=$VPN_GROUP
VPN_UID=$VPN_UID
VPN_GID=$VPN_GID

# Paths
CONFIG_PATH=$CONFIG_PATH
CERTS_PATH=$CERTS_PATH
LOGS_PATH=$LOGS_PATH

# Domain Configuration (customize these)
DOMAIN=vpn.example.com
AUTH_DOMAIN=auth.vpn.example.com

# Authelia Secrets
JWT_SECRET=$jwt_secret
SESSION_SECRET=$session_secret
STORAGE_ENCRYPTION_KEY=$storage_key
REDIS_PASSWORD=$redis_password

# Database Configuration
DB_HOST=postgres
DB_PORT=5432
DB_NAME=authelia
DB_USER=authelia
DB_PASSWORD=$(openssl rand -hex 16)

# SMTP Configuration (customize these)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_SENDER=authelia@vpn.example.com

# Notification Configuration
ADMIN_EMAIL=admin@example.com
SECURITY_EMAIL=security@example.com

# Monitoring Configuration
ENABLE_MONITORING=true
PROMETHEUS_PORT=9090
GRAFANA_PORT=3000
GRAFANA_PASSWORD=$(openssl rand -hex 16)

# WireGuard Keys
SERVER_PRIVATE_KEY=$SERVER_PRIVATE_KEY
SERVER_PUBLIC_KEY=$SERVER_PUBLIC_KEY
EOF
    
    # Set permissions
    chmod 600 "$PROJECT_ROOT/.env"
    chown "$VPN_UID:$VPN_GID" "$PROJECT_ROOT/.env"
    
    log "✓ Environment configuration created"
    warning "Please customize the domain and SMTP settings in .env file"
}

# Create systemd services
create_systemd_services() {
    log "Creating systemd services..."
    
    # WireGuard service
    cat > /etc/systemd/system/wg-quick@wg0.service.d/override.conf << EOF
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
ExecStart=/usr/bin/wg-quick up %i
ExecStop=/usr/bin/wg-quick down %i
ExecReload=/bin/bash -c 'exec /usr/bin/wg syncconf %i <(exec /usr/bin/wg-quick strip %i)'
Environment=WG_ENDPOINT_RESOLUTION_RETRIES=infinity

[Install]
WantedBy=multi-user.target
EOF
    
    # Zero Trust VPN service
    cat > /etc/systemd/system/zero-trust-vpn.service << EOF
[Unit]
Description=Zero Trust VPN Infrastructure
Documentation=https://github.com/Xieonie/zero-trust-vpn-infrastructure
Requires=docker.service
After=docker.service wg-quick@wg0.service
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
User=$VPN_USER
Group=$VPN_GROUP
WorkingDirectory=$PROJECT_ROOT/config-examples/docker
ExecStart=/usr/bin/docker-compose up -d
ExecStop=/usr/bin/docker-compose down
ExecReload=/usr/bin/docker-compose restart
TimeoutStartSec=300
TimeoutStopSec=120
Environment=COMPOSE_PROJECT_NAME=zero-trust-vpn

[Install]
WantedBy=multi-user.target
EOF
    
    # Reload systemd and enable services
    systemctl daemon-reload
    systemctl enable wg-quick@wg0.service
    systemctl enable zero-trust-vpn.service
    
    log "✓ Systemd services created and enabled"
}

# Create monitoring configuration
create_monitoring_config() {
    log "Creating monitoring configuration..."
    
    # Create Prometheus configuration
    mkdir -p "$CONFIG_PATH/prometheus"
    cat > "$CONFIG_PATH/prometheus/prometheus.yml" << EOF
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "rules/*.yml"

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'wireguard'
    static_configs:
      - targets: ['wireguard-exporter:9586']

  - job_name: 'authelia'
    static_configs:
      - targets: ['authelia:9091']

  - job_name: 'node'
    static_configs:
      - targets: ['node-exporter:9100']
EOF
    
    # Create alert rules
    mkdir -p "$CONFIG_PATH/prometheus/rules"
    cat > "$CONFIG_PATH/prometheus/rules/vpn-alerts.yml" << EOF
groups:
  - name: vpn_alerts
    rules:
      - alert: WireGuardDown
        expr: up{job="wireguard"} == 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "WireGuard is down"
          description: "WireGuard has been down for more than 5 minutes."

      - alert: AutheliaDown
        expr: up{job="authelia"} == 0
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "Authelia is down"
          description: "Authelia authentication service has been down for more than 2 minutes."

      - alert: HighConnectionCount
        expr: wireguard_device_peers > 100
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "High VPN connection count"
          description: "VPN has more than 100 active connections."

      - alert: FailedAuthenticationAttempts
        expr: increase(authelia_authentication_failed_total[5m]) > 10
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: "High authentication failure rate"
          description: "More than 10 authentication failures in the last 5 minutes."
EOF
    
    # Set ownership
    chown -R "$VPN_UID:$VPN_GID" "$CONFIG_PATH/prometheus"
    
    log "✓ Monitoring configuration created"
}

# Create backup script
create_backup_script() {
    log "Creating backup script..."
    
    cat > "$PROJECT_ROOT/scripts/maintenance/backup-vpn-config.sh" << 'EOF'
#!/bin/bash

# Zero Trust VPN Configuration Backup Script

set -euo pipefail

BACKUP_DIR="/opt/backups/zero-trust-vpn"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
CONFIG_PATH="${CONFIG_PATH:-/opt/zero-trust-vpn}"

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Create backup
tar -czf "$BACKUP_DIR/zero-trust-vpn-config-$TIMESTAMP.tar.gz" \
    -C "$(dirname "$CONFIG_PATH")" \
    "$(basename "$CONFIG_PATH")" \
    --exclude="*.log" \
    --exclude="*.pid"

# Backup WireGuard configuration
cp -r /etc/wireguard "$BACKUP_DIR/wireguard-$TIMESTAMP"

# Keep only last 30 backups
find "$BACKUP_DIR" -name "zero-trust-vpn-config-*.tar.gz" -type f -mtime +30 -delete
find "$BACKUP_DIR" -name "wireguard-*" -type d -mtime +30 -exec rm -rf {} +

echo "Backup completed: $BACKUP_DIR/zero-trust-vpn-config-$TIMESTAMP.tar.gz"
EOF
    
    chmod +x "$PROJECT_ROOT/scripts/maintenance/backup-vpn-config.sh"
    
    log "✓ Backup script created"
}

# Display next steps
display_next_steps() {
    log "Initial setup completed successfully!"
    echo ""
    echo "Next steps:"
    echo "=========="
    echo "1. Customize configuration:"
    echo "   - Edit $PROJECT_ROOT/.env with your domain and SMTP settings"
    echo "   - Review WireGuard configuration in /etc/wireguard/wg0.conf"
    echo ""
    echo "2. Set up SSL certificates:"
    echo "   - Run: $SCRIPT_DIR/ssl-setup.sh"
    echo ""
    echo "3. Configure Authelia:"
    echo "   - Edit $CONFIG_PATH/authelia/configuration.yml"
    echo "   - Set up user database"
    echo ""
    echo "4. Start services:"
    echo "   - systemctl start wg-quick@wg0"
    echo "   - systemctl start zero-trust-vpn"
    echo ""
    echo "5. Add users:"
    echo "   - $PROJECT_ROOT/scripts/management/add-user.sh username email@domain.com"
    echo ""
    echo "6. Test connectivity:"
    echo "   - Access https://auth.$DOMAIN"
    echo "   - Test VPN connection with generated client config"
    echo ""
    echo "Important files:"
    echo "==============="
    echo "- Environment config: $PROJECT_ROOT/.env"
    echo "- WireGuard config: /etc/wireguard/wg0.conf"
    echo "- Server public key: $SERVER_PUBLIC_KEY"
    echo "- Logs: $LOGS_PATH"
    echo ""
    echo "Security notes:"
    echo "=============="
    echo "- Change all default passwords"
    echo "- Configure proper SSL certificates"
    echo "- Review firewall rules"
    echo "- Set up monitoring and alerting"
    echo "- Test backup and recovery procedures"
}

# Main setup function
main() {
    log "Starting Zero Trust VPN Infrastructure setup..."
    
    check_root
    check_requirements
    install_wireguard
    create_vpn_user
    create_directories
    generate_server_keys
    configure_wireguard_server
    configure_firewall
    setup_pki
    create_environment_config
    create_systemd_services
    create_monitoring_config
    create_backup_script
    
    display_next_steps
    
    log "Zero Trust VPN Infrastructure setup completed successfully!"
}

# Handle script arguments
case "${1:-}" in
    --help|-h)
        echo "Usage: $0 [options]"
        echo ""
        echo "Options:"
        echo "  --help, -h     Show this help message"
        echo "  --unattended   Run in unattended mode with defaults"
        echo ""
        echo "Environment variables:"
        echo "  VPN_USER       Username for VPN service (default: vpn)"
        echo "  VPN_GROUP      Group name for VPN service (default: vpn)"
        echo "  VPN_UID        User ID (default: 2000)"
        echo "  VPN_GID        Group ID (default: 2000)"
        echo "  VPN_PORT       WireGuard port (default: 51820)"
        echo "  DNS_SERVERS    DNS servers for clients (default: 1.1.1.1,8.8.8.8)"
        echo ""
        exit 0
        ;;
    --unattended)
        # Set defaults for unattended installation
        export DEBIAN_FRONTEND=noninteractive
        main
        ;;
    *)
        main
        ;;
esac