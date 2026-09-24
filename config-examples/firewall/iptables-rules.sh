#!/bin/bash

# Zero Trust VPN Infrastructure - iptables Rules
# This script configures iptables rules for a Zero Trust VPN setup
# 
# Network Layout:
# - WireGuard VPN: 10.0.2.0/24
# - Internal Services: 10.0.1.0/24
# - LAN Network: 192.168.1.0/24

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
WG_INTERFACE="wg0"
WG_NETWORK="10.0.2.0/24"
SERVICES_NETWORK="10.0.1.0/24"
LAN_NETWORK="192.168.1.0/24"
WG_PORT="51820"
AUTHELIA_IP="10.0.1.100"
AUTHELIA_PORT="9091"

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

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root"
fi

# Backup existing rules
backup_rules() {
    log "Backing up existing iptables rules..."
    iptables-save > /etc/iptables/rules.v4.backup.$(date +%Y%m%d_%H%M%S) || warn "Could not backup IPv4 rules"
    ip6tables-save > /etc/iptables/rules.v6.backup.$(date +%Y%m%d_%H%M%S) || warn "Could not backup IPv6 rules"
}

# Clear existing rules
clear_rules() {
    log "Clearing existing iptables rules..."
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
    iptables -t mangle -F
    iptables -t mangle -X
    
    # Set default policies
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
}

# Basic security rules
setup_basic_rules() {
    log "Setting up basic security rules..."
    
    # Allow loopback
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    
    # Allow established and related connections
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    
    # Drop invalid packets
    iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
    iptables -A FORWARD -m conntrack --ctstate INVALID -j DROP
    
    # Rate limit SSH connections
    iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set
    iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 4 -j DROP
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    
    # Allow ICMP (ping) with rate limiting
    iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 2 -j ACCEPT
}

# WireGuard specific rules
setup_wireguard_rules() {
    log "Setting up WireGuard rules..."
    
    # Allow WireGuard traffic on UDP port
    iptables -A INPUT -p udp --dport $WG_PORT -j ACCEPT
    
    # Enable IP forwarding for WireGuard
    echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
    sysctl -p
    
    # NAT for WireGuard clients
    iptables -t nat -A POSTROUTING -s $WG_NETWORK -o eth0 -j MASQUERADE
    
    # Allow WireGuard interface traffic
    iptables -A INPUT -i $WG_INTERFACE -j ACCEPT
}

# Zero Trust rules
setup_zero_trust_rules() {
    log "Setting up Zero Trust rules..."
    
    # Block direct access from VPN to LAN (Zero Trust principle)
    iptables -A FORWARD -i $WG_INTERFACE -d $LAN_NETWORK -j DROP
    
    # Allow VPN clients to access Authelia for authentication
    iptables -A FORWARD -i $WG_INTERFACE -d $AUTHELIA_IP -p tcp --dport $AUTHELIA_PORT -j ACCEPT
    
    # Allow authenticated access to services network (via reverse proxy)
    iptables -A FORWARD -i $WG_INTERFACE -d $SERVICES_NETWORK -p tcp --dport 443 -j ACCEPT
    iptables -A FORWARD -i $WG_INTERFACE -d $SERVICES_NETWORK -p tcp --dport 80 -j ACCEPT
    
    # Allow DNS queries
    iptables -A FORWARD -i $WG_INTERFACE -p udp --dport 53 -j ACCEPT
    iptables -A FORWARD -i $WG_INTERFACE -p tcp --dport 53 -j ACCEPT
    
    # Allow NTP for time synchronization
    iptables -A FORWARD -i $WG_INTERFACE -p udp --dport 123 -j ACCEPT
    
    # Log dropped packets for monitoring
    iptables -A FORWARD -i $WG_INTERFACE -j LOG --log-prefix "ZT-VPN-DROP: " --log-level 4
    iptables -A FORWARD -i $WG_INTERFACE -j DROP
}

# Monitoring and logging rules
setup_monitoring_rules() {
    log "Setting up monitoring and logging rules..."
    
    # Log suspicious activity
    iptables -A INPUT -p tcp --tcp-flags ALL NONE -j LOG --log-prefix "NULL-SCAN: "
    iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
    
    iptables -A INPUT -p tcp --tcp-flags ALL ALL -j LOG --log-prefix "XMAS-SCAN: "
    iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
    
    # Log and drop port scans
    iptables -A INPUT -p tcp --tcp-flags ALL FIN,URG,PSH -j LOG --log-prefix "NMAP-SCAN: "
    iptables -A INPUT -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP
    
    # Rate limit logging to prevent log flooding
    iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "DROPPED: " --log-level 7
}

# Save rules
save_rules() {
    log "Saving iptables rules..."
    
    # Install iptables-persistent if not present
    if ! dpkg -l | grep -q iptables-persistent; then
        log "Installing iptables-persistent..."
        apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent
    fi
    
    # Save current rules
    iptables-save > /etc/iptables/rules.v4
    ip6tables-save > /etc/iptables/rules.v6
    
    log "Rules saved to /etc/iptables/rules.v4"
}

# Main execution
main() {
    log "Starting Zero Trust VPN iptables configuration..."
    
    backup_rules
    clear_rules
    setup_basic_rules
    setup_wireguard_rules
    setup_zero_trust_rules
    setup_monitoring_rules
    save_rules
    
    log "Zero Trust VPN iptables configuration completed successfully!"
    log "Current rule count: $(iptables -L | grep -c '^Chain')"
    
    warn "Please test your configuration thoroughly before deploying to production!"
    warn "Monitor logs with: tail -f /var/log/kern.log | grep -E '(ZT-VPN|DROPPED|SCAN)'"
}

# Script execution
case "${1:-}" in
    "clear")
        log "Clearing all iptables rules..."
        iptables -F
        iptables -X
        iptables -t nat -F
        iptables -t nat -X
        iptables -P INPUT ACCEPT
        iptables -P FORWARD ACCEPT
        iptables -P OUTPUT ACCEPT
        log "All rules cleared. WARNING: System is now unprotected!"
        ;;
    "status")
        echo "=== Current iptables rules ==="
        iptables -L -n -v
        echo ""
        echo "=== NAT rules ==="
        iptables -t nat -L -n -v
        ;;
    "test")
        log "Testing configuration (dry run)..."
        # Add test commands here
        log "Test completed"
        ;;
    *)
        main
        ;;
esac