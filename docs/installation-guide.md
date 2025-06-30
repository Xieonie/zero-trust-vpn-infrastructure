# Zero Trust VPN Installation Guide

## Prerequisites

### System Requirements

**Minimum Hardware:**
- CPU: 4 cores (8 recommended)
- RAM: 8GB (16GB recommended)
- Storage: 100GB SSD (500GB recommended)
- Network: 1Gbps interface

**Supported Operating Systems:**
- Ubuntu 20.04 LTS or newer
- Debian 11 or newer
- CentOS 8 or newer
- Rocky Linux 8 or newer

**Required Software:**
- Docker 20.10+
- Docker Compose 2.0+
- Git
- OpenSSL
- curl/wget

### Network Requirements

**Firewall Ports:**
```bash
# WireGuard VPN
51820/udp

# Authelia Web Interface
9091/tcp

# LDAP/FreeIPA
389/tcp (LDAP)
636/tcp (LDAPS)
88/tcp (Kerberos)
464/tcp (Kerberos Password)

# Monitoring
3000/tcp (Grafana)
9090/tcp (Prometheus)
5601/tcp (Kibana)
```

**DNS Requirements:**
- Internal DNS server or external DNS with internal records
- Reverse DNS entries for all servers
- Certificate authority for SSL/TLS certificates

## Installation Steps

### Step 1: System Preparation

```bash
#!/bin/bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install required packages
sudo apt install -y \
    curl \
    wget \
    git \
    openssl \
    ca-certificates \
    gnupg \
    lsb-release \
    ufw \
    fail2ban

# Install Docker
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Add user to docker group
sudo usermod -aG docker $USER

# Enable and start Docker
sudo systemctl enable docker
sudo systemctl start docker
```

### Step 2: Clone Repository

```bash
# Clone the repository
git clone https://github.com/yourusername/zero-trust-vpn-infrastructure.git
cd zero-trust-vpn-infrastructure

# Make scripts executable
chmod +x scripts/**/*.sh
```

### Step 3: Initial Setup

```bash
# Run initial setup script
sudo ./scripts/setup/initial-setup.sh

# This script will:
# - Configure firewall rules
# - Set up directory structure
# - Generate initial certificates
# - Create Docker networks
# - Set up logging
```

### Step 4: PKI Setup

```bash
# Set up Public Key Infrastructure
sudo ./scripts/setup/pki-setup.sh

# This creates:
# - Root Certificate Authority
# - Intermediate CAs
# - Server certificates
# - Client certificate templates
```

### Step 5: WireGuard Configuration

```bash
# Configure WireGuard VPN server
sudo ./scripts/setup/wireguard-setup.sh

# Parameters you'll be prompted for:
# - Server IP address
# - Network subnet
# - DNS servers
# - Port number (default: 51820)
```

### Step 6: Authelia Setup

```bash
# Configure Authelia authentication server
sudo ./scripts/setup/authelia-setup.sh

# Configuration includes:
# - LDAP connection settings
# - MFA configuration
# - Access control policies
# - Session management
```

### Step 7: Docker Deployment

```bash
# Copy environment template
cp config-examples/docker/.env.example .env

# Edit environment variables
nano .env

# Deploy the stack
docker-compose up -d

# Verify deployment
docker-compose ps
```

## Configuration Details

### Environment Variables

```bash
# .env file configuration
# Domain and networking
DOMAIN=vpn.yourdomain.com
INTERNAL_NETWORK=10.0.0.0/24
VPN_NETWORK=10.8.0.0/24

# WireGuard settings
WG_HOST=vpn.yourdomain.com
WG_PORT=51820
WG_DEFAULT_DNS=10.0.0.1

# Authelia settings
AUTHELIA_JWT_SECRET=your-jwt-secret-here
AUTHELIA_SESSION_SECRET=your-session-secret-here
AUTHELIA_STORAGE_ENCRYPTION_KEY=your-encryption-key-here

# LDAP settings
LDAP_URL=ldap://ldap.yourdomain.com:389
LDAP_BASE_DN=dc=yourdomain,dc=com
LDAP_USER=cn=admin,dc=yourdomain,dc=com
LDAP_PASSWORD=your-ldap-password

# Database settings
POSTGRES_DB=authelia
POSTGRES_USER=authelia
POSTGRES_PASSWORD=your-db-password

# Redis settings
REDIS_PASSWORD=your-redis-password

# Monitoring
GRAFANA_ADMIN_PASSWORD=your-grafana-password
PROMETHEUS_RETENTION=30d
```

### WireGuard Server Configuration

```ini
# /etc/wireguard/wg0.conf
[Interface]
PrivateKey = SERVER_PRIVATE_KEY
Address = 10.8.0.1/24
ListenPort = 51820
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

# Client configurations will be added here
```

### Authelia Configuration

```yaml
# config/authelia/configuration.yml
server:
  host: 0.0.0.0
  port: 9091
  path: ""
  read_buffer_size: 4096
  write_buffer_size: 4096

log:
  level: info
  format: text

jwt_secret: ${AUTHELIA_JWT_SECRET}

default_redirection_url: https://auth.yourdomain.com

authentication_backend:
  ldap:
    url: ${LDAP_URL}
    base_dn: ${LDAP_BASE_DN}
    username_attribute: uid
    additional_users_dn: ou=users
    users_filter: (&({username_attribute}={input})(objectClass=person))
    additional_groups_dn: ou=groups
    groups_filter: (&(member={dn})(objectClass=groupOfNames))
    group_name_attribute: cn
    mail_attribute: mail
    display_name_attribute: displayName
    user: ${LDAP_USER}
    password: ${LDAP_PASSWORD}

access_control:
  default_policy: deny
  rules:
    - domain: "vpn.yourdomain.com"
      policy: two_factor
      
    - domain: "admin.yourdomain.com"
      policy: two_factor
      subject: "group:administrators"

session:
  name: authelia_session
  secret: ${AUTHELIA_SESSION_SECRET}
  expiration: 1h
  inactivity: 5m
  remember_me_duration: 1M

regulation:
  max_retries: 3
  find_time: 2m
  ban_time: 5m

storage:
  encryption_key: ${AUTHELIA_STORAGE_ENCRYPTION_KEY}
  postgres:
    host: postgres
    port: 5432
    database: ${POSTGRES_DB}
    username: ${POSTGRES_USER}
    password: ${POSTGRES_PASSWORD}

notifier:
  smtp:
    username: noreply@yourdomain.com
    password: your-smtp-password
    host: smtp.yourdomain.com
    port: 587
    sender: noreply@yourdomain.com
```

## Post-Installation Configuration

### Step 1: Verify Services

```bash
# Check all services are running
docker-compose ps

# Check logs for any errors
docker-compose logs -f

# Test WireGuard
sudo wg show

# Test Authelia
curl -k https://localhost:9091/api/health
```

### Step 2: Create First User

```bash
# Add user to LDAP
./scripts/management/add-user.sh \
  --username admin \
  --email admin@yourdomain.com \
  --groups administrators \
  --generate-vpn-config

# This will:
# - Create LDAP user account
# - Generate WireGuard client config
# - Set up MFA enrollment
```

### Step 3: Configure Client Access

```bash
# Generate client configuration
./scripts/management/device-enrollment.sh \
  --user admin \
  --device laptop \
  --platform linux

# Download client config
scp root@vpn-server:/etc/wireguard/clients/admin-laptop.conf ./
```

### Step 4: Test Connection

```bash
# On client machine
sudo wg-quick up admin-laptop

# Test connectivity
ping 10.8.0.1
curl -k https://auth.yourdomain.com

# Check logs on server
tail -f /var/log/wireguard.log
```

## Security Hardening

### System Hardening

```bash
# Disable SSH password authentication
sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo systemctl restart ssh

# Configure fail2ban
sudo cp config-examples/fail2ban/jail.local /etc/fail2ban/
sudo systemctl restart fail2ban

# Set up automatic updates
sudo apt install unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades
```

### Firewall Configuration

```bash
# Configure UFW
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow SSH (change port if needed)
sudo ufw allow 22/tcp

# Allow WireGuard
sudo ufw allow 51820/udp

# Allow web services (if needed)
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Enable firewall
sudo ufw enable
```

### Certificate Management

```bash
# Set up automatic certificate renewal
sudo crontab -e

# Add this line for monthly renewal
0 2 1 * * /opt/zero-trust-vpn/scripts/automation/cert-renewal.sh
```

## Monitoring Setup

### Prometheus Configuration

```yaml
# config/prometheus/prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "rules/*.yml"

scrape_configs:
  - job_name: 'wireguard'
    static_configs:
      - targets: ['wireguard-exporter:9586']
      
  - job_name: 'authelia'
    static_configs:
      - targets: ['authelia:9091']
      
  - job_name: 'node'
    static_configs:
      - targets: ['node-exporter:9100']
```

### Grafana Dashboards

```bash
# Import pre-configured dashboards
curl -X POST \
  http://admin:${GRAFANA_ADMIN_PASSWORD}@localhost:3000/api/dashboards/db \
  -H 'Content-Type: application/json' \
  -d @config/grafana/dashboards/wireguard-dashboard.json
```

## Troubleshooting

### Common Issues

**WireGuard not starting:**
```bash
# Check configuration
sudo wg-quick down wg0
sudo wg-quick up wg0

# Check logs
journalctl -u wg-quick@wg0
```

**Authelia authentication failing:**
```bash
# Check LDAP connectivity
ldapsearch -x -H ${LDAP_URL} -D "${LDAP_USER}" -w "${LDAP_PASSWORD}" -b "${LDAP_BASE_DN}"

# Check Authelia logs
docker-compose logs authelia
```

**Client connectivity issues:**
```bash
# Check routing
ip route show table all

# Check iptables rules
sudo iptables -L -n -v

# Check DNS resolution
nslookup yourdomain.com
```

### Log Locations

```bash
# System logs
/var/log/syslog
/var/log/auth.log

# Application logs
/var/log/wireguard/
/var/log/authelia/
/var/log/fail2ban.log

# Docker logs
docker-compose logs [service_name]
```

## Backup and Recovery

### Backup Procedures

```bash
# Run backup script
./scripts/automation/backup.sh

# Manual backup
tar -czf backup-$(date +%Y%m%d).tar.gz \
  /etc/wireguard/ \
  /opt/zero-trust-vpn/config/ \
  /opt/zero-trust-vpn/certificates/
```

### Recovery Procedures

```bash
# Restore from backup
tar -xzf backup-20231201.tar.gz -C /

# Restart services
docker-compose down
docker-compose up -d

# Verify functionality
./scripts/monitoring/health-check.sh
```

## Maintenance

### Regular Tasks

**Daily:**
- Monitor system logs
- Check service health
- Review security alerts

**Weekly:**
- Update system packages
- Review access logs
- Check certificate expiration

**Monthly:**
- Rotate log files
- Update security policies
- Test backup/recovery procedures

**Quarterly:**
- Security audit
- Performance review
- Disaster recovery test

## Support and Documentation

### Additional Resources
- [WireGuard Documentation](https://www.wireguard.com/quickstart/)
- [Authelia Documentation](https://www.authelia.com/docs/)
- [Docker Compose Reference](https://docs.docker.com/compose/)

### Getting Help
- Check the troubleshooting section
- Review application logs
- Consult the project documentation
- Open an issue on GitHub