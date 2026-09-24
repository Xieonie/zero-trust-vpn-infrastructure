#!/bin/bash

# Zero Trust VPN - Authelia Setup Script
# This script sets up and configures Authelia authentication server

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
CONFIG_DIR="/opt/zero-trust-vpn/config/authelia"
LOG_FILE="/var/log/zero-trust-vpn/authelia-setup.log"
DOCKER_COMPOSE_DIR="$PROJECT_DIR/docker"

# Default values
DOMAIN="auth.company.com"
LDAP_URL="ldap://localhost:389"
LDAP_BASE_DN="dc=company,dc=com"
POSTGRES_DB="authelia"
REDIS_DB="0"

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

# Success function
success() {
    echo -e "${GREEN}SUCCESS: $1${NC}"
    log "SUCCESS: $1"
}

# Warning function
warning() {
    echo -e "${YELLOW}WARNING: $1${NC}"
    log "WARNING: $1"
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

Set up Authelia authentication server for Zero Trust VPN

OPTIONS:
    -d, --domain DOMAIN         Authelia domain (default: auth.company.com)
    -l, --ldap-url URL          LDAP server URL (default: ldap://localhost:389)
    -b, --base-dn DN            LDAP base DN (default: dc=company,dc=com)
    -p, --postgres-db DB        PostgreSQL database name (default: authelia)
    -r, --redis-db DB           Redis database number (default: 0)
    -f, --file-backend          Use file-based authentication instead of LDAP
    -s, --skip-docker           Skip Docker container setup
    -h, --help                  Show this help message

EXAMPLES:
    $0                          # Default setup with LDAP
    $0 --file-backend           # Setup with file-based auth
    $0 --domain auth.example.com --ldap-url ldap://dc.example.com

EOF
}

# Parse command line arguments
FILE_BACKEND=false
SKIP_DOCKER=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--domain)
            DOMAIN="$2"
            shift 2
            ;;
        -l|--ldap-url)
            LDAP_URL="$2"
            shift 2
            ;;
        -b|--base-dn)
            LDAP_BASE_DN="$2"
            shift 2
            ;;
        -p|--postgres-db)
            POSTGRES_DB="$2"
            shift 2
            ;;
        -r|--redis-db)
            REDIS_DB="$2"
            shift 2
            ;;
        -f|--file-backend)
            FILE_BACKEND=true
            shift
            ;;
        -s|--skip-docker)
            SKIP_DOCKER=true
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

log "Starting Authelia setup with domain: $DOMAIN"

# Function to generate secure secrets
generate_secrets() {
    info "Generating secure secrets..."
    
    # Generate JWT secret
    JWT_SECRET=$(openssl rand -base64 64 | tr -d '\n')
    
    # Generate session secret
    SESSION_SECRET=$(openssl rand -base64 64 | tr -d '\n')
    
    # Generate storage encryption key
    STORAGE_ENCRYPTION_KEY=$(openssl rand -base64 64 | tr -d '\n')
    
    # Generate HMAC secret for OIDC
    OIDC_HMAC_SECRET=$(openssl rand -base64 64 | tr -d '\n')
    
    # Generate database passwords
    POSTGRES_PASSWORD=$(openssl rand -base64 32 | tr -d '\n')
    REDIS_PASSWORD=$(openssl rand -base64 32 | tr -d '\n')
    LDAP_PASSWORD=$(openssl rand -base64 32 | tr -d '\n')
    
    success "Secrets generated"
}

# Function to create configuration directory
create_config_directory() {
    info "Creating Authelia configuration directory..."
    
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$CONFIG_DIR/secrets"
    mkdir -p "$CONFIG_DIR/users"
    mkdir -p "$CONFIG_DIR/certificates"
    
    # Set proper permissions
    chmod 700 "$CONFIG_DIR"
    chmod 700 "$CONFIG_DIR/secrets"
    
    success "Configuration directory created"
}

# Function to create secrets files
create_secrets_files() {
    info "Creating secrets files..."
    
    # JWT secret
    echo "$JWT_SECRET" > "$CONFIG_DIR/secrets/jwt_secret"
    chmod 600 "$CONFIG_DIR/secrets/jwt_secret"
    
    # Session secret
    echo "$SESSION_SECRET" > "$CONFIG_DIR/secrets/session_secret"
    chmod 600 "$CONFIG_DIR/secrets/session_secret"
    
    # Storage encryption key
    echo "$STORAGE_ENCRYPTION_KEY" > "$CONFIG_DIR/secrets/storage_encryption_key"
    chmod 600 "$CONFIG_DIR/secrets/storage_encryption_key"
    
    # OIDC HMAC secret
    echo "$OIDC_HMAC_SECRET" > "$CONFIG_DIR/secrets/oidc_hmac_secret"
    chmod 600 "$CONFIG_DIR/secrets/oidc_hmac_secret"
    
    # Database passwords
    echo "$POSTGRES_PASSWORD" > "$CONFIG_DIR/secrets/postgres_password"
    chmod 600 "$CONFIG_DIR/secrets/postgres_password"
    
    echo "$REDIS_PASSWORD" > "$CONFIG_DIR/secrets/redis_password"
    chmod 600 "$CONFIG_DIR/secrets/redis_password"
    
    echo "$LDAP_PASSWORD" > "$CONFIG_DIR/secrets/ldap_password"
    chmod 600 "$CONFIG_DIR/secrets/ldap_password"
    
    success "Secrets files created"
}

# Function to create main configuration file
create_main_config() {
    info "Creating main Authelia configuration..."
    
    cat > "$CONFIG_DIR/configuration.yml" << EOF
# Authelia Configuration for Zero Trust VPN
# Generated on $(date)

###############################################################
#                   Authelia Configuration                   #
###############################################################

# Server Configuration
server:
  host: 0.0.0.0
  port: 9091
  path: ""
  read_buffer_size: 4096
  write_buffer_size: 4096
  enable_pprof: false
  enable_expvars: false
  disable_healthcheck: false

# Logging Configuration
log:
  level: info
  format: text
  file_path: /config/logs/authelia.log
  keep_stdout: true

# Theme Configuration
theme: auto

# JWT Secret for session tokens
jwt_secret: \${AUTHELIA_JWT_SECRET_FILE}

# Default redirection URL
default_redirection_url: https://$DOMAIN

# TOTP Configuration
totp:
  issuer: $DOMAIN
  algorithm: sha1
  digits: 6
  period: 30
  skew: 1
  secret_size: 32

# WebAuthn Configuration (FIDO2)
webauthn:
  timeout: 60s
  display_name: Zero Trust VPN
  attestation_conveyance_preference: indirect
  user_verification: preferred
  rp_id: $(echo "$DOMAIN" | sed 's/auth\.//')
  rp_origins:
    - https://$DOMAIN
  rp_icon: https://$DOMAIN/icon.png

EOF

    if [[ "$FILE_BACKEND" == "true" ]]; then
        cat >> "$CONFIG_DIR/configuration.yml" << EOF
# Authentication Backend - File-based
authentication_backend:
  password_reset:
    disable: false
  refresh_interval: 5m
  
  file:
    path: /config/users/users_database.yml
    password:
      algorithm: argon2id
      iterations: 3
      salt_length: 16
      parallelism: 4
      memory: 64
EOF
    else
        cat >> "$CONFIG_DIR/configuration.yml" << EOF
# Authentication Backend - LDAP
authentication_backend:
  password_reset:
    disable: false
  refresh_interval: 5m
  
  ldap:
    implementation: custom
    url: $LDAP_URL
    timeout: 5s
    start_tls: false
    tls:
      skip_verify: false
      minimum_version: TLS1.2
    base_dn: $LDAP_BASE_DN
    username_attribute: uid
    additional_users_dn: ou=users
    users_filter: (&({username_attribute}={input})(objectClass=person))
    additional_groups_dn: ou=groups
    groups_filter: (&(member={dn})(objectClass=groupOfNames))
    group_name_attribute: cn
    mail_attribute: mail
    display_name_attribute: displayName
    user: cn=admin,$LDAP_BASE_DN
    password: \${AUTHELIA_LDAP_PASSWORD_FILE}
EOF
    fi

    cat >> "$CONFIG_DIR/configuration.yml" << EOF

# Access Control Configuration
access_control:
  default_policy: deny
  networks:
    - name: internal
      networks:
        - 10.0.0.0/8
        - 172.16.0.0/12
        - 192.168.0.0/16
    - name: vpn
      networks:
        - 10.8.0.0/24
  
  rules:
    # VPN Access - Requires two-factor authentication
    - domain: "vpn.$(echo "$DOMAIN" | sed 's/auth\.//')"
      policy: two_factor
      networks:
        - internal
        - vpn
      
    # Admin Panel - Restricted to administrators
    - domain: "admin.$(echo "$DOMAIN" | sed 's/auth\.//')"
      policy: two_factor
      subject: "group:administrators"
      networks:
        - internal
        - vpn

# Session Configuration
session:
  name: authelia_session
  domain: $(echo "$DOMAIN" | sed 's/auth\.//')
  secret: \${AUTHELIA_SESSION_SECRET_FILE}
  expiration: 1h
  inactivity: 5m
  remember_me_duration: 1M
  
  redis:
    host: redis
    port: 6379
    password: \${AUTHELIA_REDIS_PASSWORD_FILE}
    database_index: $REDIS_DB
    maximum_active_connections: 8
    minimum_idle_connections: 0

# Regulation Configuration (Brute Force Protection)
regulation:
  max_retries: 3
  find_time: 2m
  ban_time: 5m

# Storage Configuration
storage:
  encryption_key: \${AUTHELIA_STORAGE_ENCRYPTION_KEY_FILE}
  
  postgres:
    host: postgres
    port: 5432
    database: $POSTGRES_DB
    schema: public
    username: authelia
    password: \${AUTHELIA_POSTGRES_PASSWORD_FILE}
    timeout: 5s

# Notification Configuration
notifier:
  disable_startup_check: false
  
  smtp:
    username: noreply@$(echo "$DOMAIN" | sed 's/auth\.//')
    password: \${AUTHELIA_SMTP_PASSWORD_FILE}
    host: smtp.$(echo "$DOMAIN" | sed 's/auth\.//')
    port: 587
    sender: "Authelia <noreply@$(echo "$DOMAIN" | sed 's/auth\.//')>"
    identifier: localhost
    subject: "[Authelia] {title}"
    startup_check_address: test@authelia.com
    disable_require_tls: false
    disable_html_emails: false

# Password Policy Configuration
password_policy:
  standard:
    enabled: true
    min_length: 8
    max_length: 0
    require_uppercase: true
    require_lowercase: true
    require_number: true
    require_special: true
  zxcvbn:
    enabled: false
    min_score: 3

# NTP Configuration
ntp:
  address: "time.cloudflare.com:123"
  version: 4
  max_desync: 3s
  disable_startup_check: false
  disable_failure: false
EOF

    chmod 600 "$CONFIG_DIR/configuration.yml"
    success "Main configuration created"
}

# Function to create users database (for file backend)
create_users_database() {
    if [[ "$FILE_BACKEND" != "true" ]]; then
        return 0
    fi
    
    info "Creating users database for file backend..."
    
    # Generate password hash for default admin user
    local admin_password_hash
    admin_password_hash=$(echo 'changeme123' | argon2 somesalt -e -t 3 -m 16 -p 4)
    
    cat > "$CONFIG_DIR/users/users_database.yml" << EOF
# Authelia Users Database
# Generated on $(date)

users:
  admin:
    displayname: "System Administrator"
    password: "$admin_password_hash"
    email: admin@$(echo "$DOMAIN" | sed 's/auth\.//')
    groups:
      - admins
      - users
      - vpn-users

  user:
    displayname: "Standard User"
    password: "$admin_password_hash"
    email: user@$(echo "$DOMAIN" | sed 's/auth\.//')
    groups:
      - users
      - vpn-users
EOF

    chmod 600 "$CONFIG_DIR/users/users_database.yml"
    success "Users database created"
}

# Function to create Docker Compose configuration
create_docker_compose() {
    if [[ "$SKIP_DOCKER" == "true" ]]; then
        return 0
    fi
    
    info "Creating Docker Compose configuration..."
    
    mkdir -p "$DOCKER_COMPOSE_DIR"
    
    cat > "$DOCKER_COMPOSE_DIR/authelia-compose.yml" << EOF
# Authelia Docker Compose Configuration
# Generated on $(date)

version: '3.8'

services:
  authelia:
    container_name: authelia
    image: authelia/authelia:latest
    restart: unless-stopped
    environment:
      - TZ=\${TZ:-UTC}
      - AUTHELIA_JWT_SECRET_FILE=/config/secrets/jwt_secret
      - AUTHELIA_SESSION_SECRET_FILE=/config/secrets/session_secret
      - AUTHELIA_STORAGE_ENCRYPTION_KEY_FILE=/config/secrets/storage_encryption_key
      - AUTHELIA_POSTGRES_PASSWORD_FILE=/config/secrets/postgres_password
      - AUTHELIA_REDIS_PASSWORD_FILE=/config/secrets/redis_password
EOF

    if [[ "$FILE_BACKEND" != "true" ]]; then
        cat >> "$DOCKER_COMPOSE_DIR/authelia-compose.yml" << EOF
      - AUTHELIA_LDAP_PASSWORD_FILE=/config/secrets/ldap_password
EOF
    fi

    cat >> "$DOCKER_COMPOSE_DIR/authelia-compose.yml" << EOF
    volumes:
      - $CONFIG_DIR:/config
    ports:
      - "9091:9091"
    networks:
      - authelia-network
    depends_on:
      - postgres
      - redis
    healthcheck:
      test: ["CMD", "wget", "--no-verbose", "--tries=1", "--spider", "http://localhost:9091/api/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  postgres:
    container_name: authelia-postgres
    image: postgres:15-alpine
    restart: unless-stopped
    environment:
      - POSTGRES_DB=$POSTGRES_DB
      - POSTGRES_USER=authelia
      - POSTGRES_PASSWORD_FILE=/run/secrets/postgres_password
    secrets:
      - postgres_password
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - authelia-network
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U authelia -d $POSTGRES_DB"]
      interval: 30s
      timeout: 10s
      retries: 3

  redis:
    container_name: authelia-redis
    image: redis:7-alpine
    restart: unless-stopped
    command: redis-server --requirepass_file /run/secrets/redis_password
    secrets:
      - redis_password
    volumes:
      - redis_data:/data
    networks:
      - authelia-network
    healthcheck:
      test: ["CMD", "redis-cli", "--no-auth-warning", "-a", "\$(cat /run/secrets/redis_password)", "ping"]
      interval: 30s
      timeout: 10s
      retries: 3

secrets:
  postgres_password:
    file: $CONFIG_DIR/secrets/postgres_password
  redis_password:
    file: $CONFIG_DIR/secrets/redis_password

volumes:
  postgres_data:
  redis_data:

networks:
  authelia-network:
    driver: bridge
EOF

    success "Docker Compose configuration created"
}

# Function to create environment file
create_env_file() {
    if [[ "$SKIP_DOCKER" == "true" ]]; then
        return 0
    fi
    
    info "Creating environment file..."
    
    cat > "$DOCKER_COMPOSE_DIR/.env.authelia" << EOF
# Authelia Environment Configuration
# Generated on $(date)

# Timezone
TZ=UTC

# Domain configuration
AUTHELIA_DOMAIN=$DOMAIN

# LDAP configuration (if using LDAP backend)
LDAP_URL=$LDAP_URL
LDAP_BASE_DN=$LDAP_BASE_DN

# Database configuration
POSTGRES_DB=$POSTGRES_DB
REDIS_DB=$REDIS_DB

# Logging
AUTHELIA_LOG_LEVEL=info

# Security
AUTHELIA_SERVER_DISABLE_HEALTHCHECK=false
AUTHELIA_TELEMETRY_METRICS_ENABLED=false

# SMTP configuration (update with your SMTP settings)
SMTP_HOST=smtp.$(echo "$DOMAIN" | sed 's/auth\.//')
SMTP_PORT=587
SMTP_USERNAME=noreply@$(echo "$DOMAIN" | sed 's/auth\.//')
# SMTP_PASSWORD will be loaded from secrets file
EOF

    success "Environment file created"
}

# Function to create startup script
create_startup_script() {
    info "Creating startup script..."
    
    cat > "$CONFIG_DIR/start-authelia.sh" << EOF
#!/bin/bash

# Authelia Startup Script
# Generated on $(date)

set -euo pipefail

DOCKER_COMPOSE_DIR="$DOCKER_COMPOSE_DIR"
CONFIG_DIR="$CONFIG_DIR"

echo "Starting Authelia services..."

# Check if configuration exists
if [[ ! -f "\$CONFIG_DIR/configuration.yml" ]]; then
    echo "ERROR: Authelia configuration not found!"
    exit 1
fi

# Check if secrets exist
if [[ ! -f "\$CONFIG_DIR/secrets/jwt_secret" ]]; then
    echo "ERROR: JWT secret not found!"
    exit 1
fi

# Start services
cd "\$DOCKER_COMPOSE_DIR"
docker-compose -f authelia-compose.yml --env-file .env.authelia up -d

# Wait for services to be healthy
echo "Waiting for services to be healthy..."
sleep 30

# Check service health
if docker-compose -f authelia-compose.yml ps | grep -q "unhealthy"; then
    echo "WARNING: Some services are unhealthy"
    docker-compose -f authelia-compose.yml ps
fi

echo "Authelia services started successfully!"
echo "Access Authelia at: https://$DOMAIN"
EOF

    chmod +x "$CONFIG_DIR/start-authelia.sh"
    
    success "Startup script created"
}

# Function to create management scripts
create_management_scripts() {
    info "Creating management scripts..."
    
    local scripts_dir="$CONFIG_DIR/scripts"
    mkdir -p "$scripts_dir"
    
    # User management script
    cat > "$scripts_dir/manage-users.sh" << 'EOF'
#!/bin/bash

# Authelia User Management Script

set -euo pipefail

CONFIG_DIR="/opt/zero-trust-vpn/config/authelia"
USERS_FILE="$CONFIG_DIR/users/users_database.yml"

usage() {
    echo "Usage: $0 {add|remove|list|reset-password} [username] [options]"
    echo
    echo "Commands:"
    echo "  add <username> <email> <groups>    Add new user"
    echo "  remove <username>                  Remove user"
    echo "  list                              List all users"
    echo "  reset-password <username>         Reset user password"
    echo
    echo "Examples:"
    echo "  $0 add john.doe john@company.com users,vpn-users"
    echo "  $0 remove john.doe"
    echo "  $0 reset-password john.doe"
}

add_user() {
    local username="$1"
    local email="$2"
    local groups="$3"
    
    # Generate password hash
    read -s -p "Enter password for $username: " password
    echo
    local password_hash
    password_hash=$(echo "$password" | argon2 somesalt -e -t 3 -m 16 -p 4)
    
    # Add user to database
    cat >> "$USERS_FILE" << EOF

  $username:
    displayname: "$username"
    password: "$password_hash"
    email: $email
    groups:
EOF
    
    IFS=',' read -ra GROUP_ARRAY <<< "$groups"
    for group in "${GROUP_ARRAY[@]}"; do
        echo "      - $group" >> "$USERS_FILE"
    done
    
    echo "User $username added successfully"
}

remove_user() {
    local username="$1"
    
    # Remove user from database (simplified - in production use proper YAML parser)
    sed -i "/^  $username:/,/^  [^[:space:]]/{ /^  [^[:space:]]/!d; }" "$USERS_FILE"
    
    echo "User $username removed successfully"
}

list_users() {
    echo "Users in database:"
    grep "^  [^[:space:]]" "$USERS_FILE" | sed 's/://g' | sed 's/^  /- /'
}

reset_password() {
    local username="$1"
    
    read -s -p "Enter new password for $username: " password
    echo
    local password_hash
    password_hash=$(echo "$password" | argon2 somesalt -e -t 3 -m 16 -p 4)
    
    # Update password (simplified - in production use proper YAML parser)
    sed -i "/^  $username:/,/^  [^[:space:]]/ s/password: .*/password: \"$password_hash\"/" "$USERS_FILE"
    
    echo "Password reset for $username"
}

case "${1:-}" in
    add)
        if [[ $# -ne 4 ]]; then
            usage
            exit 1
        fi
        add_user "$2" "$3" "$4"
        ;;
    remove)
        if [[ $# -ne 2 ]]; then
            usage
            exit 1
        fi
        remove_user "$2"
        ;;
    list)
        list_users
        ;;
    reset-password)
        if [[ $# -ne 2 ]]; then
            usage
            exit 1
        fi
        reset_password "$2"
        ;;
    *)
        usage
        exit 1
        ;;
esac
EOF

    chmod +x "$scripts_dir/manage-users.sh"
    
    # Configuration backup script
    cat > "$scripts_dir/backup-config.sh" << EOF
#!/bin/bash

# Authelia Configuration Backup Script

set -euo pipefail

CONFIG_DIR="$CONFIG_DIR"
BACKUP_DIR="/backup/authelia-\$(date +%Y%m%d_%H%M%S)"

echo "Creating Authelia configuration backup..."

mkdir -p "\$BACKUP_DIR"

# Backup configuration files
cp -r "\$CONFIG_DIR" "\$BACKUP_DIR/"

# Create backup archive
tar -czf "\$BACKUP_DIR.tar.gz" -C "\$(dirname "\$BACKUP_DIR")" "\$(basename "\$BACKUP_DIR")"

# Remove temporary directory
rm -rf "\$BACKUP_DIR"

echo "Backup created: \$BACKUP_DIR.tar.gz"
EOF

    chmod +x "$scripts_dir/backup-config.sh"
    
    success "Management scripts created"
}

# Function to create systemd service
create_systemd_service() {
    if [[ "$SKIP_DOCKER" == "true" ]]; then
        return 0
    fi
    
    info "Creating systemd service..."
    
    cat > "/etc/systemd/system/authelia.service" << EOF
[Unit]
Description=Authelia Authentication Server
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=$DOCKER_COMPOSE_DIR
ExecStart=/usr/bin/docker-compose -f authelia-compose.yml --env-file .env.authelia up -d
ExecStop=/usr/bin/docker-compose -f authelia-compose.yml down
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    
    success "Systemd service created"
}

# Function to test configuration
test_configuration() {
    info "Testing Authelia configuration..."
    
    # Validate YAML syntax
    if command -v python3 >/dev/null 2>&1; then
        python3 -c "import yaml; yaml.safe_load(open('$CONFIG_DIR/configuration.yml'))" 2>/dev/null || {
            warning "Configuration YAML syntax validation failed"
            return 1
        }
    fi
    
    # Check if all required secrets exist
    local required_secrets=("jwt_secret" "session_secret" "storage_encryption_key")
    
    if [[ "$FILE_BACKEND" != "true" ]]; then
        required_secrets+=("ldap_password")
    fi
    
    for secret in "${required_secrets[@]}"; do
        if [[ ! -f "$CONFIG_DIR/secrets/$secret" ]]; then
            warning "Missing secret file: $secret"
            return 1
        fi
    done
    
    success "Configuration validation passed"
    return 0
}

# Main execution
main() {
    echo "Zero Trust VPN - Authelia Setup"
    echo "==============================="
    echo
    
    log "Starting Authelia setup"
    
    # Generate secrets
    generate_secrets
    
    # Create configuration structure
    create_config_directory
    create_secrets_files
    
    # Create configuration files
    create_main_config
    create_users_database
    
    # Create Docker configuration
    create_docker_compose
    create_env_file
    
    # Create management tools
    create_startup_script
    create_management_scripts
    create_systemd_service
    
    # Test configuration
    test_configuration
    
    # Display summary
    echo
    echo "============================================="
    echo "Authelia Setup Complete!"
    echo "============================================="
    echo
    echo "Configuration Details:"
    echo "  Domain: $DOMAIN"
    echo "  Backend: $([ "$FILE_BACKEND" == "true" ] && echo "File-based" || echo "LDAP")"
    echo "  Config Directory: $CONFIG_DIR"
    echo "  Docker Compose: $DOCKER_COMPOSE_DIR/authelia-compose.yml"
    echo
    echo "Files Created:"
    echo "  Main Config: $CONFIG_DIR/configuration.yml"
    echo "  Secrets: $CONFIG_DIR/secrets/"
    if [[ "$FILE_BACKEND" == "true" ]]; then
        echo "  Users Database: $CONFIG_DIR/users/users_database.yml"
    fi
    echo
    echo "Management Commands:"
    echo "  Start Services: $CONFIG_DIR/start-authelia.sh"
    echo "  Manage Users: $CONFIG_DIR/scripts/manage-users.sh"
    echo "  Backup Config: $CONFIG_DIR/scripts/backup-config.sh"
    echo "  Systemd Service: systemctl start authelia"
    echo
    echo "Next Steps:"
    echo "1. Review and customize configuration files"
    echo "2. Update SMTP settings for notifications"
    echo "3. Configure SSL certificates"
    echo "4. Start Authelia services"
    echo "5. Test authentication flow"
    echo
    echo "Security Reminders:"
    echo "- Change default passwords immediately"
    echo "- Secure the secrets directory (700 permissions)"
    echo "- Set up proper SSL/TLS certificates"
    echo "- Configure firewall rules"
    echo "- Enable monitoring and logging"
    echo
    echo "Access Authelia at: https://$DOMAIN"
    echo
    
    log "Authelia setup completed successfully"
}

# Run main function
main "$@"