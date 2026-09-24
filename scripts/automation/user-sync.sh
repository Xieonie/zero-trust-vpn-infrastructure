#!/bin/bash

# Zero Trust VPN Infrastructure - User Synchronization Script
# This script synchronizes user accounts and access policies between different systems
# including LDAP/AD, Authelia, and device inventory

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
SYNC_LOG_DIR="/var/log/zero-trust-vpn"
SYNC_CONFIG="$PROJECT_ROOT/config/user-sync.conf"

# Default configuration
LDAP_SERVER=""
LDAP_BASE_DN=""
LDAP_BIND_DN=""
LDAP_BIND_PASSWORD=""
AUTHELIA_CONFIG="$CONFIG_DIR/authelia/users_database.yml"
DEVICE_INVENTORY="$PROJECT_ROOT/device-inventory.json"
SYNC_INTERVAL=3600  # 1 hour
DRY_RUN=false
VERBOSE=false

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" >> "$SYNC_LOG_DIR/user-sync.log"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1" >> "$SYNC_LOG_DIR/user-sync.log"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1" >> "$SYNC_LOG_DIR/user-sync.log"
}

info() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] INFO: $1${NC}"
    if [[ "$VERBOSE" == "true" ]]; then
        echo "[$(date +'%Y-%m-%d %H:%M:%S')] INFO: $1" >> "$SYNC_LOG_DIR/user-sync.log"
    fi
}

# Display usage information
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Zero Trust VPN User Synchronization Script

OPTIONS:
    --source SOURCE         User source (ldap, ad, file, api)
    --target TARGET         Sync target (authelia, inventory, all)
    --config FILE           Configuration file path
    --dry-run               Show what would be done without making changes
    --daemon                Run as daemon with periodic sync
    --interval SECONDS      Sync interval for daemon mode (default: 3600)
    --force                 Force sync even if no changes detected
    --backup                Create backup before sync
    --verbose               Enable verbose logging
    -h, --help              Show this help message

SOURCES:
    ldap        LDAP directory server
    ad          Active Directory
    file        CSV/JSON file
    api         REST API endpoint

TARGETS:
    authelia    Authelia user database
    inventory   Device inventory
    all         All configured targets

EXAMPLES:
    $0 --source ldap --target authelia --dry-run
    $0 --source ad --target all --backup --verbose
    $0 --daemon --interval 1800
    $0 --source file --config /path/to/users.csv

EOF
}

# Parse command line arguments
parse_args() {
    SOURCE=""
    TARGET="all"
    CONFIG_FILE=""
    DAEMON_MODE=false
    FORCE_SYNC=false
    CREATE_BACKUP=false

    while [[ $# -gt 0 ]]; do
        case $1 in
            --source)
                SOURCE="$2"
                shift 2
                ;;
            --target)
                TARGET="$2"
                shift 2
                ;;
            --config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --daemon)
                DAEMON_MODE=true
                shift
                ;;
            --interval)
                SYNC_INTERVAL="$2"
                shift 2
                ;;
            --force)
                FORCE_SYNC=true
                shift
                ;;
            --backup)
                CREATE_BACKUP=true
                shift
                ;;
            --verbose)
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
    if [[ -z "$SOURCE" && "$DAEMON_MODE" == "false" ]]; then
        error "Source is required. Use --source option"
        exit 1
    fi

    # Load configuration file if specified
    if [[ -n "$CONFIG_FILE" && -f "$CONFIG_FILE" ]]; then
        source "$CONFIG_FILE"
    elif [[ -f "$SYNC_CONFIG" ]]; then
        source "$SYNC_CONFIG"
    fi
}

# Initialize synchronization environment
init_sync_environment() {
    log "Initializing user synchronization environment..."

    # Create log directory
    mkdir -p "$SYNC_LOG_DIR"

    # Check prerequisites
    local required_commands=("jq" "yq")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            error "Required command not found: $cmd"
            exit 1
        fi
    done

    # Check LDAP tools if LDAP source is used
    if [[ "$SOURCE" == "ldap" || "$SOURCE" == "ad" ]]; then
        if ! command -v ldapsearch &> /dev/null; then
            error "LDAP tools not found. Install ldap-utils package"
            exit 1
        fi
    fi

    # Create backup if requested
    if [[ "$CREATE_BACKUP" == "true" ]]; then
        create_backup
    fi
}

# Create backup of current configuration
create_backup() {
    local backup_timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_dir="$PROJECT_ROOT/backups/user-sync/$backup_timestamp"

    log "Creating backup..."

    if [[ "$DRY_RUN" == "true" ]]; then
        info "DRY RUN: Would create backup in $backup_dir"
        return
    fi

    mkdir -p "$backup_dir"

    # Backup Authelia user database
    if [[ -f "$AUTHELIA_CONFIG" ]]; then
        cp "$AUTHELIA_CONFIG" "$backup_dir/users_database.yml.backup"
    fi

    # Backup device inventory
    if [[ -f "$DEVICE_INVENTORY" ]]; then
        cp "$DEVICE_INVENTORY" "$backup_dir/device-inventory.json.backup"
    fi

    log "Backup created in: $backup_dir"
}

# Fetch users from LDAP
fetch_ldap_users() {
    log "Fetching users from LDAP server: $LDAP_SERVER"

    if [[ -z "$LDAP_SERVER" || -z "$LDAP_BASE_DN" ]]; then
        error "LDAP configuration incomplete"
        return 1
    fi

    local ldap_users_file="/tmp/ldap_users_$$.json"
    local ldap_filter="(objectClass=person)"

    # Build LDAP search command
    local ldap_cmd="ldapsearch -x -H $LDAP_SERVER -b $LDAP_BASE_DN"
    
    if [[ -n "$LDAP_BIND_DN" ]]; then
        ldap_cmd="$ldap_cmd -D $LDAP_BIND_DN"
        if [[ -n "$LDAP_BIND_PASSWORD" ]]; then
            ldap_cmd="$ldap_cmd -w $LDAP_BIND_PASSWORD"
        fi
    fi

    ldap_cmd="$ldap_cmd $ldap_filter uid mail cn memberOf"

    info "Executing LDAP search..."
    
    # Execute LDAP search and convert to JSON
    if $ldap_cmd > "/tmp/ldap_raw_$$.txt" 2>/dev/null; then
        # Parse LDAP output to JSON (simplified parser)
        python3 << EOF > "$ldap_users_file"
import re
import json

users = []
current_user = {}

with open('/tmp/ldap_raw_$$.txt', 'r') as f:
    for line in f:
        line = line.strip()
        if line.startswith('dn:'):
            if current_user:
                users.append(current_user)
            current_user = {'dn': line[3:].strip()}
        elif line.startswith('uid:'):
            current_user['username'] = line[4:].strip()
        elif line.startswith('mail:'):
            current_user['email'] = line[5:].strip()
        elif line.startswith('cn:'):
            current_user['displayname'] = line[3:].strip()
        elif line.startswith('memberOf:'):
            if 'groups' not in current_user:
                current_user['groups'] = []
            group = line[9:].strip()
            # Extract group name from DN
            group_name = re.search(r'cn=([^,]+)', group)
            if group_name:
                current_user['groups'].append(group_name.group(1))

if current_user:
    users.append(current_user)

print(json.dumps({'users': users}, indent=2))
EOF

        rm -f "/tmp/ldap_raw_$$.txt"
        echo "$ldap_users_file"
    else
        error "Failed to fetch users from LDAP"
        rm -f "/tmp/ldap_raw_$$.txt"
        return 1
    fi
}

# Fetch users from Active Directory
fetch_ad_users() {
    log "Fetching users from Active Directory..."
    
    # AD is similar to LDAP but with different attributes
    # This would use the same LDAP tools but with AD-specific filters
    fetch_ldap_users
}

# Fetch users from file
fetch_file_users() {
    local file_path="$CONFIG_FILE"
    
    log "Loading users from file: $file_path"

    if [[ ! -f "$file_path" ]]; then
        error "User file not found: $file_path"
        return 1
    fi

    # Detect file format and convert to standard JSON
    if [[ "$file_path" == *.csv ]]; then
        # Convert CSV to JSON
        python3 << EOF > "/tmp/file_users_$$.json"
import csv
import json

users = []
with open('$file_path', 'r') as csvfile:
    reader = csv.DictReader(csvfile)
    for row in reader:
        user = {
            'username': row.get('username', ''),
            'email': row.get('email', ''),
            'displayname': row.get('displayname', row.get('name', '')),
            'groups': row.get('groups', 'standard').split(',')
        }
        users.append(user)

print(json.dumps({'users': users}, indent=2))
EOF
        echo "/tmp/file_users_$$.json"
    elif [[ "$file_path" == *.json ]]; then
        echo "$file_path"
    else
        error "Unsupported file format. Use CSV or JSON"
        return 1
    fi
}

# Sync users to Authelia
sync_to_authelia() {
    local users_file="$1"
    
    log "Syncing users to Authelia..."

    if [[ ! -f "$users_file" ]]; then
        error "Users file not found: $users_file"
        return 1
    fi

    if [[ "$DRY_RUN" == "true" ]]; then
        info "DRY RUN: Would sync $(jq '.users | length' "$users_file") users to Authelia"
        return 0
    fi

    # Read users from source
    local users_json=$(cat "$users_file")
    
    # Initialize Authelia users database if it doesn't exist
    if [[ ! -f "$AUTHELIA_CONFIG" ]]; then
        echo "users:" > "$AUTHELIA_CONFIG"
    fi

    # Process each user
    echo "$users_json" | jq -r '.users[] | @base64' | while read -r user_data; do
        local user=$(echo "$user_data" | base64 -d)
        local username=$(echo "$user" | jq -r '.username')
        local email=$(echo "$user" | jq -r '.email')
        local displayname=$(echo "$user" | jq -r '.displayname')
        local groups=$(echo "$user" | jq -r '.groups[]' | tr '\n' ',' | sed 's/,$//')

        if [[ -n "$username" && -n "$email" ]]; then
            # Check if user already exists
            if yq eval ".users | has(\"$username\")" "$AUTHELIA_CONFIG" | grep -q "true"; then
                info "Updating existing user: $username"
                # Update user information
                yq eval ".users.\"$username\".email = \"$email\"" -i "$AUTHELIA_CONFIG"
                yq eval ".users.\"$username\".displayname = \"$displayname\"" -i "$AUTHELIA_CONFIG"
                yq eval ".users.\"$username\".groups = [\"$groups\"]" -i "$AUTHELIA_CONFIG"
            else
                info "Adding new user: $username"
                # Generate temporary password (user must change on first login)
                local temp_password="ChangeMe$(date +%s)"
                local password_hash=$(echo -n "$temp_password" | argon2 "$(openssl rand -base64 32)" -e -id -k 65536 -t 3 -p 4)
                
                # Add new user
                yq eval ".users.\"$username\" = {
                    \"displayname\": \"$displayname\",
                    \"password\": \"$password_hash\",
                    \"email\": \"$email\",
                    \"groups\": [\"$groups\"]
                }" -i "$AUTHELIA_CONFIG"
                
                warn "User $username added with temporary password: $temp_password"
            fi
        else
            warn "Skipping user with incomplete information: $username"
        fi
    done

    log "Authelia user sync completed"
}

# Sync users to device inventory
sync_to_inventory() {
    local users_file="$1"
    
    log "Syncing users to device inventory..."

    if [[ ! -f "$users_file" ]]; then
        error "Users file not found: $users_file"
        return 1
    fi

    if [[ "$DRY_RUN" == "true" ]]; then
        info "DRY RUN: Would update device inventory with user information"
        return 0
    fi

    # Initialize device inventory if it doesn't exist
    if [[ ! -f "$DEVICE_INVENTORY" ]]; then
        echo '{"devices": []}' > "$DEVICE_INVENTORY"
    fi

    # Update device inventory with current user information
    local users_json=$(cat "$users_file")
    
    echo "$users_json" | jq -r '.users[] | @base64' | while read -r user_data; do
        local user=$(echo "$user_data" | base64 -d)
        local username=$(echo "$user" | jq -r '.username')
        local email=$(echo "$user" | jq -r '.email')
        local groups=$(echo "$user" | jq -r '.groups[0]' 2>/dev/null || echo "standard")

        # Update devices owned by this user
        jq "(.devices[] | select(.username == \"$username\") | .email) = \"$email\"" \
           "$DEVICE_INVENTORY" > "$DEVICE_INVENTORY.tmp" && mv "$DEVICE_INVENTORY.tmp" "$DEVICE_INVENTORY"
        
        jq "(.devices[] | select(.username == \"$username\") | .access_level) = \"$groups\"" \
           "$DEVICE_INVENTORY" > "$DEVICE_INVENTORY.tmp" && mv "$DEVICE_INVENTORY.tmp" "$DEVICE_INVENTORY"
        
        jq "(.devices[] | select(.username == \"$username\") | .last_sync) = \"$(date -Iseconds)\"" \
           "$DEVICE_INVENTORY" > "$DEVICE_INVENTORY.tmp" && mv "$DEVICE_INVENTORY.tmp" "$DEVICE_INVENTORY"
    done

    log "Device inventory sync completed"
}

# Perform user synchronization
perform_sync() {
    log "Starting user synchronization from $SOURCE to $TARGET"

    local users_file=""

    # Fetch users from source
    case "$SOURCE" in
        "ldap")
            users_file=$(fetch_ldap_users)
            ;;
        "ad")
            users_file=$(fetch_ad_users)
            ;;
        "file")
            users_file=$(fetch_file_users)
            ;;
        "api")
            error "API source not yet implemented"
            return 1
            ;;
        *)
            error "Unknown source: $SOURCE"
            return 1
            ;;
    esac

    if [[ -z "$users_file" || ! -f "$users_file" ]]; then
        error "Failed to fetch users from source"
        return 1
    fi

    local user_count=$(jq '.users | length' "$users_file")
    log "Fetched $user_count users from $SOURCE"

    # Sync to targets
    case "$TARGET" in
        "authelia")
            sync_to_authelia "$users_file"
            ;;
        "inventory")
            sync_to_inventory "$users_file"
            ;;
        "all")
            sync_to_authelia "$users_file"
            sync_to_inventory "$users_file"
            ;;
        *)
            error "Unknown target: $TARGET"
            return 1
            ;;
    esac

    # Cleanup temporary files
    if [[ "$users_file" == /tmp/* ]]; then
        rm -f "$users_file"
    fi

    log "User synchronization completed successfully"
}

# Daemon mode
run_daemon() {
    log "Starting user sync daemon (interval: ${SYNC_INTERVAL}s)"

    # Create PID file
    local pid_file="/var/run/user-sync.pid"
    echo $$ > "$pid_file"

    # Trap signals for graceful shutdown
    trap 'log "Shutting down user sync daemon"; rm -f "$pid_file"; exit 0' SIGTERM SIGINT

    while true; do
        log "Running scheduled user synchronization..."
        
        if perform_sync; then
            log "Scheduled sync completed successfully"
        else
            error "Scheduled sync failed"
        fi

        log "Next sync in ${SYNC_INTERVAL} seconds"
        sleep "$SYNC_INTERVAL"
    done
}

# Main execution
main() {
    init_sync_environment

    if [[ "$DAEMON_MODE" == "true" ]]; then
        run_daemon
    else
        perform_sync
    fi
}

# Parse arguments and run main function
parse_args "$@"
main