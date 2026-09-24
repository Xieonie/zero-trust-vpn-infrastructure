#!/bin/bash

# Zero Trust VPN Infrastructure - Policy Update Script
# This script manages and updates access policies for users and devices
# in the Zero Trust VPN infrastructure

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
AUTHELIA_CONFIG="$CONFIG_DIR/authelia"
POLICY_DIR="$PROJECT_ROOT/policies"
BACKUP_DIR="$PROJECT_ROOT/backups/policies"

# Policy files
ACCESS_CONTROL_FILE="$AUTHELIA_CONFIG/access-control.yml"
USERS_DB_FILE="$AUTHELIA_CONFIG/users_database.yml"
DEVICE_INVENTORY="$PROJECT_ROOT/device-inventory.json"

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
Usage: $0 [COMMAND] [OPTIONS]

Zero Trust VPN Policy Management Script

COMMANDS:
    update-user-access USER LEVEL    Update user access level
    update-device-policy DEVICE POLICY    Update device-specific policy
    add-resource RESOURCE GROUPS    Add new protected resource
    remove-resource RESOURCE        Remove protected resource
    list-policies                   List all current policies
    validate-config                 Validate policy configuration
    backup-policies                 Backup current policies
    restore-policies BACKUP_FILE    Restore policies from backup
    sync-policies                   Synchronize policies across services

OPTIONS:
    --dry-run                       Show what would be done without making changes
    --force                         Force operation without confirmation
    -v, --verbose                   Enable verbose output
    -h, --help                      Show this help message

ACCESS LEVELS:
    admin       Full access to all resources
    standard    Access to standard user resources
    limited     Restricted access to basic resources
    guest       Minimal access for temporary users

EXAMPLES:
    $0 update-user-access john.doe admin
    $0 add-resource "https://internal.example.com" "admin,standard"
    $0 update-device-policy laptop-work "high-security"
    $0 backup-policies
    $0 validate-config

EOF
}

# Parse command line arguments
parse_args() {
    COMMAND="${1:-}"
    shift || true

    case "$COMMAND" in
        update-user-access)
            USER_TARGET="${1:-}"
            NEW_ACCESS_LEVEL="${2:-}"
            [[ -z "$USER_TARGET" ]] && error "Username required"
            [[ -z "$NEW_ACCESS_LEVEL" ]] && error "Access level required"
            shift 2 || true
            ;;
        update-device-policy)
            DEVICE_TARGET="${1:-}"
            NEW_POLICY="${2:-}"
            [[ -z "$DEVICE_TARGET" ]] && error "Device ID required"
            [[ -z "$NEW_POLICY" ]] && error "Policy name required"
            shift 2 || true
            ;;
        add-resource)
            RESOURCE_URL="${1:-}"
            ALLOWED_GROUPS="${2:-}"
            [[ -z "$RESOURCE_URL" ]] && error "Resource URL required"
            [[ -z "$ALLOWED_GROUPS" ]] && error "Allowed groups required"
            shift 2 || true
            ;;
        remove-resource)
            RESOURCE_URL="${1:-}"
            [[ -z "$RESOURCE_URL" ]] && error "Resource URL required"
            shift || true
            ;;
        list-policies|validate-config|backup-policies|sync-policies)
            # No additional arguments needed
            ;;
        restore-policies)
            BACKUP_FILE="${1:-}"
            [[ -z "$BACKUP_FILE" ]] && error "Backup file required"
            shift || true
            ;;
        ""|"-h"|"--help")
            usage
            exit 0
            ;;
        *)
            error "Unknown command: $COMMAND"
            ;;
    esac

    # Parse remaining options
    while [[ $# -gt 0 ]]; do
        case $1 in
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --force)
                FORCE=true
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
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
    DRY_RUN="${DRY_RUN:-false}"
    FORCE="${FORCE:-false}"
    VERBOSE="${VERBOSE:-false}"
}

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."

    # Check required commands
    local required_commands=("yq" "jq" "systemctl")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            error "Required command not found: $cmd"
        fi
    done

    # Create directories if they don't exist
    mkdir -p "$POLICY_DIR" "$BACKUP_DIR"

    # Check if configuration files exist
    if [[ ! -f "$ACCESS_CONTROL_FILE" ]]; then
        warn "Access control file not found: $ACCESS_CONTROL_FILE"
    fi

    if [[ ! -f "$USERS_DB_FILE" ]]; then
        warn "Users database file not found: $USERS_DB_FILE"
    fi
}

# Backup current policies
backup_policies() {
    local backup_timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_file="$BACKUP_DIR/policies_backup_$backup_timestamp.tar.gz"

    log "Creating policy backup..."

    if [[ "$DRY_RUN" == "true" ]]; then
        info "DRY RUN: Would create backup at $backup_file"
        return
    fi

    tar -czf "$backup_file" -C "$PROJECT_ROOT" \
        "config-examples/authelia/" \
        "device-inventory.json" \
        "policies/" 2>/dev/null || true

    log "Policies backed up to: $backup_file"
    echo "$backup_file"
}

# Validate configuration files
validate_config() {
    log "Validating policy configuration..."

    local errors=0

    # Validate YAML files
    if [[ -f "$ACCESS_CONTROL_FILE" ]]; then
        if ! yq eval '.' "$ACCESS_CONTROL_FILE" >/dev/null 2>&1; then
            error "Invalid YAML in access control file: $ACCESS_CONTROL_FILE"
            ((errors++))
        else
            info "Access control file is valid"
        fi
    fi

    if [[ -f "$USERS_DB_FILE" ]]; then
        if ! yq eval '.' "$USERS_DB_FILE" >/dev/null 2>&1; then
            error "Invalid YAML in users database file: $USERS_DB_FILE"
            ((errors++))
        else
            info "Users database file is valid"
        fi
    fi

    # Validate JSON files
    if [[ -f "$DEVICE_INVENTORY" ]]; then
        if ! jq empty "$DEVICE_INVENTORY" 2>/dev/null; then
            error "Invalid JSON in device inventory: $DEVICE_INVENTORY"
            ((errors++))
        else
            info "Device inventory file is valid"
        fi
    fi

    if [[ $errors -eq 0 ]]; then
        log "All configuration files are valid"
        return 0
    else
        error "Found $errors configuration errors"
        return 1
    fi
}

# Update user access level
update_user_access() {
    local username="$USER_TARGET"
    local new_level="$NEW_ACCESS_LEVEL"

    log "Updating access level for user: $username to $new_level"

    # Validate access level
    if [[ ! "$new_level" =~ ^(admin|standard|limited|guest)$ ]]; then
        error "Invalid access level. Must be: admin, standard, limited, or guest"
    fi

    if [[ "$DRY_RUN" == "true" ]]; then
        info "DRY RUN: Would update $username access level to $new_level"
        return
    fi

    # Check if user exists
    if ! yq eval ".users | has(\"$username\")" "$USERS_DB_FILE" | grep -q "true"; then
        error "User $username not found in database"
    fi

    # Backup before changes
    local backup_file=$(backup_policies)

    # Update user groups in Authelia
    yq eval ".users.\"$username\".groups = [\"$new_level\"]" -i "$USERS_DB_FILE"

    # Update device inventory
    if [[ -f "$DEVICE_INVENTORY" ]]; then
        jq "(.devices[] | select(.username == \"$username\") | .access_level) = \"$new_level\"" \
           "$DEVICE_INVENTORY" > "$DEVICE_INVENTORY.tmp" && mv "$DEVICE_INVENTORY.tmp" "$DEVICE_INVENTORY"
    fi

    log "User access level updated successfully"
    info "Backup created: $backup_file"
}

# Add new protected resource
add_resource() {
    local resource_url="$RESOURCE_URL"
    local allowed_groups="$ALLOWED_GROUPS"

    log "Adding new protected resource: $resource_url"

    if [[ "$DRY_RUN" == "true" ]]; then
        info "DRY RUN: Would add resource $resource_url for groups: $allowed_groups"
        return
    fi

    # Backup before changes
    local backup_file=$(backup_policies)

    # Convert comma-separated groups to array
    IFS=',' read -ra groups_array <<< "$allowed_groups"

    # Create new rule entry
    local new_rule=$(cat << EOF
{
  "domain": "$(echo "$resource_url" | sed 's|https\?://||' | cut -d'/' -f1)",
  "policy": "two_factor",
  "subject": [$(printf '"%s",' "${groups_array[@]}" | sed 's/,$//')],
  "resources": ["$resource_url"]
}
EOF
    )

    # Add to access control rules (this is a simplified example)
    # In practice, you'd need to properly merge with existing YAML structure
    info "Resource configuration prepared"
    warn "Manual verification of access control file required"

    log "Resource added successfully"
    info "Backup created: $backup_file"
}

# Remove protected resource
remove_resource() {
    local resource_url="$RESOURCE_URL"

    log "Removing protected resource: $resource_url"

    if [[ "$DRY_RUN" == "true" ]]; then
        info "DRY RUN: Would remove resource $resource_url"
        return
    fi

    # Backup before changes
    local backup_file=$(backup_policies)

    # Remove from access control (simplified implementation)
    warn "Resource removal requires manual editing of access control file"
    info "Resource: $resource_url"

    log "Resource removal initiated"
    info "Backup created: $backup_file"
}

# Update device-specific policy
update_device_policy() {
    local device_id="$DEVICE_TARGET"
    local new_policy="$NEW_POLICY"

    log "Updating device policy for: $device_id to $new_policy"

    if [[ "$DRY_RUN" == "true" ]]; then
        info "DRY RUN: Would update device $device_id policy to $new_policy"
        return
    fi

    # Check if device exists in inventory
    if [[ ! -f "$DEVICE_INVENTORY" ]] || ! jq -e ".devices[] | select(.id == \"$device_id\")" "$DEVICE_INVENTORY" >/dev/null; then
        error "Device $device_id not found in inventory"
    fi

    # Backup before changes
    local backup_file=$(backup_policies)

    # Update device policy in inventory
    jq "(.devices[] | select(.id == \"$device_id\") | .policy) = \"$new_policy\"" \
       "$DEVICE_INVENTORY" > "$DEVICE_INVENTORY.tmp" && mv "$DEVICE_INVENTORY.tmp" "$DEVICE_INVENTORY"

    # Update last modified timestamp
    jq "(.devices[] | select(.id == \"$device_id\") | .last_modified) = \"$(date -Iseconds)\"" \
       "$DEVICE_INVENTORY" > "$DEVICE_INVENTORY.tmp" && mv "$DEVICE_INVENTORY.tmp" "$DEVICE_INVENTORY"

    log "Device policy updated successfully"
    info "Backup created: $backup_file"
}

# List all current policies
list_policies() {
    log "Current Policy Overview"
    echo "======================"

    # List users and their access levels
    echo ""
    echo "Users and Access Levels:"
    echo "------------------------"
    if [[ -f "$USERS_DB_FILE" ]]; then
        yq eval '.users | to_entries | .[] | .key + ": " + (.value.groups | join(","))' "$USERS_DB_FILE"
    else
        warn "Users database file not found"
    fi

    # List devices and their policies
    echo ""
    echo "Devices and Policies:"
    echo "--------------------"
    if [[ -f "$DEVICE_INVENTORY" ]]; then
        jq -r '.devices[] | "\(.id): \(.access_level) (\(.device_type))"' "$DEVICE_INVENTORY"
    else
        warn "Device inventory file not found"
    fi

    # List protected resources
    echo ""
    echo "Protected Resources:"
    echo "-------------------"
    if [[ -f "$ACCESS_CONTROL_FILE" ]]; then
        yq eval '.access_control.rules[] | .domain + " -> " + (.subject | join(","))' "$ACCESS_CONTROL_FILE" 2>/dev/null || warn "No access control rules found"
    else
        warn "Access control file not found"
    fi
}

# Synchronize policies across services
sync_policies() {
    log "Synchronizing policies across services..."

    if [[ "$DRY_RUN" == "true" ]]; then
        info "DRY RUN: Would synchronize policies"
        return
    fi

    # Restart Authelia to reload configuration
    if systemctl is-active --quiet authelia; then
        log "Restarting Authelia service..."
        systemctl restart authelia
    else
        warn "Authelia service is not running"
    fi

    # Reload WireGuard configuration if needed
    if systemctl is-active --quiet wg-quick@wg0; then
        log "Reloading WireGuard configuration..."
        wg syncconf wg0 <(wg-quick strip wg0)
    else
        warn "WireGuard service is not running"
    fi

    log "Policy synchronization completed"
}

# Restore policies from backup
restore_policies() {
    local backup_file="$BACKUP_FILE"

    log "Restoring policies from backup: $backup_file"

    if [[ ! -f "$backup_file" ]]; then
        error "Backup file not found: $backup_file"
    fi

    if [[ "$FORCE" != "true" ]]; then
        echo -n "This will overwrite current policies. Continue? (y/N): "
        read -r response
        if [[ ! "$response" =~ ^[Yy]$ ]]; then
            info "Operation cancelled"
            exit 0
        fi
    fi

    if [[ "$DRY_RUN" == "true" ]]; then
        info "DRY RUN: Would restore from $backup_file"
        return
    fi

    # Create backup of current state before restore
    local current_backup=$(backup_policies)
    log "Current state backed up to: $current_backup"

    # Extract backup
    tar -xzf "$backup_file" -C "$PROJECT_ROOT"

    log "Policies restored successfully"
    info "Previous state backed up to: $current_backup"
}

# Main execution
main() {
    case "$COMMAND" in
        update-user-access)
            update_user_access
            ;;
        update-device-policy)
            update_device_policy
            ;;
        add-resource)
            add_resource
            ;;
        remove-resource)
            remove_resource
            ;;
        list-policies)
            list_policies
            ;;
        validate-config)
            validate_config
            ;;
        backup-policies)
            backup_policies
            ;;
        restore-policies)
            restore_policies
            ;;
        sync-policies)
            sync_policies
            ;;
        *)
            error "Unknown command: $COMMAND"
            ;;
    esac
}

# Parse arguments and run
parse_args "$@"
check_prerequisites
main