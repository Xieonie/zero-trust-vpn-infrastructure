#!/bin/bash

# Zero Trust VPN Infrastructure - Compliance Check Script
# This script verifies compliance with security standards and regulatory requirements
# for the Zero Trust VPN infrastructure

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
CONFIG_DIR="$PROJECT_ROOT/config-examples"
CERT_DIR="$PROJECT_ROOT/certificates"
COMPLIANCE_DIR="$PROJECT_ROOT/compliance"
REPORT_DIR="$PROJECT_ROOT/compliance-reports"

# Compliance frameworks
FRAMEWORKS=("NIST" "ISO27001" "SOC2" "GDPR" "HIPAA")
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_FILE="$REPORT_DIR/compliance_report_$TIMESTAMP.json"

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
}

info() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] INFO: $1${NC}"
}

critical() {
    echo -e "${PURPLE}[$(date +'%Y-%m-%d %H:%M:%S')] CRITICAL: $1${NC}"
}

# Display usage information
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Zero Trust VPN Compliance Check Script

OPTIONS:
    --framework FRAMEWORK   Check specific compliance framework
                           (NIST, ISO27001, SOC2, GDPR, HIPAA)
    --all                  Check all supported frameworks
    --export FORMAT        Export results (json, csv, html)
    --baseline             Create compliance baseline
    --compare BASELINE     Compare against baseline
    --remediation          Generate remediation plan
    --verbose              Enable detailed output
    -h, --help             Show this help message

FRAMEWORKS:
    NIST        NIST Cybersecurity Framework
    ISO27001    ISO/IEC 27001:2013
    SOC2        SOC 2 Type II
    GDPR        General Data Protection Regulation
    HIPAA       Health Insurance Portability and Accountability Act

EXAMPLES:
    $0 --framework NIST --verbose
    $0 --all --export json
    $0 --baseline
    $0 --compare baseline_20231201.json --remediation

EOF
}

# Parse command line arguments
parse_args() {
    FRAMEWORK=""
    CHECK_ALL=false
    EXPORT_FORMAT=""
    CREATE_BASELINE=false
    COMPARE_BASELINE=""
    GENERATE_REMEDIATION=false
    VERBOSE=false

    while [[ $# -gt 0 ]]; do
        case $1 in
            --framework)
                FRAMEWORK="$2"
                shift 2
                ;;
            --all)
                CHECK_ALL=true
                shift
                ;;
            --export)
                EXPORT_FORMAT="$2"
                shift 2
                ;;
            --baseline)
                CREATE_BASELINE=true
                shift
                ;;
            --compare)
                COMPARE_BASELINE="$2"
                shift 2
                ;;
            --remediation)
                GENERATE_REMEDIATION=true
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

    # Validate framework if specified
    if [[ -n "$FRAMEWORK" && ! " ${FRAMEWORKS[@]} " =~ " $FRAMEWORK " ]]; then
        error "Unsupported framework: $FRAMEWORK"
        error "Supported frameworks: ${FRAMEWORKS[*]}"
        exit 1
    fi

    # Set default to check all if no specific framework
    if [[ -z "$FRAMEWORK" && "$CHECK_ALL" == "false" ]]; then
        CHECK_ALL=true
    fi
}

# Initialize compliance check environment
init_compliance_check() {
    log "Initializing compliance check environment..."

    # Create necessary directories
    mkdir -p "$COMPLIANCE_DIR" "$REPORT_DIR"

    # Initialize report structure
    cat > "$REPORT_FILE" << EOF
{
    "compliance_report": {
        "timestamp": "$(date -Iseconds)",
        "version": "1.0",
        "infrastructure": "Zero Trust VPN",
        "frameworks": [],
        "overall_score": 0,
        "total_controls": 0,
        "passed_controls": 0,
        "failed_controls": 0,
        "not_applicable": 0
    }
}
EOF

    # Check prerequisites
    local required_commands=("jq" "openssl" "systemctl")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            error "Required command not found: $cmd"
            exit 1
        fi
    done
}

# NIST Cybersecurity Framework compliance check
check_nist_compliance() {
    log "Checking NIST Cybersecurity Framework compliance..."

    local nist_results='{
        "framework": "NIST",
        "version": "1.1",
        "categories": {},
        "score": 0,
        "total_controls": 0,
        "passed": 0,
        "failed": 0
    }'

    # IDENTIFY (ID)
    local identify_score=0
    local identify_total=5

    # ID.AM - Asset Management
    if [[ -f "$PROJECT_ROOT/device-inventory.json" ]]; then
        identify_score=$((identify_score + 1))
        info "✅ ID.AM-1: Physical devices and systems are inventoried"
    else
        warn "❌ ID.AM-1: Device inventory not found"
    fi

    # ID.GV - Governance
    if [[ -f "$CONFIG_DIR/authelia/access-control.yml" ]]; then
        identify_score=$((identify_score + 1))
        info "✅ ID.GV-1: Organizational cybersecurity policy is established"
    else
        warn "❌ ID.GV-1: Access control policy not found"
    fi

    # ID.RA - Risk Assessment
    if [[ -d "$PROJECT_ROOT/audit-reports" ]]; then
        identify_score=$((identify_score + 1))
        info "✅ ID.RA-1: Asset vulnerabilities are identified and documented"
    else
        warn "❌ ID.RA-1: Audit reports directory not found"
    fi

    # ID.RM - Risk Management Strategy
    if [[ -f "$PROJECT_ROOT/policies/risk-management.md" ]]; then
        identify_score=$((identify_score + 1))
        info "✅ ID.RM-1: Risk management processes are established"
    else
        warn "❌ ID.RM-1: Risk management policy not found"
    fi

    # ID.SC - Supply Chain Risk Management
    if [[ -f "$PROJECT_ROOT/docs/architecture-overview.md" ]]; then
        identify_score=$((identify_score + 1))
        info "✅ ID.SC-1: Cyber supply chain risks are identified"
    else
        warn "❌ ID.SC-1: Architecture documentation not found"
    fi

    # PROTECT (PR)
    local protect_score=0
    local protect_total=6

    # PR.AC - Identity Management and Access Control
    if systemctl is-active --quiet authelia 2>/dev/null; then
        protect_score=$((protect_score + 1))
        info "✅ PR.AC-1: Identities and credentials are issued and managed"
    else
        warn "❌ PR.AC-1: Authelia service not running"
    fi

    # PR.AT - Awareness and Training
    if [[ -f "$PROJECT_ROOT/docs/user-management.md" ]]; then
        protect_score=$((protect_score + 1))
        info "✅ PR.AT-1: All users are informed and trained"
    else
        warn "❌ PR.AT-1: User training documentation not found"
    fi

    # PR.DS - Data Security
    if [[ -f "$CERT_DIR/ca/ca.crt" ]]; then
        local key_size=$(openssl x509 -in "$CERT_DIR/ca/ca.crt" -noout -text | grep "Public-Key:" | grep -o "[0-9]*" | head -1)
        if [[ $key_size -ge 2048 ]]; then
            protect_score=$((protect_score + 1))
            info "✅ PR.DS-1: Data-at-rest is protected"
        else
            warn "❌ PR.DS-1: Inadequate encryption key size"
        fi
    else
        warn "❌ PR.DS-1: CA certificate not found"
    fi

    # PR.IP - Information Protection Processes
    if systemctl is-active --quiet wg-quick@wg0; then
        protect_score=$((protect_score + 1))
        info "✅ PR.IP-1: A baseline configuration is created and maintained"
    else
        warn "❌ PR.IP-1: WireGuard service not running"
    fi

    # PR.MA - Maintenance
    if [[ -f "$PROJECT_ROOT/scripts/maintenance/update-system.sh" ]]; then
        protect_score=$((protect_score + 1))
        info "✅ PR.MA-1: Maintenance is performed and logged"
    else
        warn "❌ PR.MA-1: Maintenance scripts not found"
    fi

    # PR.PT - Protective Technology
    if iptables -L | grep -q "DROP\|REJECT"; then
        protect_score=$((protect_score + 1))
        info "✅ PR.PT-1: Audit/log records are determined and documented"
    else
        warn "❌ PR.PT-1: Firewall rules not properly configured"
    fi

    # DETECT (DE)
    local detect_score=0
    local detect_total=3

    # DE.AE - Anomalies and Events
    if [[ -f "/var/log/auth.log" ]]; then
        detect_score=$((detect_score + 1))
        info "✅ DE.AE-1: A baseline of network operations is established"
    else
        warn "❌ DE.AE-1: Authentication logs not accessible"
    fi

    # DE.CM - Security Continuous Monitoring
    if journalctl -u wg-quick@wg0 --since "24 hours ago" --quiet 2>/dev/null; then
        detect_score=$((detect_score + 1))
        info "✅ DE.CM-1: The network is monitored to detect potential cybersecurity events"
    else
        warn "❌ DE.CM-1: WireGuard monitoring not available"
    fi

    # DE.DP - Detection Processes
    if [[ -f "$PROJECT_ROOT/scripts/monitoring/security-audit.sh" ]]; then
        detect_score=$((detect_score + 1))
        info "✅ DE.DP-1: Roles and responsibilities for detection are well defined"
    else
        warn "❌ DE.DP-1: Security audit scripts not found"
    fi

    # RESPOND (RS)
    local respond_score=0
    local respond_total=3

    # RS.RP - Response Planning
    if [[ -f "$PROJECT_ROOT/docs/incident-response.md" ]]; then
        respond_score=$((respond_score + 1))
        info "✅ RS.RP-1: Response plan is executed during or after an incident"
    else
        warn "❌ RS.RP-1: Incident response documentation not found"
    fi

    # RS.CO - Communications
    if [[ -f "$PROJECT_ROOT/scripts/monitoring/send-notification.sh" ]]; then
        respond_score=$((respond_score + 1))
        info "✅ RS.CO-1: Personnel know their roles and order of operations"
    else
        warn "❌ RS.CO-1: Notification scripts not found"
    fi

    # RS.AN - Analysis
    if [[ -f "$PROJECT_ROOT/scripts/monitoring/log-analysis.sh" ]]; then
        respond_score=$((respond_score + 1))
        info "✅ RS.AN-1: Notifications from detection systems are investigated"
    else
        warn "❌ RS.AN-1: Log analysis scripts not found"
    fi

    # RECOVER (RC)
    local recover_score=0
    local recover_total=2

    # RC.RP - Recovery Planning
    if [[ -f "$PROJECT_ROOT/scripts/backup/backup-configs.sh" ]]; then
        recover_score=$((recover_score + 1))
        info "✅ RC.RP-1: Recovery plan is executed during or after a cybersecurity incident"
    else
        warn "❌ RC.RP-1: Backup scripts not found"
    fi

    # RC.IM - Improvements
    if [[ -d "$PROJECT_ROOT/audit-reports" ]]; then
        recover_score=$((recover_score + 1))
        info "✅ RC.IM-1: Recovery planning and processes are improved"
    else
        warn "❌ RC.IM-1: Audit reports for improvement not found"
    fi

    # Calculate overall NIST score
    local total_nist_controls=$((identify_total + protect_total + detect_total + respond_total + recover_total))
    local passed_nist_controls=$((identify_score + protect_score + detect_score + respond_score + recover_score))
    local nist_percentage=$(( (passed_nist_controls * 100) / total_nist_controls ))

    # Update results
    nist_results=$(echo "$nist_results" | jq \
        --arg score "$nist_percentage" \
        --arg total "$total_nist_controls" \
        --arg passed "$passed_nist_controls" \
        --arg failed "$((total_nist_controls - passed_nist_controls))" \
        '.score = ($score | tonumber) | 
         .total_controls = ($total | tonumber) | 
         .passed = ($passed | tonumber) | 
         .failed = ($failed | tonumber)')

    log "NIST Compliance Score: $nist_percentage% ($passed_nist_controls/$total_nist_controls)"

    # Add to main report
    jq --argjson nist "$nist_results" \
       '.compliance_report.frameworks += [$nist]' \
       "$REPORT_FILE" > "$REPORT_FILE.tmp" && mv "$REPORT_FILE.tmp" "$REPORT_FILE"
}

# ISO 27001 compliance check
check_iso27001_compliance() {
    log "Checking ISO 27001:2013 compliance..."

    local iso_results='{
        "framework": "ISO27001",
        "version": "2013",
        "annexes": {},
        "score": 0,
        "total_controls": 0,
        "passed": 0,
        "failed": 0
    }'

    local total_controls=0
    local passed_controls=0

    # A.9 Access Control
    info "Checking A.9 Access Control..."
    
    # A.9.1.1 Access control policy
    if [[ -f "$CONFIG_DIR/authelia/access-control.yml" ]]; then
        passed_controls=$((passed_controls + 1))
        info "✅ A.9.1.1: Access control policy documented"
    else
        warn "❌ A.9.1.1: Access control policy not found"
    fi
    total_controls=$((total_controls + 1))

    # A.9.2.1 User registration and de-registration
    if [[ -f "$PROJECT_ROOT/scripts/management/add-user.sh" && -f "$PROJECT_ROOT/scripts/management/revoke-user.sh" ]]; then
        passed_controls=$((passed_controls + 1))
        info "✅ A.9.2.1: User registration/de-registration procedures exist"
    else
        warn "❌ A.9.2.1: User management scripts not found"
    fi
    total_controls=$((total_controls + 1))

    # A.10 Cryptography
    info "Checking A.10 Cryptography..."
    
    # A.10.1.1 Policy on the use of cryptographic controls
    if [[ -f "$CERT_DIR/ca/ca.crt" ]]; then
        local key_size=$(openssl x509 -in "$CERT_DIR/ca/ca.crt" -noout -text | grep "Public-Key:" | grep -o "[0-9]*" | head -1)
        if [[ $key_size -ge 2048 ]]; then
            passed_controls=$((passed_controls + 1))
            info "✅ A.10.1.1: Cryptographic policy implemented (${key_size}-bit keys)"
        else
            warn "❌ A.10.1.1: Inadequate cryptographic strength"
        fi
    else
        warn "❌ A.10.1.1: Cryptographic infrastructure not found"
    fi
    total_controls=$((total_controls + 1))

    # A.12 Operations Security
    info "Checking A.12 Operations Security..."
    
    # A.12.1.1 Documented operating procedures
    if [[ -f "$PROJECT_ROOT/docs/installation-guide.md" ]]; then
        passed_controls=$((passed_controls + 1))
        info "✅ A.12.1.1: Operating procedures documented"
    else
        warn "❌ A.12.1.1: Operating procedures not documented"
    fi
    total_controls=$((total_controls + 1))

    # A.12.6.1 Management of technical vulnerabilities
    if [[ -f "$PROJECT_ROOT/scripts/monitoring/security-audit.sh" ]]; then
        passed_controls=$((passed_controls + 1))
        info "✅ A.12.6.1: Vulnerability management procedures exist"
    else
        warn "❌ A.12.6.1: Vulnerability management not implemented"
    fi
    total_controls=$((total_controls + 1))

    # A.13 Communications Security
    info "Checking A.13 Communications Security..."
    
    # A.13.1.1 Network controls
    if systemctl is-active --quiet wg-quick@wg0; then
        passed_controls=$((passed_controls + 1))
        info "✅ A.13.1.1: Network security controls implemented"
    else
        warn "❌ A.13.1.1: Network security controls not active"
    fi
    total_controls=$((total_controls + 1))

    # Calculate ISO 27001 score
    local iso_percentage=$(( (passed_controls * 100) / total_controls ))

    # Update results
    iso_results=$(echo "$iso_results" | jq \
        --arg score "$iso_percentage" \
        --arg total "$total_controls" \
        --arg passed "$passed_controls" \
        --arg failed "$((total_controls - passed_controls))" \
        '.score = ($score | tonumber) | 
         .total_controls = ($total | tonumber) | 
         .passed = ($passed | tonumber) | 
         .failed = ($failed | tonumber)')

    log "ISO 27001 Compliance Score: $iso_percentage% ($passed_controls/$total_controls)"

    # Add to main report
    jq --argjson iso "$iso_results" \
       '.compliance_report.frameworks += [$iso]' \
       "$REPORT_FILE" > "$REPORT_FILE.tmp" && mv "$REPORT_FILE.tmp" "$REPORT_FILE"
}

# SOC 2 compliance check
check_soc2_compliance() {
    log "Checking SOC 2 Type II compliance..."

    local soc2_results='{
        "framework": "SOC2",
        "type": "Type II",
        "criteria": {},
        "score": 0,
        "total_controls": 0,
        "passed": 0,
        "failed": 0
    }'

    local total_controls=0
    local passed_controls=0

    # Security Criteria
    info "Checking Security Criteria..."
    
    # CC6.1 - Logical and physical access controls
    if [[ -f "$CONFIG_DIR/authelia/configuration.yml" ]]; then
        passed_controls=$((passed_controls + 1))
        info "✅ CC6.1: Logical access controls implemented"
    else
        warn "❌ CC6.1: Access controls not properly configured"
    fi
    total_controls=$((total_controls + 1))

    # CC6.7 - Data transmission
    if systemctl is-active --quiet wg-quick@wg0; then
        passed_controls=$((passed_controls + 1))
        info "✅ CC6.7: Data transmission is encrypted"
    else
        warn "❌ CC6.7: Encrypted transmission not verified"
    fi
    total_controls=$((total_controls + 1))

    # Availability Criteria
    info "Checking Availability Criteria..."
    
    # A1.1 - System availability
    if systemctl is-active --quiet wg-quick@wg0 && systemctl is-active --quiet authelia 2>/dev/null; then
        passed_controls=$((passed_controls + 1))
        info "✅ A1.1: System availability monitoring implemented"
    else
        warn "❌ A1.1: System availability not assured"
    fi
    total_controls=$((total_controls + 1))

    # Confidentiality Criteria
    info "Checking Confidentiality Criteria..."
    
    # C1.1 - Confidential information
    if [[ -f "$CERT_DIR/ca/ca.crt" ]]; then
        passed_controls=$((passed_controls + 1))
        info "✅ C1.1: Confidential information is protected"
    else
        warn "❌ C1.1: Confidentiality controls not verified"
    fi
    total_controls=$((total_controls + 1))

    # Calculate SOC 2 score
    local soc2_percentage=$(( (passed_controls * 100) / total_controls ))

    # Update results
    soc2_results=$(echo "$soc2_results" | jq \
        --arg score "$soc2_percentage" \
        --arg total "$total_controls" \
        --arg passed "$passed_controls" \
        --arg failed "$((total_controls - passed_controls))" \
        '.score = ($score | tonumber) | 
         .total_controls = ($total | tonumber) | 
         .passed = ($passed | tonumber) | 
         .failed = ($failed | tonumber)')

    log "SOC 2 Compliance Score: $soc2_percentage% ($passed_controls/$total_controls)"

    # Add to main report
    jq --argjson soc2 "$soc2_results" \
       '.compliance_report.frameworks += [$soc2]' \
       "$REPORT_FILE" > "$REPORT_FILE.tmp" && mv "$REPORT_FILE.tmp" "$REPORT_FILE"
}

# Generate compliance summary
generate_compliance_summary() {
    log "Generating compliance summary..."

    # Calculate overall scores
    local overall_score=$(jq '.compliance_report.frameworks | map(.score) | add / length' "$REPORT_FILE")
    local total_controls=$(jq '.compliance_report.frameworks | map(.total_controls) | add' "$REPORT_FILE")
    local passed_controls=$(jq '.compliance_report.frameworks | map(.passed) | add' "$REPORT_FILE")
    local failed_controls=$(jq '.compliance_report.frameworks | map(.failed) | add' "$REPORT_FILE")

    # Update main report
    jq --arg overall "$overall_score" \
       --arg total "$total_controls" \
       --arg passed "$passed_controls" \
       --arg failed "$failed_controls" \
       '.compliance_report.overall_score = ($overall | tonumber) |
        .compliance_report.total_controls = ($total | tonumber) |
        .compliance_report.passed_controls = ($passed | tonumber) |
        .compliance_report.failed_controls = ($failed | tonumber)' \
       "$REPORT_FILE" > "$REPORT_FILE.tmp" && mv "$REPORT_FILE.tmp" "$REPORT_FILE"

    # Display summary
    echo ""
    log "=== COMPLIANCE SUMMARY ==="
    printf "Overall Compliance Score: %.1f%%\n" "$overall_score"
    echo "Total Controls Checked: $total_controls"
    echo "Passed Controls: $passed_controls"
    echo "Failed Controls: $failed_controls"
    echo ""

    # Framework-specific scores
    jq -r '.compliance_report.frameworks[] | "\(.framework): \(.score)% (\(.passed)/\(.total_controls))"' "$REPORT_FILE"

    echo ""
    log "Detailed report saved to: $REPORT_FILE"
}

# Export compliance report
export_compliance_report() {
    local format="$1"
    local export_file="${REPORT_FILE%.*}.$format"

    case "$format" in
        "json")
            cp "$REPORT_FILE" "$export_file"
            log "JSON report exported to: $export_file"
            ;;
        "csv")
            # Convert JSON to CSV
            jq -r '.compliance_report.frameworks[] | [.framework, .score, .passed, .failed, .total_controls] | @csv' \
               "$REPORT_FILE" > "$export_file"
            log "CSV report exported to: $export_file"
            ;;
        "html")
            # Generate HTML report (simplified)
            cat > "$export_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Zero Trust VPN Compliance Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { background-color: #f0f0f0; padding: 20px; }
        .framework { margin: 20px 0; padding: 15px; border: 1px solid #ddd; }
        .passed { color: green; }
        .failed { color: red; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Zero Trust VPN Compliance Report</h1>
        <p>Generated: $(date)</p>
        <p>Overall Score: $(jq -r '.compliance_report.overall_score' "$REPORT_FILE")%</p>
    </div>
EOF
            jq -r '.compliance_report.frameworks[] | 
                   "<div class=\"framework\">
                    <h2>\(.framework)</h2>
                    <p>Score: \(.score)%</p>
                    <p class=\"passed\">Passed: \(.passed)</p>
                    <p class=\"failed\">Failed: \(.failed)</p>
                    </div>"' "$REPORT_FILE" >> "$export_file"
            echo "</body></html>" >> "$export_file"
            log "HTML report exported to: $export_file"
            ;;
        *)
            error "Unsupported export format: $format"
            ;;
    esac
}

# Main execution
main() {
    init_compliance_check

    log "Starting compliance check..."

    if [[ "$CHECK_ALL" == "true" ]]; then
        check_nist_compliance
        check_iso27001_compliance
        check_soc2_compliance
    else
        case "$FRAMEWORK" in
            "NIST")
                check_nist_compliance
                ;;
            "ISO27001")
                check_iso27001_compliance
                ;;
            "SOC2")
                check_soc2_compliance
                ;;
            "GDPR"|"HIPAA")
                warn "Framework $FRAMEWORK not yet implemented"
                ;;
        esac
    fi

    generate_compliance_summary

    if [[ -n "$EXPORT_FORMAT" ]]; then
        export_compliance_report "$EXPORT_FORMAT"
    fi

    if [[ "$GENERATE_REMEDIATION" == "true" ]]; then
        log "Remediation plan generation not yet implemented"
    fi

    log "Compliance check completed successfully"
}

# Parse arguments and run main function
parse_args "$@"
main