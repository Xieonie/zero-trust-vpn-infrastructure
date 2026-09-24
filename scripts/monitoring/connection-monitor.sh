#!/bin/bash

# Zero Trust VPN - Connection Monitoring Script
# This script monitors VPN connections, detects anomalies, and generates alerts

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
LOG_FILE="/var/log/zero-trust-vpn/connection-monitor.log"
ALERT_LOG="/var/log/zero-trust-vpn/alerts.log"
CONFIG_FILE="/opt/zero-trust-vpn/config/monitoring.conf"
WG_INTERFACE="wg0"

# Monitoring thresholds
MAX_FAILED_ATTEMPTS=5
SUSPICIOUS_TRAFFIC_THRESHOLD=1000000  # 1MB/s
MAX_CONCURRENT_CONNECTIONS=10
ANOMALY_DETECTION_WINDOW=300  # 5 minutes

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

# Alert function
alert() {
    local severity="$1"
    local message="$2"
    local alert_msg="$(date '+%Y-%m-%d %H:%M:%S') - [$severity] $message"
    
    echo "$alert_msg" | tee -a "$ALERT_LOG"
    
    # Send notifications based on severity
    case "$severity" in
        "CRITICAL")
            send_notification "🚨 CRITICAL ALERT" "$message" "high"
            ;;
        "WARNING")
            send_notification "⚠️ WARNING" "$message" "medium"
            ;;
        "INFO")
            send_notification "ℹ️ INFO" "$message" "low"
            ;;
    esac
}

# Error handling
error_exit() {
    echo -e "${RED}ERROR: $1${NC}" >&2
    log "ERROR: $1"
    alert "CRITICAL" "Monitoring script error: $1"
    exit 1
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

Monitor Zero Trust VPN connections and detect anomalies

OPTIONS:
    -i, --interface INTERFACE   WireGuard interface to monitor (default: wg0)
    -c, --continuous            Run in continuous monitoring mode
    -a, --analyze-logs          Analyze historical logs for patterns
    -r, --report                Generate monitoring report
    -t, --test-alerts           Test alert system
    -h, --help                  Show this help message

EXAMPLES:
    $0                          # Single monitoring check
    $0 --continuous             # Continuous monitoring
    $0 --analyze-logs           # Analyze log patterns
    $0 --report                 # Generate report

EOF
}

# Parse command line arguments
CONTINUOUS=false
ANALYZE_LOGS=false
GENERATE_REPORT=false
TEST_ALERTS=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -i|--interface)
            WG_INTERFACE="$2"
            shift 2
            ;;
        -c|--continuous)
            CONTINUOUS=true
            shift
            ;;
        -a|--analyze-logs)
            ANALYZE_LOGS=true
            shift
            ;;
        -r|--report)
            GENERATE_REPORT=true
            shift
            ;;
        -t|--test-alerts)
            TEST_ALERTS=true
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

# Create log directories
mkdir -p "$(dirname "$LOG_FILE")"
mkdir -p "$(dirname "$ALERT_LOG")"

# Function to load configuration
load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        source "$CONFIG_FILE"
    else
        # Create default configuration
        mkdir -p "$(dirname "$CONFIG_FILE")"
        cat > "$CONFIG_FILE" << EOF
# Connection Monitoring Configuration

# Thresholds
MAX_FAILED_ATTEMPTS=5
SUSPICIOUS_TRAFFIC_THRESHOLD=1000000
MAX_CONCURRENT_CONNECTIONS=10
ANOMALY_DETECTION_WINDOW=300

# Notification settings
WEBHOOK_URL=""
SLACK_WEBHOOK=""
EMAIL_ALERTS=true
ADMIN_EMAIL="admin@example.com"

# SMTP settings
SMTP_SERVER="localhost"
SMTP_PORT=587
SMTP_USER=""
SMTP_PASSWORD=""

# Monitoring intervals
CHECK_INTERVAL=60
LOG_RETENTION_DAYS=30
ALERT_RETENTION_DAYS=90
EOF
        info "Created default configuration: $CONFIG_FILE"
    fi
}

# Function to get WireGuard statistics
get_wireguard_stats() {
    local interface="$1"
    
    if ! ip link show "$interface" >/dev/null 2>&1; then
        alert "CRITICAL" "WireGuard interface $interface is not available"
        return 1
    fi
    
    # Get interface statistics
    local stats
    stats=$(wg show "$interface" 2>/dev/null || echo "")
    
    if [[ -z "$stats" ]]; then
        alert "WARNING" "Unable to retrieve WireGuard statistics for $interface"
        return 1
    fi
    
    echo "$stats"
}

# Function to monitor active connections
monitor_connections() {
    local interface="$1"
    
    info "Monitoring connections on interface: $interface"
    
    # Get current connections
    local connections
    connections=$(wg show "$interface" peers 2>/dev/null | wc -l || echo "0")
    
    log "Active connections: $connections"
    
    # Check for too many concurrent connections
    if [[ $connections -gt $MAX_CONCURRENT_CONNECTIONS ]]; then
        alert "WARNING" "High number of concurrent connections: $connections (threshold: $MAX_CONCURRENT_CONNECTIONS)"
    fi
    
    # Analyze each peer
    while IFS= read -r peer; do
        if [[ -n "$peer" ]]; then
            analyze_peer_connection "$interface" "$peer"
        fi
    done < <(wg show "$interface" peers 2>/dev/null || true)
}

# Function to analyze individual peer connections
analyze_peer_connection() {
    local interface="$1"
    local peer="$2"
    
    # Get peer information
    local peer_info
    peer_info=$(wg show "$interface" peer "$peer" 2>/dev/null || echo "")
    
    if [[ -z "$peer_info" ]]; then
        return
    fi
    
    # Extract connection details
    local endpoint
    endpoint=$(echo "$peer_info" | grep "endpoint:" | awk '{print $2}' || echo "unknown")
    
    local latest_handshake
    latest_handshake=$(echo "$peer_info" | grep "latest handshake:" | cut -d':' -f2- | xargs || echo "never")
    
    local transfer
    transfer=$(echo "$peer_info" | grep "transfer:" | cut -d':' -f2- | xargs || echo "0 B received, 0 B sent")
    
    # Parse transfer data
    local received sent
    received=$(echo "$transfer" | awk '{print $1, $2}' | sed 's/,//')
    sent=$(echo "$transfer" | awk '{print $4, $5}')
    
    # Convert to bytes for analysis
    local received_bytes sent_bytes
    received_bytes=$(convert_to_bytes "$received")
    sent_bytes=$(convert_to_bytes "$sent")
    
    # Check for suspicious traffic patterns
    check_traffic_anomalies "$peer" "$received_bytes" "$sent_bytes"
    
    # Check handshake freshness
    check_handshake_freshness "$peer" "$latest_handshake"
    
    # Log connection details
    log "Peer: $peer, Endpoint: $endpoint, Handshake: $latest_handshake, Transfer: $transfer"
}

# Function to convert human-readable sizes to bytes
convert_to_bytes() {
    local size="$1"
    local number unit
    
    number=$(echo "$size" | awk '{print $1}')
    unit=$(echo "$size" | awk '{print $2}' | tr '[:lower:]' '[:upper:]')
    
    case "$unit" in
        "B"|"BYTES")
            echo "$number"
            ;;
        "KB"|"KIB")
            echo $((number * 1024))
            ;;
        "MB"|"MIB")
            echo $((number * 1024 * 1024))
            ;;
        "GB"|"GIB")
            echo $((number * 1024 * 1024 * 1024))
            ;;
        *)
            echo "0"
            ;;
    esac
}

# Function to check traffic anomalies
check_traffic_anomalies() {
    local peer="$1"
    local received_bytes="$2"
    local sent_bytes="$3"
    
    # Calculate total traffic
    local total_traffic=$((received_bytes + sent_bytes))
    
    # Check against threshold (per monitoring window)
    local traffic_rate=$((total_traffic / ANOMALY_DETECTION_WINDOW))
    
    if [[ $traffic_rate -gt $SUSPICIOUS_TRAFFIC_THRESHOLD ]]; then
        alert "WARNING" "Suspicious traffic volume from peer $peer: $(($traffic_rate / 1024 / 1024)) MB/s"
    fi
    
    # Check for unusual patterns
    if [[ $received_bytes -gt 0 && $sent_bytes -eq 0 ]]; then
        alert "INFO" "Peer $peer shows download-only pattern (potential data exfiltration)"
    elif [[ $sent_bytes -gt 0 && $received_bytes -eq 0 ]]; then
        alert "INFO" "Peer $peer shows upload-only pattern (potential data injection)"
    fi
}

# Function to check handshake freshness
check_handshake_freshness() {
    local peer="$1"
    local handshake="$2"
    
    if [[ "$handshake" == "never" ]]; then
        alert "WARNING" "Peer $peer has never completed a handshake"
        return
    fi
    
    # Parse handshake time (this is simplified - actual parsing would be more complex)
    if echo "$handshake" | grep -q "hour\|day"; then
        alert "WARNING" "Peer $peer has stale handshake: $handshake"
    fi
}

# Function to monitor authentication logs
monitor_auth_logs() {
    info "Monitoring authentication logs..."
    
    # Check Authelia logs for failed attempts
    local authelia_log="/var/log/authelia/authelia.log"
    if [[ -f "$authelia_log" ]]; then
        local failed_attempts
        failed_attempts=$(grep -c "authentication failed" "$authelia_log" 2>/dev/null || echo "0")
        
        if [[ $failed_attempts -gt $MAX_FAILED_ATTEMPTS ]]; then
            alert "WARNING" "High number of authentication failures: $failed_attempts"
        fi
    fi
    
    # Check system auth logs
    local recent_failures
    recent_failures=$(journalctl -u wg-quick@"$WG_INTERFACE" --since="5 minutes ago" | grep -c "failed\|error" || echo "0")
    
    if [[ $recent_failures -gt 0 ]]; then
        alert "INFO" "WireGuard service errors in last 5 minutes: $recent_failures"
    fi
}

# Function to check system resources
check_system_resources() {
    info "Checking system resources..."
    
    # Check CPU usage
    local cpu_usage
    cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
    
    if (( $(echo "$cpu_usage > 80" | bc -l) )); then
        alert "WARNING" "High CPU usage: ${cpu_usage}%"
    fi
    
    # Check memory usage
    local mem_usage
    mem_usage=$(free | grep Mem | awk '{printf "%.1f", $3/$2 * 100.0}')
    
    if (( $(echo "$mem_usage > 85" | bc -l) )); then
        alert "WARNING" "High memory usage: ${mem_usage}%"
    fi
    
    # Check disk usage
    local disk_usage
    disk_usage=$(df / | tail -1 | awk '{print $5}' | cut -d'%' -f1)
    
    if [[ $disk_usage -gt 90 ]]; then
        alert "CRITICAL" "High disk usage: ${disk_usage}%"
    fi
    
    # Check network interface status
    if ! ip link show "$WG_INTERFACE" | grep -q "UP"; then
        alert "CRITICAL" "WireGuard interface $WG_INTERFACE is down"
    fi
}

# Function to analyze log patterns
analyze_log_patterns() {
    info "Analyzing log patterns..."
    
    local log_analysis_file="/tmp/log_analysis_$(date +%s).txt"
    
    # Analyze connection patterns
    echo "=== Connection Pattern Analysis ===" > "$log_analysis_file"
    echo "Analysis generated on: $(date)" >> "$log_analysis_file"
    echo >> "$log_analysis_file"
    
    # Most active peers
    echo "Top 10 Most Active Peers:" >> "$log_analysis_file"
    grep "Peer:" "$LOG_FILE" | awk '{print $4}' | sort | uniq -c | sort -nr | head -10 >> "$log_analysis_file"
    echo >> "$log_analysis_file"
    
    # Connection times analysis
    echo "Connection Activity by Hour:" >> "$log_analysis_file"
    grep "Active connections:" "$LOG_FILE" | awk '{print $2}' | cut -d':' -f1 | sort | uniq -c >> "$log_analysis_file"
    echo >> "$log_analysis_file"
    
    # Alert frequency
    echo "Alert Frequency (Last 24 Hours):" >> "$log_analysis_file"
    grep "$(date '+%Y-%m-%d')" "$ALERT_LOG" | awk '{print $4}' | sort | uniq -c >> "$log_analysis_file"
    echo >> "$log_analysis_file"
    
    # Failed authentication attempts
    echo "Authentication Failure Patterns:" >> "$log_analysis_file"
    grep "authentication failed" /var/log/authelia/authelia.log 2>/dev/null | \
        awk '{print $1, $2}' | cut -d':' -f1 | sort | uniq -c | tail -20 >> "$log_analysis_file" || \
        echo "No Authelia logs found" >> "$log_analysis_file"
    
    echo "Log analysis saved to: $log_analysis_file"
    cat "$log_analysis_file"
}

# Function to generate monitoring report
generate_monitoring_report() {
    info "Generating monitoring report..."
    
    local report_file="/tmp/vpn_monitoring_report_$(date +%Y%m%d_%H%M%S).html"
    
    cat > "$report_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Zero Trust VPN Monitoring Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 10px; border-radius: 5px; }
        .section { margin: 20px 0; }
        .alert-critical { color: red; font-weight: bold; }
        .alert-warning { color: orange; font-weight: bold; }
        .alert-info { color: blue; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Zero Trust VPN Monitoring Report</h1>
        <p>Generated on: $(date)</p>
        <p>Interface: $WG_INTERFACE</p>
    </div>
    
    <div class="section">
        <h2>Current Status</h2>
        <table>
            <tr><th>Metric</th><th>Value</th><th>Status</th></tr>
EOF
    
    # Add current statistics
    local connections
    connections=$(wg show "$WG_INTERFACE" peers 2>/dev/null | wc -l || echo "0")
    
    local interface_status
    if ip link show "$WG_INTERFACE" | grep -q "UP"; then
        interface_status="UP"
    else
        interface_status="DOWN"
    fi
    
    cat >> "$report_file" << EOF
            <tr><td>Active Connections</td><td>$connections</td><td>$([ $connections -le $MAX_CONCURRENT_CONNECTIONS ] && echo "OK" || echo "HIGH")</td></tr>
            <tr><td>Interface Status</td><td>$interface_status</td><td>$([ "$interface_status" = "UP" ] && echo "OK" || echo "ERROR")</td></tr>
        </table>
    </div>
    
    <div class="section">
        <h2>Recent Alerts (Last 24 Hours)</h2>
        <table>
            <tr><th>Time</th><th>Severity</th><th>Message</th></tr>
EOF
    
    # Add recent alerts
    grep "$(date '+%Y-%m-%d')" "$ALERT_LOG" 2>/dev/null | tail -20 | while IFS= read -r line; do
        local timestamp severity message
        timestamp=$(echo "$line" | awk '{print $1, $2}')
        severity=$(echo "$line" | awk '{print $4}' | tr -d '[]')
        message=$(echo "$line" | cut -d']' -f2- | xargs)
        
        local css_class
        case "$severity" in
            "CRITICAL") css_class="alert-critical" ;;
            "WARNING") css_class="alert-warning" ;;
            *) css_class="alert-info" ;;
        esac
        
        echo "<tr><td>$timestamp</td><td class=\"$css_class\">$severity</td><td>$message</td></tr>" >> "$report_file"
    done || echo "<tr><td colspan=\"3\">No alerts in the last 24 hours</td></tr>" >> "$report_file"
    
    cat >> "$report_file" << EOF
        </table>
    </div>
    
    <div class="section">
        <h2>System Resources</h2>
        <table>
            <tr><th>Resource</th><th>Usage</th><th>Status</th></tr>
EOF
    
    # Add system resource information
    local cpu_usage mem_usage disk_usage
    cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
    mem_usage=$(free | grep Mem | awk '{printf "%.1f", $3/$2 * 100.0}')
    disk_usage=$(df / | tail -1 | awk '{print $5}' | cut -d'%' -f1)
    
    cat >> "$report_file" << EOF
            <tr><td>CPU</td><td>${cpu_usage}%</td><td>$([ $(echo "$cpu_usage < 80" | bc -l) -eq 1 ] && echo "OK" || echo "HIGH")</td></tr>
            <tr><td>Memory</td><td>${mem_usage}%</td><td>$([ $(echo "$mem_usage < 85" | bc -l) -eq 1 ] && echo "OK" || echo "HIGH")</td></tr>
            <tr><td>Disk</td><td>${disk_usage}%</td><td>$([ $disk_usage -lt 90 ] && echo "OK" || echo "HIGH")</td></tr>
        </table>
    </div>
    
</body>
</html>
EOF
    
    echo "Monitoring report generated: $report_file"
    
    # Send report via email if configured
    if [[ "${EMAIL_ALERTS:-false}" == "true" && -n "${ADMIN_EMAIL:-}" ]]; then
        send_email_report "$report_file"
    fi
}

# Function to send notifications
send_notification() {
    local title="$1"
    local message="$2"
    local priority="$3"
    
    # Webhook notification
    if [[ -n "${WEBHOOK_URL:-}" ]]; then
        curl -X POST "$WEBHOOK_URL" \
            -H "Content-Type: application/json" \
            -d "{\"title\":\"$title\",\"message\":\"$message\",\"priority\":\"$priority\",\"timestamp\":\"$(date -Iseconds)\"}" \
            >/dev/null 2>&1 || true
    fi
    
    # Slack notification
    if [[ -n "${SLACK_WEBHOOK:-}" ]]; then
        curl -X POST "$SLACK_WEBHOOK" \
            -H "Content-Type: application/json" \
            -d "{\"text\":\"$title\\n$message\"}" \
            >/dev/null 2>&1 || true
    fi
    
    # Email notification for critical alerts
    if [[ "$priority" == "high" && "${EMAIL_ALERTS:-false}" == "true" ]]; then
        send_email_alert "$title" "$message"
    fi
}

# Function to send email alerts
send_email_alert() {
    local subject="$1"
    local body="$2"
    
    if command -v mail >/dev/null 2>&1 && [[ -n "${ADMIN_EMAIL:-}" ]]; then
        echo "$body" | mail -s "$subject" "${ADMIN_EMAIL}"
    fi
}

# Function to test alert system
test_alert_system() {
    info "Testing alert system..."
    
    alert "INFO" "Test info alert - monitoring system is working"
    alert "WARNING" "Test warning alert - this is a test"
    alert "CRITICAL" "Test critical alert - this is a test"
    
    success "Alert system test completed"
}

# Function for continuous monitoring
continuous_monitoring() {
    info "Starting continuous monitoring mode..."
    
    while true; do
        echo "=== Monitoring Check: $(date) ==="
        
        # Load current configuration
        load_config
        
        # Perform monitoring checks
        monitor_connections "$WG_INTERFACE"
        monitor_auth_logs
        check_system_resources
        
        echo "=== Check Complete ==="
        echo
        
        # Wait for next check
        sleep "${CHECK_INTERVAL:-60}"
    done
}

# Main execution
main() {
    echo "Zero Trust VPN - Connection Monitor"
    echo "=================================="
    echo
    
    # Load configuration
    load_config
    
    # Handle different modes
    if [[ "$TEST_ALERTS" == "true" ]]; then
        test_alert_system
        return
    fi
    
    if [[ "$ANALYZE_LOGS" == "true" ]]; then
        analyze_log_patterns
        return
    fi
    
    if [[ "$GENERATE_REPORT" == "true" ]]; then
        generate_monitoring_report
        return
    fi
    
    if [[ "$CONTINUOUS" == "true" ]]; then
        continuous_monitoring
        return
    fi
    
    # Single monitoring check
    log "Starting monitoring check"
    monitor_connections "$WG_INTERFACE"
    monitor_auth_logs
    check_system_resources
    log "Monitoring check completed"
}

# Run main function
main "$@"