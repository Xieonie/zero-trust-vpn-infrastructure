# Zero Trust VPN User Management Guide

## Overview

This guide covers comprehensive user management for the Zero Trust VPN infrastructure, including user lifecycle management, access control policies, and security procedures.

## User Lifecycle Management

### User Onboarding Process

#### 1. Initial User Creation

```bash
# Create new user with basic access
./scripts/management/add-user.sh \
  --username john.doe \
  --email john.doe@company.com \
  --full-name "John Doe" \
  --department "IT" \
  --role "employee" \
  --manager "jane.smith"
```

#### 2. Device Enrollment

```bash
# Enroll user's primary device
./scripts/management/device-enrollment.sh \
  --user john.doe \
  --device laptop \
  --platform linux \
  --description "Primary work laptop"

# Enroll mobile device
./scripts/management/device-enrollment.sh \
  --user john.doe \
  --device phone \
  --platform android \
  --description "Company mobile phone"
```

#### 3. Access Policy Assignment

```bash
# Assign user to appropriate groups
./scripts/management/policy-update.sh \
  --user john.doe \
  --add-groups "employees,vpn-users" \
  --access-level "standard"
```

### User Modification

#### Updating User Information

```bash
# Update user details
ldapmodify -x -H ldap://localhost:389 \
  -D "cn=admin,dc=company,dc=com" \
  -w "$LDAP_PASSWORD" << EOF
dn: uid=john.doe,ou=users,dc=company,dc=com
changetype: modify
replace: mail
mail: john.doe@newcompany.com
-
replace: telephoneNumber
telephoneNumber: +1-555-0123
EOF
```

#### Role Changes

```bash
# Promote user to administrator
./scripts/management/policy-update.sh \
  --user john.doe \
  --add-groups "administrators" \
  --access-level "admin" \
  --require-mfa "fido2"
```

### User Offboarding

#### Immediate Access Revocation

```bash
# Revoke all access immediately
./scripts/management/revoke-user.sh \
  --username john.doe \
  --reason "Employee terminated" \
  --force
```

#### Graceful Transition

```bash
# Disable account but preserve data for transition
./scripts/management/disable-user.sh \
  --username john.doe \
  --reason "Role change" \
  --preserve-data \
  --transition-period "30d"
```

## Access Control Policies

### User Roles and Permissions

#### Standard Employee
```yaml
role: employee
permissions:
  vpn_access: true
  network_zones:
    - internal
    - dmz
  services:
    - web_browsing
    - email
    - file_sharing
  restrictions:
    - no_admin_access
    - time_based_access: "business_hours"
    - bandwidth_limit: "100Mbps"
```

#### Administrator
```yaml
role: administrator
permissions:
  vpn_access: true
  network_zones:
    - internal
    - dmz
    - secure
    - management
  services:
    - all
  restrictions:
    - mfa_required: "fido2"
    - session_timeout: "4h"
    - approval_required: "manager"
```

#### Contractor
```yaml
role: contractor
permissions:
  vpn_access: true
  network_zones:
    - dmz
  services:
    - web_browsing
    - specific_applications
  restrictions:
    - time_limited_access: "project_duration"
    - bandwidth_limit: "50Mbps"
    - no_file_download
```

### Group-Based Access Control

#### Creating User Groups

```bash
# Create department group
ldapadd -x -H ldap://localhost:389 \
  -D "cn=admin,dc=company,dc=com" \
  -w "$LDAP_PASSWORD" << EOF
dn: cn=engineering,ou=groups,dc=company,dc=com
objectClass: groupOfNames
cn: engineering
description: Engineering Department
member: uid=john.doe,ou=users,dc=company,dc=com
EOF
```

#### Assigning Group Policies

```bash
# Update Authelia configuration for group access
cat >> config/authelia/configuration.yml << EOF
access_control:
  rules:
    - domain: "engineering.company.com"
      policy: two_factor
      subject: "group:engineering"
      networks:
        - internal
        - vpn
EOF
```

## Multi-Factor Authentication

### MFA Setup Process

#### TOTP Configuration

```bash
# Generate TOTP secret for user
./scripts/management/setup-mfa.sh \
  --user john.doe \
  --method totp \
  --app "Google Authenticator"
```

#### FIDO2 Hardware Keys

```bash
# Register FIDO2 key
./scripts/management/setup-mfa.sh \
  --user john.doe \
  --method fido2 \
  --device "YubiKey 5 NFC"
```

#### Backup Codes

```bash
# Generate backup codes
./scripts/management/generate-backup-codes.sh \
  --user john.doe \
  --count 10
```

### MFA Policy Enforcement

#### Role-Based MFA Requirements

```yaml
mfa_policies:
  employees:
    primary: "totp"
    backup: "backup_codes"
    grace_period: "7d"
    
  administrators:
    primary: "fido2"
    secondary: "totp"
    backup: "backup_codes"
    grace_period: "0d"
    
  contractors:
    primary: "totp"
    backup: "sms"
    grace_period: "3d"
```

## Device Management

### Device Registration

#### Automatic Device Discovery

```bash
# Scan for new devices
./scripts/monitoring/device-discovery.sh \
  --scan-network "10.8.0.0/24" \
  --identify-os \
  --check-compliance
```

#### Manual Device Registration

```bash
# Register known device
./scripts/management/register-device.sh \
  --user john.doe \
  --device-id "laptop-001" \
  --mac-address "00:11:22:33:44:55" \
  --device-type "laptop" \
  --os "Ubuntu 22.04"
```

### Device Compliance

#### Compliance Policies

```yaml
device_compliance:
  minimum_requirements:
    os_version:
      windows: "Windows 10 1909"
      macos: "macOS 11.0"
      linux: "Ubuntu 20.04"
    antivirus: "required"
    firewall: "enabled"
    encryption: "full_disk"
    
  security_checks:
    - patch_level: "current"
    - malware_scan: "clean"
    - unauthorized_software: "none"
    - network_shares: "secured"
```

#### Compliance Monitoring

```bash
# Check device compliance
./scripts/monitoring/compliance-check.sh \
  --user john.doe \
  --device laptop \
  --generate-report
```

### Device Quarantine

#### Automatic Quarantine Triggers

```bash
# Configure automatic quarantine
cat > config/quarantine-rules.yml << EOF
quarantine_triggers:
  - malware_detected
  - compliance_failure
  - suspicious_behavior
  - unauthorized_access_attempt
  - certificate_expired
  
quarantine_actions:
  - isolate_network_access
  - notify_security_team
  - require_manual_review
  - generate_incident_report
EOF
```

## Session Management

### Session Policies

#### Session Configuration

```yaml
session_management:
  default_timeout: "8h"
  idle_timeout: "30m"
  max_concurrent_sessions: 3
  
  role_based_timeouts:
    employee: "8h"
    administrator: "4h"
    contractor: "4h"
    
  security_actions:
    - log_all_sessions
    - monitor_concurrent_logins
    - detect_session_hijacking
    - enforce_session_encryption
```

#### Session Monitoring

```bash
# Monitor active sessions
./scripts/monitoring/session-monitor.sh \
  --show-active \
  --check-anomalies \
  --generate-alerts
```

### Session Security

#### Detecting Anomalous Sessions

```bash
# Analyze session patterns
./scripts/monitoring/session-analysis.sh \
  --user john.doe \
  --timeframe "24h" \
  --check-patterns \
  --detect-anomalies
```

## Audit and Compliance

### User Activity Logging

#### Log Configuration

```yaml
audit_logging:
  events:
    - user_login
    - user_logout
    - permission_changes
    - device_enrollment
    - policy_updates
    - mfa_events
    
  retention:
    security_events: "7y"
    access_logs: "3y"
    session_logs: "1y"
    
  compliance:
    - gdpr_compliant
    - hipaa_compliant
    - sox_compliant
```

#### Generating Audit Reports

```bash
# Generate user activity report
./scripts/monitoring/audit-report.sh \
  --user john.doe \
  --period "monthly" \
  --include-devices \
  --include-sessions \
  --format "pdf"
```

### Compliance Reporting

#### Regular Compliance Checks

```bash
# Run compliance audit
./scripts/monitoring/compliance-audit.sh \
  --scope "all_users" \
  --check-policies \
  --verify-mfa \
  --validate-devices \
  --generate-report
```

## Emergency Procedures

### Emergency Access

#### Break-Glass Access

```bash
# Emergency administrator access
./scripts/emergency/break-glass-access.sh \
  --admin-user "emergency.admin" \
  --reason "Security incident" \
  --duration "2h" \
  --approval-code "$EMERGENCY_CODE"
```

#### Mass User Lockout

```bash
# Lock all users in emergency
./scripts/emergency/mass-lockout.sh \
  --reason "Security breach" \
  --exclude-users "emergency.admin,security.team" \
  --notify-management
```

### Incident Response

#### Compromised User Account

```bash
# Respond to compromised account
./scripts/incident-response/compromised-user.sh \
  --user john.doe \
  --actions "disable,revoke-certs,quarantine-devices" \
  --notify-security \
  --preserve-evidence
```

## Automation and Integration

### Automated User Provisioning

#### HR System Integration

```bash
# Sync with HR system
./scripts/automation/hr-sync.sh \
  --source "hr-database" \
  --action "sync-users" \
  --dry-run false \
  --notify-changes
```

#### Identity Provider Integration

```bash
# Sync with Active Directory
./scripts/automation/ad-sync.sh \
  --ad-server "dc.company.com" \
  --sync-groups \
  --update-policies \
  --validate-sync
```

### Automated Compliance

#### Daily Compliance Checks

```bash
# Automated daily compliance
./scripts/automation/daily-compliance.sh \
  --check-all-users \
  --verify-devices \
  --update-policies \
  --send-reports
```

## Best Practices

### Security Guidelines

1. **Principle of Least Privilege**
   - Grant minimum necessary access
   - Regular access reviews
   - Time-limited permissions

2. **Defense in Depth**
   - Multiple authentication factors
   - Device compliance checking
   - Network segmentation

3. **Continuous Monitoring**
   - Real-time session monitoring
   - Behavioral analysis
   - Automated threat detection

### Operational Procedures

1. **Regular Maintenance**
   - Weekly access reviews
   - Monthly compliance audits
   - Quarterly security assessments

2. **Documentation**
   - Maintain user documentation
   - Update procedures regularly
   - Track all changes

3. **Training and Awareness**
   - User security training
   - Administrator certification
   - Incident response drills

## Troubleshooting

### Common Issues

#### User Cannot Connect

```bash
# Diagnose connection issues
./scripts/troubleshooting/diagnose-user.sh \
  --user john.doe \
  --check-certificates \
  --verify-policies \
  --test-connectivity
```

#### MFA Problems

```bash
# Reset MFA for user
./scripts/management/reset-mfa.sh \
  --user john.doe \
  --method totp \
  --generate-backup-codes \
  --notify-user
```

#### Device Compliance Issues

```bash
# Fix compliance issues
./scripts/troubleshooting/fix-compliance.sh \
  --user john.doe \
  --device laptop \
  --auto-fix \
  --generate-report
```

### Support Procedures

#### User Support Workflow

1. **Initial Assessment**
   - Verify user identity
   - Document issue details
   - Check system status

2. **Troubleshooting**
   - Run diagnostic scripts
   - Check logs and events
   - Test connectivity

3. **Resolution**
   - Apply fixes
   - Verify resolution
   - Document solution

4. **Follow-up**
   - Confirm user satisfaction
   - Update documentation
   - Prevent recurrence

## References

- [NIST SP 800-63B: Authentication and Lifecycle Management](https://csrc.nist.gov/publications/detail/sp/800-63b/final)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [Zero Trust Architecture Guidelines](https://www.nist.gov/publications/zero-trust-architecture)