# Device Enrollment Guide

## Overview

This guide covers the comprehensive device enrollment process for the Zero Trust VPN infrastructure, including device registration, certificate provisioning, compliance checking, and ongoing management.

## Device Enrollment Process

### Prerequisites

Before enrolling a device, ensure:
- User account exists in the identity provider (LDAP/AD)
- Device meets minimum security requirements
- Network connectivity to enrollment services
- Required certificates and credentials

### Enrollment Methods

#### 1. Automated Enrollment (Recommended)

```bash
# Use the device enrollment script
./scripts/management/device-enrollment.sh \
  --user john.doe \
  --device laptop-001 \
  --platform linux \
  --auto-configure
```

#### 2. Manual Enrollment

```bash
# Step-by-step manual enrollment
./scripts/management/device-enrollment.sh \
  --user john.doe \
  --device laptop-001 \
  --platform linux \
  --manual \
  --interactive
```

#### 3. Bulk Enrollment

```bash
# Enroll multiple devices from CSV file
./scripts/management/bulk-enrollment.sh \
  --input devices.csv \
  --template corporate-laptop
```

## Device Types and Platforms

### Supported Platforms

#### Desktop Operating Systems
- **Windows 10/11**: Full support with WireGuard client
- **macOS 10.15+**: Native WireGuard support
- **Linux (Ubuntu/Debian/CentOS)**: Command-line and GUI clients
- **Chrome OS**: Android WireGuard app

#### Mobile Operating Systems
- **iOS 12+**: Official WireGuard app
- **Android 7+**: Official WireGuard app
- **Windows Mobile**: Limited support

#### IoT and Embedded Devices
- **Raspberry Pi**: Full Linux support
- **OpenWrt Routers**: Site-to-site VPN
- **Docker Containers**: Sidecar VPN containers

### Device Categories

#### Corporate Devices
```yaml
corporate_device:
  requirements:
    - Domain joined
    - Endpoint protection installed
    - Full disk encryption
    - Automatic updates enabled
  
  access_level: "full"
  monitoring: "standard"
  certificate_validity: "1y"
```

#### BYOD (Bring Your Own Device)
```yaml
byod_device:
  requirements:
    - Screen lock enabled
    - OS up to date
    - No jailbreak/root
    - VPN-only access
  
  access_level: "limited"
  monitoring: "enhanced"
  certificate_validity: "6m"
```

#### IoT Devices
```yaml
iot_device:
  requirements:
    - Default credentials changed
    - Firmware up to date
    - Network isolation
    - Limited functionality
  
  access_level: "restricted"
  monitoring: "comprehensive"
  certificate_validity: "3m"
```

## Device Registration

### Registration Workflow

1. **Device Discovery**
   ```bash
   # Scan for new devices on network
   nmap -sn 192.168.1.0/24 | grep -E "Nmap scan report"
   ```

2. **Device Identification**
   ```bash
   # Get device information
   ./scripts/management/device-info.sh --ip 192.168.1.100
   ```

3. **Compliance Check**
   ```bash
   # Verify device meets requirements
   ./scripts/management/compliance-check.sh --device laptop-001
   ```

4. **Certificate Generation**
   ```bash
   # Generate device certificate
   ./scripts/management/generate-cert.sh --device laptop-001 --user john.doe
   ```

### Device Information Collection

#### Required Information
- **Device Name**: Unique identifier
- **MAC Address**: Network interface identifier
- **Operating System**: Platform and version
- **Owner**: Associated user account
- **Device Type**: Category (laptop, phone, tablet, etc.)

#### Optional Information
- **Serial Number**: Hardware identifier
- **Asset Tag**: Corporate asset management
- **Location**: Physical or logical location
- **Department**: Organizational unit

### Registration Database

#### Device Registry Schema
```sql
CREATE TABLE devices (
    id SERIAL PRIMARY KEY,
    device_name VARCHAR(255) UNIQUE NOT NULL,
    mac_address VARCHAR(17) NOT NULL,
    ip_address INET,
    user_id VARCHAR(255) NOT NULL,
    device_type VARCHAR(50) NOT NULL,
    platform VARCHAR(50) NOT NULL,
    os_version VARCHAR(100),
    enrollment_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP,
    status VARCHAR(20) DEFAULT 'active',
    compliance_status VARCHAR(20) DEFAULT 'unknown',
    certificate_serial VARCHAR(255),
    certificate_expiry TIMESTAMP
);
```

## Certificate Management

### Certificate Lifecycle

#### 1. Certificate Generation
```bash
# Generate device certificate with specific parameters
openssl req -new -newkey rsa:4096 -nodes \
  -keyout devices/laptop-001.key \
  -out devices/laptop-001.csr \
  -subj "/CN=laptop-001.john.doe/O=Company/OU=IT"

# Sign certificate with CA
openssl ca -config ca.conf \
  -in devices/laptop-001.csr \
  -out devices/laptop-001.crt \
  -days 365
```

#### 2. Certificate Distribution
```bash
# Secure certificate delivery
./scripts/management/distribute-cert.sh \
  --device laptop-001 \
  --method secure-email \
  --recipient john.doe@company.com
```

#### 3. Certificate Installation
```bash
# Automated certificate installation (Linux)
./scripts/client/install-cert.sh \
  --cert laptop-001.crt \
  --key laptop-001.key \
  --ca ca.crt
```

#### 4. Certificate Renewal
```bash
# Automated renewal before expiry
./scripts/automation/cert-renewal.sh \
  --device laptop-001 \
  --renew-before 30d
```

### Certificate Policies

#### Validity Periods
- **High-privilege devices**: 6 months
- **Standard devices**: 1 year
- **IoT devices**: 3 months
- **Temporary access**: 30 days

#### Key Specifications
- **Algorithm**: RSA 4096-bit or ECDSA P-384
- **Hash**: SHA-256 minimum
- **Key Usage**: Digital Signature, Key Encipherment
- **Extended Key Usage**: Client Authentication

## Device Configuration

### WireGuard Client Configuration

#### Automated Configuration Generation
```bash
# Generate complete client configuration
./scripts/management/generate-client-config.sh \
  --user john.doe \
  --device laptop-001 \
  --template corporate \
  --output laptop-001.conf
```

#### Configuration Template
```ini
[Interface]
# Device private key
PrivateKey = DEVICE_PRIVATE_KEY

# Device IP within VPN network
Address = 10.8.0.100/32

# DNS servers
DNS = 10.8.0.1, 1.1.1.1

# MTU optimization
MTU = 1420

# Pre/Post scripts for additional security
PreUp = /opt/vpn/scripts/pre-connect.sh
PostUp = /opt/vpn/scripts/post-connect.sh
PreDown = /opt/vpn/scripts/pre-disconnect.sh
PostDown = /opt/vpn/scripts/post-disconnect.sh

[Peer]
# Server public key
PublicKey = SERVER_PUBLIC_KEY

# Server endpoint
Endpoint = vpn.company.com:51820

# Allowed IPs (split tunneling configuration)
AllowedIPs = 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16

# Keep alive for NAT traversal
PersistentKeepalive = 25
```

### Platform-Specific Configuration

#### Windows Configuration
```powershell
# Install WireGuard
winget install WireGuard.WireGuard

# Import configuration
wireguard.exe /installtunnelservice "C:\vpn\laptop-001.conf"

# Start tunnel
wireguard.exe /start laptop-001
```

#### macOS Configuration
```bash
# Install WireGuard
brew install wireguard-tools

# Import configuration
sudo wg-quick up laptop-001

# Enable at startup
sudo launchctl load /Library/LaunchDaemons/com.wireguard.laptop-001.plist
```

#### Linux Configuration
```bash
# Install WireGuard
sudo apt install wireguard

# Copy configuration
sudo cp laptop-001.conf /etc/wireguard/

# Start and enable
sudo systemctl enable wg-quick@laptop-001
sudo systemctl start wg-quick@laptop-001
```

#### Mobile Configuration
```bash
# Generate QR code for mobile import
qrencode -t ansiutf8 < laptop-001.conf
qrencode -o laptop-001-qr.png < laptop-001.conf
```

## Compliance and Security

### Device Compliance Policies

#### Security Requirements
```yaml
compliance_policies:
  corporate_device:
    required:
      - full_disk_encryption: true
      - antivirus_installed: true
      - firewall_enabled: true
      - auto_updates: true
      - screen_lock: true
      - password_policy: "complex"
    
    prohibited:
      - jailbreak_root: false
      - unknown_software: false
      - network_shares: false
      - remote_access_tools: false

  byod_device:
    required:
      - screen_lock: true
      - os_updated: true
      - vpn_only_access: true
    
    prohibited:
      - jailbreak_root: false
      - malware_detected: false
```

### Compliance Monitoring

#### Automated Compliance Checks
```bash
# Run compliance assessment
./scripts/monitoring/compliance-check.sh \
  --device laptop-001 \
  --policy corporate_device \
  --report-format json
```

#### Compliance Reporting
```bash
# Generate compliance report
./scripts/monitoring/compliance-report.sh \
  --scope all_devices \
  --format html \
  --output compliance-report.html
```

### Non-Compliance Actions

#### Automated Responses
1. **Warning**: Notify user and administrator
2. **Restricted Access**: Limit network access
3. **Quarantine**: Move to isolated network
4. **Revocation**: Disable device access

```bash
# Handle non-compliant device
./scripts/management/handle-non-compliance.sh \
  --device laptop-001 \
  --violation "antivirus_disabled" \
  --action "restrict_access"
```

## Device Monitoring

### Continuous Monitoring

#### Health Checks
```bash
# Monitor device health
./scripts/monitoring/device-health.sh \
  --device laptop-001 \
  --check-connectivity \
  --check-certificate \
  --check-compliance
```

#### Activity Monitoring
```bash
# Monitor device activity
./scripts/monitoring/device-activity.sh \
  --device laptop-001 \
  --timeframe 24h \
  --include-traffic-analysis
```

### Alerting and Notifications

#### Alert Conditions
- Device offline for extended period
- Certificate expiration approaching
- Compliance violation detected
- Suspicious network activity
- Failed authentication attempts

#### Notification Methods
```yaml
notifications:
  email:
    enabled: true
    recipients: ["admin@company.com", "security@company.com"]
  
  webhook:
    enabled: true
    url: "https://monitoring.company.com/webhook"
  
  sms:
    enabled: false
    provider: "twilio"
```

## Troubleshooting

### Common Issues

#### Connection Problems
```bash
# Diagnose connection issues
./scripts/troubleshooting/diagnose-connection.sh \
  --device laptop-001 \
  --verbose
```

#### Certificate Issues
```bash
# Check certificate validity
./scripts/troubleshooting/check-certificate.sh \
  --device laptop-001 \
  --verify-chain
```

#### Configuration Problems
```bash
# Validate configuration
./scripts/troubleshooting/validate-config.sh \
  --device laptop-001 \
  --fix-common-issues
```

### Support Procedures

#### Remote Assistance
```bash
# Enable remote support session
./scripts/support/remote-session.sh \
  --device laptop-001 \
  --duration 1h \
  --technician support.tech
```

#### Log Collection
```bash
# Collect diagnostic logs
./scripts/support/collect-logs.sh \
  --device laptop-001 \
  --include-system-logs \
  --encrypt-output
```

## Device Lifecycle Management

### Device Updates

#### Firmware Updates
```bash
# Check for device firmware updates
./scripts/management/check-firmware.sh \
  --device laptop-001 \
  --auto-update
```

#### Configuration Updates
```bash
# Push configuration updates
./scripts/management/update-config.sh \
  --device laptop-001 \
  --config-version 2.1 \
  --restart-required
```

### Device Retirement

#### Decommissioning Process
```bash
# Decommission device
./scripts/management/decommission-device.sh \
  --device laptop-001 \
  --revoke-certificates \
  --wipe-configuration \
  --archive-logs
```

#### Data Sanitization
```bash
# Secure data removal
./scripts/management/sanitize-device.sh \
  --device laptop-001 \
  --method "dod-5220.22-m" \
  --verify-completion
```

## Best Practices

### Security Best Practices

1. **Principle of Least Privilege**
   - Grant minimum necessary access
   - Regular access reviews
   - Time-limited certificates

2. **Defense in Depth**
   - Multiple authentication factors
   - Device compliance monitoring
   - Network segmentation

3. **Continuous Monitoring**
   - Real-time device monitoring
   - Automated compliance checks
   - Proactive threat detection

### Operational Best Practices

1. **Standardization**
   - Consistent device configurations
   - Standardized naming conventions
   - Uniform security policies

2. **Automation**
   - Automated enrollment processes
   - Self-service capabilities
   - Automated compliance monitoring

3. **Documentation**
   - Comprehensive device inventory
   - Detailed configuration records
   - Incident response procedures

## Integration with External Systems

### Identity Provider Integration

#### LDAP/Active Directory
```bash
# Sync device information with AD
./scripts/integration/ad-sync.sh \
  --sync-devices \
  --update-attributes \
  --create-computer-objects
```

#### SCIM Integration
```bash
# SCIM-based device provisioning
./scripts/integration/scim-sync.sh \
  --endpoint "https://identity.company.com/scim/v2" \
  --sync-devices
```

### Asset Management Integration

#### ServiceNow Integration
```bash
# Sync with ServiceNow CMDB
./scripts/integration/servicenow-sync.sh \
  --instance company.service-now.com \
  --table cmdb_ci_computer \
  --sync-vpn-devices
```

### Security Tool Integration

#### SIEM Integration
```bash
# Send device events to SIEM
./scripts/integration/siem-integration.sh \
  --siem-type splunk \
  --endpoint "https://splunk.company.com:8088" \
  --send-device-events
```

## References

- [WireGuard Protocol Specification](https://www.wireguard.com/protocol/)
- [NIST SP 800-124: Guidelines for Managing the Security of Mobile Devices](https://csrc.nist.gov/publications/detail/sp/800-124/rev-1/final)
- [Zero Trust Device Security](https://www.nist.gov/publications/zero-trust-architecture)
- [PKI Best Practices](https://www.rfc-editor.org/rfc/rfc4210.html)