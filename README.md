# Zero Trust VPN Infrastructure 🔐🌐

This repository documents the implementation of a secure remote access solution using WireGuard VPN with Zero Trust principles. The infrastructure ensures that no user or device is trusted by default, and every access request is verified, authenticated, and authorized before granting access to network resources.

**Important Note:** Zero Trust architecture requires careful planning and implementation. The configurations provided here serve as a foundation but must be adapted to your specific security requirements and network topology.

## 🎯 Goals

* Implement Zero Trust network access principles
* Provide secure remote access to internal resources
* Ensure strong authentication and authorization for all connections
* Enable granular access control based on user identity and device posture
* Maintain comprehensive logging and monitoring of all access attempts
* Support scalable user and device management

## 🛠️ Technologies Used

* [WireGuard](https://www.wireguard.com/) - Modern VPN protocol
* [wg-easy](https://github.com/wg-easy/wg-easy) - WireGuard management interface
* [Authelia](https://www.authelia.com/) - Authentication and authorization server
* [LDAP](https://ldap.com/) or [Active Directory](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/) - User directory
* [FreeIPA](https://www.freeipa.org/) - Identity management (alternative)
* [pfSense](https://www.pfsense.org/) or [OPNsense](https://opnsense.org/) - Firewall integration
* [Suricata](https://suricata.io/) - Network intrusion detection
* [ELK Stack](https://www.elastic.co/elk-stack) - Logging and monitoring
* [Docker](https://www.docker.com/) - Containerization
* [Ansible](https://www.ansible.com/) - Configuration management

## ✨ Key Features/Highlights

* **Zero Trust Architecture:** Never trust, always verify principle
* **Multi-Factor Authentication:** TOTP, FIDO2, and certificate-based authentication
* **Device Posture Assessment:** Continuous device health and compliance checking
* **Conditional Access:** Context-aware access policies
* **Micro-Segmentation:** Granular network access controls
* **Session Management:** Dynamic session policies and timeout controls
* **Comprehensive Logging:** Detailed audit trails for all access attempts
* **Automated Certificate Management:** PKI infrastructure with automatic rotation
* **Threat Detection:** Real-time monitoring and automated response
* **Scalable Architecture:** Support for thousands of users and devices

## 🏛️ Repository Structure

```
zero-trust-vpn-infrastructure/
├── README.md
├── docs/
│   ├── architecture-overview.md
│   ├── zero-trust-principles.md
│   ├── installation-guide.md
│   ├── user-management.md
│   ├── device-enrollment.md
│   ├── policy-configuration.md
│   └── troubleshooting.md
├── config-examples/
│   ├── wireguard/
│   │   ├── wg0.conf.example
│   │   └── client-template.conf
│   ├── authelia/
│   │   ├── configuration.yml
│   │   ├── users_database.yml
│   │   └── access-control.yml
│   ├── pki/
│   │   ├── ca.conf
│   │   ├── server.conf
│   │   └── client.conf
│   ├── firewall/
│   │   ├── pfsense-rules.xml
│   │   └── iptables-rules.sh
│   └── docker/
│       ├── docker-compose.yml
│       └── .env.example
├── scripts/
│   ├── setup/
│   │   ├── initial-setup.sh
│   │   ├── pki-setup.sh
│   │   ├── wireguard-setup.sh
│   │   └── authelia-setup.sh
│   ├── management/
│   │   ├── add-user.sh
│   │   ├── revoke-user.sh
│   │   ├── device-enrollment.sh
│   │   └── policy-update.sh
│   ├── monitoring/
│   │   ├── connection-monitor.sh
│   │   ├── security-audit.sh
│   │   └── compliance-check.sh
│   └── automation/
│       ├── cert-renewal.sh
│       ├── user-sync.sh
│       └── threat-response.sh
└── certificates/
    ├── ca/
    ├── server/
    ├── clients/
    └── crl/
```

## 🏗️ Zero Trust Architecture

### Core Principles

1. **Never Trust, Always Verify**
   - Every user and device must be authenticated
   - Continuous verification throughout the session
   - No implicit trust based on network location

2. **Least Privilege Access**
   - Minimum necessary access granted
   - Just-in-time access provisioning
   - Regular access reviews and revocation

3. **Assume Breach**
   - Continuous monitoring for threats
   - Rapid incident response capabilities
   - Lateral movement prevention

### Network Architecture

```
Internet
    │
    ▼
┌─────────────────┐
│   Load Balancer │
│   (HAProxy)     │
└─────────────────┘
    │
    ▼
┌─────────────────┐
│   WAF/DDoS     │
│   Protection    │
└─────────────────┘
    │
    ▼
┌─────────────────┐
│   Authentication│
│   Gateway       │
│   (Authelia)    │
└─────────────────┘
    │
    ▼
┌─────────────────┐
│   WireGuard     │
│   VPN Server    │
└─────────────────┘
    │
    ▼
┌─────────────────┐
│   Internal      │
│   Networks      │
│   (Segmented)   │
└─────────────────┘
```

## 🚀 Getting Started / Configuration

### Prerequisites

1. **Infrastructure Requirements:**
   - Linux server (Ubuntu 20.04+ recommended)
   - Public IP address with domain name
   - SSL certificate for authentication portal
   - Minimum 2GB RAM, 4GB+ recommended

2. **Network Requirements:**
   - UDP port 51820 for WireGuard
   - TCP port 443 for authentication portal
   - Internal network subnets defined

### Quick Start

1. **Clone the repository:**
   ```bash
   git clone https://github.com/YOUR_USERNAME/zero-trust-vpn-infrastructure.git
   cd zero-trust-vpn-infrastructure
   ```

2. **Run initial setup:**
   ```bash
   sudo ./scripts/setup/initial-setup.sh
   ```

3. **Configure environment:**
   ```bash
   cp config-examples/docker/.env.example .env
   # Edit .env with your specific settings
   ```

4. **Set up PKI infrastructure:**
   ```bash
   ./scripts/setup/pki-setup.sh
   ```

5. **Deploy the stack:**
   ```bash
   docker-compose up -d
   ```

6. **Configure first admin user:**
   ```bash
   ./scripts/management/add-user.sh admin admin@example.com --admin
   ```

## 🔐 Authentication and Authorization

### Multi-Factor Authentication

#### TOTP (Time-based One-Time Password)
```yaml
# authelia configuration
authentication_backend:
  file:
    path: /config/users_database.yml
    password:
      algorithm: argon2id

totp:
  issuer: "Zero Trust VPN"
  algorithm: sha1
  digits: 6
  period: 30
  skew: 1
```

#### FIDO2/WebAuthn
```yaml
webauthn:
  timeout: 60s
  display_name: "Zero Trust VPN"
  attestation_conveyance_preference: indirect
  user_verification: preferred
```

### Access Control Policies

```yaml
# access-control.yml
access_control:
  default_policy: deny
  
  rules:
    # Admin access
    - domain: "admin.vpn.example.com"
      policy: two_factor
      subject: "group:admins"
      
    # Developer access to development resources
    - domain: "dev.internal.example.com"
      policy: two_factor
      subject: "group:developers"
      resources:
        - "^/api/.*$"
        - "^/dev/.*$"
        
    # User access to general resources
    - domain: "*.internal.example.com"
      policy: two_factor
      subject: "group:users"
      resources:
        - "^/public/.*$"
```

## 🔧 WireGuard Configuration

### Server Configuration

```ini
# wg0.conf
[Interface]
PrivateKey = SERVER_PRIVATE_KEY
Address = 10.10.0.1/24
ListenPort = 51820
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

# Client configurations added dynamically
```

### Dynamic Client Management

```bash
#!/bin/bash
# add-user.sh

USER_EMAIL=$1
USER_GROUP=$2

# Generate key pair
PRIVATE_KEY=$(wg genkey)
PUBLIC_KEY=$(echo $PRIVATE_KEY | wg pubkey)

# Assign IP address
NEXT_IP=$(get_next_available_ip)

# Create client configuration
cat > "clients/${USER_EMAIL}.conf" << EOF
[Interface]
PrivateKey = $PRIVATE_KEY
Address = $NEXT_IP/32
DNS = 10.10.0.1

[Peer]
PublicKey = $(cat server_public.key)
Endpoint = vpn.example.com:51820
AllowedIPs = 10.0.0.0/8, 192.168.0.0/16
PersistentKeepalive = 25
EOF

# Add to server configuration
wg set wg0 peer $PUBLIC_KEY allowed-ips $NEXT_IP/32

# Update user database
add_user_to_authelia $USER_EMAIL $USER_GROUP

echo "User $USER_EMAIL added successfully"
echo "Configuration file: clients/${USER_EMAIL}.conf"
```

## 🛡️ Security Implementation

### Device Posture Assessment

```python
# device_posture.py
import subprocess
import json
from datetime import datetime

class DevicePostureChecker:
    def __init__(self):
        self.required_checks = [
            'antivirus_status',
            'firewall_status',
            'os_updates',
            'disk_encryption',
            'screen_lock'
        ]
    
    def check_device_posture(self, device_id):
        results = {}
        
        for check in self.required_checks:
            results[check] = getattr(self, f'check_{check}')()
        
        compliance_score = sum(results.values()) / len(results)
        
        return {
            'device_id': device_id,
            'timestamp': datetime.now().isoformat(),
            'compliance_score': compliance_score,
            'details': results,
            'compliant': compliance_score >= 0.8
        }
    
    def check_antivirus_status(self):
        # Implementation for antivirus check
        return True
    
    def check_firewall_status(self):
        # Implementation for firewall check
        return True
```

### Conditional Access Policies

```yaml
# conditional_access.yml
policies:
  - name: "High Risk Location"
    conditions:
      - location_risk: high
    actions:
      - require_mfa: true
      - session_timeout: 1800
      - require_device_compliance: true
      
  - name: "Privileged Access"
    conditions:
      - resource_sensitivity: high
      - user_role: admin
    actions:
      - require_mfa: true
      - require_piv_card: true
      - session_timeout: 900
      - require_approval: true
      
  - name: "Off-Hours Access"
    conditions:
      - time_of_day: "18:00-08:00"
      - day_of_week: "saturday,sunday"
    actions:
      - require_justification: true
      - notify_security_team: true
      - enhanced_logging: true
```

## 📊 Monitoring and Logging

### Comprehensive Logging

```yaml
# logging configuration
logging:
  level: info
  format: json
  
  outputs:
    - type: file
      path: /var/log/authelia/authelia.log
    - type: syslog
      facility: auth
    - type: elasticsearch
      endpoint: https://elk.internal.example.com:9200
      
  events:
    - authentication_attempts
    - authorization_decisions
    - session_events
    - configuration_changes
    - security_incidents
```

### Security Metrics

```python
# metrics.py
from prometheus_client import Counter, Histogram, Gauge

# Authentication metrics
auth_attempts_total = Counter('auth_attempts_total', 'Total authentication attempts', ['result', 'method'])
auth_duration = Histogram('auth_duration_seconds', 'Authentication duration')

# VPN metrics
vpn_connections_active = Gauge('vpn_connections_active', 'Active VPN connections')
vpn_data_transferred = Counter('vpn_data_transferred_bytes', 'Data transferred through VPN', ['direction'])

# Security metrics
security_incidents = Counter('security_incidents_total', 'Security incidents detected', ['type', 'severity'])
policy_violations = Counter('policy_violations_total', 'Policy violations detected', ['policy', 'user'])
```

### Automated Threat Response

```bash
#!/bin/bash
# threat-response.sh

THREAT_TYPE=$1
SOURCE_IP=$2
USER_ID=$3

case $THREAT_TYPE in
    "brute_force")
        # Block IP address
        iptables -I INPUT -s $SOURCE_IP -j DROP
        # Disable user account temporarily
        ./scripts/management/disable-user.sh $USER_ID
        ;;
    "anomalous_behavior")
        # Require re-authentication
        ./scripts/management/force-reauth.sh $USER_ID
        # Increase monitoring
        ./scripts/monitoring/enhanced-monitoring.sh $USER_ID
        ;;
    "malware_detected")
        # Quarantine device
        ./scripts/management/quarantine-device.sh $SOURCE_IP
        # Notify security team
        ./scripts/notifications/security-alert.sh "Malware detected" $USER_ID
        ;;
esac

# Log incident
echo "$(date): Threat response executed for $THREAT_TYPE from $SOURCE_IP (user: $USER_ID)" >> /var/log/security-incidents.log
```

## 🔧 Advanced Features

### Certificate-Based Authentication

```bash
#!/bin/bash
# pki-setup.sh

# Create CA
openssl genrsa -out ca-key.pem 4096
openssl req -new -x509 -days 3650 -key ca-key.pem -out ca.pem

# Create server certificate
openssl genrsa -out server-key.pem 4096
openssl req -new -key server-key.pem -out server.csr
openssl x509 -req -days 365 -in server.csr -CA ca.pem -CAkey ca-key.pem -out server.pem

# Create client certificate template
create_client_cert() {
    local username=$1
    openssl genrsa -out "clients/${username}-key.pem" 4096
    openssl req -new -key "clients/${username}-key.pem" -out "clients/${username}.csr"
    openssl x509 -req -days 365 -in "clients/${username}.csr" -CA ca.pem -CAkey ca-key.pem -out "clients/${username}.pem"
}
```

### API Integration

```python
# api_integration.py
from flask import Flask, request, jsonify
import jwt
import requests

app = Flask(__name__)

@app.route('/api/v1/access-request', methods=['POST'])
def handle_access_request():
    token = request.headers.get('Authorization')
    user_info = validate_token(token)
    
    if not user_info:
        return jsonify({'error': 'Invalid token'}), 401
    
    # Check device posture
    device_compliant = check_device_posture(user_info['device_id'])
    
    # Evaluate access policies
    access_decision = evaluate_access_policies(user_info, request.json)
    
    if access_decision['allowed'] and device_compliant:
        # Generate temporary access credentials
        temp_creds = generate_temp_credentials(user_info)
        return jsonify({
            'access_granted': True,
            'credentials': temp_creds,
            'expires_at': access_decision['expires_at']
        })
    else:
        return jsonify({
            'access_granted': False,
            'reason': access_decision['reason']
        }), 403
```

## 🔮 Potential Improvements/Future Plans

* Integration with SIEM platforms for advanced threat detection
* Machine learning-based anomaly detection
* Integration with cloud identity providers (Azure AD, Okta)
* Mobile device management (MDM) integration
* Automated compliance reporting
* Integration with privileged access management (PAM) solutions
* Support for software-defined perimeter (SDP) protocols

## ⚠️ Security Considerations

* **Key Management:** Secure storage and rotation of cryptographic keys
* **Certificate Lifecycle:** Automated certificate renewal and revocation
* **Session Security:** Secure session management and timeout policies
* **Audit Trails:** Comprehensive logging for compliance and forensics
* **Incident Response:** Rapid response to security incidents
* **Regular Updates:** Keep all components updated with security patches

## 📚 Additional Resources

* [NIST Zero Trust Architecture](https://csrc.nist.gov/publications/detail/sp/800-207/final)
* [WireGuard Protocol Specification](https://www.wireguard.com/protocol/)
* [Zero Trust Security Model](https://www.cloudflare.com/learning/security/glossary/what-is-zero-trust/)
* [Authelia Documentation](https://www.authelia.com/docs/)
* [CISA Zero Trust Maturity Model](https://www.cisa.gov/zero-trust-maturity-model)