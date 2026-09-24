#!/bin/bash

# PKI Infrastructure Setup Script for Zero Trust VPN
# Creates and manages Certificate Authority and certificates

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

# Source environment variables
if [[ -f "$PROJECT_ROOT/.env" ]]; then
    source "$PROJECT_ROOT/.env"
else
    echo "Warning: .env file not found"
fi

# Default values
CERTS_PATH="${CERTS_PATH:-/opt/zero-trust-vpn/certificates}"
CA_VALIDITY_DAYS="${CA_VALIDITY_DAYS:-3650}"
CERT_VALIDITY_DAYS="${CERT_VALIDITY_DAYS:-365}"
KEY_SIZE="${KEY_SIZE:-2048}"

# Certificate details
CA_COUNTRY="${CA_COUNTRY:-US}"
CA_STATE="${CA_STATE:-State}"
CA_CITY="${CA_CITY:-City}"
CA_ORG="${CA_ORG:-Zero Trust VPN}"
CA_OU="${CA_OU:-Certificate Authority}"
CA_CN="${CA_CN:-Zero Trust VPN CA}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging functions
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root for certificate management"
        exit 1
    fi
}

# Create PKI directory structure
create_pki_structure() {
    log "Creating PKI directory structure..."
    
    mkdir -p "$CERTS_PATH"/{ca,server,clients,crl,private}
    mkdir -p "$CERTS_PATH"/ca/{certs,crl,newcerts,private}
    
    # Set secure permissions
    chmod 700 "$CERTS_PATH"
    chmod 700 "$CERTS_PATH"/ca/private
    chmod 700 "$CERTS_PATH"/private
    
    # Create index and serial files for CA
    touch "$CERTS_PATH/ca/index.txt"
    echo 1000 > "$CERTS_PATH/ca/serial"
    echo 1000 > "$CERTS_PATH/ca/crlnumber"
    
    log "✓ PKI directory structure created"
}

# Create OpenSSL configuration for CA
create_ca_config() {
    log "Creating CA configuration..."
    
    cat > "$CERTS_PATH/ca/openssl.cnf" << EOF
# OpenSSL CA configuration file

[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = $CERTS_PATH/ca
certs             = \$dir/certs
crl_dir           = \$dir/crl
new_certs_dir     = \$dir/newcerts
database          = \$dir/index.txt
serial            = \$dir/serial
RANDFILE          = \$dir/private/.rand

private_key       = \$dir/private/ca.key
certificate       = \$dir/ca.crt

crlnumber         = \$dir/crlnumber
crl               = \$dir/crl/ca.crl
crl_extensions    = crl_ext
default_crl_days  = 30

default_md        = sha256
name_opt          = ca_default
cert_opt          = ca_default
default_days      = $CERT_VALIDITY_DAYS
preserve          = no
policy            = policy_strict

[ policy_strict ]
countryName             = match
stateOrProvinceName     = match
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ policy_loose ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
default_bits        = $KEY_SIZE
distinguished_name  = req_distinguished_name
string_mask         = utf8only
default_md          = sha256
x509_extensions     = v3_ca

[ req_distinguished_name ]
countryName                     = Country Name (2 letter code)
stateOrProvinceName             = State or Province Name
localityName                    = Locality Name
0.organizationName              = Organization Name
organizationalUnitName          = Organizational Unit Name
commonName                      = Common Name
emailAddress                    = Email Address

countryName_default             = $CA_COUNTRY
stateOrProvinceName_default     = $CA_STATE
localityName_default            = $CA_CITY
0.organizationName_default      = $CA_ORG
organizationalUnitName_default  = $CA_OU
emailAddress_default            = admin@example.com

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ v3_intermediate_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ usr_cert ]
basicConstraints = CA:FALSE
nsCertType = client, email
nsComment = "OpenSSL Generated Client Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, emailProtection

[ server_cert ]
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "OpenSSL Generated Server Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[ crl_ext ]
authorityKeyIdentifier=keyid:always

[ ocsp ]
basicConstraints = CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, OCSPSigning
EOF
    
    log "✓ CA configuration created"
}

# Create Certificate Authority
create_ca() {
    log "Creating Certificate Authority..."
    
    # Generate CA private key
    openssl genrsa -out "$CERTS_PATH/ca/private/ca.key" $KEY_SIZE
    chmod 400 "$CERTS_PATH/ca/private/ca.key"
    
    # Generate CA certificate
    openssl req -config "$CERTS_PATH/ca/openssl.cnf" \
        -key "$CERTS_PATH/ca/private/ca.key" \
        -new -x509 -days $CA_VALIDITY_DAYS -sha256 -extensions v3_ca \
        -out "$CERTS_PATH/ca/ca.crt" \
        -subj "/C=$CA_COUNTRY/ST=$CA_STATE/L=$CA_CITY/O=$CA_ORG/OU=$CA_OU/CN=$CA_CN"
    
    chmod 444 "$CERTS_PATH/ca/ca.crt"
    
    log "✓ Certificate Authority created"
    log "  CA Certificate: $CERTS_PATH/ca/ca.crt"
    log "  CA Private Key: $CERTS_PATH/ca/private/ca.key"
}

# Create server certificate
create_server_certificate() {
    local domain="${DOMAIN:-vpn.example.com}"
    
    log "Creating server certificate for $domain..."
    
    # Generate server private key
    openssl genrsa -out "$CERTS_PATH/server/server.key" $KEY_SIZE
    chmod 400 "$CERTS_PATH/server/server.key"
    
    # Create certificate signing request
    openssl req -config "$CERTS_PATH/ca/openssl.cnf" \
        -key "$CERTS_PATH/server/server.key" \
        -new -sha256 -out "$CERTS_PATH/server/server.csr" \
        -subj "/C=$CA_COUNTRY/ST=$CA_STATE/L=$CA_CITY/O=$CA_ORG/OU=VPN Server/CN=$domain"
    
    # Create server certificate extensions
    cat > "$CERTS_PATH/server/server_ext.cnf" << EOF
authorityKeyIdentifier=keyid,issuer:always
basicConstraints=CA:FALSE
keyUsage=keyEncipherment,dataEncipherment
subjectAltName=@alt_names

[alt_names]
DNS.1=$domain
DNS.2=auth.$domain
DNS.3=*.vpn.$domain
IP.1=127.0.0.1
EOF
    
    # Sign server certificate
    openssl ca -config "$CERTS_PATH/ca/openssl.cnf" \
        -extensions server_cert -days $CERT_VALIDITY_DAYS -notext -md sha256 \
        -in "$CERTS_PATH/server/server.csr" \
        -out "$CERTS_PATH/server/server.crt" \
        -extfile "$CERTS_PATH/server/server_ext.cnf" \
        -batch
    
    chmod 444 "$CERTS_PATH/server/server.crt"
    
    # Clean up CSR
    rm "$CERTS_PATH/server/server.csr"
    
    log "✓ Server certificate created"
    log "  Server Certificate: $CERTS_PATH/server/server.crt"
    log "  Server Private Key: $CERTS_PATH/server/server.key"
}

# Create client certificate template
create_client_cert_template() {
    log "Creating client certificate template..."
    
    cat > "$CERTS_PATH/create_client_cert.sh" << 'EOF'
#!/bin/bash

# Client Certificate Creation Script

set -euo pipefail

if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <username> <email>"
    exit 1
fi

USERNAME="$1"
EMAIL="$2"
CERTS_PATH="$(dirname "$0")"
KEY_SIZE=2048

# Generate client private key
openssl genrsa -out "$CERTS_PATH/clients/${USERNAME}.key" $KEY_SIZE
chmod 400 "$CERTS_PATH/clients/${USERNAME}.key"

# Create certificate signing request
openssl req -config "$CERTS_PATH/ca/openssl.cnf" \
    -key "$CERTS_PATH/clients/${USERNAME}.key" \
    -new -sha256 -out "$CERTS_PATH/clients/${USERNAME}.csr" \
    -subj "/C=US/ST=State/L=City/O=Zero Trust VPN/OU=VPN Users/CN=${USERNAME}/emailAddress=${EMAIL}"

# Sign client certificate
openssl ca -config "$CERTS_PATH/ca/openssl.cnf" \
    -extensions usr_cert -days 365 -notext -md sha256 \
    -in "$CERTS_PATH/clients/${USERNAME}.csr" \
    -out "$CERTS_PATH/clients/${USERNAME}.crt" \
    -batch

chmod 444 "$CERTS_PATH/clients/${USERNAME}.crt"

# Clean up CSR
rm "$CERTS_PATH/clients/${USERNAME}.csr"

# Create PKCS#12 bundle for easy import
openssl pkcs12 -export \
    -out "$CERTS_PATH/clients/${USERNAME}.p12" \
    -inkey "$CERTS_PATH/clients/${USERNAME}.key" \
    -in "$CERTS_PATH/clients/${USERNAME}.crt" \
    -certfile "$CERTS_PATH/ca/ca.crt" \
    -passout pass:

echo "Client certificate created for $USERNAME"
echo "Certificate: $CERTS_PATH/clients/${USERNAME}.crt"
echo "Private Key: $CERTS_PATH/clients/${USERNAME}.key"
echo "PKCS#12 Bundle: $CERTS_PATH/clients/${USERNAME}.p12"
EOF
    
    chmod +x "$CERTS_PATH/create_client_cert.sh"
    
    log "✓ Client certificate template created"
}

# Create certificate revocation list
create_crl() {
    log "Creating Certificate Revocation List..."
    
    openssl ca -config "$CERTS_PATH/ca/openssl.cnf" \
        -gencrl -out "$CERTS_PATH/crl/ca.crl"
    
    chmod 444 "$CERTS_PATH/crl/ca.crl"
    
    log "✓ Certificate Revocation List created"
}

# Create certificate management scripts
create_management_scripts() {
    log "Creating certificate management scripts..."
    
    # Certificate verification script
    cat > "$CERTS_PATH/verify_cert.sh" << 'EOF'
#!/bin/bash

# Certificate Verification Script

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <certificate_file>"
    exit 1
fi

CERT_FILE="$1"
CA_CERT="$(dirname "$0")/ca/ca.crt"

echo "=== Certificate Information ==="
openssl x509 -in "$CERT_FILE" -text -noout

echo -e "\n=== Certificate Verification ==="
if openssl verify -CAfile "$CA_CERT" "$CERT_FILE"; then
    echo "✓ Certificate is valid"
else
    echo "✗ Certificate verification failed"
fi

echo -e "\n=== Certificate Expiration ==="
openssl x509 -in "$CERT_FILE" -noout -dates
EOF
    
    chmod +x "$CERTS_PATH/verify_cert.sh"
    
    # Certificate revocation script
    cat > "$CERTS_PATH/revoke_cert.sh" << 'EOF'
#!/bin/bash

# Certificate Revocation Script

set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <certificate_file>"
    exit 1
fi

CERT_FILE="$1"
CERTS_PATH="$(dirname "$0")"

echo "Revoking certificate: $CERT_FILE"

# Revoke certificate
openssl ca -config "$CERTS_PATH/ca/openssl.cnf" \
    -revoke "$CERT_FILE"

# Update CRL
openssl ca -config "$CERTS_PATH/ca/openssl.cnf" \
    -gencrl -out "$CERTS_PATH/crl/ca.crl"

echo "Certificate revoked and CRL updated"
EOF
    
    chmod +x "$CERTS_PATH/revoke_cert.sh"
    
    # Certificate renewal script
    cat > "$CERTS_PATH/renew_cert.sh" << 'EOF'
#!/bin/bash

# Certificate Renewal Script

set -euo pipefail

if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <username> <email>"
    exit 1
fi

USERNAME="$1"
EMAIL="$2"
CERTS_PATH="$(dirname "$0")"

# Backup old certificate
if [[ -f "$CERTS_PATH/clients/${USERNAME}.crt" ]]; then
    mv "$CERTS_PATH/clients/${USERNAME}.crt" "$CERTS_PATH/clients/${USERNAME}.crt.old"
    mv "$CERTS_PATH/clients/${USERNAME}.key" "$CERTS_PATH/clients/${USERNAME}.key.old"
fi

# Create new certificate
"$CERTS_PATH/create_client_cert.sh" "$USERNAME" "$EMAIL"

echo "Certificate renewed for $USERNAME"
EOF
    
    chmod +x "$CERTS_PATH/renew_cert.sh"
    
    log "✓ Certificate management scripts created"
}

# Create certificate monitoring script
create_monitoring_script() {
    log "Creating certificate monitoring script..."
    
    cat > "$CERTS_PATH/monitor_certs.sh" << 'EOF'
#!/bin/bash

# Certificate Monitoring Script

CERTS_PATH="$(dirname "$0")"
WARNING_DAYS=30
CRITICAL_DAYS=7

check_cert_expiry() {
    local cert_file="$1"
    local cert_name="$2"
    
    if [[ ! -f "$cert_file" ]]; then
        echo "Certificate not found: $cert_file"
        return 1
    fi
    
    local expiry_date=$(openssl x509 -in "$cert_file" -noout -enddate | cut -d= -f2)
    local expiry_epoch=$(date -d "$expiry_date" +%s)
    local current_epoch=$(date +%s)
    local days_until_expiry=$(( (expiry_epoch - current_epoch) / 86400 ))
    
    echo -n "$cert_name: "
    
    if [[ $days_until_expiry -lt $CRITICAL_DAYS ]]; then
        echo "CRITICAL - Expires in $days_until_expiry days"
        return 2
    elif [[ $days_until_expiry -lt $WARNING_DAYS ]]; then
        echo "WARNING - Expires in $days_until_expiry days"
        return 1
    else
        echo "OK - Expires in $days_until_expiry days"
        return 0
    fi
}

echo "=== Certificate Expiry Monitor ==="
echo "Date: $(date)"
echo

# Check CA certificate
check_cert_expiry "$CERTS_PATH/ca/ca.crt" "CA Certificate"

# Check server certificate
check_cert_expiry "$CERTS_PATH/server/server.crt" "Server Certificate"

# Check client certificates
if [[ -d "$CERTS_PATH/clients" ]]; then
    for cert in "$CERTS_PATH/clients"/*.crt; do
        if [[ -f "$cert" ]]; then
            local basename=$(basename "$cert" .crt)
            check_cert_expiry "$cert" "Client Certificate ($basename)"
        fi
    done
fi

echo
echo "=== End of Report ==="
EOF
    
    chmod +x "$CERTS_PATH/monitor_certs.sh"
    
    log "✓ Certificate monitoring script created"
}

# Set proper permissions
set_permissions() {
    log "Setting proper permissions..."
    
    # Set ownership
    chown -R root:root "$CERTS_PATH"
    
    # Set directory permissions
    find "$CERTS_PATH" -type d -exec chmod 755 {} \;
    
    # Set private key permissions
    find "$CERTS_PATH" -name "*.key" -exec chmod 400 {} \;
    
    # Set certificate permissions
    find "$CERTS_PATH" -name "*.crt" -exec chmod 444 {} \;
    
    # Set script permissions
    find "$CERTS_PATH" -name "*.sh" -exec chmod 755 {} \;
    
    # Secure private directories
    chmod 700 "$CERTS_PATH/ca/private"
    chmod 700 "$CERTS_PATH/private"
    
    log "✓ Permissions set securely"
}

# Display PKI information
display_pki_info() {
    log "PKI setup completed successfully!"
    echo ""
    echo "PKI Structure:"
    echo "=============="
    echo "Root Directory: $CERTS_PATH"
    echo "CA Certificate: $CERTS_PATH/ca/ca.crt"
    echo "Server Certificate: $CERTS_PATH/server/server.crt"
    echo "CRL: $CERTS_PATH/crl/ca.crl"
    echo ""
    echo "Management Scripts:"
    echo "=================="
    echo "Create client cert: $CERTS_PATH/create_client_cert.sh <username> <email>"
    echo "Verify certificate: $CERTS_PATH/verify_cert.sh <cert_file>"
    echo "Revoke certificate: $CERTS_PATH/revoke_cert.sh <cert_file>"
    echo "Renew certificate: $CERTS_PATH/renew_cert.sh <username> <email>"
    echo "Monitor certificates: $CERTS_PATH/monitor_certs.sh"
    echo ""
    echo "Certificate Information:"
    echo "======================="
    openssl x509 -in "$CERTS_PATH/ca/ca.crt" -noout -subject -issuer -dates
    echo ""
    echo "Next Steps:"
    echo "==========="
    echo "1. Distribute CA certificate to clients"
    echo "2. Create client certificates as needed"
    echo "3. Configure certificate monitoring"
    echo "4. Set up certificate renewal automation"
}

# Main function
main() {
    log "Starting PKI infrastructure setup..."
    
    check_root
    create_pki_structure
    create_ca_config
    create_ca
    create_server_certificate
    create_client_cert_template
    create_crl
    create_management_scripts
    create_monitoring_script
    set_permissions
    
    display_pki_info
    
    log "PKI infrastructure setup completed successfully!"
}

# Handle script arguments
case "${1:-}" in
    --help|-h)
        echo "Usage: $0 [options]"
        echo ""
        echo "Options:"
        echo "  --help, -h     Show this help message"
        echo ""
        echo "Environment variables:"
        echo "  CERTS_PATH           Certificate directory path"
        echo "  CA_VALIDITY_DAYS     CA certificate validity (default: 3650)"
        echo "  CERT_VALIDITY_DAYS   Certificate validity (default: 365)"
        echo "  KEY_SIZE            RSA key size (default: 2048)"
        echo ""
        exit 0
        ;;
    *)
        main
        ;;
esac