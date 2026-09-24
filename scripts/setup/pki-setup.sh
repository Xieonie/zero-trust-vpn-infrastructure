#!/usr/bin/env bash
# Creates the internal CA, the server certificate and the CRL.
#
# Safe to re-run: an existing CA is never touched (use --force to replace
# it, the old one is backed up first), the server certificate is only
# re-issued when it is missing, no longer verifies, expires within
# PKI_RENEW_DAYS or its SAN list changed. Client certificates are issued by
# scripts/management/add-user.sh and renewed by
# scripts/automation/cert-renewal.sh, not here.

set -Eeuo pipefail

# shellcheck source=scripts/lib/common.sh
source "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/../lib/common.sh"

PKI_RENEW_DAYS="${PKI_RENEW_DAYS:-30}"
# Extra server certificate SANs kept across runs (comma separated).
PKI_SERVER_SANS="${PKI_SERVER_SANS:-}"
LOG_FILE="${LOG_FILE:-$ZTVPN_LOG_DIR/pki-setup.log}"

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Initialise the zero-trust-vpn PKI under $PKI_DIR.

  - creates the CA (key encrypted with $PKI_CA_PASSFILE) if none exists
  - issues/renews the server certificate for AUTH_DOMAIN ($AUTH_DOMAIN)
    with VPN_ENDPOINT ($VPN_ENDPOINT), PKI_SERVER_SANS and --san values as SANs
  - regenerates the CRL

Options:
  --san NAME        Extra DNS name or IPv4 address for the server cert (repeatable).
                    Not persisted: add permanent ones to PKI_SERVER_SANS.
  --reissue         Re-issue the server certificate even if it is still valid
  --force           Replace an existing CA. The old CA, certificates, CRL and
                    passphrase are moved to $ZTVPN_BACKUP_DIR first. Every
                    certificate signed by the old CA stops verifying.
  --write-config    Only regenerate $PKI_CA_CNF from the PKI_* settings
  -h, --help        Show this help

Settings (ztvpn.conf or environment): PKI_ORG, PKI_COUNTRY, PKI_CA_DAYS,
PKI_CERT_DAYS, PKI_CA_KEY_ALG, PKI_KEY_ALG, PKI_CRL_URL, PKI_RENEW_DAYS,
PKI_SERVER_SANS.
EOF
}

# DNS name (optionally wildcard) or IPv4 address.
validate_san() {
    validate_ipv4 "$1" && return 0
    [[ ${#1} -le 253 && "$1" =~ ^(\*\.)?[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$ ]]
}

FORCE=0
REISSUE=0
WRITE_CONFIG_ONLY=0
EXTRA_SANS=()

while (($#)); do
    case "$1" in
        --san)
            [[ $# -ge 2 ]] || die "--san needs a value"
            EXTRA_SANS+=("$2")
            shift 2
            ;;
        --reissue) REISSUE=1; shift ;;
        --force) FORCE=1; shift ;;
        --write-config) WRITE_CONFIG_ONLY=1; shift ;;
        -h | --help) usage; exit 0 ;;
        *) die "Unknown option: $1 (see --help)" ;;
    esac
done

require_root
require_cmd openssl flock

while IFS= read -r s; do EXTRA_SANS+=("$s"); done < <(split_csv "$PKI_SERVER_SANS")

SERVER_NAME="$AUTH_DOMAIN"
validate_san "$SERVER_NAME" && ! validate_ipv4 "$SERVER_NAME" && [[ "$SERVER_NAME" != \** ]] ||
    die "AUTH_DOMAIN must be a DNS name: $SERVER_NAME"
validate_san "$VPN_ENDPOINT" || die "Invalid VPN_ENDPOINT: $VPN_ENDPOINT"
for s in "${EXTRA_SANS[@]}"; do
    validate_san "$s" || die "Invalid SAN (--san/PKI_SERVER_SANS): $s"
done
for v in PKI_CA_DAYS PKI_CERT_DAYS PKI_RENEW_DAYS; do
    [[ "${!v}" =~ ^[1-9][0-9]{0,4}$ ]] || die "Invalid $v: ${!v}"
done
[[ "$PKI_ORG" =~ ^[A-Za-z0-9\ .,\&()\'-]{1,64}$ ]] || die "Invalid PKI_ORG: $PKI_ORG"
[[ -z "$PKI_COUNTRY" || "$PKI_COUNTRY" =~ ^[A-Z]{2}$ ]] || die "PKI_COUNTRY must be a two-letter code"
[[ -z "$PKI_CRL_URL" || "$PKI_CRL_URL" =~ ^https?://[A-Za-z0-9._~:/?#@!\&\'()*+,\;=%-]+$ ]] ||
    die "Invalid PKI_CRL_URL: $PKI_CRL_URL"

ztvpn_lock pki

if ((WRITE_CONFIG_ONLY)); then
    [[ -d "$PKI_CA_DIR" ]] || die "No CA directory at $PKI_CA_DIR; run without --write-config first"
    pki_write_ca_config
    success "Rewrote $PKI_CA_CNF"
    exit 0
fi

# Moves the whole PKI (and its passphrase) into a timestamped backup dir.
backup_pki() {
    local dest d
    dest="$ZTVPN_BACKUP_DIR/pki-$(date +%Y%m%d-%H%M%S)"
    (umask 077; mkdir -p "$dest")
    for d in "$PKI_CA_DIR" "$PKI_SERVER_DIR" "$PKI_CLIENTS_DIR" "$(dirname "$PKI_CRL")"; do
        [[ -e "$d" ]] && mv "$d" "$dest/"
    done
    [[ -e "$PKI_CA_PASSFILE" ]] && mv "$PKI_CA_PASSFILE" "$dest/"
    chmod -R go-rwx "$dest"
    warn "Old PKI moved to $dest"
}

if ((FORCE)) && [[ -e "$PKI_CA_KEY" || -e "$PKI_CA_CERT" ]]; then
    warn "Replacing the existing CA. All issued certificates must be re-issued."
    backup_pki
    pki_init_ca
    success "Created new CA $PKI_CA_CERT"
elif pki_ca_exists; then
    info "CA already exists at $PKI_CA_DIR, keeping it (use --force to replace)"
elif [[ -e "$PKI_CA_KEY" || -e "$PKI_CA_CERT" ]]; then
    die "Incomplete CA in $PKI_CA_DIR (only one of ca.crt/ca.key present); fix it or use --force"
else
    pki_init_ca
    success "Created CA $PKI_CA_CERT"
fi

# Desired SAN set, normalised to "DNS:x" / "IP:x", sorted and de-duplicated.
desired_sans() {
    local s
    {
        printf 'DNS:%s\n' "$SERVER_NAME"
        for s in "$VPN_ENDPOINT" "${EXTRA_SANS[@]}"; do
            if validate_ipv4 "$s"; then printf 'IP:%s\n' "$s"; else printf 'DNS:%s\n' "$s"; fi
        done
    } | sort -u
}

current_sans() {
    openssl x509 -in "$1" -noout -ext subjectAltName 2>/dev/null |
        tail -n +2 | tr ',' '\n' | sed -e 's/^[[:space:]]*//' -e 's/^IP Address:/IP:/' | grep -v '^$' | sort -u
}

server_crt="$PKI_SERVER_DIR/$SERVER_NAME.crt"
reason=""
if ((REISSUE)); then
    reason="--reissue given"
elif [[ ! -f "$server_crt" || ! -f "$PKI_SERVER_DIR/$SERVER_NAME.key" ]]; then
    reason="no server certificate yet"
elif ! pki_verify "$server_crt"; then
    reason="certificate does not verify against the current CA/CRL"
elif (($(pki_days_left "$server_crt") < PKI_RENEW_DAYS)); then
    reason="certificate expires within $PKI_RENEW_DAYS days"
elif [[ -n "$(comm -23 <(desired_sans) <(current_sans "$server_crt"))" ]]; then
    # Only missing names trigger a re-issue, so a plain re-run never drops
    # SANs that an earlier --san added.
    reason="SAN list changed"
fi

if [[ -n "$reason" ]]; then
    info "Issuing server certificate for $SERVER_NAME ($reason)"
    sans=()
    declare -A seen=(["$SERVER_NAME"]=1)
    for s in "$VPN_ENDPOINT" "${EXTRA_SANS[@]}"; do
        [[ -n "${seen[$s]:-}" ]] && continue
        seen["$s"]=1
        sans+=("$s")
    done
    crt="$(pki_issue server "$SERVER_NAME" "$PKI_CERT_DAYS" "${sans[@]}")" || die "Issuing the server certificate failed"
    success "Server certificate: $crt (key $PKI_SERVER_DIR/$SERVER_NAME.key)"
else
    info "Server certificate $server_crt is current ($(pki_days_left "$server_crt") days left)"
fi

pki_gen_crl || die "CRL generation failed"
success "CRL refreshed: $PKI_CRL"
info "CA certificate for clients: $PKI_CA_CERT"
