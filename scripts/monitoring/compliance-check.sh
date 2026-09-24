#!/usr/bin/env bash
# Maps security-audit.sh results to a small set of compliance controls.
#
# This is technical evidence only. A control is PASS only when every
# technical check mapped to it ran and passed; organisational requirements
# (policies, reviews, training, ...) are always MANUAL, whatever documents
# exist on disk. It does not certify compliance with anything.

set -Eeuo pipefail
# shellcheck source=scripts/lib/common.sh
source "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/../lib/common.sh"

SECURITY_AUDIT="${SECURITY_AUDIT:-$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/security-audit.sh}"

usage() {
    cat <<EOF
Usage: $(basename "$0") [--framework iso27001|nist-800-207|all] [--audit-json FILE] [--json] [--output DIR]

  --framework F      Control set to evaluate (default all)
  --audit-json FILE  Use an existing "security-audit.sh --json" result instead of running it
  --json             Print the report JSON on stdout (default: table)
  --output DIR       Where to write the JSON report (default $ZTVPN_REPORT_DIR)
  -h, --help         Show this help

Statuses: PASS (all mapped technical checks passed), FAIL (a mapped check failed),
NOT_EVALUATED (a mapped check was skipped, e.g. component missing), MANUAL (no technical
evidence possible; needs a human review). PASS covers only the technical part of a control.
Exit code: number of FAIL controls (capped at 100); 125 on errors.
EOF
}

fatal() { error "$*"; exit 125; }

# framework <TAB> control <TAB> title <TAB> audit check ids (comma list, "-" = none) <TAB> manual part
CONTROLS=$(cat <<'EOF'
iso27001	A.5.15	Access control	AUTH-DEFAULT-DENY,AUTH-BYPASS,FW-POLICY,WG-ALLOWEDIPS	Access control policy approved and communicated
iso27001	A.5.17	Authentication information	FILE-AUTHELIA-USERS,FILE-AUTHELIA-SECRETS,AUTH-INLINE-SECRETS,FILE-WG-KEY,FILE-WG-CONF,FILE-WG-CLIENTS,FILE-WG-CLIENT-KEYS-ON-SERVER,FILE-CA-PASS	Process for allocating and handing over credentials; user guidance
iso27001	A.5.18	Access rights	ID-ORPHAN-PEERS,ID-IDLE-ACCOUNTS,ID-UNKNOWN-GROUPS	Documented provisioning/approval and periodic access reviews
iso27001	A.8.2	Privileged access rights	-	Review membership of the admins/security groups and SSH admin allowlist
iso27001	A.8.5	Secure authentication	AUTH-DEFAULT-DENY,AUTH-BYPASS,WG-PSK,PKI-CHAIN	Confirm two_factor policy covers all protected domains
iso27001	A.8.9	Configuration management	WG-HOOKS,WG-UNMANAGED,FILE-CONFIG	Change management and baseline documentation
iso27001	A.8.15	Logging	-	Verify Authelia, WireGuard and firewall logs are collected, protected and retained
iso27001	A.8.16	Monitoring activities	-	Verify connection-monitor/security-audit run on a schedule and alerts are handled
iso27001	A.8.20	Networks security	FW-TABLE,FW-POLICY,FW-SETS,FW-IPV6,NET-DOCKER-PORTS,WG-ALLOWEDIPS	Network diagrams and segregation requirements
iso27001	A.8.24	Use of cryptography	PKI-CA-KEY-ENCRYPTED,FILE-CA-KEY,FILE-PKI-KEYS,PKI-CA-EXPIRY,PKI-SERVER-EXPIRY,PKI-CLIENT-EXPIRY,PKI-CRL	Cryptography and key management policy
nist-800-207	T1	All data sources and computing services are resources	-	Inventory of resources behind the VPN
nist-800-207	T2	All communication is secured regardless of network location	AUTH-BYPASS,PKI-CHAIN,PKI-SERVER-EXPIRY,WG-PSK	Confirm internal services also require TLS
nist-800-207	T3	Access is granted per session	-	Review Authelia session lifetimes and re-authentication settings
nist-800-207	T4	Access is determined by dynamic policy	AUTH-DEFAULT-DENY	Policy considers identity only; no device or behavioural attributes are evaluated by this stack
nist-800-207	T5	Integrity and security posture of all assets is monitored	-	NOT IMPLEMENTED: this stack performs no device posture checks
nist-800-207	T6	Authentication and authorization are dynamic and strictly enforced	AUTH-DEFAULT-DENY,AUTH-BYPASS,ID-ORPHAN-PEERS,FW-POLICY	Review MFA enrolment of all users
nist-800-207	T7	Information about assets, network and communications is collected	-	Verify logs and monitoring data are collected and used to improve policy
EOF
)

main() {
    local framework=all audit_file="" json=0 outdir="$ZTVPN_REPORT_DIR"
    while (($#)); do
        case "$1" in
            --framework) framework="${2:-}"; shift 2 || fatal "--framework needs a value" ;;
            --audit-json) audit_file="${2:-}"; shift 2 || fatal "--audit-json needs a value" ;;
            --json) json=1; shift ;;
            --output) outdir="${2:-}"; shift 2 || fatal "--output needs a value" ;;
            -h | --help) usage; exit 0 ;;
            *) usage >&2; fatal "Unknown option: $1" ;;
        esac
    done
    case "$framework" in
        iso27001 | nist-800-207 | all) ;;
        *) fatal "Unknown framework: $framework (supported: iso27001, nist-800-207, all)" ;;
    esac
    [[ -n "$outdir" ]] || fatal "--output must not be empty"
    require_cmd jq

    local audit rc=0
    if [[ -n "$audit_file" ]]; then
        [[ -r "$audit_file" ]] || fatal "Cannot read $audit_file"
        audit="$(<"$audit_file")"
    else
        audit="$("$SECURITY_AUDIT" --json --fail-on none)" || rc=$?
        ((rc == 0)) || fatal "security-audit.sh failed (exit $rc)"
    fi
    jq -e '.checks | type == "array"' >/dev/null 2>&1 <<<"$audit" || fatal "Audit input is not security-audit.sh JSON"

    local controls_json
    controls_json="$(printf '%s\n' "$CONTROLS" | jq -R 'split("\t") | {framework: .[0], id: .[1], title: .[2],
        checks: (if .[3] == "-" then [] else (.[3] | split(",")) end), manual: .[4]}' | jq -sc .)"

    local report
    report="$(jq -n --argjson audit "$audit" --argjson controls "$controls_json" --arg fw "$framework" \
        --arg at "$(date -u +%FT%TZ)" '
        ($audit.checks | map({key: .id, value: .}) | from_entries) as $res
        | [$controls[] | select($fw == "all" or .framework == $fw)
           | . as $c
           | ($c.checks | map($res[.] // {id: ., status: "missing", severity: "unknown", items: ["check not present in audit output"]})) as $ev
           | $c + {
               evidence: $ev,
               status: (if ($ev | length) == 0 then "MANUAL"
                        elif any($ev[]; .status == "fail") then "FAIL"
                        elif all($ev[]; .status == "pass") then "PASS"
                        else "NOT_EVALUATED" end)
             }
           | del(.checks)] as $out
        | {generated: $at, framework: $fw,
           note: "Technical evidence only. PASS means every mapped automated check passed; organisational requirements listed under manual need human review.",
           audit: {generated: $audit.generated, host: $audit.host},
           summary: {PASS: ($out | map(select(.status == "PASS")) | length),
                     FAIL: ($out | map(select(.status == "FAIL")) | length),
                     NOT_EVALUATED: ($out | map(select(.status == "NOT_EVALUATED")) | length),
                     MANUAL: ($out | map(select(.status == "MANUAL")) | length)},
           controls: $out}')"

    (umask 077; mkdir -p "$outdir") || fatal "Cannot create $outdir"
    local out
    out="$outdir/compliance-$framework-$(date -u +%Y%m%dT%H%M%SZ).json"
    printf '%s\n' "$report" | atomic_write "$out" 600 || fatal "Cannot write $out"
    info "Report written to $out"

    if ((json)); then
        printf '%s\n' "$report"
    else
        jq -r '
            (.controls[] | "\(.framework)\t\(.id)\t\(.status)\t\(.title)"
               + (if .status == "FAIL" then "\n\t\t\tfailed: " + ([.evidence[] | select(.status == "fail") | .id] | join(", ")) else "" end)
               + (if .status == "NOT_EVALUATED" then "\n\t\t\tnot evaluated: " + ([.evidence[] | select(.status != "pass") | .id] | join(", ")) else "" end)
               + (if .status == "MANUAL" then "\n\t\t\tmanual: " + .manual else "" end)),
            "",
            "PASS \(.summary.PASS)  FAIL \(.summary.FAIL)  NOT_EVALUATED \(.summary.NOT_EVALUATED)  MANUAL \(.summary.MANUAL)",
            .note' <<<"$report"
    fi

    local fails
    fails="$(jq -r '.summary.FAIL' <<<"$report")"
    ((fails > 100)) && fails=100
    exit "$fails"
}

main "$@"
