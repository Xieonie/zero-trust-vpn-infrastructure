# Zero Trust VPN Infrastructure

Shell scripts and configuration for a single Debian/Ubuntu host that gives
remote users access to internal web applications through WireGuard, with
every application request authenticated and authorized by Authelia (password
plus TOTP or WebAuthn) at an nginx reverse proxy.

"Zero trust" here means one specific thing: being connected to the VPN grants
no access to applications by itself. The tunnel only lets a device reach the
reverse proxy, and the proxy asks Authelia about every request. It does not
mean device posture checks, per-user network segmentation or continuous
risk scoring; none of those exist in this project (see
[Limitations](#limitations)).

## What it is

- `wg-quick@wg0` on the host. Peers are authenticated by their WireGuard key
  and a per-peer preshared key.
- One nftables table, `inet ztvpn` (IPv4 and IPv6), that drops by default.
  VPN clients may reach only `SERVICES_SUBNET` on `SERVICES_PORTS` (default
  tcp/443, the reverse proxy). No client-to-client traffic, no internet egress
  unless `FULL_TUNNEL=yes`.
- A Docker Compose stack: nginx (the only service with published ports),
  Authelia 4.39, PostgreSQL and Redis for Authelia, plus an optional
  `monitoring` profile (Prometheus, Alertmanager, Grafana, Loki).
- nginx protects every application with Authelia forward auth
  (`auth_request`). Authelia's access control is `default_policy: deny`, every
  shipped rule is `two_factor`, limited to the `vpn` network (`VPN_SUBNET`)
  and to specific groups.
- A small private CA (OpenSSL) for the proxy's TLS certificate and optional
  client certificates, with a CRL.
- Scripts for setup, users, devices, access rules, certificate renewal,
  incident containment, LDAP reconciliation, monitoring and a technical audit.

## What it is not

- Not an identity provider. Users live in Authelia's users file (managed by
  the scripts) or in your LDAP/AD directory.
- Not multi-host or highly available. Everything runs on one machine.
- Not a way to expose arbitrary TCP/UDP services. Only HTTP(S) applications
  behind nginx get per-user authorization.
- Not scheduled. Nothing runs by itself; add cron jobs or systemd timers for
  the automation and monitoring scripts if you want them periodic.

## Architecture

```
 client device                              VPN host (Debian/Ubuntu)
+------------------+    UDP 51820     +------------------------------------------------+
| WireGuard client |=================>| wg0  10.8.0.1/24   (wg-quick@wg0)              |
|  10.8.0.x/32     |  key + PSK only  |   |                                            |
|                  |                  |   v                                            |
| browser          |                  | nftables "inet ztvpn": wg0 -> SERVICES_SUBNET  |
+------------------+                  |   tcp/443 only, everything else dropped        |
                                      |   |                                            |
                                      |   v   (Docker DNAT of published 443)           |
                                      | +---------------- docker compose ------------+ |
                                      | | nginx :443                                 | |
                                      | |   vpn-only.inc: allow VPN_SUBNET only      | |
                                      | |   auth_request --------> authelia :9091    | |
                                      | |   |  (2xx: proxy on)       |        |      | |
                                      | |   v                    postgres  redis     | |
                                      | | application upstream                       | |
                                      | | (shipped: grafana, prometheus,             | |
                                      | |  alertmanager in profile "monitoring")     | |
                                      | +--------------------------------------------+ |
                                      +------------------------------------------------+
```

Request path: the WireGuard handshake proves possession of a device key. The
client then opens `https://<app>.<DOMAIN>`, which must resolve to the proxy's
address in `SERVICES_SUBNET`. nginx refuses anything not from `VPN_SUBNET`,
asks Authelia (`/api/authz/auth-request`), redirects to the portal at
`AUTH_DOMAIN` when there is no session, and forwards the request with
`Remote-User`/`Remote-Groups` headers only when Authelia allows it. Details
and the NIST SP 800-207 mapping: [docs/architecture.md](docs/architecture.md).

## Security model

| Layer | Enforced by | Decides on |
|---|---|---|
| Network access | WireGuard (`wg0.conf`) | Device key + preshared key. No user identity, no MFA. |
| Reachability | nftables `inet ztvpn` | Source in `VPN_SUBNET`, destination `SERVICES_SUBNET:SERVICES_PORTS`, blocklist/quarantine sets |
| Application access | nginx + Authelia | Session (password + TOTP/WebAuthn), group/user, domain, path, method, `vpn` network; default deny |
| Revocation | `revoke-user.sh`, `threat-response.sh` | Removes peers from the live interface, disables the account, revokes certificates |

## Limitations

Read these before relying on the setup.

- **WireGuard keys are device credentials without MFA.** Anyone holding a
  client config (private key and PSK) gets onto the tunnel. Authelia still
  guards every application, but the proxy and portal are reachable.
- **Client private keys are generated on the server** and stay in
  `/opt/zero-trust-vpn/wireguard/clients/<peer>/` until you delete them
  (`security-audit.sh` reports this as `FILE-WG-CLIENT-KEYS-ON-SERVER`).
- **No device posture.** Nothing checks OS version, disk encryption, EDR or
  anything else about the client device.
- **Client certificates are enforced only with `MTLS=yes`** (default `no`).
  Then every HTTPS request to the proxy needs a non-revoked certificate
  from this CA, but the certificate is not tied to the Authelia user: any
  valid device certificate plus any valid login gets in.
- **Per-user authorization exists only at the HTTP layer.** The firewall
  treats all peers the same: every peer can reach
  `SERVICES_SUBNET:SERVICES_PORTS`. Adding a port there that is not behind
  nginx and Authelia exposes it to every peer without authentication.
- **nginx is published only on `PROXY_BIND_ADDR`**, this host's address in
  `SERVICES_SUBNET` (Docker's DNAT bypasses the `input` chain, so binding to
  `0.0.0.0` would expose it). Hosts on that LAN can reach the proxy at the TCP
  level; nginx answers 403 to non-VPN addresses (`vpn-only.inc`) and
  Authelia's rules only match the `vpn` network.
- **Disabling a user is not instant for web sessions.** Authelia re-reads the
  user after `refresh_interval` (1 minute in the shipped config). Tunnels are
  cut immediately because peers are removed from the running interface.
- **LDAP backend:** `add-user.sh` cannot create directory accounts, and
  `revoke-user.sh` can disable one only through an `LDAP_DISABLE_HOOK` you
  provide; otherwise it exits 2 and reports the manual step.
  `user-sync.sh` reconciles VPN access with the directory.
- **Users cannot change their own password.** The portal's change and reset
  flows are disabled because the scripts own the users file. Admins issue a
  new random password with `user-account.sh reset-password`.
- **Traffic from nginx to upstreams is plain HTTP** on the Docker network.
- **The tunnel is IPv4 only.** IPv6 arriving through the tunnel is dropped.
- **The CA key is encrypted, but its passphrase is on the same host**
  (`/etc/zero-trust-vpn/secrets/ca.pass`). The CRL is only a local file;
  `PKI_CRL_URL` embeds a URL in certificates but nothing publishes the CRL.
- **Only three application vhosts are shipped** (Grafana, Prometheus,
  Alertmanager, all in the `monitoring` profile, which needs your own
  `prometheus.yml` and `alertmanager.yml`). The Authelia rules for
  `admin`, `security`, `support`, `intranet`, `projects`, `guest` and
  `selfservice` have no nginx server blocks; add your own.
- **Second-factor registration codes go to a file** inside the Authelia
  container (`/data/notification.txt`) until you configure SMTP.

## Requirements

- Debian or Ubuntu with systemd, run as root. `initial-setup.sh` refuses
  other distributions unless `--skip-packages` is given.
- amd64 or arm64 for the pinned `yq` download (otherwise install
  mikefarah/yq v4 yourself).
- A public address for `VPN_ENDPOINT`, UDP `WG_PORT` (51820) reachable.
- An address of the host inside `SERVICES_SUBNET` on which clients reach the
  proxy (typically its LAN address).
- DNS names under `DOMAIN` for the portal (`AUTH_DOMAIN`) and applications
  that resolve, for VPN clients, to that proxy address. No resolver is shipped.
- Packages installed by `initial-setup.sh`: `wireguard-tools nftables
  conntrack openssl jq argon2 qrencode ca-certificates curl iproute2
  util-linux`, Docker Engine
  with the compose plugin (from download.docker.com), `yq` v4.44.3 (checksum
  pinned). `user-sync.sh` additionally needs `ldapsearch` (`ldap-utils`).

## Quick start

Full guide: [docs/installation.md](docs/installation.md).

```sh
# 1. Clone as root into a root-owned directory (the scripts run as root and
#    read templates from the checkout). Plain git; no Git LFS needed.
git clone https://github.com/Xieonie/zero-trust-vpn-infrastructure.git
cd zero-trust-vpn-infrastructure

# 2. Central configuration
install -d -m 755 /etc/zero-trust-vpn
install -m 600 config-examples/ztvpn.conf.example /etc/zero-trust-vpn/ztvpn.conf
editor /etc/zero-trust-vpn/ztvpn.conf
#    at least: DOMAIN, AUTH_DOMAIN, VPN_ENDPOINT, PKI_SERVER_SANS,
#    SERVICES_SUBNET, ADMIN_ALLOWLIST (your SSH source address)

# 3. Install and configure everything
scripts/setup/initial-setup.sh --admin-email admin@yourdomain.tld
#    Over SSH the firewall step rolls back after 120 s unless you confirm
#    (press Enter) after checking a second SSH session still gets in.
#    The first Authelia admin's password is written to
#    /etc/zero-trust-vpn/secrets/onboarding/authelia-admin.txt

# 4. First user with a device
scripts/management/add-user.sh alice alice@yourdomain.tld --name "Alice Example" --device laptop --qr
#    prints key=value lines: client_config=, qr=, onboarding=

# 5. The admin account has no VPN device yet
scripts/management/device-enrollment.sh enroll --user admin --device laptop
```

Connecting a client:

1. Hand over the client config
   (`/opt/zero-trust-vpn/wireguard/clients/alice--laptop/alice--laptop.conf`,
   or the QR code) and the onboarding file over a secure channel, then delete
   the server copies of the private key and onboarding file.
2. Import the config into the WireGuard app (or `wg-quick up` on Linux).
3. Install the CA certificate `/opt/zero-trust-vpn/certificates/ca/ca.crt` as
   trusted on the device; the proxy's certificate is issued by this CA.
4. Open `https://<AUTH_DOMAIN>`, log in with the onboarding password and
   register TOTP or WebAuthn. The confirmation code for that step is written
   to the notifier file: `docker compose exec authelia cat /data/notification.txt`
   (run in `/opt/zero-trust-vpn`).

## Day-2 operations

Details and examples: [docs/operations.md](docs/operations.md).

| Script | Purpose |
|---|---|
| `scripts/setup/initial-setup.sh` | Packages, directories, runs the four setup steps, deploys compose + nginx files, starts the stack. Safe to re-run. |
| `scripts/setup/pki-setup.sh` | Creates the CA (never replaces it without `--force`), issues/renews the proxy certificate, regenerates the CRL. |
| `scripts/setup/firewall-setup.sh` | Renders (`--print`) or applies (`--apply`) the `inet ztvpn` nftables table, with optional rollback timer; `--restore-state` re-adds saved blocklist/quarantine entries (run at boot by `ztvpn-firewall-state.service`). |
| `scripts/setup/wireguard-setup.sh` | Server keys, `[Interface]` of `wg0.conf` (peers kept), IPv4 forwarding, `wg-quick@wg0`. |
| `scripts/setup/authelia-setup.sh` | Authelia config, secret files, users file and first admin; `--validate` runs `authelia validate-config`. |
| `scripts/management/add-user.sh` | Authelia account with random password + first WireGuard peer (optional client cert, QR). Rolls back on failure. |
| `scripts/management/revoke-user.sh` | Disables/deletes the account, removes all peers of the user, revokes their certificates, marks inventory. |
| `scripts/management/user-account.sh` | `reset-password`, `enable`, `disable`, `show` for Authelia file-backend accounts. |
| `scripts/management/device-enrollment.sh` | `enroll`, `remove`, `list`, `show` additional devices (`<user>--<device>` peers). |
| `scripts/management/policy-update.sh` | Access-control rules and group membership in the live Authelia config, validated with rollback; backup/restore. |
| `scripts/automation/cert-renewal.sh` | `check` expiry of certificates and CRL (exit 0/1/2), `renew` server certificates and the CRL, `crl` regenerates the CRL; reloads nginx. |
| `scripts/automation/threat-response.sh` | Block IPs with expiring nftables set entries, quarantine peers, contain compromised devices/users; `unblock`, `release`. |
| `scripts/automation/user-sync.sh` | Revokes VPN access of users missing, disabled or not in the required group in LDAP/AD. Dry run unless `--apply`. |
| `scripts/monitoring/connection-monitor.sh` | Peer handshakes and transfer, unknown peers, traffic spikes, failed Authelia logins; `--respond` blocks brute force. |
| `scripts/monitoring/security-audit.sh` | 31 technical checks with stable IDs (permissions, PKI, WireGuard, firewall, Docker ports, Authelia, identities). |
| `scripts/monitoring/compliance-check.sh` | Maps audit results to ISO 27001:2022 and NIST SP 800-207 controls; organisational parts stay `MANUAL`. |

Every script has `--help`. Management scripts append to
`/var/log/zero-trust-vpn/audit.log`.

## Configuration

All scripts read `/etc/zero-trust-vpn/ztvpn.conf` (override the path with
`ZTVPN_CONFIG`). It is parsed as plain `KEY=VALUE` lines and never executed;
the loader refuses the file if it is group/world writable or owned by
another non-root user. Environment variables override the file. Defaults
and canonical paths are in `scripts/lib/common.sh`:

| Path | Content |
|---|---|
| `/etc/zero-trust-vpn/ztvpn.conf` | central config |
| `/etc/zero-trust-vpn/secrets/` | CA passphrase, onboarding files, optional LDAP bind password |
| `/etc/wireguard/wg0.conf`, `server_*.key` | WireGuard server |
| `/opt/zero-trust-vpn/` | `docker-compose.yml`, `.env`, `nginx/`, `authelia/`, `certificates/`, `wireguard/clients/` |
| `/var/lib/zero-trust-vpn/` | device inventory, quarantine records, incidents, reports, locks |
| `/var/log/zero-trust-vpn/` | per-script logs, `audit.log`, `alerts.log` |
| `/var/backups/zero-trust-vpn/` | backups the scripts make before replacing things, revoked key archives |
| `/etc/nftables.d/ztvpn.nft` | persisted firewall table, included from `/etc/nftables.conf` |

## Repository layout

```
scripts/lib/          common.sh (config, paths, validation, audit log), wireguard.sh, authelia.sh, pki.sh
scripts/setup/        initial-setup, pki-setup, firewall-setup, wireguard-setup, authelia-setup
scripts/management/   add-user, revoke-user, user-account, device-enrollment, policy-update
scripts/automation/   cert-renewal, threat-response, user-sync
scripts/monitoring/   connection-monitor, security-audit, compliance-check
config-examples/      ztvpn.conf.example
  docker/             docker-compose.yml, .env.example
  authelia/           configuration.yml, configuration.ldap.yml, users_database.yml (format only)
  nginx/              templates/ (portal, apps, vpn-only.inc), snippets/ (forward auth, proxy headers)
  firewall/           ztvpn.nft.example (default rendering), pfsense-rules.xml (illustrative)
  wireguard/          wg0.conf.example, client-template.conf
  pki/                README.md (the OpenSSL config is generated)
certificates/         empty placeholders; generated key material is git-ignored
tests/                bats suites and test_helper.bash
docs/                 architecture, installation, operations, troubleshooting
```

## Testing

The bats suites in `tests/` run every script against a sandbox: all paths
point into `$BATS_TEST_TMPDIR` (`tests/test_helper.bash`), firewall apply
tests use a stub `nft` or a private network namespace, so the host is not
modified. The scripts require root, so run the suites as root:

```sh
apt-get install bats shellcheck wireguard-tools argon2 jq openssl nftables   # plus mikefarah/yq v4
sudo -E bats tests/
```

Tests that need Docker images (`authelia/authelia:4.39`, nginx) or
`CAP_NET_ADMIN` are skipped when those are not available.

CI (`.github/workflows/ci.yml`, on every push and pull request): `bash -n`
and `shellcheck -x -S warning` on every `*.sh`, a check that no script is a
Git LFS pointer, YAML parsing of every tracked `*.yml`/`*.yaml` with `yq`,
and `sudo -E bats tests/`.

## License

The repository contains no license file.
