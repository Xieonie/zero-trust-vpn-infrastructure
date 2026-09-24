# Architecture

This document describes what the scripts and configuration in this
repository actually build, how a request is decided, and how that maps to
the tenets of NIST SP 800-207. The limitations list in the
[README](../README.md#limitations) applies throughout.

## Components

Everything runs on one Debian/Ubuntu host.

| Component | Runs as | Configured by | Role |
|---|---|---|---|
| WireGuard `wg0` | `wg-quick@wg0` on the host | `wireguard-setup.sh`, peers by `add-user.sh` / `device-enrollment.sh` | Encrypted tunnel; authenticates devices by public key + preshared key |
| nftables `table inet ztvpn` | kernel, loaded by `nftables.service` at boot | `firewall-setup.sh` | Default-drop input and WireGuard forwarding, blocklist and quarantine sets |
| nginx 1.27 | compose service `nginx`, publishes 80/443 | `config-examples/nginx/` (deployed to `/opt/zero-trust-vpn/nginx/`) | TLS termination, VPN-only allow list, Authelia forward auth |
| Authelia 4.39 | compose service `authelia` | `authelia-setup.sh`, `policy-update.sh` | Login portal, 2FA, access-control decisions |
| PostgreSQL 17 | compose service `postgres` (internal network) | compose file | Authelia storage (2FA registrations, etc.) |
| Redis 7 | compose service `redis` (internal network) | compose file | Authelia sessions |
| Private CA | files under `/opt/zero-trust-vpn/certificates` | `pki-setup.sh`, `cert-renewal.sh` | Proxy TLS certificate, optional client certificates, CRL |
| Monitoring (optional) | compose profile `monitoring` | your `prometheus.yml` / `alertmanager.yml` | Prometheus, Alertmanager, Grafana, Loki; served through nginx + Authelia |

WireGuard is deliberately not a container. The compose stack has two
networks: `frontend` (nginx, Authelia, monitoring) and `backend`
(`internal: true`: Authelia, PostgreSQL, Redis). Only nginx publishes ports.

```
                     internet
                        |
         UDP 51820      |      TCP 80/443 (Docker DNAT)       TCP 22
            |           |              |                         |
+-----------v-----------v--------------v-------------------------v------+
| host      wg0                   nginx container                 sshd  |
|  10.8.0.1/24 ---- nft inet ztvpn ---->  :443                          |
|                   wg0 -> SERVICES_SUBNET:SERVICES_PORTS only          |
|                                          | auth_request               |
|                                          v                            |
|                                    authelia :9091                     |
|                                     |          |       (backend,      |
|                                  postgres    redis     internal)      |
+-----------------------------------------------------------------------+
```

## Request flow

1. **Tunnel.** The client completes a WireGuard handshake with its private
   key and the per-peer preshared key. The server accepts the peer only for
   its one `/32` (`AllowedIPs`) inside `VPN_SUBNET` (default `10.8.0.0/24`).
   No user identity or second factor is involved at this step.
2. **Firewall.** Packets from `wg0` go to the `wg_input` or `wg_forward`
   chain. Allowed: TCP to `SERVICES_SUBNET` on `SERVICES_PORTS` (default
   `10.0.1.0/24`, port 443), ICMP echo and `WG_INPUT_PORTS` on
   `VPN_SERVER_IP`, internet egress only with `FULL_TUNNEL=yes`. Everything
   else, including IPv6, client-to-client traffic and connections towards
   clients, is dropped. Sources in `quarantine4` or the blocklists are dropped
   first.
3. **Proxy.** The client connects to `https://<app>.<DOMAIN>`. That name has
   to resolve to the host's address in `SERVICES_SUBNET`; Docker DNATs the
   connection to nginx and the client address is preserved. The server
   certificate is `/opt/zero-trust-vpn/certificates/server/<AUTH_DOMAIN>.crt`
   from the private CA, so clients must trust `ca.crt`. Unknown server names
   get no TLS handshake (`ssl_reject_handshake`). Each server block includes
   `vpn-only.inc` (`allow VPN_SUBNET; deny all;`).
4. **Authorization.** nginx sends a subrequest to
   `http://authelia:9091/api/authz/auth-request` with `X-Original-URL`,
   `X-Original-Method` and `X-Forwarded-For` set to `$remote_addr` (always
   overwritten, never appended, so a client cannot claim a VPN address).
   Authelia matches `access_control.rules` top to bottom:
   - no matching rule: denied (`default_policy: deny`)
   - rule matches but no session or only one factor: 401, which nginx turns
     into a 302 to `https://<AUTH_DOMAIN>/?rd=<original URL>`
   - user not in an allowed subject: 403
   - allowed: nginx proxies the request and passes `Remote-User`,
     `Remote-Groups`, `Remote-Name`, `Remote-Email` taken from Authelia's
     response.
5. **Every request** goes through step 4. The session cookie (domain
   `DOMAIN`) is valid for 8 hours and expires after 15 minutes of
   inactivity; "remember me" is disabled. Authelia re-reads the user
   (disabled flag, groups) at most every minute (`refresh_interval: 1m`).

## Firewall contract

`firewall-setup.sh` renders exactly one table, `inet ztvpn`, and replaces
only that table atomically. Docker's and other tables are not touched.

| Chain | Hook / policy | Content |
|---|---|---|
| `input` | input, drop | loopback; quarantined tunnel sources and blocklists dropped (before established/related, so blocking cuts open connections); established/related; `wg0` traffic to `wg_input`; limited ICMP/ICMPv6; UDP `WG_PORT`; SSH `SSH_PORT` rate limited per source and restricted to `ADMIN_ALLOWLIST` if set; `PUBLIC_TCP_PORTS` |
| `wg_input` | regular chain | IPv6 dropped, source must be in `VPN_SUBNET`, echo to `VPN_SERVER_IP`, `WG_INPUT_PORTS` (tcp+udp) on `VPN_SERVER_IP`, `SERVICES_SUBNET:SERVICES_PORTS`, then drop |
| `forward` | forward, accept | blocklists; `iifname wg0` to `wg_forward`, `oifname wg0` to `wg_forward_out`. Policy accept because Docker filters its bridge traffic in its own tables. |
| `wg_forward` | regular chain | quarantine; established; IPv6 drop; source must be in `VPN_SUBNET`; no client-to-client; `ct original` destination in `SERVICES_SUBNET` on `SERVICES_PORTS`; with `FULL_TUNNEL=yes` internet except private/special ranges; then drop |
| `wg_forward_out` | regular chain | quarantine; established/related; then drop |
| `postrouting` | nat, only if needed | masquerade `VPN_SUBNET` out of the external interface (`FULL_TUNNEL=yes`) and towards `SERVICES_SUBNET` (`SERVICES_NAT=yes`) |

Sets: `blocklist4`, `blocklist6` (with timeouts, written by
`threat-response.sh`), `quarantine4` (tunnel addresses), `admin4`/`admin6`
(from `ADMIN_ALLOWLIST`), `ssh_meter4`/`ssh_meter6` (rate limiting).

`SERVICES_NAT=yes` hides the client address from services, which breaks
Authelia's `vpn` network matching; leave it off unless the services are on a
routed network that cannot get a route back to `VPN_SUBNET`.

The default rendering is in `config-examples/firewall/ztvpn.nft.example`;
`firewall-setup.sh --print` shows the rendering for your configuration.
`config-examples/firewall/pfsense-rules.xml` is an illustrative example of
matching rules on a perimeter firewall in front of the host.

## Identity and policy

- **Users** are in `/opt/zero-trust-vpn/authelia/users_database.yml`
  (`AUTHELIA_BACKEND=file`, argon2id hashes written by the scripts, watched
  by Authelia) or in LDAP/AD (`AUTHELIA_BACKEND=ldap`, section from
  `config-examples/authelia/configuration.ldap.yml`).
- **Groups** the scripts accept (`KNOWN_GROUPS`): `admins, security,
  it-support, employees, remote-workers, contractors, guests, users,
  vpn-users, monitoring`. New users get `DEFAULT_USER_GROUPS`
  (`users,vpn-users`).
- **Second factor:** TOTP and WebAuthn are enabled. Every shipped rule uses
  `policy: two_factor`.
- **Shipped rules** (all with `networks: ['vpn']`):

  | Domain | Allowed subjects |
  |---|---|
  | `grafana.<DOMAIN>` | admins, security, monitoring |
  | `prometheus.<DOMAIN>`, `alerts.<DOMAIN>` | admins, monitoring |
  | `admin.<DOMAIN>` | admins |
  | `security.<DOMAIN>` | admins, security |
  | `support.<DOMAIN>` | admins, it-support |
  | `intranet.<DOMAIN>` | employees, remote-workers |
  | `projects.<DOMAIN>` | contractors, employees |
  | `guest.<DOMAIN>` | guests, only `GET` and `HEAD` |
  | `selfservice.<DOMAIN>` | members of both users and vpn-users |

  nginx server blocks are shipped only for the portal, Grafana, Prometheus
  and Alertmanager. For the other domains you add a server block following
  `config-examples/nginx/templates/grafana.conf.template` and point it at
  your application.
- **Brute force:** Authelia's regulation bans after 5 failed logins within
  5 minutes for 30 minutes. `connection-monitor.sh --respond` can
  additionally block source addresses in nftables.

## PKI

`pki-setup.sh` creates an EC (secp384r1) CA whose key is AES-256 encrypted
with a random passphrase in `/etc/zero-trust-vpn/secrets/ca.pass`. Every
certificate is issued with `openssl ca`, so `ca/index.txt` records all of
them and any of them can be revoked. Certificates:

- **Server:** CN `AUTH_DOMAIN`, SANs `VPN_ENDPOINT`, `PKI_SERVER_SANS` and
  any `--san`; `serverAuth`. nginx serves it for the portal and all apps, so
  `PKI_SERVER_SANS=*.<DOMAIN>` is the usual choice.
- **Client** (optional, `--cert`): CN = peer name, `clientAuth`. Issued and
  revoked, not checked by anything shipped.
- **CRL:** `/opt/zero-trust-vpn/certificates/crl/ca.crl`, regenerated on
  every revocation and by `pki-setup.sh`.

WireGuard does not use X.509.

## State and locking

Scripts serialise changes to shared state (`wg0.conf`, users file, CA
database, inventory, Authelia config) with `flock` on files in
`/var/lib/zero-trust-vpn/locks`. Files are written atomically (temp file +
rename). Peers in `wg0.conf` are wrapped in `# BEGIN PEER <name>` /
`# END PEER <name>` markers and matched exactly, so revoking `bob` never
touches `bobby` or `bob--laptop`. Changes reach the running interface with
`wg syncconf`, without dropping other sessions. Tunnel addresses of
quarantined peers stay reserved until they are released.

## Mapping to NIST SP 800-207

The seven tenets of zero trust (SP 800-207, section 2.1) and how far this
project covers them. `compliance-check.sh --framework nist-800-207` uses the
same mapping and marks the uncovered parts `MANUAL`.

| Tenet | Coverage | What exists / what is missing |
|---|---|---|
| 1. All data sources and computing services are resources | Partial | Each application behind nginx is its own resource with its own Authelia rule. Anything not put behind nginx is outside the model. No resource inventory. |
| 2. All communication is secured regardless of network location | Partial | Client traffic is encrypted by WireGuard and TLS to nginx; being on the VPN grants nothing by itself. nginx to upstream is plain HTTP on the Docker network. |
| 3. Access to individual resources is granted per session | Partial | Every request is checked against the rule for its domain, but one Authelia session (up to 8 h, 15 min idle) covers all resources the user's groups allow. No per-resource re-authentication. |
| 4. Access is determined by dynamic policy | Partial | Policy inputs are user, groups, domain, path, HTTP method and source network. No device attributes, no behavioural or risk signals. |
| 5. The enterprise monitors the integrity and security posture of all assets | Not covered | No device posture checks of any kind. `security-audit.sh` audits the VPN host only. |
| 6. Authentication and authorization are dynamic and strictly enforced before access | Covered for HTTP applications | Authelia decides on every request, default deny, 2FA on every rule, user re-read every minute. Network access (WireGuard) is key-based without MFA. Revocation removes peers from the live interface. |
| 7. The enterprise collects information to improve its security posture | Partial | `connection-monitor.sh` (handshakes, spikes, failed logins), `security-audit.sh`, audit and incident records. No central log pipeline is configured (Loki ships without a log shipper). |
