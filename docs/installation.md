# Installation

This guide installs the complete stack on one Debian or Ubuntu host with
`scripts/setup/initial-setup.sh`. Read the
[limitations](../README.md#limitations) first.

## 1. Prerequisites

- Debian or Ubuntu with systemd, root shell. amd64 or arm64 if you want
  `initial-setup.sh` to install `yq` (pinned v4.44.3 with SHA-256 check).
- Outbound HTTPS for apt, download.docker.com, GitHub (yq) and Docker Hub.
- A public address or DNS name for `VPN_ENDPOINT`; UDP `WG_PORT` (default
  51820) reachable from clients.
- An address of this host inside `SERVICES_SUBNET` (default `10.0.1.0/24`),
  normally its LAN address. nginx is published only on that address
  (`PROXY_BIND_ADDR`, detected automatically); `initial-setup.sh` refuses to
  deploy without one.
- Name resolution for clients: `AUTH_DOMAIN` and every application name
  (`grafana.<DOMAIN>`, ...) must resolve, on the VPN clients, to the address
  above. Nothing in this repository runs a resolver. Options: records in a DNS
  zone the clients already use, a resolver you run on the VPN host (then set
  `CLIENT_DNS` to `VPN_SERVER_IP` and `WG_INPUT_PORTS=53`), or hosts-file
  entries on the clients.
- Your SSH source address(es) for `ADMIN_ALLOWLIST`, so SSH is not open to
  the whole internet.

## 2. Get the code

```sh
git clone https://github.com/Xieonie/zero-trust-vpn-infrastructure.git
cd zero-trust-vpn-infrastructure
```

The scripts are regular files; no Git LFS is involved. Keep the checkout
root-owned and writable only by root: the scripts run as root and copy the
Authelia and nginx templates from `config-examples/`.

## 3. Configure

```sh
install -d -m 755 /etc/zero-trust-vpn
install -m 600 config-examples/ztvpn.conf.example /etc/zero-trust-vpn/ztvpn.conf
editor /etc/zero-trust-vpn/ztvpn.conf
```

(If you skip this, the first run of `initial-setup.sh` copies the example
into place and then stops because of the placeholder domain.)

The file is plain `KEY=VALUE`; nothing is expanded or executed. It must be
owned by root and not group/world writable, or every script refuses to load
it. Environment variables override values in the file.

| Key | Value in the example | Set it to |
|---|---|---|
| `DOMAIN` | `example.com` | Parent domain of the portal and apps (session cookie domain) |
| `AUTH_DOMAIN` | `auth.example.com` | Portal host name, must be under `DOMAIN` |
| `VPN_ENDPOINT` | `vpn.example.com` | Public name or IPv4 address clients connect to |
| `VPN_SUBNET` / `VPN_SERVER_IP` | `10.8.0.0/24` / `10.8.0.1` | Tunnel subnet and server address |
| `SERVICES_SUBNET` | `10.0.1.0/24` | Subnet containing the proxy address |
| `SERVICES_PORTS` | `443` | TCP ports clients may reach there |
| `CLIENT_ALLOWED_IPS` | `10.8.0.0/24, 10.0.1.0/24` | Routes in client configs (split tunnel) |
| `CLIENT_DNS` | empty | Resolver pushed to clients |
| `WG_INTERFACE` / `WG_PORT` | `wg0` / `51820` | |
| `ADMIN_ALLOWLIST` | empty | IPs/CIDRs (v4 or v6) allowed to SSH in and never auto-blocked. Empty = SSH open to all, rate limited |
| `SSH_PORT` | `22` | |
| `PROXY_BIND_ADDR` | empty (auto) | Host address in `SERVICES_SUBNET` that nginx publishes 80/443 on |
| `PUBLIC_TCP_PORTS` | empty | TCP ports open to everyone, only for services running natively on the host |
| `WG_INPUT_PORTS` | empty | Ports on `VPN_SERVER_IP` clients may use (e.g. `53`) |
| `FULL_TUNNEL` | `no` | `yes` allows internet egress through the tunnel (also set `CLIENT_ALLOWED_IPS=0.0.0.0/0, ::/0`) |
| `SERVICES_NAT` | `no` | See [architecture](architecture.md#firewall-contract) before changing |
| `EXTERNAL_INTERFACE` | auto | Uplink for masquerading |
| `PKI_SERVER_SANS` | `*.example.com` | Extra SANs for the proxy certificate, usually `*.<DOMAIN>` |
| `PKI_ORG`, `PKI_COUNTRY`, `PKI_CERT_DAYS`, `PKI_CA_DAYS`, `PKI_KEY_ALG`, `PKI_CA_KEY_ALG`, `PKI_CRL_URL`, `PKI_RENEW_DAYS` | see example | CA and certificate parameters (`config-examples/pki/README.md`) |
| `AUTHELIA_BACKEND` | `file` | `file` or `ldap` |
| `DEFAULT_USER_GROUPS` | `users,vpn-users` | Groups every new user gets |
| `LDAP_DISABLE_HOOK` | empty | LDAP only: executable called as `<hook> <user> disable\|delete` by `revoke-user.sh` |
| `ADMIN_EMAIL` | empty | E-mail of the first Authelia admin (default `admin@<DOMAIN>`) |
| `TZ` | `UTC` | Time zone for the containers |
| `NOTIFICATION_EMAIL`, `SLACK_WEBHOOK` | empty | Targets for `threat-response.sh --notify` |

`initial-setup.sh` refuses `example.com` values in `DOMAIN`, `AUTH_DOMAIN`,
`VPN_ENDPOINT` and `PKI_SERVER_SANS` (interactively it asks whether this is a
test install).

## 4. Run the installer

```sh
scripts/setup/initial-setup.sh --admin-email admin@yourdomain.tld
```

Options (`--help`): `--skip-packages`, `--skip-docker`,
`--non-interactive`, `--admin-user NAME`, `--admin-email EMAIL`.

What it does, in order:

1. Checks the OS and the domain settings; installs packages unless
   `--skip-packages` (see the README for the list), Docker Engine with the
   compose plugin unless `--skip-docker` or already present, and `yq`.
2. Creates the root-owned directories (`/etc/zero-trust-vpn/secrets`,
   `/opt/zero-trust-vpn`, `/var/lib/zero-trust-vpn`,
   `/var/log/zero-trust-vpn`, `/var/backups/zero-trust-vpn`, ...).
3. `pki-setup.sh`: CA, server certificate for `AUTH_DOMAIN`, CRL.
4. `firewall-setup.sh --apply`: the nftables table, before IP forwarding is
   switched on. In an interactive session it adds `--confirm-timeout 120`:
   open a second SSH session, check you still get in, then press Enter (or
   `touch /var/lib/zero-trust-vpn/firewall/confirm`). Without confirmation
   the previous rules come back and nothing is persisted. The script also
   refuses to apply rules that would cut off the SSH session it runs in.
5. `wireguard-setup.sh`: server keys, `/etc/wireguard/wg0.conf`,
   `/etc/sysctl.d/99-ztvpn.conf` (`net.ipv4.ip_forward = 1`), enables
   `wg-quick@wg0`.
6. `authelia-setup.sh` (with `--validate` unless `--skip-docker`): copies
   `configuration.yml`, creates one secret per file in
   `/opt/zero-trust-vpn/authelia/secrets/`, the users file and the first
   admin (user `admin` unless `--admin-user`, groups `admins,users,vpn-users`,
   random password in
   `/etc/zero-trust-vpn/secrets/onboarding/authelia-<user>.txt`).
7. Writes `/opt/zero-trust-vpn/docker-compose.yml`, `/opt/zero-trust-vpn/.env`
   (no secrets) and the nginx templates/snippets, then
   `docker compose up -d` (skipped with `--skip-docker`).

The script is safe to re-run: it keeps the CA, keys, peers, users and
secrets. A locally edited Authelia `configuration.yml` or nginx file is kept
(with a warning); `docker-compose.yml` is replaced after a backup to
`/var/backups/zero-trust-vpn/compose/`.

Each step can also be run on its own; see `--help` of
`scripts/setup/pki-setup.sh`, `firewall-setup.sh`, `wireguard-setup.sh` and
`authelia-setup.sh`.

## 5. Verify

```sh
wg show wg0
nft list table inet ztvpn
cd /opt/zero-trust-vpn && docker compose ps
scripts/setup/authelia-setup.sh --validate
scripts/monitoring/security-audit.sh
```

`docker compose ps` should list `authelia`, `nginx`, `postgres` and `redis`
as healthy. `security-audit.sh` exits 0 when there is no finding of
severity high or above (`--fail-on`). Low and info findings such as
`ID-IDLE-ACCOUNTS` (an account without a VPN device) or
`FILE-WG-CLIENT-KEYS-ON-SERVER` (client private keys still on the server) are
expected until you have enrolled devices and handed out their keys.

## 6. First users and clients

The admin account created in step 6 has no WireGuard peer. Give it one:

```sh
scripts/management/device-enrollment.sh enroll --user admin --device laptop --qr
```

Add a user (account plus first device):

```sh
scripts/management/add-user.sh alice alice@yourdomain.tld --name "Alice Example" --device laptop --qr
```

The output is `key=value` lines: `user`, `peer`, `ip`, `client_config`,
`qr`, `onboarding`. Hand the client config (or QR code) and the onboarding
file to the user over a secure channel, then delete the private key
(`/opt/zero-trust-vpn/wireguard/clients/<peer>/private.key`) and the
onboarding file from the server.

On the client:

1. Import the config into the WireGuard app, or on Linux:
   `install -m 600 alice--laptop.conf /etc/wireguard/ztvpn.conf && wg-quick up ztvpn`.
2. Trust `/opt/zero-trust-vpn/certificates/ca/ca.crt` (copy it from the
   server) in the device's or browser's certificate store.
3. Open `https://<AUTH_DOMAIN>`, log in with the onboarding password and
   register a TOTP app or a WebAuthn key. Authelia asks for a one-time code
   to confirm the registration; with the shipped file notifier it is in the
   container: `cd /opt/zero-trust-vpn && docker compose exec authelia cat /data/notification.txt`.
   To send it by e-mail instead, configure the `smtp` block in
   `/opt/zero-trust-vpn/authelia/configuration.yml` as described in its
   comments, put the password in
   `/opt/zero-trust-vpn/authelia/secrets/smtp_password` and add
   `AUTHELIA_NOTIFIER_SMTP_PASSWORD_FILE: /secrets/smtp_password` to the
   `authelia` service environment.

## Optional: monitoring profile

The `monitoring` profile starts Prometheus, Alertmanager, Grafana and Loki,
served by nginx at `prometheus.<DOMAIN>`, `alerts.<DOMAIN>` and
`grafana.<DOMAIN>` behind Authelia. You provide:

- `/opt/zero-trust-vpn/monitoring/prometheus.yml`
- `/opt/zero-trust-vpn/monitoring/alertmanager.yml`
- a Grafana admin password file readable by uid 472, by default
  `/etc/zero-trust-vpn/secrets/grafana_admin_password`
  (`install -o 472 -m 400 ...`); set `GRAFANA_ADMIN_PASSWORD_FILE` in
  `ztvpn.conf` to use another path, then re-run `initial-setup.sh`.

```sh
cd /opt/zero-trust-vpn && docker compose --profile monitoring up -d
```

Loki has no log shipper configured.

## Optional: LDAP / Active Directory

1. Set `AUTHELIA_BACKEND=ldap` in `ztvpn.conf`.
2. Replace the `authentication_backend:` section of
   `/opt/zero-trust-vpn/authelia/configuration.yml` with the one in
   `config-examples/authelia/configuration.ldap.yml` and adjust it (use
   `ldaps://` or StartTLS).
3. Write the bind password to `/opt/zero-trust-vpn/authelia/secrets/ldap_password`
   (mode 600) and add
   `AUTHELIA_AUTHENTICATION_BACKEND_LDAP_PASSWORD_FILE: /secrets/ldap_password`
   to the `authelia` service environment in
   `/opt/zero-trust-vpn/docker-compose.yml`. Note that re-running
   `initial-setup.sh` replaces that file with the repository version.
4. Directory group names (`cn`) must match the groups used in the access
   rules.
5. Optionally set `LDAP_DISABLE_HOOK` for `revoke-user.sh` and the
   `LDAP_*` settings for `user-sync.sh` (see
   `scripts/automation/user-sync.sh --help`).
6. `scripts/setup/authelia-setup.sh --validate`, then
   `cd /opt/zero-trust-vpn && docker compose restart authelia`.

With the LDAP backend no local admin is created, `add-user.sh` only
provisions the WireGuard peer (and reports the directory account as a manual
step), and group changes with `policy-update.sh` are refused.

## Uninstall

There is no uninstall script. The pieces to remove are:
`docker compose down` in `/opt/zero-trust-vpn` (add `-v` to delete the
volumes), `systemctl disable --now wg-quick@wg0`,
`nft delete table inet ztvpn` and the `include "/etc/nftables.d/ztvpn.nft"`
line in `/etc/nftables.conf`, `/etc/sysctl.d/99-ztvpn.conf`, and the
directories listed in the README.
