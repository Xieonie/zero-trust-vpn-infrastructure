# Troubleshooting

Commands assume the default paths and settings (`wg0`, `10.8.0.0/24`,
`/opt/zero-trust-vpn`). `docker compose` commands are run in
`/opt/zero-trust-vpn`, where `docker-compose.yml` and `.env` live:

```sh
cd /opt/zero-trust-vpn
```

First stop for most problems:

```sh
scripts/monitoring/security-audit.sh --verbose
scripts/monitoring/connection-monitor.sh
```

Script logs are in `/var/log/zero-trust-vpn/` (`initial-setup.log`,
`pki-setup.log`, `firewall-setup.log`, `wireguard-setup.log`,
`authelia-setup.log`, `cert-renewal.log`, `threat-response.log`,
`user-sync.log`, `audit.log`, `alerts.log`).

## Scripts refuse to start

**"Refusing to load /etc/zero-trust-vpn/ztvpn.conf: owned by uid ..." or
"group/world writable"**: the config ends up in commands run as root, so it
must be root-owned and not writable by others.

```sh
chown root:root /etc/zero-trust-vpn/ztvpn.conf
chmod 600 /etc/zero-trust-vpn/ztvpn.conf
```

**"Ignoring malformed line"**: only `KEY=VALUE` lines (optionally prefixed
with `export`) and comments are allowed; keys are upper case. Values are
never expanded, so `$(...)` or `${VAR}` are taken literally.

**"example.com is a placeholder"** from `initial-setup.sh`: set `DOMAIN`,
`AUTH_DOMAIN`, `VPN_ENDPOINT` and `PKI_SERVER_SANS` to your names.

**"yq (mikefarah v4) is required" / "Found a yq that is not mikefarah/yq
v4"**: the Debian/Ubuntu `yq` package is a different tool. Install
mikefarah/yq v4 (`initial-setup.sh` does this without `--skip-packages`)
and make sure it comes first in `PATH`: `yq --version`.

**"Could not acquire lock ..."**: another script holds the lock in
`/var/lib/zero-trust-vpn/locks/` for more than 60 seconds. Check for a
running script (`ps aux | grep scripts/`) before doing anything else.

## Client cannot connect (no handshake)

```sh
wg show wg0
systemctl status wg-quick@wg0
journalctl -u wg-quick@wg0 --since "1 hour ago"
grep -n -A5 "BEGIN PEER alice--laptop" /etc/wireguard/wg0.conf
nft list chain inet ztvpn input
```

- `latest handshake` missing for the peer: check that UDP `WG_PORT` (51820)
  reaches the host (cloud security groups, upstream firewalls) and that the
  client's `Endpoint` is `VPN_ENDPOINT:WG_PORT`.
- The peer's `public key` in `wg show wg0` must match
  `/opt/zero-trust-vpn/wireguard/clients/<peer>/public.key`, and the
  client's `PublicKey` must match `/etc/wireguard/server_public.key`. After
  `wireguard-setup.sh --force` (new server key) every client config has to
  be re-issued.
- Peer present in `wg0.conf` but not on the interface: apply the file
  without dropping sessions with
  `wg syncconf wg0 <(wg-quick strip wg0)` or `systemctl reload wg-quick@wg0`.
- The address may be blocked or quarantined:

  ```sh
  nft list set inet ztvpn blocklist4
  nft list set inet ztvpn quarantine4
  scripts/automation/threat-response.sh unblock --ip 203.0.113.7
  ```

- The peer may have been revoked or quarantined:
  `scripts/management/device-enrollment.sh show --user alice --device laptop`,
  `ls /var/lib/zero-trust-vpn/quarantine/`, and
  `grep alice /var/log/zero-trust-vpn/audit.log`.

## Handshake works, but the portal or apps do not load

Work through the path from the client:

1. **Name resolution.** On the client, `AUTH_DOMAIN` and the app names must
   resolve to the host's address in `SERVICES_SUBNET` (for example
   `10.0.1.10`). No resolver is shipped; see
   [installation](installation.md#1-prerequisites). If you run one on the VPN
   host, `CLIENT_DNS` and `WG_INPUT_PORTS=53` must be set and the client
   config re-issued.
2. **Routing on the client.** The client's `AllowedIPs` must include
   `SERVICES_SUBNET` (default `10.8.0.0/24, 10.0.1.0/24`).
3. **Firewall.** Only TCP `SERVICES_PORTS` to `SERVICES_SUBNET` is allowed:

   ```sh
   nft list chain inet ztvpn wg_input
   nft list chain inet ztvpn wg_forward
   ip -4 addr show     # the host needs an address inside SERVICES_SUBNET
   sysctl net.ipv4.ip_forward
   ```

   `firewall-setup.sh --apply` warns when forwarding is off, when there is
   no local address in `SERVICES_SUBNET`, and when Docker has set the
   iptables `FORWARD` policy to drop. The last one affects clients reaching
   other hosts in `SERVICES_SUBNET` or the internet (not the nginx container
   itself); the fix it suggests is `"ip-forward-no-drop": true` in
   `/etc/docker/daemon.json` (Docker 28 or later).
4. **Containers.**

   ```sh
   docker compose ps
   docker compose logs --tail 100 nginx
   docker compose logs --tail 100 authelia
   docker compose exec nginx nginx -t
   ```

   nginx waits for Authelia to be healthy, and Authelia for PostgreSQL and
   Redis.
5. **TLS.** A certificate warning means the device does not trust the
   private CA, or the name is not in the certificate's SANs:

   ```sh
   openssl x509 -in /opt/zero-trust-vpn/certificates/server/auth.example.org.crt -noout -subject -ext subjectAltName -enddate
   ```

   Install `/opt/zero-trust-vpn/certificates/ca/ca.crt` on the client. To add
   names, set `PKI_SERVER_SANS` (for example `*.example.org`), run
   `scripts/setup/pki-setup.sh` and then `docker compose restart nginx`.
   A connection reset without any certificate for an unknown host name is
   intended: nginx rejects the TLS handshake for names it has no server
   block for.
6. **403 from nginx** (plain nginx error page, not Authelia): the request did
   not come from `VPN_SUBNET` (`vpn-only.inc`). This happens when the client
   reaches the host outside the tunnel (name resolves to a public address,
   or `AllowedIPs` lacks the subnet) or with `SERVICES_NAT=yes`.

## Authelia problems

```sh
docker compose logs --since 15m authelia
docker compose exec authelia authelia validate-config --config /config/configuration.yml
scripts/setup/authelia-setup.sh --validate
scripts/management/policy-update.sh validate
```

- **Authelia does not start**: `validate-config` names the offending key.
  The secret files in `/opt/zero-trust-vpn/authelia/secrets/` must exist
  (`jwt_secret`, `session_secret`, `storage_encryption_key`,
  `postgres_password`, `redis_password`); `authelia-setup.sh` creates
  missing ones. Do not regenerate `postgres_password` or
  `storage_encryption_key` for an existing database: PostgreSQL keeps the
  old password in its volume, and Authelia cannot decrypt stored 2FA
  registrations with a new encryption key.
- **Access denied (403) after login**: list the rules and the user's groups.

  ```sh
  scripts/management/policy-update.sh list-rules
  yq '.users.alice' /opt/zero-trust-vpn/authelia/users_database.yml
  ```

  First match wins; no match means deny. Every shipped rule requires the
  `vpn` network. The user needs one of the groups in `subject`
  (`selfservice.<DOMAIN>` requires both `users` and `vpn-users`).
- **Rule change has no effect**: Authelia does not reload
  `configuration.yml` by itself: `docker compose restart authelia` (or
  `policy-update.sh ... --restart`). Changes to the users file are picked up
  automatically.
- **Login fails for a new user**: check the account is not
  `disabled: true` and that the password is the one from the onboarding file
  in `/etc/zero-trust-vpn/secrets/onboarding/`. After 5 failures within
  5 minutes Authelia bans the user for 30 minutes (`regulation`); the log
  shows it.
- **Waiting for the 2FA registration code**: with the file notifier it is in
  the container: `docker compose exec authelia cat /data/notification.txt`.
- **Redirect loop or "no session" after login**: `AUTH_DOMAIN` must be a
  subdomain of `DOMAIN` (the session cookie is set for `DOMAIN`), and the app
  must be served as `https://<name>.<DOMAIN>`.

## Firewall

```sh
nft list table inet ztvpn
scripts/setup/firewall-setup.sh --print | diff - /etc/nftables.d/ztvpn.nft
ls -lt /var/backups/zero-trust-vpn/firewall/
```

- **Locked out of SSH**: if `--confirm-timeout` was used, the previous table
  comes back by itself after the timeout. Otherwise, from the console:
  `nft delete table inet ztvpn` removes all rules of this project (the host
  is then unfiltered by it), fix `ADMIN_ALLOWLIST`/`SSH_PORT` and re-apply.
  Full previous rulesets are in `/var/backups/zero-trust-vpn/firewall/`.
- **"applying would lock you out"**: the script compared your SSH session
  (`SSH_CONNECTION`) with `ADMIN_ALLOWLIST` and `SSH_PORT`. Add your address,
  or when administering over the VPN add the SSH port to `WG_INPUT_PORTS`.
- **Containers lost network access after `systemctl restart nftables`**:
  `/etc/nftables.conf` with `flush ruleset` removed Docker's rules.
  `systemctl restart docker` recreates them. Re-apply this project's table
  with `scripts/setup/firewall-setup.sh --apply`.
- **Blocks or quarantines disappeared** after a reboot or nftables reload:
  check `systemctl status ztvpn-firewall-state.service` and run
  `scripts/setup/firewall-setup.sh --restore-state`. The saved state is
  `/var/lib/zero-trust-vpn/firewall/dynamic-sets`; expired entries are
  skipped on purpose.

## Certificates and CRL

```sh
scripts/automation/cert-renewal.sh check
openssl verify -crl_check -CAfile /opt/zero-trust-vpn/certificates/ca/ca.crt \
    -CRLfile /opt/zero-trust-vpn/certificates/crl/ca.crl \
    /opt/zero-trust-vpn/certificates/clients/alice--laptop.crt
openssl crl -in /opt/zero-trust-vpn/certificates/crl/ca.crl -noout -nextupdate
awk -F'\t' '{print $1, $2, $4, $6}' /opt/zero-trust-vpn/certificates/ca/index.txt
```

- `index.txt` columns printed: status (`V` valid, `R` revoked, `E`
  expired), expiry, serial, subject.
- **"CRL has expired"** from `openssl verify`: the CRL is valid for 30 days
  and is regenerated on every revocation and every `pki-setup.sh` run.
  Run `scripts/setup/pki-setup.sh` (it keeps the CA and the current server
  certificate).
- **"No CA at ..."**: run `scripts/setup/pki-setup.sh` first.
- **"Incomplete CA"**: only one of `ca.crt` / `ca/private/ca.key` exists.
  Restore the missing file from a backup; `--force` would create a new CA and
  invalidate every issued certificate.
- **nginx still serves the old certificate**: `cert-renewal.sh renew` reloads
  nginx itself; after `pki-setup.sh` run `docker compose restart nginx`.

## Users and devices

- **"Peer ... already exists" / "... already exists" for the client
  directory**: a device with that name is still enrolled, or a previous
  attempt left `/opt/zero-trust-vpn/wireguard/clients/<peer>/`. Check with
  `scripts/management/device-enrollment.sh list --user alice`.
- **"No free address left in 10.8.0.0/24"**: every address is assigned or
  reserved by an active quarantine record in `/var/lib/zero-trust-vpn/quarantine/`.
- **`revoke-user.sh` exits 2**: LDAP backend without `LDAP_DISABLE_HOOK`;
  disable the directory account yourself.
- **`user-sync.sh` refuses to revoke**: more users than `--max-revoke`
  would lose access, which usually means a wrong `LDAP_BASE_DN` or filter.
  Check the dry-run output before using `--force`.

## Useful state files

| File | Content |
|---|---|
| `/var/lib/zero-trust-vpn/device-inventory.json` | enrolled devices |
| `/var/lib/zero-trust-vpn/incidents/*.json` | `threat-response.sh` incident records |
| `/var/lib/zero-trust-vpn/quarantine/<peer>/` | removed peers kept for `release` |
| `/var/lib/zero-trust-vpn/monitor/wg-sample.json` | previous transfer sample for spike detection |
| `/var/lib/zero-trust-vpn/reports/` | `compliance-check.sh` reports |
| `/var/log/zero-trust-vpn/audit.log` | who changed users, devices and policies |
| `/var/log/zero-trust-vpn/alerts.log` | `connection-monitor.sh` alerts |
