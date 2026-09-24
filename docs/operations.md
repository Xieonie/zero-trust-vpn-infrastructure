# Operations

Day-to-day administration with the scripts in `scripts/`. Every script
prints its options with `--help` and reads `/etc/zero-trust-vpn/ztvpn.conf`.
Scripts that change state refuse to run without root; the monitoring
scripts need root in practice to read keys, `wg` state and the nftables
ruleset. Commands below are run as root from the root of the repository
checkout.

Management scripts (`add-user.sh`, `revoke-user.sh`,
`device-enrollment.sh`, `policy-update.sh`) append one line per action to
`/var/log/zero-trust-vpn/audit.log` with the acting user (`SUDO_USER`).

## Users

### Add a user

```sh
scripts/management/add-user.sh alice alice@example.org --name "Alice Example" --device laptop
scripts/management/add-user.sh bob bob@example.org --groups employees,remote-workers --cert --qr
scripts/management/add-user.sh carol carol@example.org --admin --no-vpn
```

- Usernames: lowercase, start with a letter, 2 to 32 characters of
  `a-z 0-9 _ -`, no `--` (reserved as the user/device separator).
- Groups: `DEFAULT_USER_GROUPS` (`users,vpn-users`) plus `--groups`
  plus `admins` with `--admin`. Only groups in `KNOWN_GROUPS` are accepted.
- The peer is `<user>` or, with `--device`, `<user>--<device>`. Its tunnel
  address is the next free one in `VPN_SUBNET`.
- `--cert` issues a client certificate with CN = peer name
  (not enforced by anything shipped, see the README limitations).
- `--qr` writes a PNG next to the client config (needs `qrencode`).
- The random password goes only into
  `/etc/zero-trust-vpn/secrets/onboarding/<user>-<timestamp>.txt` (mode 600),
  never to the terminal or e-mail.
- If any step fails, everything already created (account, peer, certificate,
  inventory entry) is rolled back.

Output on stdout, for scripting:

```
user=alice
peer=alice--laptop
ip=10.8.0.3
client_config=/opt/zero-trust-vpn/wireguard/clients/alice--laptop/alice--laptop.conf
onboarding=/etc/zero-trust-vpn/secrets/onboarding/alice-20260101T120000.txt
```

After handing over the config and onboarding file, delete
`/opt/zero-trust-vpn/wireguard/clients/<peer>/private.key` and the
onboarding file.

With `AUTHELIA_BACKEND=ldap`, `add-user.sh` only provisions the peer and
reports the directory account as a manual step.

### Change groups

```sh
scripts/management/policy-update.sh add-group alice security
scripts/management/policy-update.sh remove-group alice security
scripts/management/policy-update.sh set-groups alice employees,monitoring           # keeps users,vpn-users
scripts/management/policy-update.sh set-groups alice users,vpn-users,guests --exact  # exactly these
```

File backend only. Every change is backed up, validated and rolled back on
failure. Authelia picks up the users file by itself (`watch: true`).

### Passwords and re-enabling

The portal's password change/reset is disabled (the scripts own the users
file). Admins handle it:

```sh
scripts/management/user-account.sh reset-password alice   # new random password -> 0600 onboarding file
scripts/management/user-account.sh disable alice          # account only; peers and certificates stay
scripts/management/user-account.sh enable alice           # peers/certs removed by revoke-user are not restored
scripts/management/user-account.sh show alice             # JSON without the hash
```

File backend only. After `enable`, enrol devices again with
`device-enrollment.sh enroll`.

## Devices

```sh
scripts/management/device-enrollment.sh enroll --user alice --device phone --type phone --qr
scripts/management/device-enrollment.sh enroll --user alice --device desktop --ip 10.8.0.50 --dry-run
scripts/management/device-enrollment.sh list
scripts/management/device-enrollment.sh list --user alice --json
scripts/management/device-enrollment.sh show --user alice --device phone
scripts/management/device-enrollment.sh remove --user alice --device phone --reason keyCompromise
```

- `enroll` requires an existing, enabled Authelia user (file backend) and
  creates peer `<user>--<device>`. `--type` is `laptop`, `desktop`, `phone`
  or `tablet` and is only recorded in the inventory. `--dry-run` validates
  and prints the plan without writing anything.
- `remove` takes the peer off `wg0.conf` and the running interface, archives
  its keys under `/var/backups/zero-trust-vpn/revoked/`, revokes certificates
  with that CN and marks the inventory entry revoked. Default reason:
  `cessationOfOperation`.
- The inventory is `/var/lib/zero-trust-vpn/device-inventory.json`. `show`
  combines it with the live peer state and never prints key material.

## Revoking a user

```sh
scripts/management/revoke-user.sh alice
scripts/management/revoke-user.sh alice --reason keyCompromise
scripts/management/revoke-user.sh alice --keep-account      # VPN and certificates only
scripts/management/revoke-user.sh alice --delete-account    # remove from users file (copy archived)
```

What happens:

1. Authelia account disabled (file backend), deleted with
   `--delete-account`, or with the LDAP backend `LDAP_DISABLE_HOOK` is run as
   `<hook> <user> disable|delete`.
2. Every peer `alice` and `alice--*` removed from `wg0.conf` and the live
   interface (the tunnel ends immediately); key material archived under
   `/var/backups/zero-trust-vpn/revoked/alice-<timestamp>/`.
3. Every valid certificate with CN `alice` or `alice--*` revoked; CRL
   regenerated.
4. Inventory entries marked revoked; audit log line written.

Matching is exact: `bob` never affects `bobby`. Exit codes: 0 done, 1 a
step failed (the others still ran; failures are listed), 2 done except a
manual step (LDAP backend without hook).

Web sessions of a disabled user end when Authelia re-reads the user,
at most `refresh_interval` (1 minute) after the change.

## Access policies

The live Authelia configuration is
`/opt/zero-trust-vpn/authelia/configuration.yml`. Rules are evaluated top to
bottom, first match wins, anything unmatched is denied.

```sh
scripts/management/policy-update.sh list-rules
scripts/management/policy-update.sh add-rule --domain wiki.example.org --policy two_factor \
    --subject group:employees --subject group:contractors --network vpn
scripts/management/policy-update.sh add-rule --domain wiki.example.org --policy two_factor \
    --subject group:admins --network vpn --resource '^/admin([/?].*)?$' --position 0
scripts/management/policy-update.sh remove-rule --index 3
scripts/management/policy-update.sh remove-rule --domain wiki.example.org --restart
```

- `--policy` is `one_factor`, `two_factor` or `deny` (no `bypass`).
- Subjects (`group:<name>` or `user:<name>`) are OR-ed. Groups must be in
  `KNOWN_GROUPS`.
- Always pass `--network vpn`: the shipped rules all carry it, and a rule
  without a network matches any source address.
- `--resource` values are regular expressions on the path; Authelia's
  validator rejects expressions it cannot compile and the change is rolled
  back.
- Before every change the config and users file are copied to
  `/var/backups/zero-trust-vpn/policy/<timestamp>/`. After the change the
  script checks the structure and, when Docker is usable, runs
  `authelia validate-config` in `authelia/authelia:4.39`. On failure the
  backup is restored. `AUTHELIA_VALIDATE=yq` skips the Docker validation,
  `AUTHELIA_VALIDATE=docker` requires it.
- Authelia does not reload `configuration.yml` by itself. Pass `--restart`
  (restarts compose service `authelia`) or run
  `cd /opt/zero-trust-vpn && docker compose restart authelia`.

A new domain also needs an nginx server block. Copy
`/opt/zero-trust-vpn/nginx/templates/grafana.conf.template` to a new
`*.conf.template` in the same directory, change `server_name` and
`$upstream_app`, and restart nginx
(`cd /opt/zero-trust-vpn && docker compose restart nginx`). The server
certificate must cover the name (`PKI_SERVER_SANS=*.<DOMAIN>`).

Maintenance:

```sh
scripts/management/policy-update.sh validate
scripts/management/policy-update.sh backup
scripts/management/policy-update.sh restore 20260101T120000.123456789 --restart
```

## Certificates

```sh
scripts/automation/cert-renewal.sh check
scripts/automation/cert-renewal.sh check --days 45 --critical 14
scripts/automation/cert-renewal.sh renew --dry-run
scripts/automation/cert-renewal.sh renew --days 30
```

- `check` lists the CA, server and client certificates with days left.
  Exit 0 all fine, 1 something within `--days` (default 30), 2 within
  `--critical` (default 7) or expired. Suitable for a monitoring probe.
- `renew` re-issues server certificates within `--days` with the same CN
  and SANs and a new key, backs up the old pair first (restored if issuing
  fails), revokes the old serial as `superseded` and sends SIGHUP to the
  nginx container (`--no-reload` to skip). Client certificates are only
  re-issued with `--reissue-clients`; their new private key is created on
  the server.
- The CA is only reported (warning within 180 days). It is never renewed
  automatically.

Other certificate tasks with `pki-setup.sh`:

```sh
scripts/setup/pki-setup.sh --san 10.0.1.10 --reissue   # add a SAN (not persisted; use PKI_SERVER_SANS)
scripts/setup/pki-setup.sh --write-config              # regenerate openssl.cnf after changing PKI_* settings
```

`pki-setup.sh` does not reload nginx; after it issued a new certificate run
`cd /opt/zero-trust-vpn && docker compose restart nginx`.

CA rollover is manual: `pki-setup.sh --force` moves the old CA, all
certificates, the CRL and the passphrase to
`/var/backups/zero-trust-vpn/pki-<timestamp>/` and creates a new CA. Every
certificate signed by the old CA stops verifying, and clients must trust
the new `ca.crt`.

## Firewall changes

Edit `ztvpn.conf`, preview, then apply:

```sh
scripts/setup/firewall-setup.sh --print
scripts/setup/firewall-setup.sh --apply --confirm-timeout 120
```

`--apply` validates with `nft -c`, backs up the full ruleset to
`/var/backups/zero-trust-vpn/firewall/`, replaces only `table inet ztvpn`,
carries over current blocklist and quarantine entries, writes
`/etc/nftables.d/ztvpn.nft` and makes sure `/etc/nftables.conf` includes it.
With `--confirm-timeout N` it rolls back after N seconds unless you press
Enter or `touch /var/lib/zero-trust-vpn/firewall/confirm`.

Do not `systemctl restart nftables` on this host if `/etc/nftables.conf`
contains `flush ruleset` (the Debian default does): that also removes
Docker's rules. Re-run `firewall-setup.sh --apply` instead.

## Incident response

`threat-response.sh` performs containment actions. Each action runs even if
another one fails; the result is written to
`/var/lib/zero-trust-vpn/incidents/INC-<time>-<id>.json` and the incident id
is printed on stdout. `--dry-run` prints the plan and changes nothing.

```sh
# block an address for 1 hour (nftables set element with timeout)
scripts/automation/threat-response.sh --type brute-force --ip 203.0.113.7
scripts/automation/threat-response.sh --type brute-force --ip 203.0.113.7 --duration 7d --reason "portal scan" --notify

# external IP: block; tunnel IP: quarantine the peer (traffic dropped, peer kept)
scripts/automation/threat-response.sh --type suspicious-traffic --ip 10.8.0.14

# device: quarantine its tunnel IP, remove the peer (archived), revoke its certificate
scripts/automation/threat-response.sh --type compromised-device --device alice--laptop
scripts/automation/threat-response.sh --type compromised-device --user alice --device laptop
scripts/automation/threat-response.sh --type compromised-device --ip 10.8.0.3

# user: disable account, quarantine and remove all peers, revoke certificates (keyCompromise)
scripts/automation/threat-response.sh --type compromised-user --user alice --ip 198.51.100.23

# undo
scripts/automation/threat-response.sh unblock --ip 203.0.113.7
scripts/automation/threat-response.sh release --device alice--laptop
scripts/automation/threat-response.sh release --ip 10.8.0.14
```

- `--duration`: `<n>s|m|h|d`, default `1h`, at most `THREAT_MAX_BLOCK`
  (default `30d`). `--reason`: printable text, at most 64 characters.
- Never blocked: `ADMIN_ALLOWLIST`, `VPN_SERVER_IP`, loopback, the host's own
  addresses, the SSH client running the script, and RFC 1918 ranges when
  `THREAT_PROTECT_PRIVATE=yes`.
- Blocking cuts established connections too: the `input` chain drops
  blocklisted sources before it accepts established traffic. `conntrack`
  (installed by `initial-setup.sh`) additionally clears NAT state.
- `--notify` sends to `SLACK_WEBHOOK` and/or `NOTIFICATION_EMAIL` (via
  `sendmail`).
- `release --device` puts a removed peer back with its old keys and address
  and lifts the quarantine. Only do that if the device turned out not to be
  compromised; otherwise enrol it again with new keys. The Authelia account
  of a `compromised-user` stays disabled (see "Passwords and re-enabling").
- A removed peer's tunnel address stays reserved while its quarantine
  record `/var/lib/zero-trust-vpn/quarantine/<peer>/` exists. To retire it
  for good instead of releasing it, rename the directory with a dot suffix
  (for example `mv /var/lib/zero-trust-vpn/quarantine/alice--laptop /var/lib/zero-trust-vpn/quarantine/alice--laptop.retired`)
  and remove the address from the set:
  `nft delete element inet ztvpn quarantine4 '{ 10.8.0.3 }'`.
- Every change to the blocklists and the quarantine set is saved to
  `/var/lib/zero-trust-vpn/firewall/dynamic-sets` (with absolute expiry).
  `ztvpn-firewall-state.service` restores them at boot after
  `nftables.service`; `firewall-setup.sh --apply` merges live and saved
  entries; `firewall-setup.sh --restore-state` does it by hand. Entries added
  with plain `nft add element` are not saved.

## Directory reconciliation (LDAP / AD)

```sh
scripts/automation/user-sync.sh                 # dry run: report only
scripts/automation/user-sync.sh --json
scripts/automation/user-sync.sh --apply
scripts/automation/user-sync.sh --apply --max-revoke 20
```

Checks the owners of all WireGuard peers (and, with the file backend, all
users in the users file) against the directory. Users that are missing,
disabled/locked, or not members of `LDAP_REQUIRED_GROUP` lose VPN access
with `--apply`: peers removed (archived under
`/var/backups/zero-trust-vpn/user-sync/`), certificates revoked, file
account disabled. LDAP errors never count as "missing". More than
`--max-revoke` (default 5) revocations in one run are refused unless
`--force`. `SYNC_IGNORE_USERS` lists local accounts (for example a
break-glass admin) that are never revoked. Settings: `LDAP_URI` (`ldaps://`,
or `ldap://` with mandatory StartTLS), `LDAP_BASE_DN`, `LDAP_BIND_DN`,
`LDAP_BIND_PASSWORD_FILE`, `LDAP_FLAVOR` (`openldap` or `ad`),
`LDAP_USER_FILTER`, `LDAP_REQUIRED_GROUP`, `LDAP_CA_CERT`. Needs
`ldapsearch` (package `ldap-utils`).

## Monitoring and audit

```sh
scripts/monitoring/connection-monitor.sh
scripts/monitoring/connection-monitor.sh --json --window 30m
scripts/monitoring/connection-monitor.sh --watch 60
scripts/monitoring/connection-monitor.sh --respond
```

`connection-monitor.sh` reads `wg show wg0 dump` and reports each peer by
name with handshake age and transfer. Alerts (written to
`/var/log/zero-trust-vpn/alerts.log`): peers on the interface that are not
in `wg0.conf`, managed peers missing from the interface, transfer spikes
compared with the previous sample (`MONITOR_SPIKE_BPS`), and source
addresses with at least `MONITOR_AUTH_FAIL_THRESHOLD` (10) failed Authelia
logins within the window. Authelia logs come from `AUTHELIA_LOG_FILE`, the
container `AUTHELIA_CONTAINER`, or the compose service `authelia`.
`--respond` hands those addresses to `threat-response.sh --type
brute-force`. Exit 0 no alerts, 1 alerts, 2 error.

```sh
scripts/monitoring/security-audit.sh
scripts/monitoring/security-audit.sh --verbose
scripts/monitoring/security-audit.sh --json --fail-on medium
```

`security-audit.sh` runs 31 checks with stable IDs:

| Area | Check IDs |
|---|---|
| File permissions | `FILE-WG-KEY`, `FILE-WG-CONF`, `FILE-WG-CLIENTS`, `FILE-WG-CLIENT-KEYS-ON-SERVER`, `FILE-CA-PASS`, `FILE-CA-KEY`, `FILE-PKI-KEYS`, `FILE-AUTHELIA-USERS`, `FILE-AUTHELIA-SECRETS`, `FILE-CONFIG` |
| PKI | `PKI-CA-KEY-ENCRYPTED`, `PKI-CA-EXPIRY`, `PKI-SERVER-EXPIRY`, `PKI-CLIENT-EXPIRY`, `PKI-CHAIN`, `PKI-CRL` |
| WireGuard | `WG-HOOKS`, `WG-UNMANAGED`, `WG-ALLOWEDIPS`, `WG-PSK` |
| Firewall | `FW-TABLE`, `FW-POLICY`, `FW-SETS`, `FW-IPV6` |
| Docker | `NET-DOCKER-PORTS` |
| Authelia | `AUTH-DEFAULT-DENY`, `AUTH-BYPASS`, `AUTH-INLINE-SECRETS` |
| Identities | `ID-ORPHAN-PEERS`, `ID-IDLE-ACCOUNTS`, `ID-UNKNOWN-GROUPS` |

Each check passes, fails with a severity and the offending items, or is
skipped when the component is missing. Exit 1 if a finding reaches
`--fail-on` (default `high`), 2 on errors.

```sh
scripts/monitoring/compliance-check.sh
scripts/monitoring/compliance-check.sh --framework nist-800-207
scripts/monitoring/compliance-check.sh --framework iso27001 --json --output /root/reports
```

`compliance-check.sh` maps the audit results to ISO/IEC 27001:2022 Annex A
controls and the NIST SP 800-207 tenets and writes a JSON report to
`/var/lib/zero-trust-vpn/reports/`. `PASS` means only that all mapped
technical checks passed; organisational requirements are always `MANUAL`.
It does not certify anything. Exit code: number of failed controls.

## Scheduling

Nothing is scheduled by the installer. An example `/etc/cron.d/ztvpn` (not
shipped; adjust the checkout path and choose your own intervals):

```
*/5 * * * * root /usr/local/src/zero-trust-vpn-infrastructure/scripts/monitoring/connection-monitor.sh --once --window 5m >/dev/null
17 3 * * *  root /usr/local/src/zero-trust-vpn-infrastructure/scripts/automation/cert-renewal.sh renew --days 30
30 4 * * 1  root /usr/local/src/zero-trust-vpn-infrastructure/scripts/monitoring/security-audit.sh --fail-on none >/dev/null
0 * * * *   root /usr/local/src/zero-trust-vpn-infrastructure/scripts/automation/user-sync.sh --apply
```

## Backups

There is no backup script. The scripts make copies before they replace
something (all under `/var/backups/zero-trust-vpn/`: `pki-*`, `wireguard-*`,
`authelia/`, `policy/`, `firewall/`, `compose/`, `revoked/`, `user-sync/`),
but a restorable backup of the host needs:

| What | Where |
|---|---|
| Central config and secrets (CA passphrase, onboarding, LDAP password) | `/etc/zero-trust-vpn/` |
| WireGuard server key and peers | `/etc/wireguard/` |
| CA, certificates, CRL | `/opt/zero-trust-vpn/certificates/` |
| Authelia config, users file, secret files | `/opt/zero-trust-vpn/authelia/` |
| Compose file, `.env`, nginx templates | `/opt/zero-trust-vpn/` |
| Inventory, quarantine records, incidents | `/var/lib/zero-trust-vpn/` |
| Audit and alert logs | `/var/log/zero-trust-vpn/` |
| Authelia database (TOTP/WebAuthn registrations) | PostgreSQL volume: `cd /opt/zero-trust-vpn && docker compose exec postgres pg_dump -U authelia authelia > authelia.sql` |

These contain private keys and the CA passphrase; store the backup
encrypted. The CA key is only protected by the passphrase in
`/etc/zero-trust-vpn/secrets/ca.pass`, so do not keep both in the same
unencrypted archive.

## Updating

Pull the repository and re-run `scripts/setup/initial-setup.sh`. It keeps
keys, CA, peers, users and secrets, keeps locally edited Authelia and nginx
files (with a warning), and replaces `docker-compose.yml` after backing it
up. Image versions are pinned in the compose file.
