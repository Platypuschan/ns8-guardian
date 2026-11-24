# Guardian for NethServer 8 (autonomous hybrid)

Every host runs a **complete, independent CrowdSec engine** (local LAPI, local
database, local nftables bouncer). Detection and enforcement never depend on
another host. A private **sync worker** exchanges bans between hosts through a
small HTTPS API on one host (the *hub*). Nothing is sent to the CrowdSec cloud:
the Central API, console enrollment and runtime hub downloads are disabled; the
rules are baked into a pinned engine image.

```
 host A (hub)                          host B (member)
 ┌─────────────────────────────┐      ┌─────────────────────────────┐
 │ engine + local LAPI + bouncer│      │ engine + local LAPI + bouncer│
 │ sync worker ─ gateway ◄──────┼─HTTPS┼─ sync worker                 │
 └─────────────────────────────┘      └─────────────────────────────┘
```

- **Local protection**: bans are created and enforced locally, also when the
  hub or the network is down; engine and bouncer restarts do not need the hub.
- **Hub**: additionally serves `POST /v1/sync` through NS8 Traefik
  (`https://<hub host>/`). The LAPI is never published.
- **Member**: enrolls with a `csc2.` token (individual, revocable sync
  credential, optional private CA). It never points its engine or bouncer at
  the hub. Old `csc1.` (remote-LAPI) tokens are rejected: re-enroll.
- **Sync semantics**: a node publishes only its own bans with absolute expiry.
  Imported bans keep their remaining TTL (no renewal), are never re-exported,
  and are removed by their own decision ID only, so an independent local ban on
  the same address survives. Unbans are versioned tombstones. A disconnected
  node cannot learn new remote bans or revocations; the Status page shows the
  last successful sync and pending work separately from local protection.
- **Sync capacity and recovery**: every retained claim, including a tombstone,
  consumes its origin's storage budget (2,000 entries; 10,000 globally).
  Tombstones remain until original expiry so offline observers can revoke bans.
  Temporary quota rejections retry with persisted 5–300 second backoff; import
  saturation schedules a durable rescan rather than silently forgetting skipped
  claims. A restored hub's epoch causes relevant local bans and unbans to be
  republished. Both hub and members need the updated retry protocol: upgrading
  only the hub does not repair an old client's rejection handling. These bounds
  do not promise unlimited retention or a fixed convergence deadline.
- **Local emergency control**: allowlist and unban work without the hub. An
  unban on a member suppresses only the imported claim locally; it does not
  revoke the origin's ban elsewhere.

The module does not modify the official NethServer CrowdSec module and can run
next to it; both use separate nftables tables.

## Application authentication events

Applications with a trustworthy login-failure callback can report events to the
local gateway (**Event sources** page, `add-event-source` action) using the
durable producer helper `sdk/report_auth.py`. See
[docs/application-events.md](docs/application-events.md). Registering a source
does not install a hook; an adapter must be written and tested per application.
Design rationale: [docs/adr/0001-autonomous-hybrid.md](docs/adr/0001-autonomous-hybrid.md).

## What is detected, and how

Besides the application-specific rules (Gitea, Organizr, Samba, admin login and
registered application events) the engine ships the stock CrowdSec Hub rules,
downloaded **at image build time** and stored in the engine image (never fetched at
run time): `crowdsecurity/linux` (SSH brute force, slow brute force, refused
connections, CVE-2024-6387) and the HTTP collections `base-http-scenarios` and
`http-cve` (path probing, sensitive files, backdoors, admin-interface probing, SQLi/XSS
probe patterns, path traversal, WordPress scanning, technology probing, generic 401
brute force, ~30 CVE exploit-path rules, whitelists for CDNs and search-engine crawlers).

HTTP rules read the **Traefik access log through Guardian's own parser**, which takes the client address
exactly as Traefik wrote it, never a forgeable header: the stock Traefik parser stays
disabled because its client-IP interpretation failed the trusted-proxy fixture. NS8's
Traefik does not log request headers, so user-agent rules (`http-bad-user-agent`) cannot match.
`ns8/ns8-http-sensitive-probe` additionally bans three requests within five minutes for
paths no NS8 application serves (`/.env`, `/.git/`, `/cgi-bin/`, `/boaform/`, traversal, ...).

**Rule updates.** A new engine image is built from the then-current Hub snapshot; the module's
start script makes an *existing* configuration volume follow the image (upstream only copies missing files), so
`update-module` to a newer digest really brings new and changed rules and removes retired ones, while the module's own
`ns8-*` rules and generated files are untouched. `runtime/hub-items.lock` records the shipped item versions; the weekly
`rules-watch` workflow rebuilds with the current Hub, shows the diff and replays all rules, publishing nothing.

This is **not** a WAF: no request body inspection and no inline blocking, and no CrowdSec community IP
reputation (that requires the CrowdSec cloud; this module is offline by design).

| Source | Signal | Ban after |
| --- | --- | --- |
| SSH | hub collection `crowdsecurity/sshd` (journal of `sshd.service`/`ssh.service`) | CrowdSec defaults (verified in the hosted lab: 12 failures) |
| HTTP scanning, exploit paths | stock HTTP rules on the Traefik access log (see above) | rule defaults (verified in the hosted lab: path scan) |
| NS8 cluster-admin | Traefik access log: `POST /cluster-admin/api/login` → 401 on router `cluster-admin-https@file` | 5 failures (~10 min window) |
| Gitea web | Traefik access log: `POST /user/login` → 200 (a successful login returns 303) | 5 failures |
| Gitea git / API | Traefik access log: bursts of 401 on `/api/…` or `*.git` | > 30 in a burst |
| Organizr | Traefik access log: `POST /api/v2/login` → 401 | 5 failures |
| Samba (AD/SMB/LDAP) | Samba JSON authentication audit, failed statuses with a remote IP | 5 failures |

### Why the Traefik access log and not the application logs

Application logs often contain values chosen by the client. Gitea, for
example, logs the user name of a failed login verbatim, **including newlines**:

```
… Failed authentication attempt for x from 192.0.2.77:1: user does not exist [uid: 0, name: x from 203.0.113.10:0 …
```

A parser reading that line bans `192.0.2.77`, an address the attacker chose,
and a newline in the user name produces a complete fake log line. With shared
bans this would let anyone lock an administrator out of every host. (Verified
with Gitea 28.0.0; the CrowdSec Hub parser `LePresidente/gitea-logs` is
affected.)

NS8's Traefik writes its access log itself and drops request headers from it,
so method, path, status, router and backend cannot be forged by a client. The
companion therefore recognises HTTP applications by their Traefik router
(`<module>-https@file`) and counts failed logins by path and status. Samba is
read as structured JSON, so client-chosen account names stay inside their JSON
strings. Each journal source is bound to the owning module's container name
**and** Unix UID, so another module cannot write records for it.

The hybrid event interface complements these logs. Use a native authentication
hook when the application version supports one; otherwise use a separately
reviewed structured-log adapter. NS8 lifecycle hooks do not themselves observe
application logins. Source registration does not install or prove an adapter.

### Samba auditing

Samba's NS8 default disables authentication auditing. With **Detect failed
Samba logins** enabled, the companion raises `auth_json_audit` to 2 in the
running Samba process with `smbcontrol`, without restarting Samba or changing
its saved configuration. Removing the companion restores the previous level.

## Install

The module is rootful (it manages host nftables tables) and allows one instance
per node. It is not in the module catalog yet; there is no stable release of
this hybrid version.

This branch is a development candidate, not a published install reference.
Build and validate it before installation in an isolated lab. For an existing
instance, use NS8's update action with its exact instance ID; `add-module` would
create another instance and is not an update. Legacy remote-LAPI members require
explicit csc2 re-enrollment as described above.

### Hub

1. Point a DNS name, for example `crowdsec.example.org`, to the hub node.
2. **Settings → Role: Hub**: enter the host name, keep *Let's Encrypt* enabled
   and save.
3. **Members → Add a member** for each other host. Copy the token; it is shown
   only once.

### NS8 member

Install the module on the other node, choose **Role: Member**, paste the `csc2.`
token and save. **Status** shows local protection and synchronization
separately; **Members** on the hub shows each member's last sync.

### Servers without NS8

Not supported by this version (the former remote-LAPI enrollment is gone).

## Allowlist and unban

The allowlist is configured per node and applied to the local LAPI; allowlisted
addresses are never banned and active local bans for them are removed. Private
networks are never banned (`crowdsecurity/whitelists`). **Bans** lists the
local decisions; unban acts locally (see above).

## Security notes

- A sync token lets one peer publish its own bans (bounded lifetime, size and
  count). Remove a member on the hub when its host is compromised or retired;
  names cannot be reused. Event-source tokens only report authentication
  failures for their registered module.
- Gateway and LAPI listen on loopback. Sync clients verify certificates; there
  is no TLS-bypass option. Only `/v1/sync` is published through Traefik.
  `/v1/events` remains loopback-only and rejects forwarded requests.
- Traefik logs `X-Forwarded-For` as the client address only from trusted
  frontend proxies; the host firewall cannot block clients behind a proxy.
- Detection from the Traefik access log (not client-controlled application
  logs) is kept for apps without an event adapter; see the table above.

## Relation to Fail2ban Reworked

[ns8-fail2ban-reworked](https://github.com/Platypuschan/ns8-fail2ban-reworked)
also shares bans between NS8 hosts (coordinator, permanent bans, ntfy
notifications). Use one of them per host; running both doubles detection and
lets two modules manage Samba's audit level.

## Development and tests

```bash
PYTHONPATH=imageroot/pypkg python3 -m unittest discover -s tests -p 'test_*.py'
buildah bud -f runtime/Containerfile -t localhost/ns8-hybrid-engine:working .
HYBRID_ENGINE_IMAGE=localhost/ns8-hybrid-engine:working python3 -m unittest discover -s qa -v
bash tests/test-rules.sh   # replays tests/fixtures through the rules in the baked offline engine image
bash tests/test-e2e.sh     # real engines + nftables in isolated --network none namespaces
(cd ui && node --test qa/views.test.cjs)
./build-images.sh
```

CI (`.github/workflows/validate.yml`) runs these and then installs the module on
fresh single-node NS8 VMs. That VM test covers install, the hub role, local
detection and ban, the sync API through Traefik, event-source ingestion, unban
and removal. The container E2E exercises isolated engine/bouncer behavior and
reconnect synchronization; it is not an NS8 host-reboot or backup/restore test.
See [acceptance boundaries](docs/acceptance.md) for actual test levels and gaps.

Every change to `imageroot/`, `ui/`, `runtime/`, `sdk/` or `build-images.sh` needs a higher
`CATALOG_VERSION`.

GPL-3.0-or-later. The UI scaffold retains the upstream Nethesis copyright notices.
