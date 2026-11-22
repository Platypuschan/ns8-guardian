# ADR 0001: autonomous hybrid protection

Status: implementation target; acceptance results belong in the build report.

## Scope

Guardian continues the autonomous hybrid implementation developed from [ns8-crowdsec-companion](https://github.com/Platypuschan/ns8-crowdsec-companion). Public module/engine packages and nftables names use the Guardian namespace; the internal `cscompanion` Python package, `get-companion-status` action and `csc2` enrollment contract remain for compatibility. Every configured host runs a complete CrowdSec engine, local LAPI/database and local nftables bouncer. A hub additionally exposes a private synchronization API through NS8 Traefik. A member never points its CrowdSec engine or bouncer at the hub. Hosting source and tested development candidates does not authorize stable publication, catalog enrollment or live instance replacement.

## Hybrid acquisition

1. Applications with a trustworthy authentication callback send a structured `authentication_failed` event to the local gateway. Applications lacking a callback may use a separately maintained adapter over structured audit data. The NS8 packaging layer does not magically know an application's login outcome.
2. The receiving gateway authenticates an individually revocable source credential and assigns its registered module identity. It validates and durably accepts a minimal event with stable UUID, schema version, original UTC timestamp and canonical source IP. It does not accept a requested ban, arbitrary source identity, password, session token or raw request.
3. Accepted events feed a dedicated CrowdSec parser/scenario. Thresholds, ban duration and allowlists remain in the local protection stack.
4. Existing SSH, NS8 admin, Samba and proxy acquisition remain available. Enrolling an application event source switches off that application's overlapping proxy-login fallback. This switch requires a tested working sender before production enrollment; registration alone does not install an application hook.
5. A durable producer-side spool decouples application availability from receiver availability. Accepted means stored, not that a ban has already been created. Bounded storage cannot promise unlimited retention. Delivery guarantees across independent databases, file tails and CrowdSec in-memory scenario buckets must be stated honestly, not called exactly-once.

## Private synchronization

The sync worker is independent of engine/bouncer startup. Local decisions are made before any remote request. The hub authenticates individual peers, not a global administrator credential. Administrative changes use NS8's action authorization, not the peer-upload token.

Use supported local LAPI/cscli operations, not direct writes to CrowdSec SQLite. Persist outbound state, remote revisions and decision provenance in separate SQLite storage. Preserve absolute expiry; reconnect must not grant a fresh full ban duration. Imported decisions must not be re-exported as detections. Delete imported claims by their own decision identity, never indiscriminately remove a genuinely independent local ban on the same IP. Version removals/overrides so stale retries cannot resurrect them. A full remote state refresh must preserve local claims and fresh offline detections.

A disconnected node necessarily cannot learn new remote threats, revocations or policies. Expose last successful synchronization and pending work separately from local LAPI/enforcement status. Local emergency allowlisting and unban must not require a reachable hub. Document whether an unban is local, origin-owned or globally overriding; never silently conflate these operations.

## Startup, privileges and privacy

Pin the upstream engine and bouncer image identities. Bake required rule content into an engine image and suppress runtime hub updates/installation, including hidden entrypoint version lookups. Provisioning a first installation still requires those images. Rule updates are new tested image builds; keep the last working image available. Explicitly disable CrowdSec CAPI/Console and avoid vendor insights/feed integrations. Public rules are not community IP reputation.

The module remains rootful because it needs trusted host-journal access and nftables. Only the bouncer receives the firewall capabilities. Keep gateway and LAPI listeners on loopback; publish only the synchronization gateway for a hub via HTTPS. Verify certificates; do not offer a production TLS-bypass toggle. Per-source and per-peer tokens confer reporting rights, not trust in every report: enforce schema/TTL/size/rate limits and keep administrator access separate.

## Compatibility

The former member architecture depended on a remote LAPI. New enrollment must be versioned (`csc2`); reject or explicitly migrate `csc1`, never silently reinterpret it. Do not claim an in-place migration or backup/restore is verified until exercised on NS8 guests. Never run the old and new firewall owners on the same node as a migration shortcut.

## Required acceptance

- Hook event and trusted-log path each produce real local CrowdSec decisions.
- Invalid input, forged identities, replayed UUIDs and untrusted journal sources do not produce additional detections.
- Hub down: new local attack produces a decision and real packet drop; engine/bouncer restart restores local protection without the hub.
- Reconnect: propagate remaining TTL, no echoes, no duplicated/renewed bans; apply removal without deleting independent causes.
- IPv4 and IPv6, allowlist and expiry; unblocked client positive controls.
- Persist event/sync state, exercise failed delivery and process restart, validate backup projection.
- Build actual module metadata image plus actual offline engine image; compare labels with exported artifacts.
- Test NS8 actions and real guest lifecycle separately from local fixtures. A local container E2E is not a real NS8 reboot/restore result.

## Non-goals of this change

No application forks or unverified auth hooks in sibling repositories; no global internet reputation database; no inline WAF/browser challenge promise; no automatic high-availability controller election; no infinite lossless retention on finite disks.
