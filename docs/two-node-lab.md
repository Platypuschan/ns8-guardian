# Two-node Guardian lab (two independent full NS8 VMs)

Manual workflow `.github/workflows/two-node-lab.yml` (launcher: `tests/lab/twolab/`, offline regressions:
`qa/test_two_node_lab*.py`). It tests an **immutable published module digest**; it never builds, publishes or promotes
anything (`contents: read` only, no `packages`, no secrets). It does not touch any existing NS8 cluster, node, test
server or the repository's other workflows.

Default input: `ghcr.io/platypuschan/guardian@sha256:de710c02de9215879b5bfa120f61e8b2901f2f7b0cfe5031cda12213da09ac71`
(`0.2.0-rc.3`, source `4d8c243478fc9bd3c04ca813a27b6d70123b0b6d`). The repository is fixed; only the digest is an input.
The run refuses to start unless the registry returns exactly that digest and the image's
`org.opencontainers.image.revision` / `version` labels equal the expected inputs.

## Status of this document

No completed two-VM result is claimed here. Only a completed run's `result.json` establishes anything. Offline tests below use
**mocks that are not real NS8**: they check launcher mechanics and that every assertion fails on wrong evidence.

## Topology

- One hosted `ubuntu-24.04` runner, KVM only. `qemu-system-x86_64 -machine q35,accel=kvm`: if KVM is unusable QEMU
  refuses to start; TCG is never used. The launcher fails closed before touching anything when `/dev/kvm` is not
  usable or free memory, disk or CPUs are below the requirement (2 guests x 3072 MiB + 2 GiB headroom; (2 x 24 + 8) GiB
  disk; 4 CPUs). The upstream single-VM 8 GiB/4 vCPU default is deliberately not inherited, and guest size is not
  a workflow input.
- Two guests: hub = Debian 13, member = Rocky 9 (inputs allow the other combinations), 2 vCPU / 3 GiB / 24 GiB each.
  Cloud images come from the distributions over HTTPS and are **refused unless their published SHA checksum matches**
  (no "weekly key, skip verification" fallback).
- Private owned network: one bridge `gl<run>b`, taps `gl<run>h`/`gl<run>m`, a free random `192.168.16x-23x.0/24`,
  NAT only through iptables rules commented `glab-<run>`; every created link/rule/container/process/directory is
  recorded in a ledger *before* it is created, names carry the unique 8-hex run id, and cleanup touches only ledger
  entries (a crashed launcher is cleaned by `python3 -m twolab cleanup` from the same ledger).
- Two **independent** full NS8 clusters: each guest runs the real `install.sh` and its own `create-cluster` with a
  distinct WireGuard network and a random admin password. No `join-node`, no shared WireGuard peers; this is asserted
  (distinct machine-id, WireGuard key and network; one node and zero peers each).
- Verified HTTPS over a **private CA**: a short-lived CA and a hub certificate are generated on the runner and
  uploaded to the hub's Traefik. The member verifies through the CA carried in its enrollment token. There is no
  TLS-skip option in Guardian (`insecure_skip_verify` is rejected, asserted). Negative controls: the certificate does
  not verify without the private CA and does not verify for a wrong host name.
- Management source: the runner (bridge gateway). It keeps SSH and TCP/443 to both guests throughout and is never in a
  decision or nftables set.

## Synthetic attackers

Attack traffic exists only inside each guest, in an owned network namespace `glab-<run>` connected by an owned veth
pair, using addresses in `198.51.100.0/24` (TEST-NET-2). Bans are produced through Guardian's production event path
(`add-event-source` + six `authentication_failed` events per address), become real CrowdSec decisions and nftables set
entries, and the drop is shown by a TCP probe bound to the synthetic source address (reachable before, silently
dropped after). Nothing external is attacked; the bearer token travels on stdin, never argv.

## Acceptance cases

Every case reports `pass`, `fail` or `not_run`. There is no skipped status (no skipped required case can be green). The run is green only if every required case
passed; a case that did not execute makes the run fail. Required cases:

| id | what it establishes |
|---|---|
| `preflight_capacity_kvm` | measured memory/disk/CPU and usable KVM (no TCG) |
| `cloud_image_checksums` | both images verified against the distribution-published checksum |
| `independent_clusters` | two separate clusters, no shared identity or peers; runner/guest clock skew <= 3 s |
| `module_digest_runtime_readback` | the exact digest is in both guests' image stores and the running containers use exactly the label-pinned engine/bouncer digests |
| `private_ca_verified_https` | verified TLS to the hub with the private CA, plus negative controls |
| `hub_member_enrollment` | member enrolled, sync healthy, hub lists it |
| `member_to_hub_sync_and_drop` | member-local ban becomes a decision and a packet drop on both nodes |
| `hub_to_member_sync_and_drop` | the reverse |
| `absolute_ttl` | after a >= 130 s outage the importing node's expiry equals the origin's absolute expiry within 20 s (a TTL restarted at import would differ by the outage length), both directions |
| `no_echo` | no echo: hub claim origins are exactly the originator; imports are not re-exported; exactly one imported decision per node |
| `allowlist_negative_control` | allowlisted addresses are never banned or dropped on either node |
| `engine_restart_event_replay` | consumer ACK and bucket rebuild: 3 failure events reach the hub engine (bucket capacity 4, no ban) and are acknowledged; the engine unit restarts (in-memory bucket lost); 4 more events must still ban because the acknowledged events were replayed (4 alone cannot overflow the bucket) |
| `hub_unreachable_local_protection` | with hub<->member traffic dropped by an owned nft table inside both guests (host management stays up), the member reports the hub stale yet turns new local auth events into a decision and packet drop; the isolated hub does too |
| `reconnect_convergence_ban_unban` | after the link returns, bans created during the outage converge both ways and an origin unban made during the outage reaches the hub (drop removed) |
| `member_guest_reboot` | full guest reboot (boot id changed), all five units active, bans/nftables/drops persisted, unbanned address not resurrected, sync works again and a new ban propagates |
| `hub_guest_reboot` | same for the hub, plus claims, tombstone and epoch unchanged by a plain reboot |
| `native_ns8_backup_restore` | native `module-backup` to a `cluster` WebDAV repository inside the hub guest, hub module removed, NS8 `restore-module` from the snapshot (same module UUID), units active |
| `restore_new_epoch_tombstone_reconverge` | an unban acknowledged **after** the backup and before the restore: after the restore the hub epoch changed, and the member's origin tombstone replaced the restored live claim; the address is not banned/dropped again, a kept ban is |
| `fresh_observer_no_resurrection` | a brand-new member instance (fresh state, new peer name) enrolled after reconvergence receives the live ban but not the acknowledged-unbanned one |
| `management_source_unaffected` | the runner stays unbanned and keeps SSH, TCP/443 and an NS8 admin API login on both guests throughout |
| `owned_cleanup` | released only run-owned resources; no leftover link or firewall rule |

Optional, only when `disk_rollback=true` (then required): `hub_disk_snapshot_rollback`.

Optional, only when the `previous_digest` input is set (then required): `module_update_rollback`. After all other cases the hub
module is updated with `cluster/update-module` (instances = the hub instance, never `add-module`) to the earlier digest
(rollback) and then to the tested digest again (roll-forward). After each step the case reads back: units active, running
`IMAGE_DIGEST` equals the requested digest, module UUID and hub epoch unchanged, a ban created before the update still a
decision, in nftables and dropping packets, sync not stale. After the roll-forward `PREV_IMAGE_DIGEST` records the earlier
digest and a new ban through the event path works. This is an in-place module update, not a backup restore; it does not prove
that every earlier release is a valid downgrade target.

### Native NS8 backup/restore vs VM disk snapshot

These are different things and are reported separately. `native_ns8_backup_restore` only passes with evidence that NS8's
`restore-module` ran from a restic snapshot (the report refuses that case on any other evidence).
`hub_disk_snapshot_rollback` rolls one VM's qcow2 back to an internal snapshot: it creates **no** new hub epoch, loses
enrollments made after the snapshot, and is **not a native restore**. It asserts exactly that (epoch equals the snapshot
epoch, a later enrollment is gone, local protection still works); it does not claim restore semantics.

## Fresh observer ordering and limits

The observer is the member VM's module re-created with fresh state. It is enrolled only after the hub has finished
tombstone reconvergence, so the race "observer syncs before the member republished its tombstone" is **not** covered by
a deterministic test with two VMs. A third guest would be needed.

## Outputs and what is never uploaded

Only `lab-out/public/` is uploaded: `result.json` (schema `guardian-two-node-lab/1`, exact lab commit and workflow hash,
module digest/labels, per-case evidence), `summary.md`, `source-evidence.json`, a sanitized command `transcript.json`,
sanitized per-guest diagnostics and serial console logs. Redaction covers bearer tokens, `csc*` sync tokens, key/secret/
password/Redis-URL assignments, PEM private keys and every secret generated or received during the run. Evidence keys
that look secret-bearing are rejected, not silently dropped. SSH keys, cloud-init seeds, CA/server keys, admin passwords,
raw consoles and raw Redis are in a private `0700` directory that is deleted at the end and never uploaded.

## Known limits

- The hosted run itself is the only real evidence; offline tests cannot show NS8 behaviour. The restore path assumes
  guest-local `cluster` WebDAV/Restic backup and `upload-certificate` reload must still be exercised by the real run. The installer source is pinned to Core commit `e27e2abbeee37e16e92c23027dbe0d3403aa385c`, Core image `3.25.1`; the password reaches both installer and cluster creation privately. Private-CA upload uses the documented `selfsign` full-chain validation and restores policy `chain` afterward.
- Existing host IPv4 forwarding is required; the lab refuses a host without it instead of changing global policy. AppArmor policy is not relaxed.
- Absolute-TTL comparison needs synchronized clocks; skew above 3 s fails `independent_clusters`.
- The management check proves SSH, TCP/443 and a real NS8 admin API login (`POST /cluster-admin/api/login`, HTTP 200, token discarded) from the gateway. The hub login is TLS-verified against the private CA; the member's default Traefik certificate is not verified for this check.
- Sync cycles are 5 s; waits are bounded (2-4 min per convergence step); the whole job is capped at 90 minutes.

## Running the offline checks

```bash
python3 -B -m unittest discover -s qa -p 'test_two_node_lab*.py' -v
```
