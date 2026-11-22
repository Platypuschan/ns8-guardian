# Acceptance boundaries for the autonomous hybrid module

This document describes what each test level establishes. A successful lower-level fixture must not be presented as a higher-level acceptance result.

## Automated source and protocol tests

- `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=imageroot/pypkg python3 -m unittest discover -s tests -v` discovers the backend suites. Actual engine tests are intentionally gated; run them separately using `tests/test-e2e.sh` or `RUN_ENGINE_TESTS=1` with the declared tools image. Count skips explicitly.
- `python3 -B -m unittest discover -s qa -v` covers packaging contracts, the producer SDK and real isolated offline-runtime startup/restart. Supply `HYBRID_ENGINE_IMAGE` as the immutable image ID or freshly verified reference under test.
- `(cd ui && node --test qa/views.test.cjs)` exercises actual view scripts across an explicit fake NS8 task boundary. Lint/build compile the production UI. `ui/qa/browser-checks.js` additionally exercises real rendered Vue/Carbon views. Neither is a live NS8 browser integration test.
- Additional remediation regression suites exercise the review's previously failing state sequences, not just existing happy paths. Refer to their actual RED/GREEN results in the accompanying project handover, rather than assuming an unchanged passing count proves the fixes.

## Isolated real engine and firewall

`bash tests/test-rules.sh` replays fixtures through actual CrowdSec rules. It verifies expected synthetic detections and negative controls, not current login behavior of running Gitea/Organizr/Samba instances.

`bash tests/test-e2e.sh` runs actual local engines and nftables bouncers inside owned rootless Podman network namespaces. It covers local decisions and packet drops, controller-independent service restarts, imports, expiry, allowlisting and independent local/remote ban causes. It is not a real NS8 host reboot, firewalld coexistence, container-FORWARD or backup/restore test. Event-consumer recovery must be verified separately from the mere survival of existing bans.

## NS8 guest smoke and lifecycle

`tests/ns8-smoke.sh` and `tests/ns8-remove.sh` exercise a fresh guest's NS8 actions, routing, source provisioning, local protection, unban and removal. The workflow definition expresses the intended Debian/Rocky matrix; only actual completed job logs establish which platforms and exact source/artifact identities passed.

Earlier development handovers reported single-node Debian NS8 installation, VM reboot, backup/restore and legacy-hub upgrade tests before this remediation. Those are historical evidence, not acceptance of the repaired source. No automatic claim is made that the revised event or synchronization protocol has passed a new complete VM lifecycle run.

Before production deployment, repeat on the repaired artifact:

- Real two-node NS8 synchronization with the controller unavailable, and new local attacks on both nodes.
- Host reboot, reconnection and restored-controller convergence, including an unban acknowledged after the backup snapshot and before restore.
- Both supported guest distributions, plus the actual container forwarding and trusted-proxy/CDN path.
- Real application adapters with success/failure/MFA controls and correctly attributed IPv4/IPv6 clients.
- Capacity/retry behavior, storage failures and relevant upgrade/rollback paths under the deployed topology.

## Coverage and non-goals

This version provides two conservative generic HTTP scanner rules (`ns8-http-probing`, `ns8-http-sensitive-probe`, replayed by `tests/test-rules.sh` against the real engine, including negative controls) but no inline WAF/AppSec, and it does not recreate CrowdSec's community reputation database. Enabling stock HTTP collections without fixing the demonstrated client-IP attribution problem is not an acceptable shortcut. Registering a source does not install an application hook. There is no infinite lossless retention guarantee on finite storage, and in-memory detection buckets do not survive an engine restart by themselves: events acknowledged within the last two minutes are replayed (see docs/application-events.md).

An OCI archive or local image is a test artifact, not a published remotely installable release. Release promotion, catalog inclusion and changes to running instances require their own authorization and read-back verification.
