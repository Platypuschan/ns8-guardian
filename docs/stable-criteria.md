# Criteria for a stable release / catalog entry

Promoting beyond a prerelease is an **owner decision**; this list only says what evidence must exist. Nothing here
authorizes publishing. Every item needs a link to a run, log or read-back, not a statement.

| # | Criterion | Evidence | Status (update on each RC) |
|---|---|---|---|
| 1 | Validate Guardian green on the exact release commit (tests, ui, policy, images, both NS8 install jobs, publish jobs) | run URL | per RC |
| 2 | Hosted two-node lab green on the **exact promoted digest** (all required cases incl. `engine_restart_event_replay`, admin API login, native backup/restore) | `result.json` of the run, digest equal to the release digest | per RC |
| 3 | Lab green with both distro combinations (hub/member Debian 13 and Rocky 9, swapped) | two runs | satisfied for rc.6 candidate (runs 45047517971 and 45056728971); repeat per RC |
| 4 | Optional `hub_disk_snapshot_rollback` case green once (`disk_rollback=true`) | run URL | satisfied (run 45047517971, rc.6 candidate); repeat per RC |
| 5 | Upgrade path: an existing earlier RC instance updated with `cluster/update-module` keeps its state, bans and enrollment; rollback to the previous digest documented and exercised | read-back log on a disposable instance | lab-proven on rc.7 candidate (run 45147228479: update-module to the previous digest and forward again, ban/UUID/epoch preserved); real node2 rc.3 -> rc.6 upgrade done; rollback on node2 not exercised; **owner decision 2026-11-24: rollback on node2 is waived** — no earlier version was a sound base, this RC line is the first that could serve as one |
| 6 | Rules replay (`tests/test-rules.sh`) green with real engine, including HTTP scanner negative controls | CI/local output | per RC |
| 7 | No open known limit that can lose accepted security input silently: consumer ACK/replay in place; limits (finite storage, at-least-once, replay window 120 s) documented | docs/application-events.md | satisfied since rc.4 candidate |
| 8 | Real application adapters: at least the documented SDK path demonstrated end to end against a real NS8 app, with wrong-password/correct-password/MFA controls | adapter acceptance log | open (adapter work is per application) |
| 9 | Production-like soak: one real multi-app node with the module for at least 7 days, no unexplained bans of the management source, no sync errors beyond transient | status/journal export | **running** on node2 (hub, rc.17 since 2026-11-24 23:05 UTC); earliest evidence 2026-12-01; a module update restarts the count |
| 10 | Security review of the release diff (credentials, gateway exposure, redaction) and dependency/image digests pinned | review note | per RC |
| 11 | Catalog metadata, icon/UI texts and documentation reviewed; `CATALOG_VERSION` raised | PR | at promotion |
| 12 | Owner approval in writing for stable/latest tags and catalog publication | issue/PR comment | owner; **given in chat by the owner on 2026-11-24** (stable promotion once the other criteria hold; the publish step itself is announced before it runs) |

Release notes must state remaining limits verbatim from this table. Do not weaken a criterion to make a release pass.
