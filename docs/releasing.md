# Guardian prerelease promotion

This is an explicit, manually authorized RC promotion, not a stable release,
catalog publication, or production approval. It does not rebuild images or alter
labels. Existing `validate.yml`, application sources and `CATALOG_VERSION` are
not changed by promotion.

## Before dispatch

1. Review and merge the promotion workflow/script/tests to **main** in
   `Platypuschan/ns8-guardian`. Dispatch from main only. The executable code is
   checked out at the exact dispatch SHA, not from `tested_sha` or a mutable ref.
2. Select a completed successful **Validate Guardian** push-to-main run in this
   repository. Required jobs are tests, ui, policy / Renovate config and release
   policy, images, publish-candidate, both NS8 install jobs (rocky9 and debian13),
   and publish-development-image. Missing, skipped, duplicate or unsuccessful
   required jobs fail closed; optional screenshots may be skipped. All paginated
   jobs must reconcile with the API total. This checks job outcomes, not invented
   test-case counts or a replacement for reviewing candidate acceptance logs.
3. Resolve the immutable module digest. Verify `CATALOG_VERSION` at the tested
   commit and the published image version/revision. **The first tested candidate
   is 0.2.0-rc.3, not rc.2**: the earlier hosting report's version was incorrect.
   The workflow reads the version and bouncer pin from that exact commit, requires
   module and engine revisions/source labels, immutable engine linkage and matching
   published SHA candidate digests. The tested SHA must be an ancestor of the
   trusted main checkout. No source code from that commit is executed.
4. Ensure repository Actions policy permits the job's GITHUB_TOKEN to write
   packages and releases. Only the owner/main promotion job has contents:write,
   packages:write and actions:read. Offline tests run with contents:read only.
   Secrets are supplied only through the step environment, registry login uses
   stdin and a temporary private authfile, and tool/API errors are never printed.

## First RC dispatch inputs

After review/merge, dispatch `prerelease.yml` on main with:

```text
candidate_run_id=45016982171
tested_sha=4d8c243478fc9bd3c04ca813a27b6d70123b0b6d
module_digest=sha256:de710c02de9215879b5bfa120f61e8b2901f2f7b0cfe5031cda12213da09ac71
version=0.2.0-rc.3
```

For an authorized operator (this command **publishes**):

```sh
gh workflow run prerelease.yml --repo Platypuschan/ns8-guardian --ref main \
  -f candidate_run_id=45016982171 \
  -f tested_sha=4d8c243478fc9bd3c04ca813a27b6d70123b0b6d \
  -f module_digest=sha256:de710c02de9215879b5bfa120f61e8b2901f2f7b0cfe5031cda12213da09ac71 \
  -f version=0.2.0-rc.3
```

The resulting targets are OCI `ghcr.io/platypuschan/guardian:0.2.0-rc.3`,
lightweight Git tag `v0.2.0-rc.3` pointing at the tested SHA, and a GitHub release
with `prerelease=true`, `draft=false`, `make_latest=false`. No stable/latest/dev
OCI tag or catalog entry is written. Copy uses `--all --preserve-digests` from
the immutable source; source and destination digests must remain identical.

## Retry and verification

Promotion is serialized across versions/reruns. Before any write, all existing
OCI/Git/release targets are checked; mismatches are refused, not overwritten or
silently repaired. Existing Git tags must directly point to the tested commit;
an annotated tag is deliberately refused rather than reinterpreted. Existing
releases must match the generated source/digest/run notes and RC flags exactly.
Only explicit manifest-not-found / HTTP 404 responses count as absent targets;
authentication, network and other failures are not interpreted as permission to
write. Retry **the same four inputs** after an interrupted copy, Git tag creation
or release request. An already copied matching OCI tag is not copied again, while
missing Git/release steps are independently recovered. Never delete conflicting
tags or weaken checks to make a retry pass.

The job reads back the exact destination digest, Git tag target, release metadata
and latest stable release endpoint before success. Independently inspect these
same targets after the run. GHCR has no atomic tag create-if-absent: concurrency
serializes this workflow, not unrelated external writers. Restrict other package
writers and do not manually modify version tags during promotion.

The CLI deliberately emits a fixed failure message without unsafe upstream error
text. Diagnose by read-only checks of the run, version, registry identities and
existing targets; do not enable shell tracing or print token-bearing exceptions.

## Installation and limitations

Install the digest, not a moving development tag:

```text
ghcr.io/platypuschan/guardian@sha256:de710c02de9215879b5bfa120f61e8b2901f2f7b0cfe5031cda12213da09ac71
```

**Existing installation first:** inventory the exact instance ID, backup,
allowlists, dependencies and previous digest. Use `cluster/update-module` with
`module_url` set to the digest reference and `instances` containing only the
verified existing module ID. `add-module` is **not** an update and creates another
instance. Do not repeat initial SSO preparation for an update.

Only when no instance exists and a fresh installation is authorized, use
`cluster/add-module` with that digest and an explicitly chosen node. Follow the
installed Core API schema, wait for action completion, and read back module
identity, health, allowlists and actual ban/unban behavior. Preserve the previous
digest and configuration for rollback. Host credentials and server selection are
separate from release promotion; do not paste credentials into release notes.

Known RC limits are carried in generated release notes: incomplete consumer ACK /
append-to-consume crash-window guarantees, outstanding real two-node NS8,
host-reboot and backup/restore acceptance, and limited application adapters. No
generic HTTP WAF or universal application-login coverage is claimed. Passing the
Debian13/Rocky9 single-node install smoke tests is not production approval.

## Offline regressions

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s qa -p 'test_prerelease*.py' -v
```

These execute the production orchestration and validation using stubs only at
subprocess and HTTP boundaries, with rejection cases and partial-publication
readbacks. They perform **no real registry or GitHub writes** and are not live
registry/NS8 acceptance. The dispatch workflow runs them before the write job;
the existing QA discovery also discovers them without modifying validate.yml.
