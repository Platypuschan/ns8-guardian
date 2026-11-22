#!/usr/bin/env python3
"""Promote an already tested Guardian digest; never build or relabel images."""
import re
import json
import os
import subprocess
import tempfile
import sys
from urllib.request import Request, urlopen
from urllib.error import HTTPError


class Rejected(Exception):
    """Fail closed with a fixed, credential-free diagnostic."""


def require(condition, message):
    if not condition:
        raise Rejected(message)


REPO = 'Platypuschan/ns8-guardian'
IMAGE = 'ghcr.io/platypuschan/guardian'
ENGINE = 'ghcr.io/platypuschan/guardian-engine'
REQUIRED_JOBS = {
    'tests', 'ui', 'policy / Renovate config and release policy', 'images',
    'publish-candidate', 'NS8 (rocky9) / install rocky9',
    'NS8 (debian13) / install debian13', 'publish-development-image',
}


def validate_run(run, jobs, run_id, sha):
    expected = dict(id=int(run_id), name='Validate Guardian',
                    path='.github/workflows/validate.yml', head_sha=sha,
                    head_branch='main', event='push', status='completed',
                    conclusion='success')
    require(all(run.get(key) == value for key, value in expected.items()),
            'Candidate validation run identity or result mismatch')
    require(all(run.get(key, {}).get('full_name') == REPO
                for key in ('repository', 'head_repository')),
            'Candidate validation repository mismatch')
    for name in REQUIRED_JOBS:
        matches = [job for job in jobs if job.get('name') == name]
        require(len(matches) == 1 and matches[0].get('status') == 'completed'
                and matches[0].get('conclusion') == 'success',
                'Required candidate job missing, ambiguous or unsuccessful')


def command(args, **kwargs):
    result = subprocess.run(args, text=True, capture_output=True, timeout=300, **kwargs)
    require(result.returncode == 0, 'External tool failed (details suppressed)')
    return result.stdout


def api(path, payload=None, optional=False):
    request = Request('https://api.github.com/repos/' + REPO + path,
                      data=json.dumps(payload).encode() if payload is not None else None,
                      headers={'Authorization': 'Bearer ' + os.environ['GH_TOKEN'],
                               'Accept': 'application/vnd.github+json',
                               'X-GitHub-Api-Version': '2022-11-28',
                               'Content-Type': 'application/json'},
                      method='POST' if payload is not None else 'GET')
    try:
        with urlopen(request, timeout=60) as response:
            return json.load(response)
    except HTTPError as error:
        if optional and error.code == 404:
            return None
        raise Rejected('GitHub API request failed (details suppressed)') from None


def inspect(ref, optional=False):
    result = subprocess.run(['skopeo', 'inspect', 'docker://' + ref],
                            text=True, capture_output=True, timeout=120)
    if optional and result.returncode and 'manifest unknown' in result.stderr.lower():
        return None
    require(result.returncode == 0, 'Registry inspection failed (details suppressed)')
    return json.loads(result.stdout)


def preflight(run_id, sha, digest, version):
    validate_inputs(run_id, sha, digest, version)
    require(os.environ.get('GITHUB_REPOSITORY') == REPO
            and os.environ.get('GITHUB_REF') == 'refs/heads/main'
            and os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch',
            'Promotion must run manually in the owner repository on main')
    command(['git', 'merge-base', '--is-ancestor', sha, 'HEAD'])
    require(command(['git', 'show', sha + ':CATALOG_VERSION']).strip() == version,
            'Version differs from tested source CATALOG_VERSION')
    run = api('/actions/runs/' + run_id)
    jobs = []
    page = 1
    while True:
        batch = api(f'/actions/runs/{run_id}/jobs?filter=latest&per_page=100&page={page}')
        jobs.extend(batch['jobs'])
        require(len(jobs) <= batch['total_count'], 'Candidate job count mismatch')
        if len(jobs) == batch['total_count']:
            break
        require(batch['jobs'], 'Candidate jobs pagination incomplete')
        page += 1
    validate_run(run, jobs, run_id, sha)
    module = inspect(IMAGE + '@' + digest)
    require(module.get('Digest') == digest, 'Immutable module digest mismatch')
    labels = module.get('Labels', {})
    for key, value in [('revision', sha), ('version', version),
                       ('source', 'https://github.com/' + REPO)]:
        require(labels.get('org.opencontainers.image.' + key) == value,
                'Immutable module provenance mismatch')
    require(inspect(IMAGE + ':sha-' + sha[:12]).get('Digest') == digest,
            'Module differs from published SHA candidate')
    runtimes = labels.get('org.nethserver.images', '').split()
    require(len(runtimes) == 2 and re.fullmatch(
        re.escape(ENGINE) + r'@sha256:[a-f0-9]{64}', runtimes[0]),
        'Module runtime linkage is not pinned to Guardian engine')
    recipe = command(['git', 'show', sha + ':build-images.sh'])
    bouncer = re.search(r'bouncer_image="\$\{CROWDSEC_FIREWALL_BOUNCER_IMAGE:-'
                        r'(ghcr\.io/nethserver/crowdsec-firewall-bouncer:'
                        r'[0-9.]+@sha256:[a-f0-9]{64})\}"', recipe)
    require(bouncer and runtimes[1] == bouncer[1], 'Bouncer differs from tested source pin')
    engine_digest = runtimes[0].split('@')[1]
    engine = inspect(runtimes[0])
    require(engine.get('Digest') == engine_digest
            and engine.get('Labels', {}).get('org.opencontainers.image.revision') == sha
            and engine.get('Labels', {}).get('org.opencontainers.image.source') == 'https://github.com/' + REPO,
            'Immutable runtime provenance mismatch')
    require(inspect(ENGINE + ':sha-' + sha[:12]).get('Digest') == engine_digest,
            'Runtime differs from published SHA candidate')


LEGACY_LIMITS = '''Consumer ACK/replay and append/consume crash-window guarantees remain incomplete.
Two-node NS8, host reboot, backup/restore and application-adapter acceptance remain
open. No generic HTTP WAF or blanket application-login coverage is claimed.
Single-node Debian 13 and Rocky 9 install smoke tests are not production approval.'''

CURRENT_LIMITS = '''Consumer ACK: events are acknowledged per engine-generation (read offset of the same
engine process plus a settle time); after an engine restart unacknowledged and recently
acknowledged events are replayed, except for addresses unbanned since. This is
at-least-once for events younger than the replay window (120 s), not exactly-once;
a restored database never replays. Evidence: the hosted two-node NS8 lab (reboots,
backup/restore, engine restart replay, private-CA enrollment) for the exact digest above.
Remaining limits: application adapters are accepted per application; two generic HTTP
scanner rules exist but this is not a WAF and not universal application-login coverage;
no multi-day soak and no upgrade-path acceptance from earlier RCs are claimed.
This prerelease is not production approval.'''


def release_notes(run_id, sha, digest, version):
    module = IMAGE + '@' + digest
    limits = LEGACY_LIMITS if version == '0.2.0-rc.3' else CURRENT_LIMITS
    return f'''# Guardian {version} — prerelease, not production approval

Source SHA: `{sha}`
Immutable module: `{module}`
Validation: https://github.com/{REPO}/actions/runs/{run_id}
The same tested manifest is promoted without rebuild or relabeling.

## Known limitations
{limits}

## Install by digest
Inventory existing modules, backups, allowlists and rollback before changing a host.
For an EXISTING instance, use cluster/update-module with module_url `{module}`
and an explicit instances list containing only its verified module ID. Do not use
add-module to upgrade: it creates a second instance. Do not rerun initial SSO setup.
Only for a verified FRESH install use cluster/add-module with module_url `{module}`
and the explicitly chosen node. Wait for the task and read back installed identity,
health, allowlists and ban/unban behavior. Retain the previous digest for rollback.

No stable/latest OCI tags or catalog entry are published by this prerelease.
'''


def check_tag(ref, sha):
    require(ref.get('object', {}).get('type') == 'commit'
            and ref['object'].get('sha') == sha,
            'Existing Git tag does not point directly to tested commit')


def check_release(release, expected):
    require(all(release.get(key) == value for key, value in expected.items()
                if key != 'make_latest'), 'Existing release conflicts with prerelease identity')


def promote(run_id, sha, digest, version):
    preflight(run_id, sha, digest, version)
    target = IMAGE + ':' + version
    tag_path = '/git/ref/tags/v' + version
    release_path = '/releases/tags/v' + version
    expected = dict(tag_name='v' + version, target_commitish=sha,
                    name='Guardian ' + version,
                    body=release_notes(run_id, sha, digest, version),
                    draft=False, prerelease=True, make_latest='false')
    # Inspect ALL existing targets before the first write; never repair conflicts.
    existing = inspect(target, optional=True)
    require(existing is None or existing.get('Digest') == digest,
            'Existing OCI version tag has a different digest')
    ref = api(tag_path, optional=True)
    if ref is not None:
        check_tag(ref, sha)
    release = api(release_path, optional=True)
    if release is not None:
        check_release(release, expected)
    if existing is None:
        with tempfile.TemporaryDirectory(prefix='guardian-auth-') as private:
            authfile = private + '/auth.json'
            command(['skopeo', 'login', '--authfile', authfile,
                     '--username', os.environ['GITHUB_ACTOR'], '--password-stdin', 'ghcr.io'],
                    input=os.environ['GH_TOKEN'])
            # Serialize our writers, recheck after login, preserve the exact manifest.
            existing = inspect(target, optional=True)
            require(existing is None or existing.get('Digest') == digest,
                    'OCI version tag changed during promotion')
            if existing is None:
                command(['skopeo', 'copy', '--all', '--preserve-digests',
                         '--authfile', authfile, 'docker://' + IMAGE + '@' + digest,
                         'docker://' + target])
    require(inspect(target).get('Digest') == digest, 'Promoted OCI digest mismatch')
    if ref is None:
        api('/git/refs', dict(ref='refs/tags/v' + version, sha=sha))
    check_tag(api(tag_path), sha)
    if release is None:
        api('/releases', expected)
    # Read back exact targets; reruns independently recover partial publication.
    check_release(api(release_path), expected)
    check_tag(api(tag_path), sha)
    require(inspect(target).get('Digest') == digest, 'Final OCI digest mismatch')
    latest = api('/releases/latest', optional=True)
    require(latest is None or latest.get('tag_name') != 'v' + version,
            'Prerelease must not be the latest stable release')


def validate_inputs(run_id, sha, digest, version):
    number = r'(?:0|[1-9][0-9]*)'
    for value, pattern in (
        (run_id, r'[1-9][0-9]*'),
        (sha, r'[a-f0-9]{40}'),
        (digest, r'sha256:[a-f0-9]{64}'),
        (version, rf'{number}\.{number}\.{number}-rc\.[1-9][0-9]*'),
    ):
        require(re.fullmatch(pattern, value), 'Invalid prerelease input')


def main():
    try:
        promote(*(os.environ[key] for key in
                  ('CANDIDATE_RUN_ID', 'TESTED_SHA', 'MODULE_DIGEST', 'VERSION')))
    except Exception:
        # Never format upstream exceptions, requests, tool stderr, or credentials.
        print('Guardian prerelease failed; unsafe details suppressed.', file=sys.stderr)
        return 1
    print('Guardian prerelease verified: OCI digest, Git tag and GitHub prerelease.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
