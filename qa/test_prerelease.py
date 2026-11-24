"""Offline promotion regressions; no registry/GitHub writes or live acceptance."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
from copy import deepcopy
import io
import json
import subprocess
from urllib.error import HTTPError

SCRIPT = Path(__file__).resolve().parents[1] / '.github/scripts/prerelease.py'


def load():
    spec = importlib.util.spec_from_file_location('prerelease', SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Inputs(unittest.TestCase):
    def test_only_canonical_rc_identity_is_accepted(self):
        self.assertTrue(SCRIPT.exists(), 'promotion implementation is missing')
        p = load()
        good = ('45016982171', 'a' * 40, 'sha256:' + 'b' * 64, '0.2.0-rc.2')
        p.validate_inputs(*good)
        for index, values in enumerate((['0', '-1', '1;echo x', '01'],
                                        ['main', 'A' * 40, 'a' * 39],
                                        ['guardian:dev', 'sha256:' + 'B' * 64],
                                        ['0.2.0', 'v0.2.0-rc.2', '0.2.0-beta.1',
                                         '0.2.0-rc.0', '0.2.0-rc.02', '00.2.0-rc.2',
                                         '0.2.0-rc.2\n'])):
            for value in values:
                with self.subTest(index=index, value=value):
                    args = list(good)
                    args[index] = value
                    with self.assertRaises(p.Rejected):
                        p.validate_inputs(*args)


SHA = 'a' * 40
REPO = 'Platypuschan/ns8-guardian'
GATES = ['tests', 'ui', 'policy / Renovate config and release policy', 'images',
         'publish-candidate', 'NS8 (rocky9) / install rocky9',
         'NS8 (debian13) / install debian13', 'publish-development-image']


def candidate_run():
    return dict(id=123, name='Validate Guardian', path='.github/workflows/validate.yml',
                head_sha=SHA, head_branch='main', event='push', status='completed',
                conclusion='success', repository={'full_name': REPO},
                head_repository={'full_name': REPO})


def candidate_jobs():
    return [dict(name=name, status='completed', conclusion='success') for name in GATES]


class RunGate(unittest.TestCase):
    def test_run_and_every_required_job_are_bound_to_candidate(self):
        p = load()
        p.validate_run(candidate_run(), candidate_jobs(), '123', SHA)
        for field, value in [('id', 124), ('name', 'Other'), ('path', 'other.yml'),
                             ('head_sha', 'b' * 40), ('head_branch', 'feature'),
                             ('event', 'workflow_dispatch'), ('event', 'pull_request'),
                             ('status', 'in_progress'), ('conclusion', 'failure'),
                             ('repository', {'full_name': 'other/repo'}),
                             ('head_repository', {'full_name': 'fork/repo'})]:
            run = candidate_run()
            run[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(p.Rejected):
                p.validate_run(run, candidate_jobs(), '123', SHA)
        for name in GATES:
            for mode in ['missing', 'skipped', 'failure', 'pending', 'duplicate']:
                jobs = candidate_jobs()
                index = GATES.index(name)
                if mode == 'missing':
                    del jobs[index]
                elif mode == 'duplicate':
                    jobs.append(jobs[index].copy())
                elif mode == 'pending':
                    jobs[index]['status'] = 'in_progress'
                else:
                    jobs[index]['conclusion'] = mode
                with self.subTest(name=name, mode=mode), self.assertRaises(p.Rejected):
                    p.validate_run(candidate_run(), jobs, '123', SHA)
        jobs = candidate_jobs() + [dict(name='NS8 (rocky9) / screenshots',
                                       status='completed', conclusion='skipped')]
        p.validate_run(candidate_run(), jobs, '123', SHA)


DIGEST = 'sha256:' + 'b' * 64
ENGINE_DIGEST = 'sha256:' + 'c' * 64
BOUNCER = ('ghcr.io/nethserver/crowdsec-firewall-bouncer:1.4.0@sha256:' + 'd' * 64)
VERSION = '0.2.0-rc.3'


class Boundaries:
    """Stub only subprocess and HTTP; execute the real gate/orchestration code."""
    def __init__(self, p):
        self.p = p
        self.commands = []
        self.requests = []
        self.source_version = VERSION + '\n'
        self.module = dict(Digest=DIGEST, Labels={
            'org.opencontainers.image.revision': SHA,
            'org.opencontainers.image.source': 'https://github.com/' + REPO,
            'org.opencontainers.image.version': VERSION,
            'org.nethserver.images': p.ENGINE + '@' + ENGINE_DIGEST + ' ' + BOUNCER})
        self.engine = dict(Digest=ENGINE_DIGEST, Labels={
            'org.opencontainers.image.revision': SHA,
            'org.opencontainers.image.source': 'https://github.com/' + REPO})
        self.images = {p.IMAGE + '@' + DIGEST: self.module,
                       p.IMAGE + ':sha-' + SHA[:12]: self.module,
                       p.ENGINE + '@' + ENGINE_DIGEST: self.engine,
                       p.ENGINE + ':sha-' + SHA[:12]: self.engine}
        self.run = candidate_run()
        self.jobs = candidate_jobs()
        self.git_ref = None
        self.release = None
        self.fail_release = False

    def command(self, args, **kwargs):
        self.commands.append(args)
        rc, out, err = 0, '', ''
        if args[:2] == ['git', 'merge-base']:
            pass
        elif args[:2] == ['git', 'show']:
            if args[2] == SHA + ':CATALOG_VERSION':
                out = self.source_version
            elif args[2] == SHA + ':build-images.sh':
                out = 'bouncer_image="${CROWDSEC_FIREWALL_BOUNCER_IMAGE:-' + BOUNCER + '}"'
            else:
                raise AssertionError(args)
        elif args[:2] == ['skopeo', 'inspect']:
            ref = args[-1].removeprefix('docker://')
            if ref in self.images:
                out = json.dumps(self.images[ref])
            else:
                rc, err = 1, 'manifest unknown'
        elif args[:2] == ['skopeo', 'login']:
            assert kwargs['input'] == 'secret-token'
        elif args[:2] == ['skopeo', 'copy']:
            assert '--preserve-digests' in args and '--all' in args
            self.images[args[-1].removeprefix('docker://')] = deepcopy(
                self.images[args[-2].removeprefix('docker://')])
        else:
            raise AssertionError(args)
        return subprocess.CompletedProcess(args, rc, out, err)

    def http(self, request, **kwargs):
        path = request.full_url.removeprefix('https://api.github.com/repos/' + REPO)
        method = request.get_method()
        payload = json.loads(request.data) if request.data else None
        self.requests.append((method, path, payload))
        assert request.get_header('Authorization') == 'Bearer secret-token'
        if path == '/actions/runs/123':
            result = self.run
        elif path.startswith('/actions/runs/123/jobs?'):
            result = dict(total_count=len(self.jobs), jobs=self.jobs)
        elif path == '/git/ref/tags/v' + VERSION:
            result = self.git_ref
        elif path == '/git/refs' and method == 'POST':
            self.git_ref = dict(object=dict(type='commit', sha=payload['sha']))
            result = self.git_ref
        elif path == '/releases/latest':
            result = None  # no stable release in the offline fixture
        elif path == '/releases/tags/v' + VERSION:
            result = self.release
        elif path == '/releases' and method == 'POST':
            if self.fail_release:
                raise HTTPError(request.full_url, 503, 'secret request failure', {}, None)
            self.release = dict(payload, id=42)
            result = self.release
        else:
            raise AssertionError((method, path, payload))
        if result is None:
            raise HTTPError(request.full_url, 404, 'secret not found', {}, None)
        return io.BytesIO(json.dumps(result).encode())

    def context(self):
        from contextlib import ExitStack
        stack = ExitStack()
        stack.enter_context(patch.object(self.p.subprocess, 'run', self.command))
        stack.enter_context(patch.object(self.p, 'urlopen', self.http))
        stack.enter_context(patch.dict(self.p.os.environ, {'GH_TOKEN': 'secret-token',
            'GITHUB_REPOSITORY': REPO, 'GITHUB_REF': 'refs/heads/main',
            'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_ACTOR': 'operator'}))
        return stack


class Provenance(unittest.TestCase):
    def test_immutable_source_module_and_runtime_provenance(self):
        p = load()
        self.assertTrue(hasattr(p, 'preflight'), 'provenance orchestration is missing')
        b = Boundaries(p)
        with b.context():
            p.preflight('123', SHA, DIGEST, VERSION)
        cases = ['source_version', 'version', 'revision', 'source', 'engine_revision',
                 'engine_source', 'engine_tag_digest', 'module_tag_digest',
                 'mutable_runtime', 'wrong_runtime', 'wrong_bouncer', 'extra_runtime']
        for case in cases:
            b = Boundaries(p)
            labels = b.module['Labels']
            if case == 'source_version':
                b.source_version = '0.2.0-rc.2\n'
            elif case in ('version', 'revision', 'source'):
                labels['org.opencontainers.image.' + case] = 'wrong'
            elif case.startswith('engine_') and case != 'engine_tag_digest':
                b.engine['Labels']['org.opencontainers.image.' + case[7:]] = 'wrong'
            elif case in ('engine_tag_digest', 'module_tag_digest'):
                image = p.ENGINE if case.startswith('engine') else p.IMAGE
                b.images[image + ':sha-' + SHA[:12]] = dict(Digest='sha256:' + 'e' * 64)
            elif case == 'mutable_runtime':
                labels['org.nethserver.images'] = p.ENGINE + ':dev ' + BOUNCER
            elif case == 'wrong_runtime':
                labels['org.nethserver.images'] = 'evil.example/engine@' + ENGINE_DIGEST + ' ' + BOUNCER
            elif case == 'wrong_bouncer':
                labels['org.nethserver.images'] = p.ENGINE + '@' + ENGINE_DIGEST + ' ' + BOUNCER.replace('d' * 64, 'e' * 64)
            elif case == 'extra_runtime':
                labels['org.nethserver.images'] += ' evil.example/extra:latest'
            with b.context(), self.subTest(case=case), self.assertRaises(p.Rejected):
                p.preflight('123', SHA, DIGEST, VERSION)
            self.assertFalse(any(args[:2] in (['skopeo', 'copy'], ['skopeo', 'login'])
                                 for args in b.commands))
            self.assertFalse(any(method == 'POST' for method, _, _ in b.requests))


class Publication(unittest.TestCase):
    def test_same_digest_retry_recovers_release_failure_without_overwriting(self):
        p = load()
        self.assertTrue(hasattr(p, 'promote'), 'publication orchestration is missing')
        b = Boundaries(p)
        b.fail_release = True
        with b.context(), self.assertRaises(p.Rejected):
            p.promote('123', SHA, DIGEST, VERSION)
        self.assertEqual(b.images[p.IMAGE + ':' + VERSION]['Digest'], DIGEST)
        self.assertEqual(b.git_ref['object']['sha'], SHA)
        b.fail_release = False
        with b.context():
            p.promote('123', SHA, DIGEST, VERSION)
            p.promote('123', SHA, DIGEST, VERSION)
        copies = [args for args in b.commands if args[:2] == ['skopeo', 'copy']]
        self.assertEqual(len(copies), 1)
        self.assertEqual(copies[0][-2:], ['docker://' + p.IMAGE + '@' + DIGEST,
                                        'docker://' + p.IMAGE + ':' + VERSION])
        self.assertEqual(sum(method == 'POST' and path == '/git/refs'
                             for method, path, _ in b.requests), 1)
        releases = [body for method, path, body in b.requests
                    if method == 'POST' and path == '/releases']
        self.assertEqual(len(releases), 2)  # one failed request, then successful recovery
        self.assertEqual(releases[-1]['make_latest'], 'false')
        self.assertTrue(releases[-1]['prerelease'])
        self.assertFalse(releases[-1]['draft'])
        self.assertEqual(releases[-1]['tag_name'], 'v' + VERSION)
        for text in [SHA, DIGEST, 'update-module', 'add-module', 'ACK', 'WAF']:
            self.assertIn(text, releases[-1]['body'])
        self.assertEqual(b.requests[-1][:2], ('GET', '/releases/latest'))

    def test_existing_conflicting_oci_git_or_release_is_never_overwritten(self):
        p = load()
        for case in ['oci', 'git', 'release_version', 'release_body', 'stable_release', 'draft']:
            b = Boundaries(p)
            if case == 'oci':
                b.images[p.IMAGE + ':' + VERSION] = dict(Digest='sha256:' + 'f' * 64)
            elif case == 'git':
                b.git_ref = dict(object=dict(type='commit', sha='f' * 40))
            else:
                b.release = dict(tag_name='v' + VERSION, target_commitish=SHA,
                    name='Guardian ' + VERSION, body=p.release_notes('123', SHA, DIGEST, VERSION),
                    prerelease=True, draft=False)
                if case == 'release_version':
                    b.release['target_commitish'] = 'f' * 40
                elif case == 'release_body':
                    b.release['body'] = 'unrelated release'
                elif case == 'stable_release':
                    b.release['prerelease'] = False
                elif case == 'draft':
                    b.release['draft'] = True
            with b.context(), self.subTest(case=case), self.assertRaises(p.Rejected):
                p.promote('123', SHA, DIGEST, VERSION)
            self.assertFalse(any(method == 'POST' for method, _, _ in b.requests))
            self.assertFalse(any(args[:2] == ['skopeo', 'copy'] for args in b.commands))

    def test_readback_detects_wrong_copy_and_wrong_git_creation(self):
        p = load()
        for case in ['copy', 'git']:
            b = Boundaries(p)
            original_command, original_http = b.command, b.http
            def wrong_copy(args, **kwargs):
                result = original_command(args, **kwargs)
                if args[:2] == ['skopeo', 'copy']:
                    b.images[p.IMAGE + ':' + VERSION] = dict(Digest='sha256:' + 'f' * 64)
                return result
            def wrong_git(request, **kwargs):
                result = original_http(request, **kwargs)
                if request.get_method() == 'POST' and request.full_url.endswith('/git/refs'):
                    b.git_ref = dict(object=dict(type='commit', sha='f' * 40))
                return result
            if case == 'copy':
                b.command = wrong_copy
            else:
                b.http = wrong_git
            with b.context(), self.subTest(case=case), self.assertRaises(p.Rejected):
                p.promote('123', SHA, DIGEST, VERSION)
            self.assertIsNone(b.release)


class Robustness(unittest.TestCase):
    def test_copy_reported_failure_can_retry_same_digest_without_second_copy(self):
        p = load()
        b = Boundaries(p)
        original = b.command
        def interrupted_copy(args, **kwargs):
            result = original(args, **kwargs)
            if args[:2] == ['skopeo', 'copy']:
                result.returncode = 1
                result.stderr = 'secret-token interrupted request'
            return result
        b.command = interrupted_copy
        with b.context(), self.assertRaises(p.Rejected):
            p.promote('123', SHA, DIGEST, VERSION)
        self.assertIsNone(b.git_ref)
        b.command = original
        with b.context():
            p.promote('123', SHA, DIGEST, VERSION)
        self.assertEqual(sum(args[:2] == ['skopeo', 'copy'] for args in b.commands), 1)

    def test_job_pagination_and_incomplete_counts_fail_closed(self):
        p = load()
        for incomplete in [False, True]:
            b = Boundaries(p)
            b.jobs = [dict(name='optional-' + str(i), status='completed', conclusion='success')
                      for i in range(100)] + candidate_jobs()
            original = b.http
            def paginated(request, **kwargs):
                if '/jobs?' not in request.full_url:
                    return original(request, **kwargs)
                b.requests.append(('GET', request.full_url, None))
                second = request.full_url.endswith('page=2')
                jobs = b.jobs[100:] if second else b.jobs[:100]
                if incomplete and second:
                    jobs = []
                return io.BytesIO(json.dumps(dict(total_count=len(b.jobs), jobs=jobs)).encode())
            b.http = paginated
            with b.context():
                if incomplete:
                    with self.assertRaises(p.Rejected):
                        p.preflight('123', SHA, DIGEST, VERSION)
                else:
                    p.preflight('123', SHA, DIGEST, VERSION)
            self.assertTrue(any('page=2' in path for _, path, _ in b.requests))

    def test_only_manifest_unknown_and_http_404_are_absence(self):
        p = load()
        b = Boundaries(p)
        with b.context():
            with patch.object(p.subprocess, 'run', return_value=subprocess.CompletedProcess(
                    ['skopeo'], 1, '', 'secret-token unauthorized')):
                with self.assertRaises(p.Rejected):
                    p.inspect(p.IMAGE + ':' + VERSION, optional=True)
            for code in [401, 403, 429, 500]:
                with patch.object(p, 'urlopen', side_effect=HTTPError(
                        'https://secret-token', code, 'secret-token request', {}, None)):
                    with self.assertRaises(p.Rejected) as error:
                        p.api('/releases/tags/v' + VERSION, optional=True)
                    self.assertNotIn('secret-token', str(error.exception))


class Entrypoint(unittest.TestCase):
    def test_cli_suppresses_secret_bearing_tool_and_http_errors(self):
        p = load()
        self.assertTrue(hasattr(p, 'main'), 'safe CLI entrypoint is missing')
        for failure in [subprocess.TimeoutExpired(['tool', 'secret-token'], 1),
                        OSError('secret-token request URL'),
                        HTTPError('https://secret-token', 500, 'secret-token', {}, None)]:
            b = Boundaries(p)
            with b.context(), patch.object(p.subprocess, 'run', side_effect=failure), \
                    patch.dict(p.os.environ, dict(CANDIDATE_RUN_ID='123', TESTED_SHA=SHA,
                                                 MODULE_DIGEST=DIGEST, VERSION=VERSION)), \
                    patch('sys.stdout', new_callable=io.StringIO) as out, \
                    patch('sys.stderr', new_callable=io.StringIO) as err:
                self.assertEqual(p.main(), 1)
                self.assertNotIn('secret-token', out.getvalue() + err.getvalue())
                self.assertIn('failed', err.getvalue())

    def test_cli_rejects_untrusted_context_before_any_tool_or_api(self):
        p = load()
        for key, value in [('GITHUB_REPOSITORY', 'fork/guardian'),
                           ('GITHUB_REF', 'refs/heads/feature'),
                           ('GITHUB_EVENT_NAME', 'push')]:
            b = Boundaries(p)
            with b.context(), patch.dict(p.os.environ, {key: value}), self.assertRaises(p.Rejected):
                p.promote('123', SHA, DIGEST, VERSION)
            self.assertEqual(b.commands, [])
            self.assertEqual(b.requests, [])


class Workflow(unittest.TestCase):
    def test_dispatch_is_main_owner_only_serialized_and_uses_exact_trusted_checkout(self):
        workflow = SCRIPT.parents[1] / 'workflows/prerelease.yml'
        self.assertTrue(workflow.exists(), 'manually dispatched workflow is missing')
        text = workflow.read_text()
        for expected in ["workflow_dispatch:", 'candidate_run_id:', 'tested_sha:',
                         'module_digest:', 'version:', 'group: guardian-prerelease-promotion',
                         'cancel-in-progress: false',
                         "github.repository == 'Platypuschan/ns8-guardian'",
                         "github.ref == 'refs/heads/main'",
                         "github.event_name == 'workflow_dispatch'",
                         'repository: Platypuschan/ns8-guardian', 'ref: ${{ github.sha }}',
                         'persist-credentials: false', 'fetch-depth: 0',
                         'GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}',
                         'CANDIDATE_RUN_ID: ${{ inputs.candidate_run_id }}',
                         'TESTED_SHA: ${{ inputs.tested_sha }}',
                         'MODULE_DIGEST: ${{ inputs.module_digest }}',
                         'VERSION: ${{ inputs.version }}',
                         'python3 .github/scripts/prerelease.py']:
            self.assertIn(expected, text)
        self.assertEqual(text.count('contents: write'), 1)
        self.assertEqual(text.count('packages: write'), 1)
        self.assertNotIn('${{ inputs.', text.split('run: python3')[0].split('steps:')[0])
        self.assertNotIn('pull_request:', text)
        self.assertNotIn('push:', text)


if __name__ == '__main__':
    unittest.main()


class ReleaseNotesLimits(unittest.TestCase):
    """rc.3 notes must stay byte-identical (idempotent retry of the published release); later RCs state the current limits."""
    def test_rc3_notes_keep_the_original_limitations(self):
        body = load().release_notes('1', SHA, DIGEST, '0.2.0-rc.3')
        self.assertIn('Consumer ACK/replay and append/consume crash-window guarantees remain incomplete.', body)

    def test_later_rcs_describe_ack_replay_and_what_remains_open(self):
        body = load().release_notes('1', SHA, DIGEST, '0.2.0-rc.7')
        self.assertNotIn('remain incomplete', body)
        for text in ('engine-generation', 'at-least-once', 'not exactly-once', 'two-node', 'no WAF/AppSec', 'community blocklist', 'update-module', 'add-module', 'ACK', 'WAF'):
            self.assertIn(text, body)
        self.assertNotIn('Two-node NS8, host reboot, backup/restore and application-adapter acceptance remain', body)
        self.assertIn(DIGEST, body)

    def test_notes_are_deterministic(self):
        p = load()
        self.assertEqual(p.release_notes('1', SHA, DIGEST, '0.2.0-rc.7'), p.release_notes('1', SHA, DIGEST, '0.2.0-rc.7'))
