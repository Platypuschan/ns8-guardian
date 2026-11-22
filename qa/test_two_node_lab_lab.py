"""Offline regressions for the launcher's resource ownership, ordering and published outputs.

A recording fake replaces every local command (sudo/ip/qemu/podman/curl/ssh). No VM or NS8 is involved.
"""
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'tests' / 'lab'))

from twolab.cases import REQUIRED_CASES  # noqa: E402
from twolab.lab import Lab, PUBLIC_FILES  # noqa: E402

DIGEST = 'sha256:' + 'd' * 64
SHA = '4d8c243478fc9bd3c04ca813a27b6d70123b0b6d'
HEAD = 'ca47c9a964a551c44d131378d666516c55d86f55'
ENV = {'GITHUB_SHA': HEAD, 'GITHUB_REPOSITORY': 'Platypuschan/ns8-guardian', 'GITHUB_REF': 'refs/heads/main', 'GITHUB_RUN_ID': '9',
       'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_EVENT_NAME': 'workflow_dispatch', 'MODULE_DIGEST': DIGEST, 'EXPECTED_SOURCE_SHA': SHA,
       'EXPECTED_VERSION': '0.2.0-rc.3'}
GIB = 1024 ** 3
INSPECT = json.dumps({'Digest': DIGEST, 'Labels': {
    'org.opencontainers.image.revision': SHA, 'org.opencontainers.image.version': '0.2.0-rc.3',
    'org.nethserver.images': 'ghcr.io/platypuschan/guardian-engine@sha256:' + 'e' * 64 + ' ghcr.io/nethserver/crowdsec-firewall-bouncer:1.4.0@sha256:' + 'f' * 64}})
RID = 'a1b2c3d4'


class Recorder:
    def __init__(self, fail_on=None):
        self.calls = []
        self.fail_on = fail_on

    def __call__(self, argv, input=None, timeout=None):
        self.calls.append(list(argv))
        text = ' '.join(argv)
        if self.fail_on and self.fail_on in text:
            return 1, 'forced failure'
        if argv[0] == 'git' and 'rev-parse' in argv and argv[-1] == 'HEAD':
            return 0, HEAD + '\n'
        if argv[0] == 'git' and 'rev-parse' in argv:
            return 0, 'treehash\n'
        if argv[0] == 'git' and 'status' in argv:
            return 0, ''
        if argv[0] == 'ssh-keygen':
            Path(argv[-1] + '.pub').write_text('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGxhYi1zZWVk glab-test\n')
            return 0, ''
        if argv[0] == 'skopeo':
            return 0, INSPECT
        if argv[:3] == ['ip', '-4', 'route']:
            return 0, 'default via 10.1.0.1 dev eth0\n'
        return 0, ''

    def text(self):
        return [' '.join(c) for c in self.calls]


def host(**kw):
    base = dict(meminfo_text='MemAvailable: %d kB\n' % (14000 * 1024), disk_free_bytes=86 * GIB, cpus=4,
                kvm={'exists': True, 'readable': True, 'writable': True}, user='runner')
    base.update(kw)
    return base


def fetch(spec, dest):
    Path(dest).write_bytes(b'qcow2-bytes')
    import hashlib
    return hashlib.new(spec['algo'], b'qcow2-bytes').hexdigest()


def run_lab(tmp, recorder, hostinfo=None):
    lab = Lab(env=ENV, runner=recorder, hostinfo=hostinfo or host(), fetch_image=fetch, workbase=tmp + '/work',
              out_dir=tmp + '/out', run_id=RID, repo_root=str(ROOT), sleep=lambda s: None)
    code = lab.run()
    return code, json.loads(Path(tmp, 'out', 'public', 'result.json').read_text())


def cases(result):
    return {c['id']: c for c in result['cases']}


class Launcher(unittest.TestCase):
    def test_insufficient_capacity_fails_closed_before_any_privileged_or_vm_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            rec = Recorder()
            code, result = run_lab(tmp, rec, host(meminfo_text='MemAvailable: %d kB\n' % (4000 * 1024)))
            self.assertEqual(code, 1)
            self.assertEqual(result['overall'], 'fail')
            self.assertEqual(cases(result)['preflight_capacity_kvm']['status'], 'fail')
            joined = '\n'.join(rec.text())
            for forbidden in ('sudo ', 'qemu-system', 'podman run', 'cloud-localds'):
                self.assertNotIn(forbidden, joined)
            self.assertEqual(cases(result)['independent_clusters']['status'], 'not_run')

    def test_missing_kvm_is_a_failure_not_a_tcg_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            rec = Recorder()
            code, result = run_lab(tmp, rec, host(kvm={'exists': False, 'readable': False, 'writable': False}))
            self.assertEqual(code, 1)
            self.assertIn('kvm', cases(result)['preflight_capacity_kvm']['evidence']['error'])
            self.assertNotIn('qemu-system', '\n'.join(rec.text()))

    def test_unreadable_source_or_wrong_registry_digest_stops_the_run_with_a_result_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = dict(ENV, GITHUB_REF='refs/heads/feature')
            lab = Lab(env=bad, runner=Recorder(), hostinfo=host(), fetch_image=fetch, workbase=tmp + '/w', out_dir=tmp + '/o',
                      run_id=RID, repo_root=str(ROOT), sleep=lambda s: None)
            self.assertEqual(lab.run(), 1)
            result = json.loads(Path(tmp, 'o', 'public', 'result.json').read_text())
            self.assertEqual(result['overall'], 'fail')
            self.assertIn('source_error', result['environment'])

    def test_failure_after_resources_exist_still_cleans_only_owned_resources(self):
        with tempfile.TemporaryDirectory() as tmp:
            rec = Recorder(fail_on='qemu-system-x86_64')
            code, result = run_lab(tmp, rec)
            self.assertEqual(code, 1)
            text = rec.text()
            self.assertTrue(any('ip link del glA1B2C3D4b'.lower() in t for t in text) or any('ip link del gl%sb' % RID in t for t in text))
            self.assertTrue(any('iptables' in t and ' -D ' in t and 'glab-' + RID in t for t in text))
            for t in text:
                if ' del ' in t or ' -D ' in t or 'rm -' in t or 'pkill' in t or 'kill' in t:
                    self.assertIn(RID, t, t)
                    self.assertNotIn('docker0', t)
            self.assertEqual(cases(result)['owned_cleanup']['status'], 'pass')
            self.assertIn('qemu-system-x86_64', result['environment']['abort'])
            self.assertEqual(cases(result)['member_to_hub_sync_and_drop']['status'], 'not_run')
            self.assertEqual(result['overall'], 'fail')

    def test_cleanup_runs_even_when_a_cleanup_step_fails_and_that_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            class Failing(Recorder):
                def __call__(self, argv, input=None, timeout=None):
                    if argv[:4] == ['sudo', 'ip', 'link', 'del']:
                        self.calls.append(list(argv))
                        return 1, 'busy'
                    if argv == ['ip', '-o', 'link', 'show']:
                        return 0, '2: gl%sb: <BROADCAST> mtu 1500\n' % RID
                    return super().__call__(argv, input, timeout)
            rec = Failing(fail_on='qemu-system-x86_64')
            code, result = run_lab(tmp, rec)
            self.assertEqual(cases(result)['owned_cleanup']['status'], 'fail')
            self.assertEqual(code, 1)

    def test_public_directory_holds_only_the_explicit_safe_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_lab(tmp, Recorder(fail_on='qemu-system-x86_64'))
            names = {p.name for p in Path(tmp, 'out', 'public').iterdir()}
            self.assertLessEqual(names, set(PUBLIC_FILES))
            self.assertIn('result.json', names)
            self.assertIn('summary.md', names)
            self.assertIn('source-evidence.json', names)
            for p in Path(tmp, 'out', 'public').iterdir():
                text = p.read_text()
                for needle in ('PRIVATE KEY', 'Bearer ', 'csc2.', 'BEGIN '):
                    self.assertNotIn(needle, text, p.name)

    def test_private_work_directory_with_keys_and_raw_consoles_is_removed_after_the_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_lab(tmp, Recorder(fail_on='qemu-system-x86_64'))
            self.assertFalse(Path(tmp, 'work', 'gl-' + RID).exists())

    def test_the_summary_lists_every_required_case_explicitly(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_lab(tmp, Recorder(fail_on='qemu-system-x86_64'))
            text = Path(tmp, 'out', 'public', 'summary.md').read_text()
            for case in REQUIRED_CASES:
                self.assertIn(case, text)
            self.assertIn('not_run', text)
            self.assertIn('FAIL', text)

    def test_qemu_is_started_only_after_capacity_images_and_network_exist(self):
        with tempfile.TemporaryDirectory() as tmp:
            rec = Recorder(fail_on='qemu-system-x86_64')
            run_lab(tmp, rec)
            text = rec.text()
            first_qemu = next(i for i, t in enumerate(text) if t.startswith('qemu-system-x86_64'))
            first_bridge = next(i for i, t in enumerate(text) if 'type bridge' in t)
            first_seed = next(i for i, t in enumerate(text) if t.startswith('cloud-localds'))
            self.assertLess(first_bridge, first_qemu)
            self.assertLess(first_seed, first_qemu)
            self.assertNotIn('tcg', '\n'.join(text).lower())


    def test_disk_snapshot_commands_are_never_issued_unless_requested(self):
        with tempfile.TemporaryDirectory() as tmp:
            rec = Recorder(fail_on='qemu-system-x86_64')
            run_lab(tmp, rec)
            self.assertNotIn('snapshot', '\n'.join(rec.text()))

    def test_requested_disk_rollback_adds_a_required_case_that_cannot_be_green_when_never_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(ENV, DISK_ROLLBACK='true')
            lab = Lab(env=env, runner=Recorder(fail_on='qemu-system-x86_64'), hostinfo=host(), fetch_image=fetch, workbase=tmp + '/w',
                      out_dir=tmp + '/o', run_id=RID, repo_root=str(ROOT), sleep=lambda s: None)
            lab.run()
            result = json.loads(Path(tmp, 'o', 'public', 'result.json').read_text())
            disk = cases(result)['hub_disk_snapshot_rollback']
            self.assertTrue(disk['required'])
            self.assertEqual(disk['status'], 'not_run')
            self.assertEqual(result['overall'], 'fail')


class CrashRecovery(unittest.TestCase):
    def test_the_ledger_is_persisted_before_each_resource_is_used_so_a_killed_runner_can_be_cleaned(self):
        with tempfile.TemporaryDirectory() as tmp:
            seen = {}

            class Peek(Recorder):
                def __call__(self, argv, input=None, timeout=None):
                    if argv and argv[0] == 'qemu-system-x86_64':
                        seen['ledger'] = json.loads(Path(tmp, 'work', 'gl-' + RID, 'ledger.json').read_text())
                        return 1, 'stop here'
                    return super().__call__(argv, input, timeout)
            run_lab(tmp, Peek())
            kinds = {(k, n) for k, n in seen['ledger']}
            self.assertIn(('link', 'gl%sb' % RID), kinds)
            self.assertIn(('link', 'gl%sh' % RID), kinds)
            self.assertIn(('qemu', 'gl-%s-hub' % RID), kinds)


class Leftovers(unittest.TestCase):
    def test_a_surviving_qemu_process_of_this_run_fails_owned_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            class Survivor(Recorder):
                def __call__(self, argv, input=None, timeout=None):
                    if argv and argv[0] == 'pgrep':
                        self.calls.append(list(argv))
                        return 0, '4242 qemu-system-x86_64 -name gl-%s-hub -m 3072\n' % RID
                    return super().__call__(argv, input, timeout)
            code, result = run_lab(tmp, Survivor(fail_on='qemu-system-x86_64'))
            self.assertEqual(cases(result)['owned_cleanup']['status'], 'fail')
            self.assertIn('qemu', json.dumps(cases(result)['owned_cleanup']['evidence']))
