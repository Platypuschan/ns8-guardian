"""Offline regressions: log sanitizer and the acceptance report (no false passes)."""
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'tests' / 'lab'))

from twolab.cases import REQUIRED_CASES, OPTIONAL_CASES, Report, ReportError  # noqa: E402
from twolab.sanitize import Sanitizer, UnsafeEvidence  # noqa: E402

NATIVE = {'restore_method': 'ns8-restore-module', 'restore_exit_code': 0}
PEM = '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkq\n-----END PRIVATE KEY-----'


class Sanitizing(unittest.TestCase):
    def test_bearer_credentials_and_sync_tokens_are_redacted(self):
        text = 'curl -H "Authorization: Bearer abc.def-123" and csc2.eyJwZWVyIjoiYSJ9 end'
        out = Sanitizer().clean(text)
        self.assertNotIn('abc.def-123', out)
        self.assertNotIn('csc2.eyJ', out)
        self.assertIn('[REDACTED]', out)

    def test_private_keys_are_removed_whole(self):
        out = Sanitizer().clean('before\n' + PEM + '\nafter')
        self.assertNotIn('MIIEvQ', out)
        self.assertIn('before', out)
        self.assertIn('after', out)

    def test_key_value_secrets_json_secrets_and_redis_urls_are_redacted(self):
        for raw, leak in (('password=hunter2 next', 'hunter2'), ('"secret": "s3cr3t-value"', 's3cr3t-value'),
                          ('sync_secret: zzTOP', 'zzTOP'), ('redis://:r3dis-pw@127.0.0.1:6379/0', 'r3dis-pw'),
                          ('AWS_SECRET_ACCESS_KEY=abcd1234', 'abcd1234'), ('RCLONE_CONFIG_PASS=xx9', 'xx9'),
                          ('token = tok123', 'tok123'), ('"api_key":"k-1"', 'k-1')):
            self.assertNotIn(leak, Sanitizer().clean(raw), raw)

    def test_known_runtime_secrets_are_removed_wherever_they_appear(self):
        s = Sanitizer()
        s.register('Zx9-unrecognisable-secret')
        self.assertNotIn('Zx9-unrecognisable-secret', s.clean('line a\nxx Zx9-unrecognisable-secret yy'))

    def test_short_or_empty_secrets_are_not_registered_to_avoid_mangling_logs(self):
        s = Sanitizer()
        s.register('')
        s.register('ab')
        self.assertEqual(s.clean('absolute ab'), 'absolute ab')

    def test_synthetic_ips_ttl_and_ordinary_log_lines_survive(self):
        line = 'decision 198.51.100.21 until 2026-11-22T13:00:00Z origin crowdsec'
        self.assertEqual(Sanitizer().clean(line), line)

    def test_evidence_with_secret_bearing_keys_is_rejected_not_silently_stripped(self):
        for key in ('token', 'sync_secret', 'password', 'authorization', 'private_key', 'bearer'):
            with self.assertRaises(UnsafeEvidence, msg=key):
                Sanitizer().evidence({key: 'x'})
        with self.assertRaises(UnsafeEvidence):
            Sanitizer().evidence({'nested': {'bouncer_key': 'x'}})
        self.assertEqual(Sanitizer().evidence({'ip': '198.51.100.21'}), {'ip': '198.51.100.21'})

    def test_evidence_string_values_are_cleaned(self):
        out = Sanitizer().evidence({'note': 'Authorization: Bearer topsecret'})
        self.assertNotIn('topsecret', json.dumps(out))


def full_report(skip=()):
    r = Report(run_id='a1b2c3d4', source={'sha': 'c' * 40}, module={'digest': 'sha256:' + 'b' * 64})
    for case in REQUIRED_CASES:
        if case not in skip:
            r.record(case, 'pass', NATIVE if case == 'native_ns8_backup_restore' else {'ok': True})
    return r


class Reporting(unittest.TestCase):
    def test_all_required_cases_passing_gives_overall_pass(self):
        result = full_report().finish()
        self.assertEqual(result['overall'], 'pass')
        self.assertEqual({c['id'] for c in result['cases']} >= set(REQUIRED_CASES), True)

    def test_a_required_case_never_run_makes_the_run_fail_explicitly(self):
        r = full_report(skip=(REQUIRED_CASES[-1],))
        result = r.finish()
        self.assertEqual(result['overall'], 'fail')
        missing = [c for c in result['cases'] if c['id'] == REQUIRED_CASES[-1]][0]
        self.assertEqual(missing['status'], 'not_run')

    def test_skipped_is_not_an_accepted_status_for_any_case(self):
        r = Report(run_id='a1b2c3d4', source={}, module={})
        with self.assertRaises(ReportError):
            r.record(REQUIRED_CASES[0], 'skipped', {})

    def test_one_failure_fails_the_run_and_keeps_the_reason(self):
        r = full_report(skip=('hub_guest_reboot',))
        r.record('hub_guest_reboot', 'fail', {'reason': 'boot id unchanged'})
        result = r.finish()
        self.assertEqual(result['overall'], 'fail')
        self.assertEqual([c for c in result['cases'] if c['id'] == 'hub_guest_reboot'][0]['status'], 'fail')

    def test_unknown_case_ids_and_duplicate_results_are_rejected(self):
        r = Report(run_id='a1b2c3d4', source={}, module={})
        with self.assertRaises(ReportError):
            r.record('made_up_case', 'pass', {})
        r.record(REQUIRED_CASES[0], 'pass', {})
        with self.assertRaises(ReportError):
            r.record(REQUIRED_CASES[0], 'pass', {})

    def test_optional_disk_rollback_is_reported_not_run_and_does_not_block_green(self):
        result = full_report().finish()
        disk = [c for c in result['cases'] if c['id'] == 'hub_disk_snapshot_rollback'][0]
        self.assertEqual(disk['status'], 'not_run')
        self.assertFalse(disk['required'])
        self.assertEqual(result['overall'], 'pass')
        self.assertIn('hub_disk_snapshot_rollback', OPTIONAL_CASES)

    def test_requested_disk_rollback_becomes_required(self):
        r = Report(run_id='a1b2c3d4', source={}, module={}, disk_rollback=True)
        for case in REQUIRED_CASES:
            r.record(case, 'pass', NATIVE if case == 'native_ns8_backup_restore' else {})
        self.assertEqual(r.finish()['overall'], 'fail')

    def test_native_restore_cannot_pass_on_disk_snapshot_evidence(self):
        r = Report(run_id='a1b2c3d4', source={}, module={})
        with self.assertRaisesRegex(ReportError, 'native'):
            r.record('native_ns8_backup_restore', 'pass', {'restore_method': 'qemu-disk-snapshot'})
        r.record('native_ns8_backup_restore', 'pass', {'restore_method': 'ns8-restore-module', 'restore_exit_code': 0})

    def test_disk_rollback_cannot_be_labelled_native_restore(self):
        r = Report(run_id='a1b2c3d4', source={}, module={}, disk_rollback=True)
        with self.assertRaisesRegex(ReportError, 'disk'):
            r.record('hub_disk_snapshot_rollback', 'pass', {'restore_method': 'ns8-restore-module'})

    def test_report_json_is_sanitized_and_marks_mocks_never_real(self):
        r = full_report()
        data = r.finish(real_ns8=True)
        self.assertTrue(data['real_ns8'])
        text = json.dumps(data)
        self.assertNotIn('Bearer', text)
        self.assertEqual(data['schema'], 'guardian-two-node-lab/1')

    def test_offline_mock_report_cannot_claim_real_ns8(self):
        data = full_report().finish(real_ns8=False)
        self.assertEqual(data['overall'], 'mock-only')
        self.assertFalse(data['real_ns8'])
