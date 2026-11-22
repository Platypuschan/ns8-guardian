"""The management check must prove a real NS8 admin API login from the runner, not only SSH and TCP/443."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'tests' / 'lab'))
sys.path.insert(0, str(ROOT / 'qa'))

import test_two_node_lab_lab as base  # noqa: E402
from test_two_node_lab_ops import FakeRunner, make  # noqa: E402
from twolab import evidence as ev  # noqa: E402
from twolab.lab import Lab, HUB_HOST  # noqa: E402

PW = 'Gl1-admin-secret-value'


def lab(tmp, rec):
    lab = Lab(env=base.ENV, runner=rec, hostinfo=base.host(), fetch_image=base.fetch, workbase=tmp + '/w',
              out_dir=tmp + '/o', run_id=base.RID, repo_root=str(ROOT), sleep=lambda s: None)
    lab.addr = {'hub': '192.168.161.11', 'member': '192.168.161.12'}
    lab.secrets = {'admin_hub': PW, 'admin_member': PW + '2'}
    lab.ca = {'ca': '/work/ca/ca.pem'}
    return lab


class Recorder(base.Recorder):
    def __init__(self, code='200'):
        super().__init__()
        self.code, self.inputs = code, []

    def __call__(self, argv, input=None, timeout=None):
        if argv[0] == 'curl':
            self.calls.append(list(argv))
            self.inputs.append(input)
            return 0, self.code
        return super().__call__(argv, input, timeout)


class AdminLogin(unittest.TestCase):
    def test_hub_login_pins_the_private_ca_and_keeps_the_password_on_stdin(self):
        with tempfile.TemporaryDirectory() as tmp:
            rec = Recorder()
            self.assertTrue(lab(tmp, rec).admin_login('hub'))
            argv = rec.calls[0]
            self.assertNotIn(PW, ' '.join(argv))
            self.assertIn('--cacert', argv)
            self.assertIn('%s:443:192.168.161.11' % HUB_HOST, argv)
            self.assertEqual(argv[-1], 'https://%s/cluster-admin/api/login' % HUB_HOST)
            self.assertEqual(json.loads(rec.inputs[0]), {'username': 'admin', 'password': PW})
            self.assertNotIn('--insecure', argv)

    def test_member_has_no_private_ca_and_is_reached_by_address_without_verification_claims(self):
        with tempfile.TemporaryDirectory() as tmp:
            rec = Recorder()
            self.assertTrue(lab(tmp, rec).admin_login('member'))
            argv = rec.calls[0]
            self.assertIn('--insecure', argv)
            self.assertEqual(argv[-1], 'https://192.168.161.12/cluster-admin/api/login')
            self.assertEqual(json.loads(rec.inputs[0])['password'], PW + '2')

    def test_anything_but_http_200_is_a_failed_login(self):
        for code in ('401', '000', '503', ''):
            with tempfile.TemporaryDirectory() as tmp:
                self.assertFalse(lab(tmp, Recorder(code)).admin_login('hub'), code)

    def test_management_access_reports_the_login_and_the_scenario_requires_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            ops, _, _ = make(tmp, FakeRunner())
            ops.tcp_probe = lambda host, port: True
            ops.admin_login = lambda: True
            self.assertEqual(ops.management_access(), {'ssh': True, 'https_tcp': True, 'admin_login': True})
            ops.admin_login = lambda: False
            access = ops.management_access()
            with self.assertRaises(ev.EvidenceError):
                ev.assert_management_unaffected('192.168.161.1', [], '', ev.MANAGEMENT_OK, access)

    def test_missing_login_hook_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            ops, _, _ = make(tmp, FakeRunner())
            ops.tcp_probe = lambda host, port: True
            self.assertFalse(ops.management_access()['admin_login'])


if __name__ == '__main__':
    unittest.main()
