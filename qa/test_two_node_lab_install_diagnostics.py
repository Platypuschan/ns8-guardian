"""Hosted run 45028129299 failed the cluster install with only '[private output withheld]'.
Diagnostics must carry the sanitized install/create-cluster logs from each guest so the cause is visible."""
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'tests' / 'lab'))
sys.path.insert(0, str(ROOT / 'qa'))

from test_two_node_lab_lab import RID, Recorder, host, run_lab  # noqa: E402


class InstallDiagnostics(unittest.TestCase):
    def test_guest_install_and_create_cluster_logs_are_collected_and_sanitized(self):
        secret = 'Gl1-supersecretvalue'

        class Guest(Recorder):
            def __call__(self, argv, input=None, timeout=None):
                if argv[0] == 'ssh' and 'install.log' in argv[-1] and 'tail' in argv[-1]:
                    return 0, 'install failed: password=%s\n' % secret
                return super().__call__(argv, input, timeout)

        with tempfile.TemporaryDirectory() as tmp:
            rec = Guest(fail_on='qemu-system-x86_64')
            run_lab(tmp, rec, host())
            self.assertFalse(any('install.log' in t for t in rec.text()))   # no guests booted in this scenario
        with tempfile.TemporaryDirectory() as tmp:
            from twolab.lab import Lab
            import test_two_node_lab_lab as base
            lab = Lab(env=base.ENV, runner=Guest(), hostinfo=host(), fetch_image=base.fetch, workbase=tmp + '/w',
                      out_dir=tmp + '/o', run_id=RID, repo_root=str(ROOT), sleep=lambda s: None)
            lab.sanitizer.register(secret)
            from twolab.ssh import Guest as SshGuest
            lab.guests = {'hub': SshGuest('hub', '192.168.161.11', 'k', 'h', lab.runner, lab.sanitizer, lab.transcript)}
            lab.ops = {'hub': type('O', (), {'module': ''})()}
            files = lab.collect_diagnostics()
            text = files['diagnostics-hub.log']
            self.assertIn('core install log', text)
            self.assertIn('install failed', text)
            self.assertNotIn(secret, text)
            self.assertTrue(any('create-cluster-private.log' in ' '.join(c) for c in lab.runner.calls))


if __name__ == '__main__':
    unittest.main()
