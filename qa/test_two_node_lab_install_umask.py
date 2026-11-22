"""Hosted run 45029461131: rootless Traefik create-module failed with "No module named 'agent'".
The install command ran core/install.sh under `umask 077`, so /usr/local/agent was root-only. Installers must
run with the normal umask; only the log files are pre-created private."""
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'tests' / 'lab'))
sys.path.insert(0, str(ROOT / 'qa'))

import test_two_node_lab_lab as base  # noqa: E402
from twolab.lab import Lab  # noqa: E402
from twolab.ssh import Guest  # noqa: E402


class InstallUmask(unittest.TestCase):
    def commands(self):
        rec = base.Recorder()
        with tempfile.TemporaryDirectory() as tmp:
            lab = Lab(env=base.ENV, runner=rec, hostinfo=base.host(), fetch_image=base.fetch, workbase=tmp + '/w',
                      out_dir=tmp + '/o', run_id=base.RID, repo_root=str(ROOT), sleep=lambda s: None)
            lab.addr = {'hub': '192.168.161.11'}
            lab.secrets = {'admin_hub': 'Gl1-secret-value'}
            lab.guests = {'hub': Guest('hub', '192.168.161.11', 'k', 'h', rec, lab.sanitizer, lab.transcript)}
            lab.install_cluster('hub')
        return [c[-1] for c in rec.calls if c[0] == 'ssh']

    def test_no_restrictive_umask_while_the_installer_or_create_cluster_run(self):
        install, create = self.commands()
        for cmd in (install, create):
            self.assertNotIn('umask 077', cmd.split('install.sh')[-1] if 'install.sh' in cmd else cmd)
            self.assertNotRegex(cmd.split(';')[1] if cmd.startswith('set -eu;') else cmd, r'^\s*umask 077')
        self.assertIn('umask 022', install)
        self.assertIn('umask 022', create)

    def test_logs_are_precreated_private_and_password_stays_on_stdin(self):
        install, create = self.commands()
        self.assertIn('install -m 600 /dev/null /root/install.log', install)
        self.assertIn('install -m 600 /dev/null /root/create-cluster-private.log', create)
        for cmd in (install, create):
            self.assertNotIn('Gl1-secret-value', cmd)


if __name__ == '__main__':
    unittest.main()
