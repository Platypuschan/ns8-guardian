"""/dev/kvm access must survive KVM's own uevents (hosted run 45027781330: hub QEMU started, member QEMU got EACCES).

A one-shot `setfacl` is wiped when udev re-applies its rules on a KVM change event, so access is granted with a
run-owned udev rule that is removed again on cleanup. Offline: every command is recorded, nothing privileged runs.
"""
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'tests' / 'lab'))
sys.path.insert(0, str(ROOT / 'qa'))

from test_two_node_lab_lab import RID, Recorder, cases, host, run_lab  # noqa: E402
from twolab.resources import Ledger, Names, NotOwnedError  # noqa: E402

NO_ACCESS = {'exists': True, 'readable': False, 'writable': False}


class KvmAccess(unittest.TestCase):
    def run_lab(self, **kw):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        rec = Recorder(**kw)
        code, result = run_lab(tmp.name, rec, host(kvm=NO_ACCESS))
        return rec, result

    def test_access_is_granted_with_a_run_owned_persistent_udev_rule_not_a_one_shot_acl(self):
        rec, _ = self.run_lab()
        text = rec.text()
        self.assertFalse(any('setfacl' in t for t in text))
        grant = [t for t in text if '/etc/udev/rules.d/99-glab-kvm-%s.rules' % RID in t and 'udevadm' in t and 'rm -f' not in t]
        self.assertEqual(len(grant), 1, text)
        self.assertIn('OWNER="runner"', grant[0])
        self.assertIn('MODE="0660"', grant[0])
        self.assertNotIn('0666', grant[0])
        self.assertIn('trigger --name-match=kvm', grant[0])
        self.assertIn('settle', grant[0])

    def test_access_is_verified_as_the_runner_user_before_any_guest_starts(self):
        rec, _ = self.run_lab()
        text = rec.text()
        grant = next(i for i, t in enumerate(text) if 'udevadm trigger' in t)
        verify = next(i for i, t in enumerate(text) if t.startswith('sh -c') and '/dev/kvm' in t)
        first_qemu = next((i for i, t in enumerate(text) if t.startswith('qemu-system')), len(text))
        self.assertLess(grant, verify)
        self.assertLess(verify, first_qemu)

    def test_failed_access_verification_fails_closed_and_still_removes_the_rule(self):
        rec, result = self.run_lab(fail_on='sh -c')
        self.assertEqual(cases(result)['preflight_capacity_kvm']['status'], 'fail')
        text = rec.text()
        self.assertNotIn('qemu-system', '\n'.join(text))
        self.assertTrue(any('rm -f /etc/udev/rules.d/99-glab-kvm-%s.rules' % RID in t for t in text), text)

    def test_cleanup_removes_only_this_runs_rule_and_reapplies_default_permissions(self):
        rec, result = self.run_lab()
        removal = [t for t in rec.text() if t.startswith('sudo sh -ec') and 'rm -f' in t]
        self.assertEqual(len(removal), 1)
        self.assertIn('/etc/udev/rules.d/99-glab-kvm-%s.rules' % RID, removal[0])
        self.assertNotIn('*', removal[0])
        self.assertIn('udevadm control --reload-rules', removal[0])
        self.assertIn('udevadm trigger --name-match=kvm', removal[0])

    def test_ledger_accepts_only_the_run_owned_rule_entry(self):
        names = Names(RID, '/tmp/gl-' + RID)
        ledger = Ledger(names)
        ledger.register('udev', 'kvm-udev-' + RID)
        for foreign in ('kvm-udev-deadbeef', 'kvm-acl-' + RID, '../' + RID):
            with self.assertRaises(NotOwnedError):
                ledger.register('udev', foreign)
        with self.assertRaises(ValueError):
            ledger.register('acl', 'kvm-acl-' + RID)


if __name__ == '__main__':
    unittest.main()
