"""Offline regressions: owned-resource ledger, bridge/NAT, QEMU and cloud-init builders.

These tests build and inspect command lines; they do not create VMs or networks.
"""
from pathlib import Path
import json
import os
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'tests' / 'lab'))

from twolab.resources import Ledger, Names, NotOwnedError, new_run_id, pick_subnet  # noqa: E402
from twolab.vm import cloud_init_files, qemu_argv  # noqa: E402
from twolab.net import net_create_commands, net_delete_commands  # noqa: E402


class Ownership(unittest.TestCase):
    def setUp(self):
        self.rid = 'a1b2c3d4'
        self.names = Names(self.rid, '/work/gl-' + self.rid)

    def test_run_ids_are_unique_8_hex(self):
        ids = {new_run_id() for _ in range(50)}
        self.assertEqual(len(ids), 50)
        self.assertTrue(all(len(i) == 8 and set(i) <= set('0123456789abcdef') for i in ids))

    def test_every_resource_name_carries_the_run_id_and_fits_the_kernel_limit(self):
        for name in (self.names.bridge, self.names.tap_hub, self.names.tap_member):
            self.assertIn(self.rid, name)
            self.assertLessEqual(len(name), 15)
        self.assertIn(self.rid, self.names.s3_container)
        self.assertTrue(self.names.rule_comment.endswith(self.rid))

    def test_ledger_rejects_names_that_do_not_belong_to_this_run(self):
        ledger = Ledger(self.names)
        for kind, name in (('link', 'eth0'), ('link', 'docker0'), ('link', 'gl00000000b'), ('container', 'prod-db')):
            with self.assertRaises(NotOwnedError, msg=name):
                ledger.register(kind, name)

    def test_cleanup_plan_only_touches_registered_owned_resources_in_reverse_order(self):
        ledger = Ledger(self.names)
        ledger.register('link', self.names.bridge)
        ledger.register('link', self.names.tap_hub)
        ledger.register('qemu', self.names.qemu_name('hub'))
        plan = ledger.cleanup_plan()
        flat = [' '.join(step.argv) for step in plan]
        self.assertEqual(len(flat), 3)
        self.assertIn(self.names.qemu_name('hub'), flat[0])          # last in, first out
        self.assertTrue(all(self.rid in line for line in flat))
        self.assertFalse(any('docker0' in line or ' eth0' in line for line in flat))

    def test_cleanup_continues_after_a_failing_step_and_reports_it(self):
        ledger = Ledger(self.names)
        ledger.register('link', self.names.bridge)
        ledger.register('link', self.names.tap_hub)
        calls = []

        def runner(argv):
            calls.append(argv)
            if argv == ['ip', '-o', 'link', 'show']:
                return 0, '2: %s: <BROADCAST> mtu 1500\n' % self.names.tap_hub
            return (1, 'busy') if self.names.tap_hub in ' '.join(argv) else (0, '')
        failures = ledger.cleanup(runner)
        self.assertEqual(len(calls), 3)
        self.assertEqual(len(failures), 1)

    def test_ledger_persists_to_a_private_file_and_reloads(self):
        with tempfile.TemporaryDirectory() as tmp:
            names = Names(self.rid, tmp)
            ledger = Ledger(names)
            ledger.register('link', names.bridge)
            ledger.save()
            self.assertEqual(oct(Path(tmp, 'ledger.json').stat().st_mode & 0o777), '0o600')
            again = Ledger.load(names)
            self.assertEqual(again.entries, [('link', names.bridge)])

    def test_subnet_choice_avoids_every_existing_route(self):
        routes = 'default via 10.1.0.1 dev eth0\n192.168.171.0/24 dev docker0\n192.168.172.0/24 dev br-x\n'
        subnet = pick_subnet(routes, 'a1b2c3d4')
        self.assertTrue(subnet.startswith('192.168.') and subnet.endswith('.0/24'))
        self.assertNotIn(subnet, routes)

    def test_subnet_choice_fails_when_every_candidate_is_taken(self):
        routes = '\n'.join('192.168.%d.0/24 dev x' % i for i in range(160, 240))
        with self.assertRaises(RuntimeError):
            pick_subnet(routes, 'a1b2c3d4')


class Network(unittest.TestCase):
    def test_bridge_nat_commands_are_owned_and_removable_exactly(self):
        names = Names('a1b2c3d4', '/w')
        create = [' '.join(c) for c in net_create_commands(names, '192.168.171.0/24', 'runner')]
        delete = [' '.join(c) for c in net_delete_commands(names, '192.168.171.0/24')]
        self.assertTrue(any('ip link add name ' + names.bridge + ' type bridge' in c for c in create))
        self.assertTrue(any('MASQUERADE' in c and names.rule_comment in c and '-s 192.168.171.0/24' in c for c in create))
        # every inserted firewall rule has an exact -D twin; no flush/policy edits
        inserted = [c for c in create if 'iptables' in c]
        removed = [c for c in delete if 'iptables' in c]
        self.assertEqual(len(inserted), len(removed))
        for text in create + delete:
            self.assertNotIn(' -F', text)
            self.assertNotIn(' -P ', text)
            self.assertNotIn('flush', text)
        self.assertTrue(any(c.startswith('sudo ip link del ' + names.bridge) for c in delete))


class VmBuilders(unittest.TestCase):
    def argv(self, **kw):
        names = Names('a1b2c3d4', '/w/gl-a1b2c3d4')
        args = dict(names=names, role='hub', mem_mib=3072, cpus=2, mac='52:54:00:aa:bb:01', tap=names.tap_hub)
        args.update(kw)
        return qemu_argv(**args)

    def test_qemu_requires_kvm_acceleration_and_never_tcg(self):
        text = ' '.join(self.argv())
        self.assertIn('q35,accel=kvm', text)
        self.assertNotIn('tcg', text.lower())
        self.assertIn('-cpu host', text)

    def test_qemu_uses_the_small_guest_sizing_and_owned_tap(self):
        text = ' '.join(self.argv())
        self.assertIn('-m 3072', text)
        self.assertIn('-smp 2,', text)
        self.assertIn('ifname=gla1b2c3d4h', text)
        self.assertIn('-name gl-a1b2c3d4-hub', text)
        self.assertIn('-daemonize', text)
        self.assertIn('/w/gl-a1b2c3d4/hub.pid', text)
        self.assertIn('mac=52:54:00:aa:bb:01', text)

    def test_serial_console_goes_to_a_private_raw_log_file_in_the_workdir(self):
        self.assertIn('file:/w/gl-a1b2c3d4/hub.console.raw', ' '.join(self.argv()))

    def test_cloud_init_uses_key_only_root_login_static_ip_and_unique_identity(self):
        files = cloud_init_files(role='member', pubkey='ssh-ed25519 AAAA lab', ip='192.168.171.12', gateway='192.168.171.1',
                                 mac='52:54:00:aa:bb:02', run_id='a1b2c3d4', hosts={'192.168.171.11': 'guardian-hub.lab.test'})
        ud = files['user-data']
        self.assertIn('ssh-ed25519 AAAA lab', ud)
        self.assertIn('ssh_pwauth: false', ud)
        self.assertNotIn('chpasswd', ud)
        self.assertNotIn('plain_text_passwd', ud)
        self.assertIn('192.168.171.11 guardian-hub.lab.test', ud)
        self.assertIn('a1b2c3d4', files['meta-data'])
        self.assertIn('192.168.171.12/24', files['network-config'])
        self.assertIn('52:54:00:aa:bb:02', files['network-config'])
        self.assertIn('nameservers', files['network-config'])

    def test_cloud_init_rejects_a_pubkey_carrying_extra_yaml(self):
        with self.assertRaises(ValueError):
            cloud_init_files(role='hub', pubkey='ssh-ed25519 AAAA\n  - evil', ip='192.168.171.11', gateway='192.168.171.1',
                             mac='52:54:00:aa:bb:01', run_id='a1b2c3d4', hosts={})


class KillOwned(unittest.TestCase):
    def test_a_reused_pid_that_is_not_our_qemu_is_never_killed(self):
        import subprocess
        from twolab.vm import kill_owned_qemu
        with tempfile.TemporaryDirectory() as tmp:
            proc = subprocess.Popen(['sleep', '30'])
            try:
                pidfile = Path(tmp, 'hub.pid')
                pidfile.write_text(str(proc.pid))
                self.assertEqual(kill_owned_qemu(str(pidfile), 'gl-a1b2c3d4-hub'), 1)
                self.assertIsNone(proc.poll())
            finally:
                proc.kill(); proc.wait()

    def test_a_process_carrying_the_owned_name_is_terminated(self):
        import subprocess
        from twolab.vm import kill_owned_qemu
        with tempfile.TemporaryDirectory() as tmp:
            proc = \
                subprocess.Popen(['python3', '-c', 'import time; time.sleep(30)', '-name', 'gl-a1b2c3d4-hub'])
            pidfile = Path(tmp, 'hub.pid')
            pidfile.write_text(str(proc.pid))
            self.assertEqual(kill_owned_qemu(str(pidfile), 'gl-a1b2c3d4-hub'), 0)
            proc.wait(timeout=5)
            self.assertIsNotNone(proc.poll())

    def test_missing_pidfile_means_nothing_to_stop(self):
        from twolab.vm import kill_owned_qemu
        self.assertEqual(kill_owned_qemu('/nonexistent/hub.pid', 'gl-a1b2c3d4-hub'), 0)


class KillErrors(unittest.TestCase):
    def test_an_unreadable_pidfile_is_a_cleanup_failure_not_a_silent_success(self):
        from twolab.vm import kill_owned_qemu
        if os.geteuid() == 0:
            self.skipTest('root can read mode 000 files')
        with tempfile.TemporaryDirectory() as tmp:
            pidfile = Path(tmp, 'hub.pid')
            pidfile.write_text('1')
            pidfile.chmod(0)
            self.assertEqual(kill_owned_qemu(str(pidfile), 'gl-a1b2c3d4-hub'), 1)

    def test_a_pid_we_may_not_signal_is_a_cleanup_failure(self):
        import subprocess
        from unittest import mock
        from twolab.vm import kill_owned_qemu
        with tempfile.TemporaryDirectory() as tmp:
            proc = subprocess.Popen(['python3', '-c', 'import time; time.sleep(30)', '-name', 'gl-a1b2c3d4-hub'])
            try:
                pidfile = Path(tmp, 'hub.pid')
                pidfile.write_text(str(proc.pid))
                with mock.patch('os.kill', side_effect=PermissionError):
                    self.assertEqual(kill_owned_qemu(str(pidfile), 'gl-a1b2c3d4-hub'), 1)
            finally:
                proc.kill(); proc.wait()
