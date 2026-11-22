"""Offline regressions for the SSH transport and per-node operations, driven by a RECORDING FAKE runner.

The fake answers commands from canned text. These tests prove command construction, secret handling, parsing and
control flow. They are not real NS8 / CrowdSec / nftables behaviour.
"""
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'tests' / 'lab'))

from twolab.guestops import GuestOps  # noqa: E402
from twolab.resources import Names  # noqa: E402
from twolab.sanitize import Sanitizer  # noqa: E402
from twolab.ssh import Guest, RemoteError  # noqa: E402


class FakeRunner:
    def __init__(self):
        self.calls = []          # (argv, input)
        self.rules = []          # (substring, (rc, stdout))

    def when(self, needle, rc=0, out=''):
        self.rules.append((needle, (rc, out)))

    def __call__(self, argv, input=None, timeout=None):
        self.calls.append((list(argv), input))
        remote = argv[-1] if argv and argv[0] == 'ssh' else ' '.join(argv)
        for needle, (rc, out) in self.rules:
            if needle in remote:
                return rc, out
        return 0, ''

    def remote_commands(self):
        return [a[-1] for a, _ in self.calls if a and a[0] == 'ssh']


def make(tmp, runner, sanitizer=None):
    sanitizer = sanitizer or Sanitizer()
    names = Names('a1b2c3d4', tmp)
    guest = Guest(role='member', ip='192.168.171.12', keyfile=tmp + '/key', known_hosts=tmp + '/kh', runner=runner,
                  sanitizer=sanitizer, transcript=[])
    return GuestOps(guest, names=names, role='member', module='guardian1', peer='member1', clock=lambda: 1_800_000_000.0), sanitizer, guest


class Transport(unittest.TestCase):
    def test_ssh_argv_is_key_only_batchmode_with_a_private_known_hosts_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = FakeRunner()
            _, _, guest = make(tmp, r)
            guest.run('uname -r')
            argv = r.calls[0][0]
            joined = ' '.join(argv)
            self.assertIn('BatchMode=yes', joined)
            self.assertIn('PasswordAuthentication=no', joined)
            self.assertIn('UserKnownHostsFile=' + tmp + '/kh', joined)
            self.assertIn('StrictHostKeyChecking=accept-new', joined)
            self.assertEqual(argv[-2], 'root@192.168.171.12')
            self.assertEqual(argv[-1], 'uname -r')

    def test_nonzero_exit_raises_with_a_sanitized_message_unless_check_is_off(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = FakeRunner()
            r.when('boom', 3, 'Authorization: Bearer LEAKME')
            _, _, guest = make(tmp, r)
            with self.assertRaises(RemoteError) as ctx:
                guest.run('boom')
            self.assertNotIn('LEAKME', str(ctx.exception))
            self.assertEqual(guest.run('boom', check=False)[0], 3)

    def test_transcript_records_commands_but_never_stdin_secrets(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = FakeRunner()
            ops, san, guest = make(tmp, r)
            guest.run('cat > /root/x', stdin='TOPSECRETVALUE-123', secret_stdin=True)
            text = json.dumps(guest.transcript)
            self.assertIn('cat > /root/x', text)
            self.assertNotIn('TOPSECRETVALUE', text)

    def test_ssh_failure_255_is_distinguished_from_remote_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = FakeRunner()
            r.when('flaky', 255, 'Connection refused')
            _, _, guest = make(tmp, r)
            with self.assertRaises(RemoteError) as ctx:
                guest.run('flaky')
            self.assertTrue(ctx.exception.transport)


class NodeOps(unittest.TestCase):
    def test_ban_by_events_registers_one_source_and_sends_six_events_with_the_bearer_on_stdin_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = FakeRunner()
            r.when('add-event-source', 0, json.dumps({'name': 'lab-app', 'module': 'lab-app1', 'token': 'SRC-TOKEN-ABCDEF', 'endpoint': 'http://127.0.0.1:20007/v1/events'}))
            r.when('/v1/events', 0, '202')
            ops, san, guest = make(tmp, r)
            ops.ban_by_events('198.51.100.21')
            ops.ban_by_events('198.51.100.22')
            cmds = r.remote_commands()
            self.assertEqual(sum('add-event-source' in c for c in cmds), 1)
            self.assertEqual(sum('/v1/events' in c and 'curl' in c for c in cmds), 12)
            self.assertFalse(any('SRC-TOKEN-ABCDEF' in c for c in cmds))
            stdins = [i for a, i in r.calls if i]
            self.assertTrue(stdins and all('SRC-TOKEN-ABCDEF' in i for i in stdins if 'Bearer' in i))
            self.assertNotIn('SRC-TOKEN-ABCDEF', san.clean('x SRC-TOKEN-ABCDEF y'))

    def test_a_rejected_event_is_an_error_not_silently_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = FakeRunner()
            r.when('add-event-source', 0, json.dumps({'token': 'SRC-TOKEN-ABCDEF', 'endpoint': 'http://127.0.0.1:20007/v1/events'}))
            r.when('/v1/events', 0, '401')
            ops, _, _ = make(tmp, r)
            with self.assertRaises(RemoteError):
                ops.ban_by_events('198.51.100.21')

    def test_decisions_use_the_guest_clock_for_duration_only_decisions(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = FakeRunner()
            alerts = json.dumps([{'decisions': [{'id': 1, 'type': 'ban', 'scope': 'Ip', 'value': '198.51.100.21', 'duration': '10m', 'scenario': 's', 'origin': 'x'}]}])
            r.when('cscli', 0, '1700000000.5\n' + alerts)
            ops, _, _ = make(tmp, r)
            self.assertAlmostEqual(ops.decisions()[0]['expires_at'], 1700000600.5)

    def test_reachability_uses_the_probe_and_maps_exit_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = FakeRunner()
            r.when('ip netns exec', 0, 'open\n')
            ops, _, _ = make(tmp, r)
            self.assertTrue(ops.reachable('198.51.100.21'))
            r.rules.clear()
            r.when('ip netns exec', 0, 'blocked\n')
            self.assertFalse(ops.reachable('198.51.100.21'))

    def test_probe_infrastructure_failure_is_not_read_as_dropped(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = FakeRunner()
            r.when('ip netns exec', 1, 'Cannot open network namespace')
            ops, _, _ = make(tmp, r)
            with self.assertRaises(RemoteError):
                ops.reachable('198.51.100.21')

    def test_unit_states_parse_to_a_mapping(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = FakeRunner()
            r.when('is-active', 0, ''.join('guardian1%s active\n' % s for s in ('.service', '-bouncer.service', '-refresh.timer', '-gateway.service', '-sync.service')))
            ops, _, _ = make(tmp, r)
            self.assertEqual(len(ops.units()), 5)

    def test_reboot_waits_for_a_changed_boot_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = FakeRunner()
            seq = iter([(0, '11111111-1111-4111-8111-111111111111\n'), (255, 'refused'), (0, '22222222-2222-4222-8222-222222222222\n')])
            base = r.__call__

            def runner(argv, input=None, timeout=None):
                if argv[-1] == 'cat /proc/sys/kernel/random/boot_id':
                    return next(seq)
                return base(argv, input, timeout)
            names = Names('a1b2c3d4', tmp)
            guest = Guest('member', '192.168.171.12', tmp + '/key', tmp + '/kh', runner, Sanitizer(), [])
            slept = []
            ops = GuestOps(guest, names=names, role='member', module='guardian1', peer='member1', clock=lambda: 0.0, sleep=slept.append)
            ops.reboot()
            self.assertTrue(any('systemctl reboot' in c for c in r.remote_commands()))
            self.assertTrue(slept)

    def test_management_access_checks_ssh_and_tcp_443_from_the_runner(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = FakeRunner()
            r.when('true', 0, '')
            ops, _, _ = make(tmp, r)
            ops.tcp_probe = lambda host, port: True
            ops.admin_login = lambda: True
            self.assertEqual(ops.management_access(), {'ssh': True, 'https_tcp': True, 'admin_login': True})
            ops.tcp_probe = lambda host, port: False
            self.assertEqual(ops.management_access()['https_tcp'], False)
