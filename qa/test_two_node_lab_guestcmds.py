"""Offline regressions: guest command construction is injection-safe and owned; state probe works on real Store DBs."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'tests' / 'lab'))
sys.path.insert(0, str(ROOT / 'imageroot' / 'pypkg'))

from twolab import guestcmds as g  # noqa: E402
from twolab.resources import Names  # noqa: E402

NAMES = Names('a1b2c3d4', '/w')


class SafeCommands(unittest.TestCase):
    def test_module_ids_are_validated(self):
        self.assertEqual(g.valid_module('guardian1'), 'guardian1')
        for bad in ('guardian', 'guardian1; reboot', '../x', 'Guardian1', 'guardian1 --x', ''):
            with self.assertRaises(ValueError, msg=bad):
                g.valid_module(bad)

    def test_api_calls_quote_json_and_never_leak_shell_syntax(self):
        cmd = g.api_run('module/guardian1', 'unban', {'addresses': ["198.51.100.1'; reboot; '"]})
        self.assertTrue(cmd.startswith('api-cli run module/guardian1/unban --data '))
        # round-trip through a real shell parser: still one argv element holding the JSON
        import shlex
        argv = shlex.split(cmd)
        self.assertEqual(json.loads(argv[-1])['addresses'][0], "198.51.100.1'; reboot; '")
        self.assertEqual(len(argv), 5)

    def test_api_action_names_are_a_safe_charset(self):
        for bad in ('unban; id', 'a b', '../x', ''):
            with self.assertRaises(ValueError):
                g.api_run('module/guardian1', bad, {})

    def test_secret_bearing_api_calls_use_stdin_not_argv(self):
        cmd, stdin = g.api_run_stdin('add-backup-repository', {'parameters': {'aws_secret_access_key': 'S3KR3T-value'}})
        self.assertNotIn('S3KR3T', cmd)
        self.assertIn('--data -', cmd)
        self.assertIn('S3KR3T-value', stdin)

    def test_event_delivery_keeps_the_bearer_off_the_command_line(self):
        cmd, stdin = g.send_event('http://127.0.0.1:7777/v1/events', 'tok-SECRET-1', '198.51.100.21', 'b6a3c4a2-7d52-4b87-9f0b-1c3b9f9a4d11', '2026-11-22T12:00:00Z')
        self.assertNotIn('tok-SECRET-1', cmd)
        self.assertIn('tok-SECRET-1', stdin)
        self.assertIn('198.51.100.21', cmd)

    def test_event_delivery_rejects_non_ip_and_non_loopback_endpoints(self):
        with self.assertRaises(ValueError):
            g.send_event('http://127.0.0.1:7777/v1/events', 't', '1.2.3.4; id', 'b6a3c4a2-7d52-4b87-9f0b-1c3b9f9a4d11', '2026-11-22T12:00:00Z')
        with self.assertRaises(ValueError):
            g.send_event('http://evil.example/v1/events', 't', '198.51.100.21', 'b6a3c4a2-7d52-4b87-9f0b-1c3b9f9a4d11', '2026-11-22T12:00:00Z')

    def test_attacker_namespace_uses_only_owned_names_and_synthetic_addresses(self):
        setup = g.attacker_setup(NAMES, ['198.51.100.21', '198.51.100.22'])
        teardown = g.attacker_teardown(NAMES)
        text = '\n'.join(setup + teardown)
        self.assertIn('glab-a1b2c3d4', text)
        for line in setup + teardown:
            self.assertNotRegex(line, r'ip netns (del|delete) (?!glab-a1b2c3d4)')
            self.assertNotRegex(line, r'ip link del (?!gva1b2c3d4h)')
        self.assertTrue(all(len(n) <= 15 for n in g.attacker_links(NAMES)))
        self.assertIn('198.51.100.1/24', text)

    def test_attacker_setup_rejects_addresses_outside_the_documentation_ranges(self):
        for bad in ('8.8.8.8', '10.0.0.5', '192.168.171.1', '198.51.100.1'):
            with self.assertRaises(ValueError, msg=bad):
                g.attacker_setup(NAMES, [bad])

    def test_reachability_probe_binds_the_synthetic_source_inside_the_owned_namespace(self):
        cmd = g.probe_reachable(NAMES, '198.51.100.21')
        self.assertIn('ip netns exec glab-a1b2c3d4', cmd)
        self.assertIn('198.51.100.21 198.51.100.1', cmd)
        self.assertIn('s.bind', cmd)
        self.assertIn('timeout 10', cmd)

    def test_reachability_distinguishes_a_silent_drop_from_a_broken_probe_or_a_refusal(self):
        self.assertIs(g.reachability(0, 'open\n'), True)
        self.assertIs(g.reachability(0, 'blocked\n'), False)
        for rc, out in ((0, 'refused\n'), (124, ''), (1, 'Cannot open network namespace'), (1, 'blocked\n')):
            self.assertIsNone(g.reachability(rc, out), (rc, out))

    def test_unit_stop_targets_only_the_recorded_lab_module(self):
        cmds = g.stop_module_units('guardian3')
        self.assertTrue(all('guardian3' in c for c in cmds))
        with self.assertRaises(ValueError):
            g.stop_module_units('crowdsec1')

    def test_backup_helpers_validate_identifiers(self):
        with self.assertRaises(ValueError):
            g.restore_module_data('not-a-uuid', 'guardian/xx', 'snap', 1)
        data = g.restore_module_data('6a2a6208-7d4f-5915-9419-e4f1faaa1c76', 'guardian/6a2a6208-7d4f-5915-9419-e4f1faaa1c76', 'deadbeef', 1)
        self.assertEqual(data['replace'], True)
        self.assertEqual(data['node'], 1)


class HybridProbe(unittest.TestCase):
    """Runs the real probe script against databases created by the production Store/Client code."""

    def run_probe(self, state):
        script = g.hybrid_state_script()
        out = subprocess.run([sys.executable, '-I', '-c', script, str(state)], capture_output=True, text=True, check=True).stdout
        return g.parse_hybrid_state(out)

    def test_probe_reads_hub_claims_epoch_and_never_emits_credentials(self):
        from cscompanion import hybrid
        with tempfile.TemporaryDirectory() as tmp:
            store = hybrid.Store(tmp)
            token = store.add_peer('member1')
            store.exchange(token, {'cursor': 0, 'updates': [
                {'id': '1', 'value': '198.51.100.21', 'expires_at': time.time() + 600, 'deleted': False}]})
            raw = subprocess.run([sys.executable, '-I', '-c', g.hybrid_state_script(), tmp], capture_output=True, text=True, check=True).stdout
            self.assertNotIn(token, raw)
            self.assertNotIn('token_hash', raw)
            state = g.parse_hybrid_state(raw)
            self.assertEqual(state['claims'][0]['origin'], 'member1')
            self.assertEqual(state['claims'][0]['value'], '198.51.100.21')
            self.assertEqual(state['claims'][0]['deleted'], 0)
            self.assertEqual(state['epoch'], store.epoch())

    def test_probe_reports_client_tables_when_present_and_is_read_only(self):
        from cscompanion import hybrid, sync
        with tempfile.TemporaryDirectory() as tmp:
            store = hybrid.Store(tmp)
            sync.Client(store, object(), 'member1')
            with store.connect() as db:
                db.execute("INSERT INTO local_claims(id,lapi_id,value,expires_at,deleted,pending) VALUES('9','1','198.51.100.22',?,0,0)", (time.time() + 60,))
            before = Path(tmp, 'hybrid.db').read_bytes()
            state = self.run_probe(tmp)
            self.assertEqual(state['local_claims'][0]['value'], '198.51.100.22')
            self.assertEqual(state['imports'], [])
            self.assertEqual(Path(tmp, 'hybrid.db').read_bytes(), before)

    def test_unparseable_probe_output_is_an_error(self):
        with self.assertRaises(ValueError):
            g.parse_hybrid_state('Traceback')


class ModuleStdin(unittest.TestCase):
    def test_module_agent_calls_can_carry_secrets_on_stdin(self):
        cmd, stdin = g.api_run_stdin('configure-module', {'role': 'member', 'token': 'csc2.SECRETVALUE'}, agent='module/guardian2')
        self.assertEqual(cmd, 'api-cli run module/guardian2/configure-module --data -')
        self.assertIn('csc2.SECRETVALUE', stdin)
        with self.assertRaises(ValueError):
            g.api_run_stdin('configure-module', {}, agent='module/x; id')
