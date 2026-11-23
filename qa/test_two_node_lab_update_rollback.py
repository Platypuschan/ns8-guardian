"""Optional case module_update_rollback: update-module to an earlier digest (rollback) and forward again.

Offline model (NOT real NS8). Mutants break exactly one property; the case must fail on it."""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'tests' / 'lab'))

from twolab.cases import OPTIONAL_CASES, REQUIRED_CASES, Report  # noqa: E402
from twolab.config import ConfigError, parse_inputs  # noqa: E402
from twolab.scenario import ATTACKER_IPS, I_UPDATE_BAN, J_UPDATE_POST, run_update_rollback  # noqa: E402

PREV = 'sha256:' + 'a' * 64
TARGET = 'sha256:' + 'b' * 64
ENV = {'MODULE_DIGEST': TARGET, 'EXPECTED_SOURCE_SHA': 'c' * 40, 'EXPECTED_VERSION': '0.2.0-rc.7'}


class Clock:
    def __init__(self): self.t = 1000.0
    def now(self): return self.t
    def sleep(self, s): self.t += s


class Hub:
    name = 'hub'

    def __init__(self, **mutants):
        self.m, self.digest, self.uuid, self.module, self.epoch = mutants, TARGET, 'u-1', 'guardian1', 'e-1'
        self.prev, self.bans, self.up, self.calls = '', set(), True, []

    def update_module(self, ref):
        self.calls.append(ref)
        digest = ref.rsplit('@', 1)[1]
        if self.m.get('update_ignored'):
            return
        self.prev, self.digest = self.digest, digest
        if self.m.get('new_uuid'): self.uuid = 'u-2'
        if self.m.get('new_epoch'): self.epoch = 'e-2'
        if self.m.get('lose_bans'): self.bans = set()
        if self.m.get('units_down'): self.up = False

    def image_digest(self): return self.digest
    def previous_image_digest(self): return self.prev
    def module_uuid(self): return self.uuid
    def hybrid_state(self): return {'epoch': self.epoch}
    def units(self): return {self.module + s: 'active' if self.up else 'failed' for s in ('.service', '-bouncer.service', '-refresh.timer', '-gateway.service', '-sync.service')}
    def sync_status(self): return {'stale': False, 'error': ''}
    def ban_by_events(self, ip, count=6):
        if self.m.get('post_ingest_broken') and self.digest == TARGET and self.prev: return
        self.bans.add(ip)
    def decisions(self): return [{'ip': i, 'expires_at': 9e9} for i in sorted(self.bans)]
    def nft(self): return 'elements = { %s }' % ', '.join(sorted(self.bans))
    def reachable(self, ip): return ip not in self.bans
    def unban(self, ip): self.bans.discard(ip)


def run(**mutants):
    hub, clock = Hub(**mutants), Clock()
    report = Report(run_id='a1b2c3d4', source={}, module={}, update_rollback=True)
    run_update_rollback(hub, PREV, TARGET, clock, report)
    case = report.results['module_update_rollback']
    return hub, case


class UpdateRollback(unittest.TestCase):
    def test_rollback_and_roll_forward_pass_with_readbacks(self):
        hub, case = run()
        self.assertEqual(case['status'], 'pass', case['evidence'])
        self.assertEqual(hub.calls, ['ghcr.io/platypuschan/guardian@' + PREV, 'ghcr.io/platypuschan/guardian@' + TARGET])
        ev = case['evidence']
        self.assertEqual((ev['rolled_back_to'], ev['rolled_forward_to']), (PREV, TARGET))
        self.assertTrue(ev['uuid_unchanged'] and ev['epoch_unchanged'] and ev['ban_survived_rollback'] and ev['ban_survived_roll_forward'])
        self.assertEqual(hub.bans, set())          # probe bans are removed again

    def test_each_broken_property_is_caught(self):
        for mutant, pattern in (('update_ignored', 'digest'), ('new_uuid', 'UUID'), ('new_epoch', 'epoch'),
                                ('lose_bans', 'ban'), ('units_down', 'units'), ('post_ingest_broken', 'ingest|ban')):
            with self.subTest(mutant):
                _, case = run(**{mutant: True})
                self.assertEqual(case['status'], 'fail')
                self.assertRegex(str(case['evidence']), '(?i)' + pattern)

    def test_probe_addresses_exist_in_the_attacker_namespace(self):
        self.assertIn(I_UPDATE_BAN, ATTACKER_IPS)
        self.assertIn(J_UPDATE_POST, ATTACKER_IPS)


class Wiring(unittest.TestCase):
    def test_case_is_optional_and_becomes_required_only_when_requested(self):
        self.assertIn('module_update_rollback', OPTIONAL_CASES)
        self.assertNotIn('module_update_rollback', REQUIRED_CASES)
        plain = Report(run_id='a1b2c3d4', source={}, module={})
        self.assertNotIn('module_update_rollback', plain.required())
        wanted = Report(run_id='a1b2c3d4', source={}, module={}, update_rollback=True)
        self.assertIn('module_update_rollback', wanted.required())

    def test_previous_digest_input_is_validated_and_empty_by_default(self):
        self.assertEqual(parse_inputs(ENV).previous_digest, '')
        self.assertEqual(parse_inputs(dict(ENV, PREVIOUS_DIGEST=PREV)).previous_digest, PREV)
        for bad in ('latest', 'sha256:abc', PREV + ';id', TARGET):
            with self.assertRaises(ConfigError):
                parse_inputs(dict(ENV, PREVIOUS_DIGEST=bad))

    def test_workflow_passes_the_optional_input(self):
        text = (ROOT / '.github/workflows/two-node-lab.yml').read_text()
        self.assertIn('previous_digest:', text)
        self.assertIn('PREVIOUS_DIGEST: ${{ inputs.previous_digest }}', text)
        block = text.split('previous_digest:')[1].split('disk_rollback:')[0]
        self.assertIn('required: false', block)


if __name__ == '__main__':
    unittest.main()


class GuestOpsContract(unittest.TestCase):
    def test_update_module_uses_instances_list_and_the_digest_ref_and_reads_back_from_the_environment(self):
        import json
        import tempfile
        from test_two_node_lab_ops import FakeRunner, make
        r = FakeRunner()
        r.when('update-module', 0, '{}')
        r.when('IMAGE_DIGEST', 0, json.dumps(TARGET))
        ops, _, _ = make(tempfile.mkdtemp(), r)
        ops.update_module('ghcr.io/platypuschan/guardian@' + PREV)
        update = [c for c in r.remote_commands() if 'update-module' in c][0]
        self.assertIn('"module_url":"ghcr.io/platypuschan/guardian@%s"' % PREV, update)
        self.assertIn('"instances":["guardian1"]', update)
        self.assertNotIn('add-module', update)
        self.assertEqual(ops.image_digest(), TARGET)
        self.assertEqual(ops.previous_image_digest(), TARGET)
        with self.assertRaises(ValueError):
            ops.update_module('ghcr.io/evil/guardian@' + PREV)
        with self.assertRaises(ValueError):
            ops.update_module('ghcr.io/platypuschan/guardian:latest')

    def test_launcher_runs_the_case_last_and_only_when_a_previous_digest_is_given(self):
        text = (ROOT / 'tests/lab/twolab/lab.py').read_text()
        self.assertIn('if self.cfg.previous_digest:', text)
        self.assertIn('update_rollback=bool(self.cfg.previous_digest)', text)
        self.assertLess(text.index('self.stage_scenario()\n'), text.index('self.stage_update_rollback()'))
