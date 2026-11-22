"""Scenario-level regressions against a MOCK two-node model (NOT real NS8, NOT real CrowdSec/nftables).

The mock implements the documented Guardian sync semantics (absolute expiry, origin-only publication, tombstones,
epoch reset). Mutants break exactly one property each; the scenario must then fail the matching case and the run.
"""
from pathlib import Path
import copy
import sys
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'tests' / 'lab'))

from twolab.cases import REQUIRED_CASES, Report  # noqa: E402
from twolab.scenario import run_scenario  # noqa: E402

TTL = 1800.0


class MockCluster:
    def __init__(self, **mutants):
        self.t = 1_800_000_000.0
        self.m = mutants
        self.link = True
        self.hub = MockNode(self, 'hub', 'guardian1', 'guardian1-local')
        self.member = MockNode(self, 'member', 'guardian1', 'member1')
        self.claims = []            # hub store: {origin,id,value,expires_at,deleted}
        self.epoch = 'epoch-1'
        self.member_epoch_seen = 'epoch-1'
        self.link_log = []
        self.seq = 0

    # clock / host
    def now(self): return self.t
    def sleep(self, seconds):
        end = self.t + seconds
        while self.t < end:
            self.t += min(5, end - self.t)
            self.sync_tick()

    def set_link(self, role, up):
        self.link = up
        self.link_log.append((role, up, self.t))

    # sync model
    def sync_tick(self):
        for node in (self.hub, self.member):
            node.expire(self.t)
        self.hub.export_local(self)         # the hub's own local peer publishes locally even with the link down
        if not (self.link and self.hub.up and self.member.up):
            return
        if self.member_epoch_seen != self.epoch:
            self.member_epoch_seen = self.epoch
            if not self.m.get('no_tombstone_on_restore'):
                for c in self.member.local_claims:
                    c['pending'] = True
        self.member.export_local(self, to_hub=True)
        self.hub.import_claims(self, self.claims, 'guardian1-local')
        self.member.import_claims(self, self.claims, self.member.peer)

    def hub_claims(self):
        return [dict(c) for c in self.claims]


class MockNode:
    def __init__(self, cluster, role, module, peer):
        self.c, self.role, self.module, self.peer = cluster, role, module, peer
        self.decisions = {}            # ip -> {scenario, expires_at}
        self.local_claims = []         # {id,value,expires_at,deleted,pending}
        self.imports = {}
        self.boot = str(uuid.uuid4())
        self.up = True
        self.suppressed = set()
        self.name = role

    def expire(self, now):
        for ip in [i for i, d in self.decisions.items() if d['expires_at'] <= now]:
            del self.decisions[ip]

    def export_local(self, cluster, to_hub=False):
        local = {ip: d for ip, d in self.decisions.items() if not d['scenario'].startswith('ns8-sync/') or cluster.m.get('echo')}
        now = cluster.t
        for ip, d in local.items():
            if not any(c['value'] == ip and not c['deleted'] for c in self.local_claims):
                self.local_claims.append({'id': str(len(self.local_claims) + 1), 'value': ip, 'expires_at': d['expires_at'], 'deleted': 0, 'pending': True})
        for c in self.local_claims:
            if not c['deleted'] and c['value'] not in local:
                c['deleted'], c['pending'] = 1, True
        if self.role == 'hub':
            for c in self.local_claims:
                if c['pending']:
                    self._put(cluster, self.peer, c); c['pending'] = False
        elif to_hub:
            for c in self.local_claims:
                if c['pending'] and c['expires_at'] > now:
                    self._put(cluster, self.peer, c); c['pending'] = False

    def _put(self, cluster, origin, c):
        for row in cluster.claims:
            if row['origin'] == origin and row['id'] == c['id']:
                row['deleted'] = max(row['deleted'], c['deleted']); return
        cluster.claims.append({'origin': origin, 'id': c['id'], 'value': c['value'], 'expires_at': c['expires_at'], 'deleted': c['deleted']})

    def import_claims(self, cluster, claims, me):
        for row in claims:
            if row['origin'] == me or row['expires_at'] <= cluster.t:
                continue
            key = (row['origin'], row['id'])
            if row['deleted']:
                if row['value'] in self.decisions and self.decisions[row['value']]['scenario'].startswith('ns8-sync/'):
                    del self.decisions[row['value']]
                self.suppressed.discard(key); continue
            if key in self.suppressed or row['value'] in self.decisions:
                continue
            exp = row['expires_at'] if not cluster.m.get('reset_ttl') else cluster.t + TTL
            self.decisions[row['value']] = {'scenario': 'ns8-sync/' + row['origin'], 'expires_at': exp}


class MockOps:
    """NodeOps over the mock."""
    def __init__(self, cluster, node):
        self.c, self.n = cluster, node
        self.name = node.role
        self.pre = {}

    @property
    def module(self): return self.n.module
    def boot_id(self): return self.n.boot
    def units(self):
        mod = self.n.module
        s = 'active' if self.n.up else 'inactive'
        return {mod + '.service': s, mod + '-bouncer.service': s, mod + '-refresh.timer': s, mod + '-gateway.service': s, mod + '-sync.service': s}
    def decisions(self):
        return [{'id': str(i), 'ip': ip, 'scenario': d['scenario'], 'origin': 'crowdsec', 'expires_at': d['expires_at']} for i, (ip, d) in enumerate(self.n.decisions.items())]
    def nft(self):
        if self.c.m.get('no_drop'):
            return 'table ip guardian { }'
        return 'table ip guardian { set s { elements = { %s } } }' % ', '.join(self.n.decisions)
    def hybrid_state(self):
        if self.n.role == 'hub':
            return {'epoch': self.c.epoch, 'claims': self.c.hub_claims(), 'imports': [], 'local_claims': copy.deepcopy(self.n.local_claims)}
        return {'epoch': '', 'claims': [], 'imports': [], 'local_claims': copy.deepcopy(self.n.local_claims)}
    def sync_status(self):
        return {'stale': not self.c.link, 'error': '' if self.c.link else 'URLError', 'age_seconds': 1.0}
    def ban_by_events(self, ip, count=6):
        if ip in self.allowlist():
            return
        self.n.decisions[ip] = {'scenario': 'crowdsec/lab', 'expires_at': self.c.t + TTL}
    def allowlist(self): return {'198.51.100.241'}
    def unban(self, ip):
        self.n.decisions.pop(ip, None)
    def reachable(self, ip):
        return self.c.m.get('no_drop') or ip not in self.n.decisions
    def hub_https_ok(self): return self.c.link
    def reboot(self):
        self.n.boot = str(uuid.uuid4()) if not self.c.m.get('boot_id_same') else self.n.boot
        if self.c.m.get('no_persist_reboot'):
            self.n.decisions = {}
        self.c.sleep(60)
    def prepare_attacker(self): pass
    def management_access(self): return {'ssh': True, 'https_tcp': True}
    def management_ip(self): return '192.168.171.1'
    # hub only
    def backup_now(self):
        self.snap = (copy.deepcopy(self.c.claims), copy.deepcopy(self.n.decisions), copy.deepcopy(self.n.local_claims))
        return {'snapshot': 'ab' * 8, 'repository': 'r', 'path': 'guardian/u'}
    def restore_native(self, info):
        before = self.n.module
        self.c.claims, self.n.decisions, self.n.local_claims = copy.deepcopy(self.snap[0]), copy.deepcopy(self.snap[1]), copy.deepcopy(self.snap[2])
        if not self.c.m.get('epoch_same'):
            self.c.epoch = 'epoch-2'
        self.c.sleep(30)
        return {'restore_method': 'ns8-restore-module', 'restore_exit_code': 0, 'module_before': before, 'module_after': self.n.module, 'module_uuid_before': 'u-1', 'module_uuid_after': 'u-1', 'module_removed_before_restore': True}
    # member only
    def fresh_observer(self):
        self.n.decisions, self.n.local_claims, self.n.suppressed = {}, [], set()
        self.n.peer = 'observer1'
        self.c.member_epoch_seen = self.c.epoch
        self.c.sleep(30)
    def peer_name(self): return self.n.peer


def run(**mutants):
    c = MockCluster(**mutants)
    report = Report(run_id='a1b2c3d4', source={}, module={})
    hub, member = MockOps(c, c.hub), MockOps(c, c.member)
    run_scenario(hub=hub, member=member, host=c, clock=c, report=report)
    return report.finish(real_ns8=False), c


def reason(result, case):
    return str([x for x in result['cases'] if x['id'] == case][0]['evidence'].get('error', ''))


def status(result, case):
    return [x for x in result['cases'] if x['id'] == case][0]['status']


SCENARIO_CASES = [c for c in REQUIRED_CASES if c not in (
    'preflight_capacity_kvm', 'cloud_image_checksums', 'independent_clusters', 'module_digest_runtime_readback',
    'private_ca_verified_https', 'hub_member_enrollment', 'owned_cleanup')]


class Scenario(unittest.TestCase):
    def test_faithful_mock_passes_every_scenario_case(self):
        result, _ = run()
        for case in SCENARIO_CASES:
            self.assertEqual(status(result, case), 'pass', (case, status(result, case), [x for x in result['cases'] if x['id'] == case][0]['evidence']))
        self.assertEqual(result['overall'], 'mock-only')   # provisioning cases were not run: never 'pass'

    def test_every_scenario_case_records_evidence(self):
        result, _ = run()
        for case in SCENARIO_CASES:
            self.assertTrue([x for x in result['cases'] if x['id'] == case][0]['evidence'], case)

    def test_the_outage_is_real_and_long_enough_to_discriminate_ttl(self):
        _, c = run()
        downs = [t for r, up, t in c.link_log if not up]
        ups = [t for r, up, t in c.link_log if up]
        self.assertTrue(downs and ups)
        self.assertGreaterEqual(ups[0] - downs[0], 120)

    def test_ttl_restart_at_import_is_caught(self):
        result, _ = run(reset_ttl=True)
        self.assertEqual(status(result, 'absolute_ttl'), 'fail')
        self.assertIn('absolute TTL', reason(result, 'absolute_ttl'))

    def test_echo_is_caught(self):
        result, _ = run(echo=True)
        self.assertEqual(status(result, 'no_echo'), 'fail')
        self.assertIn('echo', reason(result, 'no_echo'))

    def test_missing_packet_drop_is_caught_everywhere_a_drop_is_claimed(self):
        result, _ = run(no_drop=True)
        for case in ('member_to_hub_sync_and_drop', 'hub_to_member_sync_and_drop', 'hub_unreachable_local_protection'):
            self.assertEqual(status(result, case), 'fail', case)
            self.assertRegex(reason(result, case), 'still reachable|nftables|no packet drop|reach', case)

    def test_reboot_without_new_boot_id_is_caught(self):
        result, _ = run(boot_id_same=True)
        self.assertEqual(status(result, 'member_guest_reboot'), 'fail')
        self.assertEqual(status(result, 'hub_guest_reboot'), 'fail')
        self.assertIn('boot id unchanged', reason(result, 'member_guest_reboot'))

    def test_bans_lost_over_reboot_are_caught(self):
        result, _ = run(no_persist_reboot=True)
        self.assertEqual(status(result, 'member_guest_reboot'), 'fail')
        self.assertIn('lost bans over reboot', reason(result, 'member_guest_reboot'))

    def test_unchanged_epoch_after_restore_is_caught(self):
        result, _ = run(epoch_same=True)
        self.assertEqual(status(result, 'restore_new_epoch_tombstone_reconverge'), 'fail')
        self.assertIn('epoch unchanged', reason(result, 'restore_new_epoch_tombstone_reconverge'))

    def test_restore_that_resurrects_the_acknowledged_unban_is_caught(self):
        result, _ = run(no_tombstone_on_restore=True)
        self.assertEqual(status(result, 'restore_new_epoch_tombstone_reconverge'), 'fail')
        self.assertEqual(status(result, 'fresh_observer_no_resurrection'), 'fail')
        self.assertIn('resurrected', reason(result, 'fresh_observer_no_resurrection'))
        self.assertIn('tombstone', reason(result, 'restore_new_epoch_tombstone_reconverge'))
        self.assertEqual(result['overall'], 'mock-only')

    def test_an_unexpected_probe_error_fails_the_case_and_never_passes(self):
        c = MockCluster()
        hub, member = MockOps(c, c.hub), MockOps(c, c.member)
        hub.nft = lambda: (_ for _ in ()).throw(RuntimeError('ssh died'))
        report = Report(run_id='a1b2c3d4', source={}, module={})
        run_scenario(hub=hub, member=member, host=c, clock=c, report=report)
        result = report.finish(real_ns8=True)
        self.assertEqual(result['overall'], 'fail')
        self.assertIn('fail', {x['status'] for x in result['cases']})

    def test_disk_rollback_is_never_reported_as_native_restore(self):
        result, _ = run()
        native = [x for x in result['cases'] if x['id'] == 'native_ns8_backup_restore'][0]
        self.assertEqual(native['evidence']['restore_method'], 'ns8-restore-module')
        self.assertEqual(native['evidence']['module_uuid_before'], native['evidence']['module_uuid_after'])
        self.assertTrue(native['evidence']['module_removed_before_restore'])


if __name__ == '__main__':
    unittest.main()
