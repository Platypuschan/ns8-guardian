"""Offline regressions: scenario assertions must fail on wrong evidence (no false passes).

Inputs are hand-built evidence shaped like the guest probes' output. They are NOT real NS8 results.
"""
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'tests' / 'lab'))

from twolab import evidence as ev  # noqa: E402

NOW = 1_800_000_000.0


def alerts(*decisions):
    return json.dumps([{'decisions': [dict({'type': 'ban', 'scope': 'Ip', 'simulated': False, 'origin': 'crowdsec'}, **d)]}
                       for d in decisions])


class Parsing(unittest.TestCase):
    def test_null_alert_output_means_no_decisions(self):
        self.assertEqual(ev.parse_decisions('null', NOW), [])
        self.assertEqual(ev.parse_decisions('', NOW), [])

    def test_until_is_preferred_and_duration_is_the_fallback(self):
        out = ev.parse_decisions(alerts({'id': 1, 'value': '198.51.100.21', 'scenario': 'x', 'until': '2027-01-15T08:10:00Z', 'duration': '1m'},
                                        {'id': 2, 'value': '198.51.100.22', 'scenario': 'y', 'duration': '29m30s'}), NOW)
        self.assertEqual(out[0]['expires_at'], 1800000600.0)
        self.assertAlmostEqual(out[1]['expires_at'], NOW + 29 * 60 + 30)
        self.assertEqual({d['ip'] for d in out}, {'198.51.100.21', '198.51.100.22'})

    def test_deleted_decisions_stay_in_alert_output_with_a_past_expiry_and_are_not_active_bans(self):
        # `cscli decisions delete` soft-deletes: the decision remains in `alerts list`, expired (hosted run 45031286662).
        out = ev.parse_decisions(alerts({'id': 1, 'value': '198.51.100.25', 'scenario': 'x', 'duration': '-3s'},
                                        {'id': 2, 'value': '198.51.100.26', 'scenario': 'x', 'until': '2020-01-01T00:00:00Z', 'duration': '5m'},
                                        {'id': 3, 'value': '198.51.100.27', 'scenario': 'x', 'duration': '4m'}), NOW)
        self.assertEqual([d['ip'] for d in out], ['198.51.100.27'])

    def test_simulated_and_non_ban_decisions_do_not_count(self):
        out = ev.parse_decisions(alerts({'id': 1, 'value': '198.51.100.21', 'scenario': 'x', 'duration': '5m', 'simulated': True},
                                        {'id': 2, 'value': '198.51.100.22', 'scenario': 'x', 'duration': '5m', 'type': 'captcha'}), NOW)
        self.assertEqual(out, [])

    def test_garbage_raises_instead_of_looking_like_an_empty_ban_list(self):
        with self.assertRaises(ev.EvidenceError):
            ev.parse_decisions('Traceback (most recent call last)', NOW)

    def test_nft_membership_is_exact_not_substring(self):
        table = 'table ip guardian {\n set banned { elements = { 198.51.100.21, 198.51.100.210 timeout 5m } }\n}'
        self.assertTrue(ev.nft_has_ip(table, '198.51.100.21'))
        self.assertTrue(ev.nft_has_ip(table, '198.51.100.210'))
        self.assertFalse(ev.nft_has_ip(table, '198.51.100.2'))
        self.assertFalse(ev.nft_has_ip(table, '198.51.100.211'))


class Ttl(unittest.TestCase):
    def test_equal_absolute_expiry_after_a_long_outage_passes(self):
        ev.assert_absolute_ttl(origin_expires=NOW + 1000, peer_expires=NOW + 1002, outage_seconds=130)

    def test_ttl_restarted_at_import_time_is_caught(self):
        with self.assertRaisesRegex(ev.EvidenceError, 'absolute'):
            ev.assert_absolute_ttl(origin_expires=NOW + 1000, peer_expires=NOW + 1000 + 130, outage_seconds=130)

    def test_a_measurement_without_a_real_delay_is_not_discriminating(self):
        with self.assertRaisesRegex(ev.EvidenceError, 'discriminat'):
            ev.assert_absolute_ttl(origin_expires=NOW + 1000, peer_expires=NOW + 1001, outage_seconds=5)

    def test_peer_ban_lasting_much_shorter_than_origin_is_also_wrong(self):
        with self.assertRaises(ev.EvidenceError):
            ev.assert_absolute_ttl(origin_expires=NOW + 1000, peer_expires=NOW + 900, outage_seconds=130)


class NoEcho(unittest.TestCase):
    def good(self):
        return dict(
            hub_claims=[{'origin': 'member1', 'value': '198.51.100.21', 'deleted': 0},
                        {'origin': 'guardian1-local', 'value': '198.51.100.22', 'deleted': 0}],
            member_local=[{'value': '198.51.100.21', 'deleted': 0}],
            member_decisions=[{'ip': '198.51.100.21', 'scenario': 'crowdsec/x'}, {'ip': '198.51.100.22', 'scenario': 'ns8-sync/abc'}],
            hub_decisions=[{'ip': '198.51.100.22', 'scenario': 'crowdsec/x'}, {'ip': '198.51.100.21', 'scenario': 'ns8-sync/def'}],
            member_ip='198.51.100.21', hub_ip='198.51.100.22', member_peer='member1', hub_peer='guardian1-local')

    def test_clean_state_passes(self):
        ev.assert_no_echo(**self.good())

    def test_member_reflecting_hub_ban_back_to_hub_is_an_echo(self):
        g = self.good()
        g['hub_claims'].append({'origin': 'member1', 'value': '198.51.100.22', 'deleted': 0})
        with self.assertRaisesRegex(ev.EvidenceError, 'echo'):
            ev.assert_no_echo(**g)

    def test_hub_reflecting_member_ban_as_its_own_local_claim_is_an_echo(self):
        g = self.good()
        g['hub_claims'].append({'origin': 'guardian1-local', 'value': '198.51.100.21', 'deleted': 0})
        with self.assertRaisesRegex(ev.EvidenceError, 'echo'):
            ev.assert_no_echo(**g)

    def test_member_exporting_an_imported_ban_as_local_claim_is_an_echo(self):
        g = self.good()
        g['member_local'].append({'value': '198.51.100.22', 'deleted': 0})
        with self.assertRaisesRegex(ev.EvidenceError, 'echo'):
            ev.assert_no_echo(**g)

    def test_missing_imported_decision_is_not_a_pass(self):
        g = self.good()
        g['member_decisions'] = [{'ip': '198.51.100.21', 'scenario': 'crowdsec/x'}]
        with self.assertRaisesRegex(ev.EvidenceError, 'import'):
            ev.assert_no_echo(**g)


class Enforcement(unittest.TestCase):
    def test_drop_requires_reachable_before_and_blocked_after(self):
        ev.assert_dropped(before=True, after=False, what='x')
        for before, after in ((False, False), (True, True), (False, True)):
            with self.assertRaises(ev.EvidenceError):
                ev.assert_dropped(before, after, 'x')

    def test_boot_id_must_change_and_be_a_uuid(self):
        a, b = '11111111-1111-4111-8111-111111111111', '22222222-2222-4222-8222-222222222222'
        ev.assert_boot_changed(a, b)
        for pair in ((a, a), ('', b), (a, 'not-a-uuid')):
            with self.assertRaises(ev.EvidenceError):
                ev.assert_boot_changed(*pair)

    def test_all_five_module_units_must_be_active(self):
        states = {'guardian1.service': 'active', 'guardian1-bouncer.service': 'active', 'guardian1-refresh.timer': 'active',
                  'guardian1-gateway.service': 'active', 'guardian1-sync.service': 'active'}
        ev.assert_units_active(states)
        states['guardian1-sync.service'] = 'activating'
        with self.assertRaises(ev.EvidenceError):
            ev.assert_units_active(states)
        with self.assertRaises(ev.EvidenceError):
            ev.assert_units_active({})

    def test_tombstone_must_be_from_the_original_origin_and_no_live_claim_may_remain(self):
        rows = [{'origin': 'member1', 'value': '198.51.100.24', 'deleted': 1}]
        ev.assert_origin_tombstone(rows, '198.51.100.24', 'member1')
        with self.assertRaises(ev.EvidenceError):
            ev.assert_origin_tombstone(rows, '198.51.100.24', 'other')
        rows.append({'origin': 'member1', 'value': '198.51.100.24', 'deleted': 0})
        with self.assertRaisesRegex(ev.EvidenceError, 'live'):
            ev.assert_origin_tombstone(rows, '198.51.100.24', 'member1')
        with self.assertRaises(ev.EvidenceError):
            ev.assert_origin_tombstone([], '198.51.100.24', 'member1')

    def test_epoch_must_change_after_restore(self):
        ev.assert_epoch_changed('e1', 'e2')
        for pair in (('e1', 'e1'), ('', 'e2'), ('e1', '')):
            with self.assertRaises(ev.EvidenceError):
                ev.assert_epoch_changed(*pair)

    def test_clusters_are_independent_only_when_identities_differ_and_no_peers_exist(self):
        a = {'machine_id': 'm1', 'wg_public_key': 'k1', 'nodes': 1, 'wg_peers': 0, 'vpn_network': '10.5.4.0/24'}
        b = {'machine_id': 'm2', 'wg_public_key': 'k2', 'nodes': 1, 'wg_peers': 0, 'vpn_network': '10.5.5.0/24'}
        ev.assert_independent_clusters(a, b)
        for mutate in ({'machine_id': 'm1'}, {'wg_public_key': 'k1'}, {'nodes': 2}, {'wg_peers': 1}, {'vpn_network': '10.5.4.0/24'}):
            with self.assertRaises(ev.EvidenceError, msg=mutate):
                ev.assert_independent_clusters(a, dict(b, **mutate))

    def test_digest_readback_must_match_for_module_and_every_engine_image(self):
        want = 'sha256:' + 'd' * 64
        ev.assert_digest_readback(want, {'hub': want, 'member': want})
        with self.assertRaises(ev.EvidenceError):
            ev.assert_digest_readback(want, {'hub': want, 'member': 'sha256:' + 'e' * 64})
        with self.assertRaises(ev.EvidenceError):
            ev.assert_digest_readback(want, {'hub': want})

    def test_management_source_must_never_appear_in_decisions_or_nft_and_keep_ssh_and_https_access(self):
        ok = {'ssh': True, 'https_tcp': True}
        ev.assert_management_unaffected('192.168.171.1', decisions=[{'ip': '198.51.100.21'}], nft_text='elements = { 198.51.100.21 }',
                                        access_before=ok, access_after=ok)
        with self.assertRaises(ev.EvidenceError):
            ev.assert_management_unaffected('192.168.171.1', decisions=[{'ip': '192.168.171.1'}], nft_text='', access_before=ok, access_after=ok)
        with self.assertRaises(ev.EvidenceError):
            ev.assert_management_unaffected('192.168.171.1', decisions=[], nft_text='x 192.168.171.1 y', access_before=ok, access_after=ok)
        with self.assertRaises(ev.EvidenceError):
            ev.assert_management_unaffected('192.168.171.1', decisions=[], nft_text='', access_before=ok, access_after={'ssh': True, 'https_tcp': False})
        with self.assertRaises(ev.EvidenceError):
            ev.assert_management_unaffected('192.168.171.1', decisions=[], nft_text='', access_before={}, access_after=ok)


class RuntimeDigests(unittest.TestCase):
    def test_every_node_must_run_exactly_the_label_pinned_engine_images(self):
        want = {'sha256:' + 'e' * 64, 'sha256:' + 'f' * 64}
        ev.assert_runtime_digests(want, {'hub': set(want), 'member': set(want)})
        for observed in ({'hub': set(want)}, {'hub': set(want), 'member': {'sha256:' + 'e' * 64}},
                         {'hub': set(want), 'member': want | {'sha256:' + '1' * 64}},
                         {'hub': set(want), 'member': {'sha256:' + 'e' * 64, 'sha256:' + '2' * 64}}):
            with self.assertRaises(ev.EvidenceError):
                ev.assert_runtime_digests(want, observed)

    def test_clock_skew_between_runner_and_guests_is_bounded(self):
        ev.assert_clock_skew({'hub': 0.4, 'member': -1.2})
        with self.assertRaises(ev.EvidenceError):
            ev.assert_clock_skew({'hub': 0.4, 'member': 9.0})
