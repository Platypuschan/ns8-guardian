"""Hosted run 45029875773: cutting the hub's host tap also cut the lab's SSH management channel to the hub,
so hub-side observation during the outage failed. The outage must sever only hub<->member traffic (inside the
guests, owned nft table) and leave host management reachable. Published JSON must stay valid JSON."""
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
from twolab.lab import Lab  # noqa: E402
from twolab.ssh import Guest  # noqa: E402


def make_lab(tmp, rec):
    lab = Lab(env=base.ENV, runner=rec, hostinfo=base.host(), fetch_image=base.fetch, workbase=tmp + '/w',
              out_dir=tmp + '/o', run_id=base.RID, repo_root=str(ROOT), sleep=lambda s: None)
    lab.addr = {'hub': '192.168.161.11', 'member': '192.168.161.12'}
    lab.guests = {r: Guest(r, lab.addr[r], 'k', 'h', rec, lab.sanitizer, lab.transcript) for r in ('hub', 'member')}
    return lab


class PeerCut(unittest.TestCase):
    def test_outage_is_an_inter_guest_nft_cut_not_a_host_tap_down(self):
        class Rec(base.Recorder):
            def __init__(self):
                super().__init__()
                self.inputs = []

            def __call__(self, argv, input=None, timeout=None):
                self.inputs.append((argv, input))
                if argv[0] == 'ssh' and 'list table inet glab_cut' in argv[-1]:
                    return 1, 'No such file or directory'   # absent, as expected after removal
                return super().__call__(argv, input, timeout)
        rec = Rec()
        with tempfile.TemporaryDirectory() as tmp:
            lab = make_lab(tmp, rec)
            lab.set_peer_link('hub', False)
            down = [(a, i) for a, i in rec.inputs if a[0] == 'ssh']
            self.assertEqual({a[-1].split('@')[-1] for a, _ in down if False} or {a[-2].split('@')[-1] for a, _ in down},
                             {'192.168.161.11', '192.168.161.12'})
            self.assertFalse(any(a[0] == 'sudo' and 'down' in a for a, _ in rec.inputs))
            by_host = {a[-2].split('@')[-1]: i for a, i in down if i}
            self.assertIn('ip saddr 192.168.161.12 drop', by_host['192.168.161.11'])
            self.assertIn('ip daddr 192.168.161.12 drop', by_host['192.168.161.11'])
            self.assertIn('ip saddr 192.168.161.11 drop', by_host['192.168.161.12'])
            self.assertIn('table inet glab_cut', by_host['192.168.161.12'])
            rec.calls.clear()
            lab.set_peer_link('hub', True)
            joined = '\n'.join(rec.text())
            self.assertEqual(joined.count('nft delete table inet glab_cut'), 2)
            self.assertNotIn('sudo ip link set', joined)

    def test_restoring_fails_closed_if_the_cut_table_cannot_be_proven_absent(self):
        class Stuck(base.Recorder):
            def __call__(self, argv, input=None, timeout=None):
                if argv[0] == 'ssh' and 'list table inet glab_cut' in argv[-1]:
                    return 0, 'table inet glab_cut {}'
                return super().__call__(argv, input, timeout)
        with tempfile.TemporaryDirectory() as tmp:
            lab = make_lab(tmp, Stuck())
            with self.assertRaises(Exception):
                lab.set_peer_link('hub', True)


class PublishedJson(unittest.TestCase):
    def test_public_json_stays_parseable_when_redacting_key_like_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            lab = make_lab(tmp, base.Recorder())
            lab.write_public({'overall': 'fail', 'run_id': 'x', 'real_ns8': True, 'cases': [],
                              'evidence': {'wg_public_key': 'AbCdEf0123456789AbCdEf0123456789AbCdEf0123='}}, {})
            for name in ('result.json', 'source-evidence.json', 'transcript.json'):
                json.loads(Path(lab.out, name).read_text())


if __name__ == '__main__':
    unittest.main()
