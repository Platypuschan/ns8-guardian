"""Rendered-shell and partial-cleanup guards from independent review."""
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tests/lab'))
from twolab.vm import cloud_init_files
from twolab.resources import Ledger, Names


class ReviewGuards(unittest.TestCase):
    def test_rendered_resolver_printf_produces_two_real_lines(self):
        text = cloud_init_files('hub', 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest',
            '192.168.220.11', '192.168.220.1', '52:54:00:aa:bb:01', 'aabbccdd', {})['user-data']
        command = next(line.strip() for line in text.splitlines() if 'printf ' in line).split(' > ')[0]
        result = subprocess.run(['bash', '-c', command], text=True, capture_output=True, check=True)
        self.assertEqual(result.stdout, 'nameserver 1.1.1.1\nnameserver 8.8.8.8\n')

    def test_missing_registered_link_is_idempotently_clean(self):
        with tempfile.TemporaryDirectory() as state:
            names = Names('aabbccdd', state + '/gl-aabbccdd')
            ledger = Ledger(names)
            ledger.register('link', names.bridge)
            calls = []
            def runner(args):
                calls.append(args)
                if args == ['ip', '-o', 'link', 'show']:
                    return 0, '1: lo: <LOOPBACK> mtu 65536\n'
                return 1, 'Cannot find device'
            self.assertEqual(ledger.cleanup(runner), [])
            self.assertIn(['ip', '-o', 'link', 'show'], calls)

    def test_unreadable_link_inventory_does_not_claim_clean(self):
        with tempfile.TemporaryDirectory() as state:
            names = Names('aabbccdd', state + '/gl-aabbccdd')
            ledger = Ledger(names)
            ledger.register('link', names.bridge)
            self.assertTrue(ledger.cleanup(lambda args: (1, 'unavailable')))
