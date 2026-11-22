"""Hosted run 45045614201: the optional disk-rollback case probed 198.51.100.31, an address never added to the
attacker namespace (EADDRNOTAVAIL), and the restore case read nftables before the bouncer had caught up."""
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'tests' / 'lab'))
sys.path.insert(0, str(ROOT / 'qa'))

from twolab import scenario  # noqa: E402


class AttackerAddresses(unittest.TestCase):
    def test_every_probed_address_in_the_launcher_and_scenario_exists_in_the_attacker_namespace(self):
        sources = (ROOT / 'tests/lab/twolab/lab.py').read_text() + (ROOT / 'tests/lab/twolab/scenario.py').read_text()
        probed = set(re.findall(r"198\.51\.100\.\d+", sources))
        probed -= {scenario.H_ENGINE_RESTART, scenario.ALLOWLIST_CIDR.split('/')[0], '198.51.100.1'}   # H is observed, never probed
        missing = sorted(probed - set(scenario.ATTACKER_IPS))
        self.assertEqual(missing, [], 'probed but not configured in the attacker namespace')

    def test_disk_rollback_uses_the_scenario_constant(self):
        self.assertIn(scenario.DISK_ROLLBACK_PROBE, scenario.ATTACKER_IPS)
        self.assertNotIn("'198.51.100.31'", (ROOT / 'tests/lab/twolab/lab.py').read_text())

    def test_restore_waits_for_the_bouncer_instead_of_reading_nftables_once(self):
        text = (ROOT / 'tests/lab/twolab/scenario.py').read_text()
        self.assertIn('wait_until(self.clock, lambda: hub.reachable(X_UNBAN_AFTER_BACKUP)', text)


if __name__ == '__main__':
    unittest.main()
