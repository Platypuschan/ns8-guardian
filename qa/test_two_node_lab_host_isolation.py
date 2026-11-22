"""Offline contract: the lab refuses, not changes, shared host kernel policy."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tests/lab'))
from twolab.net import net_create_commands
from twolab.resources import Names


class HostIsolation(unittest.TestCase):
    def test_network_setup_never_changes_host_forwarding_policy(self):
        commands = net_create_commands(Names('deadbeef', '/private/gl-deadbeef'), '192.168.220.0/24', 'runner')
        for args in commands:
            self.assertNotIn('net.ipv4.ip_forward=1', args)
        self.assertTrue(any('sysctl -n net.ipv4.ip_forward' in ' '.join(args) for args in commands))
