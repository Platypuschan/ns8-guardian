"""Offline regressions: the private CA and hub server certificate are real openssl artifacts (no mocks)."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'tests' / 'lab'))

from twolab.ca import generate_private_ca  # noqa: E402


def openssl(*args):
    return subprocess.run(['openssl', *args], capture_output=True, text=True)


class PrivateCA(unittest.TestCase):
    def test_server_certificate_verifies_against_the_private_ca_for_the_hub_name_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            files = generate_private_ca(tmp, 'a1b2c3d4', 'guardian-hub.lab.test')
            ok = openssl('verify', '-CAfile', files['ca'], '-verify_hostname', 'guardian-hub.lab.test', files['server'])
            self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)
            bad = openssl('verify', '-CAfile', files['ca'], '-verify_hostname', 'other.lab.test', files['server'])
            self.assertNotEqual(bad.returncode, 0)

    def test_certificate_is_not_trusted_without_the_private_ca(self):
        with tempfile.TemporaryDirectory() as tmp:
            files = generate_private_ca(tmp, 'a1b2c3d4', 'guardian-hub.lab.test')
            other = generate_private_ca(Path(tmp, 'other'), 'b1b2c3d4', 'guardian-hub.lab.test')
            res = openssl('verify', '-CAfile', other['ca'], files['server'])
            self.assertNotEqual(res.returncode, 0)

    def test_private_keys_are_owner_only_and_short_lived(self):
        with tempfile.TemporaryDirectory() as tmp:
            files = generate_private_ca(tmp, 'a1b2c3d4', 'guardian-hub.lab.test')
            for key in ('ca_key', 'server_key'):
                self.assertEqual(oct(Path(files[key]).stat().st_mode & 0o777), '0o600')
            res = openssl('x509', '-in', files['server'], '-noout', '-checkend', str(4 * 86400))
            self.assertNotEqual(res.returncode, 0, 'certificate must not outlive the lab by days')
            res = openssl('x509', '-in', files['server'], '-noout', '-checkend', '3600')
            self.assertEqual(res.returncode, 0)

    def test_the_ca_is_a_ca_and_the_leaf_is_not(self):
        with tempfile.TemporaryDirectory() as tmp:
            files = generate_private_ca(tmp, 'a1b2c3d4', 'guardian-hub.lab.test')
            self.assertIn('CA:TRUE', openssl('x509', '-in', files['ca'], '-noout', '-text').stdout)
            leaf = openssl('x509', '-in', files['server'], '-noout', '-text').stdout
            self.assertNotIn('CA:TRUE', leaf)
            self.assertIn('DNS:guardian-hub.lab.test', leaf)

    def test_hostnames_with_shell_or_config_syntax_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            for bad in ('x;id', 'a b.test', 'x\nDNS:evil', '-x.test', 'nodots'):
                with self.assertRaises(ValueError, msg=bad):
                    generate_private_ca(tmp, 'a1b2c3d4', bad)
