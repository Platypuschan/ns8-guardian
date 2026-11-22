"""Offline regressions for the two-VM lab input contract (no VM, no NS8 involved)."""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'tests' / 'lab'))

from twolab.config import ConfigError, parse_inputs  # noqa: E402

DIGEST = 'sha256:' + 'a' * 64
BASE = {
    'MODULE_DIGEST': DIGEST,
    'EXPECTED_SOURCE_SHA': '4d8c243478fc9bd3c04ca813a27b6d70123b0b6d',
    'EXPECTED_VERSION': '0.2.0-rc.3',
}


def env(**extra):
    return {**BASE, **extra}


class InputContract(unittest.TestCase):
    def test_defaults_are_the_two_distro_small_guest_topology(self):
        cfg = parse_inputs(env())
        self.assertEqual((cfg.hub_distro, cfg.member_distro), ('debian13', 'rocky9'))
        self.assertEqual((cfg.vm_cpus, cfg.vm_mem_mib, cfg.disk_gib), (2, 3072, 24))
        self.assertEqual(cfg.module_ref, 'ghcr.io/platypuschan/guardian@' + DIGEST)

    def test_module_must_be_an_immutable_digest_never_a_tag(self):
        for bad in ('latest', '0.2.0-rc.3', 'sha256:' + 'A' * 64, 'sha256:abc', DIGEST + '\n--x',
                    'ghcr.io/evil/guardian@' + DIGEST, ''):
            with self.assertRaises(ConfigError, msg=bad):
                parse_inputs(env(MODULE_DIGEST=bad))

    def test_registry_repository_is_not_an_input(self):
        cfg = parse_inputs(env(MODULE_REPOSITORY='ghcr.io/evil/x'))
        self.assertEqual(cfg.module_ref, 'ghcr.io/platypuschan/guardian@' + DIGEST)

    def test_expected_source_must_be_full_lowercase_sha(self):
        for bad in ('4d8c243', 'G' * 40, '4D8C243478FCA' + '0' * 27, ''):
            with self.assertRaises(ConfigError, msg=bad):
                parse_inputs(env(EXPECTED_SOURCE_SHA=bad))

    def test_vm_resources_are_bounded_so_the_single_vm_8gib_default_cannot_creep_in(self):
        for key, bad in (('VM_MEM_MIB', '8192'), ('VM_MEM_MIB', '1024'), ('VM_CPUS', '4'), ('VM_CPUS', '0'),
                         ('DISK_GIB', '10'), ('DISK_GIB', '200'), ('VM_MEM_MIB', '3072; rm -rf /'), ('VM_CPUS', 'two')):
            with self.assertRaises(ConfigError, msg=(key, bad)):
                parse_inputs(env(**{key: bad}))

    def test_distro_values_are_a_closed_set(self):
        parse_inputs(env(HUB_DISTRO='rocky9', MEMBER_DISTRO='debian13'))
        with self.assertRaises(ConfigError):
            parse_inputs(env(HUB_DISTRO='ubuntu24'))

    def test_core_ref_and_restore_mode_are_restricted(self):
        parse_inputs(env(CORE_REF='ns8-stable'))
        for bad in ('../x', 'a b', 'x;y', ''):
            with self.assertRaises(ConfigError, msg=bad):
                parse_inputs(env(CORE_REF=bad))
        with self.assertRaises(ConfigError):
            parse_inputs(env(DISK_ROLLBACK='maybe'))
        self.assertFalse(parse_inputs(env()).disk_rollback)
        self.assertTrue(parse_inputs(env(DISK_ROLLBACK='true')).disk_rollback)


if __name__ == '__main__':
    unittest.main()
