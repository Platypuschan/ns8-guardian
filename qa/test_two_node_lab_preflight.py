"""Offline regressions: capacity/KVM fail-closed and cloud-image checksum verification."""
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'tests' / 'lab'))

from twolab.capacity import CapacityError, check_capacity  # noqa: E402
from twolab.config import parse_inputs  # noqa: E402
from twolab.images import ChecksumError, IMAGES, parse_checksums, verify_file  # noqa: E402

CFG = parse_inputs({'MODULE_DIGEST': 'sha256:' + 'b' * 64, 'EXPECTED_SOURCE_SHA': 'c' * 40, 'EXPECTED_VERSION': '0.2.0-rc.3'})
GIB = 1024 ** 3


def meminfo(avail_mib):
    return 'MemTotal:       16000000 kB\nMemAvailable:   %d kB\n' % (avail_mib * 1024)


def kvm(**kw):
    return {'exists': True, 'readable': True, 'writable': True, **kw}


class Capacity(unittest.TestCase):
    def ok(self, **kw):
        args = dict(meminfo_text=meminfo(14000), disk_free_bytes=86 * GIB, cpus=4, kvm=kvm(), cfg=CFG)
        args.update(kw)
        return check_capacity(**args)

    def test_hosted_runner_numbers_from_the_real_log_pass_and_are_recorded(self):
        report = self.ok()
        self.assertEqual(report['guests'], 2)
        self.assertEqual(report['mem_available_mib'], 14000)
        self.assertEqual(report['accel'], 'kvm')

    def test_missing_or_unusable_kvm_fails_closed_never_tcg(self):
        for state in (kvm(exists=False), kvm(writable=False), kvm(readable=False)):
            with self.assertRaisesRegex(CapacityError, 'kvm'):
                self.ok(kvm=state)

    def test_not_enough_available_memory_fails(self):
        with self.assertRaisesRegex(CapacityError, 'memory'):
            self.ok(meminfo_text=meminfo(7000))

    def test_not_enough_disk_fails(self):
        with self.assertRaisesRegex(CapacityError, 'disk'):
            self.ok(disk_free_bytes=30 * GIB)

    def test_not_enough_cpus_fails(self):
        with self.assertRaisesRegex(CapacityError, 'cpu'):
            self.ok(cpus=2)

    def test_unparseable_meminfo_fails_instead_of_assuming_capacity(self):
        with self.assertRaises(CapacityError):
            self.ok(meminfo_text='garbage')


class Images(unittest.TestCase):
    def test_every_supported_distro_has_https_urls_and_a_checksum_algorithm(self):
        for name in ('debian13', 'rocky9'):
            spec = IMAGES[name]
            self.assertTrue(spec['url'].startswith('https://'))
            self.assertTrue(spec['checksum_url'].startswith('https://'))
            self.assertIn(spec['algo'], ('sha256', 'sha512'))

    def test_parse_bsd_style_rocky_checksum_file(self):
        text = 'SHA256 (Rocky-9-GenericCloud-Base.latest.x86_64.qcow2) = ' + 'ab' * 32 + '\nSHA256 (other.qcow2) = ' + 'cd' * 32 + '\n'
        sums = parse_checksums(text)
        self.assertEqual(sums['Rocky-9-GenericCloud-Base.latest.x86_64.qcow2'], 'ab' * 32)
        self.assertEqual(sums['other.qcow2'], 'cd' * 32)

    def test_parse_gnu_style_debian_checksum_file(self):
        sums = parse_checksums('%s  debian-13-genericcloud-amd64.qcow2\n%s *x.raw\n' % ('12' * 64, '34' * 64))
        self.assertEqual(sums['debian-13-genericcloud-amd64.qcow2'], '12' * 64)
        self.assertEqual(sums['x.raw'], '34' * 64)

    def test_verify_accepts_matching_bytes_and_rejects_modified_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, 'img.qcow2')
            path.write_bytes(b'image-bytes')
            good = hashlib.sha256(b'image-bytes').hexdigest()
            self.assertEqual(verify_file(path, good, 'sha256'), good)
            path.write_bytes(b'image-bytez')
            with self.assertRaisesRegex(ChecksumError, 'mismatch'):
                verify_file(path, good, 'sha256')

    def test_missing_published_checksum_is_an_error_not_a_warning(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, 'img')
            path.write_bytes(b'x')
            for expected in ('', None, 'zz', 'ab' * 10):
                with self.assertRaises(ChecksumError, msg=expected):
                    verify_file(path, expected, 'sha256')

    def test_file_name_missing_from_checksum_listing_is_an_error(self):
        with self.assertRaises(ChecksumError):
            parse_checksums('nonsense line\n')
