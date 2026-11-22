"""Hosted run 45032689667: a digest-pinned image is listed by Core as source 'ghcr.io/platypuschan/guardian@sha256',
module 'guardian@sha256' (the ref is split at ':'). Readback must match by source repository and id, not module name."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_two_node_lab_ops import FakeRunner, make  # noqa: E402
from twolab.ssh import RemoteError  # noqa: E402

UUID = '01234567-1234-4234-8234-0123456789ab'
DIGEST_LISTING = {'ghcr.io/platypuschan/guardian@sha256': [
    {'id': 'guardian2', 'source': 'ghcr.io/platypuschan/guardian@sha256', 'module': 'guardian@sha256', 'node': '1'}]}


class DigestListing(unittest.TestCase):
    def ops(self, listing):
        r = FakeRunner()
        ops, _, _ = make(tempfile.mkdtemp(), r)
        r.when('list-installed-modules', out=json.dumps(listing))
        return ops

    def test_digest_pinned_guardian_is_found_by_source_repository(self):
        self.assertEqual(self.ops(DIGEST_LISTING).installed_guardians(), ['guardian2'])

    def test_tag_style_listing_still_works_and_foreign_modules_are_ignored(self):
        listing = {'ghcr.io/platypuschan/guardian': [{'id': 'guardian3', 'source': 'ghcr.io/platypuschan/guardian', 'module': 'guardian', 'node': '1'}],
                   'ghcr.io/nethserver/traefik': [{'id': 'traefik1', 'source': 'ghcr.io/nethserver/traefik', 'module': 'traefik', 'node': '1'}],
                   'ghcr.io/evil/guardian@sha256': [{'id': 'guardian9', 'source': 'ghcr.io/evil/guardian@sha256', 'module': 'guardian@sha256', 'node': '1'}]}
        self.assertEqual(self.ops(listing).installed_guardians(), ['guardian3'])

    def test_other_node_is_ignored_and_bad_ids_are_rejected(self):
        other = {'ghcr.io/platypuschan/guardian@sha256': [dict(DIGEST_LISTING['ghcr.io/platypuschan/guardian@sha256'][0], node='2')]}
        self.assertEqual(self.ops(other).installed_guardians(), [])
        bad = {'ghcr.io/platypuschan/guardian@sha256': [dict(DIGEST_LISTING['ghcr.io/platypuschan/guardian@sha256'][0], id='x;rm')]}
        with self.assertRaises(ValueError):
            self.ops(bad).installed_guardians()


if __name__ == '__main__':
    unittest.main()
