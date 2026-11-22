"""Offline regressions: exact source and artifact evidence is checked, not assumed."""
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'tests' / 'lab'))

from twolab.config import parse_inputs  # noqa: E402
from twolab.source import SourceError, expected_runtime_digests, source_evidence  # noqa: E402

SHA = '4d8c243478fc9bd3c04ca813a27b6d70123b0b6d'
HEAD = 'ca47c9a964a551c44d131378d666516c55d86f55'
DIGEST = 'sha256:' + 'd' * 64
ENGINE = 'ghcr.io/platypuschan/guardian-engine@sha256:' + 'e' * 64
BOUNCER = 'ghcr.io/nethserver/crowdsec-firewall-bouncer:1.4.0@sha256:' + 'f' * 64
CFG = parse_inputs({'MODULE_DIGEST': DIGEST, 'EXPECTED_SOURCE_SHA': SHA, 'EXPECTED_VERSION': '0.2.0-rc.3'})
ENV = {'GITHUB_SHA': HEAD, 'GITHUB_REPOSITORY': 'Platypuschan/ns8-guardian', 'GITHUB_REF': 'refs/heads/main',
       'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_EVENT_NAME': 'workflow_dispatch'}


def inspect(**kw):
    data = {'Digest': DIGEST, 'Labels': {'org.opencontainers.image.revision': SHA, 'org.opencontainers.image.version': '0.2.0-rc.3',
                                         'org.opencontainers.image.source': 'https://github.com/Platypuschan/ns8-guardian',
                                         'org.nethserver.images': ENGINE + ' ' + BOUNCER}}
    data.update(kw)
    return data


def good(**over):
    args = dict(cfg=CFG, env=ENV, git_head=HEAD, git_dirty='', registry=inspect(), workflow_sha256='a' * 64, lab_tree=HEAD[:40])
    args.update(over)
    return source_evidence(**args)


class SourceEvidence(unittest.TestCase):
    def test_exact_evidence_is_recorded(self):
        ev = good()
        self.assertEqual(ev['lab_source_sha'], HEAD)
        self.assertEqual(ev['module_digest'], DIGEST)
        self.assertEqual(ev['module_source_sha'], SHA)
        self.assertEqual(ev['module_version'], '0.2.0-rc.3')
        self.assertEqual(ev['workflow_sha256'], 'a' * 64)
        json.dumps(ev)

    def test_checked_out_commit_must_equal_the_dispatched_sha(self):
        with self.assertRaisesRegex(SourceError, 'checkout'):
            good(git_head='0' * 40)

    def test_dirty_tree_is_rejected(self):
        with self.assertRaisesRegex(SourceError, 'dirty'):
            good(git_dirty=' M tests/lab/twolab/cli.py')

    def test_only_owner_main_dispatch_is_accepted(self):
        for key, value in (('GITHUB_REPOSITORY', 'fork/ns8-guardian'), ('GITHUB_REF', 'refs/heads/feature'), ('GITHUB_EVENT_NAME', 'push')):
            with self.assertRaises(SourceError, msg=key):
                good(env=dict(ENV, **{key: value}))

    def test_registry_digest_must_equal_the_requested_immutable_digest(self):
        with self.assertRaisesRegex(SourceError, 'digest'):
            good(registry=inspect(Digest='sha256:' + '0' * 64))

    def test_module_revision_and_version_labels_must_match_expectations(self):
        with self.assertRaisesRegex(SourceError, 'revision'):
            good(registry=inspect(Labels={**inspect()['Labels'], 'org.opencontainers.image.revision': 'b' * 40}))
        with self.assertRaisesRegex(SourceError, 'version'):
            good(registry=inspect(Labels={**inspect()['Labels'], 'org.opencontainers.image.version': '0.2.0-rc.2'}))
        with self.assertRaisesRegex(SourceError, 'label'):
            good(registry=inspect(Labels={}))

    def test_runtime_images_are_the_digest_pinned_label_images(self):
        self.assertEqual(expected_runtime_digests(inspect()['Labels']), {'sha256:' + 'e' * 64, 'sha256:' + 'f' * 64})

    def test_label_images_without_digest_pins_are_rejected(self):
        with self.assertRaises(SourceError):
            expected_runtime_digests({'org.nethserver.images': 'ghcr.io/x/engine:latest'})
