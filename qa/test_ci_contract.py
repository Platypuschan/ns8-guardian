"""Safety and provenance of the Guardian candidate workflow."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class CIContract(unittest.TestCase):
    def test_rules_use_built_runtime_and_engine_is_transferred_not_rebuilt(self):
        text = (ROOT / '.github/workflows/validate.yml').read_text()
        self.assertIn('run: HYBRID_ENGINE_IMAGE=localhost/ns8-hybrid-engine:working bash tests/test-rules.sh', text)
        self.assertIn('oci-archive:guardian-engine.tar', text)
        self.assertIn('name: tested-engine', text)
        self.assertIn('CROWDSEC_IMAGE: ${{ steps.engine.outputs.engine }}', text)

    def test_archive_imports_use_buildah_user_namespace_not_standalone_skopeo(self):
        text = (ROOT / '.github/workflows/validate.yml').read_text()
        self.assertNotIn('containers-storage:', text)
        self.assertIn('buildah pull --quiet oci-archive:guardian-engine.tar', text)
        self.assertIn('buildah from oci-archive:guardian-module.tar', text)

    def test_readonly_build_and_owner_scoped_candidate_publication_are_distinct(self):
        text = (ROOT / '.github/workflows/validate.yml').read_text()
        self.assertIn('  publish-candidate:', text)
        images = text.split('  images:')[1].split('  publish-candidate:')[0]
        self.assertNotIn('packages: write', images)
        self.assertIn("github.repository == 'Platypuschan/ns8-guardian'", text)
        self.assertIn('needs: [tests, ui, policy]', text)


if __name__ == '__main__':
    unittest.main()
