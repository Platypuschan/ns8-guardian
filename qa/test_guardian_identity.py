"""Public Guardian package identity must agree with NS8 image environment names."""
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class GuardianIdentity(unittest.TestCase):
    def test_repository_runtime_and_ui_use_guardian_namespace(self):
        build = (ROOT / 'build-images.sh').read_text()
        self.assertIn('module="${repobase}/guardian"', build)
        self.assertIn('${repobase}/guardian-engine:', build)
        self.assertIn('image("GUARDIAN_ENGINE_IMAGE")',
                      (ROOT / 'imageroot/pypkg/cscompanion/lifecycle.py').read_text())
        for name in ('build-images.sh', 'runtime/Containerfile'):
            self.assertIn('https://github.com/Platypuschan/ns8-guardian', (ROOT / name).read_text())
        meta = json.loads((ROOT / 'ui/public/metadata.json').read_text())
        self.assertEqual(meta['name'], 'Guardian')
        self.assertEqual(meta['source'], 'ghcr.io/platypuschan/guardian')
        self.assertEqual(meta['docs']['code_url'], 'https://github.com/Platypuschan/ns8-guardian')
        render = (ROOT / 'imageroot/pypkg/cscompanion/render.py').read_text()
        self.assertIn('"table": "guardian6"', render)


if __name__ == '__main__':
    unittest.main()
