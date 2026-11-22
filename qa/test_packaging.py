"""Packaging boundary regressions; no host firewall operations."""
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class PackagingTests(unittest.TestCase):
    def test_module_reserves_gateway_port(self):
        self.assertIn('org.nethserver.tcp-ports-demand=3', (ROOT / 'build-images.sh').read_text())

    def test_build_has_explicit_runtime_override(self):
        script = (ROOT / 'build-images.sh').read_text()
        self.assertIn('CROWDSEC_IMAGE', script)
        self.assertIn('CROWDSEC_FIREWALL_BOUNCER_IMAGE', script)
        self.assertIn('org.opencontainers.image.revision', script)

    def test_engine_image_environment_name_matches_ns8_derivation(self):
        # NS8 exports the image environment variable from the last path
        # component of each org.nethserver.images entry (upper case, - -> _).
        script = (ROOT / 'build-images.sh').read_text()
        self.assertIn('guardian-engine:', script)
        name = 'guardian-engine'.upper().replace('-', '_') + '_IMAGE'
        self.assertIn('image("%s")' % name, (ROOT / 'imageroot/pypkg/cscompanion/lifecycle.py').read_text())

    def test_build_does_not_require_corepack(self):
        script = (ROOT / 'build-images.sh').read_text()
        self.assertNotIn('corepack yarn', script)
        self.assertIn('@yarnpkg/cli-dist@', script)

    def test_offline_patcher_disables_hub_function_only(self):
        with tempfile.TemporaryDirectory() as td:
            target = pathlib.Path(td) / 'docker_start.sh'
            target.write_text('prepare_hub() {\n    echo NETWORK\n}\necho LOCAL\nprepare_hub\n')
            subprocess.run(['bash', str(ROOT / 'runtime/disable-hub-downloads.sh'), str(target)], check=True)
            out = subprocess.check_output(['bash', str(target)], text=True)
            self.assertEqual(out, 'LOCAL\n')

    def test_offline_patcher_rejects_unknown_upstream(self):
        with tempfile.TemporaryDirectory() as td:
            target = pathlib.Path(td) / 'docker_start.sh'
            target.write_text('echo UPSTREAM_CHANGED\n')
            result = subprocess.run(['bash', str(ROOT / 'runtime/disable-hub-downloads.sh'), str(target)], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('upstream prepare_hub function not found', result.stderr)
            self.assertEqual(target.read_text(), 'echo UPSTREAM_CHANGED\n')


if __name__ == '__main__':
    unittest.main()
