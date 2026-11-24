"""A newer engine image must bring its hub rules to an EXISTING config volume (upstream only copies missing files).

Real engines, no network: first start with the previously published image (rc.6, no HTTP scenarios), then with the
image under test on the same volume, started exactly like the module unit (offline-start.sh as entrypoint)."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
OLD = os.environ.get('OLD_ENGINE_IMAGE', 'ghcr.io/platypuschan/guardian-engine@sha256:ecfa1d1f35ecf2794a1297de2351aefa6867ad1376c6f287d27fc70f77975b0c')
NEW = os.environ.get('HYBRID_ENGINE_IMAGE', 'localhost/ns8-hybrid-engine:working')


def run(*args, check=True, timeout=120):
    return subprocess.run(args, check=check, capture_output=True, text=True, timeout=timeout)


def available(image):
    return run('podman', 'image', 'exists', image, check=False).returncode == 0 or run('podman', 'pull', '-q', image, check=False, timeout=300).returncode == 0


class RuleUpdate(unittest.TestCase):
    def start(self, image, root, name):
        run('podman', 'run', '-d', '--name', name, '--network', 'none', '--entrypoint', '/bin/bash',
            '-e', 'CUSTOM_HOSTNAME=update-test', '-e', 'DISABLE_ONLINE_API=true',
            '-v', str(root / 'config') + ':/etc/crowdsec:Z', '-v', str(root / 'data') + ':/var/lib/crowdsec/data:Z',
            '-v', str(root / 'logs') + ':/hybrid-logs:ro,Z', '-v', str(ROOT / 'imageroot/crowdsec/offline-start.sh') + ':/offline-start.sh:ro,Z',
            image, '/offline-start.sh')
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if run('podman', 'exec', name, 'cscli', 'lapi', 'status', check=False).returncode == 0:
                return
            if run('podman', 'inspect', '--format', '{{.State.Status}}', name).stdout.strip() == 'exited':
                self.fail('engine exited: ' + run('podman', 'logs', name).stderr[-1500:])
            time.sleep(.5)
        self.fail('engine not ready: ' + run('podman', 'logs', name, check=False).stderr[-1500:])

    def test_new_image_rules_reach_an_existing_volume_and_obsolete_ones_leave(self):
        for image in (OLD, NEW):
            if not available(image):
                self.skipTest('engine image unavailable: ' + image)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for part in ('config', 'data', 'logs'):
                (root / part).mkdir()
            (root / 'logs/events.log').touch()
            (root / 'config/config.yaml.local').write_text(json.dumps({
                'api': {'server': {'listen_uri': '127.0.0.1:8080', 'disable_usage_metrics_export': True}}, 'prometheus': {'enabled': False}}))
            (root / 'config/acquis.yaml').write_text(json.dumps({'filenames': ['/hybrid-logs/events.log'], 'labels': {'type': 'syslog'}}))
            name = 'rule-update-' + uuid.uuid4().hex[:8]
            try:
                self.start(OLD, root, name)
                self.assertNotIn('crowdsecurity/http-probing', run('podman', 'exec', name, 'cscli', 'scenarios', 'list', '-o', 'raw').stdout)
                run('podman', 'rm', '-f', name)
                config = root / 'config'
                (config / 'scenarios/ns8-local-rule.yaml').write_text('# module-owned regular file must survive\n')
                os.symlink('/etc/crowdsec/hub/scenarios/crowdsecurity/gone-from-image.yaml', config / 'scenarios/gone-from-image.yaml')
                self.start(NEW, root, name)
                listing = run('podman', 'exec', name, 'cscli', 'scenarios', 'list', '-o', 'raw').stdout
                for item in ('crowdsecurity/http-probing', 'crowdsecurity/http-sensitive-files', 'crowdsecurity/http-cve-probing', 'crowdsecurity/ssh-bf'):
                    self.assertIn(item, listing)
                self.assertTrue((config / 'scenarios/http-probing.yaml').is_symlink())
                self.assertTrue((config / 'scenarios/ns8-local-rule.yaml').read_text().startswith('# module-owned'))
                self.assertFalse((config / 'scenarios/gone-from-image.yaml').is_symlink(), 'obsolete hub symlink was not removed')
                self.assertTrue((root / 'data/sensitive_data.txt').is_symlink())
                logs = run('podman', 'logs', name).stdout + run('podman', 'logs', name).stderr
                self.assertNotIn('Downloading ', logs)
            finally:
                run('podman', 'rm', '-f', name, check=False)


if __name__ == '__main__':
    unittest.main()
