"""Opt-in community blocklist in the real engine image: the Central API client is activated by offline-start.sh only
when the API is reachable, because crowdsec exits at start otherwise (verified: 'authenticate watcher' fatal) and that
would take local protection down after a reboot without internet. Registration needs the internet and is covered by
unit tests plus a manual live check."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
IMAGE = os.environ.get('HYBRID_ENGINE_IMAGE', 'localhost/ns8-hybrid-engine:working')
FRAGMENT = 'credentials_path: /etc/crowdsec/online_api_credentials.yaml\nsharing: false\npull:\n  community: true\n  blocklists: false\n'


def run(*args, check=True, timeout=120):
    return subprocess.run(args, check=check, capture_output=True, text=True, timeout=timeout)


def mounts(root):
    return ['-v', str(root / 'config') + ':/etc/crowdsec:Z', '-v', str(root / 'data') + ':/var/lib/crowdsec/data:Z',
            '-v', str(root / 'logs') + ':/hybrid-logs:ro,Z', '-v', str(ROOT / 'imageroot/crowdsec/offline-start.sh') + ':/offline-start.sh:ro,Z']


class CommunityStart(unittest.TestCase):
    def setUp(self):
        if run('podman', 'image', 'exists', IMAGE, check=False).returncode:
            self.skipTest('engine image unavailable')
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        for part in ('config', 'data', 'logs'):
            (self.root / part).mkdir()
        (self.root / 'logs/events.log').touch()
        (self.root / 'config/config.yaml.local').write_text(json.dumps({
            'api': {'server': {'listen_uri': '127.0.0.1:8080', 'disable_usage_metrics_export': True}}, 'prometheus': {'enabled': False}}))
        (self.root / 'config/acquis.yaml').write_text(json.dumps({'filenames': ['/hybrid-logs/events.log'], 'labels': {'type': 'syslog'}}))
        self.addCleanup(self.tmp.cleanup)

    def prepare_config_yaml(self):
        run('podman', 'run', '--rm', '--entrypoint', 'bash', *mounts(self.root), IMAGE, '-c',
            'cp -a /staging/etc/crowdsec/. /etc/crowdsec/ && cp /staging/etc/crowdsec/config.yaml /etc/crowdsec/config.yaml')

    def dry_run(self, probe):
        self.prepare_config_yaml()
        return run('podman', 'run', '--rm', '--network', 'none', '--entrypoint', '/bin/bash', '-e', 'GUARDIAN_START_DRYRUN=1',
                   '-e', 'GUARDIAN_CAPI_PROBE=' + probe, '-e', 'DISABLE_ONLINE_API=true', *mounts(self.root), IMAGE, '/offline-start.sh')

    def test_client_is_merged_when_the_central_api_answers(self):
        (self.root / 'config/community.yaml').write_text(FRAGMENT)
        out = self.dry_run('ok')
        self.assertIn('DISABLE_ONLINE_API=false', out.stdout)
        self.assertIn('community: true', out.stdout)
        self.assertIn('blocklists: false', out.stdout)

    def test_client_is_left_out_when_the_central_api_is_unreachable(self):
        (self.root / 'config/community.yaml').write_text(FRAGMENT)
        out = self.dry_run('fail')
        self.assertIn('DISABLE_ONLINE_API=true', out.stdout)
        self.assertNotIn('community: true', out.stdout)
        self.assertIn('Central API is unreachable', out.stderr)

    def test_a_previous_merge_does_not_survive_a_disabled_option(self):
        (self.root / 'config/community.yaml').write_text(FRAGMENT)
        self.dry_run('ok')
        (self.root / 'config/community.yaml').unlink()
        out = self.dry_run('ok')
        self.assertIn('DISABLE_ONLINE_API=true', out.stdout)
        self.assertNotIn('community: true', out.stdout)

    def test_engine_really_starts_offline_with_the_option_on_and_no_internet(self):
        (self.root / 'config/community.yaml').write_text(FRAGMENT)
        (self.root / 'config/online_api_credentials.yaml').write_text('url: https://api.crowdsec.net/\nlogin: fake\npassword: fake\n')
        name = 'community-cfg-' + uuid.uuid4().hex[:8]
        try:
            run('podman', 'run', '-d', '--name', name, '--network', 'none', '--entrypoint', '/bin/bash', '-e', 'CUSTOM_HOSTNAME=community-test',
                '-e', 'DISABLE_ONLINE_API=true', *mounts(self.root), IMAGE, '/offline-start.sh')
            deadline = time.monotonic() + 60
            while run('podman', 'exec', name, 'cscli', 'lapi', 'status', check=False).returncode:
                self.assertLess(time.monotonic(), deadline, 'engine not ready: ' + run('podman', 'logs', name, check=False).stderr[-1200:])
                time.sleep(1)
            self.assertNotIn('online_client', run('podman', 'exec', name, 'cscli', 'config', 'show-yaml').stdout)
        finally:
            run('podman', 'rm', '-f', name, check=False)


if __name__ == '__main__':
    unittest.main()
