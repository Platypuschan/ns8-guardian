"""Run actual bundled engine offline, including a restart with a stale Hub index."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
import uuid


def run(*args, check=True):
    return subprocess.run(args, check=check, capture_output=True, text=True, timeout=90)


class OfflineRuntimeTests(unittest.TestCase):
    def test_first_start_and_restart_need_no_rule_downloads(self):
        image = os.environ.get('HYBRID_ENGINE_IMAGE', 'localhost/ns8-hybrid-engine:working')
        name = 'hybrid-offline-' + uuid.uuid4().hex[:10]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for part in ('config', 'data', 'logs'):
                (root / part).mkdir()
            (root / 'logs/events.log').touch()
            (root / 'config/config.yaml.local').write_text(json.dumps({
                'api': {'server': {'listen_uri': '127.0.0.1:8080', 'disable_usage_metrics_export': True}},
                'prometheus': {'enabled': False},
                'cscli': {'hub_branch': 'master'},
            }))
            (root / 'config/acquis.yaml').write_text(json.dumps({
                'filenames': ['/hybrid-logs/events.log'], 'labels': {'type': 'syslog'},
            }))
            try:
                run('podman', 'run', '-d', '--name', name, '--network', 'none',
                    '-e', 'CUSTOM_HOSTNAME=offline-test', '-e', 'DISABLE_ONLINE_API=true',
                    '-v', str(root / 'config') + ':/etc/crowdsec:Z',
                    '-v', str(root / 'data') + ':/var/lib/crowdsec/data:Z',
                    '-v', str(root / 'logs') + ':/hybrid-logs:ro,Z', image)
                self.wait_ready(name)
                index = root / 'config/hub/.index.json'
                self.assertTrue(index.exists())
                os.utime(index, (1, 1))
                run('podman', 'restart', name)
                self.wait_ready(name)
                logs = run('podman', 'logs', name).stdout + run('podman', 'logs', name).stderr
                self.assertNotIn('Running hub update', logs)
                self.assertNotIn('Running hub upgrade', logs)
                self.assertNotIn('version.crowdsec.net', logs)
                self.assertNotIn('Downloading ', logs)
                config = run('podman', 'exec', name, 'cscli', 'config', 'show-yaml').stdout
                self.assertNotIn('online_client:', config)
                manifest = run('podman', 'exec', name, 'wc', '-l', '/ruleset-manifest.sha256').stdout
                print('OFFLINE_RUNTIME_OK', manifest.strip())
            finally:
                run('podman', 'rm', '-f', name, check=False)
                self.assertEqual(run('podman', 'container', 'exists', name, check=False).returncode, 1)

    def wait_ready(self, name):
        deadline = time.monotonic() + 45
        started = json.loads(run('podman', 'inspect', name).stdout)[0]['State']['StartedAt']
        while time.monotonic() < deadline:
            result = run('podman', 'exec', name, 'cscli', 'lapi', 'status', check=False)
            logs = run('podman', 'logs', '--since', started, name, check=False)
            if result.returncode == 0 and 'Starting processing data' in logs.stdout + logs.stderr:
                return
            state = run('podman', 'inspect', '--format', '{{.State.Status}}', name).stdout.strip()
            if state == 'exited':
                self.fail('offline engine exited: ' + run('podman', 'logs', name).stderr[-2000:])
            time.sleep(.5)
        logs = run('podman', 'logs', name, check=False)
        useful = [line for line in (logs.stdout + logs.stderr).splitlines() if any(word in line.lower() for word in ('starting', 'fatal', 'error', 'acquisition', 'loading'))]
        self.fail('local stack did not become ready: ' + '\n'.join(useful)[-6000:])


if __name__ == '__main__':
    unittest.main()
