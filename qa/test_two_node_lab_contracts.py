"""Offline tests against pinned NS8 Core/Traefik contracts; no guest execution."""
import base64
import json
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_two_node_lab_ops import FakeRunner, make
from test_two_node_lab_lab import ENV, RID
from twolab.lab import Lab
from twolab.config import parse_inputs
from twolab.ssh import RemoteError

UUID = '01234567-1234-4234-8234-0123456789ab'
CORE = 'e27e2abbeee37e16e92c23027dbe0d3403aa385c'


class NodeShapeContract(unittest.TestCase):
    def test_pinned_list_nodes_envelope_is_required_not_arbitrary_mapping_length(self):
        from twolab.lab import parse_cluster_nodes
        node = {'node_id': 1, 'vpn_ip_address': '10.5.4.1'}
        self.assertEqual(parse_cluster_nodes({'nodes': [node]}), [node])
        for invalid in ([node], {'1': node}, {'nodes': {}}, {'nodes': [{}]}, {'nodes': [node, node]}, {'nodes': []}):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                parse_cluster_nodes(invalid)


class BootstrapContract(unittest.TestCase):
    def test_installer_and_cluster_receive_same_private_password_and_fixed_image(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = FakeRunner()
            ops, _, guest = make(tmp, r)
            lab = Lab(ENV, workbase=tmp, run_id=RID)
            lab.cfg = parse_inputs(ENV)
            lab.guests = {'hub': guest}
            lab.addr = {'hub': '192.168.171.11'}
            lab.secrets['admin_hub'] = 'Gl1-secret-test-value'
            lab.install_cluster('hub')
            install = next((a[-1], i) for a, i in r.calls if 'bash install.sh' in a[-1])
            self.assertIn(CORE, install[0])
            self.assertIn('ghcr.io/nethserver/core:3.25.1', install[0])
            self.assertIn('ADMIN_PASSWORD="$pw"', install[0])
            self.assertEqual(install[1], 'Gl1-secret-test-value\n')
            self.assertIn('/root/create-cluster-private.log', r.remote_commands()[-1])
            self.assertNotIn('Gl1-secret-test-value', json.dumps(guest.transcript))


class CertificateContract(unittest.TestCase):
    def lab(self, tmp, runner):
        from twolab.ca import generate_private_ca
        ops, _, guest = make(tmp, runner)
        lab = Lab(ENV, workbase=tmp, run_id=RID)
        lab.ca = generate_private_ca(Path(tmp, 'ca'), RID, 'guardian-hub.lab.test')
        lab.guests = {'hub': guest}
        lab.addr = {'hub': '192.168.171.11'}
        runner.when('list-installed-modules', out=json.dumps({'ghcr.io/nethserver/traefik': [
            {'id': 'traefik1', 'module': 'traefik', 'node': '1'}]}))
        return lab

    def test_fullchain_upload_policy_reset_and_poll_exact_served_leaf(self):
        import hashlib
        import ssl
        with tempfile.TemporaryDirectory() as tmp:
            r = FakeRunner()
            lab = self.lab(tmp, r)
            fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(Path(lab.ca['server']).read_text())).hexdigest()
            # Watcher first serves an unrelated leaf, then the uploaded leaf.
            polls = []
            original = r.__call__
            def runner(argv, input=None, timeout=None):
                if 's_client' in argv[-1]:
                    polls.append(1)
                    return 0, ('0' * 64 if len(polls) == 1 else fingerprint) + '  -\n'
                return original(argv, input, timeout)
            lab.guests['hub'].runner = runner
            lab.sleep = lambda _: None
            lab.install_hub_certificate()
            commands = r.remote_commands()
            self.assertLess(next(i for i,c in enumerate(commands) if 'selfsign' in c),
                            next(i for i,c in enumerate(commands) if 'upload-certificate' in c))
            self.assertTrue(any('set_env' in c and 'chain' in c for c in commands))
            self.assertTrue(any('list-certificates' in c for c in commands))
            payload = next(i for a,i in r.calls if 'upload-certificate' in a[-1])
            fullchain = base64.b64decode(json.loads(payload)['certFile']).decode()
            self.assertEqual(fullchain, Path(lab.ca['server']).read_text() + Path(lab.ca['ca']).read_text())
            self.assertEqual(len(polls), 2)

    def test_upload_failure_still_restores_chain_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = FakeRunner()
            lab = self.lab(tmp, r)
            r.when('upload-certificate', rc=2, out='validator failed')
            with self.assertRaises(RemoteError):
                lab.install_hub_certificate()
            self.assertIn('chain', r.remote_commands()[-1])
            self.assertNotIn('s_client', '\n'.join(r.remote_commands()))


class DestinationContract(unittest.TestCase):
    def test_destination_uses_observed_vpn_ip_and_native_provider_without_s3(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = FakeRunner()
            hub, _, _ = make(tmp, r)
            r.when('list-nodes', out=json.dumps({'nodes': [{'node_id': 1, 'vpn_ip_address': '10.5.4.1'}]}))
            r.when('add-backup-repository', out=json.dumps({'id': UUID, 'password': 'private-dest-password'}))
            r.when('list-backup-repositories', out=json.dumps({'repositories': [
                {'id': UUID, 'provider': 'cluster', 'url': 'webdav:http://10.5.4.1:4694'}]}))
            r.when('add-backup ', out='7')
            r.when('list-backups', out=json.dumps({'backups': [{'id': 7, 'repository': UUID,
                'instances': [{'module_id': 'guardian1'}], 'enabled': True}]}))
            lab = Lab(ENV, runner=lambda *a, **k: self.fail('no host container allowed'), workbase=tmp, run_id=RID)
            lab.ops = {'hub': hub}
            lab.stage_backup_target()
            self.assertEqual(hub.backup, {'repository': UUID, 'backup_id': 7})
            payload = json.loads(next(i for a,i in r.calls if 'add-backup-repository' in a[-1]))
            self.assertEqual(payload['provider'], 'cluster')
            self.assertEqual(payload['url'], 'webdav:http://10.5.4.1:4694')
            self.assertEqual(payload['parameters'], {})
            self.assertNotIn('private-dest-password', json.dumps(hub.guest.transcript))
            self.assertIn('list-backups', '\n'.join(r.remote_commands()))


class RestoreContract(unittest.TestCase):
    def test_remove_first_restore_requires_new_id_uuid_and_installed_readback(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = FakeRunner()
            ops, _, _ = make(tmp, r)
            r.when('restore-module', out=json.dumps({'module_id': 'guardian2', 'module_uuid': UUID}))
            r.when('read_envfile', out=json.dumps(UUID))
            r.when('cluster/module_uuid', out=UUID + '\n')
            count = []
            original = r.__call__
            def runner(argv, input=None, timeout=None):
                if 'list-installed-modules' in argv[-1]:
                    count.append(1)
                    r.calls.append((list(argv), input))
                    return 0, json.dumps({} if len(count) == 1 else {'ghcr.io/platypuschan/guardian': [
                        {'id': 'guardian2', 'module': 'guardian', 'node': '1'}]})
                return original(argv, input, timeout)
            ops.guest.runner = runner
            info = {'module_uuid': UUID, 'path': 'guardian/' + UUID, 'snapshot': 'b' * 64, 'repository': UUID}
            result = ops.restore_native(info)
            self.assertEqual(result['module_after'], 'guardian2')
            self.assertEqual(result['module_uuid_after'], UUID)
            self.assertEqual(len(count), 2)
            commands = r.remote_commands()
            self.assertLess(next(i for i,c in enumerate(commands) if 'remove-module' in c),
                            next(i for i,c in enumerate(commands) if 'restore-module' in c))
            command = next(c for c in commands if 'restore-module' in c)
            self.assertIn('"replace":false', command)

    def test_restore_rejects_same_id_or_changed_uuid(self):
        with tempfile.TemporaryDirectory() as tmp:
            for reply in ({'module_id': 'guardian1', 'module_uuid': UUID},
                          {'module_id': 'guardian2', 'module_uuid': 'aaaaaaaa-1234-4234-8234-0123456789ab'}):
                with self.subTest(reply=reply):
                    r = FakeRunner()
                    ops, _, _ = make(tmp, r)
                    r.when('list-installed-modules', out='{}')
                    r.when('restore-module', out=json.dumps(reply))
                    r.when('read_envfile', out=json.dumps(UUID))
                    r.when('cluster/module_uuid', out=UUID)
                    with self.assertRaises(RemoteError):
                        ops.restore_native({'module_uuid': UUID, 'path': 'guardian/' + UUID,
                                            'snapshot': 'b' * 64, 'repository': UUID})


class BackupContract(unittest.TestCase):
    def test_native_helper_uses_schedule_id_and_restic_time(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = FakeRunner()
            ops, _, _ = make(tmp, r)
            ops.backup = {'repository': 'repo1', 'backup_id': 7}
            r.when("grep -m1 '^MODULE_UUID='", out='MODULE_UUID=' + UUID + '\n')
            r.when('read_envfile', out=json.dumps(UUID))
            r.when('cluster/module_uuid', out=UUID + '\n')
            r.when(' snapshots --json', out=json.dumps([
                {'id': 'a' * 64, 'time': '2026-11-22T12:00:00Z'},
                {'id': 'b' * 64, 'time': '2026-11-22T12:00:01.123456789Z'}]))
            r.when(' ls ', out='/state/environment\n/state/config.json\n/state/secrets/secrets.json\n/state/backup/hybrid.db\n/state/backup/crowdsec.db\n')
            info = ops.backup_now()
            self.assertEqual(info['snapshot'], 'b' * 64)
            self.assertEqual(info['path'], 'guardian/' + UUID)
            commands = '\n'.join(r.remote_commands())
            self.assertIn('runagent -m guardian1 module-backup 7', commands)
            self.assertIn('restic-wrapper --backup 7 snapshots --json', commands)
            self.assertNotIn('cluster/run-backup', commands)
            self.assertIn(' ls ', commands)

    def test_uuid_environment_and_redis_disagreement_fails_before_backup(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = FakeRunner()
            ops, _, _ = make(tmp, r)
            ops.backup = {'repository': 'repo1', 'backup_id': 7}
            r.when("grep -m1 '^MODULE_UUID='", out='MODULE_UUID=' + UUID + '\n')
            r.when('read_envfile', out=json.dumps(UUID))
            r.when('cluster/module_uuid', out='aaaaaaaa-1234-4234-8234-0123456789ab\n')
            with self.assertRaises(RemoteError):
                ops.backup_now()
            self.assertFalse(any('module-backup' in x for x in r.remote_commands()))


if __name__ == '__main__':
    unittest.main()
