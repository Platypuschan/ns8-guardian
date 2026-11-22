"""Behavioral tests for offline runtime, durable ingress and private sync."""
import base64
import datetime as dt
import importlib
import json
import os
from pathlib import Path
import tempfile
import unittest
import uuid
import threading
import urllib.request
import urllib.error
import time
import io
import contextlib
from unittest.mock import patch
from cscompanion import common, lifecycle, render

class ActionTests(unittest.TestCase):
    def test_legacy_upgrade_requires_explicit_enrollment_and_rerender_pins_local_credentials(self):
        from cscompanion import actions
        with tempfile.TemporaryDirectory() as state, patch.dict(os.environ,{'AGENT_STATE_DIR':state,'MODULE_ID':'companion1','TCP_PORTS':'21001,21002,21003'}),patch.object(lifecycle,'apply'):
            common.save_config(dict(common.DEFAULTS,role='member'))
            common.write_secret('machine_password','old-secret'); common.write_secret('bouncer_key','foreign-bouncer')
            with self.assertRaisesRegex(RuntimeError,'csc2'):
                actions.update_module({})
            actions.configure_module({'role':'member','token':common.encode_token({'url':'https://hub.example.org/','peer':'node1','secret':'s'*43})})
            self.assertNotEqual(common.read_secret('bouncer_key'),'foreign-bouncer')
            render.render_all(common.load_config(),'companion1',state,root='/nonexistent')
            self.assertEqual(json.loads((Path(state)/'crowdsec_config/local_api_credentials.yaml.local').read_text())['url'],'http://127.0.0.1:21001/')
    def test_member_status_reports_sync_freshness_and_persistent_queue_errors(self):
        from cscompanion import actions
        with tempfile.TemporaryDirectory() as state, patch.dict(os.environ,{'AGENT_STATE_DIR':state,'MODULE_ID':'companion1'}):
            common.save_config(dict(common.DEFAULTS,role='member'))
            (Path(state)/'sync-status.json').write_text(json.dumps({'last_success':time.time()-10,'pending':3,'event_pending':2,'error':'URLError'}))
            with patch.object(lifecycle,'services_state',return_value={}),patch.object(lifecycle,'cscli',return_value=type('R',(),{'returncode':0})()),patch.object(lifecycle,'cscli_json',return_value=[]),contextlib.redirect_stdout(io.StringIO()) as out:
                actions.get_status({})
            result=json.loads(out.getvalue())
            self.assertEqual(result['sync']['pending'],3)
            self.assertEqual(result['sync']['error'],'URLError')
            self.assertGreaterEqual(result['sync']['age_seconds'],10)
    def test_backup_restores_private_credentials_cursors_and_event_queue(self):
        hybrid=importlib.import_module('cscompanion.hybrid')
        with tempfile.TemporaryDirectory() as state, patch.dict(os.environ,{'AGENT_STATE_DIR':state}):
            root=Path(state); (root/'backup').mkdir()
            db=hybrid.Store(root); token=db.add_peer('node1')
            db.add_source('app','gitea1')
            self.assertTrue(lifecycle.dump_database()) # works even before engine DB exists
            db.remove_peer('node1'); db.remove_source('app')
            self.assertTrue(lifecycle.restore_database())
            self.assertEqual(len(hybrid.Store(root).list_sources()),1)
            self.assertEqual(hybrid.Store(root).exchange(token,{'cursor':0,'updates':[]})['changes'],[])
    def test_hub_members_are_private_peers_and_member_emergency_actions_are_local(self):
        from cscompanion import actions
        with tempfile.TemporaryDirectory() as state, patch.dict(os.environ,{'AGENT_STATE_DIR':state,'MODULE_ID':'companion1'}):
            common.save_config(dict(common.DEFAULTS,role='hub',hub_url='https://hub.example.org/'))
            with contextlib.redirect_stdout(io.StringIO()) as output, patch.object(lifecycle,'cscli',side_effect=AssertionError('must not create CrowdSec machines')):
                actions.add_member({'name':'node1'})
            token=json.loads(output.getvalue())['token']
            self.assertEqual(common.decode_token(token)['peer'],'node1')
            common.save_config(dict(common.DEFAULTS,role='member'))
            with patch.object(lifecycle,'cscli') as cscli, patch.object(lifecycle,'cscli_json',return_value=[]), contextlib.redirect_stdout(io.StringIO()):
                actions.list_decisions({})
                actions.unban({'addresses':['203.0.113.8']})
                cscli.assert_called_with('decisions','delete','--ip','203.0.113.8')
    def test_configure_member_uses_private_sync_never_foreign_bouncer(self):
        from cscompanion import actions
        with tempfile.TemporaryDirectory() as state, patch.dict(os.environ,{'AGENT_STATE_DIR':state,'MODULE_ID':'companion1'}), patch.object(lifecycle,'apply'):
            token=common.encode_token({'url':'https://hub.example.org/','peer':'node1','secret':'s'*43})
            actions.configure_module({'role':'member','token':token})
            self.assertEqual(common.read_secret('sync_peer'),'node1')
            self.assertEqual(common.read_secret('sync_secret'),'s'*43)
            self.assertNotEqual(common.read_secret('bouncer_key'),'s'*43)
            self.assertTrue(common.read_secret('bouncer_key'))
            with patch.object(actions,'fail',side_effect=lambda field,message: (_ for _ in ()).throw(ValueError(message))):
                with self.assertRaisesRegex(ValueError,'insecure'):
                    actions.configure_module({'role':'member','insecure_skip_verify':True})
                with self.assertRaisesRegex(ValueError,'legacy'):
                    actions.configure_module({'role':'member','token':'csc1.e30'})

    def test_event_source_actions_return_bearer_and_local_endpoint(self):
        from cscompanion import actions
        with tempfile.TemporaryDirectory() as state, patch.dict(os.environ,{'AGENT_STATE_DIR':state,'MODULE_ID':'companion1','TCP_PORTS':'21001,21002,21003'}), patch.object(lifecycle,'apply'):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                actions.ACTIONS['add-event-source']({'name':'app','module':'gitea1'})
            result=json.loads(output.getvalue())
            self.assertEqual(result['endpoint'],'http://127.0.0.1:21003/v1/events')
            self.assertTrue(result['token'])
            with contextlib.redirect_stdout(io.StringIO()) as output:
                actions.ACTIONS['list-event-sources']({})
            self.assertEqual(json.loads(output.getvalue())['sources'][0]['module'],'gitea1')
            actions.ACTIONS['remove-event-source']({'name':'app'})

class SyncTests(unittest.TestCase):
    def test_allowlist_removes_active_local_claim_and_reversibly_skips_import(self):
        hybrid=importlib.import_module('cscompanion.hybrid'); sync=importlib.import_module('cscompanion.sync')
        class Local:
            def __init__(self): self.rows=[{'id':'1','value':'203.0.113.8','expires_at':time.time()+600,'scenario':'local'}]; self.n=1
            def decisions(self): return self.rows.copy()
            def delete(self,id): self.rows=[r for r in self.rows if r['id']!=id]
            def add(self,value,duration,reason):
                self.n+=1; self.rows.append({'id':str(self.n),'value':value,'expires_at':time.time()+duration,'scenario':reason})
        with tempfile.TemporaryDirectory() as state:
            local=Local(); client=sync.Client(hybrid.Store(Path(state)),local,'node1')
            client.reconcile([])
            remote={'origin':'node2','id':'3','value':'198.51.100.8','expires_at':time.time()+600,'deleted':False,'seq':1}
            client.receive({'cursor':1,'changes':[remote]}); client.reconcile([])
            self.assertEqual(len(local.rows),2)
            client.reconcile(['203.0.113.0/24','198.51.100.0/24'])
            self.assertEqual(local.rows,[])
            self.assertTrue(client.pending()[0]['deleted'])
            client.reconcile([])
            self.assertEqual([r['value'] for r in local.rows],['198.51.100.8'])
    def test_https_sync_validates_private_ca_and_uses_peer_bearer(self):
        import ssl
        import subprocess
        hybrid=importlib.import_module('cscompanion.hybrid'); gateway=importlib.import_module('cscompanion.gateway'); sync=importlib.import_module('cscompanion.sync')
        class Empty:
            def decisions(self): return []
        with tempfile.TemporaryDirectory() as state:
            state=Path(state); db=hybrid.Store(state/'hub'); token=db.add_peer('node1')
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(state/'key'),'-out',str(state/'cert'),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],check=True,capture_output=True)
            srv=gateway.server(db,0,True); ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(state/'cert',state/'key'); srv.socket=ctx.wrap_socket(srv.socket,server_side=True)
            t=threading.Thread(target=srv.serve_forever,daemon=True); t.start()
            try:
                node=hybrid.Store(state/'node'); client=sync.Client(node,Empty(),'node1')
                with patch.dict(os.environ,{'AGENT_STATE_DIR':str(state/'node')}):
                    common.write_secret('sync_secret',token)
                    cfg={'role':'member','hub_url':'https://localhost:%d/'%srv.server_port}
                    with self.assertRaises(urllib.error.URLError): client.exchange(cfg)
                    common.write_secret('sync_ca',(state/'cert').read_text())
                    self.assertEqual(client.exchange(cfg)['changes'],[])
                    db.remove_peer('node1')
                    with self.assertRaises(urllib.error.HTTPError): client.exchange(cfg)
            finally: srv.shutdown(); srv.server_close(); t.join()
    def test_offline_reconcile_import_claims_no_echo_no_ttl_extension_or_ip_delete(self):
        hybrid = importlib.import_module('cscompanion.hybrid')
        sync = importlib.import_module('cscompanion.sync')
        class Local:
            def __init__(self): self.rows = [{'id':'1','value':'203.0.113.8','expires_at':time.time()+600,'scenario':'local'}]; self.n=1
            def decisions(self): return list(self.rows)
            def add(self, value, duration, reason):
                self.n+=1; self.rows.append({'id':str(self.n),'value':value,'expires_at':time.time()+duration,'scenario':reason})
            def delete(self, id): self.rows = [r for r in self.rows if r['id'] != str(id)]
        with tempfile.TemporaryDirectory() as state:
            db=hybrid.Store(Path(state)); local=Local(); client=sync.Client(db,local,'node1')
            client.reconcile([])
            updates=client.pending()
            self.assertEqual(len(updates),1)
            remote={'origin':'node2','id':'2','value':'203.0.113.8','expires_at':time.time()+90,'deleted':False,'seq':1}
            client.receive({'cursor':1,'changes':[remote]})
            client.reconcile([])
            self.assertEqual(len(local.rows),2)
            first=local.rows[-1]['expires_at']
            client.reconcile([])
            self.assertEqual(local.rows[-1]['expires_at'],first)
            self.assertEqual(len(client.pending()),1) # import never echoes
            client.receive({'cursor':2,'changes':[dict(remote,deleted=True,seq=2)]})
            client.reconcile([])
            self.assertEqual([r['id'] for r in local.rows],['1']) # never delete IP
            self.assertEqual(len(sync.Client(hybrid.Store(Path(state)),local,'node1').pending()),1)
    def test_peer_can_only_publish_own_claims_with_fixed_expiry_and_durable_tombstones(self):
        hybrid = importlib.import_module('cscompanion.hybrid')
        with tempfile.TemporaryDirectory() as state:
            db = hybrid.Store(Path(state))
            token = db.add_peer('node1')
            claim = {'id':'42', 'value':'203.0.113.8','expires_at':time.time()+120,'deleted':False}
            reply = db.exchange(token, {'cursor':0, 'updates':[claim]})
            self.assertEqual(reply['changes'][0]['origin'], 'node1')
            self.assertEqual(reply['changes'][0]['expires_at'], claim['expires_at'])
            # An unusable claim is rejected individually; it neither changes the stored
            # claim nor blocks a valid claim sent in the same batch.
            other = {'id':'43', 'value':'203.0.113.9','expires_at':time.time()+120,'deleted':False}
            bad = db.exchange(token, {'cursor':0,'updates':[dict(claim,expires_at=time.time()+240), other]})
            self.assertEqual(bad['rejected'], ['42'])
            self.assertEqual([c['id'] for c in bad['changes']], ['42', '43'])
            self.assertEqual(bad['changes'][0]['expires_at'], claim['expires_at'])
            self.assertEqual(db.exchange(token, {'cursor':0,'updates':[dict(claim,origin='node2')]})['rejected'], ['42'])
            for invalid in (dict(claim, id='\u0663'), dict(claim, value='::ffff:203.0.113.8'), dict(claim, value='127.0.0.1')):
                self.assertEqual(len(db.exchange(token, {'cursor':0,'updates':[invalid]})['rejected']), 1)
            db.exchange(token, {'cursor':reply['cursor'],'updates':[dict(claim,deleted=True)]})
            reply = hybrid.Store(Path(state)).exchange(token, {'cursor':0,'updates':[claim]})
            self.assertTrue(reply['changes'][-1]['deleted'])
            db.remove_peer('node1')
            with self.assertRaises(PermissionError): db.exchange(token, {'cursor':0,'updates':[]})

class OfflineTests(unittest.TestCase):
    def test_prepare_creates_event_acquisition_target_without_truncating(self):
        with tempfile.TemporaryDirectory() as state,patch.dict(os.environ,{'AGENT_STATE_DIR':state}):
            lifecycle.prepare_dirs()
            path=Path(state)/'events/auth.jsonl'
            self.assertTrue(path.exists())
            path.write_text('existing\n'); lifecycle.prepare_dirs()
            self.assertEqual(path.read_text(),'existing\n')
    def test_private_services_and_route_never_expose_lapi(self):
        with patch.dict(os.environ, {'MODULE_ID':'test1','TCP_PORTS':'21001,21002,21003',
            'GUARDIAN_ENGINE_IMAGE':'engine','CROWDSEC_FIREWALL_BOUNCER_IMAGE':'bouncer'}):
            units=lifecycle.units()
            self.assertIn('test1-sync.service',units)
            self.assertIn('test1-gateway.service',units)
            for name in ['test1.service','test1-bouncer.service']:
                self.assertNotIn('sync.service',units[name])
                self.assertNotIn('gateway.service',units[name])
            self.assertEqual(render.gateway_port(),21003)
    def test_enrollment_is_separate_from_legacy_lapi_credentials(self):
        token = common.encode_token({'url':'https://hub.example.org/','peer':'node1','secret':'x'*43})
        self.assertTrue(token.startswith('csc2.'))
        self.assertEqual(common.decode_token(token)['peer'], 'node1')
        old = 'csc1.' + base64.urlsafe_b64encode(b'{}').decode()
        with self.assertRaisesRegex(ValueError, 'legacy'):
            common.decode_token(old)
    def test_runtime_never_runs_online_hub_preparation(self):
        with patch.dict(os.environ, {'MODULE_ID':'test1', 'TCP_PORTS':'21001,21002,21003',
                                     'GUARDIAN_ENGINE_IMAGE':'engine', 'CROWDSEC_FIREWALL_BOUNCER_IMAGE':'bouncer'}):
            unit = lifecycle.units()['test1.service']
        self.assertIn('--entrypoint=/bin/bash', unit)
        self.assertIn('/offline-start.sh', unit)
        script = Path(__file__).parents[1] / 'imageroot/crowdsec/offline-start.sh'
        self.assertIn('/^prepare_hub$/d', script.read_text())

class EventTests(unittest.TestCase):
    def test_registered_module_disables_only_router_auth_fallback(self):
        with tempfile.TemporaryDirectory() as state, patch.dict(os.environ,{'AGENT_STATE_DIR':state,'TCP_PORTS':'20001,20002,20003'}):
            hybrid=importlib.import_module('cscompanion.hybrid')
            hybrid.Store(Path(state)).add_source('gitea','gitea1')
            found={'gitea':[{'module':'gitea1'},{'module':'gitea2'}], 'traefik':[{'module':'traefik1','uid':1001}]}
            expr=json.loads(render.routers_parser(found))['statics'][0]['expression']
            self.assertNotIn('gitea1-https',expr)
            self.assertIn('gitea2-https',expr)
            docs=[json.loads(x) for x in render.acquisition(found,'/nonexistent').split('---\n')]
            self.assertTrue(any(d['labels']['type']=='ns8_auth_event' for d in docs))
            generic=[d for d in docs if d['labels'].get('ns8_source')=='traefik-generic']
            self.assertEqual(len(generic),1)
            self.assertEqual(generic[0]['journalctl_filter'],['CONTAINER_NAME=traefik','_UID=1001'])
    def test_ingress_rejects_unknown_fields_bad_ip_time_and_binds_identity(self):
        hybrid = importlib.import_module('cscompanion.hybrid')
        gateway = importlib.import_module('cscompanion.gateway')
        with tempfile.TemporaryDirectory() as state:
            db = hybrid.Store(Path(state))
            token = db.add_source('app', 'gitea1')
            server = gateway.server(db, 0, hub=False)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            def send(data, bearer=token, extra=None):
                req = urllib.request.Request('http://127.0.0.1:%d/v1/events' % server.server_port,
                    data=json.dumps(data).encode(), headers={'Authorization':'Bearer '+bearer,'Content-Type':'application/json',**(extra or {})})
                try:
                    with urllib.request.urlopen(req) as response: return response.status
                except urllib.error.HTTPError as e: return e.code
            event = {'schema_version':1,'id':str(uuid.uuid4()),'event':'authentication_failed',
                'occurred_at':dt.datetime.now(dt.timezone.utc).isoformat().replace('+00:00','Z'), 'source_ip':'203.0.113.8'}
            try:
                self.assertEqual(send(event), 202)
                self.assertEqual(send(event), 202)
                for invalid in [dict(event,password='secret'),dict(event,module='other'),dict(event,source_ip='::1'),
                                dict(event,occurred_at='2000-01-01T00:00:00Z'),dict(event,id='not-uuid'),
                                dict(event,event='ban'),dict(event,source_ip='224.1.1.1'),dict(event,version=True)]:
                    self.assertEqual(send(invalid), 422, invalid)
                self.assertEqual(send(event,'wrong'), 401)
                # A request that came through a reverse proxy is never ingested.
                self.assertEqual(send(event, extra={'X-Forwarded-For':'198.51.100.9'}), 404)
                self.assertEqual(send(dict(event,password='x'*4096)), 413)
            finally:
                server.shutdown(); server.server_close(); thread.join()

    def test_durable_authenticated_event_is_delivered_once(self):
        hybrid = importlib.import_module('cscompanion.hybrid')
        with tempfile.TemporaryDirectory() as state:
            db = hybrid.Store(Path(state))
            token = db.add_source('gitea', 'gitea1')
            event = {'schema_version':1, 'id':'c7b575d1-1d55-47fa-8e71-e71bd0b4c7c9',
                     'occurred_at':dt.datetime.now(dt.timezone.utc).isoformat().replace('+00:00','Z'),
                     'event':'authentication_failed', 'source_ip':'2001:db8::1'}
            self.assertTrue(db.accept_event(token, event))
            self.assertFalse(hybrid.Store(Path(state)).accept_event(token, event))
            self.assertEqual(db.deliver_events(), 1)
            self.assertEqual(db.deliver_events(), 0)
            line = json.loads((Path(state)/'events/auth.jsonl').read_text())
            self.assertEqual(line['service'], 'gitea1')
            self.assertNotIn('token', line)
            db.remove_source('gitea')
            with self.assertRaises(PermissionError): db.accept_event(token, event)

class UpgradePortTests(unittest.TestCase):
    def test_legacy_two_port_instance_claims_gateway_port_before_apply(self):
        import sys, types
        actions = importlib.import_module('cscompanion.actions')
        calls = []
        fake = types.ModuleType('agent')
        fake.allocate_ports = lambda n, proto: calls.append(('alloc', n, proto)) or (20010, 20012)
        fake.mset_env = lambda env: calls.append(('env', dict(env)))
        with patch.dict(sys.modules, {'agent': fake}), patch.dict(os.environ, {'TCP_PORTS': '20001,20002'}):
            actions.ensure_gateway_port()
            self.assertEqual(os.environ['TCP_PORTS'], '20010,20011,20012')
        self.assertEqual(calls[0], ('alloc', 3, 'tcp'))
        self.assertEqual(calls[1][1]['TCP_PORTS_RANGE'], '20010-20012')
        calls.clear()
        with patch.dict(sys.modules, {'agent': fake}), patch.dict(os.environ, {'TCP_PORTS': '1,2,3'}):
            actions.ensure_gateway_port()
        self.assertEqual(calls, [])

    def test_legacy_hub_gets_local_sync_identity_and_legacy_member_changes_nothing(self):
        actions = importlib.import_module('cscompanion.actions')
        with tempfile.TemporaryDirectory() as state, patch.dict(os.environ, {'AGENT_STATE_DIR': state, 'MODULE_ID': 'csc1', 'TCP_PORTS': '1,2,3'}), \
                patch.object(actions.lifecycle, 'apply') as apply, patch.object(actions.lifecycle, 'route') as route, \
                patch.object(actions, 'ensure_gateway_port') as ports:
            common.save_config(dict(common.DEFAULTS, role='hub', hub_host='h.example.org'))
            actions.update_module({})
            route.assert_called_once()
            self.assertEqual(common.read_secret('sync_peer'), 'csc1-local')
            self.assertTrue(common.read_secret('sync_secret'))
            apply.assert_called_once()
            first = common.read_secret('sync_secret'); actions.update_module({})
            self.assertEqual(common.read_secret('sync_secret'), first)
        with tempfile.TemporaryDirectory() as state, patch.dict(os.environ, {'AGENT_STATE_DIR': state, 'MODULE_ID': 'csc1'}), \
                patch.object(actions.lifecycle, 'apply') as apply, patch.object(actions, 'ensure_gateway_port') as ports:
            common.save_config(dict(common.DEFAULTS, role='member'))
            with self.assertRaisesRegex(RuntimeError, 'Legacy'):
                actions.update_module({})
            ports.assert_not_called(); apply.assert_not_called()


if __name__ == '__main__':
    unittest.main()
