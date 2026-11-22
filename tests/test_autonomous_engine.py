"""Rootless real Engine + nftables tests. All firewall work is inside a
--network none Podman namespace; never host nft/network operations.
Run: CROWDSEC_TEST_IMAGE=localhost/ns8-hybrid-engine:working PYTHONPATH=imageroot/pypkg python3 tests/test_autonomous_engine.py
"""
import datetime as dt
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
import uuid
from unittest.mock import patch
from cscompanion import common, render, hybrid, sync

IMAGE=os.environ.get('CROWDSEC_TEST_IMAGE',os.environ.get('HYBRID_ENGINE_IMAGE','localhost/ns8-hybrid-engine:working'))
BOUNCER=os.environ.get('BOUNCER_IMAGE','ghcr.io/nethserver/crowdsec-firewall-bouncer:1.4.0')
ROOT=Path(__file__).resolve().parents[1]


def run(*args,check=True):
    p=subprocess.run(args,text=True,capture_output=True,timeout=180)
    if check and p.returncode: raise AssertionError('command failed '+str(args[:4])+'\n'+p.stdout+'\n'+p.stderr)
    return p


def wait(fn,timeout=60):
    until=time.monotonic()+timeout
    while time.monotonic()<until:
        if fn(): return
        time.sleep(1)
    raise AssertionError('timed out waiting for '+str(fn))


class PodmanLAPI(sync.LAPI):
    def __init__(self,name): self.name=name
    def decisions(self):
        from cscompanion import lifecycle
        with patch.dict(os.environ,{'MODULE_ID':self.name}): return super().decisions()
    def add(self,value,duration,reason):
        with patch.dict(os.environ,{'MODULE_ID':self.name}): return super().add(value,duration,reason)
    def delete(self,id):
        with patch.dict(os.environ,{'MODULE_ID':self.name}): return super().delete(id)


@unittest.skipUnless(os.environ.get('RUN_ENGINE_TESTS')=='1','set RUN_ENGINE_TESTS=1 for isolated rootless Podman')
class EngineTests(unittest.TestCase):
    def test_reconnect_sync_keeps_local_claim_and_removes_only_import_then_ipv6_ttl_allowlist(self):
        a,an,al=self.engine('origin',41401)
        b,bn,bl=self.engine('member',41411)
        controller=hybrid.Store(self.state/'controller')
        at=controller.add_peer('origin'); bt=controller.add_peer('member')
        ca=sync.Client(hybrid.Store(a),al,'origin'); cb=sync.Client(hybrid.Store(b),bl,'member')
        al.add('203.0.113.90',150,'source-local')
        bl.add('203.0.113.90',300,'independent-local')
        ca.reconcile([]); cb.reconcile([])
        def exchange(client,token):
            sent=client.pending(); reply=controller.exchange(token,{'cursor':client.cursor(),'updates':sent}); client.receive(reply,sent); client.reconcile([])
        exchange(ca,at); exchange(cb,bt)
        imported=[r for r in bl.decisions() if r['scenario'].startswith(sync.PREFIX)]
        self.assertEqual(len(imported),1)
        self.assertEqual(len(bl.decisions()),2)
        imported_id=imported[0]['id']; expiry=imported[0]['expires_at']
        exchange(cb,bt)
        same=[r for r in bl.decisions() if r['id']==imported_id]
        self.assertEqual(len(same),1)
        self.assertLessEqual(same[0]['expires_at'],expiry+1)
        # Origin unban creates tombstone, separate member-local claim survives.
        original=[r for r in al.decisions() if not r['scenario'].startswith(sync.PREFIX)][0]
        al.delete(original['id']); ca.reconcile([]); exchange(ca,at); exchange(cb,bt)
        self.assertFalse(any(r['id']==imported_id for r in bl.decisions()))
        self.assertTrue(any(r['scenario']=='independent-local' for r in bl.decisions()))
        # Real IPv6 decision, local allowlist and absolute TTL (not renewed).
        al.add('2001:db8::55',15,'ipv6-local'); ca.reconcile([]); exchange(ca,at); exchange(cb,bt)
        self.assertTrue(any(r['value']=='2001:db8::55' for r in bl.decisions()))
        cb.reconcile(['2001:db8::/48'])
        self.assertFalse(any(r['value']=='2001:db8::55' for r in bl.decisions()))
        # Removing allowlist can restore the still-live original claim; no TTL renewal.
        cb.reconcile([])
        wait(lambda:not any(r['value']=='2001:db8::55' for r in bl.decisions()),timeout=25)
        # Real LAPI allowlists prevent event-derived decisions too.
        run('podman','exec',bn,'cscli','allowlists','create','test-allowlist','--description','test')
        run('podman','exec',bn,'cscli','allowlists','add','test-allowlist','198.51.100.0/24')
        self.attack(b,'198.51.100.7'); time.sleep(5)
        self.assertFalse(any(r['value']=='198.51.100.7' for r in bl.decisions()))
        print('PASS reconnect imports without renewal/echo, origin unban preserves independent local ban, IPv6 TTL and local allowlist')
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.state=Path(self.tmp.name)
        self.prefix='hybrid-'+uuid.uuid4().hex[:10]; self.containers=[]
        self.tools=self.prefix+'-tools'
        self.start(self.tools,'--network','none','--cap-add','NET_ADMIN','localhost/cscompanion-e2e-tools','sleep','infinity')
        self.ns='container:'+self.tools

    def start(self,name,*args):
        self.containers.append(name)
        run('podman','run','-d','--name',name,*args)

    def tearDown(self):
        if True:
            for name in self.containers:
                result=run('podman','logs','--tail','30',name,check=False)
                print(name,result.stdout+result.stderr)
        for name in reversed(self.containers): run('podman','rm','-f',name,check=False)
        self.tmp.cleanup()

    def engine(self,label,port):
        state=self.state/label; state.mkdir(); (state/'crowdsec_data').mkdir(); (state/'events').mkdir()
        (state/'events/auth.jsonl').touch(); (state/'events/traefik.log').touch()
        cfg=dict(common.DEFAULTS,role='member',hub_url='https://controller.invalid/',ban_duration='2h')
        with patch.dict(os.environ,{'AGENT_STATE_DIR':str(state),'TCP_PORTS':f'{port},{port+1},{port+2}'}):
            common.secret('bouncer_key')
            render.render_all(cfg,label,state,root='/nonexistent')
        conf=state/'crowdsec_config'
        (conf/'acquis.yaml').write_text(json.dumps({'source':'file','filenames':['/events/auth.jsonl'], 'labels':{'type':'ns8_auth_event'}})+'\n---\n'+json.dumps({'source':'file','filenames':['/events/traefik.log'],'labels':{'type':'syslog','ns8_source':'traefik'}}))
        (conf/'local_api_credentials.yaml.local').write_text(json.dumps({'url':f'http://127.0.0.1:{port}/'}))
        (conf/'parsers/s02-enrich/ns8-router-apps.yaml').write_text(render.routers_parser({'gitea':[{'module':'gitea1'}]}))
        name=self.prefix+'-'+label
        self.start(name,'--network',self.ns,'--env-file',str(state/'crowdsec.env'),
            '-v',str(conf)+':/etc/crowdsec','-v',str(state/'crowdsec_data')+':/var/lib/crowdsec/data',
            '-v',str(state/'events')+':/events:ro','--entrypoint','/bin/bash',
            '-v',str(state/'offline-start.sh')+':/offline-start.sh:ro',IMAGE,'/offline-start.sh')
        wait(lambda:run('podman','exec',name,'cscli','lapi','status',check=False).returncode==0)
        wait(lambda:'Starting processing data' in (run('podman','logs',name).stdout+run('podman','logs',name).stderr))
        return state,name,PodmanLAPI(name)

    def bouncer(self,state,name):
        # Keep a short test poll, same production binary/config otherwise.
        conf=json.loads((state/'crowdsec_config/bouncer.yaml').read_text()); conf['update_frequency']='1s'
        (state/'crowdsec_config/bouncer.yaml').write_text(json.dumps(conf))
        bname=name+'-bouncer'
        self.start(bname,'--network',self.ns,'--cap-drop','all','--cap-add','NET_ADMIN','--cap-add','NET_RAW',
            '-v',str(state/'crowdsec_config/bouncer.yaml')+':/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml:ro',BOUNCER)
        return bname

    def attack(self,state,ip):
        store=hybrid.Store(state)
        token=store.add_source('app','gitea1')
        for i in range(6):
            store.accept_event(token,{'schema_version':1,'id':str(uuid.uuid4()),'event':'authentication_failed',
                'occurred_at':dt.datetime.now(dt.timezone.utc).isoformat().replace('+00:00','Z'),'source_ip':ip})
        self.assertEqual(store.deliver_events(),6)

    def test_engine_down_gap_retains_queue_then_creates_real_decision(self):
        state,name,lapi=self.engine('gap',41421)
        store=hybrid.Store(state)
        ready=lambda:store.event_consumer_ready(name,'/events/auth.jsonl')
        wait(ready)
        run('podman','stop',name)
        token=store.add_source('app','gitea1')
        for _ in range(6):
            store.accept_event(token,{'schema_version':1,'id':str(uuid.uuid4()),'event':'authentication_failed',
                'occurred_at':dt.datetime.now(dt.timezone.utc).isoformat().replace('+00:00','Z'),'source_ip':'203.0.113.77'})
        self.assertFalse(ready())
        self.assertEqual(store.deliver_events(consumer_ready=ready),0)
        with store.connect() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM events WHERE delivered=0').fetchone()[0],6)
        self.assertEqual((state/'events/auth.jsonl').stat().st_size,0)
        run('podman','start',name)
        wait(ready)
        self.assertEqual(store.deliver_events(consumer_ready=ready),6)
        wait(lambda:any(d['value']=='203.0.113.77' for d in lapi.decisions()))
        print('PASS real stopped Engine gap: six entries pending, replay after acquisition readiness -> real ban; no crash-window exactly-once claim')

    def test_rotation_waits_for_new_inode_before_replaying_real_events(self):
        state,name,lapi=self.engine('rotation',41431)
        store=hybrid.Store(state)
        ready=lambda:store.event_consumer_ready(name,'/events/auth.jsonl')
        probe_drained=store.event_consumer_drained
        drained=lambda:probe_drained(name,'/events/auth.jsonl')
        wait(ready)
        path=state/'events/auth.jsonl'
        with path.open('ab') as output:
            output.write(b'\n'*4096)
            output.flush()
            os.fsync(output.fileno())
        wait(drained)
        old_inode=path.stat().st_ino
        token=store.add_source('app','gitea1')
        for _ in range(6):
            store.accept_event(token,{'schema_version':1,'id':str(uuid.uuid4()),'event':'authentication_failed',
                'occurred_at':dt.datetime.now(dt.timezone.utc).isoformat().replace('+00:00','Z'),'source_ip':'203.0.113.78'})
        # Small threshold exercises the production rotation path, not a 32MiB load test.
        with patch.object(store,'EVENT_LOG_LIMIT',1024), patch.object(store,'event_consumer_drained',side_effect=drained):
            self.assertEqual(store.deliver_events(ready),0)
        self.assertNotEqual(path.stat().st_ino,old_inode)
        self.assertEqual(path.stat().st_size,0)
        with store.connect() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM events WHERE delivered=0').fetchone()[0],6)
        wait(ready)
        self.assertEqual(store.deliver_events(ready),6)
        wait(lambda:any(d['value']=='203.0.113.78' for d in lapi.decisions()))
        print('PASS real rotation: old EOF checked, new inode acquired before six pending events -> ban')

    def test_offline_auth_events_create_real_decision_and_packet_drop_after_restart(self):
        state,name,lapi=self.engine('member',41381)
        bname=self.bouncer(state,name)
        run('podman','exec',self.tools,'sh','-ec', 'ip link set lo up; ip addr add 203.0.113.50/32 dev lo; (while true; do nc -l -p 9000 -s 127.0.0.1 >/dev/null 2>&1; done) &')
        probe=lambda:run('podman','exec',self.tools,'sh','-c','echo x | nc -w 2 -s 203.0.113.50 127.0.0.1 9000',check=False).returncode==0
        self.assertTrue(probe())
        self.attack(state,'203.0.113.50')
        wait(lambda:any(d['value']=='203.0.113.50' for d in lapi.decisions()))
        wait(lambda:'203.0.113.50' in run('podman','exec',self.tools,'nft','list','ruleset').stdout)
        self.assertFalse(probe())
        run('podman','stop',bname)
        run('podman','restart',name)
        wait(lambda:run('podman','exec',name,'cscli','lapi','status',check=False).returncode==0)
        run('podman','start',bname)
        wait(lambda:'203.0.113.50' in run('podman','exec',self.tools,'nft','list','ruleset').stdout)
        self.assertFalse(probe())
        print('PASS offline event -> real local decision -> packet drop; engine+bouncer restart without controller')

if __name__=='__main__': unittest.main(verbosity=2)
