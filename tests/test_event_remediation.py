"""Event regression tests: real SQLite and loopback transport."""
import datetime as dt
import importlib.util
import json
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
import uuid
from unittest.mock import patch
from cscompanion import hybrid, gateway, actions

spec = importlib.util.spec_from_file_location('report_auth', Path(__file__).resolve().parents[1]/'sdk/report_auth.py')
sdk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sdk)


def event(age=0):
    return dict(schema_version=1, id=str(uuid.uuid4()), event='authentication_failed',
                occurred_at=dt.datetime.fromtimestamp(time.time()-age,dt.timezone.utc).isoformat().replace('+00:00','Z'),
                source_ip='203.0.113.50')


class EventTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state=Path(self.tmp.name)
        self.store=hybrid.Store(self.state/'receiver')
        self.token=self.store.add_source('app','gitea1')

    def test_identical_duplicate_survives_age_window_but_changed_identity_is_rejected(self):
        item=event()
        self.assertTrue(self.store.accept_event(self.token,item))
        with patch.object(hybrid.time,'time',return_value=time.time()+600):
            self.assertFalse(self.store.accept_event(self.token,item))
        with self.assertRaises(ValueError):
            self.store.accept_event(self.token,dict(item,source_ip='203.0.113.51'))

    def test_old_sender_entry_is_persistently_quarantined_without_blocking_next(self):
        queue=sdk.Spool(self.state/'sender'/'spool.db',limit=2)
        old=queue.enqueue('203.0.113.50')
        old['occurred_at']=event(age=7*86400+600)['occurred_at']
        with queue.connect() as db:
            db.execute('UPDATE events SET payload=? WHERE id=?',(json.dumps(old),old['id']))
            db.commit()
        fresh=queue.enqueue('203.0.113.51')
        http=gateway.server(self.store,0,False)
        worker=threading.Thread(target=http.serve_forever,daemon=True); worker.start()
        self.addCleanup(http.server_close); self.addCleanup(http.shutdown)
        self.assertEqual(queue.flush('http://127.0.0.1:%d/v1/events'%http.server_port,self.token),1)
        reopened=sdk.Spool(queue.path,limit=2)
        self.assertEqual(reopened.pending(),[])
        quarantined=reopened.quarantined()
        self.assertEqual(reopened.quarantine_count(),1)
        self.assertEqual(quarantined[0]['payload'],old)
        self.assertEqual(quarantined[0]['http_status'],422)
        self.assertEqual(quarantined[0]['reason'],'invalid_event')
        with self.store.connect() as db:
            self.assertEqual(json.loads(db.execute('SELECT body FROM events').fetchone()[0])['occurred_at'],fresh['occurred_at'])
        reopened.enqueue('203.0.113.52')
        with self.assertRaises(OverflowError): reopened.enqueue('203.0.113.53')

    def test_unready_consumer_keeps_events_pending_without_append(self):
        self.store.accept_event(self.token,event())
        self.assertEqual(self.store.deliver_events(consumer_ready=lambda:False),0)
        self.assertFalse((self.store.state/'events/auth.jsonl').exists())
        with self.store.connect() as db:
            self.assertEqual(db.execute('SELECT delivered FROM events').fetchone()[0],0)
        self.assertEqual(self.store.deliver_events(consumer_ready=lambda:True),1)

    def test_connection_limit_applies_to_incomplete_headers_before_threads(self):
        http=gateway.server(self.store,0,False,max_connections=2)
        worker=threading.Thread(target=http.serve_forever,daemon=True); worker.start()
        self.addCleanup(http.server_close); self.addCleanup(http.shutdown)
        baseline={t.ident for t in threading.enumerate()}
        sockets=[]
        for _ in range(8):
            sock=socket.create_connection(http.server_address,timeout=1)
            sockets.append(sock); self.addCleanup(sock.close)
            sock.sendall(b'POST /v1/events HTTP/1.1\r\nX-Slow: ')
        time.sleep(.15)
        handlers=[t for t in threading.enumerate() if t.ident not in baseline and 'process_request_thread' in t.name]
        self.assertLessEqual(len(handlers),2)

    def test_header_trickle_cannot_extend_total_connection_deadline(self):
        http=gateway.server(self.store,0,False,max_connections=1,request_timeout=.25)
        worker=threading.Thread(target=http.serve_forever,daemon=True); worker.start()
        self.addCleanup(http.server_close); self.addCleanup(http.shutdown)
        sock=socket.create_connection(http.server_address,timeout=1); self.addCleanup(sock.close)
        sock.sendall(b'POST /v1/events HTTP/1.1\r\nX-Slow: ')
        closed=False
        until=time.monotonic()+.8
        while time.monotonic()<until:
            time.sleep(.05)
            try:
                sock.sendall(b'x')
                sock.settimeout(.01)
                if sock.recv(1)==b'': closed=True; break
            except socket.timeout: pass
            except (ConnectionResetError,BrokenPipeError): closed=True; break
        self.assertTrue(closed,'trickled headers exceeded the total deadline')
        # Slot is released even when the deadline interrupts header parsing.
        good=socket.create_connection(http.server_address,timeout=1); self.addCleanup(good.close)
        good.sendall(b'GET / HTTP/1.0\r\n\r\n')
        self.assertIn(b'501',good.recv(4096))

    def test_failed_source_apply_rolls_back_registration_and_restores_fallback(self):
        calls=[]
        def apply(cfg):
            # A slow lifecycle call must not hold a SQLite write transaction.
            with self.store.connect() as db:
                db.execute('BEGIN IMMEDIATE')
            parser=actions.render.routers_parser({'gitea':[{'module':'gitea1'}]})
            calls.append(parser)
            if len(calls)==1: raise RuntimeError('injected apply failure')
        import io
        out=io.StringIO()
        with patch.object(actions,'state_dir',return_value=self.store.state), \
             patch.object(actions.render,'state_dir',return_value=self.store.state), \
             patch.object(actions,'load_config',return_value={}), \
             patch.object(actions.lifecycle,'apply',side_effect=apply), patch.object(actions.sys,'stdout',out):
            with self.assertRaises(RuntimeError):
                actions.add_event_source({'name':'new','module':'gitea2'})
        self.assertEqual([s['name'] for s in self.store.list_sources()],['app'])
        self.assertEqual(len(calls),2)
        self.assertEqual(out.getvalue(),'')

    def test_source_fallback_remains_enabled_until_token_output_is_flushed(self):
        import io
        store=self.store
        class Output(io.StringIO):
            def flush(output):
                self.assertFalse(any(s['name']=='new' for s in store.list_sources()))
                return super().flush()
        output=Output()
        def apply(cfg):
            parser=actions.render.routers_parser({'gitea':[{'module':'gitea2'}]})
            self.assertIn('gitea2',parser,'undelivered token must not suppress fallback')
        with patch.object(actions,'state_dir',return_value=store.state), \
             patch.object(actions.render,'state_dir',return_value=store.state), \
             patch.object(actions,'load_config',return_value={}), \
             patch.object(actions.lifecycle,'apply',side_effect=apply), \
             patch.object(actions,'source_endpoint',return_value='http://127.0.0.1:1/v1/events'), \
             patch.object(actions.sys,'stdout',output):
            actions.add_event_source({'name':'new','module':'gitea2'})
        reply=json.loads(output.getvalue())
        self.assertEqual(reply['name'],'new')
        self.assertTrue(store.known_credential('source',reply['token']))
        self.assertTrue(any(s['name']=='new' for s in store.list_sources()))

    def test_listen_receives_effective_backlog_before_accepting_connections(self):
        seen=[]
        listen=socket.socket.listen
        def capture(sock,backlog):
            seen.append(backlog)
            return listen(sock,backlog)
        with patch.object(socket.socket,'listen',capture):
            http=gateway.server(self.store,0,False)
        self.addCleanup(http.server_close)
        self.assertEqual(seen,[64])


if __name__=='__main__': unittest.main()
