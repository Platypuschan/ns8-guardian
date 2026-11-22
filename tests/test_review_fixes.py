"""Regression tests for the findings of the independent backend reviews."""
import http.client
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import unittest
import uuid
from unittest.mock import patch

from cscompanion import common, hybrid, gateway, sync


class FakeLAPI:
    """In-memory stand-in for the LAPI wrapper (decision rows as sync.LAPI.decisions returns them)."""
    def __init__(self, rows=(), refuse=()):
        self.rows = [dict(r) for r in rows]
        self.refuse = set(refuse)
        self.next = 100
        self.on_add = None

    def decisions(self):
        return [dict(r) for r in self.rows]

    def add(self, value, duration, reason):
        if self.on_add:
            self.on_add()
        if value in self.refuse:
            raise RuntimeError('cscli decisions failed: %s is allowlisted by item 1 (use --bypass-allowlist)' % value)
        self.next += 1
        self.rows.append({'id': str(self.next), 'value': value, 'expires_at': time.time() + duration,
                          'scenario': reason, 'stamp': ''})

    def delete(self, id):
        self.rows = [r for r in self.rows if str(r['id']) != str(id)]


def local(id, value, ttl=600, stamp='s'):
    return {'id': str(id), 'value': value, 'expires_at': time.time() + ttl, 'scenario': 'local', 'stamp': stamp}


def remote(id, value, origin='node2', ttl=600, deleted=False, seq=1):
    return {'origin': origin, 'id': str(id), 'value': value, 'expires_at': time.time() + ttl, 'deleted': deleted, 'seq': seq}


class SyncReviewTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = hybrid.Store(Path(self.tmp.name))

    def tearDown(self):
        self.tmp.cleanup()

    def test_unshareable_local_decisions_never_block_sync(self):
        lapi = FakeLAPI([local(1, '127.0.0.1'), local(2, '::ffff:198.51.100.7'), local(3, 'fe80::1'), local(4, '203.0.113.5')])
        client = sync.Client(self.store, lapi, 'node1')
        client.reconcile([])
        sent = client.pending()
        self.assertEqual(sorted(c['value'] for c in sent), ['198.51.100.7', '203.0.113.5'])
        token = self.store.add_peer('node1')
        reply = self.store.exchange(token, {'cursor': 0, 'updates': sent})
        self.assertEqual(reply['rejected'], [])

    def test_hub_rejects_only_the_unusable_claim_and_client_stops_resending_it(self):
        token = self.store.add_peer('node1')
        client = sync.Client(hybrid.Store(Path(self.tmp.name + '/c')), FakeLAPI(), 'node1')
        good = {'id': '1', 'value': '203.0.113.5', 'expires_at': time.time() + 60, 'deleted': False}
        bad = {'id': '2', 'value': '127.0.0.1', 'expires_at': time.time() + 60, 'deleted': False}
        reply = self.store.exchange(token, {'cursor': 0, 'updates': [bad, good]})
        self.assertEqual(reply['rejected'], ['2'])
        self.assertEqual([c['id'] for c in reply['changes']], ['1'])
        with client.store.connect() as db:
            for c in (bad, good):
                db.execute('INSERT INTO local_claims(id,lapi_id,value,expires_at) VALUES(?,?,?,?)', (c['id'], c['id'], c['value'], c['expires_at']))
        client.receive(dict(reply, cursor=reply['cursor']), sent=[good])
        self.assertEqual(client.pending(), [])  # the rejected claim is not retried forever

    def test_lapi_allowlist_refusal_suppresses_one_claim_and_imports_the_rest(self):
        lapi = FakeLAPI(refuse={'203.0.113.200'})
        client = sync.Client(self.store, lapi, 'node1')
        client.receive({'cursor': 2, 'changes': [remote(1, '203.0.113.200', seq=1), remote(2, '203.0.113.201', seq=2)]})
        client.reconcile([])  # must not raise
        self.assertEqual([r['value'] for r in lapi.rows], ['203.0.113.201'])
        client.reconcile([])
        self.assertEqual(len(lapi.rows), 1)  # the refused claim stays suppressed

    def test_other_cscli_failure_is_reported_but_other_claims_still_imported(self):
        lapi = FakeLAPI()
        original = lapi.add
        def flaky(value, duration, reason):
            if value == '203.0.113.200':
                raise RuntimeError('cscli decisions failed: connection refused')
            return original(value, duration, reason)
        lapi.add = flaky
        client = sync.Client(self.store, lapi, 'node1')
        client.receive({'cursor': 2, 'changes': [remote(1, '203.0.113.200', seq=1), remote(2, '203.0.113.201', seq=2)]})
        with self.assertRaises(RuntimeError):
            client.reconcile([])
        self.assertEqual([r['value'] for r in lapi.rows], ['203.0.113.201'])

    def test_no_database_lock_is_held_while_the_lapi_is_called(self):
        lapi = FakeLAPI()
        client = sync.Client(self.store, lapi, 'node1')
        client.receive({'cursor': 1, 'changes': [remote(1, '203.0.113.200')]})
        started = time.monotonic()
        def concurrent_writer():
            conn = sqlite3.connect(self.store.path, timeout=0.2)
            try:
                conn.execute("UPDATE meta SET value=value WHERE key='sequence'")
                conn.commit()
            finally:
                conn.close()
        lapi.on_add = concurrent_writer  # raises OperationalError if reconcile still holds the write lock
        client.reconcile([])
        self.assertLess(time.monotonic() - started, 5)

    def test_private_ranges_and_lan_are_never_enforced_from_remote_claims(self):
        lapi = FakeLAPI()
        client = sync.Client(self.store, lapi, 'node1')
        client.receive({'cursor': 2, 'changes': [remote(1, '10.1.2.3', seq=1), remote(2, '192.168.1.1', seq=2),
                                                 remote(3, '203.0.113.9', seq=3)]})
        client.reconcile([])
        self.assertEqual([r['value'] for r in lapi.rows], ['203.0.113.9'])

    def test_per_origin_import_quota_protects_other_origins(self):
        client = sync.Client(self.store, FakeLAPI(), 'node1')
        flood = [dict(remote(i, '203.0.%d.%d' % (i // 250, i % 250 + 1), origin='noisy', seq=i)) for i in range(1, 300)]
        with patch.object(sync, 'MAX_IMPORTS_PER_ORIGIN', 50):
            for i in range(0, len(flood), 100):
                client.receive({'cursor': i + 100, 'changes': flood[i:i + 100]})
            client.receive({'cursor': 400, 'changes': [remote(1, '198.51.100.1', origin='polite', seq=400)]})
        with client.store.connect() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM imports WHERE origin='noisy'").fetchone()[0], 50)
            self.assertEqual(db.execute("SELECT count(*) FROM imports WHERE origin='polite'").fetchone()[0], 1)

    def test_cursor_never_moves_backwards_unless_the_hub_epoch_changed(self):
        client = sync.Client(self.store, FakeLAPI(), 'node1')
        client.receive({'cursor': 10, 'changes': [], 'epoch': 'a'})
        with self.assertRaises(ValueError):
            client.receive({'cursor': 3, 'changes': [], 'epoch': 'a'})
        self.assertEqual(client.cursor(), 10)
        client.receive({'cursor': 3, 'changes': [], 'epoch': 'b'})  # restored hub: start over
        self.assertEqual(client.cursor(), 0)

    def test_restored_hub_gets_a_new_epoch_and_clamps_future_cursors(self):
        token = self.store.add_peer('node1')
        first = self.store.exchange(token, {'cursor': 0, 'updates': []})
        self.store.new_epoch()
        self.assertNotEqual(self.store.exchange(token, {'cursor': 0, 'updates': []})['epoch'], first['epoch'])
        c = {'id': '1', 'value': '203.0.113.5', 'expires_at': time.time() + 60, 'deleted': False}
        self.store.exchange(token, {'cursor': 0, 'updates': [c]})
        reply = self.store.exchange(token, {'cursor': 10 ** 9, 'updates': []})
        self.assertEqual([x['id'] for x in reply['changes']], ['1'])  # clamped to 0, not silently skipped

    def test_reused_lapi_decision_ids_become_new_claims(self):
        lapi = FakeLAPI([local(1, '203.0.113.5', stamp='before')])
        client = sync.Client(self.store, lapi, 'node1')
        client.reconcile([])
        first = client.pending()
        self.assertEqual(len(first), 1)
        lapi.rows = [local(1, '203.0.113.77', stamp='after-reset')]  # LAPI database was rebuilt
        client.reconcile([])
        pending = {c['value']: c['deleted'] for c in client.pending()}
        self.assertEqual(pending, {'203.0.113.5': True, '203.0.113.77': False})

    def test_per_peer_claim_quota_leaves_room_for_other_peers(self):
        a, b = self.store.add_peer('node1'), self.store.add_peer('node2')
        with patch.object(hybrid, 'MAX_PEER_CLAIMS', 3):
            ups = [{'id': str(i), 'value': '203.0.113.%d' % i, 'expires_at': time.time() + 60, 'deleted': False} for i in range(1, 8)]
            reply = self.store.exchange(a, {'cursor': 0, 'updates': ups})
            self.assertEqual(reply['rejected'], ['4', '5', '6', '7'])
            ok = self.store.exchange(b, {'cursor': 0, 'updates': [dict(ups[0], id='1')]})
            self.assertEqual(ok['rejected'], [])

    def test_expired_claims_free_journal_space(self):
        token = self.store.add_peer('node1')
        with self.store.connect() as db:
            db.execute("INSERT INTO claims VALUES('node1','9','203.0.113.5',?,0,1)", (time.time() - 3600,))
        self.store.exchange(token, {'cursor': 0, 'updates': []})
        with self.store.connect() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM claims').fetchone()[0], 0)


class EventReviewTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = hybrid.Store(Path(self.tmp.name))

    def tearDown(self):
        self.tmp.cleanup()

    @staticmethod
    def event(ip='203.0.113.8'):
        import datetime as dt
        return {'schema_version': 1, 'id': str(uuid.uuid4()), 'event': 'authentication_failed', 'source_ip': ip,
                'occurred_at': dt.datetime.now(dt.timezone.utc).isoformat().replace('+00:00', 'Z')}

    def test_delivery_is_fast_on_a_large_log_and_repairs_a_torn_line(self):
        directory = Path(self.tmp.name) / 'events'
        directory.mkdir(exist_ok=True)
        log = directory / 'auth.jsonl'
        log.write_text('{"x":1}\n' * 200000 + '{"torn":')
        token = self.store.add_source('app', 'gitea1')
        for _ in range(256):
            self.store.accept_event(token, self.event())
        started = time.monotonic()
        self.assertEqual(self.store.deliver_events(), 256)
        self.assertLess(time.monotonic() - started, 2)
        lines = log.read_text().splitlines()
        self.assertEqual(len(lines), 200000 + 1 + 256)
        self.assertEqual(lines[200000], '{"torn":')  # torn fragment stays isolated on its own line
        self.assertTrue(all(json.loads(l)['event'] == 'authentication_failed' for l in lines[-256:]))

    def test_crash_between_append_and_commit_does_not_duplicate(self):
        token = self.store.add_source('app', 'gitea1')
        self.store.accept_event(token, self.event())
        self.assertEqual(self.store.deliver_events(), 1)
        with self.store.connect() as db:
            db.execute('UPDATE events SET delivered=0')  # the commit that marks delivery was lost
        self.assertEqual(self.store.deliver_events(), 0)
        log = Path(self.tmp.name) / 'events/auth.jsonl'
        self.assertEqual(len(log.read_text().splitlines()), 1)

    def test_one_source_cannot_fill_the_queue_for_everyone(self):
        a, b = self.store.add_source('a', 'app-a'), self.store.add_source('b', 'app-b')
        with patch.object(hybrid, 'MAX_SOURCE_EVENTS', 5):
            for _ in range(5):
                self.store.accept_event(a, self.event())
            with self.assertRaises(OverflowError):
                self.store.accept_event(a, self.event())
            self.assertTrue(self.store.accept_event(b, self.event()))

    def test_timestamp_must_be_strict_rfc3339(self):
        token = self.store.add_source('app', 'gitea1')
        for bad in (self.event() | {'occurred_at': self.event()['occurred_at'][:-1] + '\x00Z'},
                    self.event() | {'occurred_at': ' ' + self.event()['occurred_at']},
                    self.event() | {'source_ip': '203.0.113.255'} | {'source_ip': '255.255.255.255'}):
            with self.assertRaises(ValueError):
                self.store.accept_event(token, bad)


class GatewayReviewTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = hybrid.Store(Path(self.tmp.name))
        self.server = gateway.server(self.store, 0, True)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.tmp.cleanup()

    def post(self, body, token, path='/v1/sync'):
        conn = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=10)
        conn.request('POST', path, body, {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token,
                                          'Content-Length': str(len(body))})
        status = conn.getresponse().status
        conn.close()
        return status

    def test_deeply_nested_json_is_a_400_for_peers_and_never_parsed_for_strangers(self):
        token = self.store.add_peer('node1')
        bomb = b'[' * 100000
        self.assertEqual(self.post(bomb[:60000], token), 400)
        self.assertEqual(self.post(bomb[:60000], 'not-a-token'), 401)

    def test_sqlite_busy_is_a_503_not_a_dropped_connection(self):
        token = self.store.add_peer('node1')
        with patch.object(self.store, 'exchange', side_effect=sqlite3.OperationalError('database is locked')):
            self.assertEqual(self.post(b'{"cursor":0,"updates":[]}', token), 503)

    def test_connection_slots_are_bounded(self):
        self.server.shutdown(); self.server.server_close()
        self.server = gateway.server(self.store, 0, True, max_connections=1)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        token = self.store.add_peer('node1')
        import socket
        hog = socket.create_connection(('127.0.0.1', self.server.server_port))
        hog.sendall(b'POST /v1/sync HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 100\r\n'
                    b'Authorization: Bearer ' + token.encode() + b'\r\n\r\n')  # body never arrives
        time.sleep(0.3)
        try:
            self.assertEqual(self.post(b'{"cursor":0,"updates":[]}', token), 503)
        finally:
            hog.close()


class ActionReviewTests(unittest.TestCase):
    def test_local_peer_recovery_after_a_crash_between_database_and_secret(self):
        from cscompanion import actions
        with tempfile.TemporaryDirectory() as state, patch.dict(os.environ, {'AGENT_STATE_DIR': state, 'MODULE_ID': 'csc9'}):
            hybrid.Store(Path(state)).add_peer('csc9-local')  # database written, secret never stored
            actions.ensure_local_peer()
            token = common.read_secret('sync_secret')
            self.assertTrue(token)
            self.assertEqual(hybrid.Store(Path(state)).exchange(token, {'cursor': 0, 'updates': []})['rejected'], [])

    def test_restore_database_issues_a_new_hub_epoch(self):
        from cscompanion import lifecycle
        with tempfile.TemporaryDirectory() as state, patch.dict(os.environ, {'AGENT_STATE_DIR': state}):
            lifecycle.prepare_dirs()
            store = hybrid.Store(Path(state))
            before = store.epoch()
            lifecycle.dump_database()
            lifecycle.restore_database()
            self.assertNotEqual(hybrid.Store(Path(state)).epoch(), before)

    def test_state_directory_and_event_log_permissions_are_repaired(self):
        from cscompanion import lifecycle
        with tempfile.TemporaryDirectory() as state, patch.dict(os.environ, {'AGENT_STATE_DIR': state}):
            os.chmod(state, 0o755)
            lifecycle.prepare_dirs()
            log = Path(state) / 'events/auth.jsonl'
            os.chmod(log, 0o666)
            lifecycle.prepare_dirs()
            self.assertEqual(log.stat().st_mode & 0o777, 0o600)
            hybrid.Store(Path(state))
            self.assertEqual(Path(state).stat().st_mode & 0o777, 0o700)


if __name__ == '__main__':
    unittest.main()
