"""S1-S5 deterministic production Store/Client regressions; in-memory LAPI, not engine E2E."""
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from cscompanion import hybrid, sync


class MemoryLAPI:
    def __init__(self):
        self.rows = []
        self.counter = 0

    def decisions(self):
        return list(self.rows)

    def add(self, value, duration, reason):
        self.counter += 1
        self.rows.append(dict(id=str(self.counter), value=value,
                              expires_at=time.time()+duration, scenario=reason))

    def delete(self, id):
        self.rows = [r for r in self.rows if r['id'] != str(id)]


class SyncRemediationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.hub = hybrid.Store(self.root/'hub')
        self.token = self.hub.add_peer('node1')
        self.expiry = time.time()+600

    def claim(self, id, **kwargs):
        return dict(id=str(id), value='203.0.113.8', expires_at=self.expiry,
                    deleted=False, **kwargs)

    def exchange(self, updates, token=None, cursor=0):
        return self.hub.exchange(token or self.token, dict(cursor=cursor, updates=updates))

    def client(self, name='node1'):
        return sync.Client(hybrid.Store(self.root/name), MemoryLAPI(), name)

    def test_s2_tombstones_consume_origin_budget_without_blocking_other_peer(self):
        other = self.hub.add_peer('node2')
        with patch.object(hybrid, 'MAX_PEER_CLAIMS', 2), patch.object(hybrid, 'MAX_CLAIMS', 4):
            self.exchange([dict(self.claim(i), deleted=True) for i in range(2)])
            reply = self.exchange([dict(self.claim(2), deleted=True)])
            self.assertEqual(reply.get('retryable'), ['2'])
            self.exchange([self.claim(3)], other)
        with self.hub.connect() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM claims WHERE origin=?', ('node1',)).fetchone()[0], 2)
            self.assertEqual(db.execute('SELECT count(*) FROM claims WHERE origin=?', ('node2',)).fetchone()[0], 1)

    def test_s3_nonempty_upload_collects_expired_journal_before_admission(self):
        with patch.object(hybrid, 'MAX_PEER_CLAIMS', 1), patch.object(hybrid, 'MAX_CLAIMS', 1):
            self.exchange([self.claim(1)])
            with patch.object(hybrid.time, 'time', return_value=self.expiry+61):
                fresh = dict(self.claim(2), expires_at=self.expiry+300)
                reply = self.exchange([fresh])
            self.assertEqual(reply.get('retryable'), [])
            self.assertEqual([c['id'] for c in reply['changes']], ['2'])

    def test_s5_quota_rejection_retries_fairly_after_capacity_returns(self):
        client = self.client()
        with client.store.connect() as db:
            for i in range(5):
                db.execute('INSERT INTO local_claims(id,value,expires_at) VALUES(?,?,?)',
                           (str(i), '203.0.113.8', self.expiry if i else self.expiry-300))
        with patch.object(sync, 'BATCH', 2), patch.object(hybrid, 'MAX_PEER_CLAIMS', 1):
            sent = client.pending()
            client.receive(self.exchange(sent), sent)
            with client.store.connect() as db:
                self.assertEqual(db.execute("SELECT pending FROM local_claims WHERE id='1'").fetchone()[0], 1)
            # Deferred quota failures must not occupy the next batch's head.
            self.assertEqual([c['id'] for c in client.pending()], ['2', '3'])
            sent = client.pending()
            client.receive(self.exchange(sent), sent)
            self.assertEqual([c['id'] for c in client.pending()], ['4'])
            sent = client.pending()
            client.receive(self.exchange(sent), sent)
            # Same durable queue survives restart and eventually retries.
            client = sync.Client(client.store, client.lapi, 'node1')
            with patch.object(sync.time, 'time', return_value=self.expiry-299):
                sent = client.pending()
                self.assertTrue(sent)
                reply = self.exchange(sent)
                client.receive(reply, sent)
                self.assertEqual(reply['retryable'], [sent[1]['id']])
                self.assertEqual(reply['rejected'], reply['retryable'])
            with client.store.connect() as db:
                self.assertEqual(db.execute('SELECT pending FROM local_claims WHERE id=?', (sent[0]['id'],)).fetchone()[0], 0)

    def test_s1_epoch_restore_republishes_acknowledged_local_tombstone(self):
        client = self.client()
        client.lapi.add('203.0.113.8', 600, 'local')
        client.reconcile([])
        sent = client.pending()
        client.receive(self.exchange(sent), sent)
        snapshot = sqlite3.connect(self.root/'snapshot.db')
        self.addCleanup(snapshot.close)
        with self.hub.connect() as db:
            db.backup(snapshot)
        client.lapi.rows.clear()
        client.reconcile([])
        sent = client.pending()
        self.assertTrue(sent[0]['deleted'])
        client.receive(self.exchange(sent, cursor=client.cursor()), sent)
        self.assertEqual(client.pending(), [])
        with self.hub.connect() as db:
            snapshot.backup(db)
        self.hub.new_epoch()
        client.receive(self.exchange([], cursor=client.cursor()))
        restored = client.pending()
        self.assertEqual(restored, sent)
        # The restored ban must be revoked before a fresh observer enforces it.
        client.receive(self.exchange(restored, cursor=client.cursor()), restored)
        observer = self.client('observer')
        token = self.hub.add_peer('observer')
        observer.receive(self.exchange([], token))
        observer.reconcile([])
        self.assertEqual(observer.lapi.rows, [])

    def test_s4_import_quota_rescans_after_capacity_frees_without_origin_starvation(self):
        self.exchange([dict(self.claim(1), deleted=True, expires_at=self.expiry-300), self.claim(2)])
        token2 = self.hub.add_peer('node2')
        self.exchange([self.claim(3)], token2)
        observer = self.client('observer')
        token = self.hub.add_peer('observer')
        with patch.object(sync, 'MAX_IMPORTS_PER_ORIGIN', 1), patch.object(sync, 'MAX_IMPORTS', 2), \
                patch.object(hybrid, 'BATCH', 2), patch.object(sync, 'BATCH', 2):
            observer.receive(self.exchange([], token, observer.cursor()))
            self.assertEqual(observer.cursor(), 2)  # continue past the saturated origin
            observer.receive(self.exchange([], token, observer.cursor()))
            observer.reconcile([])
            self.assertEqual(len(observer.lapi.rows), 1)  # node2 was not starved
            self.assertEqual(observer.cursor(), 0)  # skipped work is not permanently ACKed
            observer = sync.Client(observer.store, observer.lapi, 'observer')
            with patch.object(sync.time, 'time', return_value=self.expiry-299):
                observer.receive(self.exchange([], token, observer.cursor()))
                observer.receive(self.exchange([], token, observer.cursor()))
                observer.reconcile([])
            with observer.store.connect() as db:
                self.assertEqual({(r['origin'], r['id']) for r in db.execute('SELECT * FROM imports')},
                                 {('node1', '2'), ('node2', '3')})
                self.assertEqual(db.execute("SELECT value FROM meta WHERE key='import_overload'").fetchone()[0], '0')
            self.assertEqual(len(observer.lapi.rows), 2)

    def test_s5_quota_rejections_keep_legacy_id_list_with_retry_classification(self):
        with patch.object(hybrid, 'MAX_PEER_CLAIMS', 1):
            self.exchange([self.claim(1)])
            reply = self.exchange([self.claim(2)])
        self.assertEqual(reply['rejected'], ['2'])
        self.assertEqual(reply['retryable'], ['2'])

    def test_s3_local_journal_collects_expired_pending_before_new_admission(self):
        client = self.client()
        with client.store.connect() as db:
            db.execute('INSERT INTO local_claims(id,value,expires_at,deleted) VALUES(?,?,?,1)',
                       ('1', '203.0.113.8', time.time()-1))
        client.lapi.add('198.51.100.8', 600, 'local')
        with patch.object(sync, 'MAX_IMPORTS', 1):
            client.reconcile([])
        self.assertEqual([c['value'] for c in client.pending()], ['198.51.100.8'])

    def test_s5_full_local_journal_still_exports_revocations_and_retries_new_bans(self):
        client = self.client()
        client.lapi.add('203.0.113.8', 300, 'local')
        with patch.object(sync, 'MAX_IMPORTS', 1):
            client.reconcile([])
            first = client.pending()[0]
            client.lapi.rows.clear()
            client.lapi.add('198.51.100.8', 600, 'local')
            client.reconcile([])
            self.assertEqual(client.pending(), [dict(first, deleted=True)])
            with client.store.connect() as db:
                self.assertEqual(db.execute('SELECT count(*) FROM local_claims').fetchone()[0], 1)
                self.assertEqual(db.execute("SELECT value FROM meta WHERE key='local_export_overload'").fetchone()[0], '1')
            with patch.object(sync.time, 'time', return_value=first['expires_at']+1):
                client.reconcile([])
            self.assertEqual([c['value'] for c in client.pending()], ['198.51.100.8'])

    def test_s2_revocation_collects_expired_rows_but_retains_relevant_tombstones(self):
        self.exchange([dict(self.claim(1), expires_at=self.expiry-300), self.claim(2)])
        with patch.object(hybrid.time, 'time', return_value=self.expiry-299):
            self.hub.remove_peer('node1')
        with self.hub.connect() as db:
            rows = [dict(r) for r in db.execute('SELECT * FROM claims')]
        self.assertEqual([r['id'] for r in rows], ['2'])
        self.assertTrue(rows[0]['deleted'])
        other = self.hub.add_peer('node2')
        self.assertEqual(self.exchange([], other)['changes'][0]['id'], '2')
        with self.assertRaises(PermissionError):
            self.exchange([])

    def test_s5_old_permanent_rejection_does_not_ack_newer_local_tombstone(self):
        client = self.client()
        with client.store.connect() as db:
            db.execute('INSERT INTO local_claims(id,value,expires_at) VALUES(?,?,?)',
                       ('1', '203.0.113.8', self.expiry))
        sent = client.pending()
        with client.store.connect() as db:
            db.execute("UPDATE local_claims SET deleted=1,pending=1 WHERE id='1'")
        client.receive(dict(cursor=0, changes=[], rejected=['1']), sent)
        self.assertEqual(client.pending(), [dict(sent[0], deleted=True)])

    def test_s2_real_limits_bound_tombstone_flood_and_allow_other_origin(self):
        rejected = 0
        total = hybrid.MAX_CLAIMS+1
        for start in range(0, total, hybrid.BATCH):
            reply = self.exchange([dict(self.claim(i), deleted=True)
                                   for i in range(start, min(start+hybrid.BATCH, total))])
            rejected += len(reply['retryable'])
        with self.hub.connect() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM claims').fetchone()[0], hybrid.MAX_PEER_CLAIMS)
        self.assertEqual(rejected, total-hybrid.MAX_PEER_CLAIMS)
        token = self.hub.add_peer('node2')
        self.assertEqual(self.exchange([self.claim(1)], token)['rejected'], [])

    def test_s2_global_full_batch_still_accepts_existing_revocation(self):
        with patch.object(hybrid, 'MAX_CLAIMS', 1):
            self.exchange([self.claim(1)])
            reply = self.exchange([self.claim(2), dict(self.claim(1), deleted=True)])
        self.assertEqual(reply['retryable'], ['2'])
        self.assertEqual([(c['id'], c['deleted']) for c in reply['changes']], [('1', True)])

    def test_s1_epoch_reset_wins_over_same_response_tombstone_ack(self):
        client = self.client()
        with client.store.connect() as db:
            db.execute('INSERT INTO local_claims(id,value,expires_at,deleted) VALUES(?,?,?,1)',
                       ('1', '203.0.113.8', self.expiry))
        client.receive(dict(cursor=0, changes=[], epoch='old'))
        sent = client.pending()
        client.receive(dict(cursor=0, changes=[], epoch='new'), sent)
        self.assertEqual(client.pending(), sent)

    def test_s4_global_import_quota_keeps_durable_retry(self):
        self.exchange([dict(self.claim(1), deleted=True, expires_at=self.expiry-300)])
        token = self.hub.add_peer('node2')
        self.exchange([self.claim(2)], token)
        observer = self.client('observer')
        token = self.hub.add_peer('observer')
        with patch.object(sync, 'MAX_IMPORTS', 1):
            observer.receive(self.exchange([], token, observer.cursor()))
            self.assertEqual(observer.cursor(), 0)
            with observer.store.connect() as db:
                self.assertEqual(db.execute('SELECT count(*) FROM imports').fetchone()[0], 1)
                self.assertEqual(db.execute("SELECT value FROM meta WHERE key='import_overload'").fetchone()[0], '1')
            observer = sync.Client(observer.store, observer.lapi, 'observer')
            with patch.object(sync.time, 'time', return_value=self.expiry-299):
                observer.receive(self.exchange([], token, observer.cursor()))
                observer.reconcile([])
            self.assertEqual(len(observer.lapi.rows), 1)
            with observer.store.connect() as db:
                self.assertEqual(db.execute('SELECT origin FROM imports').fetchone()[0], 'node2')

    def test_s5_retry_backoff_is_bounded_and_revocations_bypass_old_delay(self):
        client = self.client()
        with client.store.connect() as db:
            db.execute('INSERT INTO local_claims(id,value,expires_at) VALUES(?,?,?)',
                       ('1', '203.0.113.8', self.expiry+86400))
        now = time.time()
        for attempt in range(10):
            with patch.object(sync.time, 'time', return_value=now):
                sent = client.pending()
                self.assertEqual(len(sent), 1)
                client.receive(dict(cursor=0, changes=[], rejected=['1'], retryable=['1']), sent)
                self.assertEqual(client.pending(), [])
            with client.store.connect() as db:
                after = db.execute('SELECT retry_after FROM local_claims').fetchone()[0]
            self.assertLessEqual(after-now, sync.MAX_RETRY_SECONDS)
            self.assertGreaterEqual(after-now, sync.RETRY_SECONDS)
            now = after
        # A fresh local unban is urgent even if the live claim was backed off.
        client.reconcile([])
        self.assertTrue(client.pending()[0]['deleted'])


if __name__ == '__main__':
    unittest.main()
