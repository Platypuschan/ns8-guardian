"""Consumer ACK, engine-generation requeue and bounded bucket-window replay (real SQLite, controllable probes)."""
import datetime as dt
import json
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
import uuid
from unittest.mock import patch

from cscompanion import hybrid


def event(ip='203.0.113.50', at=None):
    return dict(schema_version=1, id=str(uuid.uuid4()), event='authentication_failed',
                occurred_at=dt.datetime.fromtimestamp(at or time.time(), dt.timezone.utc).isoformat().replace('+00:00', 'Z'), source_ip=ip)


class Engine:
    """Stands in for the running CrowdSec container: generation, open acquisition fd, read offset."""
    def __init__(self, path):
        self.path, self.gen, self.up, self.read = path, 'g1', True, 0
        self.fail = False

    def restart(self):
        self.gen = self.gen + 'x'
        self.read = self.path.stat().st_size if self.path.exists() else 0   # tail mode: starts at EOF

    def consume(self):
        self.read = self.path.stat().st_size

    def state(self):
        if self.fail:
            return None
        size = self.path.stat().st_size if self.path.exists() else 0
        return {'ready': self.up, 'gen': self.gen, 'pos': self.read, 'size': size}


class AckTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = hybrid.Store(Path(self.tmp.name))
        self.token = self.store.add_source('app', 'gitea1')
        self.log = Path(self.tmp.name) / 'events/auth.jsonl'
        self.engine = Engine(self.log)
        self.now = [1_800_000_000.0]
        patcher = patch.object(hybrid.time, 'time', side_effect=lambda: self.now[0])
        patcher.start()
        self.addCleanup(patcher.stop)

    def send(self, n=1, ip='203.0.113.50'):
        items = [event(ip, self.now[0]) for _ in range(n)]
        for item in items:
            self.store.accept_event(self.token, item)
        return items

    def deliver(self):
        return self.store.deliver_events(None, self.engine.state)

    def rows(self):
        with self.store.connect() as db:
            return [dict(r) for r in db.execute('SELECT * FROM events ORDER BY accepted, id')]

    def tick(self, seconds):
        self.now[0] += seconds

    # -- ACK ---------------------------------------------------------------------------------
    def test_append_alone_is_not_an_ack_and_records_offset_and_generation(self):
        self.send(2)
        self.assertEqual(self.deliver(), 2)
        for row in self.rows():
            self.assertEqual((row['delivered'], row['acked'], row['appended_gen']), (1, None, 'g1'))
        self.assertEqual(max(r['file_end'] for r in self.rows()), self.log.stat().st_size)
        self.assertEqual(self.store.ack_events(self.engine.state), {'acked': 0, 'requeued': 0, 'replayed': 0})
        self.assertEqual(self.store.event_status()['unacked'], 2)

    def test_ack_needs_the_engine_to_have_read_past_the_event_and_a_settle_time(self):
        self.send()
        self.deliver()
        self.engine.consume()
        self.assertEqual(self.store.ack_events(self.engine.state)['acked'], 0)    # same instant: not settled
        self.tick(hybrid.ACK_SETTLE + 1)
        self.assertEqual(self.store.ack_events(self.engine.state)['acked'], 1)
        self.assertEqual(self.store.event_status()['unacked'], 0)

    def test_offset_short_of_the_event_is_not_acked(self):
        self.send(2)
        self.deliver()
        self.engine.read = min(r['file_end'] for r in self.rows())      # only the first line was read
        self.tick(hybrid.ACK_SETTLE + 1)
        self.assertEqual(self.store.ack_events(self.engine.state)['acked'], 1)
        self.assertEqual(self.store.event_status()['unacked'], 1)

    def test_probe_failure_changes_nothing(self):
        self.send()
        self.deliver()
        self.engine.fail = True
        self.tick(1000)
        self.assertEqual(self.store.ack_events(self.engine.state), {'acked': 0, 'requeued': 0, 'replayed': 0})
        self.assertEqual(self.store.event_status()['unacked'], 1)
        self.assertEqual(self.deliver(), 0)

    # -- crash windows -----------------------------------------------------------------------
    def test_engine_restart_before_consumption_requeues_and_reappends_the_same_line(self):
        item, = self.send()
        self.deliver()
        self.engine.restart()                      # crash after append, before the engine consumed the line
        self.tick(5)
        self.assertEqual(self.store.ack_events(self.engine.state)['requeued'], 1)
        self.assertEqual(self.rows()[0]['delivered'], 0)
        self.assertEqual(self.deliver(), 1)        # replay bypasses the torn-commit duplicate guard
        lines = self.log.read_text().splitlines()
        self.assertEqual([json.loads(l)['id'] for l in lines], [item['id']] * 2)
        self.engine.consume()
        self.tick(hybrid.ACK_SETTLE + 1)
        self.assertEqual(self.store.ack_events(self.engine.state)['acked'], 1)

    def test_restart_replays_only_recently_acked_events_to_rebuild_lost_buckets(self):
        old, = self.send()
        self.deliver(); self.engine.consume(); self.tick(hybrid.ACK_SETTLE + 1); self.store.ack_events(self.engine.state)
        self.tick(hybrid.REPLAY_WINDOW + 60)
        recent = self.send(3)
        self.deliver(); self.engine.consume(); self.tick(hybrid.ACK_SETTLE + 1); self.store.ack_events(self.engine.state)
        self.engine.restart()                      # bucket state (in memory) is gone
        result = self.store.ack_events(self.engine.state)
        self.assertEqual(result['replayed'], 3)
        self.assertEqual(self.deliver(), 3)
        lines = [json.loads(l)['id'] for l in self.log.read_text().splitlines()]
        self.assertEqual(lines.count(old['id']), 1)
        self.assertTrue(all(lines.count(i['id']) == 2 for i in recent))
        self.assertEqual(self.store.event_status()['replayed_total'], 3)

    def test_replay_skips_addresses_unbanned_after_the_event(self):
        a, = self.send(1, '203.0.113.60')
        b, = self.send(1, '203.0.113.61')
        self.deliver(); self.engine.consume(); self.tick(hybrid.ACK_SETTLE + 1); self.store.ack_events(self.engine.state)
        self.tick(5)
        self.store.note_unban('203.0.113.60')
        self.engine.restart()
        self.assertEqual(self.store.ack_events(self.engine.state)['replayed'], 1)
        self.deliver()
        lines = [json.loads(l)['id'] for l in self.log.read_text().splitlines()]
        self.assertEqual(lines.count(a['id']), 1)
        self.assertEqual(lines.count(b['id']), 2)

    def test_restored_database_never_replays_or_requeues_old_events(self):
        # hosted run 45038765312: replay re-banned an address that was unbanned after the backup was taken
        self.send(3, '203.0.113.70')
        self.deliver(); self.engine.consume(); self.tick(hybrid.ACK_SETTLE + 1); self.store.ack_events(self.engine.state)
        item, = self.send(1, '203.0.113.71')
        self.deliver()                                  # appended, not yet acked when the snapshot was taken
        self.store.new_epoch()                          # what restore_database() does after copying the snapshot
        self.engine.restart()                           # the restored module starts a new engine
        self.assertEqual(self.store.ack_events(self.engine.state), {'acked': 0, 'requeued': 0, 'replayed': 0})
        self.assertEqual(self.deliver(), 0)
        lines = [json.loads(l)['id'] for l in self.log.read_text().splitlines()]
        self.assertEqual(lines.count(item['id']), 1)
        self.assertEqual(self.store.event_status()['replayed_total'], 0)
        self.assertEqual(self.store.event_status()['unacked'], 0)

    def test_first_observation_never_replays_and_same_generation_never_replays(self):
        self.send(2)
        self.deliver(); self.engine.consume(); self.tick(hybrid.ACK_SETTLE + 1)
        self.assertEqual(self.store.ack_events(self.engine.state), {'acked': 2, 'requeued': 0, 'replayed': 0})
        self.assertEqual(self.store.ack_events(self.engine.state), {'acked': 0, 'requeued': 0, 'replayed': 0})

    def test_unready_engine_keeps_events_pending_and_does_not_start_a_generation(self):
        self.send()
        self.engine.up = False
        self.assertEqual(self.deliver(), 0)
        self.assertFalse(self.log.exists())

    def test_rotation_acknowledges_rows_of_the_drained_file(self):
        self.send(2)
        self.deliver(); self.engine.consume()
        with patch.object(self.store, 'EVENT_LOG_LIMIT', 1), patch.object(self.store, 'event_consumer_drained', return_value=True):
            self.send(1)
            self.assertEqual(self.deliver(), 0)       # rotation tick
        rows = self.rows()
        self.assertEqual([r['acked'] is not None for r in rows if r['delivered']], [True, True])
        self.assertEqual(sum(1 for r in rows if not r['delivered']), 1)

    # -- migration / status -------------------------------------------------------------------
    def test_legacy_database_is_migrated_and_legacy_rows_are_not_tracked(self):
        path = Path(self.tmp.name) / 'legacy' / 'hybrid.db'
        path.parent.mkdir()
        db = sqlite3.connect(path)
        db.executescript('''CREATE TABLE events(source TEXT NOT NULL, id TEXT NOT NULL, body TEXT NOT NULL,
            accepted REAL NOT NULL, delivered INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(source,id));
            INSERT INTO events VALUES('g','1','{}',1,1);''')
        db.commit(); db.close()
        store = hybrid.Store(path.parent)
        self.assertEqual(store.event_status(), {'pending': 0, 'unacked': 0, 'replayed_total': 0})
        self.assertEqual(store.ack_events(lambda: {'ready': True, 'gen': 'a', 'pos': 0, 'size': 0}), {'acked': 0, 'requeued': 0, 'replayed': 0})

    def test_unban_action_records_the_address_for_replay_filtering(self):
        from cscompanion import actions
        with patch.object(actions.lifecycle, 'cscli'), patch.object(actions, 'Store', return_value=self.store), \
                patch.object(actions, 'state_dir', return_value=Path(self.tmp.name)):
            actions.unban({'addresses': ['203.0.113.77']})
        with self.store.connect() as db:
            self.assertEqual(db.execute('SELECT ip FROM unbans').fetchone()[0], '203.0.113.77')


if __name__ == '__main__':
    unittest.main()


class ProbeScript(unittest.TestCase):
    """Run the real in-container probe script against a real process named crowdsec holding a real fd."""
    def test_probe_reports_generation_offset_and_restart_changes_generation(self):
        import shutil
        import subprocess
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            shutil.copy('/bin/sleep', tmp / 'crowdsec')
            data = tmp / 'auth.jsonl'
            data.write_bytes(b'x' * 100)

            def start():
                return subprocess.Popen(['bash', '-c', 'exec 3<"$1"; dd bs=1 count=40 <&3 >/dev/null 2>&1; exec "$2" 30', 'b', str(data), str(tmp / 'crowdsec')])

            def run(argv, **kw):
                shell = argv[argv.index('sh'):]
                done = subprocess.run(shell, capture_output=True, text=True, timeout=10)
                return SimpleNamespace(returncode=done.returncode, stdout=done.stdout, stderr=done.stderr)
            store = hybrid.Store(tmp / 'state')
            first = start()
            self.addCleanup(first.kill)
            time.sleep(.5)
            with patch('cscompanion.lifecycle.run', side_effect=run):
                a = store.event_consumer_state('c', str(data))
                self.assertTrue(a['ready'])
                self.assertEqual((a['pos'], a['size']), (40, 100))
                first.kill(); first.wait()
                second = start()
                self.addCleanup(second.kill)
                time.sleep(.5)
                b = store.event_consumer_state('c', str(data))
                self.assertNotEqual(a['gen'], b['gen'])
                second.kill(); second.wait()
                c = store.event_consumer_state('c', str(data))
                self.assertFalse(c['ready'])
                self.assertEqual(c['gen'], '')


class StatusCounters(unittest.TestCase):
    def test_sync_status_publishes_the_acked_counter(self):
        text = (Path(__file__).resolve().parents[1] / 'imageroot/pypkg/cscompanion/sync.py').read_text()
        self.assertIn("status['event_acked']", text)
