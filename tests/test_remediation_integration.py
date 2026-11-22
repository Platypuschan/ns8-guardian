"""Production-loop wiring across the independently repaired ownership slices."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cscompanion import hybrid, sync


class LoopIntegrationTests(unittest.TestCase):
    def test_production_loop_requires_actual_event_consumer_readiness(self):
        with tempfile.TemporaryDirectory() as state:
            store = hybrid.Store(Path(state))
            client = sync.Client(store, None, 'node1')
            with patch.object(sync, 'Store', return_value=store), \
                 patch.object(sync, 'Client', return_value=client), \
                 patch.object(sync, 'load_config', return_value={'allowlist': []}), \
                 patch.object(sync, 'read_secret', return_value='node1'), \
                 patch.object(sync, 'state_dir', return_value=Path(state)), \
                 patch.object(client, 'reconcile'), \
                 patch.object(client, 'exchange'), \
                 patch.object(store, 'deliver_events') as deliver, \
                 patch.object(sync.time, 'sleep', side_effect=InterruptedError):
                with self.assertRaises(InterruptedError):
                    sync.main()
                deliver.assert_called_once_with(store.event_consumer_ready, store.event_consumer_state)


    def test_interrupted_rotation_recreates_target_before_readiness_probe(self):
        import datetime as dt
        import uuid
        with tempfile.TemporaryDirectory() as state:
            store = hybrid.Store(Path(state))
            directory = Path(state) / 'events'
            directory.mkdir()
            (directory / 'auth.previous').write_text('retained prior file\n')
            path = directory / 'auth.jsonl'
            token = store.add_source('app', 'app1')
            store.accept_event(token, {'schema_version': 1, 'id': str(uuid.uuid4()),
                'occurred_at': dt.datetime.now(dt.timezone.utc).isoformat().replace('+00:00', 'Z'),
                'event': 'authentication_failed', 'source_ip': '203.0.113.20'})
            def ready():
                self.assertTrue(path.exists(), 'rotation recovery must precede the FD probe')
                self.assertEqual(path.stat().st_size, 0)
                return False
            self.assertEqual(store.deliver_events(ready), 0)
            self.assertEqual((directory / 'auth.previous').read_text(), 'retained prior file\n')
            with store.connect() as db:
                self.assertEqual(db.execute('SELECT delivered FROM events').fetchone()[0], 0)
            self.assertEqual(store.deliver_events(lambda: True), 1)

    def test_rotation_waits_for_old_file_read_then_new_file_acquisition(self):
        import datetime as dt
        import uuid
        with tempfile.TemporaryDirectory() as state:
            store = hybrid.Store(Path(state))
            directory = Path(state) / 'events'
            directory.mkdir()
            log = directory / 'auth.jsonl'
            with log.open('wb') as output:
                output.truncate(32 * 1024 * 1024 + 1)
            old_inode = log.stat().st_ino
            token = store.add_source('app', 'app1')
            event = {'schema_version': 1, 'id': str(uuid.uuid4()),
                     'occurred_at': dt.datetime.now(dt.timezone.utc).isoformat().replace('+00:00', 'Z'),
                     'event': 'authentication_failed', 'source_ip': '203.0.113.19'}
            store.accept_event(token, event)
            with patch.object(store, 'event_consumer_drained', create=True, return_value=False):
                self.assertEqual(store.deliver_events(lambda: True), 0)
            self.assertEqual(log.stat().st_ino, old_inode)
            with patch.object(store, 'event_consumer_drained', create=True, return_value=True):
                self.assertEqual(store.deliver_events(lambda: True), 0)
            self.assertNotEqual(log.stat().st_ino, old_inode)
            self.assertEqual(log.stat().st_size, 0)
            self.assertEqual(store.deliver_events(lambda: False), 0)
            with store.connect() as db:
                self.assertEqual(db.execute('SELECT delivered FROM events').fetchone()[0], 0)
            self.assertEqual(store.deliver_events(lambda: True), 1)


if __name__ == '__main__':
    unittest.main()
