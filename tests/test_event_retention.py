"""L1: bounded original-time replay using real SQLite and loopback HTTP."""
import datetime as dt
import importlib.util
import json
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from cscompanion import gateway, hybrid

SPEC = importlib.util.spec_from_file_location('retention_sdk', Path(__file__).resolve().parents[1] / 'sdk/report_auth.py')
sdk = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sdk)


class RetentionTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.state = Path(temp.name)
        self.store = hybrid.Store(self.state / 'receiver')
        self.token = self.store.add_source('app', 'gitea1')
        self.queue = sdk.Spool(self.state / 'sender/spool.db', limit=2)

    def start(self, http):
        worker = threading.Thread(target=http.serve_forever, daemon=True)
        worker.start()
        self.addCleanup(http.server_close)
        self.addCleanup(http.shutdown)
        return 'http://127.0.0.1:%d/v1/events' % http.server_port

    def age_item(self, age):
        item = self.queue.enqueue('203.0.113.50')
        item['occurred_at'] = dt.datetime.fromtimestamp(time.time() - age, dt.timezone.utc).isoformat().replace('+00:00', 'Z')
        with self.queue.connect() as db:
            db.execute('UPDATE events SET payload=? WHERE id=?', (json.dumps(item), item['id']))
            db.commit()
        return item

    def test_permanent_event_validation_is_explicit_bounded_and_id_matched(self):
        import urllib.error
        import urllib.request
        endpoint = self.start(gateway.server(self.store, 0, False))
        for age in (7 * 86400 + 10, -310):
            with self.subTest(age=age):
                item = self.age_item(age)
                request = urllib.request.Request(endpoint, data=json.dumps(item).encode(),
                    headers={'Authorization': 'Bearer ' + self.token, 'Content-Type': 'application/json'})
                with self.assertRaises(urllib.error.HTTPError) as caught:
                    urllib.request.urlopen(request)
                with caught.exception as response:
                    body = json.load(response)
                    self.assertEqual(response.code, 422)
                self.assertEqual(body, {'id': item['id'], 'permanent': True, 'error': 'invalid_event'})
                self.assertLessEqual(len(body['error']), 128)

    def test_only_explicit_matching_permanent_422_advances_to_quarantine(self):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        item = self.queue.enqueue('203.0.113.50')
        cases = [
            (400, {'error': 'request_timeout'}),
            (413, {'id': item['id'], 'permanent': True, 'error': 'invalid_event'}),
            (422, {'error': 'unknown'}),
            (422, {'id': 'wrong', 'permanent': True, 'error': 'invalid_event'}),
            (422, {'id': item['id'], 'permanent': 1, 'error': 'invalid_event'}),
            (422, {'id': item['id'], 'permanent': True, 'error': 'x' * 129}),
            (422, {'id': item['id'], 'permanent': True, 'error': 'invalid_event'}),
        ]
        for index, (code, body) in enumerate(cases):
            class Handler(BaseHTTPRequestHandler):
                def log_message(self, *args): pass
                def do_POST(self):
                    self.rfile.read(int(self.headers['Content-Length']))
                    raw = json.dumps(body).encode()
                    self.send_response(code)
                    self.send_header('Content-Length', str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
            endpoint = self.start(ThreadingHTTPServer(('127.0.0.1', 0), Handler))
            with self.subTest(code=code, body=body):
                self.assertEqual(self.queue.flush(endpoint, self.token), 0)
                final = index == len(cases) - 1
                self.assertEqual(self.queue.pending(), [] if final else [item])
                self.assertEqual(self.queue.quarantine_count(), int(final))
        entry = self.queue.quarantined()[0]
        self.assertEqual(entry['payload'], item)
        self.assertEqual(entry['reason'], 'invalid_event')
        self.assertEqual(entry['http_status'], 422)

    def test_incomplete_rejection_body_retries_original_event(self):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        item = self.queue.enqueue('203.0.113.50')
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format, *args): pass
            def do_POST(self):
                self.rfile.read(int(self.headers['Content-Length']))
                self.send_response(422)
                self.send_header('Content-Length', '1000')
                self.end_headers()
                self.wfile.write(json.dumps({'id': item['id'], 'permanent': True,
                                             'error': 'invalid_event'}).encode())
        endpoint = self.start(ThreadingHTTPServer(('127.0.0.1', 0), Handler))
        self.assertEqual(self.queue.flush(endpoint, self.token), 0)
        self.assertEqual(self.queue.pending(), [item])
        self.assertEqual(self.queue.quarantine_count(), 0)

    def test_incomplete_chunked_rejection_retries_original_event(self):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        item = self.queue.enqueue('203.0.113.50')
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format, *args): pass
            def do_POST(self):
                self.rfile.read(int(self.headers['Content-Length']))
                self.send_response(422)
                self.send_header('Transfer-Encoding', 'chunked')
                self.end_headers()
                self.wfile.write(b'20\r\n{"permanent":true')
        endpoint = self.start(ThreadingHTTPServer(('127.0.0.1', 0), Handler))
        self.assertEqual(self.queue.flush(endpoint, self.token), 0)
        self.assertEqual(self.queue.pending(), [item])
        self.assertEqual(self.queue.quarantine_count(), 0)

    def run_cli(self, *args):
        import subprocess
        import sys
        return subprocess.run([sys.executable, '-B', str(Path(__file__).resolve().parents[1] / 'sdk/report_auth.py'),
                               *args, '--spool', str(self.queue.path)], capture_output=True, text=True)

    def fill_quarantine(self):
        items = [self.age_item(7 * 86400 + 10), self.age_item(7 * 86400 + 20)]
        endpoint = self.start(gateway.server(self.store, 0, False))
        self.assertEqual(self.queue.flush(endpoint, self.token), 0)
        self.assertEqual(self.queue.quarantine_count(), 2)
        self.assertEqual(self.queue.pending(), [])
        return items

    def test_operator_inspection_is_bounded_metadata_with_total_count(self):
        items = self.fill_quarantine()
        result = self.run_cli('quarantine-inspect', '--limit', '1')
        self.assertEqual(result.returncode, 0, result.stderr)
        body = json.loads(result.stdout)
        self.assertEqual(body['count'], 2)
        self.assertEqual(body['entries'], [{'id': items[0]['id'], 'occurred_at': items[0]['occurred_at'],
                                          'http_status': 422, 'reason': 'invalid_event'}])
        self.assertNotIn('source_ip', result.stdout)
        self.assertEqual(self.queue.quarantine_count(), 2)

    def test_operator_discard_requires_exact_id_and_frees_only_target_capacity(self):
        items = self.fill_quarantine()
        with self.assertRaises(OverflowError):
            self.queue.enqueue('203.0.113.51')
        result = self.run_cli('quarantine-discard', '--id', items[0]['id'])
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.queue.quarantine_count(), 2)
        for bad_id in ('*', items[0]['id'][:8], str(__import__('uuid').uuid4())):
            result = self.run_cli('quarantine-discard', '--id', bad_id, '--confirm-discard')
            self.assertEqual(self.queue.quarantine_count(), 2)
        result = self.run_cli('quarantine-discard', '--id', items[0]['id'], '--confirm-discard')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {'id': items[0]['id'], 'discarded': True})
        reopened = sdk.Spool(self.queue.path, limit=2)
        self.assertEqual([entry['payload'] for entry in reopened.quarantined()], [items[1]])
        fresh = reopened.enqueue('203.0.113.51')
        # A pending ID is never a quarantine discard target.
        result = self.run_cli('quarantine-discard', '--id', fresh['id'], '--confirm-discard')
        self.assertEqual(json.loads(result.stdout)['discarded'], False)
        self.assertEqual(reopened.pending(), [fresh])
        with self.assertRaises(OverflowError):
            reopened.enqueue('203.0.113.52')

    def test_replay_age_boundaries_and_retained_duplicate_ack(self):
        item = self.queue.enqueue('203.0.113.50')
        occurred = dt.datetime.fromisoformat(item['occurred_at'].replace('Z', '+00:00')).timestamp()
        with patch.object(hybrid.time, 'time', return_value=occurred + 7 * 86400):
            self.assertTrue(self.store.accept_event(self.token, item))
        with patch.object(hybrid.time, 'time', return_value=occurred + 8 * 86400):
            self.assertFalse(self.store.accept_event(self.token, item))
            with self.assertRaises(ValueError):
                self.store.accept_event(self.token, dict(item, source_ip='203.0.113.51'))
        with patch.object(hybrid.time, 'time', return_value=occurred - 300):
            self.assertEqual(hybrid.validate_event(item), item)
        for now in (occurred - 300.001, occurred + 7 * 86400 + .001):
            with patch.object(hybrid.time, 'time', return_value=now):
                with self.assertRaises(ValueError):
                    hybrid.validate_event(item)

    def test_gateway_transport_failures_are_not_permanent(self):
        import http.client
        server = gateway.server(self.store, 0, False)
        self.start(server)
        for raw in (b'{', b'not json'):
            connection = http.client.HTTPConnection(*server.server_address)
            connection.request('POST', '/v1/events', raw,
                {'Authorization': 'Bearer ' + self.token, 'Content-Type': 'application/json'})
            response = connection.getresponse()
            self.assertEqual(response.status, 400)
            self.assertNotIn('permanent', json.loads(response.read()))
            connection.close()
        # Authenticated incomplete body: half-close permits a JSON response.
        with socket.create_connection(server.server_address, timeout=2) as sock:
            sock.sendall(('POST /v1/events HTTP/1.0\r\nAuthorization: Bearer ' + self.token +
                '\r\nContent-Type: application/json\r\nContent-Length: 50\r\n\r\n{').encode())
            sock.shutdown(socket.SHUT_WR)
            response = b''
            while True:
                chunk = sock.recv(4096)
                if not chunk: break
                response += chunk
            self.assertIn(b'400', response)
            self.assertNotIn(b'permanent', response)

    def test_outage_over_five_minutes_replays_original_identity_then_fresh(self):
        item = self.queue.enqueue('203.0.113.50')
        # Reserve a loopback port without listening: the first flush really fails.
        with socket.socket() as unavailable:
            unavailable.bind(('127.0.0.1', 0))
            endpoint = 'http://127.0.0.1:%d/v1/events' % unavailable.getsockname()[1]
            self.assertEqual(self.queue.flush(endpoint, self.token), 0)
        self.assertEqual(self.queue.pending(), [item])
        endpoint = self.start(gateway.server(self.store, 0, False))
        # Advance receiver time, not the queued UUID or occurred_at.
        with patch.object(hybrid.time, 'time', return_value=time.time() + 601):
            self.assertEqual(self.queue.flush(endpoint, self.token), 1)
        fresh = self.queue.enqueue('203.0.113.51')
        self.assertEqual(self.queue.flush(endpoint, self.token), 1)
        with self.store.connect() as db:
            rows = [json.loads(row[0]) for row in db.execute('SELECT body FROM events ORDER BY accepted')]
        self.assertEqual({r['id']: r['occurred_at'] for r in rows},
                         {i['id']: i['occurred_at'] for i in (item, fresh)})
        self.assertEqual(self.queue.quarantine_count(), 0)
