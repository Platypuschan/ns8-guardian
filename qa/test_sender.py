"""Producer-side durability and safe delivery regressions."""
from contextlib import contextmanager
import http.server
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
import urllib.request
import uuid

PATH = Path(__file__).resolve().parents[1] / 'sdk/report_auth.py'


def sender():
    if not PATH.exists():
        return None
    spec = importlib.util.spec_from_file_location('hybrid_report_auth', PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@contextmanager
def local_receiver(reply):
    received = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            raw = self.rfile.read(int(self.headers.get('Content-Length', 0)))
            item = json.loads(raw) if raw else None
            received.append((self.command, self.path, dict(self.headers), item))
            status, headers, body = reply(item)
            self.send_response(status)
            for key, value in headers.items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(json.dumps(body).encode())

        do_GET = do_POST

        def log_message(self, format, *args):
            pass

    with http.server.HTTPServer(('127.0.0.1', 0), Handler) as server:
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            yield 'http://127.0.0.1:%d/v1/events' % server.server_port, received
        finally:
            server.shutdown()
            worker.join(3)


class SenderTests(unittest.TestCase):
    def test_mismatched_ack_id_retains_event_until_matching_duplicate_ack(self):
        mod = sender()
        assert mod is not None
        other_id = str(uuid.uuid4())
        ack = {'id': other_id, 'accepted': True}
        with tempfile.TemporaryDirectory() as td, local_receiver(
                lambda item: (202, {}, ack)) as (endpoint, received):
            queue = mod.Spool(Path(td) / 'private/queue.db')
            item = queue.enqueue('198.51.100.42')
            self.assertNotEqual(item['id'], other_id)
            self.assertEqual(queue.flush(endpoint, 'source-secret'), 0)
            self.assertEqual(queue.pending(), [item])
            ack.clear()
            ack.update(id=item['id'], status='duplicate')
            self.assertEqual(queue.flush(endpoint, 'source-secret'), 1)
            self.assertEqual(queue.pending(), [])
            self.assertEqual([entry[3] for entry in received], [item, item])

    def test_redirects_never_forward_credentials_or_acknowledge_event(self):
        mod = sender()
        assert mod is not None
        with tempfile.TemporaryDirectory() as td, local_receiver(
                lambda item: (202, {}, {'accepted': True})) as (target, egress):
            queue = mod.Spool(Path(td) / 'private/queue.db')
            item = queue.enqueue('198.51.100.42')
            for status in (301, 302, 303, 307, 308):
                with self.subTest(status=status), local_receiver(
                        lambda item: (status, {'Location': target}, {})) as (endpoint, received):
                    self.assertEqual(queue.flush(endpoint, 'source-secret'), 0)
                    self.assertEqual(queue.pending(), [item])
                    self.assertEqual(len(received), 1)
                    self.assertEqual(received[0][2]['Authorization'], 'Bearer source-secret')
                    self.assertEqual(egress, [])

    def test_environment_http_proxy_receives_no_credentials_or_events(self):
        mod = sender()
        assert mod is not None
        for variable in ('HTTP_PROXY', 'http_proxy'):
            with self.subTest(variable=variable), tempfile.TemporaryDirectory() as td, local_receiver(
                    lambda item: (202, {}, {'id': item['id'], 'accepted': True})
                    ) as (endpoint, received), local_receiver(
                    lambda item: (200, {}, {})) as (proxy, egress):
                queue = mod.Spool(Path(td) / 'private/queue.db')
                item = queue.enqueue('198.51.100.42')
                with patch.dict(os.environ, {variable: proxy, 'NO_PROXY': '', 'no_proxy': ''}, clear=True):
                    # Positive control: this environment really routes urllib through the proxy.
                    with urllib.request.build_opener().open(endpoint, timeout=3) as response:
                        self.assertEqual(response.status, 200)
                    self.assertEqual(len(egress), 1)
                    egress.clear()
                    self.assertEqual(queue.flush(endpoint, 'source-secret'), 1)
                self.assertEqual(egress, [])
                self.assertEqual(queue.pending(), [])
                self.assertEqual(len(received), 1)
                self.assertEqual(received[0][2]['Authorization'], 'Bearer source-secret')
                self.assertEqual(received[0][3], item)

    def test_queue_retains_original_uuid_and_time_after_restart(self):
        mod = sender()
        self.assertIsNotNone(mod, 'durable producer is missing')
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'private/queue.db'
            first = mod.Spool(path)
            item = first.enqueue('2001:db8::42')
            reopened = mod.Spool(path)
            self.assertEqual(reopened.pending(), [item])
            self.assertEqual(item['schema_version'], 1)
            self.assertEqual(item['event'], 'authentication_failed')
            self.assertEqual(item['source_ip'], '2001:db8::42')
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)


    def test_failed_delivery_retains_event_and_ack_deletes_it(self):
        mod = sender()
        assert mod is not None
        self.assertTrue(hasattr(mod.Spool, 'flush'), 'delivery is not implemented')
        import http.server
        import threading
        reply = {'status': 503}
        received = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                item = __import__('json').loads(self.rfile.read(int(self.headers['Content-Length'])))
                received.append((self.path, self.headers['Authorization'], item))
                self.send_response(reply['status'])
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                body = [] if reply.get('malformed') else {'id': item['id'], 'accepted': True}
                self.wfile.write(__import__('json').dumps(body).encode())

            def log_message(self, *_args):
                pass

        with tempfile.TemporaryDirectory() as td, http.server.HTTPServer(('127.0.0.1', 0), Handler) as server:
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            try:
                queue = mod.Spool(Path(td) / 'private/queue.db')
                item = queue.enqueue('198.51.100.42')
                endpoint = 'http://127.0.0.1:%d/v1/events' % server.server_port
                self.assertEqual(queue.flush(endpoint, 'source-secret'), 0)
                self.assertEqual(queue.pending(), [item])
                reply['status'] = 202
                reply['malformed'] = True
                self.assertEqual(queue.flush(endpoint, 'source-secret'), 0)
                self.assertEqual(queue.pending(), [item])
                reply['malformed'] = False
                self.assertEqual(queue.flush(endpoint, 'source-secret'), 1)
                self.assertEqual(queue.pending(), [])
                self.assertEqual(received[0][2], received[1][2])
                self.assertEqual(received[1][1], 'Bearer source-secret')
            finally:
                server.shutdown()
                worker.join(3)


    def test_sender_refuses_remote_endpoint_and_url_credentials(self):
        mod = sender()
        assert mod is not None
        with tempfile.TemporaryDirectory() as td:
            queue = mod.Spool(Path(td) / 'private/queue.db')
            for endpoint in ('http://example.org/v1/events', 'https://example.org/v1/events',
                             'http://secret@127.0.0.1/v1/events', 'http://127.0.0.1/v1/events?token=bad',
                             'file:///etc/passwd'):
                with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                    queue.flush(endpoint, 'source-secret')

    def test_spool_limit_preserves_existing_events(self):
        mod = sender()
        assert mod is not None
        with tempfile.TemporaryDirectory() as td:
            queue = mod.Spool(Path(td) / 'private/queue.db', limit=1)
            item = queue.enqueue('198.51.100.42')
            with self.assertRaises(OverflowError):
                queue.enqueue('198.51.100.43')
            self.assertEqual(queue.pending(), [item])


    def test_enqueue_cli_returns_id_without_sending(self):
        import json
        import subprocess
        import sys
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'private/queue.db'
            result = subprocess.run([sys.executable, str(PATH), 'enqueue', '--spool', str(path),
                                     '--ip', '198.51.100.45'], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0)
            self.assertTrue(result.stdout.strip(), 'CLI did not enqueue an event')
            item = json.loads(result.stdout)
            mod = sender()
            assert mod is not None
            self.assertEqual(mod.Spool(path).pending()[0]['id'], item['id'])


if __name__ == '__main__':
    unittest.main()
