"""Loopback-only gateway; Traefik terminates verified HTTPS on the hub.

There is deliberately no HTTP administration API. NS8 actions alone provision
or revoke sources/peers. Bodies, bearer credentials and addresses are not logged.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import socket
import sqlite3
import threading

from .hybrid import Store
from .common import load_config, state_dir
from . import render


def server(store, port, hub, max_connections=32, request_timeout=5):
    slots = threading.BoundedSemaphore(max_connections)

    class BoundedServer(ThreadingHTTPServer):
        # This attribute is consumed by listen(), during construction.
        request_queue_size = 64
        daemon_threads = True

        def process_request(self, request, client_address):
            # Admission must precede header parsing AND handler thread creation.
            if not slots.acquire(blocking=False):
                # Best-effort fixed response: no parsing, no additional thread,
                # and no slow-client write may stall admission indefinitely.
                try:
                    request.settimeout(.05)
                    request.sendall(b'HTTP/1.0 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
                except OSError:
                    pass
                self.shutdown_request(request)
                return
            try:
                super().process_request(request, client_address)
            except BaseException:
                slots.release()
                raise

        def process_request_thread(self, request, client_address):
            def expire():
                try:
                    request.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            # Absolute lifetime, not an idle timeout reset by every input byte.
            deadline = threading.Timer(request_timeout, expire)
            deadline.daemon = True
            deadline.start()
            try:
                super().process_request_thread(request, client_address)
            finally:
                deadline.cancel()
                deadline.join()
                slots.release()

    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(request_timeout)

        def log_message(self, format, *args):
            pass

        def reply(self, code, body):
            raw = json.dumps(body, separators=(',', ':')).encode()
            try:
                self.send_response(code)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(raw)))
                self.send_header('Cache-Control', 'no-store')
                self.end_headers()
                self.wfile.write(raw)
            except (BrokenPipeError, ConnectionResetError, socket.timeout):
                self.close_connection = True

        def do_POST(self):
            self.handle_post()

        def handle_post(self):
            is_sync=self.path=='/v1/sync' and hub
            if self.path != '/v1/events' and not is_sync:
                self.reply(404, {'error':'not_found'})
                return
            if not is_sync and any(self.headers.get(h) for h in ('X-Forwarded-For','X-Forwarded-Host','X-Real-Ip','Forwarded')):
                # Event ingestion is for local producers only; a proxied request
                # (e.g. through the public Traefik route) is refused.
                self.reply(404, {'error':'not_found'})
                return
            try:
                if self.headers.get('Transfer-Encoding') or len(self.headers.get_all('Content-Length', [])) != 1:
                    raise ValueError('length required')
                size = int(self.headers.get('Content-Length', '0'))
                if size > (128*1024 if is_sync else 2048):
                    self.reply(413, {'error':'body_too_large'})
                    return
                if size <= 0 or self.headers.get_content_type() != 'application/json':
                    raise ValueError('JSON required')
                auth = self.headers.get('Authorization', '')
                if not auth.startswith('Bearer ') or len(auth) > 256:
                    raise PermissionError()
                # Authenticate before spending any CPU on the untrusted body.
                if not store.known_credential('peer' if is_sync else 'source', auth[7:]):
                    raise PermissionError()
                raw = self.rfile.read(size)
                if len(raw) != size:
                    raise ValueError('incomplete request')
                event = json.loads(raw)
                if is_sync:
                    self.reply(200,store.exchange(auth[7:],event))
                else:
                    try:
                        accepted = store.accept_event(auth[7:], event)
                    except (ValueError, TypeError, KeyError):
                        # Only semantic rejection of a completely parsed event
                        # is permanent. Never reflect unbounded input/errors.
                        event_id = event.get('id') if isinstance(event, dict) else None
                        if not isinstance(event_id, str) or len(event_id) > 36:
                            event_id = None
                        self.reply(422, {'id':event_id, 'permanent':True, 'error':'invalid_event'})
                        return
                    self.reply(202, {'id':event['id'],'accepted':True, 'duplicate':not accepted})
            except PermissionError:
                self.reply(401, {'error':'unauthorized'})
            except OverflowError:
                self.reply(503, {'error':'queue_full'})
            except sqlite3.OperationalError:
                self.reply(503, {'error':'busy'})
            except (ValueError, TypeError, KeyError, socket.timeout, RecursionError):
                self.reply(400, {'error':'invalid_event'})

    return BoundedServer(('127.0.0.1', port), Handler)


def main():
    cfg = load_config()
    server(Store(state_dir()), render.gateway_port(), cfg['role'] == 'hub').serve_forever()


if __name__ == '__main__':
    main()
