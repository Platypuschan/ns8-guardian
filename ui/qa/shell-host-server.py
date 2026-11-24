#!/usr/bin/env python3
"""Local imitation of the NS8 shell around the production build (see qa/README.md). Not NS8, not a backend.

Serves   /cluster-admin/index.html      qa/shell-host.html (the parent window with a stub `core`)
         /cluster-admin/css/core.css    compiled from qa/ns8-core-styles (the real core stylesheet, pinned copy)
         /cluster-admin/apps/guardian1  ../dist (the production build)
Answers  POST /api/module/<id>/tasks    with canned fixture output, delivered to the page through GET /api/queue
         (the page polls it and emits the task events exactly where the real shell would)."""
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

QA = Path(__file__).resolve().parent
UI = QA.parent
CORE_CSS = Path(os.environ.get('CORE_CSS', '/tmp/core.css'))
STATE = {
    'role': os.environ.get('FIXTURE_ROLE', 'hub'), 'queue': [],
    'decisions': [{'id': 1, 'ip': '198.51.100.7', 'scope': 'Ip', 'scenario': 'crowdsecurity/http-probing', 'origin': 'crowdsec', 'until': '2026-11-25T01:00:00Z', 'duration': '3h59m', 'machine': 'guardian1', 'country': 'DE'},
                  {'id': 2, 'ip': '2001:db8::25', 'scope': 'Ip', 'scenario': 'ns8/ns8-admin-bf', 'origin': 'crowdsec', 'until': '2026-11-25T02:30:00Z', 'duration': '1h12m', 'machine': 'guardian1', 'country': ''}],
    'members': [{'name': 'node3-member', 'local': False, 'ip_address': '10.0.0.3', 'last_push': 1764020000, 'last_heartbeat': 1764020100}],
    'sources': [{'name': 'gitea-events', 'module': 'gitea1', 'active': 1, 'endpoint': 'http://127.0.0.1:20007/v1/events'}],
}


def output(action, data):
    if action == 'get-configuration':
        return {'role': STATE['role'], 'hub_host': 'node2.example.org', 'lets_encrypt': True, 'hub_url': 'https://node2.example.org/', 'member_name': 'node3-member',
                'ban_duration': '30m', 'allowlist': ['127.0.0.0/8', '10.0.0.0/8', '192.168.178.0/24'], 'samba_audit': False, 'insecure_skip_verify': False,
                'community_blocklist': False, 'community_sharing': False}
    if action == 'get-companion-status':
        return {'role': STATE['role'], 'hub_url': 'https://node2.example.org/', 'lapi': 'ok', 'active_bans': len(STATE['decisions']), 'members': len(STATE['members']),
                'community': {'enabled': True, 'sharing': False, 'error': '', 'entries': 15000},
                'services': {'guardian1.service': 'active', 'guardian1-bouncer.service': 'active', 'guardian1-sync.service': 'active', 'guardian1-gateway.service': 'active', 'guardian1-refresh.timer': 'active'},
                'sources': {'gitea': ['gitea1'], 'samba': ['samba1'], 'traefik': ['traefik1']},
                'sync': {'pending': 0, 'last_success': 1764020000, 'age_seconds': 4, 'stale': False, 'error': '', 'event_pending': 0, 'event_unacked': 0, 'event_replayed_total': 3},
                'event_ingress': {'endpoint': 'http://127.0.0.1:20007/v1/events', 'pending': 0}}
    if action == 'list-decisions':
        return {'decisions': list(STATE['decisions'])}
    if action == 'unban':
        STATE['decisions'] = [d for d in STATE['decisions'] if d['ip'] not in data.get('addresses', [])]
        return {}
    if action == 'list-members':
        return {'members': list(STATE['members'])}
    if action == 'add-member':
        STATE['members'].append({'name': data['name']})
        return {'name': data['name'], 'token': 'csc2.fixture-opaque-token', 'hub_url': 'https://node2.example.org'}
    if action == 'remove-member':
        STATE['members'] = [m for m in STATE['members'] if m['name'] != data['name']]
        return {}
    if action == 'list-event-sources':
        return {'sources': list(STATE['sources'])}
    if action == 'add-event-source':
        STATE['sources'].append({'name': data['name'], 'module': data['module'], 'active': 1})
        return {'name': data['name'], 'token': 'fixture-token', 'endpoint': 'http://127.0.0.1:20007/v1/events'}
    if action == 'remove-event-source':
        STATE['sources'] = [s for s in STATE['sources'] if s['name'] != data['name']]
        return {}
    if action == 'get-name':
        return {'name': ''}
    return {}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def send(self, code, body, ctype='application/json'):
        raw = body if isinstance(body, bytes) else body.encode()
        self.send_response(code); self.send_header('Content-Type', ctype); self.send_header('Content-Length', str(len(raw)))
        self.send_header('Cache-Control', 'no-store'); self.end_headers(); self.wfile.write(raw)

    def do_GET(self):
        path = urlparse(self.path).path
        if path == '/api/queue':
            items, STATE['queue'] = STATE['queue'], []
            return self.send(200, json.dumps(items))
        mapping = {'/cluster-admin/index.html': QA / 'shell-host.html', '/cluster-admin/css/core.css': CORE_CSS}
        file = mapping.get(path)
        if file is None and path.startswith('/cluster-admin/apps/guardian1/'):
            file = UI / 'dist' / path[len('/cluster-admin/apps/guardian1/'):]
        if file is None and path.startswith('/i18n/'):
            file = UI / 'public' / path[1:]
        if file is None or not file.is_file():
            return self.send(404, 'not found', 'text/plain')
        types = {'.js': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.json': 'application/json', '.png': 'image/png', '.svg': 'image/svg+xml'}
        self.send(200, file.read_bytes(), types.get(file.suffix, 'application/octet-stream'))

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get('Content-Length', 0))) or b'{}')
        action, data = body.get('action'), body.get('data') or {}
        event = (body.get('extra') or {}).get('eventId')
        STATE['queue'].append({'action': action, 'eventId': event, 'output': output(action, data)})
        self.send(200, '{}')


if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5190
    ThreadingHTTPServer(('127.0.0.1', port), Handler).serve_forever()
