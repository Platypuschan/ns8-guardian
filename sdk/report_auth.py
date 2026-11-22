#!/usr/bin/env python3
"""Durable local auth-event producer. No network call in enqueue().

Use only from a trustworthy application authentication callback or structured
log adapter. Never derive source_ip from a username or an untrusted header.
"""
import datetime as dt
import ipaddress
import json
import os
from pathlib import Path
import sqlite3
import stat
import uuid


class Spool:
    def __init__(self, path, limit=10000):
        self.path = Path(path)
        self.limit = limit
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        parent = self.path.parent.stat()
        if parent.st_uid != os.getuid() or parent.st_mode & 0o022:
            raise ValueError('spool directory must be owned by the sender and not writable by others')
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise ValueError('spool must be a private regular file owned by the sender')
        finally:
            os.close(fd)
        with self.connect() as db:
            db.execute('PRAGMA journal_mode=WAL')
            db.execute('CREATE TABLE IF NOT EXISTS events (seq INTEGER PRIMARY KEY, id TEXT UNIQUE NOT NULL, payload TEXT NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS quarantine (id TEXT PRIMARY KEY, payload TEXT NOT NULL, http_status INTEGER NOT NULL, reason TEXT NOT NULL)')

    def connect(self):
        # SQLite's context manager commits/rolls back, but does not close.
        from contextlib import closing
        return closing(sqlite3.connect(self.path, timeout=5))

    def enqueue(self, source_ip):
        ip = ipaddress.ip_address(source_ip)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        # Same rules as the receiver; otherwise the event would be queued but never accepted.
        if (ip.is_multicast or ip.is_unspecified or ip.is_loopback or ip.is_link_local or ip.is_reserved
                or str(ip) == '255.255.255.255' or '%' in str(ip)):
            raise ValueError('source_ip must be a non-loopback unicast IP')
        item = {'schema_version': 1, 'id': str(uuid.uuid4()),
                'occurred_at': dt.datetime.now(dt.timezone.utc).isoformat().replace('+00:00', 'Z'),
                'event': 'authentication_failed', 'source_ip': str(ip)}
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            if db.execute('SELECT (SELECT COUNT(*) FROM events)+(SELECT COUNT(*) FROM quarantine)').fetchone()[0] >= self.limit:
                raise OverflowError('event spool is full; no existing event was discarded')
            db.execute('INSERT INTO events(id,payload) VALUES (?,?)', (item['id'], json.dumps(item)))
            db.commit()
        return item

    def flush(self, endpoint, token, limit=100):
        import http.client
        import urllib.error
        import urllib.request
        from urllib.parse import urlsplit
        url = urlsplit(endpoint)
        if (url.scheme not in ('http', 'https') or url.username or url.password or url.query or url.fragment
                or url.path != '/v1/events' or not ipaddress.ip_address(url.hostname or '').is_loopback):
            raise ValueError('event endpoint must be a literal loopback /v1/events URL without credentials')
        if not isinstance(token, str) or not token or any(c.isspace() for c in token):
            raise ValueError('invalid source token')

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None

        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        sent = 0
        for item in self.pending(limit):
            request = urllib.request.Request(endpoint, data=json.dumps(item).encode(),
                                             headers={'Authorization': 'Bearer ' + token,
                                                      'Content-Type': 'application/json'}, method='POST')
            try:
                with opener.open(request, timeout=3) as response:
                    raw = response.read(8193)
                    if response.status not in (200, 201, 202) or len(raw) > 8192:
                        break
                    ack = json.loads(raw)
                    if not isinstance(ack, dict) or ack.get('id') != item['id'] or not (ack.get('accepted') is True or ack.get('status') in ('accepted', 'duplicate')):
                        break
            except urllib.error.HTTPError as error:
                # Only explicit permanent payload rejections advance the queue.
                # Authentication, overload, redirects and transport errors retry.
                try:
                    if error.code != 422:
                        break
                    raw = error.read(8193)
                    length = error.headers.get('Content-Length')
                    rejection = json.loads(raw) if len(raw) <= 8192 and (length is None or int(length) == len(raw)) else None
                    if (not isinstance(rejection, dict) or rejection.get('id') != item['id']
                            or rejection.get('permanent') is not True
                            or not isinstance(rejection.get('error'), str)
                            or not 1 <= len(rejection['error']) <= 128):
                        break
                    reason = rejection['error']
                except (OSError, ValueError, http.client.HTTPException):
                    break
                finally:
                    error.close()
                with self.connect() as db:
                    db.execute('BEGIN IMMEDIATE')
                    db.execute('INSERT OR IGNORE INTO quarantine SELECT id,payload,?,? FROM events WHERE id=?',
                               (error.code,reason,item['id']))
                    db.execute('DELETE FROM events WHERE id=?',(item['id'],))
                    db.commit()
                continue
            except (urllib.error.URLError, OSError, ValueError):
                break
            with self.connect() as db:
                db.execute('DELETE FROM events WHERE id=?', (item['id'],))
                db.commit()
            sent += 1
        return sent

    def quarantined(self, limit=100):
        with self.connect() as db:
            return [dict(id=row[0],payload=json.loads(row[1]),http_status=row[2],reason=row[3])
                    for row in db.execute('SELECT id,payload,http_status,reason FROM quarantine ORDER BY rowid LIMIT ?', (limit,))]

    def quarantine_count(self):
        with self.connect() as db:
            return db.execute('SELECT count(*) FROM quarantine').fetchone()[0]

    def pending(self, limit=100):
        with self.connect() as db:
            return [json.loads(row[0]) for row in db.execute('SELECT payload FROM events ORDER BY seq LIMIT ?', (limit,))]


def read_token(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError('token file must be private and owned by the sender')
        token = os.read(fd, 4097).decode().strip()
        if not token or len(token) > 4096 or any(c.isspace() for c in token):
            raise ValueError('invalid token file')
        return token
    finally:
        os.close(fd)


def main():
    import argparse
    import sys
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    enqueue = commands.add_parser('enqueue', help='durably queue one failure without a network call')
    enqueue.add_argument('--spool', required=True)
    enqueue.add_argument('--ip', required=True)
    flush = commands.add_parser('flush', help='deliver a bounded batch; credentials come from a private file')
    flush.add_argument('--spool', required=True)
    flush.add_argument('--endpoint', required=True)
    flush.add_argument('--token-file', required=True)
    inspect = commands.add_parser('quarantine-inspect', help='show bounded quarantine metadata, without payload addresses')
    inspect.add_argument('--spool', required=True)
    inspect.add_argument('--limit', type=int, default=100)
    discard = commands.add_parser('quarantine-discard', help='irreversibly discard one exact quarantined UUID')
    discard.add_argument('--spool', required=True)
    discard.add_argument('--id', required=True)
    discard.add_argument('--confirm-discard', required=True, action='store_true')
    args = parser.parse_args()
    try:
        queue = Spool(args.spool)
        if args.command == 'quarantine-discard':
            if str(uuid.UUID(args.id)) != args.id:
                raise ValueError('id must be canonical UUID')
            with queue.connect() as db:
                discarded = bool(db.execute('DELETE FROM quarantine WHERE id=?', (args.id,)).rowcount)
                db.commit()
            print(json.dumps({'id': args.id, 'discarded': discarded}))
            return 0
        if args.command == 'quarantine-inspect':
            if not 1 <= args.limit <= 1000:
                raise ValueError('inspection limit must be between 1 and 1000')
            entries = [dict(id=e['id'], occurred_at=e['payload'].get('occurred_at'),
                            http_status=e['http_status'], reason=e['reason'])
                       for e in queue.quarantined(args.limit)]
            print(json.dumps({'count': queue.quarantine_count(), 'entries': entries}))
            return 0
        if args.command == 'enqueue':
            item = queue.enqueue(args.ip)
            print(json.dumps({'id': item['id'], 'queued': True}))
            return 0
        sent = queue.flush(args.endpoint, read_token(args.token_file))
        pending = bool(queue.pending(1))
        quarantined = queue.quarantine_count()
        print(json.dumps({'sent': sent, 'has_pending': pending, 'quarantined': quarantined}))
        return 75 if pending else (65 if quarantined else 0)
    except (ValueError, OSError, OverflowError, sqlite3.Error) as error:
        # Never format exception messages: URLs, paths and credentials may occur.
        print('auth-event producer failed: ' + type(error).__name__, file=sys.stderr)
        return 65


if __name__ == '__main__':
    raise SystemExit(main())
