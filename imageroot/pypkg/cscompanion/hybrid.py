"""Durable private state. No access to CrowdSec's database.

Event output is a fsynced append plus a transactional *appended* marker (column
``delivered``). Consumption is acknowledged separately (``acked``): an event is
acked only when the SAME engine process generation that was running at append time
has read past the event's end offset and a short settle time has passed. If the
engine generation changes first (crash/restart) the event is re-appended, and after
any generation change recently acked events are replayed (bounded window, minus
addresses unbanned since) so in-memory scenario buckets are rebuilt. Scenarios
deduplicate by event id (``distinct``), so replay does not double count.
Guarantee: at-least-once into the engine for events younger than the replay window;
reading past an event is the strongest consumption signal available without
changing CrowdSec, and a crash inside the settle time is covered by the replay.
"""
import datetime as dt
import hashlib
import ipaddress
import json
import os
import re
from pathlib import Path
import secrets
import sqlite3
import time
import uuid
from contextlib import contextmanager

from .common import MEMBER

MAX_EVENTS = 10000
MAX_SOURCE_EVENTS = 2000   # undelivered events per source: one source cannot starve the others
MAX_CLAIMS = 10000
MAX_PEER_CLAIMS = 2000     # all retained claims per peer, including tombstones
BATCH = 256
ACK_SETTLE = 3.0         # seconds after append before a read-past offset counts as consumed
REPLAY_WINDOW = 120.0    # re-feed acked events newer than this after an engine restart (bucket rebuild)
TIMESTAMP = re.compile(r'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{1,6})?Z\Z')


def digest(token):
    return hashlib.sha256(token.encode()).hexdigest()


def address(value):
    ip = ipaddress.ip_address(value)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if ip.is_multicast or ip.is_unspecified or ip.is_loopback or ip.is_link_local or ip.is_reserved or str(ip) == '255.255.255.255':
        raise ValueError('source_ip must be unicast, non-local')
    return str(ip)


def validate_event(event, check_age=True):
    fields = {'schema_version', 'id', 'occurred_at', 'event', 'source_ip'}
    if not isinstance(event, dict) or set(event) != fields:
        raise ValueError('unknown or missing event field')
    if type(event['schema_version']) is not int or event['schema_version'] != 1 or event['event'] != 'authentication_failed':
        raise ValueError('unsupported event')
    if not isinstance(event['id'], str) or str(uuid.UUID(event['id'])) != event['id']:
        raise ValueError('id must be canonical UUID')
    timestamp = event['occurred_at']
    if not isinstance(timestamp, str) or not TIMESTAMP.match(timestamp):
        raise ValueError('occurred_at must be UTC RFC3339')
    occurred = dt.datetime.fromisoformat(timestamp.replace('Z', '+00:00')).timestamp()
    if check_age:
        age = time.time() - occurred
        if age > 7 * 86400:
            raise ValueError('event exceeds seven day replay limit')
        if age < -300:
            raise ValueError('event exceeds 300 second future clock skew')
    if not isinstance(event['source_ip'], str):
        raise ValueError('source_ip must be string')
    return dict(event, source_ip=address(event['source_ip']))


class Store:
    def __init__(self, state):
        self.state = Path(state)
        self.state.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.path = self.state / 'hybrid.db'
        with self.connect() as db:
            db.executescript('''
            CREATE TABLE IF NOT EXISTS sources(name TEXT PRIMARY KEY, module TEXT UNIQUE NOT NULL,
                token_hash TEXT UNIQUE NOT NULL, created REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS events(source TEXT NOT NULL, id TEXT NOT NULL, body TEXT NOT NULL,
                accepted REAL NOT NULL, delivered INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(source,id));
            CREATE TABLE IF NOT EXISTS peers(name TEXT PRIMARY KEY, token_hash TEXT UNIQUE NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0, last_seen REAL);
            CREATE TABLE IF NOT EXISTS claims(origin TEXT NOT NULL, id TEXT NOT NULL, value TEXT NOT NULL,
                expires_at REAL NOT NULL, deleted INTEGER NOT NULL, seq INTEGER NOT NULL,
                PRIMARY KEY(origin,id));
            CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS unbans(ip TEXT PRIMARY KEY, at REAL NOT NULL);
            INSERT OR IGNORE INTO meta VALUES('sequence','0');
            ''')
            db.execute('BEGIN IMMEDIATE')  # serialize concurrent source-schema migration
            # Existing installations have active sources; new action-created
            # sources remain pending until their credential is flushed.
            if 'active' not in {r[1] for r in db.execute('PRAGMA table_info(sources)')}:
                db.execute('ALTER TABLE sources ADD COLUMN active INTEGER NOT NULL DEFAULT 1')
            have = {r[1] for r in db.execute('PRAGMA table_info(events)')}
            for column, ddl in (('file_end', 'INTEGER'), ('appended_gen', 'TEXT'), ('appended_at', 'REAL'), ('acked', 'REAL'),
                                ('log_seq', 'INTEGER NOT NULL DEFAULT 0'), ('replay', 'INTEGER NOT NULL DEFAULT 0')):
                if column not in have:
                    db.execute('ALTER TABLE events ADD COLUMN %s %s' % (column, ddl))
            db.execute("INSERT OR IGNORE INTO meta VALUES('epoch',?)", (str(uuid.uuid4()),))
        os.chmod(self.state, 0o700)
        os.chmod(self.path, 0o600)

    def epoch(self):
        with self.connect() as db:
            return db.execute("SELECT value FROM meta WHERE key='epoch'").fetchone()[0]

    def new_epoch(self):
        """Forget what peers know: used after the database was restored from a snapshot."""
        with self.connect() as db:
            db.execute("INSERT OR REPLACE INTO meta VALUES('epoch',?)", (str(uuid.uuid4()),))
            # Events of the snapshot belong to a past that may contain addresses unbanned elsewhere since: never
            # requeue or replay them into the restored engine, and forget the engine generation they refer to.
            db.execute('UPDATE events SET appended_gen=NULL, acked=NULL WHERE delivered=1')
            db.execute("DELETE FROM meta WHERE key='engine_gen'")

    def known_credential(self, kind, token):
        """Cheap pre-parse authentication check (kind: 'peer' or 'source')."""
        table, extra = ('peers', ' AND revoked=0') if kind == 'peer' else ('sources', ' AND active=1')
        with self.connect() as db:
            return db.execute('SELECT 1 FROM %s WHERE token_hash=?%s' % (table, extra), (digest(token),)).fetchone() is not None

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=15)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA journal_mode=WAL')
        db.execute('PRAGMA synchronous=FULL')
        try:
            with db:
                yield db
        finally:
            db.close()

    def add_source(self, name, module, active=True):
        if not isinstance(name, str) or not MEMBER.fullmatch(name) or not isinstance(module, str) or not MEMBER.fullmatch(module):
            raise ValueError('invalid source name/module')
        token = secrets.token_urlsafe(32)
        with self.connect() as db:
            db.execute('INSERT INTO sources(name,module,token_hash,created,active) VALUES(?,?,?,?,?)',
                       (name,module,digest(token),time.time(),int(active)))
        return token

    def add_peer(self, name):
        if not isinstance(name, str) or not MEMBER.fullmatch(name):
            raise ValueError('invalid peer name')
        token = secrets.token_urlsafe(32)
        with self.connect() as db:
            # Names cannot be reused: old claim origins must remain unambiguous.
            db.execute('INSERT INTO peers(name,token_hash) VALUES(?,?)', (name,digest(token)))
        return token

    def rotate_peer(self, name):
        """New credential for an existing, non-revoked peer (lost-secret recovery)."""
        token = secrets.token_urlsafe(32)
        with self.connect() as db:
            if not db.execute('UPDATE peers SET token_hash=? WHERE name=? AND revoked=0', (digest(token), name)).rowcount:
                raise KeyError(name)
        return token

    def list_peers(self):
        with self.connect() as db:
            return [dict(r) for r in db.execute('SELECT name,revoked,last_seen FROM peers ORDER BY name')]

    def remove_peer(self, name):
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('DELETE FROM claims WHERE expires_at<=?', (time.time(),))
            db.execute('UPDATE peers SET revoked=1 WHERE name=?', (name,))
            # Retain bounded revocations until the original expiry: deleting
            # them early would strand bans on observers that were offline.
            rows = db.execute('SELECT * FROM claims WHERE origin=? AND deleted=0', (name,)).fetchall()
            for row in rows:
                self._put_claim(db, name, dict(row, deleted=True))

    def _put_claim(self, db, origin, item):
        current = db.execute('SELECT * FROM claims WHERE origin=? AND id=?', (origin,item['id'])).fetchone()
        if current:
            if current['value'] != item['value'] or current['expires_at'] != item['expires_at']:
                raise ValueError('claim identity/expiry is immutable')
            if current['deleted'] or bool(current['deleted']) == item['deleted']:
                return
        elif item['expires_at'] <= time.time():
            return  # already expired: nothing to enforce or to revoke
        elif db.execute('SELECT count(*) FROM claims WHERE origin=?', (origin,)).fetchone()[0] >= MAX_PEER_CLAIMS:
            raise OverflowError('per-peer journal quota exceeded')
        elif db.execute('SELECT count(*) FROM claims').fetchone()[0] >= MAX_CLAIMS:
            raise OverflowError('claim journal full')
        db.execute("UPDATE meta SET value=CAST(value AS INTEGER)+1 WHERE key='sequence'")
        seq = int(db.execute("SELECT value FROM meta WHERE key='sequence'").fetchone()[0])
        db.execute('INSERT OR REPLACE INTO claims VALUES(?,?,?,?,?,?)',
            (origin,item['id'],item['value'],item['expires_at'],int(item['deleted']),seq))

    def exchange(self, token, request):
        if not isinstance(request, dict) or set(request) != {'cursor','updates'}:
            raise ValueError('invalid sync request')
        if type(request['cursor']) is not int or request['cursor'] < 0 or not isinstance(request['updates'],list) or len(request['updates']) > BATCH:
            raise ValueError('invalid sync batch')
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            peer = db.execute('SELECT name FROM peers WHERE token_hash=? AND revoked=0', (digest(token),)).fetchone()
            if peer is None:
                raise PermissionError('invalid peer credential')
            # Never make admission depend on a previous empty exchange. Expired
            # bans and tombstones cannot affect enforcement on any client.
            db.execute('DELETE FROM claims WHERE expires_at<=?', (time.time(),))
            rejected = []
            retryable = []
            for item in request['updates']:
                # Classify each claim independently: invalid claims are final,
                # capacity failures retain a retryable ID for bounded backoff.
                try:
                    if not isinstance(item,dict) or set(item) != {'id','value','expires_at','deleted'}:
                        raise ValueError('invalid claim')
                    if not isinstance(item['id'],str) or not (item['id'].isascii() and item['id'].isdigit()) or len(item['id']) > 20 or type(item['deleted']) is not bool:
                        raise ValueError('invalid claim identity')
                    if type(item['expires_at']) not in (int,float) or not 0 < item['expires_at'] <= time.time()+7*86400:
                        raise ValueError('claim lifetime exceeds seven day sync limit')
                    if not isinstance(item['value'],str) or item['value'] != address(item['value']):
                        raise ValueError('claim IP must be normalized')
                    self._put_claim(db, peer['name'], item)
                except OverflowError:
                    rejected.append(item['id'])
                    retryable.append(item['id'])
                except ValueError:
                    rejected.append(item.get('id') if isinstance(item,dict) and isinstance(item.get('id'),str) else None)
            db.execute('UPDATE peers SET last_seen=? WHERE name=?', (time.time(),peer['name']))

            sequence = int(db.execute("SELECT value FROM meta WHERE key='sequence'").fetchone()[0])
            cursor = request['cursor'] if request['cursor'] <= sequence else 0  # a cursor from the future is meaningless
            rows = db.execute('SELECT * FROM claims WHERE seq>? ORDER BY seq LIMIT ?', (cursor,BATCH)).fetchall()
            changes = [dict(r, deleted=bool(r['deleted'])) for r in rows]
            epoch = db.execute("SELECT value FROM meta WHERE key='epoch'").fetchone()[0]
            return {'changes':changes, 'cursor':rows[-1]['seq'] if rows else cursor, 'has_more':len(rows)==BATCH,
                    'epoch':epoch, 'rejected':rejected, 'retryable':retryable}

    def activate_source(self, name, token):
        with self.connect() as db:
            if not db.execute('UPDATE sources SET active=1 WHERE name=? AND token_hash=?', (name,digest(token))).rowcount:
                raise ValueError('pending source no longer exists')

    def list_sources(self, include_pending=False):
        with self.connect() as db:
            return [dict(r) for r in db.execute('SELECT name,module,created,active FROM sources' +
                    ('' if include_pending else ' WHERE active=1') + ' ORDER BY name')]

    def remove_source(self, name):
        with self.connect() as db:
            db.execute('DELETE FROM sources WHERE name=?', (name,))

    def accept_event(self, token, event):
        with self.connect() as db:
            source = db.execute('SELECT * FROM sources WHERE token_hash=? AND active=1', (digest(token),)).fetchone()
            if source is None:
                raise PermissionError('invalid source credential')
            event = validate_event(event, check_age=False)
            body = dict(event, service=source['module'])
            current = db.execute('SELECT body FROM events WHERE source=? AND id=?', (source['module'],event['id'])).fetchone()
            if current:
                if json.loads(current['body']) != body:
                    raise ValueError('event identity is immutable')
                return False
            validate_event(event)
            if db.execute('SELECT count(*) FROM events WHERE delivered=0').fetchone()[0] >= MAX_EVENTS \
                    or db.execute('SELECT count(*) FROM events WHERE delivered=0 AND source=?', (source['module'],)).fetchone()[0] >= MAX_SOURCE_EVENTS:
                raise OverflowError('event queue full')
            db.execute('INSERT INTO events(source,id,body,accepted) VALUES(?,?,?,?)',
                       (source['module'],event['id'],json.dumps(body,separators=(',',':')),time.time()))
        return True

    TAIL = 512 * 1024

    @classmethod
    def _tail_lines(cls, path):
        """Last complete lines of a log file. A crash between the fsynced append
        and the database commit can only have left events at the very end."""
        try:
            with open(path, 'rb') as f:
                size = f.seek(0, os.SEEK_END)
                f.seek(max(0, size - cls.TAIL))
                data = f.read()
        except FileNotFoundError:
            return set()
        return set(data.decode('utf-8', 'replace').splitlines())

    def event_consumer_state(self, container=None, event_path='/var/log/ns8-events/auth.jsonl'):
        """Engine process generation and acquisition offset, or None if it cannot be determined.

        Returns {'ready': fd open, 'gen': 'boot:pid:starttime', 'pos': smallest read offset, 'size': file size}.
        """
        from . import lifecycle
        container = container or lifecycle.module_id()
        script = r'''path=$1
        size=$(stat -Lc %s "$path" 2>/dev/null) || size=0
        boot=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)
        gen=; pos=; ready=0
        for proc in /proc/[0-9]*; do
            [ "$(cat "$proc/comm" 2>/dev/null)" = crowdsec ] || continue
            read -r stat < "$proc/stat" 2>/dev/null || continue
            set -- ${stat##*) }
            gen="$boot:${proc##*/}:${20}"
            for fd in "$proc"/fd/*; do
                [ "$fd" -ef "$path" ] || continue
                ready=1
                p=
                while read -r key value rest; do
                    [ "$key" = pos: ] && p=$value
                done < "$proc/fdinfo/${fd##*/}"
                [ -n "$p" ] || continue
                if [ -z "$pos" ] || [ "$p" -lt "$pos" ]; then pos=$p; fi
            done
        done
        echo "gen=$gen"; echo "ready=$ready"; echo "pos=${pos:-0}"; echo "size=$size"'''
        result = lifecycle.run(['podman', 'exec', container, 'sh', '-c', script, 'state', event_path], check=False, timeout=5)
        if result.returncode != 0:
            return None
        values = dict(line.split('=', 1) for line in (result.stdout or '').splitlines() if '=' in line)
        try:
            if not values.get('gen'):
                return {'ready': False, 'gen': '', 'pos': 0, 'size': int(values.get('size', 0))}
            return {'ready': values.get('ready') == '1', 'gen': values['gen'],
                    'pos': int(values.get('pos', 0)), 'size': int(values.get('size', 0))}
        except (ValueError, KeyError):
            return None

    def event_consumer_ready(self, container=None, event_path='/var/log/ns8-events/auth.jsonl'):
        """Check a running Engine's actual open acquisition file, not just LAPI.

        This is a readiness gate, NOT a consumption ACK. A crash immediately
        after this probe or append can still lose unconsumed bucket input.
        """
        from . import lifecycle
        container = container or lifecycle.module_id()
        script = r'''for proc in /proc/[0-9]*; do
            [ "$(cat "$proc/comm" 2>/dev/null)" = crowdsec ] || continue
            for fd in "$proc"/fd/*; do
                [ "$fd" -ef "$1" ] && exit 0
            done
        done
        exit 1'''
        result = lifecycle.run(['podman','exec',container,'sh','-c',script,'readiness',event_path],
                               check=False,timeout=5)
        return result.returncode == 0

    def event_consumer_drained(self, container=None, event_path='/var/log/ns8-events/auth.jsonl'):
        """Rotation guard: every matching acquisition FD reached current EOF.

        A kernel read offset is not an acknowledgement of parsing or scenarios.
        """
        from . import lifecycle
        container = container or lifecycle.module_id()
        script = r'''size=$(stat -Lc %s "$1") || exit 1
        found=0
        for proc in /proc/[0-9]*; do
            [ "$(cat "$proc/comm" 2>/dev/null)" = crowdsec ] || continue
            for fd in "$proc"/fd/*; do
                [ "$fd" -ef "$1" ] || continue
                found=1
                pos=
                while read -r key value rest; do
                    [ "$key" = pos: ] && pos=$value
                done < "$proc/fdinfo/${fd##*/}"
                [ -n "$pos" ] && [ "$pos" -ge "$size" ] || exit 1
            done
        done
        [ "$found" = 1 ]'''
        result = lifecycle.run(['podman','exec',container,'sh','-c',script,'rotation',event_path],
                               check=False,timeout=5)
        return result.returncode == 0

    EVENT_LOG_LIMIT = 32 * 1024 * 1024

    def note_unban(self, ip):
        """Remember an operator unban so replay never re-feeds events from before it."""
        with self.connect() as db:
            db.execute('INSERT OR REPLACE INTO unbans VALUES(?,?)', (str(ipaddress.ip_address(ip)), time.time()))
            db.execute('DELETE FROM unbans WHERE at<?', (time.time() - 7 * 86400,))

    def event_status(self):
        with self.connect() as db:
            replayed = db.execute("SELECT value FROM meta WHERE key='event_replayed_total'").fetchone()
            return {'pending': db.execute('SELECT count(*) FROM events WHERE delivered=0').fetchone()[0],
                    'unacked': db.execute('SELECT count(*) FROM events WHERE delivered=1 AND acked IS NULL AND appended_gen IS NOT NULL').fetchone()[0],
                    'replayed_total': int(replayed[0]) if replayed else 0}

    def _observe_generation(self, db, gen):
        """Detect an engine restart. Returns (requeued, replayed). Must run inside a write transaction."""
        row = db.execute("SELECT value FROM meta WHERE key='engine_gen'").fetchone()
        if row and row[0] == gen:
            return 0, 0
        db.execute("INSERT OR REPLACE INTO meta VALUES('engine_gen',?)", (gen,))
        if row is None:
            return 0, 0                      # first observation: nothing was fed to an earlier generation
        now = time.time()
        requeued = db.execute("""UPDATE events SET delivered=0, replay=1, appended_gen=NULL, file_end=NULL
                                 WHERE delivered=1 AND acked IS NULL AND appended_gen IS NOT NULL""").rowcount
        replayed = db.execute("""UPDATE events SET delivered=0, replay=1, appended_gen=NULL, file_end=NULL, acked=NULL
                                 WHERE delivered=1 AND acked IS NOT NULL AND appended_gen IS NOT NULL AND appended_at>=?
                                   AND NOT EXISTS (SELECT 1 FROM unbans WHERE unbans.ip=json_extract(events.body,'$.source_ip')
                                                   AND unbans.at>=events.appended_at)""", (now - REPLAY_WINDOW,)).rowcount
        if replayed:
            total = db.execute("SELECT value FROM meta WHERE key='event_replayed_total'").fetchone()
            db.execute("INSERT OR REPLACE INTO meta VALUES('event_replayed_total',?)", (str(int(total[0] if total else 0) + replayed),))
        return requeued, replayed

    def ack_events(self, consumer_state):
        """Acknowledge consumed events, requeue those lost to an engine restart. Idempotent; never raises on probe failure."""
        empty = {'acked': 0, 'requeued': 0, 'replayed': 0}
        state = consumer_state()
        if not state or not state.get('gen'):
            return empty
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            requeued, replayed = self._observe_generation(db, state['gen'])
            now = time.time()
            seq = int((db.execute("SELECT value FROM meta WHERE key='log_seq'").fetchone() or ('0',))[0])
            acked = db.execute("""UPDATE events SET acked=? WHERE delivered=1 AND acked IS NULL AND appended_gen=? AND (
                                    log_seq<? OR (log_seq=? AND file_end<=? AND appended_at<=?))""",
                               (now, state['gen'], seq, seq, state['pos'], now - ACK_SETTLE)).rowcount
        return {'acked': acked, 'requeued': requeued, 'replayed': replayed}

    def deliver_events(self, consumer_ready=None, consumer_state=None):
        directory = self.state / 'events'
        path = directory / 'auth.jsonl'
        previous = directory / 'auth.previous'
        # Recover a crash after rename but before creation. Acquisition cannot
        # reopen a missing filename, so repair it before the readiness probe.
        if previous.exists() and not path.exists():
            with path.open('xb') as fresh:
                os.chmod(path, 0o600)
                os.fsync(fresh.fileno())
            fd = os.open(directory, os.O_RDONLY)
            try: os.fsync(fd)
            finally: os.close(fd)
        # Call the real readiness probe before opening a write transaction.
        # A false result leaves the durable queue untouched for the next tick.
        state = None
        if consumer_state is not None:
            state = consumer_state()
            if not state or not state.get('ready') or not state.get('gen'):
                return 0
        elif consumer_ready is not None and not consumer_ready():
            return 0
        directory.mkdir(mode=0o700, exist_ok=True)
        rotate = path.exists() and path.stat().st_size > self.EVENT_LOG_LIMIT
        # A tailer follows the filename after rotation. Never put a pending
        # batch into a new inode before acquisition has opened that inode.
        if rotate and (consumer_ready is not None or state is not None) and not self.event_consumer_drained():
            return 0
        count = 0
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            if state is not None:
                self._observe_generation(db, state['gen'])
            rows = db.execute('SELECT * FROM events WHERE delivered=0 ORDER BY accepted LIMIT ?', (BATCH,)).fetchall()
            if not rows:
                return 0
            seq = int((db.execute("SELECT value FROM meta WHERE key='log_seq'").fetchone() or ('0',))[0])
            if rotate:
                # The old file was read to EOF by every matching fd (drained probe above): its rows are consumed.
                db.execute('UPDATE events SET acked=? WHERE delivered=1 AND acked IS NULL AND appended_gen IS NOT NULL AND log_seq=?', (time.time(), seq))
                db.execute("INSERT OR REPLACE INTO meta VALUES('log_seq',?)", (str(seq + 1),))
                os.replace(path, previous)
                with path.open('xb') as fresh:
                    os.chmod(path, 0o600)
                    os.fsync(fresh.fileno())
                fd = os.open(directory, os.O_RDONLY)
                try: os.fsync(fd)
                finally: os.close(fd)
                # Leave rows pending. Next tick verifies the new inode is open.
                return 0
            seen = self._tail_lines(path) | self._tail_lines(previous)
            created = not path.exists()
            with path.open('ab') as log:
                os.chmod(path, 0o600)
                if log.tell():
                    with open(path, 'rb') as last:
                        last.seek(-1, os.SEEK_END)
                        if last.read(1) != b'\n':
                            log.write(b'\n')  # a torn last line must not swallow the next event
                for row in rows:
                    if row['replay'] or row['body'] not in seen:
                        log.write(row['body'].encode() + b'\n')
                        count += 1
                    if state is not None:
                        log.flush()
                        db.execute('UPDATE events SET delivered=1, replay=0, acked=NULL, appended_gen=?, appended_at=?, file_end=?, log_seq=? '
                                   'WHERE source=? AND id=?', (state['gen'], time.time(), log.tell(), seq, row['source'], row['id']))
                    else:
                        db.execute('UPDATE events SET delivered=1 WHERE source=? AND id=?', (row['source'],row['id']))
                log.flush()
                os.fsync(log.fileno())
            if created:
                fd = os.open(directory, os.O_RDONLY)
                try: os.fsync(fd)
                finally: os.close(fd)
            db.execute('DELETE FROM events WHERE delivered=1 AND accepted<?', (time.time()-86400,))   # retention also bounds unacked rows
        return count
