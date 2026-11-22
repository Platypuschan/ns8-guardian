"""Independent local-LAPI reconciliation and outbound private sync.

Imported claims have stable reason tags and are removed ONLY by their LAPI
IDs. Manual local unban suppresses that imported claim until expiry; it does
not revoke another origin's shared claim. A node publishes only its own bans.
"""
import datetime as dt
import ipaddress
import json
import math
import re
import ssl
import time
import urllib.request

from .common import load_config, read_secret, secret, state_dir, atomic_write
from .common import MEMBER
from .hybrid import Store, BATCH, address, digest
from . import lifecycle

PREFIX = 'ns8-sync/'


def duration_seconds(value):
    return sum(float(n)*{'ns':1e-9,'us':1e-6,'µs':1e-6,'ms':.001,'s':1,'m':60,'h':3600}[u]
               for n,u in re.findall(r'(\d+(?:\.\d+)?)(ns|us|µs|ms|s|m|h)', value)) * (-1 if value.startswith('-') else 1)


class LAPI:
    def decisions(self):
        now = time.time()
        rows=[]
        # `decisions list` deduplicates by IP, hiding independent claims. The
        # supported alerts API retains every decision ID, including overlaps.
        for alert in lifecycle.cscli_json('alerts','list','--limit','0'):
            for d in alert.get('decisions') or []:
                if d.get('simulated') or d.get('type') != 'ban' or d.get('scope','').lower() != 'ip':
                    continue
                try:
                    until = d.get('until')
                    expires = dt.datetime.fromisoformat(until.replace('Z','+00:00')).timestamp() if until else now+duration_seconds(d['duration'])
                    if expires <= now:
                        continue
                    rows.append({'id':str(d['id']),'value':str(ipaddress.ip_address(d['value'])),
                        'expires_at':expires,'scenario':d.get('scenario',''),'stamp':str(alert.get('created_at') or alert.get('start_at') or '')})
                except (ValueError,KeyError,TypeError):
                    raise RuntimeError('unsupported local decision format') from None
        return rows

    def add(self, value, duration, reason):
        lifecycle.cscli('decisions','add','--ip',value,'--duration',str(max(1,math.floor(duration)))+'s','--reason',reason)

    def delete(self, id):
        lifecycle.cscli('decisions','delete','--id',str(id))


# Never enforce imported bans for these ranges: a peer must not be able to ban a
# host's LAN, VPN or management addresses. Local detection still bans them locally.
PRIVATE = [ipaddress.ip_network(n) for n in
           ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10', 'fc00::/7')]
MAX_IMPORTS_PER_ORIGIN = 2000
MAX_IMPORTS = 10000
RETRY_SECONDS = 5
MAX_RETRY_SECONDS = 300


def claim_id(row):
    """Stable claim identity that survives LAPI id reuse after a database reset."""
    return str(int(digest('%s|%s|%s' % (row['id'], row['value'], row.get('stamp', '')))[:16], 16))


class Client:
    def __init__(self, store, lapi, origin):
        self.store,self.lapi,self.origin = store,lapi,origin
        with store.connect() as db:
            db.executescript('''
            CREATE TABLE IF NOT EXISTS local_claims(id TEXT PRIMARY KEY, lapi_id TEXT, value TEXT NOT NULL,
                expires_at REAL NOT NULL, deleted INTEGER NOT NULL DEFAULT 0, pending INTEGER NOT NULL DEFAULT 1);
            CREATE TABLE IF NOT EXISTS imports(origin TEXT NOT NULL, id TEXT NOT NULL, value TEXT NOT NULL,
                expires_at REAL NOT NULL, deleted INTEGER NOT NULL, local_id TEXT, suppressed INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(origin,id));
            INSERT OR IGNORE INTO meta VALUES('cursor','0');
            INSERT OR IGNORE INTO meta VALUES('hub_epoch','');
            INSERT OR IGNORE INTO meta VALUES('rejected_total','0');
            INSERT OR IGNORE INTO meta VALUES('import_retry','0');
            INSERT OR IGNORE INTO meta VALUES('import_overload','0');
            INSERT OR IGNORE INTO meta VALUES('local_export_overload','0');
            ''')
            # Migrate existing private journals without discarding pending work.
            columns = {r['name'] for r in db.execute('PRAGMA table_info(local_claims)')}
            for name, definition in (('retry_after', 'REAL NOT NULL DEFAULT 0'),
                                     ('attempts', 'INTEGER NOT NULL DEFAULT 0')):
                if name not in columns:
                    db.execute('ALTER TABLE local_claims ADD COLUMN '+name+' '+definition)

    def marker(self, origin, id):
        return PREFIX + digest(origin+':'+id)[:32]

    def reconcile(self, allowlist):
        """Align the local LAPI with the journals.

        All LAPI calls happen outside database transactions (they take seconds
        on a loaded engine and would otherwise starve the hub's own writers).
        One failing claim never prevents the others from being processed; the
        error is raised at the end so status shows the sync as incomplete.
        """
        now=time.time()
        networks=[ipaddress.ip_network(v,strict=False) for v in allowlist]
        def allowed(value): return any(ipaddress.ip_address(value) in n for n in networks)
        errors=0
        rows=self.lapi.decisions() # Failure MUST NOT be treated as empty state.
        by_reason={r['scenario']:r for r in rows if r['scenario'].startswith(PREFIX)}
        for row in rows:
            if not row['scenario'].startswith(PREFIX) and allowed(row['value']):
                try: self.lapi.delete(row['id'])
                except RuntimeError: errors+=1
        own={}
        for r in rows:
            if r['scenario'].startswith(PREFIX) or r['expires_at']<=now or allowed(r['value']): continue
            try: value=address(r['value'])
            except ValueError: continue # loopback/multicast/...: not shareable, stays local
            # Never clear long local bans. Only export what the protocol's
            # maximum remaining lifetime (seven days) can carry.
            if r['expires_at']>now+7*86400: continue
            own[claim_id(r)]=(r,value)
        with self.store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            # Even an unacknowledged expired tombstone is now irrelevant to a
            # restored hub: its original ban cannot be enforced anywhere.
            db.execute('DELETE FROM local_claims WHERE expires_at<=?', (now,))
            overflow=False
            for cid,(r,value) in own.items():
                if not db.execute('SELECT 1 FROM local_claims WHERE id=?',(cid,)).fetchone():
                    if db.execute('SELECT count(*) FROM local_claims').fetchone()[0]>=MAX_IMPORTS:
                        # The LAPI remains authoritative for this live local ban:
                        # retry next reconciliation, without blocking revocations.
                        overflow=True
                        continue
                    db.execute('INSERT INTO local_claims(id,lapi_id,value,expires_at) VALUES(?,?,?,?)',(cid,str(r['id']),value,r['expires_at']))
            db.execute("UPDATE meta SET value=? WHERE key='local_export_overload'", ('1' if overflow else '0',))
            for row in db.execute('SELECT * FROM local_claims WHERE deleted=0').fetchall():
                if row['id'] not in own or row['expires_at']<=now:
                    db.execute('UPDATE local_claims SET deleted=1,pending=1,retry_after=0,attempts=0 WHERE id=?',(row['id'],))
            imports=[dict(r) for r in db.execute('SELECT * FROM imports').fetchall()]
        updates=[]; created=[]
        for claim in imports:
            marker=self.marker(claim['origin'],claim['id'])
            actual=by_reason.get(marker)
            key=(claim['origin'],claim['id'])
            private=any(ipaddress.ip_address(claim['value']) in n for n in PRIVATE)
            remove=claim['deleted'] or claim['expires_at']<=now or allowed(claim['value']) or claim['suppressed'] or private
            try:
                if remove:
                    if actual:
                        self.lapi.delete(actual['id'])
                    if private and not claim['suppressed']:
                        updates.append(('UPDATE imports SET suppressed=1,local_id=NULL WHERE origin=? AND id=?',key))
                    elif allowed(claim['value']) and not claim['suppressed']:
                        updates.append(('UPDATE imports SET local_id=NULL WHERE origin=? AND id=?',key))
                    continue
                if actual:
                    updates.append(('UPDATE imports SET local_id=? WHERE origin=? AND id=?',(actual['id'],)+key))
                    continue
                if claim['local_id']:
                    # An administrator/bouncer policy removed the claim. Keep
                    # a durable override, never recreate it on next snapshot.
                    updates.append(('UPDATE imports SET suppressed=1 WHERE origin=? AND id=?',key))
                    continue
                try:
                    self.lapi.add(claim['value'],claim['expires_at']-time.time(),marker)
                except RuntimeError as error:
                    if 'allowlist' not in str(error).lower(): raise
                    # An administrator's LAPI allowlist outside this module's config.
                    updates.append(('UPDATE imports SET suppressed=1 WHERE origin=? AND id=?',key))
                    continue
                created.append((marker,key))
            except RuntimeError:
                errors+=1
        if created:
            # Recovery after a crash also relies on the unique scenario marker.
            found={r['scenario']:r for r in self.lapi.decisions()}
            for marker,key in created:
                if marker in found:
                    updates.append(('UPDATE imports SET local_id=? WHERE origin=? AND id=?',(found[marker]['id'],)+key))
                else:
                    updates.append(('UPDATE imports SET suppressed=1 WHERE origin=? AND id=?',key))
        with self.store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            for sql,params in updates: db.execute(sql,params)
            db.execute('DELETE FROM imports WHERE expires_at<?',(now-60,))
            db.execute('DELETE FROM local_claims WHERE pending=0 AND expires_at<?',(now-60,))
        if errors: raise RuntimeError('reconcile incomplete: %d LAPI operations failed'%errors)

    def pending(self):
        with self.store.connect() as db:
            return [dict(r,deleted=bool(r['deleted'])) for r in db.execute(
                'SELECT id,value,expires_at,deleted FROM local_claims WHERE pending=1 AND retry_after<=? '
                'ORDER BY retry_after,id LIMIT ?', (time.time(),BATCH))]

    def cursor(self):
        with self.store.connect() as db: return int(db.execute("SELECT value FROM meta WHERE key='cursor'").fetchone()[0])

    def receive(self, reply, sent=()):
        if not isinstance(reply,dict) or not isinstance(reply.get('changes'),list) or len(reply['changes'])>BATCH \
                or type(reply.get('cursor')) is not int or reply['cursor']<0 \
                or not isinstance(reply.get('epoch',''),str) or not isinstance(reply.get('rejected',[]),list) \
                or not isinstance(reply.get('retryable',[]),list) \
                or any(not isinstance(id,str) for id in reply.get('retryable',[])):
            raise ValueError('invalid controller response')
        with self.store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            cursor=int(db.execute("SELECT value FROM meta WHERE key='cursor'").fetchone()[0])
            known=db.execute("SELECT value FROM meta WHERE key='hub_epoch'").fetchone()[0]
            epoch=reply.get('epoch','')
            reset=bool(known and epoch and known!=epoch)
            if reply['cursor']<cursor and not reset:
                raise ValueError('controller cursor moved backwards')
            # No expired claim can enforce a ban; collect before admission,
            # including retained revocations and manual-suppression markers.
            db.execute('DELETE FROM imports WHERE expires_at<=?', (time.time(),))
            for item in reply['changes']:
                if not isinstance(item,dict) or set(item)!={'origin','id','value','expires_at','deleted','seq'} \
                        or not isinstance(item['origin'],str) or not MEMBER.fullmatch(item['origin']) \
                        or not isinstance(item['id'],str) or not (item['id'].isascii() and item['id'].isdigit()) or len(item['id'])>20:
                    raise ValueError('invalid remote claim')
                if item['origin']==self.origin: continue
                try:
                    if address(item['value'])!=item['value']: continue # not shareable: ignore, never enforce
                except (ValueError,TypeError): continue
                if type(item['expires_at']) not in (int,float) or not math.isfinite(item['expires_at']) or item['expires_at']>time.time()+7*86400 or type(item['deleted']) is not bool:
                    raise ValueError('invalid remote expiry')
                old=db.execute('SELECT * FROM imports WHERE origin=? AND id=?',(item['origin'],item['id'])).fetchone()
                if old:
                    if old['value']!=item['value'] or old['expires_at']!=item['expires_at']: raise ValueError('remote claim mutation')
                    db.execute('UPDATE imports SET deleted=max(deleted,?) WHERE origin=? AND id=?',(int(item['deleted']),item['origin'],item['id']))
                elif item['expires_at']<=time.time():
                    continue
                elif db.execute('SELECT count(*) FROM imports WHERE origin=?',(item['origin'],)).fetchone()[0]>=MAX_IMPORTS_PER_ORIGIN \
                        or db.execute('SELECT count(*) FROM imports').fetchone()[0]>=MAX_IMPORTS:
                    db.execute("UPDATE meta SET value='1' WHERE key IN ('import_retry','import_overload')")
                    continue
                else:
                    db.execute('INSERT INTO imports(origin,id,value,expires_at,deleted) VALUES(?,?,?,?,?)',
                               (item['origin'],item['id'],item['value'],item['expires_at'],int(item['deleted'])))
            if reset:
                # The hub was restored from an older snapshot or rebuilt: start
                # from its beginning. Republish below, AFTER acknowledgements.
                db.execute("UPDATE meta SET value='0' WHERE key='cursor'")
            else:
                db.execute("UPDATE meta SET value=? WHERE key='cursor'",(str(reply['cursor']),))
                if not reply.get('has_more',False):
                    retry=db.execute("SELECT value FROM meta WHERE key='import_retry'").fetchone()[0]=='1'
                    if retry:
                        # Finish the scan BEFORE rewinding: a saturated origin
                        # must not hide later pages belonging to other origins.
                        db.execute("UPDATE meta SET value='0' WHERE key='cursor'")
                    db.execute("UPDATE meta SET value=? WHERE key='import_overload'", ('1' if retry else '0',))
                    db.execute("UPDATE meta SET value='0' WHERE key='import_retry'")
            if epoch: db.execute("UPDATE meta SET value=? WHERE key='hub_epoch'",(epoch,))
            sent_ids=set()
            for row in sent:
                sent_ids.add(row['id'])
                key=(row['id'],int(row['deleted']))
                if row['id'] in reply.get('retryable',[]):
                    current=db.execute('SELECT attempts FROM local_claims WHERE id=? AND deleted=?',key).fetchone()
                    if current:
                        attempts=min(current['attempts']+1,7)
                        delay=min(MAX_RETRY_SECONDS,RETRY_SECONDS*2**(attempts-1))
                        db.execute('UPDATE local_claims SET pending=1,retry_after=?,attempts=? WHERE id=? AND deleted=?',
                                   (time.time()+delay,attempts)+key)
                else:
                    db.execute('UPDATE local_claims SET pending=0,retry_after=0,attempts=0 WHERE id=? AND deleted=?',key)
            for rejected in reply.get('rejected',[]):
                # Preserve the legacy rejected-ID list, but capacity failures
                # are temporary and must retain their durable backoff state.
                if isinstance(rejected,str) and rejected not in reply.get('retryable',[]) and rejected not in sent_ids:
                    # Legacy callers may supply rejected IDs outside `sent`;
                    # never let such an ACK erase a newer local revocation.
                    db.execute('UPDATE local_claims SET pending=0 WHERE id=? AND deleted=0',(rejected,))
            if reply.get('rejected'):
                db.execute("UPDATE meta SET value=CAST(value AS INTEGER)+? WHERE key='rejected_total'",(len(reply['rejected']),))
            if reset:
                # A restored pre-unban snapshot may still hold a revoked ban.
                # Relevant tombstones must win over this response's sent ACKs.
                db.execute('UPDATE local_claims SET pending=1,retry_after=0,attempts=0 WHERE expires_at>?', (time.time(),))

    def exchange(self, cfg):
        sent=self.pending()
        payload={'cursor':self.cursor(),'updates':sent}
        if cfg['role']=='hub':
            reply=self.store.exchange(read_secret('sync_secret'),payload)
        else:
            context=ssl.create_default_context()
            ca=read_secret('sync_ca')
            if ca: context.load_verify_locations(cadata=ca)
            req=urllib.request.Request(cfg['hub_url'].rstrip('/')+'/v1/sync',data=json.dumps(payload).encode(),
                headers={'Authorization':'Bearer '+read_secret('sync_secret'),'Content-Type':'application/json'})
            # Default urllib redirects would forward bearer credentials. Reject
            # all redirects rather than ever forwarding a private peer token.
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self,*args,**kwargs): return None
            opener=urllib.request.build_opener(NoRedirect(),urllib.request.HTTPSHandler(context=context))
            with opener.open(req,timeout=10) as response:
                raw=response.read(256*1024+1)
                if len(raw)>256*1024: raise ValueError('oversized controller response')
                reply=json.loads(raw)
        self.receive(reply,sent)
        return reply


def main():
    store=Store(state_dir())
    while True:
        cfg=load_config()
        status={'last_attempt':time.time(),'error':''}
        errors=[]
        def step(function,*args):
            try: function(*args)
            except Exception as error:
                # Never log exception strings: HTTP errors may contain URLs/token
                # material from external systems. Status is deliberately bounded.
                errors.append(type(error).__name__)
        try:
            client=Client(store,LAPI(),read_secret('sync_peer'))
        except Exception as error:
            errors.append(type(error).__name__); client=None
        if client:
            # Independent steps: a failing LAPI call must not stop event
            # delivery or synchronization, and vice versa.
            step(client.reconcile,cfg['allowlist'])
            step(store.deliver_events, store.event_consumer_ready)
            step(client.exchange,cfg)
            step(client.reconcile,cfg['allowlist'])
        if not errors:
            with store.connect() as db:
                db.execute("INSERT OR REPLACE INTO meta VALUES('last_success',?)",(str(time.time()),))
        status['error']=','.join(dict.fromkeys(errors))
        with store.connect() as db:
            row=db.execute("SELECT value FROM meta WHERE key='last_success'").fetchone()
            status['last_success']=float(row[0]) if row else None
            status['pending']=db.execute('SELECT count(*) FROM local_claims WHERE pending=1').fetchone()[0] if db.execute("SELECT 1 FROM sqlite_master WHERE name='local_claims'").fetchone() else 0
            status['rejected_total']=int(db.execute("SELECT value FROM meta WHERE key='rejected_total'").fetchone()[0]) if db.execute("SELECT 1 FROM meta WHERE key='rejected_total'").fetchone() else 0
            status['quota_pending']=db.execute('SELECT count(*) FROM local_claims WHERE pending=1 AND attempts>0').fetchone()[0] if client else 0
            overload=db.execute("SELECT value FROM meta WHERE key='import_overload'").fetchone()
            status['import_overload']=bool(overload and overload[0]=='1')
            export=db.execute("SELECT value FROM meta WHERE key='local_export_overload'").fetchone()
            status['local_export_overload']=bool(export and export[0]=='1')
            status['event_pending']=db.execute('SELECT count(*) FROM events WHERE delivered=0').fetchone()[0]
        atomic_write(state_dir()/'sync-status.json',json.dumps(status)+'\n')
        time.sleep(5)


if __name__=='__main__': main()
