"""NodeOps over SSH for one real NS8 guest (see scenario.py for the interface)."""
import ast
import datetime as dt
import json
import re
import shlex
import socket
import time
import uuid

from . import guestcmds as g
from .scenario import ALLOWLIST_CIDR
from .ssh import RemoteError


def parse_api(output):
    text = output.strip()
    if not text:
        return {}
    try:
        return json.loads(text)
    except ValueError:
        return ast.literal_eval(text)


class GuestOps:
    def __init__(self, guest, names, role, module, peer, clock=time.time, sleep=time.sleep, image_ref=None,
                 enroll=None, attacker_ips=None, node_id=1, backup=None):
        self.guest, self.names, self.role, self.name = guest, names, role, role
        self.module, self.peer, self.clock, self.sleep = module, peer, clock, sleep
        self.image_ref, self.enroll, self.node_id, self.backup = image_ref, enroll, node_id, backup
        if attacker_ips is None:
            from .scenario import ATTACKER_IPS
            attacker_ips = ATTACKER_IPS
        self.attacker_ips = attacker_ips
        self._source = None
        self.tcp_probe = self._tcp_probe

    # -- helpers --------------------------------------------------------------
    def api(self, agent, action, data, secret=False, timeout=300):
        if secret:
            cmd, stdin = g.api_run_stdin(action, data, agent=agent)
            return parse_api(self.guest.run(cmd, stdin=stdin, secret_stdin=True, timeout=timeout)[1])
        return parse_api(self.guest.run(g.api_run(agent, action, data), timeout=timeout)[1])

    def peer_name(self):
        return self.module + '-local' if self.role == 'hub' else self.peer

    def mod_agent(self):
        return 'module/' + g.valid_module(self.module)

    def state_env(self, key):
        module = g.valid_module(self.module)
        script = 'import agent,json; print(json.dumps(agent.read_envfile(%r)[%r]))' % (
            '/var/lib/nethserver/%s/state/environment' % module, key)
        return parse_api(self.guest.run('runagent -m cluster python3 -c ' + shlex.quote(script))[1])

    def module_uuid(self):
        """Compare Core's environment parser with the authoritative cluster map."""
        value = self.state_env('MODULE_UUID')
        mapped = self.guest.run('redis-cli --raw HGET cluster/module_uuid ' + g.valid_module(self.module))[1].strip()
        try:
            valid = isinstance(value, str) and str(uuid.UUID(value)) == value
        except ValueError:
            valid = False
        if not valid or mapped != value:
            raise RemoteError('module UUID missing, malformed, or inconsistent with cluster/module_uuid')
        return value

    # -- observation ----------------------------------------------------------
    def boot_id(self):
        return self.guest.run(g.boot_id_cmd())[1].strip()

    def units(self):
        out = self.guest.run(g.unit_states_cmd(self.module), check=False)[1]
        return dict(line.split() for line in out.splitlines() if len(line.split()) == 2)

    def decisions(self):
        from .evidence import parse_decisions
        out = self.guest.run('date +%%s.%%N; %s' % g.alerts_cmd(self.module))[1]
        first, _, rest = out.partition('\n')
        return parse_decisions(rest, float(first))

    def nft(self):
        return self.guest.run(g.nft_table_cmd())[1]

    def hybrid_state(self):
        return g.parse_hybrid_state(self.guest.run(g.hybrid_state_cmd(self.module))[1])

    def sync_status(self):
        status = self.api(self.mod_agent(), 'get-companion-status', {})
        return status.get('sync') or {'stale': True, 'error': 'no sync status'}

    def event_status(self):
        sync = self.api(self.mod_agent(), 'get-companion-status', {}).get('sync') or {}
        try:
            return {'pending': int(sync['event_pending']), 'unacked': int(sync['event_unacked']),
                    'replayed_total': int(sync['event_replayed_total'])}
        except (KeyError, TypeError, ValueError):
            raise RemoteError('%s: companion status carries no event acknowledgement counters' % self.role) from None

    def engine_restart(self):
        """Restart only the Engine unit: its in-memory scenario buckets are lost, the module state stays."""
        self.guest.run('systemctl restart %s.service' % g.valid_module(self.module), timeout=300)

    def reachable(self, ip):
        rc, out = self.guest.run(g.probe_reachable(self.names, ip), check=False)
        verdict = g.reachability(rc, out)
        if verdict is None:
            raise RemoteError('%s: reachability probe for %s failed (rc=%s): %s' % (self.role, ip, rc, out.strip()[-200:]))
        return verdict

    # -- actions --------------------------------------------------------------
    def _ensure_source(self):
        if self._source and self._source[0] == self.module:
            return self._source
        agent = self.mod_agent()
        self.guest.run(g.api_run(agent, 'remove-event-source', {'name': 'lab-app'}), check=False)
        reply = self.api(agent, 'add-event-source', {'name': 'lab-app', 'module': 'lab-app1'}, secret=True)
        self.guest.sanitizer.register(reply['token'])
        self._source = (self.module, reply['token'], reply['endpoint'])
        return self._source

    def ban_by_events(self, ip, count=6):
        _, token, endpoint = self._ensure_source()
        for _ in range(count):
            stamp = dt.datetime.fromtimestamp(self.clock(), dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
            cmd, stdin = g.send_event(endpoint, token, ip, str(uuid.uuid4()), stamp)
            code = self.guest.run(cmd, stdin=stdin, secret_stdin=True)[1].strip()
            if code != '202':
                raise RemoteError('%s: event for %s was not accepted (HTTP %s)' % (self.role, ip, code))

    def unban(self, ip):
        self.guest.run(g.api_run(self.mod_agent(), 'unban', {'addresses': [ip]}))

    def prepare_attacker(self):
        for cmd in g.attacker_teardown(self.names):
            self.guest.run(cmd, check=False)
        for cmd in g.attacker_setup(self.names, self.attacker_ips):
            self.guest.run(cmd)

    def teardown_attacker(self):
        for cmd in g.attacker_teardown(self.names):
            self.guest.run(cmd, check=False)

    def reboot(self):
        before = self.boot_id()
        self.guest.run('systemctl reboot', check=False, timeout=60)
        self.sleep(20)
        for _ in range(60):
            try:
                if self.boot_id() != before:
                    break
            except RemoteError as error:
                if not error.transport:
                    raise
            self.sleep(10)
        else:
            raise RemoteError('%s: guest did not come back with a new boot id' % self.role)
        self.guest.run('systemctl is-system-running --wait', check=False, timeout=300)

    # -- management source ----------------------------------------------------
    def management_ip(self):
        return self.guest.ip.rsplit('.', 1)[0] + '.1'

    @staticmethod
    def _tcp_probe(host, port):
        try:
            with socket.create_connection((host, port), timeout=5):
                return True
        except OSError:
            return False

    def management_access(self):
        return {'ssh': self.guest.run('true', check=False)[0] == 0, 'https_tcp': bool(self.tcp_probe(self.guest.ip, 443))}

    # -- hub: native NS8 backup/restore ----------------------------------------
    def backup_now(self):
        b = self.backup
        module_uuid = self.module_uuid()
        backup_id = b['backup_id']
        if type(backup_id) is not int or backup_id < 1:
            raise RemoteError('invalid native backup schedule ID')
        prefix = 'runagent -m %s ' % g.valid_module(self.module)
        self.guest.run(prefix + 'module-backup %d' % backup_id, timeout=900)
        restic = prefix + 'restic-wrapper --backup %d ' % backup_id
        snaps = parse_api(self.guest.run(restic + 'snapshots --json', timeout=300)[1])
        if not isinstance(snaps, list) or not snaps:
            raise RemoteError('hub: NS8 backup produced no snapshot')

        def snapshot_time(s):
            if not isinstance(s, dict) or not re.fullmatch(r'[0-9a-f]{64}', s.get('id', '')):
                raise RemoteError('invalid Restic snapshot ID')
            try:
                stamp = dt.datetime.fromisoformat(s['time'].replace('Z', '+00:00'))
                if stamp.tzinfo is None:
                    raise ValueError('missing timezone')
                return stamp
            except (KeyError, ValueError, TypeError, AttributeError) as error:
                raise RemoteError('invalid Restic snapshot time') from error

        latest = max(snaps, key=snapshot_time)
        listing = self.guest.run(restic + 'ls ' + latest['id'], timeout=300)[1]
        paths = set(listing.splitlines())
        required = {'/state/environment', '/state/config.json', '/state/backup/hybrid.db', '/state/backup/crowdsec.db'}
        if not required <= paths or not any(p.startswith('/state/secrets/') for p in paths):
            raise RemoteError('native snapshot missing config, secrets or consistent database dumps')
        return {'snapshot': latest['id'], 'repository': b['repository'], 'path': 'guardian/' + module_uuid,
                'backup_id': backup_id, 'module_uuid': module_uuid, 'snapshot_time': latest['time']}

    def installed_guardians(self):
        listing = self.api('cluster', 'list-installed-modules', None)
        if not isinstance(listing, dict) or not all(isinstance(entries, list) for entries in listing.values()):
            raise RemoteError('invalid list-installed-modules output')
        result = []
        for entries in listing.values():
            for entry in entries:
                if not isinstance(entry, dict):
                    raise RemoteError('invalid installed module entry')
                # Core splits a digest-pinned ref at ':' (source '...guardian@sha256', module 'guardian@sha256'),
                # so identify Guardian by its source repository, never by the module name.
                source = str(entry.get('source', '')).split('@')[0]
                if source == 'ghcr.io/platypuschan/guardian' and entry.get('node') == str(self.node_id):
                    result.append(g.valid_module(entry['id']))
        return result

    def restore_native(self, info):
        before, uuid_before = self.module, info['module_uuid']
        data = g.restore_module_data(uuid_before, info['path'], info['snapshot'], self.node_id)
        data.update(repository=info['repository'], replace=False)
        if self.module_uuid() != uuid_before:
            raise RemoteError('backup UUID does not match current hub')
        # max-per-node=1: old instance removal precedes cluster restore/create.
        self.api('cluster', 'remove-module', {'module_id': before, 'preserve_data': False}, timeout=600)
        if self.installed_guardians():
            raise RemoteError('old Guardian still installed before restore')
        reply = self.api('cluster', 'restore-module', data, timeout=900)
        self.module = g.valid_module(reply['module_id'])
        self._source = None
        if self.module == before or reply.get('module_uuid') != uuid_before:
            raise RemoteError('cluster restore did not return a new module ID with original UUID')
        uuid_after = self.module_uuid()
        if uuid_after != uuid_before or self.installed_guardians() != [self.module]:
            raise RemoteError('restored module identity/readback mismatch')
        return {'restore_method': 'ns8-restore-module', 'restore_exit_code': 0, 'module_before': before, 'module_after': self.module,
                'module_uuid_before': uuid_before, 'module_uuid_after': uuid_after,
                'module_removed_before_restore': True}

    # -- member: fresh observer -------------------------------------------------
    def fresh_observer(self):
        name = 'observer1'
        token = self.enroll(name)
        self.guest.sanitizer.register(token)
        self.api('cluster', 'remove-module', {'module_id': self.module, 'preserve_data': False}, timeout=600)
        reply = parse_api(self.guest.run('add-module %s 1' % self.image_ref, timeout=900)[1])
        self.module, self.peer, self._source = g.valid_module(reply['module_id']), name, None
        self.api(self.mod_agent(), 'configure-module', {'role': 'member', 'token': token, 'ban_duration': '30m', 'allowlist': [ALLOWLIST_CIDR]}, secret=True)
