"""Shell command text executed in the guests. Every dynamic value is validated and shlex-quoted;
secrets travel on stdin, never in argv (which `ps` and journals would expose)."""
import ipaddress
import json
import re
import shlex
import uuid

MODULE_RE = re.compile(r'guardian[0-9]{1,4}')
ACTION_RE = re.compile(r'[a-z][a-z0-9-]{0,63}')
AGENT_RE = re.compile(r'module/[a-z][a-z0-9]{0,31}')
ENDPOINT_RE = re.compile(r'http://127\.0\.0\.1:[0-9]{2,5}/v1/events')
STAMP_RE = re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z')
TEST_NET = ipaddress.ip_network('198.51.100.0/24')
GUEST_ATTACK_IP = '198.51.100.1'


def valid_module(module):
    if not isinstance(module, str) or not MODULE_RE.fullmatch(module):
        raise ValueError('not a Guardian module id')
    return module


def _action(action):
    if not ACTION_RE.fullmatch(action or ''):
        raise ValueError('invalid action name')
    return action


def api_run(agent, action, data):
    """agent: 'cluster' or 'module/<id>'."""
    _action(action)
    if agent == 'cluster':
        target = action
    elif AGENT_RE.fullmatch(agent):
        target = '%s/%s' % (agent, action)
    else:
        raise ValueError('invalid agent')
    return 'api-cli run %s --data %s' % (target, shlex.quote(json.dumps(data, separators=(',', ':'))))


def api_run_stdin(action, data, agent='cluster'):
    _action(action)
    if agent == 'cluster':
        target = action
    elif AGENT_RE.fullmatch(agent):
        target = '%s/%s' % (agent, action)
    else:
        raise ValueError('invalid agent')
    return 'api-cli run %s --data -' % target, json.dumps(data, separators=(',', ':'))


def cscli(module, *args):
    valid_module(module)
    return 'runagent -m %s podman exec %s cscli %s' % (module, module, ' '.join(shlex.quote(a) for a in args))


def alerts_cmd(module):
    return cscli(module, 'alerts', 'list', '--limit', '0', '-o', 'json')


def nft_table_cmd():
    return 'nft list table ip guardian'


def boot_id_cmd():
    return 'cat /proc/sys/kernel/random/boot_id'


def unit_names(module):
    valid_module(module)
    return [module + '.service', module + '-bouncer.service', module + '-refresh.timer',
            module + '-gateway.service', module + '-sync.service']


def unit_states_cmd(module):
    return 'for u in %s; do printf "%%s %%s\\n" "$u" "$(systemctl is-active "$u")"; done' % ' '.join(unit_names(module))


def stop_module_units(module):
    return ['systemctl stop ' + unit for unit in reversed(unit_names(module))]


def send_event(endpoint, token, ip, event_id, occurred_at):
    if not ENDPOINT_RE.fullmatch(endpoint):
        raise ValueError('event endpoint must be the local loopback gateway')
    ipaddress.ip_address(ip)
    uuid.UUID(event_id)
    if not STAMP_RE.fullmatch(occurred_at):
        raise ValueError('bad timestamp')
    body = json.dumps({'schema_version': 1, 'id': event_id, 'occurred_at': occurred_at,
                       'event': 'authentication_failed', 'source_ip': ip}, separators=(',', ':'))
    cmd = "curl -sS -o /dev/null -w '%%{http_code}' --config - -H 'Content-Type: application/json' -d %s %s" % (shlex.quote(body), endpoint)
    return cmd, 'header = "Authorization: Bearer %s"\n' % token.replace('"', '')


def attacker_links(names):
    return ['gv%sh' % names.run_id, 'gv%sc' % names.run_id]


def attacker_ns(names):
    return 'glab-' + names.run_id


def attacker_setup(names, addresses):
    ns = attacker_ns(names)
    host, peer = attacker_links(names)
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if ip not in TEST_NET or str(ip) == GUEST_ATTACK_IP:
            raise ValueError('%s is not an allowed synthetic attacker address' % address)
    cmds = [
        'ip netns add %s' % ns,
        'ip link add %s type veth peer name %s' % (host, peer),
        'ip link set %s netns %s' % (peer, ns),
        'ip addr add %s/24 dev %s' % (GUEST_ATTACK_IP, host),
        'ip link set %s up' % host,
        'ip -n %s link set %s up' % (ns, peer),
        'ip -n %s link set lo up' % ns,
        'firewall-cmd --zone=public --add-interface=%s' % host,
    ]
    cmds += ['ip -n %s addr add %s/24 dev %s' % (ns, a, peer) for a in addresses]
    return cmds


def attacker_teardown(names):
    ns = attacker_ns(names)
    host = attacker_links(names)[0]
    return ['firewall-cmd --zone=public --remove-interface=%s' % host, 'ip netns del %s' % ns, 'ip link del %s' % host]


PROBE_PY = ('import socket,sys\n'
            's=socket.socket()\ns.settimeout(3)\ns.bind((sys.argv[1],0))\n'
            'try:\n s.connect((sys.argv[2],443))\n print("open")\n'
            'except socket.timeout:\n print("blocked")\n'
            'except ConnectionRefusedError:\n print("refused")\n')


def probe_reachable(names, source_ip):
    ipaddress.ip_address(source_ip)
    return 'ip netns exec %s timeout 10 python3 -c %s %s %s' % (
        attacker_ns(names), shlex.quote(PROBE_PY), source_ip, GUEST_ATTACK_IP)


def reachability(returncode, output):
    """True = TCP handshake completed, False = SYN silently dropped, None = the probe itself failed."""
    word = output.strip()
    if returncode == 0 and word == 'open':
        return True
    if returncode == 0 and word == 'blocked':
        return False
    return None


def restore_module_data(module_uuid, path, snapshot, node):
    uuid.UUID(module_uuid)
    if path != 'guardian/' + module_uuid:
        raise ValueError('unexpected backup path')
    if not re.fullmatch(r'[0-9a-f]{8,64}', snapshot or ''):
        raise ValueError('unexpected snapshot id')
    return {'path': path, 'snapshot': snapshot, 'node': int(node), 'replace': True}


STATE_SCRIPT = r'''
import json, sqlite3, sys
db = sqlite3.connect("file:%s/hybrid.db?mode=ro" % sys.argv[1], uri=True, timeout=15)
db.row_factory = sqlite3.Row
have = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
def rows(sql, table):
    return [dict(r) for r in db.execute(sql)] if table in have else []
meta = {r["key"]: r["value"] for r in db.execute("SELECT key,value FROM meta")} if "meta" in have else {}
print(json.dumps({
  "epoch": meta.get("epoch", ""), "hub_epoch": meta.get("hub_epoch", ""), "cursor": meta.get("cursor", ""),
  "sequence": meta.get("sequence", ""),
  "claims": rows("SELECT origin,id,value,expires_at,deleted,seq FROM claims", "claims"),
  "imports": rows("SELECT origin,id,value,expires_at,deleted,suppressed FROM imports", "imports"),
  "local_claims": rows("SELECT id,value,expires_at,deleted,pending FROM local_claims", "local_claims"),
}))
'''


def hybrid_state_script():
    return STATE_SCRIPT


def hybrid_state_cmd(module):
    valid_module(module)
    return 'python3 -I -c %s /var/lib/nethserver/%s/state' % (shlex.quote(STATE_SCRIPT), module)


def parse_hybrid_state(text):
    try:
        data = json.loads(text)
        for key in ('epoch', 'claims', 'imports', 'local_claims'):
            data[key]
        return data
    except (ValueError, KeyError, TypeError):
        raise ValueError('unparseable hybrid state probe output') from None
