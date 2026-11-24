"""NS8 action entry points: python3 -m cscompanion.actions <action>."""
import ipaddress
import json
import os
import secrets
import sys
import sqlite3
import ssl
import time
from typing import NoReturn

from . import lifecycle, render
from .hybrid import Store
from .common import (DURATION, HOST, MEMBER, ROLES, decode_token, encode_token, hub_url, load_config,
                     normalize_allowlist, read_secret, save_config, secret, state_dir, write_secret)


def fail(field, message) -> NoReturn:
    """Report a validation error the way NS8 shows it next to a form field."""
    import agent
    agent.set_status("validation-failed")
    json.dump([{"field": field, "parameter": field, "value": "", "error": message}], sys.stdout)
    sys.exit(2)


def read_input():
    data = sys.stdin.read().strip()
    return json.loads(data) if data else {}


def create_module(_request):
    lifecycle.prepare_dirs()
    save_config(load_config())


def ensure_local_peer():
    """The hub's own sync worker uses an ordinary peer identity."""
    if read_secret('sync_secret'):
        return
    peer = os.environ['MODULE_ID'] + '-local'
    store = Store(state_dir())
    try:
        token = store.add_peer(peer)
    except sqlite3.IntegrityError:
        # A crash after the database write but before the secret was stored:
        # issue a fresh credential for the existing local peer.
        token = store.rotate_peer(peer)
    write_secret('sync_peer', peer)
    write_secret('sync_secret', token)


def configure_module(request):
    cfg = load_config()
    role = request.get("role", cfg["role"])
    if role not in ROLES:
        fail("role", "invalid_role")
    if cfg["role"] and role != cfg["role"]:
        # A hub's database holds every member's credentials; switching would
        # silently disconnect them. A new instance must be installed instead.
        fail("role", "role_is_fixed")
    cfg["role"] = role
    duration = str(request.get("ban_duration", cfg["ban_duration"])).strip()
    if not DURATION.match(duration):
        fail("ban_duration", "invalid_duration")
    cfg["ban_duration"] = duration
    try:
        cfg["allowlist"] = normalize_allowlist(request.get("allowlist", cfg["allowlist"]))
    except ValueError:
        fail("allowlist", "invalid_address")
    cfg["samba_audit"] = bool(request.get("samba_audit", cfg["samba_audit"]))
    cfg["community_blocklist"] = bool(request.get("community_blocklist", cfg["community_blocklist"]))
    cfg["community_sharing"] = bool(request.get("community_sharing", cfg["community_sharing"])) and cfg["community_blocklist"]
    if request.get('insecure_skip_verify',False):
        fail('insecure_skip_verify','insecure_sync_not_supported')
    cfg['insecure_skip_verify']=False
    token = ""
    if role == "hub":
        host = str(request.get("hub_host", cfg["hub_host"])).strip().lower()
        if not HOST.match(host):
            fail("hub_host", "invalid_host")
        cfg["hub_host"] = host
        cfg["lets_encrypt"] = bool(request.get("lets_encrypt", cfg["lets_encrypt"]))
        cfg["hub_url"] = hub_url(cfg)
        secret("bouncer_key", 32)
        ensure_local_peer()
    else:
        token = str(request.get("token", "")).strip()
        if token:
            try:
                data = decode_token(token)
            except (ValueError, KeyError, TypeError) as error:
                fail("token", "legacy_token_requires_reenrollment" if token.startswith('csc1.') else "invalid_token")
            cfg["hub_url"] = data["url"]
            old_peer=read_secret('sync_peer')
            if old_peer and old_peer != data['peer']:
                fail('token','sync_identity_is_fixed')
            if data.get('ca'):
                try: ssl.create_default_context(cadata=data['ca'])
                except ssl.SSLError: fail('token','invalid_private_ca')
            if not read_secret('sync_secret'):
                write_secret('bouncer_key',secrets.token_urlsafe(32))
            write_secret('sync_peer',data['peer'])
            write_secret('sync_secret',data['secret'])
            write_secret('sync_ca',data.get('ca',''))
        elif not read_secret("sync_secret"):
            fail("token", "token_required")
        secret('bouncer_key',32)
    save_config(cfg)
    lifecycle.apply(cfg, restart=bool(token))
    if role == "hub":
        lifecycle.route(cfg)


def get_configuration(_request):
    cfg = load_config()
    out = {k: cfg[k] for k in ("role", "hub_host", "lets_encrypt", "hub_url", "ban_duration",
                               "allowlist", "samba_audit", "insecure_skip_verify", "community_blocklist", "community_sharing")}
    out["member_name"] = read_secret("sync_peer") if cfg["role"] == "member" else ""
    json.dump(out, sys.stdout)


def require_hub():
    if load_config()["role"] != "hub":
        fail("role", "hub_only")


def source_endpoint():
    return 'http://127.0.0.1:%d/v1/events' % render.gateway_port()


def add_event_source(request):
    store = Store(state_dir())
    try:
        token=store.add_source(request.get('name'),request.get('module'),active=False)
    except (ValueError,sqlite3.IntegrityError):
        fail('name','invalid_or_existing_source')
    # Lifecycle and output are fallible; neither belongs in a DB transaction.
    try:
        lifecycle.apply(load_config())
        json.dump({'name':request['name'],'module':request['module'],'token':token,'endpoint':source_endpoint()},sys.stdout)
        sys.stdout.flush()
        # No second fallible lifecycle call after credential delivery. The next
        # normal refresh suppresses fallback; until then both paths stay enabled.
        store.activate_source(request['name'], token)
    except BaseException as error:
        store.remove_source(request['name'])
        try:
            # Re-render/reload restores the fallback suppressed by registration.
            lifecycle.apply(load_config())
        except Exception as rollback_error:
            error.add_note('source removed; fallback recovery apply failed: ' + type(rollback_error).__name__)
        raise


def list_event_sources(_request):
    json.dump({'sources':[dict(s,endpoint=source_endpoint()) for s in Store(state_dir()).list_sources(include_pending=True)]},sys.stdout)


def remove_event_source(request):
    Store(state_dir()).remove_source(request.get('name',''))
    lifecycle.apply(load_config())


def add_member(request):
    require_hub()
    name = str(request.get('name','')).strip().lower()
    if not MEMBER.fullmatch(name) or name in (os.environ['MODULE_ID'],read_secret('sync_peer')):
        fail('name','invalid_member_name')
    ca=request.get('ca','')
    if ca:
        try: ssl.create_default_context(cadata=ca)
        except (ssl.SSLError,TypeError): fail('ca','invalid_private_ca')
    try:
        credential=Store(state_dir()).add_peer(name)
    except sqlite3.IntegrityError:
        fail('name','member_exists_or_revoked')
    token=encode_token({'url':load_config()['hub_url'],'peer':name,'secret':credential,**({'ca':ca} if ca else {})})
    json.dump({'name':name,'token':token,'hub_url':load_config()['hub_url']},sys.stdout)


def list_members(_request):
    require_hub()
    members=[dict(p,local=p['name']==read_secret('sync_peer'),last_heartbeat=p['last_seen'],last_push=p['last_seen']) for p in Store(state_dir()).list_peers()]
    json.dump({'members':members},sys.stdout)


def remove_member(request):
    require_hub()
    name=str(request.get('name','')).strip().lower()
    if not MEMBER.fullmatch(name) or name==read_secret('sync_peer'):
        fail('name','invalid_member_name')
    Store(state_dir()).remove_peer(name)


def list_decisions(_request):
    decisions = []
    for alert in lifecycle.cscli_json("decisions", "list", "--limit", "0"):
        for d in alert.get("decisions") or []:
            decisions.append({
                "id": d.get("id"),
                "ip": d.get("value", ""),
                "scope": d.get("scope", ""),
                "scenario": d.get("scenario", ""),
                "origin": d.get("origin", ""),
                "until": d.get("until", ""),
                "duration": d.get("duration", ""),
                "machine": alert.get("machine_id", ""),
                "country": (alert.get("source") or {}).get("cn", ""),
            })
    json.dump({"decisions": decisions}, sys.stdout)


def unban(request):
    addresses = request.get("addresses") or []
    for value in addresses:
        try:
            ipaddress.ip_address(str(value))
        except ValueError:
            fail("addresses", "invalid_address")
    for value in addresses:
        lifecycle.cscli("decisions", "delete", "--ip", str(value))
    if addresses:
        try:
            store = Store(state_dir())
            for value in addresses:
                store.note_unban(str(value))
        except (sqlite3.Error, OSError):
            pass    # best effort: only narrows replay after an engine restart


def get_status(_request):
    cfg = load_config()
    status = {"role": cfg["role"], "hub_url": cfg["hub_url"], "services": {}, "lapi": "", "sources": {}}
    if not cfg["role"]:
        json.dump(status, sys.stdout)
        return
    status["services"] = lifecycle.services_state()
    result = lifecycle.cscli("lapi", "status", check=False, timeout=30)
    status["lapi"] = "ok" if result.returncode == 0 else (result.stderr or result.stdout).strip()[-300:]
    try:
        found = json.loads((state_dir() / "discovery.json").read_text())
    except (FileNotFoundError, ValueError):
        found = {}
    status["sources"] = {kind: [i["module"] for i in items] for kind, items in found.items()}
    try:
        sync_status=json.loads((state_dir()/'sync-status.json').read_text())
    except (FileNotFoundError,ValueError):
        sync_status={'last_success':None,'pending':None,'event_pending':None,'error':'not_started'}
    sync_status['age_seconds']=max(0,time.time()-sync_status['last_success']) if sync_status.get('last_success') else None
    sync_status['stale']=sync_status['age_seconds'] is None or sync_status['age_seconds']>60
    status['sync']=sync_status
    status['event_sources']=Store(state_dir()).list_sources()
    try:
        endpoint = source_endpoint()
    except RuntimeError:
        endpoint = None
    status['event_ingress']={'endpoint':endpoint,'pending':sync_status.get('event_pending')}
    if status["lapi"] == "ok":
        alerts = lifecycle.cscli_json("decisions", "list", "--limit", "0")
        status["active_bans"] = sum(len(a.get("decisions") or []) for a in alerts)
        info = lifecycle.community_state()
        status["community"] = {"enabled": bool(cfg["community_blocklist"]), "sharing": bool(cfg["community_sharing"]),
                               "error": info.get("error", ""),
                               "entries": lifecycle.community_entries() if cfg["community_blocklist"] else 0}
        if cfg['role']=='hub':
            status['members']=sum(not p['revoked'] and p['name']!=read_secret('sync_peer') for p in Store(state_dir()).list_peers())
    json.dump(status, sys.stdout)


def destroy_module(_request):
    cfg = load_config()
    lifecycle.restore_samba_audit()
    if cfg["role"] == "hub":
        try:
            lifecycle.route(cfg, delete=True)
        except Exception as error:  # the module is being removed anyway
            print("Route removal failed: %s" % error, file=sys.stderr)
    lifecycle.remove_units()


def ensure_gateway_port():
    """Instances created by 0.1.x own two TCP ports; this version needs three.

    NS8's update-module only records the new demand. The module must claim the
    extra port itself, otherwise the gateway cannot start after the upgrade.
    A new contiguous range replaces the old one, so every port is re-rendered.
    """
    if len([p for p in os.environ.get('TCP_PORTS', '').split(',') if p.strip()]) >= 3:
        return
    import agent
    first, last = agent.allocate_ports(3, 'tcp')
    env = {'TCP_PORT': str(first), 'TCP_PORTS_RANGE': '%d-%d' % (first, last),
           'TCP_PORTS': ','.join(str(p) for p in range(first, last + 1))}
    agent.mset_env(env)
    os.environ.update(env)


def update_module(_request):
    cfg = load_config()
    if cfg['role']=='member' and not read_secret('sync_secret'):
        # Checked first: nothing (ports, units) may change for a member that cannot be migrated.
        raise RuntimeError('Legacy remote-LAPI member: explicitly enroll with a new csc2 token before upgrade')
    ensure_gateway_port()
    if cfg['role']=='hub':
        # A 0.1.x hub has no sync identity yet; its members must re-enroll (csc2).
        ensure_local_peer()
    if cfg["role"]:
        lifecycle.apply(cfg, restart=True)
    if cfg["role"] == "hub":
        # The public route must follow the new gateway port and the /v1/sync-only path.
        lifecycle.route(cfg)


def restore_module(request):
    lifecycle.prepare_dirs()
    module=lifecycle.module_id()
    lifecycle.systemctl('stop',module+'-sync.service',module+'-gateway.service',module+'-bouncer.service',module+'.service',check=False)
    lifecycle.restore_database()
    cfg = load_config()
    if cfg["role"]:
        lifecycle.apply(cfg, restart=True)
        if cfg["role"] == "hub":
            lifecycle.route(cfg)


def module_dump_state(_request):
    lifecycle.dump_database()


ACTIONS = {
    'add-event-source':add_event_source,
    'list-event-sources':list_event_sources,
    'remove-event-source':remove_event_source,
    "create-module": create_module,
    "configure-module": configure_module,
    "get-configuration": get_configuration,
    "add-member": add_member,
    "list-members": list_members,
    "remove-member": remove_member,
    "list-decisions": list_decisions,
    "unban": unban,
    "get-companion-status": get_status,
    "destroy-module": destroy_module,
    "update-module": update_module,
    "restore-module": restore_module,
    "module-dump-state": module_dump_state,
}


def main():
    action = sys.argv[1]
    request = read_input() if action not in ("update-module", "module-dump-state") else {}
    ACTIONS[action](request)


if __name__ == "__main__":
    main()
