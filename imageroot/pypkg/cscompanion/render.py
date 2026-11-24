"""Render CrowdSec, bouncer and container configuration from settings.

YAML files are written as JSON documents, which every YAML parser accepts,
so no template engine or YAML library is needed.
"""
import json
import os
from pathlib import Path
import shutil

from . import discovery
from .common import changed_write, read_secret, state_dir
from .hybrid import Store

# Deliberately no crowdsecurity/traefik or base-http-scenarios: the stock
# traefik-logs parser takes the last X-Forwarded-For element as the client, so a
# forwarded chain would ban the trusted proxy (tests/test-rules.sh covers this).
COLLECTIONS = "crowdsecurity/linux"
STATIC_RULES = Path(__file__).resolve().parents[2] / "crowdsec"
# Router names Traefik derives from a module ID: <module>-http / <module>-https.
ROUTER_SUFFIXES = ("-https@file", "-http@file")


def ports():
    values = os.environ.get("TCP_PORTS", os.environ.get("TCP_PORT", "")).split(",")
    if len(values) < 2 or not all(v.strip().isdigit() for v in values[:2]):
        raise RuntimeError("NS8 did not allocate the two TCP ports this module needs")
    return int(values[0]), int(values[1])


def yaml_doc(data):
    return json.dumps(data, indent=2, sort_keys=True) + "\n"


def gateway_port():
    values = os.environ.get('TCP_PORTS','').split(',')
    if len(values) < 3 or not values[2].strip().isdigit():
        raise RuntimeError('NS8 did not allocate the private gateway TCP port')
    return int(values[2])


CAPI_CREDENTIALS = 'online_api_credentials.yaml'


def community_client(cfg, state=None, registering=False):
    """Central API client section, only when the administrator opted in and this node is registered."""
    if not cfg.get('community_blocklist'):
        return None
    ready = registering or (Path(state if state is not None else state_dir()) / 'crowdsec_config' / CAPI_CREDENTIALS).is_file()
    if not ready:
        return None
    return {'credentials_path': '/etc/crowdsec/' + CAPI_CREDENTIALS,
            'sharing': bool(cfg.get('community_sharing')),
            'pull': {'community': True, 'blocklists': False}}


def config_local(cfg, state=None, registering=False):
    lapi, metrics = ports()
    data = {
        "prometheus": {"enabled": True, "level": "full", "listen_addr": "127.0.0.1", "listen_port": metrics},
        "db_config": {"use_wal": True, "flush": {"max_items": 20000, "max_age": "30d"}},
        # A fixed hub branch avoids cscli's online version lookup. The image's
        # entrypoint runs "cscli parsers install" at every start; without this
        # the container cannot start while version.crowdsec.net is unreachable.
        "cscli": {"hub_branch": "master"},
    }
    if cfg["role"] in ("hub", "member"):
        # Traefik is the only client that reaches this loopback listener from
        # outside and replaces any X-Forwarded-For sent by the remote client.
        # X-Forwarded-For is honoured only from loopback (Traefik); CrowdSec's
        # default would trust it from any IPv4 source.
        # log_level error: the access log would record every bouncer poll.
        data["api"] = {"server": {"listen_uri": "127.0.0.1:%d" % lapi, "use_forwarded_for_headers": True,
                                  "trusted_proxies": ["127.0.0.1/32", "::1/128"], "log_level": "error"}}
        if registering:        # cscli needs the client section once, to register; at run time offline-start.sh adds it
            data["api"]["server"]["online_client"] = community_client(cfg, state, True)
    return yaml_doc(data)


def acquisition(found, root="/"):
    docs = [{
        "source": "journalctl",
        "journalctl_filter": ["_SYSTEMD_UNIT=" + u for u in discovery.ssh_units(root)],
        "labels": {"type": "syslog", "ns8_source": "sshd"},
    }]
    for item in found.get("traefik", []):
        docs.append({
            'source':'journalctl',
            'journalctl_filter':['CONTAINER_NAME=traefik','_UID=%d' % item['uid']],
            'labels':{'type':'syslog','ns8_source':'traefik-generic','ns8_module':item['module']},
        })
        docs.append({
            "source": "journalctl",
            # Different fields are ANDed by journalctl: only this module's container.
            "journalctl_filter": ["CONTAINER_NAME=traefik", "_UID=%d" % item["uid"]],
            "labels": {"type": "syslog", "ns8_source": "traefik", "ns8_module": item["module"]},
        })
    for item in found.get("samba", []):
        docs.append({
            "source": "journalctl",
            "journalctl_filter": ["CONTAINER_NAME=samba-dc", "_UID=%d" % item["uid"]],
            "labels": {"type": "syslog", "ns8_source": "samba", "ns8_module": item["module"]},
        })
    docs.append({'source':'file','filenames':['/var/log/ns8-events/auth.jsonl'],
                 'labels':{'type':'ns8_auth_event','ns8_source':'events'}})
    return "---\n".join(yaml_doc(d) for d in docs)


def routers_parser(found):
    """Generated s02 parser: map Traefik router names to application kinds."""
    expr = "''"
    registered = {s['module'] for s in Store(state_dir()).list_sources()} if (state_dir()/'hybrid.db').exists() else set()
    for kind in ("organizr", "gitea"):
        names = sorted(item["module"] + s for item in found.get(kind, []) if item['module'] not in registered for s in ROUTER_SUFFIXES)
        if names:
            expr = "evt.Meta.ns8_router in %s ? '%s' : (%s)" % (json.dumps(names), kind, expr)
    return yaml_doc({
        "name": "ns8/router-apps",
        "description": "Map NS8 Traefik routers to application kinds (generated)",
        "filter": "evt.Meta.ns8_log == 'traefik'",
        "onsuccess": "next_stage",
        "statics": [{"meta": "ns8_app", "expression": expr}],
    })


def profiles(cfg):
    return yaml_doc({
        "name": "ns8_ip_ban",
        "filters": ["Alert.Remediation == true && Alert.GetScope() == 'Ip'"],
        "decisions": [{"type": "ban", "duration": cfg["ban_duration"]}],
        "on_success": "break",
    })


def bouncer(cfg, module):
    url = "http://127.0.0.1:%d/" % ports()[0]
    return yaml_doc({
        "mode": "nftables",
        "update_frequency": "10s",
        "log_mode": "stdout",
        "log_level": "info",
        "api_url": url,
        "api_key": read_secret("bouncer_key"),
        "insecure_skip_verify": False,
        "disable_ipv6": False,
        "deny_action": "DROP",
        "deny_log": False,
        "supported_decisions_types": ["ban"],
        "nftables": {
            "ipv4": {"enabled": True, "set-only": False, "table": "guardian",
                     "chain": "guardian-chain", "priority": -10},
            "ipv6": {"enabled": True, "set-only": False, "table": "guardian6",
                     "chain": "guardian6-chain", "priority": -10},
        },
        "nftables_hooks": ["input", "forward"],
    })


def crowdsec_env(cfg, module):
    env = {
        "DISABLE_ONLINE_API": "true",
        "COLLECTIONS": COLLECTIONS,
        "CUSTOM_HOSTNAME": module,
        "METRICS_PORT": str(ports()[1]),
        "NO_HUB_UPGRADE": "true",
    }
    env["BOUNCER_KEY_" + module.replace("-", "_") + "_firewall"] = read_secret("bouncer_key")
    return "".join("%s=%s\n" % kv for kv in sorted(env.items()))


GENERATED_RULES = {'parsers/s02-enrich/ns8-router-apps.yaml'}


def prune_retired_rules(conf):
    """Remove module-owned ns8-* rule files that this version no longer ships (changed_write only adds/updates)."""
    shipped = {str(p.relative_to(STATIC_RULES)) for p in STATIC_RULES.rglob('*.yaml')} | GENERATED_RULES
    removed = False
    for sub in ('parsers/s00-raw', 'parsers/s01-parse', 'parsers/s02-enrich', 'scenarios', 'postoverflows/s01-whitelist'):
        directory = Path(conf) / sub
        if not directory.is_dir():
            continue
        for path in sorted(directory.glob('ns8-*.yaml')):
            if path.is_file() and not path.is_symlink() and str(path.relative_to(conf)) not in shipped:
                path.unlink()
                removed = True
    return removed


def render_all(cfg, module, state, root="/"):
    """Write every generated file; return True if CrowdSec must reload."""
    state = Path(state)
    changed_write(state / "offline-start.sh", (STATIC_RULES / "offline-start.sh").read_text(), 0o644)
    conf = state / "crowdsec_config"
    found = discovery.discover(root)
    reload = False
    reload |= changed_write(conf / "acquis.yaml", acquisition(found, root), 0o644)
    reload |= changed_write(conf / "parsers/s02-enrich/ns8-router-apps.yaml", routers_parser(found), 0o644)
    reload |= prune_retired_rules(conf)
    for path in sorted(STATIC_RULES.rglob("*.yaml")):
        target = conf / path.relative_to(STATIC_RULES)
        reload |= changed_write(target, path.read_text(), 0o644)
    restart = changed_write(conf / "config.yaml.local", config_local(cfg), 0o644)
    client = community_client(cfg, state)
    fragment = conf / "community.yaml"
    if client:
        restart |= changed_write(fragment, yaml_doc(client), 0o600)
    elif fragment.exists():
        fragment.unlink()
        restart = True
    restart |= changed_write(conf/'local_api_credentials.yaml.local',yaml_doc({'url':'http://127.0.0.1:%d/'%ports()[0]}))
    restart |= changed_write(conf / "profiles.yaml", profiles(cfg), 0o644)
    restart |= changed_write(state / "crowdsec.env", crowdsec_env(cfg, module))
    bouncer_changed = changed_write(conf / "bouncer.yaml", bouncer(cfg, module))
    changed_write(state / "discovery.json", json.dumps(found, indent=2, sort_keys=True) + "\n", 0o644)
    return {"reload": reload, "restart": restart, "bouncer": bouncer_changed, "found": found}


def remove_tree(path):
    shutil.rmtree(path, ignore_errors=True)
