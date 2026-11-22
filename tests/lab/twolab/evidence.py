"""Assertions over probe output. Each raises EvidenceError; none ever treats missing data as success."""
import datetime as dt
import ipaddress
import json
import re
import uuid

PREFIX = 'ns8-sync/'
TTL_TOLERANCE = 20.0
MIN_DISCRIMINATING_DELAY = 90.0


class EvidenceError(AssertionError):
    pass


def _seconds(value):
    units = {'ns': 1e-9, 'us': 1e-6, 'µs': 1e-6, 'ms': .001, 's': 1, 'm': 60, 'h': 3600}
    parts = re.findall(r'(\d+(?:\.\d+)?)(ns|us|µs|ms|s|m|h)', value)
    if not parts:
        raise EvidenceError('unparseable duration')
    return sum(float(n) * units[u] for n, u in parts) * (-1 if value.startswith('-') else 1)


def parse_decisions(text, now):
    text = (text or '').strip()
    if text in ('', 'null'):
        return []
    try:
        alerts = json.loads(text)
        out = []
        for alert in alerts or []:
            for d in alert.get('decisions') or []:
                if d.get('simulated') or d.get('type') != 'ban' or str(d.get('scope', '')).lower() != 'ip':
                    continue
                until = d.get('until')
                expires = dt.datetime.fromisoformat(until.replace('Z', '+00:00')).timestamp() if until else now + _seconds(d['duration'])
                if expires <= now:
                    continue    # soft-deleted/expired decision: crowdsec keeps it in alert output but it no longer bans
                out.append({'id': str(d['id']), 'ip': str(ipaddress.ip_address(d['value'])), 'scenario': d.get('scenario', ''),
                            'origin': d.get('origin', ''), 'expires_at': expires})
        return out
    except (ValueError, KeyError, TypeError, AttributeError) as error:
        raise EvidenceError('unsupported decision output: %s' % type(error).__name__) from None


def nft_has_ip(text, ip):
    return re.search(r'(?<![0-9.])%s(?![0-9.])' % re.escape(ip), text or '') is not None


def has_ban(decisions, ip):
    return any(d['ip'] == ip for d in decisions)


def assert_absolute_ttl(origin_expires, peer_expires, outage_seconds):
    if outage_seconds < MIN_DISCRIMINATING_DELAY:
        raise EvidenceError('delay %ss is not discriminating: a TTL restarted at import would look identical' % outage_seconds)
    if abs(peer_expires - origin_expires) > TTL_TOLERANCE:
        raise EvidenceError('peer expiry differs from the origin by %.0fs: not an absolute TTL' % (peer_expires - origin_expires))


def assert_no_echo(hub_claims, member_local, member_decisions, hub_decisions, member_ip, hub_ip, member_peer, hub_peer):
    live = lambda rows: [r for r in rows if not r.get('deleted')]
    if any(r['value'] == hub_ip and r['origin'] == member_peer for r in hub_claims):
        raise EvidenceError('echo: hub-originated ban %s was re-published to the hub by the member' % hub_ip)
    if any(r['value'] == member_ip and r['origin'] == hub_peer for r in hub_claims):
        raise EvidenceError('echo: member-originated ban %s was re-published by the hub as its own claim' % member_ip)
    if any(r['value'] == hub_ip for r in live(member_local)):
        raise EvidenceError('echo: imported ban %s is exported as a member local claim' % hub_ip)
    imported_on_member = [d for d in member_decisions if d['ip'] == hub_ip]
    imported_on_hub = [d for d in hub_decisions if d['ip'] == member_ip]
    if len(imported_on_member) != 1 or not imported_on_member[0]['scenario'].startswith(PREFIX):
        raise EvidenceError('import missing or duplicated on member for %s' % hub_ip)
    if len(imported_on_hub) != 1 or not imported_on_hub[0]['scenario'].startswith(PREFIX):
        raise EvidenceError('import missing or duplicated on hub for %s' % member_ip)


def assert_dropped(before, after, what):
    if not before:
        raise EvidenceError('%s: control was not reachable before the ban, drop proves nothing' % what)
    if after:
        raise EvidenceError('%s: still reachable after the ban (no packet drop)' % what)


def assert_reachable(reachable, what):
    if not reachable:
        raise EvidenceError('%s: expected reachable' % what)


def assert_boot_changed(before, after):
    try:
        uuid.UUID(before), uuid.UUID(after)
    except (ValueError, AttributeError, TypeError):
        raise EvidenceError('boot id is not a UUID') from None
    if before == after:
        raise EvidenceError('boot id unchanged: the guest did not reboot')


def assert_units_active(states):
    needed = ('.service', '-bouncer.service', '-refresh.timer', '-gateway.service', '-sync.service')
    if len(states) != 5:
        raise EvidenceError('expected five module units, got %d' % len(states))
    bad = {k: v for k, v in states.items() if v != 'active'}
    if bad or not all(any(k.endswith(n) for k in states) for n in needed):
        raise EvidenceError('units not active: %s' % sorted(bad))


def assert_origin_tombstone(claims, ip, origin):
    rows = [r for r in claims if r['value'] == ip and r['origin'] == origin]
    if not rows:
        raise EvidenceError('no claim for %s from origin %s' % (ip, origin))
    if any(not r['deleted'] for r in rows):
        raise EvidenceError('live claim still present for %s from origin %s' % (ip, origin))


def assert_epoch_changed(before, after):
    if not before or not after:
        raise EvidenceError('epoch unreadable')
    if before == after:
        raise EvidenceError('hub epoch unchanged after restore')


def assert_independent_clusters(a, b):
    for side in (a, b):
        if side['nodes'] != 1 or side['wg_peers'] != 0:
            raise EvidenceError('cluster is not a single isolated node')
    for key in ('machine_id', 'wg_public_key', 'vpn_network'):
        if not a[key] or a[key] == b[key]:
            raise EvidenceError('clusters share %s' % key)


def assert_digest_readback(expected, observed):
    if set(observed) != {'hub', 'member'}:
        raise EvidenceError('digest read back for %s only' % sorted(observed))
    for node, digest in observed.items():
        if digest != expected:
            raise EvidenceError('%s runs %s, expected %s' % (node, digest, expected))


MANAGEMENT_OK = {'ssh': True, 'https_tcp': True}


def assert_management_unaffected(source_ip, decisions, nft_text, access_before, access_after):
    if has_ban(decisions, source_ip) or nft_has_ip(nft_text, source_ip):
        raise EvidenceError('management source %s was banned' % source_ip)
    if access_before != MANAGEMENT_OK or access_after != MANAGEMENT_OK:
        raise EvidenceError('management access changed (%s -> %s)' % (access_before, access_after))


def assert_runtime_digests(expected, observed):
    if set(observed) != {'hub', 'member'}:
        raise EvidenceError('runtime images read back for %s only' % sorted(observed))
    for node, digests in observed.items():
        if set(digests) != set(expected):
            raise EvidenceError('%s runs images %s, expected %s' % (node, sorted(digests), sorted(expected)))


MAX_CLOCK_SKEW = 3.0


def assert_clock_skew(skews):
    for node, skew in skews.items():
        if abs(skew) > MAX_CLOCK_SKEW:
            raise EvidenceError('%s clock differs from the runner by %.1fs: absolute-TTL comparison would be unsound' % (node, skew))
