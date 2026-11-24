"""The acceptance scenario, written against an abstract node interface.

NodeOps (implemented over SSH by guestops.GuestOps, and by a labelled mock in qa/):
  name, module, peer_name(), boot_id(), units(), decisions(), nft(), hybrid_state(), sync_status(),
  ban_by_events(ip), unban(ip), reachable(ip), reboot(), prepare_attacker(), management_access(),
  management_ip();  hub only: backup_now(), restore_native(info);  member only: fresh_observer().
host: set_link(role, up).   clock: now(), sleep(seconds).
Every case records an explicit pass/fail. An exception inside a case is a failure, never a skip.
"""
from . import evidence as ev

A_MEMBER = '198.51.100.21'      # banned on the member, must reach the hub
B_HUB = '198.51.100.22'         # banned on the hub, must reach the member
C_OUTAGE_MEMBER = '198.51.100.23'
D_OUTAGE_HUB = '198.51.100.24'
E_UNBAN_DURING_OUTAGE = '198.51.100.25'
X_UNBAN_AFTER_BACKUP = '198.51.100.26'
Y_KEEP = '198.51.100.27'
F_POST_REBOOT = '198.51.100.28'
G_POST_REBOOT_HUB = '198.51.100.29'
H_ENGINE_RESTART = '198.51.100.30'   # not an attacker-namespace address: only decisions/nftables are observed
SSH_ATTACKER = '198.51.100.32'          # real sshd failures on the member (stock crowdsecurity/sshd rules)
HTTP_SCANNER = '198.51.100.33'         # real path scan against the hub's Traefik (access-log rules)
DISK_ROLLBACK_PROBE = '198.51.100.31'   # banned/probed only by the optional disk-rollback case
I_UPDATE_BAN = '198.51.100.32'      # banned before the update/rollback case, must survive both directions
J_UPDATE_POST = '198.51.100.33'     # banned after the roll-forward: the event path works again
ALLOWLISTED = '198.51.100.241'
ALLOWLIST_CIDR = '198.51.100.240/29'
ATTACKER_IPS = [A_MEMBER, B_HUB, C_OUTAGE_MEMBER, D_OUTAGE_HUB, E_UNBAN_DURING_OUTAGE, X_UNBAN_AFTER_BACKUP, Y_KEEP,
                F_POST_REBOOT, G_POST_REBOOT_HUB, DISK_ROLLBACK_PROBE, I_UPDATE_BAN, J_UPDATE_POST, ALLOWLISTED]
MIN_OUTAGE_SECONDS = 130


def wait_until(clock, predicate, timeout, interval=5):
    deadline = clock.now() + timeout
    while True:
        if predicate():
            return True
        if clock.now() >= deadline:
            return False
        clock.sleep(interval)


def _decision(node, ip):
    for d in node.decisions():
        if d['ip'] == ip:
            return d
    return None


def _require(condition, message):
    if not condition:
        raise ev.EvidenceError(message)


def _claim_rows(state, value):
    return [{'origin': r['origin'], 'deleted': r['deleted']} for r in state['claims'] if r['value'] == value]


class Scenario:
    def __init__(self, hub, member, host, clock, report):
        self.hub, self.member, self.host, self.clock, self.report = hub, member, host, clock, report
        self.ctx = {}

    # -- plumbing -----------------------------------------------------------
    def case(self, case_id, function):
        try:
            evidence = function()
            if not evidence:
                raise ev.EvidenceError('case produced no evidence')
        except Exception as error:     # any probe/transport error is a failed acceptance, never a skip
            self.report.record(case_id, 'fail', {'error': '%s: %s' % (type(error).__name__, error)})
            return False
        try:
            self.report.record(case_id, 'pass', evidence)
        except Exception as error:
            self.report.results.pop(case_id, None)
            self.report.record(case_id, 'fail', {'error': '%s: %s' % (type(error).__name__, error)})
            return False
        return True

    def ban_and_wait_local(self, node, ip, what):
        reach_before = node.reachable(ip)
        node.ban_by_events(ip)
        _require(wait_until(self.clock, lambda: _decision(node, ip) is not None, 120), '%s: no local decision for %s' % (what, ip))
        _require(wait_until(self.clock, lambda: ev.nft_has_ip(node.nft(), ip), 60), '%s: %s never reached nftables' % (what, ip))
        reach_after = node.reachable(ip)
        ev.assert_dropped(reach_before, reach_after, '%s %s' % (what, ip))
        return {'reachable_before': reach_before, 'reachable_after': reach_after, 'expires_at': _decision(node, ip)['expires_at']}

    def propagate(self, origin, peer, ip, what):
        _require(wait_until(self.clock, lambda: _decision(peer, ip) is not None, 120), '%s: %s never arrived on %s' % (what, ip, peer.name))
        _require(wait_until(self.clock, lambda: ev.nft_has_ip(peer.nft(), ip), 60), '%s: %s not in %s nftables' % (what, ip, peer.name))
        _require(not peer.reachable(ip), '%s: %s still reaches %s' % (what, ip, peer.name))
        return {'expires_at': _decision(peer, ip)['expires_at']}

    # -- cases --------------------------------------------------------------
    def sync_both_ways(self):
        def member_to_hub():
            local = self.ban_and_wait_local(self.member, A_MEMBER, 'member')
            remote = self.propagate(self.member, self.hub, A_MEMBER, 'member->hub')
            return {'ip': A_MEMBER, 'member': local, 'hub_enforced': True, 'hub_expires_at': remote['expires_at']}

        def hub_to_member():
            local = self.ban_and_wait_local(self.hub, B_HUB, 'hub')
            remote = self.propagate(self.hub, self.member, B_HUB, 'hub->member')
            return {'ip': B_HUB, 'hub': local, 'member_enforced': True, 'member_expires_at': remote['expires_at']}
        self.case('member_to_hub_sync_and_drop', member_to_hub)
        self.case('hub_to_member_sync_and_drop', hub_to_member)

    def no_echo(self):
        def check():
            self.clock.sleep(20)          # several 5 s sync cycles: an echo would have been published by now
            hub_state, member_state = self.hub.hybrid_state(), self.member.hybrid_state()
            ev.assert_no_echo(hub_claims=hub_state['claims'], member_local=member_state['local_claims'],
                              member_decisions=self.member.decisions(), hub_decisions=self.hub.decisions(),
                              member_ip=A_MEMBER, hub_ip=B_HUB, member_peer=self.member.peer_name(), hub_peer=self.hub.peer_name())
            return {'hub_claim_origins_for_member_ip': sorted({r['origin'] for r in hub_state['claims'] if r['value'] == A_MEMBER}),
                    'hub_claim_origins_for_hub_ip': sorted({r['origin'] for r in hub_state['claims'] if r['value'] == B_HUB})}
        self.case('no_echo', check)

    def allowlist(self):
        def check():
            out = {}
            for node in (self.hub, self.member):
                before = node.reachable(ALLOWLISTED)
                node.ban_by_events(ALLOWLISTED)
                self.clock.sleep(30)
                _require(_decision(node, ALLOWLISTED) is None, '%s banned the allowlisted address' % node.name)
                _require(not ev.nft_has_ip(node.nft(), ALLOWLISTED), '%s has the allowlisted address in nftables' % node.name)
                _require(before and node.reachable(ALLOWLISTED), '%s: allowlisted address lost reachability' % node.name)
                out[node.name] = {'banned': False, 'reachable': True}
            out['allowlist'] = ALLOWLIST_CIDR
            out['positive_control'] = 'non-allowlisted addresses were banned by the same event path in the sync cases'
            return out
        self.case('allowlist_negative_control', check)

    def stock_detections(self):
        """Detections that do not come from Guardian's event path: sshd failures and an HTTP path scan through Traefik."""
        def detect(node, ip, attack, prefixes, what):
            def check():
                before = node.reachable(ip)
                attack(ip)
                _require(wait_until(self.clock, lambda: _decision(node, ip) is not None, 150), '%s: no decision after the attack' % what)
                decision = _decision(node, ip)
                _require(any(decision['scenario'].startswith(p) for p in prefixes),
                         '%s: decision came from %r, expected one of %s' % (what, decision['scenario'], prefixes))
                _require(wait_until(self.clock, lambda: ev.nft_has_ip(node.nft(), ip), 60), '%s: %s never reached nftables' % (what, ip))
                ev.assert_dropped(before, node.reachable(ip), what)
                node.unban(ip)
                return {'ip': ip, 'node': node.name, 'scenario': decision['scenario'], 'origin': decision.get('origin', ''),
                        'reachable_before': before, 'reachable_after': False}
            return check
        self.case('ssh_bruteforce_detection', detect(self.member, SSH_ATTACKER, self.member.ssh_attack,
                                                     ('crowdsecurity/ssh-',), 'sshd failures'))
        self.case('http_scan_detection', detect(self.hub, HTTP_SCANNER, self.hub.http_scan,
                                                ('crowdsecurity/http-', 'ns8/ns8-http-'), 'HTTP path scan'))

    def engine_restart_replay(self):
        """Consumer ACK + bucket rebuild: 3 failures reach the hub's engine (bucket capacity 4, no ban yet), the engine
        restarts (its in-memory bucket is gone), and 4 more failures must still produce the ban because the acknowledged
        events were replayed. 4 events alone cannot overflow the bucket, so a ban proves the replay."""
        def check():
            hub, ip = self.hub, H_ENGINE_RESTART
            before, acked_before = hub.event_status()['replayed_total'], hub.event_status()['acked']
            hub.ban_by_events(ip, count=3)
            # The status file is refreshed every few seconds: 'nothing pending' alone can be a stale reading from before
            # the events arrived (hosted run 45343499773), so require the acknowledged counter to advance by 3.
            _require(wait_until(self.clock, lambda: hub.event_status()['acked'] >= acked_before + 3 and hub.event_status()['pending'] == 0
                                and hub.event_status()['unacked'] == 0, 120),
                     'events were not acknowledged as consumed by the engine')
            _require(_decision(hub, ip) is None and not ev.nft_has_ip(hub.nft(), ip), 'bucket overflowed early: test premise broken')
            hub.engine_restart()
            _require(wait_until(self.clock, lambda: self._units_ok(hub), 240, 10), 'hub units not active after the engine restart')
            _require(wait_until(self.clock, lambda: hub.event_status()['replayed_total'] >= before + 3 and hub.event_status()['unacked'] == 0
                                and hub.event_status()['pending'] == 0, 180), 'acknowledged events were not replayed after the engine restart')
            hub.ban_by_events(ip, count=4)
            _require(wait_until(self.clock, lambda: _decision(hub, ip) is not None, 120), 'no ban after replay: bucket state was not rebuilt')
            _require(wait_until(self.clock, lambda: ev.nft_has_ip(hub.nft(), ip), 60), 'ban never reached nftables')
            replayed = hub.event_status()['replayed_total'] - before
            hub.unban(ip)
            return {'ip': ip, 'events_before_restart': 3, 'events_after_restart': 4, 'bucket_capacity': 4, 'replayed_events': replayed,
                    'banned_after_restart': True, 'note': 'ban impossible from the 4 post-restart events alone'}
        self.case('engine_restart_event_replay', check)

    def outage_and_reconnect(self):
        ctx = self.ctx
        outage = {}

        def prepare_unban_candidate():
            self.ban_and_wait_local(self.member, E_UNBAN_DURING_OUTAGE, 'member')
            self.propagate(self.member, self.hub, E_UNBAN_DURING_OUTAGE, 'member->hub')
        prepared = self.case_guard(prepare_unban_candidate)

        def run_outage():
            self.host.set_link('hub', False)
            outage['down_at'] = self.clock.now()
            try:
                _require(wait_until(self.clock, lambda: bool(self.member.sync_status().get('stale')), 120),
                         'member never reported the hub as stale')
                outage['member_error'] = self.member.sync_status().get('error', '')
                local = self.ban_and_wait_local(self.member, C_OUTAGE_MEMBER, 'member (hub down)')
                hub_local = self.ban_and_wait_local(self.hub, D_OUTAGE_HUB, 'hub (isolated)')
                outage['member_ban_at'] = self.clock.now()
                self.member.unban(E_UNBAN_DURING_OUTAGE)
                _require(wait_until(self.clock, lambda: _decision(self.member, E_UNBAN_DURING_OUTAGE) is None, 30), 'member unban failed')
                # hub still enforces E: it cannot know yet
                _require(_decision(self.hub, E_UNBAN_DURING_OUTAGE) is not None, 'hub lost E without any link')
                _require(_decision(self.hub, C_OUTAGE_MEMBER) is None and _decision(self.member, D_OUTAGE_HUB) is None,
                         'ban crossed a disconnected link')
                # Measure from the member ban (the TTL origin), not from the link cut: detecting the stale hub
                # already consumes a minute or more (hosted run 45032689667 left only 37s).
                self.clock.sleep(max(0, MIN_OUTAGE_SECONDS - (self.clock.now() - outage['member_ban_at'])))
                outage['member_local'], outage['hub_local'] = local, hub_local
            finally:
                self.host.set_link('hub', True)
                outage['up_at'] = self.clock.now()
            return {'outage_seconds': round(outage['up_at'] - outage['down_at']), 'member_sync_error': outage['member_error'],
                    'member_ban_dropped_while_hub_down': True, 'hub_ban_dropped_while_isolated': True,
                    'link_cut': 'hub<->member traffic dropped by an owned nft table in both guests; host management stayed up'}
        ok = self.case('hub_unreachable_local_protection', run_outage)
        ctx['outage'] = outage

        def reconverge():
            _require(ok and prepared, 'prerequisite outage step failed')
            _require(wait_until(self.clock, lambda: _decision(self.hub, C_OUTAGE_MEMBER) is not None and _decision(self.member, D_OUTAGE_HUB) is not None, 180),
                     'bans did not converge after reconnect')
            _require(wait_until(self.clock, lambda: _decision(self.hub, E_UNBAN_DURING_OUTAGE) is None, 180), 'origin unban did not reach the hub')
            for node, ip in ((self.hub, C_OUTAGE_MEMBER), (self.member, D_OUTAGE_HUB)):
                _require(wait_until(self.clock, lambda: ev.nft_has_ip(node.nft(), ip), 60), '%s lacks %s in nftables' % (node.name, ip))
                _require(not node.reachable(ip), '%s still reachable on %s' % (ip, node.name))
            _require(wait_until(self.clock, lambda: self.hub.reachable(E_UNBAN_DURING_OUTAGE), 60), 'unbanned address is still dropped on the hub')
            _require(not ev.nft_has_ip(self.hub.nft(), E_UNBAN_DURING_OUTAGE), 'unbanned address remains in hub nftables')
            _require(self.member.reachable(E_UNBAN_DURING_OUTAGE), 'unbanned address is dropped on the member')
            return {'bans_converged': [C_OUTAGE_MEMBER, D_OUTAGE_HUB], 'unban_converged': E_UNBAN_DURING_OUTAGE,
                    'unban_origin': 'member', 'sync_recovered': True}
        self.case('reconnect_convergence_ban_unban', reconverge)

        def ttl():
            _require(ok, 'outage case failed')
            delay = outage['up_at'] - outage['member_ban_at']
            m_origin = _decision(self.member, C_OUTAGE_MEMBER)['expires_at']
            h_peer = _decision(self.hub, C_OUTAGE_MEMBER)['expires_at']
            ev.assert_absolute_ttl(m_origin, h_peer, delay)
            h_origin = _decision(self.hub, D_OUTAGE_HUB)['expires_at']
            m_peer = _decision(self.member, D_OUTAGE_HUB)['expires_at']
            ev.assert_absolute_ttl(h_origin, m_peer, outage['up_at'] - outage['member_ban_at'])
            return {'delay_before_import_seconds': round(delay),
                    'member_to_hub_expiry_delta_seconds': round(h_peer - m_origin, 1),
                    'hub_to_member_expiry_delta_seconds': round(m_peer - h_origin, 1)}
        self.case('absolute_ttl', ttl)

    def case_guard(self, function):
        try:
            function()
            return True
        except Exception:
            return False

    def reboot(self, node, other, case_id, plain_epoch_check=False):
        def check():
            expected = {A_MEMBER, B_HUB, C_OUTAGE_MEMBER, D_OUTAGE_HUB}
            before_ips = {d['ip'] for d in node.decisions()}
            _require(expected <= before_ips, 'pre-reboot ban set incomplete on %s' % node.name)
            boot_before = node.boot_id()
            state_before = node.hybrid_state() if plain_epoch_check else None
            node.reboot()
            _require(wait_until(self.clock, lambda: self._units_ok(node), 400, 10), '%s units not active after reboot' % node.name)
            node.prepare_attacker()
            ev.assert_boot_changed(boot_before, node.boot_id())
            ev.assert_units_active(node.units())
            after_ips = {d['ip'] for d in node.decisions()}
            _require(expected <= after_ips, '%s lost bans over reboot: %s' % (node.name, sorted(expected - after_ips)))
            _require(E_UNBAN_DURING_OUTAGE not in after_ips, 'unbanned address reappeared on %s after reboot' % node.name)
            nft = node.nft()
            for ip in expected:
                _require(ev.nft_has_ip(nft, ip), '%s: %s missing from nftables after reboot' % (node.name, ip))
                _require(not node.reachable(ip), '%s: %s reachable after reboot' % (node.name, ip))
            _require(wait_until(self.clock, lambda: not node.sync_status().get('stale'), 180), '%s sync did not recover after reboot' % node.name)
            new_ip = F_POST_REBOOT if node is self.member else G_POST_REBOOT_HUB
            node.ban_by_events(new_ip)
            _require(wait_until(self.clock, lambda: _decision(node, new_ip) is not None, 120), 'no new local decision after reboot')
            _require(wait_until(self.clock, lambda: _decision(other, new_ip) is not None, 180), 'post-reboot ban did not sync to %s' % other.name)
            out = {'boot_id_changed': True, 'bans_persisted': sorted(expected), 'units_active': True, 'post_reboot_ban_synced': new_ip}
            if plain_epoch_check:
                after = node.hybrid_state()
                ev.assert_origin_tombstone(  # E's tombstone must persist across the reboot
                    [r for r in after['claims'] if r['value'] == E_UNBAN_DURING_OUTAGE], E_UNBAN_DURING_OUTAGE, self.member.peer_name())
                _require(after['epoch'] == state_before['epoch'], 'a plain reboot changed the hub epoch')
                _require(any(r['value'] == A_MEMBER and r['origin'] == self.member.peer_name() and not r['deleted'] for r in after['claims']),
                         'hub claim database lost member claims over reboot')
                out.update(epoch_unchanged=True, claims_persisted=True)
            return out
        self.case(case_id, check)

    def _units_ok(self, node):
        try:
            ev.assert_units_active(node.units())
            return True
        except (ev.EvidenceError, OSError, RuntimeError):
            return False

    def backup_restore(self):
        ctx = self.ctx
        hub, member = self.hub, self.member

        def prepare():
            for ip in (X_UNBAN_AFTER_BACKUP, Y_KEEP):
                self.ban_and_wait_local(member, ip, 'member')
                self.propagate(member, hub, ip, 'member->hub')
            ctx['epoch_before'] = hub.hybrid_state()['epoch']
            ctx['backup'] = hub.backup_now()
            member.unban(X_UNBAN_AFTER_BACKUP)
            _require(wait_until(self.clock, lambda: _decision(hub, X_UNBAN_AFTER_BACKUP) is None, 120), 'unban did not reach the hub')
            state = hub.hybrid_state()
            ev.assert_origin_tombstone([r for r in state['claims'] if r['value'] == X_UNBAN_AFTER_BACKUP], X_UNBAN_AFTER_BACKUP, member.peer_name())
            _require(wait_until(self.clock, lambda: not any(c['pending'] for c in member.hybrid_state()['local_claims']), 60),
                     'unban was never acknowledged by the hub')
            ctx['acknowledged'] = True
        prepared = self.case_guard(prepare)

        def native():
            _require(prepared, 'backup preparation failed')
            result = hub.restore_native(ctx['backup'])
            ctx['restore'] = result
            _require(result['module_uuid_after'] == result['module_uuid_before'], 'restored instance has a different module UUID')
            _require(result.get('module_removed_before_restore') is True, 'hub module was not removed before the restore')
            _require(wait_until(self.clock, lambda: self._units_ok(hub), 300, 10), 'restored hub units not active')
            return dict(result, backup_snapshot=ctx['backup']['snapshot'],
                        note='NS8 cluster backup/restore-module (restic repository); not a VM disk snapshot')
        native_ok = self.case('native_ns8_backup_restore', native)

        def reconverge():
            _require(native_ok, 'native restore failed')
            after = hub.hybrid_state()
            ev.assert_epoch_changed(ctx['epoch_before'], after['epoch'])

            def tombstoned():
                rows = [r for r in hub.hybrid_state()['claims'] if r['value'] == X_UNBAN_AFTER_BACKUP]
                return bool(rows) and all(r['deleted'] for r in rows)
            _require(wait_until(self.clock, tombstoned, 240), 'origin tombstone never replaced the restored live claim')
            state = hub.hybrid_state()
            ev.assert_origin_tombstone([r for r in state['claims'] if r['value'] == X_UNBAN_AFTER_BACKUP], X_UNBAN_AFTER_BACKUP, member.peer_name())
            _require(wait_until(self.clock, lambda: _decision(hub, X_UNBAN_AFTER_BACKUP) is None, 120), 'unbanned address is banned again on the hub')
            # the restored bouncer polls: nftables follow the decision with a delay, so wait instead of sampling once
            _require(wait_until(self.clock, lambda: hub.reachable(X_UNBAN_AFTER_BACKUP), 90, 5), 'unbanned address dropped on the hub after restore')
            _require(_decision(member, X_UNBAN_AFTER_BACKUP) is None and member.reachable(X_UNBAN_AFTER_BACKUP), 'unbanned address back on the member')
            _require(wait_until(self.clock, lambda: _decision(hub, Y_KEEP) is not None, 120) and not hub.reachable(Y_KEEP), 'kept ban lost on the hub')
            return {'epoch_before': ctx['epoch_before'], 'epoch_after': after['epoch'], 'tombstone_origin': member.peer_name(),
                    'unbanned_address_enforced': False, 'kept_ban_enforced': True}
        self.case('restore_new_epoch_tombstone_reconverge', reconverge)

        def observer():
            _require(native_ok, 'native restore failed')
            member.fresh_observer()
            _require(wait_until(self.clock, lambda: self._units_ok(member), 300, 10), 'observer units not active')
            member.prepare_attacker()
            _require(wait_until(self.clock, lambda: _decision(member, Y_KEEP) is not None, 240), 'fresh observer never received the live ban')
            self.clock.sleep(30)
            _require(_decision(member, X_UNBAN_AFTER_BACKUP) is None, 'old, acknowledged-unbanned address resurrected on the fresh observer')
            _require(not ev.nft_has_ip(member.nft(), X_UNBAN_AFTER_BACKUP), 'resurrected in observer nftables')
            _require(member.reachable(X_UNBAN_AFTER_BACKUP), 'unbanned address dropped on observer')
            return {'observer_peer': member.peer_name(), 'live_ban_received': Y_KEEP, 'unbanned_address_received': False,
                    'ordering': 'observer enrolled after the hub finished origin-tombstone reconvergence; races before it are not covered'}
        self.case('fresh_observer_no_resurrection', observer)

    def management(self):
        def check():
            ip = self.hub.management_ip()
            out = {}
            for node in (self.hub, self.member):
                ev.assert_management_unaffected(ip, node.decisions(), node.nft(), self.ctx['mgmt_before'].get(node.name, {}), node.management_access())
                out[node.name] = 'not banned; SSH and TCP/443 from the management source unchanged'
            out['source'] = 'runner bridge gateway address (independent management/SSH source)'
            return out
        self.case('management_source_unaffected', check)

    def run(self):
        self.ctx['mgmt_before'] = {}
        try:
            self.ctx['mgmt_before'] = {n.name: n.management_access() for n in (self.hub, self.member)}
        except Exception:
            self.ctx['mgmt_before'] = {}
        self.sync_both_ways()
        self.no_echo()
        self.allowlist()
        self.stock_detections()
        self.engine_restart_replay()
        self.outage_and_reconnect()
        self.reboot(self.member, self.hub, 'member_guest_reboot')
        self.reboot(self.hub, self.member, 'hub_guest_reboot', plain_epoch_check=True)
        self.backup_restore()
        self.management()


def run_scenario(hub, member, host, clock, report):
    Scenario(hub, member, host, clock, report).run()


MODULE_REPOSITORY = 'ghcr.io/platypuschan/guardian'


def run_update_rollback(hub, previous_digest, target_digest, clock, report):
    """update-module to an earlier digest (rollback) and forward again; state must survive both directions."""
    sc = Scenario(hub, None, None, clock, report)

    def units_ok():
        try:
            ev.assert_units_active(hub.units())
            return True
        except ev.EvidenceError:
            return False

    def step(digest, label):
        hub.update_module('%s@%s' % (MODULE_REPOSITORY, digest))
        _require(wait_until(clock, units_ok, 400, 10), '%s: units not active after update-module' % label)
        _require(hub.image_digest() == digest, '%s: running digest %s is not the requested %s' % (label, hub.image_digest(), digest))
        _require(hub.module_uuid() == before['uuid'], '%s: module UUID changed' % label)
        _require(hub.hybrid_state()['epoch'] == before['epoch'], '%s: hub epoch changed by a plain update' % label)
        _require(wait_until(clock, lambda: _decision(hub, I_UPDATE_BAN) is not None, 120), '%s: ban lost across update-module' % label)
        _require(wait_until(clock, lambda: ev.nft_has_ip(hub.nft(), I_UPDATE_BAN), 90), '%s: ban missing in nftables after update-module' % label)
        _require(wait_until(clock, lambda: not hub.reachable(I_UPDATE_BAN), 60), '%s: banned address reachable after update-module' % label)
        _require(wait_until(clock, lambda: not hub.sync_status().get('stale'), 240), '%s: sync stale after update-module' % label)

    def check():
        nonlocal before
        before = {'uuid': hub.module_uuid(), 'epoch': hub.hybrid_state()['epoch']}
        hub.ban_by_events(I_UPDATE_BAN)
        _require(wait_until(clock, lambda: _decision(hub, I_UPDATE_BAN) is not None and ev.nft_has_ip(hub.nft(), I_UPDATE_BAN), 120), 'probe ban not enforced before the update')
        step(previous_digest, 'rollback')
        step(target_digest, 'roll-forward')
        _require(hub.previous_image_digest() == previous_digest, 'PREV_IMAGE_DIGEST does not record the rolled-back digest')
        hub.ban_by_events(J_UPDATE_POST)
        _require(wait_until(clock, lambda: _decision(hub, J_UPDATE_POST) is not None, 120), 'event ingest broken after roll-forward: no ban for new events')
        _require(wait_until(clock, lambda: ev.nft_has_ip(hub.nft(), J_UPDATE_POST), 60), 'new ban missing in nftables after roll-forward')
        for ip in (I_UPDATE_BAN, J_UPDATE_POST):
            hub.unban(ip)
        return {'rolled_back_to': previous_digest, 'rolled_forward_to': target_digest, 'module': hub.module if hasattr(hub, 'module') else '',
                'uuid_unchanged': True, 'epoch_unchanged': True, 'ban_survived_rollback': True, 'ban_survived_roll_forward': True,
                'new_ban_after_roll_forward': True, 'method': 'cluster update-module with the module image digest (not a backup restore)'}
    before = {}
    sc.case('module_update_rollback', check)
