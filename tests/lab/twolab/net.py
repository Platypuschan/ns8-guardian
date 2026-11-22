"""Owned private bridge/NAT for the two guests. Every command has an exact inverse; no flushes, no policy edits."""


def _rules(names, subnet):
    c = ['-m', 'comment', '--comment', names.rule_comment]
    return [
        ['-t', 'nat', 'POSTROUTING', '-s', subnet, '!', '-d', subnet, '-j', 'MASQUERADE'] + c,
        ['FORWARD', '-i', names.bridge, '-j', 'ACCEPT'] + c,
        ['FORWARD', '-o', names.bridge, '-m', 'conntrack', '--ctstate', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'] + c,
    ]


def _with_table(rule, action):
    if rule[0] == '-t':
        return ['sudo', 'iptables', '-t', rule[1], action] + rule[2:]
    return ['sudo', 'iptables', action] + rule


def net_create_commands(names, subnet, owner):
    gateway = subnet.rsplit('.', 1)[0] + '.1'
    cmds = [
        ['sudo', 'ip', 'link', 'add', 'name', names.bridge, 'type', 'bridge'],
        ['sudo', 'ip', 'addr', 'add', gateway + '/24', 'dev', names.bridge],
        ['sudo', 'ip', 'link', 'set', names.bridge, 'up'],
    ]
    for tap in (names.tap_hub, names.tap_member):
        cmds += [['sudo', 'ip', 'tuntap', 'add', 'dev', tap, 'mode', 'tap', 'user', owner],
                 ['sudo', 'ip', 'link', 'set', tap, 'master', names.bridge],
                 ['sudo', 'ip', 'link', 'set', tap, 'up']]
    # Hosted runners already provide forwarding. Refuse unsupported hosts rather
    # than leaving a global kernel-policy change behind on cleanup/crash.
    cmds.append(['sudo', 'sh', '-ec', 'test "$(sysctl -n net.ipv4.ip_forward)" = 1'])
    for rule in _rules(names, subnet):
        # -I so Docker's default FORWARD DROP on hosted runners does not eat guest traffic
        cmds.append(_with_table(rule, '-I') if rule[0] == '-t' else ['sudo', 'iptables', '-I', 'FORWARD', '1'] + rule[1:])
    return cmds


def net_delete_commands(names, subnet):
    cmds = [_with_table(rule, '-D') for rule in reversed(_rules(names, subnet))]
    for tap in (names.tap_member, names.tap_hub):
        cmds.append(['sudo', 'ip', 'link', 'del', tap])
    cmds.append(['sudo', 'ip', 'link', 'del', names.bridge])
    return cmds


def link_state_command(names, role, up):
    tap = names.tap_hub if role == 'hub' else names.tap_member
    return ['sudo', 'ip', 'link', 'set', tap, 'up' if up else 'down']
