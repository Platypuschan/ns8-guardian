"""Run-unique resource names and an ownership ledger: cleanup touches only what this run created."""
from dataclasses import dataclass
import ipaddress
import json
import os
import re
import secrets
import shlex
from pathlib import Path


class NotOwnedError(RuntimeError):
    pass


def new_run_id():
    return secrets.token_hex(4)


class Names:
    def __init__(self, run_id, workdir):
        if not re.fullmatch(r'[0-9a-f]{8}', run_id):
            raise ValueError('run id must be 8 lowercase hex digits')
        self.run_id = run_id
        self.workdir = str(workdir)
        self.bridge = 'gl%sb' % run_id
        self.tap_hub = 'gl%sh' % run_id
        self.tap_member = 'gl%sm' % run_id
        self.s3_container = 'glab-%s-s3' % run_id
        self.rule_comment = 'glab-' + run_id

    def qemu_name(self, role):
        return 'gl-%s-%s' % (self.run_id, role)

    def owns(self, name):
        return self.run_id in name


@dataclass(frozen=True)
class Step:
    kind: str
    name: str
    argv: tuple


def kvm_rule_path(run_id):
    if not re.fullmatch(r'[0-9a-f]{8}', run_id):
        raise ValueError('run id must be 8 lowercase hex digits')
    return '/etc/udev/rules.d/99-glab-kvm-%s.rules' % run_id


def _destroy_argv(kind, name, workdir):
    if kind == 'iptables':
        return tuple(json.loads(name))
    if kind == 'link':
        return ('sudo', 'ip', 'link', 'del', name)
    if kind == 'container':
        return ('podman', 'rm', '-f', name)
    if kind == 'qemu':
        # Pseudo-command handled by the CLI runner: verifies /proc/<pid>/cmdline names this run before killing.
        return ('@kill-qemu', '%s/%s.pid' % (workdir, name.rsplit('-', 1)[1]), name)
    if kind == 'udev':
        rule = kvm_rule_path(name.rsplit('-', 1)[1])
        return ('sudo', 'sh', '-ec', 'rm -f %s; udevadm control --reload-rules; udevadm trigger --name-match=kvm; udevadm settle' % rule)
    if kind == 'dir':
        return ('rm', '-rf', '--one-file-system', name)
    raise ValueError('unknown resource kind ' + kind)


class Ledger:
    KINDS = ('link', 'container', 'qemu', 'dir', 'udev', 'iptables')

    def __init__(self, names):
        self.names = names
        self.entries = []

    def register(self, kind, name):
        if kind not in self.KINDS:
            raise ValueError('unknown resource kind')
        owned = {
            'link': (self.names.bridge, self.names.tap_hub, self.names.tap_member),
            'container': (self.names.s3_container,),
            'qemu': (self.names.qemu_name('hub'), self.names.qemu_name('member')),
            'dir': (self.names.workdir,),
            'udev': ('kvm-udev-' + self.names.run_id,),
        }
        if not isinstance(name, str):
            raise ValueError('resource name must be a string')
        if kind == 'iptables':
            from .net import net_delete_commands
            rule = json.loads(name)
            if not isinstance(rule, list) or not all(isinstance(t, str) for t in rule):
                raise ValueError('rule must be an argv list')
            subnet = '192.168.160.0/24'
            if '-s' in rule:
                try:
                    subnet = rule[rule.index('-s') + 1]
                    network = ipaddress.IPv4Network(subnet)
                    if (network.prefixlen != 24 or
                            not network.subnet_of(ipaddress.IPv4Network('192.168.0.0/16'))):
                        raise ValueError('invalid lab subnet')
                except (IndexError, ValueError) as error:
                    raise ValueError('invalid lab rule subnet') from error
            if rule not in [c for c in net_delete_commands(self.names, subnet) if 'iptables' in c]:
                raise NotOwnedError('not an exact owned lab rule')
        elif name not in owned[kind]:
            raise NotOwnedError('%s %r does not belong to run %s' % (kind, name, self.names.run_id))
        entry = (kind, name)
        if entry not in self.entries:
            self.entries.append(entry)

    def cleanup_plan(self):
        entries = list(reversed(self.entries))
        entries.sort(key=lambda e: e[0] == 'dir')
        return [Step(k, n, _destroy_argv(k, n, self.names.workdir)) for k, n in entries]

    def cleanup(self, runner):
        failures = []
        for step in self.cleanup_plan():
            if step.kind == 'dir':
                continue
            try:
                result = runner(list(step.argv))
                code = result[0] if isinstance(result, tuple) else result
            except Exception as error:   # keep going: every owned resource gets its attempt
                failures.append((step.kind, step.name, type(error).__name__))
                continue
            if code not in (0, None) and step.kind not in ('iptables', 'link'):
                failures.append((step.kind, step.name, 'exit %s' % code))
        failures += self.verify_links(runner)
        failures += self.verify_rules(runner)
        failures += self.verify_qemu(runner)
        if not failures:
            for step in self.cleanup_plan():
                if step.kind != 'dir':
                    continue
                try:
                    result = runner(list(step.argv))
                    code = result[0] if isinstance(result, tuple) else result
                    if code not in (0, None):
                        failures.append((step.kind, step.name, 'exit %s' % code))
                except Exception as error:
                    failures.append((step.kind, step.name, type(error).__name__))
        return failures

    def verify_links(self, runner):
        owned = {n for k, n in self.entries if k == 'link'}
        if not owned:
            return []
        try:
            code, output = runner(['ip', '-o', 'link', 'show'])
            if code != 0:
                return [('link', self.names.run_id, 'cannot verify absence')]
            present = set(re.findall(r'^\d+:\s+([^:@\s]+)', output, re.M))
            return [('link', name, 'still present') for name in sorted(owned & present)]
        except Exception as error:
            return [('link', self.names.run_id, 'cannot verify absence: ' + type(error).__name__)]

    def verify_qemu(self, runner):
        owned = {n for k, n in self.entries if k == 'qemu'}
        if not owned:
            return []
        try:
            code, output = runner(['pgrep', '-af', '--', 'qemu-system'])
            if code not in (0, 1):
                return [('qemu', self.names.run_id, 'cannot verify absence: exit %s' % code)]
            for line in output.splitlines():
                tokens = shlex.split(line)
                if any(t == '-name' and i + 1 < len(tokens) and tokens[i + 1] in owned
                       for i, t in enumerate(tokens)):
                    return [('qemu', self.names.run_id, 'process still running')]
        except Exception as error:
            return [('qemu', self.names.run_id, 'cannot verify absence: ' + type(error).__name__)]
        return []

    def verify_rules(self, runner):
        if not any(k == 'iptables' for k, _ in self.entries):
            return []
        try:
            code, output = runner(['sudo', 'iptables-save'])
            if code != 0:
                return [('iptables', self.names.rule_comment, 'cannot verify absence: exit %s' % code)]
            for line in output.splitlines():
                tokens = shlex.split(line)
                if any(t == '--comment' and i + 1 < len(tokens) and tokens[i + 1] == self.names.rule_comment
                       for i, t in enumerate(tokens)):
                    return [('iptables', self.names.rule_comment, 'rule still present')]
        except Exception as error:
            return [('iptables', self.names.rule_comment, 'cannot verify absence: ' + type(error).__name__)]
        return []

    def save(self):
        import tempfile
        path = Path(self.names.workdir, 'ledger.json')
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, pending = tempfile.mkstemp(prefix='.ledger-', dir=path.parent)
        try:
            with os.fdopen(fd, 'w') as handle:
                json.dump(self.entries, handle)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(pending, path)
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            Path(pending).unlink(missing_ok=True)

    @classmethod
    def load(cls, names):
        ledger = cls(names)
        entries = json.loads(Path(names.workdir, 'ledger.json').read_text())
        if not isinstance(entries, list):
            raise ValueError('ledger must be a list')
        for entry in entries:
            if (not isinstance(entry, list) or len(entry) != 2 or
                    not all(isinstance(token, str) for token in entry)):
                raise ValueError('invalid ledger entry')
            ledger.register(*entry)
        return ledger


def pick_subnet(routes_text, run_id):
    taken = []
    for token in re.findall(r'\d+\.\d+\.\d+\.\d+(?:/\d+)?', routes_text):
        try:
            taken.append(ipaddress.ip_network(token if '/' in token else token + '/32', strict=False))
        except ValueError:
            pass
    start = int(run_id[:2], 16) % 80
    for offset in range(80):
        third = 160 + (start + offset) % 80
        candidate = ipaddress.ip_network('192.168.%d.0/24' % third)
        if not any(candidate.overlaps(t) for t in taken if t.prefixlen > 0):
            return str(candidate)
    raise RuntimeError('no free private /24 for the lab bridge')
