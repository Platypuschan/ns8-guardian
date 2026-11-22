"""Orchestration: preflight -> images -> owned bridge -> two guests -> two clusters -> private CA -> hub/member ->
scenario -> sanitized public report -> owned cleanup. Cleanup and the report are in a finally block."""
import base64
import concurrent.futures
import getpass
import hashlib
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

from . import evidence as ev
from . import guestcmds as g
from .ca import generate_private_ca
from .capacity import CapacityError, check_capacity
from .cases import REQUIRED_CASES, Report
from .config import ConfigError, parse_inputs
from .guestops import GuestOps, parse_api
from .images import ChecksumError, IMAGES, parse_checksums, verify_file
from .net import link_state_command, net_create_commands, net_delete_commands
from .resources import Ledger, Names, kvm_rule_path, new_run_id, pick_subnet
from .sanitize import Sanitizer
from .scenario import ALLOWLIST_CIDR, run_scenario
from .source import SourceError, expected_runtime_digests, source_evidence
from .ssh import Guest, RemoteError, subprocess_runner
from .vm import cloud_init_files, kill_owned_qemu, qemu_argv, qemu_running, seed_command, snapshot_commands

PUBLIC_FILES = ('result.json', 'summary.md', 'source-evidence.json', 'transcript.json', 'diagnostics-hub.log',
                'diagnostics-member.log', 'console-hub.log', 'console-member.log')
HUB_HOST = 'guardian-hub.lab.test'
CORE_INSTALLER_REF = 'e27e2abbeee37e16e92c23027dbe0d3403aa385c'
CORE_IMAGE = 'ghcr.io/nethserver/core:3.25.1'
VPN = {'hub': '10.5.4.0/24', 'member': '10.5.5.0/24'}
DEADLINE_SECONDS = 80 * 60


def parse_cluster_nodes(reply):
    """Core 3.25.1 list-nodes returns {nodes: [...]}, never a node-keyed map."""
    if not isinstance(reply, dict) or not isinstance(reply.get('nodes'), list) or not reply['nodes']:
        raise ValueError('invalid list-nodes output')
    nodes = reply['nodes']
    if any(not isinstance(n, dict) or type(n.get('node_id')) is not int or n['node_id'] < 1 for n in nodes):
        raise ValueError('invalid list-nodes node ID')
    if len({n['node_id'] for n in nodes}) != len(nodes):
        raise ValueError('duplicate list-nodes node ID')
    return nodes


class Abort(RuntimeError):
    """A stage failed; its case is already recorded and later stages must not run."""


def real_hostinfo():
    import getpass as gp
    kvm = '/dev/kvm'
    return {'meminfo_text': Path('/proc/meminfo').read_text(), 'disk_free_bytes': None, 'cpus': os.cpu_count() or 1,
            'kvm': {'exists': os.path.exists(kvm), 'readable': os.access(kvm, os.R_OK), 'writable': os.access(kvm, os.W_OK)},
            'user': gp.getuser()}


def real_fetch_image(spec, dest):
    def fetch(url, target):
        done = subprocess.run(['curl', '-fsSL', '--proto', '=https', '--tlsv1.2', '--retry', '3', '--retry-delay', '5', '-o', target, url],
                              capture_output=True, text=True)
        if done.returncode != 0:
            raise ChecksumError('download failed: %s' % done.stderr.strip()[-200:])
    listing = Path(str(dest) + '.sums')
    fetch(spec['checksum_url'], str(listing))
    name = spec['url'].rsplit('/', 1)[1]
    expected = parse_checksums(listing.read_text()).get(name)
    fetch(spec['url'], str(dest))
    return expected


class Lab:
    def __init__(self, env, runner=subprocess_runner, hostinfo=None, fetch_image=real_fetch_image, workbase=None, out_dir='lab-out',
                 run_id=None, repo_root='.', sleep=time.sleep, clock=time.time):
        self.env, self.runner, self.fetch_image = env, runner, fetch_image
        self.hostinfo = hostinfo
        self.sleep, self.clock = sleep, clock
        self.run_id = run_id or new_run_id()
        base = workbase or env.get('RUNNER_TEMP') or '/tmp'
        self.names = Names(self.run_id, str(Path(base) / ('gl-' + self.run_id)))
        self.ledger = Ledger(self.names)
        self.out = Path(out_dir) / 'public'
        self.repo_root = repo_root
        self.sanitizer = Sanitizer()
        self.transcript = []
        self.guests, self.ops = {}, {}
        self.net_rules_added = False
        self.subnet = None
        self.secrets = {}
        self.report = None
        self.deadline = clock() + DEADLINE_SECONDS

    # -- plumbing ---------------------------------------------------------------
    def local(self, argv, check=True, input=None, timeout=600):
        rc, out = self.runner(list(argv), input=input, timeout=timeout)
        if check and rc != 0:
            raise Abort('%s failed (%d): %s' % (argv[0], rc, self.sanitizer.clean(out)[-300:]))
        return out

    def own(self, kind, name):
        """Register and persist BEFORE the resource is created: a killed runner can then be cleaned from the ledger."""
        self.ledger.register(kind, name)
        self.ledger.save()

    def stage(self, case_id, function):
        try:
            evidence = function()
        except Exception as error:
            self.report.record(case_id, 'fail', {'error': '%s: %s' % (type(error).__name__, error)})
            raise Abort(case_id) from error
        if case_id:
            try:
                self.report.record(case_id, 'pass', evidence)
            except Exception as error:
                self.report.record(case_id, 'fail', {'error': '%s: %s' % (type(error).__name__, error)})
                raise Abort(case_id) from error

    # -- stages -----------------------------------------------------------------
    def stage_source(self):
        head = self.local(['git', '-C', self.repo_root, 'rev-parse', 'HEAD']).strip()
        dirty = self.local(['git', '-C', self.repo_root, 'status', '--porcelain'])
        tree = self.local(['git', '-C', self.repo_root, 'rev-parse', 'HEAD:tests/lab']).strip()
        wf = Path(self.repo_root, '.github/workflows/two-node-lab.yml')
        wf_sha = hashlib.sha256(wf.read_bytes()).hexdigest() if wf.exists() else ''
        registry = json.loads(self.local(['skopeo', 'inspect', 'docker://' + self.cfg.module_ref]))
        evidence = source_evidence(self.cfg, self.env, head, dirty, registry, wf_sha, tree)
        self.source = evidence
        self.report.source = evidence
        self.expected_engine = expected_runtime_digests(registry['Labels'])

    def stage_preflight(self):
        def check():
            info = self.hostinfo or real_hostinfo()
            if info.get('disk_free_bytes') is None:
                Path(self.names.workdir).parent.mkdir(parents=True, exist_ok=True)
                info = dict(info, disk_free_bytes=shutil.disk_usage(Path(self.names.workdir).parent).free)
            kvm = info['kvm']
            if kvm['exists'] and not (kvm['readable'] and kvm['writable']):
                # A one-shot setfacl is reset when udev re-applies its rules on a KVM change event (hosted run
                # 45027781330: first QEMU started, second got EACCES). A run-owned udev rule persists until cleanup.
                if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', info['user']):
                    raise Abort('unexpected runner user name')
                self.own('udev', 'kvm-udev-' + self.run_id)
                rule = 'KERNEL=="kvm", OWNER="%s", GROUP="kvm", MODE="0660"' % info['user']
                self.local(['sudo', 'sh', '-ec', "umask 022; printf '%%s\\n' '%s' > %s; udevadm control --reload-rules; "
                            'udevadm trigger --name-match=kvm; udevadm settle' % (rule, kvm_rule_path(self.run_id))])
                self.local(['sh', '-c', 'test -r /dev/kvm && test -w /dev/kvm'])
                kvm = {'exists': True, 'readable': True, 'writable': True}
            report = check_capacity(info['meminfo_text'], info['disk_free_bytes'], info['cpus'], kvm, self.cfg)
            self.user = info['user']
            return report
        self.stage('preflight_capacity_kvm', check)

    def stage_images(self):
        def fetch():
            out = {}
            Path(self.names.workdir).mkdir(parents=True, mode=0o700, exist_ok=True)
            self.own('dir', self.names.workdir)
            for distro in sorted({self.cfg.hub_distro, self.cfg.member_distro}):
                spec = IMAGES[distro]
                dest = Path(self.names.workdir, distro + '.base.qcow2')
                expected = self.fetch_image(spec, dest)
                digest = verify_file(dest, expected, spec['algo'])
                out[distro] = {'url': spec['url'], 'algo': spec['algo'], 'checksum': digest, 'checksum_source': spec['checksum_url']}
            return out
        self.stage('cloud_image_checksums', fetch)

    def stage_prepare_guests(self):
        w = Path(self.names.workdir)
        self.keyfile, self.known_hosts = str(w / 'id_ed25519'), str(w / 'known_hosts')
        self.local(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'glab-' + self.run_id, '-f', self.keyfile])
        pub = Path(self.keyfile + '.pub').read_text().strip()
        routes = self.local(['ip', '-4', 'route'])
        self.subnet = pick_subnet(routes, self.run_id)
        prefix = self.subnet.rsplit('.', 1)[0]
        self.addr = {'gw': prefix + '.1', 'hub': prefix + '.11', 'member': prefix + '.12'}
        self.mac = {'hub': '52:54:00:%s:%s:01' % (self.run_id[:2], self.run_id[2:4]), 'member': '52:54:00:%s:%s:02' % (self.run_id[:2], self.run_id[2:4])}
        self.distro = {'hub': self.cfg.hub_distro, 'member': self.cfg.member_distro}
        for role in ('hub', 'member'):
            files = cloud_init_files(role=role, pubkey=pub, ip=self.addr[role], gateway=self.addr['gw'], mac=self.mac[role],
                                     run_id=self.run_id, hosts={self.addr['hub']: HUB_HOST})
            for name, text in files.items():
                (w / ('%s.%s' % (role, name))).write_text(text)
            self.local(seed_command(self.names.workdir, role))
            disk = str(w / (role + '.qcow2'))
            self.local(['cp', '--reflink=auto', str(w / (self.distro[role] + '.base.qcow2')), disk])
            self.local(['qemu-img', 'resize', disk, '%dG' % self.cfg.disk_gib])

    def stage_network(self):
        cmds = net_create_commands(self.names, self.subnet, self.user)
        for link in (self.names.bridge, self.names.tap_hub, self.names.tap_member):
            self.own('link', link)
        for cmd in cmds:
            if 'iptables' in cmd:
                inverse = list(cmd)
                pos = inverse.index('-I')
                inverse[pos] = '-D'
                if inverse[pos + 2] == '1':
                    inverse.pop(pos + 2)
                self.own('iptables', json.dumps(inverse))
                self.net_rules_added = True
            self.local(cmd)

    def stage_boot(self):
        for role, tap in (('hub', self.names.tap_hub), ('member', self.names.tap_member)):
            self.own('qemu', self.names.qemu_name(role))
            self.local(qemu_argv(self.names, role, self.cfg.vm_mem_mib, self.cfg.vm_cpus, self.mac[role], tap))
            guest = Guest(role, self.addr[role], self.keyfile, self.known_hosts, self.runner, self.sanitizer, self.transcript)
            self.guests[role] = guest
            self.ops[role] = GuestOps(guest, names=self.names, role=role, module='', peer='member1' if role == 'member' else '',
                                      clock=self.clock, sleep=self.sleep, image_ref=self.cfg.module_ref)
        for role, guest in self.guests.items():
            self.wait_ssh(guest)
            guest.run('cloud-init status --wait --long', timeout=600)
            guest.run('systemctl is-system-running --wait', check=False, timeout=300)
            guest.run('getent hosts registry-1.docker.io', timeout=60)

    def wait_ssh(self, guest, attempts=90):
        for _ in range(attempts):
            try:
                guest.run('true', timeout=30)
                return
            except RemoteError as error:
                if not error.transport:
                    raise
            self.sleep(4)
        raise Abort('%s guest never accepted SSH' % guest.role)

    def install_cluster(self, role):
        guest = self.guests[role]
        password = self.secrets['admin_' + role]
        guest.run('set -eu; umask 022; IFS= read -r pw; install -m 600 /dev/null /root/install.log; cd /root; if [ -d /etc/apt/apt.conf.d ]; then echo \'Acquire::Retries "5";\' > /etc/apt/apt.conf.d/80-lab-retries; fi; '
                  'curl -fsSL --retry 3 -o install.sh https://raw.githubusercontent.com/NethServer/ns8-core/%s/core/install.sh; '
                  'sha256sum install.sh; ADMIN_PASSWORD="$pw" bash install.sh %s '
                  'ghcr.io/nethserver/traefik:4.2.6 ghcr.io/nethserver/ldapproxy:1.4.0 '
                  'ghcr.io/nethserver/loki:1.5.3 ghcr.io/nethserver/metrics:1.7.1 '
                  '>/root/install.log 2>&1' % (CORE_INSTALLER_REF, CORE_IMAGE),
                  stdin=password + '\n', secret_stdin=True, timeout=1800)
        guest.run('set -eu; umask 022; IFS= read -r pw; install -m 600 /dev/null /root/create-cluster-private.log; create-cluster %s:55820 %s "$pw" '
                  '>/root/create-cluster-private.log 2>&1' % (self.addr[role], VPN[role]),
                  stdin=password + '\n', secret_stdin=True, timeout=900)

    def stage_clusters(self):
        import secrets as sec
        for role in ('hub', 'member'):
            self.secrets['admin_' + role] = 'Gl1-' + sec.token_urlsafe(16)   # meets typical complexity rules
            self.sanitizer.register(self.secrets['admin_' + role])

        def both():
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                for future in [pool.submit(self.install_cluster, r) for r in ('hub', 'member')]:
                    future.result()
            ident, skew = {}, {}
            for role, guest in self.guests.items():
                guest_now = float(guest.run('date +%s.%N')[1])
                skew[role] = guest_now - self.clock()
                nodes = parse_cluster_nodes(parse_api(guest.run(g.api_run('cluster', 'list-nodes', {}))[1]))
                ident[role] = {
                    'machine_id': guest.run('cat /etc/machine-id')[1].strip(),
                    'wg_public_key': guest.run('wg show wg0 public-key', check=False)[1].strip(),
                    'nodes': len(nodes), 'vpn_network': VPN[role],
                    'wg_peers': len([x for x in guest.run('wg show wg0 peers', check=False)[1].split() if x]),
                    'os': guest.run('. /etc/os-release; echo "$PRETTY_NAME"')[1].strip(),
                    'kernel': guest.run('uname -r')[1].strip(),
                    'core_images': guest.run("podman images --digests --format '{{.Repository}}:{{.Tag}} {{.Digest}}' | grep -i ns8-core || true")[1].strip().splitlines()[:6],
                    'mem_mib': int(guest.run("awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo")[1]),
                    'vcpus': int(guest.run('nproc')[1]),
                }
            ev.assert_independent_clusters(ident['hub'], ident['member'])
            ev.assert_clock_skew(skew)
            return {'hub': ident['hub'], 'member': ident['member'], 'clock_skew_seconds': {k: round(v, 2) for k, v in skew.items()},
                    'topology': 'two separate create-cluster installs; no join-node, no shared WireGuard peers'}
        self.stage('independent_clusters', both)

    def traefik_agent(self, guest):
        listing = parse_api(guest.run(g.api_run('cluster', 'list-installed-modules', None))[1])
        if not isinstance(listing, dict):
            raise ev.EvidenceError('invalid list-installed-modules output')
        entries = listing.get('ghcr.io/nethserver/traefik', [])
        if not isinstance(entries, list):
            raise ev.EvidenceError('invalid Traefik module listing')
        matches = [x for x in entries if isinstance(x, dict) and x.get('module') == 'traefik' and x.get('node') == '1']
        if len(matches) != 1:
            raise ev.EvidenceError('expected exactly one Traefik on node 1')
        module = matches[0].get('id', '')
        if not re.fullmatch(r'traefik[1-9][0-9]*', module):
            raise ev.EvidenceError('invalid Traefik module ID')
        return 'module/' + module

    def install_hub_certificate(self):
        """Documented selfsign fullchain import; always restore strict upload policy."""
        import shlex
        import ssl
        guest = self.guests['hub']
        agent = self.traefik_agent(guest)
        module = agent.removeprefix('module/')
        leaf = Path(self.ca['server']).read_text()
        chain = leaf + Path(self.ca['ca']).read_text()
        key = base64.b64encode(Path(self.ca['server_key']).read_bytes()).decode()
        self.sanitizer.register(key)
        data = {'certFile': base64.b64encode(chain.encode()).decode(), 'keyFile': key}
        cmd, stdin = g.api_run_stdin('upload-certificate', data, agent=agent)
        def policy(value):
            script = 'import agent; agent.set_env("UPLOAD_CERTIFICATE_VERIFY_TYPE", %r)' % value
            guest.run('runagent -m %s python3 -c %s' % (module, shlex.quote(script)))
        try:
            policy('selfsign')
            guest.run(cmd, stdin=stdin, secret_stdin=True, timeout=300)
        finally:
            policy('chain')
        guest.run(g.api_run(agent, 'list-certificates', {}))
        expected = hashlib.sha256(ssl.PEM_cert_to_DER_cert(leaf)).hexdigest()
        probe = ('set -o pipefail; timeout 10 openssl s_client -connect %s:443 -servername %s '
                 '</dev/null 2>/dev/null | openssl x509 -outform DER 2>/dev/null | sha256sum') % (self.addr['hub'], HUB_HOST)
        def served():
            rc, out = guest.run(probe, check=False, timeout=20)
            return rc == 0 and out.split()[:1] == [expected]
        self.wait_for(served, 120, 'Traefik to serve the uploaded leaf certificate')

    def stage_hub_and_member(self):
        hub, member = self.ops['hub'], self.ops['member']
        self.ca = generate_private_ca(Path(self.names.workdir, 'ca'), self.run_id, HUB_HOST)
        for path in (self.ca['ca_key'], self.ca['server_key']):
            self.sanitizer.register(Path(path).read_text().strip().splitlines()[1])
        ca_pem = Path(self.ca['ca']).read_text()
        self.install_hub_certificate()

        def add(ops):
            reply = parse_api(ops.guest.run('add-module %s 1' % self.cfg.module_ref, timeout=1200)[1])
            ops.module = g.valid_module(reply['module_id'])
            return ops.module
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            for future in [pool.submit(add, hub), pool.submit(add, member)]:
                future.result()
        hub.api(hub.mod_agent(), 'configure-module', {'role': 'hub', 'hub_host': HUB_HOST, 'lets_encrypt': False, 'ban_duration': '30m',
                                                      'allowlist': [ALLOWLIST_CIDR], 'samba_audit': False}, timeout=600)
        self.ca_pem = ca_pem

        def digests():
            observed, images, expected_ref = {}, {}, self.cfg.module_digest
            for role, ops in self.ops.items():
                listing = ops.guest.run("podman images --digests --format '{{.Repository}}@{{.Digest}}'")[1]
                if 'ghcr.io/platypuschan/guardian@' + expected_ref not in listing.split():
                    raise ev.EvidenceError('%s: module digest not present in the guest image store' % role)
                images[role] = expected_ref
                names = ops.guest.run("podman ps --format '{{.Names}}'")[1].split()
                pinned = set()
                for name in names:
                    if name.startswith(ops.module):
                        pinned.add(ops.guest.run("podman inspect --format '{{.ImageDigest}}' %s" % name.replace("'", ''))[1].strip())
                observed[role] = pinned
            ev.assert_digest_readback(self.cfg.module_digest, images)
            ev.assert_runtime_digests(self.expected_engine, observed)
            return {'module_digest': expected_ref, 'engine_images': sorted(self.expected_engine),
                    'runtime_container_digests': {k: sorted(v) for k, v in observed.items()},
                    'registry_manifest_digest': self.source['module_digest']}
        # the member's module is installed but still unconfigured: containers appear after enrollment, so read back later
        self.digest_check = digests

        def verify_tls():
            member_guest = member.guest
            member_guest.run('cat > /root/glab-ca.pem', stdin=ca_pem)
            base = 'openssl s_client -connect %s:443 -servername %s -verify_return_error </dev/null' % (self.addr['hub'], HUB_HOST)
            good = member_guest.run(base + ' -CAfile /root/glab-ca.pem -verify_hostname %s 2>&1' % HUB_HOST, check=False)
            if good[0] != 0 or 'Verification: OK' not in good[1]:
                raise ev.EvidenceError('hub certificate did not verify against the private CA')
            system = member_guest.run(base + ' 2>&1', check=False)    # default system trust store only
            if system[0] == 0:
                raise ev.EvidenceError('negative control failed: certificate verified without the private CA')
            wrong = member_guest.run(base + ' -CAfile /root/glab-ca.pem -verify_hostname wrong.lab.test 2>&1', check=False)
            if wrong[0] == 0:
                raise ev.EvidenceError('negative control failed: wrong host name verified')
            rejected = member_guest.run(g.api_run(member.mod_agent(), 'configure-module', {'role': 'member', 'insecure_skip_verify': True}) + ' 2>&1', check=False)
            if rejected[0] == 0 or 'insecure_skip_verify' not in rejected[1]:
                raise ev.EvidenceError('Guardian did not reject insecure_skip_verify with a field error')
            return {'hub_host': HUB_HOST, 'verified_with_private_ca': True, 'rejected_without_private_ca': True,
                    'rejected_for_wrong_hostname': True, 'guardian_rejects_insecure_skip_verify': True,
                    'ca_subject': 'glab-%s-ca (2 day validity, generated on the runner)' % self.run_id}
        self.stage('private_ca_verified_https', verify_tls)

        def enroll():
            token_reply = hub.api(hub.mod_agent(), 'add-member', {'name': 'member1', 'ca': ca_pem}, secret=True)
            self.sanitizer.register(token_reply['token'])
            member.api(member.mod_agent(), 'configure-module', {'role': 'member', 'token': token_reply['token'], 'ban_duration': '30m',
                                                                'allowlist': [ALLOWLIST_CIDR]}, secret=True, timeout=600)
            for ops in (hub, member):
                self.wait_for(lambda o=ops: self._units_ok(o), 300, 'units of %s' % ops.role)
            self.wait_for(lambda: not member.sync_status().get('stale') and not member.sync_status().get('error'), 240, 'member sync success')
            members = hub.api(hub.mod_agent(), 'list-members', {})['members']
            if not any(m['name'] == 'member1' and not m.get('revoked', 0) for m in members):
                raise ev.EvidenceError('hub does not list member1')
            return {'member': 'member1', 'transport': 'https://%s/v1/sync verified by the token-carried private CA',
                    'sync_stale': False, 'hub_lists_member': True}
        self.stage('hub_member_enrollment', enroll)
        self.stage('module_digest_runtime_readback', self.digest_check)
        hub.enroll = None
        member.enroll = lambda name: hub.api(hub.mod_agent(), 'add-member', {'name': name, 'ca': ca_pem}, secret=True)['token']

    def _units_ok(self, ops):
        try:
            ev.assert_units_active(ops.units())
            return True
        except (ev.EvidenceError, RemoteError):
            return False

    def wait_for(self, predicate, timeout, what):
        end = self.clock() + timeout
        while self.clock() < end:
            try:
                if predicate():
                    return
            except RemoteError:
                pass
            self.sleep(5)
        raise Abort('timeout waiting for %s' % what)

    def stage_backup_target(self):
        """Native persistent guest-local WebDAV destination (not guest-loss DR)."""
        import ipaddress
        import uuid
        hub = self.ops['hub']
        nodes = parse_cluster_nodes(hub.api('cluster', 'list-nodes', {}))
        local = [n for n in nodes if n['node_id'] == hub.node_id]
        if len(local) != 1:
            raise ev.EvidenceError('native backup destination requires exactly one local node')
        vpn_ip = ipaddress.ip_address(local[0]['vpn_ip_address'])
        if vpn_ip.version != 4 or vpn_ip not in ipaddress.ip_network(VPN['hub']):
            raise ev.EvidenceError('backup destination VPN address outside hub network')
        url = 'webdav:http://%s:4694' % vpn_ip
        repo = hub.api('cluster', 'add-backup-repository', {
            'name': 'glab-' + self.run_id, 'provider': 'cluster', 'password': '', 'url': url,
            'parameters': {}}, secret=True, timeout=300)
        if not isinstance(repo, dict) or not isinstance(repo.get('id'), str) or not isinstance(repo.get('password'), str):
            raise ev.EvidenceError('invalid add-backup-repository output')
        repo_id = repo['id']
        if str(uuid.UUID(repo_id)) != repo_id:
            raise ev.EvidenceError('invalid backup repository UUID')
        self.sanitizer.register(repo['password'])
        # This API returns the password too, so its output must remain private.
        listing = hub.api('cluster', 'list-backup-repositories', {}, secret=True)
        matches = [r for r in listing['repositories'] if r.get('id') == repo_id]
        if len(matches) != 1 or matches[0].get('provider') != 'cluster' or matches[0].get('url') != url:
            raise ev.EvidenceError('native backup destination readback mismatch')
        backup_id = hub.api('cluster', 'add-backup', {'name': 'glab', 'repository': repo_id, 'schedule': 'daily', 'schedule_hint': {},
                                                     'retention': 3, 'instances': [hub.module], 'enabled': True}, timeout=300)
        if type(backup_id) is not int or backup_id < 1:
            raise ev.EvidenceError('add-backup must return a positive JSON integer')
        listing = hub.api('cluster', 'list-backups', {})
        matches = [b for b in listing['backups'] if b.get('id') == backup_id]
        if (len(matches) != 1 or matches[0].get('repository') != repo_id or matches[0].get('enabled') is not True
                or not any(i.get('module_id') == hub.module for i in matches[0].get('instances', []))):
            raise ev.EvidenceError('native backup schedule readback mismatch')
        hub.backup = {'repository': repo_id, 'backup_id': backup_id}

    @staticmethod
    def _tcp(host, port):
        import socket
        try:
            with socket.create_connection((host, port), timeout=3):
                return True
        except OSError:
            return False

    def hub_disk_cycle(self, action):
        """Graceful poweroff of the hub guest, qcow2 internal snapshot create/apply, boot again. Hub only."""
        guest, w = self.guests['hub'], self.names.workdir
        guest.run('systemctl poweroff', check=False, timeout=30)
        pidfile = '%s/hub.pid' % w
        for _ in range(60):
            if not qemu_running(pidfile):
                break
            self.sleep(2)
        else:
            raise Abort('hub guest did not power off')
        self.local(snapshot_commands(w, 'hub', 'glab-baseline-' + self.run_id)[action])
        self.local(qemu_argv(self.names, 'hub', self.cfg.vm_mem_mib, self.cfg.vm_cpus, self.mac['hub'], self.names.tap_hub))
        self.wait_ssh(guest)

    def disk_baseline(self):
        hub = self.ops['hub']
        self.baseline = {'epoch': hub.hybrid_state()['epoch'], 'module': hub.module, 'boot_id': hub.boot_id()}
        self.hub_disk_cycle('create')

    def stage_disk_rollback(self):
        hub, member = self.ops['hub'], self.ops['member']

        def rollback():
            before_epoch, before_boot = hub.hybrid_state()['epoch'], hub.boot_id()
            self.hub_disk_cycle('apply')
            hub.module = self.baseline['module']
            hub._source = None
            self.wait_for(lambda: self._units_ok(hub), 400, 'hub units after disk rollback')
            hub.prepare_attacker()
            ev.assert_boot_changed(before_boot, hub.boot_id())
            after_epoch = hub.hybrid_state()['epoch']
            if after_epoch != self.baseline['epoch']:
                raise ev.EvidenceError('hub epoch is not the snapshot epoch')
            members = hub.api(hub.mod_agent(), 'list-members', {})['members']
            names = sorted(m['name'] for m in members)
            if 'observer1' in names:
                raise ev.EvidenceError('hub still lists an enrollment created after the snapshot: not an older state')
            probe = '198.51.100.31'
            before = hub.reachable(probe)
            hub.ban_by_events(probe)
            self.wait_for(lambda: ev.nft_has_ip(hub.nft(), probe), 120, 'local ban after disk rollback')
            ev.assert_dropped(before, hub.reachable(probe), 'hub after disk rollback')
            return {'restore_method': 'qemu-disk-snapshot', 'snapshot': 'glab-baseline-' + self.run_id,
                    'epoch_before_rollback': before_epoch, 'epoch_after_rollback': after_epoch, 'epoch_equals_snapshot_epoch': True,
                    'enrollments_after_rollback': names, 'later_enrollment_lost': True, 'local_protection_after_rollback': True,
                    'note': 'single-VM qcow2 snapshot rollback; NOT an NS8 backup restore, no new hub epoch is created'}
        self.stage('hub_disk_snapshot_rollback', rollback)

    def stage_scenario(self):
        hub, member = self.ops['hub'], self.ops['member']
        for ops in (hub, member):
            ops.prepare_attacker()

        class Host:
            def __init__(inner, lab): inner.lab = lab
            def set_link(inner, role, up):
                inner.lab.local(link_state_command(inner.lab.names, role, up))

        class Clock:
            def __init__(inner, lab): inner.lab = lab
            def now(inner): return inner.lab.clock()
            def sleep(inner, seconds): inner.lab.sleep(seconds)
        run_scenario(hub=hub, member=member, host=Host(self), clock=Clock(self), report=self.report)

    # -- outputs ----------------------------------------------------------------
    def collect_diagnostics(self):
        files = {}
        for role, guest in self.guests.items():
            ops = self.ops[role]
            parts = []
            for title, cmd in (('failed units', 'systemctl --failed --no-pager'),
                               ('guardian units', "journalctl -b --no-pager -n 400 -u 'guardian*'"),
                               ('containers', "podman ps -a --format '{{.Names}} {{.Status}} {{.ImageDigest}}'"),
                               ('nft', g.nft_table_cmd()), ('netns', 'ip netns list'),
                               ('kernel warnings', 'journalctl -b -p warning --no-pager -n 120'),
                               # Sanitized (registered secrets and key=value patterns are redacted by the sanitizer).
                               ('core install log', 'tail -n 120 /root/install.log 2>&1'),
                               ('create-cluster log', 'tail -n 60 /root/create-cluster-private.log 2>&1'),
                               ('core agent journal', "journalctl -b --no-pager -n 200 -u agent@cluster -u agent@node -u 'agent@traefik*' 2>&1"),
                               ('rootless module agent journal', 'journalctl -b --no-pager -n 250 _UID=1000 2>&1; journalctl -b --no-pager -n 60 -u user@1000 2>&1'),
                               ('memory pressure', "journalctl -k -b --no-pager 2>&1 | grep -iE 'out of memory|killed process' | tail -n 20; free -m")):
                try:
                    parts.append('== %s\n%s' % (title, guest.run(cmd, check=False, timeout=60)[1]))
                except Exception as error:      # diagnostics must never mask the verdict
                    parts.append('== %s\n(unavailable: %s)' % (title, type(error).__name__))
            files['diagnostics-%s.log' % role] = self.sanitizer.clean('\n'.join(parts))
            raw = Path(self.names.workdir, role + '.console.raw')
            if raw.exists():
                files['console-%s.log' % role] = self.sanitizer.clean(raw.read_text(errors='replace')[-60000:])
        return files

    def guest_teardown(self):
        for role, ops in self.ops.items():
            try:
                ops.teardown_attacker()
            except Exception:
                pass
            if ops.module:
                for cmd in g.stop_module_units(ops.module):
                    try:
                        self.guests[role].run(cmd, check=False, timeout=60)
                    except Exception:
                        pass
        for role in self.guests:
            try:
                self.guests[role].run('systemctl poweroff', check=False, timeout=30)
            except Exception:
                pass

    def cleanup(self):
        def runner(argv):
            if argv and argv[0] == '@kill-qemu':
                return kill_owned_qemu(argv[1], argv[2])
            return self.runner(list(argv), input=None, timeout=120)
        # Retain the private ledger until public evidence has been written.
        keep = Ledger(self.names)
        keep.entries = [e for e in self.ledger.entries if e[0] != 'dir']
        failures = keep.cleanup(runner)
        self._cleanup_safe = not failures
        return failures

    def write_public(self, result, extra):
        self.out.mkdir(parents=True, exist_ok=True)
        files = {'result.json': json.dumps(result, indent=2, sort_keys=True) + '\n',
                 'source-evidence.json': json.dumps(getattr(self, 'source', {'error': 'unavailable'}), indent=2, sort_keys=True) + '\n',
                 'transcript.json': json.dumps(self.transcript, indent=1)[:2_000_000],
                 'summary.md': self.summary(result)}
        files.update(extra)
        for name, text in files.items():
            if name not in PUBLIC_FILES:
                raise RuntimeError('refusing to publish ' + name)
            (self.out / name).write_text(self.sanitizer.clean(text))

    def summary(self, result):
        lines = ['# Guardian two-VM lab: **%s**' % result['overall'].upper(), '',
                 'run `%s` - real NS8: %s' % (result['run_id'], result['real_ns8']), '', '| case | required | status |', '|---|---|---|']
        for case in result['cases']:
            status = case['status'] if case['status'] == 'not_run' else case['status'].upper()
            lines.append('| %s | %s | %s |' % (case['id'], 'yes' if case['required'] else 'no', status))
        failed = [c for c in result['cases'] if c['status'] == 'fail']
        if failed:
            lines += ['', '## Failures']
            lines += ['- `%s`: %s' % (c['id'], str(c['evidence'].get('error', ''))[:300]) for c in failed]
        return '\n'.join(lines) + '\n'

    def run(self):
        try:
            self.cfg = parse_inputs(self.env)
        except ConfigError as error:
            self.report = Report(run_id=self.run_id, source={}, module={})
            self.report.environment['config_error'] = str(error)
            result = self.report.finish(real_ns8=True)
            self.write_public(result, {})
            return 1
        self.report = Report(run_id=self.run_id, source={}, module={'ref': self.cfg.module_ref}, disk_rollback=self.cfg.disk_rollback,
                             sanitizer=self.sanitizer)
        self.report.environment = {'hub_distro': self.cfg.hub_distro, 'member_distro': self.cfg.member_distro, 'vm_cpus': self.cfg.vm_cpus,
                                   'vm_mem_mib': self.cfg.vm_mem_mib, 'disk_gib': self.cfg.disk_gib, 'core_ref': CORE_INSTALLER_REF,
                                   'core_image': CORE_IMAGE,
                                   'restore_kinds': ['ns8-restore-module'] + (['qemu-disk-snapshot'] if self.cfg.disk_rollback else [])}
        extra = {}
        try:
            try:
                self.stage_source()
            except Exception as error:
                self.report.environment['source_error'] = '%s: %s' % (type(error).__name__, error)
                raise Abort('source') from error
            self.stage_preflight()
            self.stage_images()
            self.stage_prepare_guests()
            self.stage_network()
            self.stage_boot()
            self.stage_clusters()
            self.stage_hub_and_member()
            self.stage_backup_target()
            if self.cfg.disk_rollback:
                self.disk_baseline()
            self.stage_scenario()
            if self.cfg.disk_rollback:
                self.stage_disk_rollback()
        except Abort as error:
            self.report.environment.setdefault('abort', str(error))
        except Exception as error:     # unexpected: still a failed acceptance, still cleaned up
            self.report.environment['unexpected_error'] = '%s: %s' % (type(error).__name__, error)
        finally:
            try:
                extra = self.collect_diagnostics() if self.guests else {}
            except Exception:
                extra = {}
            self.guest_teardown()
            failures = self.cleanup()
            leftovers = self.verify_clean()
            problems = failures + leftovers
            try:
                if problems:
                    self.report.record('owned_cleanup', 'fail', {'failures': [list(p) for p in problems]})
                else:
                    self.report.record('owned_cleanup', 'pass', {'released': [list(e) for e in self.ledger.entries if e[0] != 'dir'],
                                                                 'only_run_id': self.run_id})
            except Exception:
                pass
            result = self.report.finish(real_ns8=True)
            self.write_public(result, extra)
            self.remove_private_dir()
        return 0 if result['overall'] == 'pass' else 1

    def verify_clean(self):
        left = []
        if not self.ledger.entries:
            return left
        try:
            rc, links = self.runner(['ip', '-o', 'link', 'show'], input=None, timeout=30)
            if rc != 0:
                left.append(('link', self.run_id, 'cannot verify absence'))
            for kind, link in self.ledger.entries:
                if kind == 'link' and re.search(r'\b%s\b' % re.escape(link), links):
                    left.append(('link', link, 'still present'))
        except Exception as error:
            left.append(('link', self.run_id, 'cannot verify absence: ' + type(error).__name__))
        probe = lambda argv: self.runner(argv, input=None, timeout=30)
        left += self.ledger.verify_qemu(probe)
        left += self.ledger.verify_rules(probe)
        self._cleanup_safe = getattr(self, '_cleanup_safe', False) and not left
        return left

    def remove_private_dir(self):
        if not getattr(self, '_cleanup_safe', False):
            return  # retain pidfiles, private artifacts and recovery ledger on partial cleanup
        path = Path(self.names.workdir)
        if path.exists() and self.names.owns(str(path)):
            shutil.rmtree(path, ignore_errors=True)
