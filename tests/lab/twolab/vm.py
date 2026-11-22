"""QEMU argv, cloud-init seed contents and disk-snapshot commands for the guests."""
import os
import re
from pathlib import Path

PUBKEY_RE = re.compile(r'(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256) [A-Za-z0-9+/=]+( [A-Za-z0-9._@-]+)?')
MAC_RE = re.compile(r'52:54:00:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}')


def qemu_argv(names, role, mem_mib, cpus, mac, tap):
    w = names.workdir
    return ['qemu-system-x86_64',
            '-name', names.qemu_name(role),
            # accel=kvm only: if KVM is unusable QEMU must refuse to start, never fall back to TCG.
            '-machine', 'q35,accel=kvm', '-cpu', 'host',
            '-smp', '%d,sockets=1,cores=%d,threads=1' % (cpus, cpus), '-m', str(mem_mib),
            '-display', 'none', '-monitor', 'none',
            '-serial', 'file:%s/%s.console.raw' % (w, role),
            '-device', 'virtio-rng-pci',
            '-drive', 'if=virtio,file=%s/%s.qcow2,format=qcow2,cache=writeback,discard=unmap' % (w, role),
            '-drive', 'if=virtio,file=%s/%s.seed.iso,format=raw,readonly=on' % (w, role),
            '-netdev', 'tap,id=n0,ifname=%s,script=no,downscript=no' % tap,
            '-device', 'virtio-net-pci,netdev=n0,mac=%s' % mac,
            '-daemonize', '-pidfile', '%s/%s.pid' % (w, role)]


def cloud_init_files(role, pubkey, ip, gateway, mac, run_id, hosts):
    if not PUBKEY_RE.fullmatch(pubkey):
        raise ValueError('unexpected SSH public key format')
    if not MAC_RE.fullmatch(mac):
        raise ValueError('unexpected MAC')
    fqdn = 'ns8-%s-%s.lab.test' % (role, run_id)
    host_lines = ''.join("  - [ bash, -c, \"echo '%s %s' >> /etc/hosts\" ]\n" % (addr, name) for addr, name in hosts.items())
    user_data = '''#cloud-config
hostname: ns8-{role}-{rid}
fqdn: {fqdn}
prefer_fqdn_over_hostname: true
manage_etc_hosts: false
disable_root: false
ssh_pwauth: false
users:
  - name: root
    ssh_authorized_keys:
      - "{pubkey}"
growpart:
  mode: auto
  devices: ["/"]
resize_rootfs: true
write_files:
  - path: /etc/ssh/sshd_config.d/00-lab-root.conf
    permissions: '0600'
    content: |
      PermitRootLogin prohibit-password
      PasswordAuthentication no
      PubkeyAuthentication yes
      UseDNS no
  - path: /usr/local/sbin/lab-prepare
    permissions: '0755'
    content: |
      #!/bin/bash
      # Debian's resolved stub holds :53; the image boots once under another machine-id.
      if systemctl is-active --quiet systemd-resolved; then
          systemctl disable --now systemd-resolved
          rm -f /etc/resolv.conf
          printf 'nameserver 1.1.1.1\\nnameserver 8.8.8.8\\n' > /etc/resolv.conf
      fi
      if [ -d "/var/log/journal/$(cat /etc/machine-id)" ]; then
          journalctl --flush
          rm -rf /run/log/journal/*
      fi
      systemctl restart ssh 2>/dev/null || systemctl restart sshd
runcmd:
  - [ bash, -c, "echo '{ip} {fqdn} ns8-{role}-{rid}' >> /etc/hosts" ]
{hosts}  - [ /usr/local/sbin/lab-prepare ]
'''.format(role=role, rid=run_id, fqdn=fqdn, pubkey=pubkey, ip=ip, hosts=host_lines)
    meta = 'instance-id: glab-%s-%s\nlocal-hostname: ns8-%s-%s\n' % (run_id, role, role, run_id)
    network = '''version: 2
ethernets:
  eth0:
    match:
      macaddress: "{mac}"
    set-name: eth0
    dhcp4: false
    dhcp6: false
    addresses:
      - "{ip}/24"
    routes:
      - to: 0.0.0.0/0
        via: "{gw}"
    nameservers:
      addresses: [1.1.1.1, 8.8.8.8]
    mtu: 1500
'''.format(mac=mac, ip=ip, gw=gateway)
    return {'user-data': user_data, 'meta-data': meta, 'network-config': network}


def seed_command(workdir, role):
    d = str(workdir)
    return ['cloud-localds', '--network-config=%s/%s.network-config' % (d, role), '%s/%s.seed.iso' % (d, role),
            '%s/%s.user-data' % (d, role), '%s/%s.meta-data' % (d, role)]


def snapshot_commands(workdir, role, tag):
    disk = '%s/%s.qcow2' % (workdir, role)
    return {'create': ['qemu-img', 'snapshot', '-c', tag, disk], 'apply': ['qemu-img', 'snapshot', '-a', tag, disk],
            'list': ['qemu-img', 'snapshot', '-l', disk]}


def kill_owned_qemu(pidfile, name):
    """SIGTERM then SIGKILL, but only if /proc/<pid>/cmdline proves the process carries this run's -name.

    0 = gone/stopped, 1 = could not stop it (unreadable pidfile, not ours, no permission): a cleanup failure."""
    import signal, time
    try:
        pid = int(Path(pidfile).read_text().strip())
    except FileNotFoundError:
        return 0     # never started or already cleaned
    except (OSError, ValueError):
        return 1
    try:
        cmdline = Path('/proc/%d/cmdline' % pid).read_bytes().split(b'\0')
    except FileNotFoundError:
        return 0     # process already gone
    except OSError:
        return 1
    if b'-name' not in cmdline or name.encode() not in cmdline:
        return 1     # pid reused by something not ours: never kill it
    try:
        os.kill(pid, signal.SIGTERM)
        for _ in range(50):
            try:
                if Path('/proc/%d/stat' % pid).read_text().rsplit(')', 1)[1].split()[0] == 'Z':
                    return 0
            except OSError:
                return 0
            time.sleep(0.2)
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        return 0
    except PermissionError:
        return 1
    return 0


def qemu_running(pidfile):
    try:
        pid = int(Path(pidfile).read_text().strip())
        state = Path('/proc/%d/stat' % pid).read_text().rsplit(')', 1)[1].split()[0]
    except (OSError, ValueError, IndexError):
        return False
    return state != 'Z'
