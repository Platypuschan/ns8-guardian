"""Fail-closed runner capacity and KVM checks. Software emulation (TCG) is never acceptable."""
import re

MIB = 1024 ** 2
GIB = 1024 ** 3
HEADROOM_MIB = 2048      # runner OS, containers, rclone S3 server, ssh


class CapacityError(RuntimeError):
    pass


def check_capacity(meminfo_text, disk_free_bytes, cpus, kvm, cfg):
    guests = 2
    if not (kvm.get('exists') and kvm.get('readable') and kvm.get('writable')):
        raise CapacityError('kvm: /dev/kvm missing or not read/write accessible; TCG fallback is not allowed')
    match = re.search(r'^MemAvailable:\s+(\d+)\s+kB$', meminfo_text or '', re.M)
    if not match:
        raise CapacityError('memory: MemAvailable could not be read')
    avail_mib = int(match.group(1)) // 1024
    need_mib = guests * cfg.vm_mem_mib + HEADROOM_MIB
    if avail_mib < need_mib:
        raise CapacityError('memory: %d MiB available, %d MiB required' % (avail_mib, need_mib))
    need_disk = (guests * cfg.disk_gib + 8) * GIB
    if disk_free_bytes < need_disk:
        raise CapacityError('disk: %d GiB free, %d GiB required' % (disk_free_bytes // GIB, need_disk // GIB))
    need_cpu = guests * cfg.vm_cpus
    if cpus < need_cpu:
        raise CapacityError('cpu: %d available, %d required' % (cpus, need_cpu))
    return {'guests': guests, 'accel': 'kvm', 'mem_available_mib': avail_mib, 'mem_required_mib': need_mib,
            'disk_free_gib': disk_free_bytes // GIB, 'disk_required_gib': need_disk // GIB,
            'cpus': cpus, 'cpus_required': need_cpu, 'vm_mem_mib': cfg.vm_mem_mib, 'vm_cpus': cfg.vm_cpus}
