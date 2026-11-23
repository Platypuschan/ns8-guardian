"""Validated lab inputs. Everything arrives as environment, never spliced into shell text."""
from dataclasses import dataclass
import re

MODULE_REPOSITORY = 'ghcr.io/platypuschan/guardian'   # fixed: not an input
DISTROS = ('debian13', 'rocky9')
DIGEST_RE = re.compile(r'sha256:[0-9a-f]{64}')
SHA_RE = re.compile(r'[0-9a-f]{40}')
REF_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}')
VERSION_RE = re.compile(r'[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?')


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class LabConfig:
    module_digest: str
    expected_source_sha: str
    expected_version: str
    hub_distro: str
    member_distro: str
    vm_cpus: int
    vm_mem_mib: int
    disk_gib: int
    core_ref: str
    disk_rollback: bool
    previous_digest: str = ''

    @property
    def module_ref(self):
        return MODULE_REPOSITORY + '@' + self.module_digest


def _int(env, key, default, low, high):
    raw = env.get(key, str(default))
    if not re.fullmatch(r'[0-9]{1,6}', raw or ''):
        raise ConfigError('%s must be an integer' % key)
    value = int(raw)
    if not low <= value <= high:
        raise ConfigError('%s must be within %d..%d' % (key, low, high))
    return value


def _match(env, key, pattern, default=None):
    value = env.get(key, default)
    if value is None or not pattern.fullmatch(value):
        raise ConfigError('%s has an invalid value' % key)
    return value


def parse_inputs(env):
    distros = []
    for key, default in (('HUB_DISTRO', 'debian13'), ('MEMBER_DISTRO', 'rocky9')):
        value = env.get(key, default)
        if value not in DISTROS:
            raise ConfigError('%s must be one of %s' % (key, ', '.join(DISTROS)))
        distros.append(value)
    flag = env.get('DISK_ROLLBACK', 'false')
    if flag not in ('true', 'false'):
        raise ConfigError('DISK_ROLLBACK must be true or false')
    previous = env.get('PREVIOUS_DIGEST', '')
    if previous and (not DIGEST_RE.fullmatch(previous) or previous == env.get('MODULE_DIGEST')):
        raise ConfigError('PREVIOUS_DIGEST must be a sha256 digest different from MODULE_DIGEST')
    return LabConfig(
        module_digest=_match(env, 'MODULE_DIGEST', DIGEST_RE),
        expected_source_sha=_match(env, 'EXPECTED_SOURCE_SHA', SHA_RE),
        expected_version=_match(env, 'EXPECTED_VERSION', VERSION_RE),
        hub_distro=distros[0], member_distro=distros[1],
        # Two guests share one runner: never inherit the single-VM 8 GiB/4 vCPU upstream default.
        vm_cpus=_int(env, 'VM_CPUS', 2, 1, 2),
        vm_mem_mib=_int(env, 'VM_MEM_MIB', 3072, 2816, 4096),
        disk_gib=_int(env, 'DISK_GIB', 24, 20, 40),
        core_ref=_match(env, 'CORE_REF', REF_RE, 'ns8-stable'),
        disk_rollback=flag == 'true',
        previous_digest=previous,
    )
