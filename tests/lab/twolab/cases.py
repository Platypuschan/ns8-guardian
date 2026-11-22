"""Explicit acceptance outcomes. Nothing is green unless every required case really passed."""
SCHEMA = 'guardian-two-node-lab/1'

REQUIRED_CASES = [
    'preflight_capacity_kvm',
    'cloud_image_checksums',
    'independent_clusters',
    'module_digest_runtime_readback',
    'private_ca_verified_https',
    'hub_member_enrollment',
    'member_to_hub_sync_and_drop',
    'hub_to_member_sync_and_drop',
    'absolute_ttl',
    'no_echo',
    'allowlist_negative_control',
    'engine_restart_event_replay',
    'hub_unreachable_local_protection',
    'reconnect_convergence_ban_unban',
    'member_guest_reboot',
    'hub_guest_reboot',
    'native_ns8_backup_restore',
    'restore_new_epoch_tombstone_reconverge',
    'fresh_observer_no_resurrection',
    'management_source_unaffected',
    'owned_cleanup',
]
OPTIONAL_CASES = ['hub_disk_snapshot_rollback']
STATUSES = ('pass', 'fail')


class ReportError(ValueError):
    pass


class Report:
    def __init__(self, run_id, source, module, disk_rollback=False, sanitizer=None):
        from .sanitize import Sanitizer
        self.run_id, self.source, self.module = run_id, source, module
        self.disk_rollback = disk_rollback
        self.sanitizer = sanitizer or Sanitizer()
        self.results = {}
        self.environment = {}

    def required(self):
        return REQUIRED_CASES + (OPTIONAL_CASES if self.disk_rollback else [])

    def record(self, case, status, evidence):
        if case not in REQUIRED_CASES + OPTIONAL_CASES:
            raise ReportError('unknown case ' + case)
        if status not in STATUSES:
            raise ReportError('status must be pass or fail; skipped/pending is not a result')
        if case in self.results:
            raise ReportError('duplicate result for ' + case)
        method = evidence.get('restore_method')
        if status == 'pass':
            if case == 'native_ns8_backup_restore' and (method != 'ns8-restore-module' or evidence.get('restore_exit_code') != 0):
                raise ReportError('native NS8 restore needs restore-module evidence, not a disk operation')
            if case == 'hub_disk_snapshot_rollback' and method != 'qemu-disk-snapshot':
                raise ReportError('disk rollback evidence must say qemu-disk-snapshot; it is not a native restore')
        self.results[case] = {'id': case, 'status': status, 'required': case in self.required(),
                              'evidence': self.sanitizer.evidence(evidence)}

    def finish(self, real_ns8=True):
        cases = []
        for case in REQUIRED_CASES + OPTIONAL_CASES:
            cases.append(self.results.get(case) or {'id': case, 'status': 'not_run', 'required': case in self.required(),
                                                    'evidence': {}})
        ok = all(c['status'] == 'pass' for c in cases if c['required'])
        overall = ('pass' if ok else 'fail') if real_ns8 else 'mock-only'
        return {'schema': SCHEMA, 'run_id': self.run_id, 'overall': overall, 'real_ns8': bool(real_ns8),
                'source': self.source, 'module': self.module, 'environment': self.environment, 'cases': cases,
                'counts': {s: sum(1 for c in cases if c['status'] == s) for s in ('pass', 'fail', 'not_run')}}
