"""Exact source/artifact evidence for the result file."""
import re

OWNER_REPO = 'Platypuschan/ns8-guardian'
PIN_RE = re.compile(r'@(sha256:[0-9a-f]{64})$')


class SourceError(RuntimeError):
    pass


def source_evidence(cfg, env, git_head, git_dirty, registry, workflow_sha256, lab_tree):
    if env.get('GITHUB_REPOSITORY') != OWNER_REPO or env.get('GITHUB_REF') != 'refs/heads/main' \
            or env.get('GITHUB_EVENT_NAME') != 'workflow_dispatch':
        raise SourceError('only a manual dispatch of %s main is accepted' % OWNER_REPO)
    if git_head != env.get('GITHUB_SHA'):
        raise SourceError('checkout %s does not equal the dispatched commit %s' % (git_head, env.get('GITHUB_SHA')))
    if git_dirty.strip():
        raise SourceError('dirty working tree')
    if registry.get('Digest') != cfg.module_digest:
        raise SourceError('registry digest %s differs from the requested digest' % registry.get('Digest'))
    labels = registry.get('Labels') or {}
    if not labels:
        raise SourceError('module image carries no labels')
    if labels.get('org.opencontainers.image.revision') != cfg.expected_source_sha:
        raise SourceError('module revision label %s is not the expected source' % labels.get('org.opencontainers.image.revision'))
    if labels.get('org.opencontainers.image.version') != cfg.expected_version:
        raise SourceError('module version label %s is not the expected version' % labels.get('org.opencontainers.image.version'))
    return {'lab_repository': env['GITHUB_REPOSITORY'], 'lab_ref': env['GITHUB_REF'], 'lab_source_sha': git_head,
            'lab_tree': lab_tree, 'workflow_sha256': workflow_sha256, 'run_id': env.get('GITHUB_RUN_ID', ''),
            'run_attempt': env.get('GITHUB_RUN_ATTEMPT', ''), 'module_ref': cfg.module_ref, 'module_digest': registry['Digest'],
            'module_source_sha': labels['org.opencontainers.image.revision'], 'module_version': labels['org.opencontainers.image.version'],
            'module_source_repo': labels.get('org.opencontainers.image.source', ''),
            'engine_images': sorted(expected_runtime_digests(labels))}


def expected_runtime_digests(labels):
    images = (labels.get('org.nethserver.images') or '').split()
    digests = set()
    for image in images:
        match = PIN_RE.search(image)
        if not match:
            raise SourceError('label image %s is not digest-pinned' % image)
        digests.add(match.group(1))
    if not digests:
        raise SourceError('no runtime images declared in labels')
    return digests
