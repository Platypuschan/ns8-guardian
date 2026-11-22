"""Cloud image sources and mandatory checksum verification (no weekly-key fallback)."""
import hashlib
import re

IMAGES = {
    'debian13': {
        'url': 'https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2',
        'checksum_url': 'https://cloud.debian.org/images/cloud/trixie/latest/SHA512SUMS',
        'algo': 'sha512',
    },
    'rocky9': {
        'url': 'https://dl.rockylinux.org/pub/rocky/9/images/x86_64/Rocky-9-GenericCloud-Base.latest.x86_64.qcow2',
        'checksum_url': 'https://dl.rockylinux.org/pub/rocky/9/images/x86_64/CHECKSUM',
        'algo': 'sha256',
    },
}
HEX_LEN = {'sha256': 64, 'sha512': 128}


class ChecksumError(RuntimeError):
    pass


def parse_checksums(text):
    sums = {}
    for line in text.splitlines():
        bsd = re.fullmatch(r'SHA(?:256|512) \((.+)\) = ([0-9a-fA-F]+)', line.strip())
        gnu = re.fullmatch(r'([0-9a-fA-F]{64,128}) [ *](.+)', line.strip())
        if bsd:
            sums[bsd.group(1)] = bsd.group(2).lower()
        elif gnu:
            sums[gnu.group(2)] = gnu.group(1).lower()
    if not sums:
        raise ChecksumError('no checksums found in listing')
    return sums


def verify_file(path, expected, algo):
    if algo not in HEX_LEN:
        raise ChecksumError('unsupported algorithm')
    if not expected or not re.fullmatch(r'[0-9a-f]{%d}' % HEX_LEN[algo], expected):
        raise ChecksumError('no valid published checksum: refusing to boot unverified image')
    digest = hashlib.new(algo)
    with open(path, 'rb') as handle:
        for block in iter(lambda: handle.read(1 << 20), b''):
            digest.update(block)
    if digest.hexdigest() != expected:
        raise ChecksumError('checksum mismatch')
    return expected
