"""Short-lived private CA + hub server certificate, generated on the runner with openssl."""
import os
import re
import subprocess
from pathlib import Path

HOST_RE = re.compile(r'(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}')


def _openssl(*args):
    done = subprocess.run(['openssl', *args], capture_output=True, text=True)
    if done.returncode != 0:
        raise RuntimeError('openssl %s failed: %s' % (args[0], done.stderr.strip()[-300:]))


def generate_private_ca(directory, run_id, hostname):
    if not HOST_RE.fullmatch(hostname):
        raise ValueError('invalid hub host name')
    d = Path(directory)
    d.mkdir(parents=True, exist_ok=True)
    f = {k: str(d / v) for k, v in (('ca_key', 'ca.key'), ('ca', 'ca.pem'), ('server_key', 'server.key'), ('server_csr', 'server.csr'),
                                    ('server', 'server.pem'), ('ext', 'server.ext'))}
    old = os.umask(0o077)
    try:
        _openssl('ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', f['ca_key'])
        _openssl('req', '-x509', '-new', '-key', f['ca_key'], '-sha256', '-days', '2', '-subj', '/CN=glab-%s-ca' % run_id,
                 '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign', '-out', f['ca'])
        _openssl('ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', f['server_key'])
        _openssl('req', '-new', '-key', f['server_key'], '-subj', '/CN=' + hostname, '-out', f['server_csr'])
        Path(f['ext']).write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n'
                                  'extendedKeyUsage=serverAuth\nsubjectAltName=DNS:%s\n' % hostname)
        _openssl('x509', '-req', '-in', f['server_csr'], '-CA', f['ca'], '-CAkey', f['ca_key'], '-CAcreateserial', '-days', '2',
                 '-sha256', '-extfile', f['ext'], '-out', f['server'])
    finally:
        os.umask(old)
    for key in ('ca_key', 'server_key'):
        os.chmod(f[key], 0o600)
    return f
