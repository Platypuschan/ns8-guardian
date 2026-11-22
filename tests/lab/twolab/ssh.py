"""SSH transport to a guest with a sanitized transcript. Secrets go on stdin and are never logged."""
import subprocess


class RemoteError(RuntimeError):
    def __init__(self, message, transport=False, returncode=None):
        super().__init__(message)
        self.transport = transport
        self.returncode = returncode


def subprocess_runner(argv, input=None, timeout=None):
    try:
        done = subprocess.run(argv, input=input, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return 124, 'timed out after %ss' % timeout
    return done.returncode, (done.stdout or '') + (done.stderr or '')


class Guest:
    def __init__(self, role, ip, keyfile, known_hosts, runner, sanitizer, transcript, connect_timeout=10):
        self.role, self.ip, self.keyfile, self.known_hosts = role, ip, keyfile, known_hosts
        self.runner, self.sanitizer, self.transcript = runner, sanitizer, transcript
        self.connect_timeout = connect_timeout

    def ssh_argv(self, remote):
        return ['ssh', '-i', self.keyfile, '-o', 'BatchMode=yes', '-o', 'PasswordAuthentication=no',
                '-o', 'StrictHostKeyChecking=accept-new', '-o', 'UserKnownHostsFile=' + self.known_hosts,
                '-o', 'ConnectTimeout=%d' % self.connect_timeout, '-o', 'ServerAliveInterval=15',
                '-o', 'ServerAliveCountMax=8', '-o', 'LogLevel=ERROR', 'root@' + self.ip, remote]

    def run(self, cmd, stdin=None, secret_stdin=False, check=True, timeout=300):
        rc, out = self.runner(self.ssh_argv(cmd), input=stdin, timeout=timeout)
        # Private calls can return newly generated credentials that are not yet
        # in the sanitizer registry. Never serialize their output or errors.
        clean = '[private output withheld]' if secret_stdin else self.sanitizer.clean(out)
        self.transcript.append({'role': self.role, 'cmd': self.sanitizer.clean(cmd), 'rc': rc,
                                'stdin_bytes': len(stdin) if stdin else 0, 'out': clean[-4000:]})
        if rc == 255 and check:
            raise RemoteError('ssh transport failure to %s: %s' % (self.role, clean[-300:]), transport=True, returncode=rc)
        if check and rc != 0:
            raise RemoteError('%s: command failed (%d): %s' % (self.role, rc, clean[-500:]), returncode=rc)
        return rc, out
