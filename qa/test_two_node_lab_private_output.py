"""Private remote steps must not publish yet-unknown returned credentials."""
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tests/lab'))
from twolab.sanitize import Sanitizer
from twolab.ssh import Guest, RemoteError


class PrivateOutput(unittest.TestCase):
    def test_private_stdout_is_returned_but_never_recorded(self):
        transcript = []
        raw = 'join-cluster --token UNREGISTERED_JOIN_CREDENTIAL'
        guest = Guest('hub', '192.168.200.11', '/key', '/hosts',
                      lambda *a, **k: (0, raw), Sanitizer(), transcript)
        self.assertEqual(guest.run('create-cluster', stdin='private\n', secret_stdin=True), (0, raw))
        self.assertNotIn('UNREGISTERED_JOIN_CREDENTIAL', json.dumps(transcript))

    def test_private_failure_never_formats_unknown_output(self):
        transcript = []
        raw = 'UNREGISTERED_JOIN_CREDENTIAL'
        guest = Guest('hub', '192.168.200.11', '/key', '/hosts',
                      lambda *a, **k: (1, raw), Sanitizer(), transcript)
        with self.assertRaises(RemoteError) as raised:
            guest.run('create-cluster', stdin='private\n', secret_stdin=True)
        self.assertNotIn(raw, str(raised.exception))
        self.assertNotIn(raw, json.dumps(transcript))
