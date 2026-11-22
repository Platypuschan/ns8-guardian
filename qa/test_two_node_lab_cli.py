"""Offline regressions for the launcher CLI: safe argument handling and exit codes."""
import io
import json
import contextlib
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'tests' / 'lab'))

from twolab import cli  # noqa: E402
from twolab.resources import Ledger, Names  # noqa: E402


def call(argv, env=None):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = cli.main(argv, env=env or {})
        except SystemExit as exit_:
            code = exit_.code
    return code, out.getvalue(), err.getvalue()


class Cli(unittest.TestCase):
    def test_unknown_commands_and_extra_arguments_are_rejected(self):
        for argv in ([], ['frobnicate'], ['run', '--out', 'x', '--insecure'], ['run', 'extra']):
            code, _, _ = call(argv)
            self.assertNotEqual(code, 0, argv)

    def test_run_refuses_unsafe_output_directories(self):
        for bad in ('/', '/etc', '../escape', 'a/../../b', ''):
            code, _, err = call(['run', '--out', bad], env={})
            self.assertEqual(code, 2, bad)

    def test_run_with_invalid_inputs_exits_nonzero_and_names_the_problem_without_traceback(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out, err = call(['run', '--out', 'lab-out-test'], env={'MODULE_DIGEST': 'latest', 'LAB_ROOT': tmp})
            self.assertEqual(code, 1)
            self.assertNotIn('Traceback', err + out)

    def test_cleanup_requires_a_well_formed_run_id_and_an_existing_ledger(self):
        code, _, _ = call(['cleanup', '--run-id', 'nothex!!', '--workdir', '/tmp/x'])
        self.assertEqual(code, 2)
        with tempfile.TemporaryDirectory() as tmp:
            code, _, err = call(['cleanup', '--run-id', 'a1b2c3d4', '--workdir', tmp + '/gl-a1b2c3d4'])
            self.assertEqual(code, 2)

    def test_cleanup_refuses_a_workdir_that_does_not_carry_the_run_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, _, _ = call(['cleanup', '--run-id', 'a1b2c3d4', '--workdir', tmp])
            self.assertEqual(code, 2)

    def test_preflight_prints_capacity_json_or_fails_closed(self):
        code, out, _ = call(['preflight'], env={'MODULE_DIGEST': 'sha256:' + 'a' * 64, 'EXPECTED_SOURCE_SHA': 'b' * 40,
                                                'EXPECTED_VERSION': '0.2.0-rc.3', 'LAB_FAKE_HOST': json.dumps({
                                                    'meminfo_text': 'MemAvailable: 100 kB\n', 'disk_free_bytes': 1, 'cpus': 1,
                                                    'kvm': {'exists': False, 'readable': False, 'writable': False}, 'user': 'x'})})
        self.assertEqual(code, 1)
        self.assertIn('kvm', out)
