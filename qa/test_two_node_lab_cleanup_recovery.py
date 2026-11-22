"""Crash/restart regressions. All host commands use an in-memory firewall model."""
import json
from pathlib import Path
import shlex
import sys
import tempfile
import unittest
from collections.abc import Callable
from contextlib import redirect_stderr, redirect_stdout
import io

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tests' / 'lab'))
from unittest.mock import patch
from types import SimpleNamespace

from twolab import cli
from twolab.lab import Lab
from twolab.resources import Ledger


class Firewall:
    def __init__(self):
        self.rules = set()
        self.calls = []
        self.before_insert: Callable | None = None

    def __call__(self, argv, input=None, timeout=None):
        self.calls.append(list(argv))
        if argv[:2] == ['sudo', 'iptables']:
            rule = list(argv)
            action = next(x for x in ('-I', '-D') if x in rule)
            pos = rule.index(action)
            rule[pos] = '-D'
            if action == '-I' and len(rule) > pos + 2 and rule[pos + 2] == '1':
                rule.pop(pos + 2)
            key = tuple(rule)
            if action == '-I':
                if self.before_insert:
                    self.before_insert(key)
                self.rules.add(key)
                return 0, ''
            if key in self.rules:
                self.rules.remove(key)
                return 0, ''
            return 1, 'Bad rule (does a matching rule exist in that chain?)'
        if argv == ['sudo', 'iptables-save']:
            return 0, '\n'.join(shlex.join(r[2:]).replace('-D ', '-A ', 1) for r in sorted(self.rules))
        return 0, ''


class Recovery(unittest.TestCase):
    def make_lab(self, tmp, firewall):
        lab = Lab({}, runner=firewall, run_id='a1b2c3d4', workbase=tmp)
        lab.subnet, lab.user = '192.168.171.0/24', 'runner'
        return lab

    def test_malformed_or_unowned_ledger_is_rejected_before_any_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            fw = Firewall()
            lab = self.make_lab(tmp, fw)
            Path(lab.names.workdir).mkdir()
            bad_entries = [
                ('link', 'eth0-' + lab.run_id),
                ('qemu', 'foreign-' + lab.run_id),
                ('dir', str(Path(tmp) / ('other-' + lab.run_id))),
                ('container', 'foreign-' + lab.run_id),
                ('acl', 'foreign-' + lab.run_id),
                ('iptables', json.dumps(['sudo', 'iptables', '-F', '--comment', lab.names.rule_comment])),
                ('iptables', json.dumps(['sudo', 'iptables', '-D', 'FORWARD', '-j', 'ACCEPT', '-m', 'comment', '--comment', lab.names.rule_comment + '-foreign'])),
                ('iptables', 'not-json-' + lab.run_id),
            ]
            for entry in bad_entries:
                with self.subTest(entry=entry):
                    Path(lab.names.workdir, 'ledger.json').write_text(json.dumps([entry]))
                    with self.assertRaises((ValueError, RuntimeError)):
                        Ledger.load(lab.names)
            self.assertFalse(fw.calls)

    def test_delete_errors_require_successful_absence_verification(self):
        for state in ('missing', 'survives', 'permission'):
            with self.subTest(state=state), tempfile.TemporaryDirectory() as tmp:
                fw = Firewall()
                lab = self.make_lab(tmp, fw)
                lab.stage_network()
                if state == 'missing':
                    fw.rules.clear()  # crash before creation, or earlier cleanup already removed it
                probes = []
                def runner(argv):
                    probes.append(argv)
                    if 'iptables' in argv and '-D' in argv and state != 'missing':
                        return 1, 'Permission denied'
                    if argv == ['sudo', 'iptables-save'] and state == 'permission':
                        return 4, 'Permission denied'
                    return fw(argv)
                failures = Ledger.load(lab.names).cleanup(runner)
                self.assertEqual(bool(failures), state != 'missing')
                self.assertIn(['sudo', 'iptables-save'], probes)

    def test_cli_keeps_ledger_if_owned_qemu_survives_even_after_successful_kill(self):
        with tempfile.TemporaryDirectory() as tmp:
            fw = Firewall()
            lab = self.make_lab(tmp, fw)
            lab.stage_network()
            lab.own('qemu', lab.names.qemu_name('hub'))
            lab.own('dir', lab.names.workdir)  # directory order must not depend on registration order
            removed = []
            def run(argv, **kwargs):
                if argv[0] == 'pgrep':
                    rc, out = 0, '123 qemu-system-x86_64 -name ' + lab.names.qemu_name('hub')
                elif argv[0] == 'rm':
                    removed.append(argv)
                    rc, out = 0, ''
                else:
                    rc, out = fw(argv)
                return SimpleNamespace(returncode=rc, stdout=out, stderr='')
            with patch('subprocess.run', side_effect=run), patch.object(cli, 'kill_owned_qemu', return_value=0), redirect_stdout(io.StringIO()):
                code = cli.main(['cleanup', '--run-id', lab.run_id, '--workdir', lab.names.workdir])
            self.assertEqual(code, 1)
            self.assertFalse(removed)
            self.assertTrue(Path(lab.names.workdir, 'ledger.json').exists())
            self.assertFalse(fw.rules)  # still attempt all independent resources

    def test_in_process_cleanup_retains_private_files_on_surviving_qemu(self):
        with tempfile.TemporaryDirectory() as tmp:
            fw = Firewall()
            lab = self.make_lab(tmp, fw)
            lab.stage_network()
            lab.own('dir', lab.names.workdir)
            lab.own('qemu', lab.names.qemu_name('hub'))
            private = Path(lab.names.workdir, 'private-key')
            private.write_text('private artifact')
            def runner(argv, **kwargs):
                if argv[0] == 'pgrep':
                    return 0, '123 qemu-system-x86_64 -name ' + lab.names.qemu_name('hub')
                return fw(argv)
            lab.runner = runner
            with patch('twolab.lab.kill_owned_qemu', return_value=0):
                self.assertTrue(lab.cleanup())
                self.assertTrue(lab.verify_clean())
                lab.remove_private_dir()
            self.assertTrue(private.exists())
            self.assertTrue(Path(lab.names.workdir, 'ledger.json').exists())
            self.assertFalse(fw.rules)

    def test_interrupted_ledger_save_preserves_previous_recovery_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            lab = self.make_lab(tmp, Firewall())
            lab.own('link', lab.names.bridge)
            original = Path(lab.names.workdir, 'ledger.json').read_bytes()
            lab.ledger.register('link', lab.names.tap_hub)
            def interrupted(entries, handle):
                handle.write('[')
                raise OSError('launcher interrupted during write')
            with patch('twolab.resources.json.dump', side_effect=interrupted):
                with self.assertRaises(OSError):
                    lab.ledger.save()
            self.assertEqual(Path(lab.names.workdir, 'ledger.json').read_bytes(), original)
            self.assertEqual(Ledger.load(lab.names).entries, [('link', lab.names.bridge)])

    def test_cli_refuses_malformed_ledger_without_executing_commands(self):
        with tempfile.TemporaryDirectory() as tmp:
            lab = self.make_lab(tmp, Firewall())
            Path(lab.names.workdir).mkdir()
            for malformed in ('null', '{}', '[null]', '[[[], "x"]]', '[["link", "eth0-a1b2c3d4"]]'):
                with self.subTest(malformed=malformed):
                    Path(lab.names.workdir, 'ledger.json').write_text(malformed)
                    with patch('subprocess.run') as run, redirect_stderr(io.StringIO()):
                        code = cli.main(['cleanup', '--run-id', lab.run_id, '--workdir', lab.names.workdir])
                    self.assertEqual(code, 2)
                    run.assert_not_called()

    def test_partial_creation_restart_removes_only_existing_owned_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            fw = Firewall()
            lab = self.make_lab(tmp, fw)
            def crash(rule):
                if fw.rules:
                    raise SystemExit('launcher killed before second insert')
            fw.before_insert = crash
            with self.assertRaises(SystemExit):
                lab.stage_network()
            self.assertEqual(len(fw.rules), 1)
            recovered = Ledger.load(lab.names)
            self.assertEqual(sum(k == 'iptables' for k, _ in recovered.entries), 2)
            foreign = tuple(t.replace(lab.names.rule_comment, lab.names.rule_comment + '-foreign')
                            for t in next(iter(fw.rules)))
            fw.rules.add(foreign)
            self.assertFalse(recovered.cleanup(fw))
            self.assertEqual(fw.rules, {foreign})
            self.assertFalse(any('-F' in c or '-P' in c for c in fw.calls))

    def test_successful_deletes_with_unreadable_save_cannot_report_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            fw = Firewall()
            lab = self.make_lab(tmp, fw)
            lab.stage_network()
            def runner(argv):
                if argv == ['sudo', 'iptables-save']:
                    return 4, ''
                return fw(argv)
            failures = Ledger.load(lab.names).cleanup(runner)
            self.assertFalse(fw.rules)
            self.assertTrue(failures)
            self.assertIn('cannot verify absence', str(failures))

    def test_directory_is_last_and_retained_until_all_rule_cleanup_is_verified(self):
        with tempfile.TemporaryDirectory() as tmp:
            fw = Firewall()
            lab = self.make_lab(tmp, fw)
            lab.stage_network()
            lab.own('dir', lab.names.workdir)
            calls = []
            def failing(argv):
                calls.append(argv)
                if 'iptables' in argv and '-D' in argv:
                    raise OSError('permission denied')
                return fw(argv)
            ledger = Ledger.load(lab.names)
            self.assertTrue(ledger.cleanup(failing))
            self.assertEqual(sum('-D' in c for c in calls), 3)
            self.assertEqual(sum(c[:4] == ['sudo', 'ip', 'link', 'del'] for c in calls), 3)
            self.assertFalse(any(c[0] == 'rm' for c in calls))
            self.assertTrue(Path(lab.names.workdir, 'ledger.json').exists())
            calls.clear()
            def successful(argv):
                calls.append(argv)
                return fw(argv)
            self.assertFalse(ledger.cleanup(successful))
            self.assertEqual(calls[-1][0], 'rm')
            self.assertIn(['sudo', 'iptables-save'], calls[:-1])

    def test_crash_restart_has_precise_rule_intents_before_each_insert(self):
        with tempfile.TemporaryDirectory() as tmp:
            fw = Firewall()
            lab = self.make_lab(tmp, fw)
            def check_intent(rule):
                saved = Ledger.load(lab.names)
                self.assertIn(rule, [step.argv for step in saved.cleanup_plan()])
            fw.before_insert = check_intent
            lab.stage_network()
            self.assertEqual(len(fw.rules), 3)
            restarted = Ledger.load(lab.names)
            self.assertFalse(restarted.cleanup(fw))
            self.assertFalse(fw.rules)
            self.assertEqual(sum('iptables' in c and '-D' in c for c in fw.calls), 3)


if __name__ == '__main__':
    unittest.main()
