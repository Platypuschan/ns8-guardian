"""Contract tests for .github/workflows/two-node-lab.yml and docs/two-node-lab.md (text-level, offline)."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = (ROOT / '.github/workflows/two-node-lab.yml').read_text()
DOC = (ROOT / 'docs/two-node-lab.md').read_text()
RC3 = 'sha256:de710c02de9215879b5bfa120f61e8b2901f2f7b0cfe5031cda12213da09ac71'


def run_blocks(text):
    blocks, lines, i = [], text.splitlines(), 0
    while i < len(lines):
        match = re.match(r'^(\s*)(?:- )?run: [|>][-+]?\s*$', lines[i])
        if match:
            indent = len(match.group(1))
            i += 1
            body = []
            while i < len(lines) and (not lines[i].strip() or len(lines[i]) - len(lines[i].lstrip()) > indent):
                body.append(lines[i]); i += 1
            blocks.append('\n'.join(body))
            continue
        single = re.match(r'^\s*(?:- )?run: (.+)$', lines[i])
        if single:
            blocks.append(single.group(1))
        i += 1
    return blocks


class WorkflowContract(unittest.TestCase):
    def test_no_obsolete_core_override_or_global_kernel_relaxation(self):
        self.assertNotIn('CORE_REF:', WORKFLOW)
        self.assertNotIn('core_ref:', WORKFLOW)
        self.assertNotIn('kernel.apparmor_restrict_unprivileged_userns', WORKFLOW)

    def test_manual_dispatch_only(self):
        on = WORKFLOW.split('permissions:')[0]
        self.assertIn('workflow_dispatch:', on)
        for trigger in ('pull_request', 'push:', 'schedule:', 'workflow_run', 'workflow_call', 'issue_comment'):
            self.assertNotIn(trigger, on)

    def test_contents_read_only_and_no_package_or_other_write_permission(self):
        self.assertIn('permissions:\n  contents: read\n', WORKFLOW)
        self.assertNotRegex(WORKFLOW, r'(?m)^\s*(packages|contents|actions|id-token|statuses|pull-requests|checks|deployments|issues): write')
        self.assertNotIn('secrets.', WORKFLOW)

    def test_owner_main_dispatch_guard_on_every_job(self):
        jobs_text = WORKFLOW.split('\njobs:\n')[1]
        blocks = re.split(r'(?m)^  (?=[a-z-]+:\n)', jobs_text)
        blocks = [b for b in blocks if b.strip()]
        self.assertGreaterEqual(len(blocks), 2)
        for block in blocks:
            guard = block.split('runs-on:')[0]
            self.assertIn("github.repository == 'Platypuschan/ns8-guardian'", guard, block[:30])
            self.assertIn("github.ref == 'refs/heads/main'", guard, block[:30])
            self.assertIn("github.event_name == 'workflow_dispatch'", guard, block[:30])

    def test_timeouts_and_the_lab_job_budget_are_at_most_ninety_minutes(self):
        values = [int(v) for v in re.findall(r'timeout-minutes: (\d+)', WORKFLOW)]
        self.assertTrue(values)
        self.assertLessEqual(max(values), 90)
        self.assertIn('timeout-minutes: 90', WORKFLOW)

    def test_default_module_is_the_published_rc_digest_and_inputs_are_closed_choices(self):
        self.assertIn('default: ' + RC3, WORKFLOW)
        self.assertIn('default: 4d8c243478fc9bd3c04ca813a27b6d70123b0b6d', WORKFLOW)
        self.assertIn('default: 0.2.0-rc.3', WORKFLOW)
        self.assertIn('type: choice', WORKFLOW)
        self.assertNotIn('module_repository', WORKFLOW)
        self.assertNotIn('module_tag', WORKFLOW)

    def test_inputs_reach_the_launcher_only_through_env_never_inside_run_scripts(self):
        for block in run_blocks(WORKFLOW):
            self.assertNotIn('${{', block, block)

    def test_checkout_is_pinned_to_the_dispatched_sha_without_persisted_credentials(self):
        self.assertRegex(WORKFLOW, r'actions/checkout@[0-9a-f]{40}')
        self.assertIn('ref: ${{ github.sha }}', WORKFLOW)
        self.assertIn('persist-credentials: false', WORKFLOW)

    def test_only_the_sanitized_public_directory_is_uploaded(self):
        uploads = re.findall(r'uses: actions/upload-artifact@\S+\n\s+with:\n((?:\s+.+\n)+)', WORKFLOW)
        self.assertEqual(len(uploads), 1)
        self.assertIn('path: lab-out/public/', uploads[0])
        self.assertNotIn('*', uploads[0].split('path:')[1].splitlines()[0])
        self.assertIn('if: always()', WORKFLOW)
        self.assertIn('retention-days:', uploads[0])

    def test_owned_cleanup_runs_always_and_there_is_no_debug_shell_or_failure_masking(self):
        self.assertIn('python3 -B -m twolab cleanup', WORKFLOW)
        self.assertRegex(WORKFLOW, r'- name: Release any resources left by a killed launcher\n\s+if: always\(\)')
        for banned in ('tmate', 'continue-on-error', 'ACTIONS_STEP_DEBUG', '|| true'):
            self.assertNotIn(banned, WORKFLOW)

    def test_offline_regressions_gate_the_real_lab(self):
        self.assertIn("python3 -B -m unittest discover -s qa -p 'test_two_node_lab*.py' -v", WORKFLOW)
        self.assertRegex(WORKFLOW, r'needs: offline-regressions')

    def test_no_guest_sizing_inputs_so_the_8gib_single_vm_default_cannot_be_selected(self):
        inputs = WORKFLOW.split('permissions:')[0]
        self.assertNotIn('vm_mem', inputs)
        self.assertNotIn('8192', WORKFLOW)

    def test_the_lab_step_requires_kvm_and_never_enables_software_emulation(self):
        self.assertIn('/dev/kvm', WORKFLOW)
        self.assertNotIn('tcg', WORKFLOW.lower())


class DocContract(unittest.TestCase):
    def test_doc_states_what_is_real_what_is_mock_and_the_restore_distinction(self):
        for phrase in ('mock', 'not real NS8', 'native NS8 backup', 'disk snapshot', 'not a native', 'two independent',
                       'verified HTTPS', 'private CA', 'absolute', 'no echo', 'fresh observer', 'no skipped'):
            self.assertIn(phrase.lower(), DOC.lower(), phrase)

    def test_doc_lists_every_required_case_by_id(self):
        import sys
        sys.path.insert(0, str(ROOT / 'tests' / 'lab'))
        from twolab.cases import REQUIRED_CASES, OPTIONAL_CASES
        for case in REQUIRED_CASES + OPTIONAL_CASES:
            self.assertIn('`%s`' % case, DOC, case)

    def test_doc_states_the_default_digest_and_does_not_claim_an_unrun_result(self):
        self.assertIn(RC3, DOC)
        self.assertNotRegex(DOC.lower(), r'(has passed|passed on|verified on) (github|hosted|ci)')


if __name__ == '__main__':
    unittest.main()
