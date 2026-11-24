"""The scheduled rules watch must stay read-only, publish nothing and compare against the committed lock."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = (ROOT / '.github/workflows/rules-watch.yml').read_text()


class RulesWatch(unittest.TestCase):
    def test_scheduled_weekly_and_manual_only(self):
        on = WORKFLOW.split('permissions:')[0]
        self.assertIn('schedule:', on)
        self.assertIn('workflow_dispatch:', on)
        for trigger in ('push:', 'pull_request', 'workflow_run'):
            self.assertNotIn(trigger, on)

    def test_read_only_and_no_secrets_or_publication(self):
        self.assertIn('permissions:\n  contents: read\n', WORKFLOW)
        self.assertNotRegex(WORKFLOW, r'(?m)^\s*[a-z-]+: write')
        for forbidden in ('secrets.', 'skopeo copy', 'docker push', 'buildah push', 'gh release', 'GITHUB_TOKEN'):
            self.assertNotIn(forbidden, WORKFLOW)

    def test_lock_exists_and_covers_the_http_and_ssh_rules(self):
        lock = (ROOT / 'runtime/hub-items.lock').read_text().splitlines()
        names = {l.split(',')[0] for l in lock}
        for item in ('crowdsecurity/http-probing', 'crowdsecurity/http-sensitive-files', 'crowdsecurity/http-cve-probing',
                     'crowdsecurity/ssh-bf', 'crowdsecurity/http-logs', 'crowdsecurity/sshd-logs'):
            self.assertIn(item, names)
        self.assertTrue(all(re.fullmatch(r'[^,]+,[a-z,"]+,[0-9.]*', l) or l.count(',') >= 2 for l in lock))

    def test_the_workflow_compares_and_replays(self):
        self.assertIn('runtime/hub-items.lock', WORKFLOW)
        self.assertIn('tests/test-rules.sh', WORKFLOW)
        self.assertIn('qa.test_engine_rule_update', WORKFLOW)


if __name__ == '__main__':
    unittest.main()
