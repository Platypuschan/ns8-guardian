"""Opt-in CrowdSec community blocklist (Central API): off by default, no network for registration unless enabled,
decisions are never replicated between Guardian nodes, disabling removes them again."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from cscompanion import actions, common, lifecycle, render

CREDS = 'crowdsec_config/online_api_credentials.yaml'


def cfg(**kw):
    return {**common.DEFAULTS, 'role': 'hub', 'hub_host': 'g.example.org', **kw}


class Rendering(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state = Path(self.tmp.name)
        self.root = tempfile.TemporaryDirectory()
        env = mock.patch.dict(os.environ, {'TCP_PORTS': '20001,20002', 'MODULE_ID': 'guardian1', 'AGENT_STATE_DIR': str(self.state)})
        env.start(); self.addCleanup(env.stop)
        self.addCleanup(self.tmp.cleanup); self.addCleanup(self.root.cleanup)
        common.secret('bouncer_key')
        (self.state / 'crowdsec_config').mkdir(exist_ok=True)

    def online(self, c, **kw):
        # What the engine will be given at its next start: the fragment offline-start.sh merges after a reachability probe.
        found = render.render_all(c, 'guardian1', self.state, root=self.root.name)
        fragment = self.state / 'crowdsec_config/community.yaml'
        self.assertNotIn('online_client', json.loads(render.config_local(c, state=self.state))['api']['server'],
                         'config.yaml.local must never carry the client: crowdsec exits at start when the API is unreachable')
        if kw.get('registering'):
            return json.loads(render.config_local(c, state=self.state, registering=True))['api']['server']['online_client']
        return json.loads(fragment.read_text()) if fragment.exists() else None

    def test_default_is_off_and_offline(self):
        self.assertFalse(common.DEFAULTS['community_blocklist'])
        self.assertFalse(common.DEFAULTS['community_sharing'])
        self.assertIsNone(self.online(cfg()))

    def test_enabled_without_credentials_stays_offline_until_registered(self):
        self.assertIsNone(self.online(cfg(community_blocklist=True)))

    def test_enabled_with_credentials_pulls_the_community_list_only(self):
        (self.state / CREDS).write_text('url: x\n')
        online = self.online(cfg(community_blocklist=True))
        self.assertEqual(online['credentials_path'], '/etc/crowdsec/online_api_credentials.yaml')
        self.assertEqual(online['pull'], {'community': True, 'blocklists': False})
        self.assertFalse(online['sharing'], 'signals are never shared unless asked')

    def test_sharing_is_a_separate_explicit_choice(self):
        (self.state / CREDS).write_text('url: x\n')
        self.assertTrue(self.online(cfg(community_blocklist=True, community_sharing=True))['sharing'])

    def test_disabling_removes_the_fragment_and_asks_for_a_restart(self):
        (self.state / CREDS).write_text('url: x\n')
        self.online(cfg(community_blocklist=True))
        found = render.render_all(cfg(community_blocklist=False), 'guardian1', self.state, root=self.root.name)
        self.assertFalse((self.state / 'crowdsec_config/community.yaml').exists())
        self.assertTrue(found['restart'])

    def test_disabled_never_renders_online_client_even_with_old_credentials(self):
        (self.state / CREDS).write_text('url: x\n')
        self.assertIsNone(self.online(cfg(community_blocklist=False, community_sharing=True)))

    def test_registration_phase_renders_the_client_so_cscli_can_register(self):
        online = self.online(cfg(community_blocklist=True), registering=True)
        self.assertEqual(online['credentials_path'], '/etc/crowdsec/online_api_credentials.yaml')

    def test_engine_env_keeps_the_upstream_online_api_disabled(self):
        # Registration is done by the module (fail-soft); the upstream entry point must never register or abort the start.
        env = render.crowdsec_env(cfg(community_blocklist=True), 'guardian1')
        self.assertIn('DISABLE_ONLINE_API=true', env)


class Configuration(unittest.TestCase):
    def test_validate_schema_and_defaults_accept_both_flags(self):
        schema = json.loads((Path(__file__).resolve().parents[1] / 'imageroot/actions/configure-module/validate-input.json').read_text())
        for key in ('community_blocklist', 'community_sharing'):
            self.assertEqual(schema['properties'][key]['type'], 'boolean')

    def test_get_configuration_reports_the_flags(self):
        import io, contextlib
        with mock.patch.object(actions, 'load_config', return_value=cfg(community_blocklist=True)), \
                mock.patch.object(actions, 'read_secret', return_value=''), contextlib.redirect_stdout(io.StringIO()) as out:
            actions.get_configuration({})
        data = json.loads(out.getvalue())
        self.assertTrue(data['community_blocklist'])
        self.assertFalse(data['community_sharing'])


class Lifecycle(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state = Path(self.tmp.name)
        (self.state / 'crowdsec_config').mkdir()
        self.creds = self.state / CREDS
        self.calls = []
        env = mock.patch.dict(os.environ, {'MODULE_ID': 'guardian1'})
        env.start(); self.addCleanup(env.stop)
        cl = mock.patch.object(lifecycle.render, 'config_local', return_value='{}')
        cl.start(); self.addCleanup(cl.stop)
        sd = mock.patch.object(lifecycle, 'state_dir', return_value=self.state)
        sd.start(); self.addCleanup(sd.stop)
        self.addCleanup(self.tmp.cleanup)

    def fake_cscli(self, ok=True):
        def run(*args, check=True, timeout=60):
            self.calls.append(args)
            if args[:2] == ('capi', 'register') and ok:
                self.creds.write_text('login: a\npassword: b\nurl: https://api.crowdsec.net/\n')
            return mock.Mock(returncode=0 if ok else 1, stdout='', stderr='' if ok else 'network unreachable')
        return mock.patch.object(lifecycle, 'cscli', side_effect=run)

    def test_registers_once_when_enabled_and_reports_a_restart_need(self):
        with self.fake_cscli(), mock.patch.object(lifecycle.render, 'render_all') as render_all:
            self.assertTrue(lifecycle.ensure_community(cfg(community_blocklist=True)))
        self.assertTrue(any(c[:2] == ('capi', 'register') for c in self.calls))
        self.assertEqual(oct(self.creds.stat().st_mode & 0o777), '0o600')
        self.assertTrue(render_all.called, 'the rendering with credentials must be written after registering')

    def test_existing_credentials_are_reused_without_contacting_the_central_api(self):
        self.creds.write_text('login: a\n')
        with self.fake_cscli():
            self.assertFalse(lifecycle.ensure_community(cfg(community_blocklist=True)))
        self.assertEqual(self.calls, [])

    def test_failed_registration_is_recorded_and_does_not_break_the_module(self):
        with self.fake_cscli(ok=False), mock.patch.object(lifecycle.render, 'render_all'):
            self.assertFalse(lifecycle.ensure_community(cfg(community_blocklist=True)))
        self.assertFalse(self.creds.exists())
        state = json.loads((self.state / 'community.json').read_text())
        self.assertIn('network unreachable', state['error'])

    def test_failed_registration_is_not_retried_every_refresh(self):
        with self.fake_cscli(ok=False), mock.patch.object(lifecycle.render, 'render_all'):
            lifecycle.ensure_community(cfg(community_blocklist=True))
            self.calls.clear()
            lifecycle.ensure_community(cfg(community_blocklist=True))
        self.assertEqual(self.calls, [], 'CAPI rate-limits aggressive re-registration')

    def test_disabling_removes_the_imported_community_decisions_and_keeps_local_ones(self):
        self.creds.write_text('login: a\n')
        with self.fake_cscli():
            self.assertTrue(lifecycle.ensure_community(cfg(community_blocklist=False)))
        deletes = [c for c in self.calls if c[:2] == ('decisions', 'delete')]
        self.assertEqual({c[c.index('--origin') + 1] for c in deletes}, {'CAPI', 'lists'})
        self.assertFalse(any('--all' in c or '--ip' in c for c in deletes))
        self.assertFalse(self.creds.exists(), 'a later opt-in must register afresh to get the full list again')
        with self.fake_cscli():
            self.assertFalse(lifecycle.ensure_community(cfg(community_blocklist=False)))
        self.assertEqual(self.calls[len(deletes):], [], 'purge happens once')

    def test_never_enabled_never_touches_cscli(self):
        with self.fake_cscli():
            self.assertFalse(lifecycle.ensure_community(cfg()))
        self.assertEqual(self.calls, [])


class NoReplication(unittest.TestCase):
    def test_hub_sync_reads_local_decisions_only(self):
        text = (Path(__file__).resolve().parents[1] / 'imageroot/pypkg/cscompanion/sync.py').read_text()
        self.assertIn("'alerts','list','--limit','0'", text)
        self.assertNotIn("'--all'", text)
        self.assertNotIn("'-a'", text)


if __name__ == '__main__':
    unittest.main()
