// Actual view scripts with only the external NS8 task boundary replaced.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const root = path.resolve(__dirname, '..');
function view(name) {
  const source = fs.readFileSync(path.join(root, 'src/views', name + '.vue'), 'utf8');
  const script = source.match(/<script>([\s\S]*?)<\/script>/)[1]
    .replace(/import task from "..\/task";/, 'const task = {};')
    .replace('export default', 'module.exports =');
  const context = { module: { exports: {} }, window: { confirm: () => true }, Date, Set };
  vm.runInNewContext(script, context);
  return { component: context.module.exports, template: source.split('<script>')[0] };
}
function mount(name, task) {
  const { component, template } = view(name);
  const instance = { ...component.data(), task, $t: key => key, $set: (o,k,v) => o[k] = v };
  for (const [key, fn] of Object.entries(component.methods || {})) instance[key] = fn.bind(instance);
  for (const [key, fn] of Object.entries(component.computed || {})) Object.defineProperty(instance, key, { get: fn.bind(instance) });
  return { instance, component, template };
}
module.exports = { view, mount };

for (const name of ['Members', 'EventSources']) {
  test(name + ' does not retain a late secret response after navigation', async () => {
    let complete;
    const { instance: s, component } = mount(name, action => action.startsWith('add-') ? new Promise(resolve => { complete = resolve; }) : Promise.resolve({ members: [], sources: [] }));
    s.name = 'office'; s.module = 'gitea1';
    const pending = s.add();
    component.beforeDestroy.call(s);
    complete({ token: 'late-secret', hub_url: 'https://fixture', endpoint: 'http://fixture' });
    await pending;
    assert.equal(s.token, '');
  });
}

test('settings clears membership secret synchronously even when reload fails', async () => {
  let reject;
  const { instance: s } = mount('Settings', () => new Promise((resolve, fail) => { reject = fail; }));
  s.form.token = 'membership-secret';
  const pending = s.load();
  const tokenDuringReload = s.form.token;
  reject(new Error('reload failed'));
  await pending;
  assert.equal(tokenDuringReload, '');
  assert.equal(s.form.token, '');
  assert.equal(s.error, 'reload failed');
});

test('settings clears membership secret on destruction', () => {
  const { instance: s, component } = mount('Settings', async () => ({}));
  s.form.token = 'membership-secret';
  assert.equal(typeof component.beforeDestroy, 'function');
  component.beforeDestroy.call(s);
  assert.equal(s.form.token, '');
});

test('settings never copies a late configuration token into the form after navigation', async () => {
  let complete;
  const { instance: s, component } = mount('Settings', () => new Promise(resolve => { complete = resolve; }));
  const pending = s.load();
  s.form.token = 'membership-secret';
  component.beforeDestroy.call(s);
  const assignments = [];
  let token = s.form.token;
  Object.defineProperty(s.form, 'token', {
    enumerable: true,
    get: () => token,
    set: value => { assignments.push(value); token = value; },
  });
  complete({ role: 'member', token: 'unexpected-response-secret', allowlist: [] });
  await pending;
  assert.equal(s.form.token, '');
  assert.equal(assignments.includes('unexpected-response-secret'), false);
});

test('settings keeps configured roles fixed and omits empty membership token on update', async () => {
  const calls = [];
  const { instance: s, template } = mount('Settings', async (action, data) => {
    calls.push({ action, data });
    return { role: 'hub', hub_host: 'hub.example', lets_encrypt: true, allowlist: [] };
  });
  await s.load();
  assert.equal(s.configured, true);
  assert.match(template, /:disabled="configured \|\| busy"/);
  await s.save();
  const data = calls.find(c => c.action === 'configure-module').data;
  assert.equal(data.hub_host, 'hub.example');
  assert.equal(data.lets_encrypt, true);
  assert.equal(Object.hasOwn(data, 'token'), false);
  s.form.role = 'member';
  await s.save();
  assert.equal(Object.hasOwn(calls.filter(c => c.action === 'configure-module').at(-1).data, 'token'), false);
});

test('all view buttons are explicitly non-submit and locale keys are complete', () => {
  const messages = ['en', 'de'].map(locale => JSON.parse(fs.readFileSync(path.join(root, 'public/i18n', locale, 'translation.json'))));
  const keys = object => Object.entries(object).flatMap(([key,value]) => typeof value === 'object' ? keys(value).map(child => key + '.' + child) : [key]);
  assert.deepEqual(keys(messages[0]).sort(), keys(messages[1]).sort());
  for (const name of ['Settings', 'Status', 'Members', 'Bans', 'EventSources']) {
    const { template } = view(name);
    for (const match of template.matchAll(/<cv-button\b[^>]*>/g)) assert.match(match[0], /type="button"/);
    for (const match of template.matchAll(/\$t\(['"]([\w.]+)['"]\)/g)) {
      for (const locale of messages) assert.notEqual(match[1].split('.').reduce((value,key) => value?.[key], locale), undefined, match[1]);
    }
  }
});

test('event sources are reachable through router and the shared desktop/mobile menu', () => {
  const router = fs.readFileSync(path.join(root, 'src/router/index.js'), 'utf8');
  const menu = fs.readFileSync(path.join(root, 'src/components/AppSideMenuContent.vue'), 'utf8');
  assert.match(router, /path: "\/event-sources"/);
  assert.match(router, /component: EventSources/);
  assert.match(menu, /goToAppPage\(instanceName, 'event-sources'\)/);
  for (const locale of ['en', 'de']) {
    const messages = JSON.parse(fs.readFileSync(path.join(root, 'public/i18n', locale, 'translation.json')));
    assert.ok(messages.eventSources.title);
    assert.ok(messages.c.hookGuide);
    assert.ok(messages.c.adapterGuide);
  }
});

test('event sources distinguish pending, active and unknown registration state from event type', async () => {
  const sources = [{ name: 'pending', active: 0 }, { name: 'active', active: 1 }, { name: 'unknown' }];
  const { instance: s, template } = mount('EventSources', async () => ({ sources }));
  await s.load();
  assert.equal(s.sourceState(s.sources[0]), 'c.sourcePending');
  assert.equal(s.sourceState(s.sources[1]), 'c.sourceActive');
  for (const active of [undefined, null, false, true, '1', '0', 2]) {
    assert.equal(s.sourceState({ active }), 'c.unknown');
  }
  assert.match(template, /c.sourceStatus/);
  assert.match(template, /sourceState\(source\)/);
  assert.match(template, /c.authEvents/);
});

test('pending source recovery is localized, conditional and uses remove then recreate without exposing list secrets', async () => {
  const { instance: s, template } = mount('EventSources', async () => ({ sources: [{ name: 'interrupted', module: 'gitea1', active: 0, token: 'never-render-list-secret' }] }));
  await s.load();
  assert.match(template, /v-if="source.active === 0"[\s\S]*?c.sourcePendingRecovery/);
  assert.doesNotMatch(template, /source\.token|v-html/);
  for (const locale of ['en', 'de']) {
    const messages = JSON.parse(fs.readFileSync(path.join(root, 'public/i18n', locale, 'translation.json')));
    const guidance = messages.c.sourcePendingRecovery;
    assert.equal(typeof guidance, 'string');
    assert.ok(guidance.length < 400);
    assert.match(guidance, locale === 'en' ? /[Rr]emove.*recreate/ : /[Ee]ntfernen.*neu/);
    assert.match(messages.c.fallbackGuide, locale === 'en' ? /active registration/ : /aktive Registrierung/);
  }
});

test('event source provisioning uses module identity and a separate ephemeral bearer token', async () => {
  assert.ok(fs.existsSync(path.join(root, 'src/views/EventSources.vue')), 'event source provisioning view is missing');
  const calls = [];
  let sources = [];
  const { instance: s, component, template } = mount('EventSources', async (action, data) => {
    calls.push({ action, data });
    if (action === 'add-event-source') {
      sources = [{ name: data.name, module: data.module }];
      return { name: data.name, token: '<img src=x onerror=alert(1)>', endpoint: 'http://127.0.0.1/events' };
    }
    if (action === 'remove-event-source') sources = [];
    return { sources };
  });
  s.name = ' gitea-auth ';
  s.module = ' gitea1 ';
  await s.add();
  assert.equal(calls[0].action, 'add-event-source');
  assert.equal(calls[0].data.name, 'gitea-auth');
  assert.equal(calls[0].data.module, 'gitea1');
  assert.equal(s.sources.length, 1);
  assert.equal(s.token, '<img src=x onerror=alert(1)>');
  assert.match(template, /{{ token }}/);
  assert.doesNotMatch(template, /v-html/);
  await s.load();
  assert.equal(s.token, '');
  s.token = 'secret';
  await s.remove('gitea-auth');
  assert.equal(s.token, '');
  assert.equal(s.sources.length, 0);
  s.token = 'secret';
  component.beforeDestroy.call(s);
  assert.equal(s.token, '');
});

test('status separates local LAPI from central sync and never infers readiness from absent fields', async () => {
  const { instance: s, template } = mount('Status', async () => ({ role: 'member', lapi: 'ok' }));
  await s.refresh();
  assert.equal(s.syncState, 'c.unknown');
  assert.equal(s.display(undefined), 'c.unknown');
  assert.equal(s.display(false), 'false');
  assert.match(template, /c.activeBans/);
  assert.match(template, /c.eventIngress/);
  assert.match(template, /sync.last_success/);
  s.status.sync = { pending: 2, last_success: 'raw-last-success' };
  assert.equal(s.syncState, 'c.pending');
  s.status.sync = { pending: 0 };
  assert.equal(s.syncState, 'c.unknown');
  s.status.sync = { pending: 0, last_success: 'raw-last-success' };
  assert.equal(s.syncState, 'c.syncIdle');
  assert.equal(s.moment(1795210996.38), new Date(1795210996380).toLocaleString());
  assert.equal(s.moment(undefined), 'c.unknown');
  s.status.sync.error = 'certificate verification failed';
  assert.equal(s.syncState, 'certificate verification failed');
});

test('status highlights stale synchronization before idle or pending and exposes age', () => {
  const { instance: s, template } = mount('Status', async () => ({}));
  s.status = { sync: { pending: 0, last_success: 1, stale: true, age_seconds: 3600 } };
  assert.equal(s.syncState, 'c.syncStale');
  assert.match(template, /sync.age_seconds/);
  s.status.sync.pending = 4;
  assert.equal(s.syncState, 'c.syncStale');
  s.status.sync = { pending: 0, last_success: 1, stale: false, age_seconds: 61 };
  assert.equal(s.syncState, 'c.syncStale');
  s.status.sync.age_seconds = 5;
  assert.equal(s.syncState, 'c.syncIdle');
  s.status.sync.error = 'local sync error';
  assert.equal(s.syncState, 'local sync error');
});

test('sync capacity signals override stale, pending and idle with bounded localized guidance', () => {
  const { instance: s } = mount('Status', async () => ({}));
  const signals = [{ import_overload: true }, { local_export_overload: true }, { quota_pending: 1 }, { quota_pending: 25 }];
  for (const signal of signals) {
    for (const base of [{}, { pending: 0, last_success: 1 }, { pending: 7, last_success: 1, stale: true, age_seconds: 3600 }]) {
      s.status = { sync: { ...base, ...signal } };
      assert.equal(s.syncState, 'c.syncOverload', JSON.stringify(s.status));
    }
  }
  s.status.sync.error = 'existing sync error';
  assert.equal(s.syncState, 'existing sync error');
  for (const signal of [{}, { import_overload: false, local_export_overload: false, quota_pending: 0 }, { import_overload: 'false', local_export_overload: 'false', quota_pending: -1 }]) {
    s.status = { sync: { pending: 0, last_success: 1, ...signal } };
    assert.equal(s.syncState, 'c.syncIdle');
  }
  for (const locale of ['en', 'de']) {
    const messages = JSON.parse(fs.readFileSync(path.join(root, 'public/i18n', locale, 'translation.json')));
    assert.equal(typeof messages.c.syncOverload, 'string');
    assert.ok(messages.c.syncOverload.length < 400);
  }
});

test('event integration guide does not claim unavailable generic HTTP protection', () => {
  for (const locale of ['en', 'de']) {
    const messages = JSON.parse(fs.readFileSync(path.join(root, 'public/i18n', locale, 'translation.json')));
    assert.doesNotMatch(messages.c.fallbackGuide, /protection remains active|HTTP-Schutz bleibt aktiv/);
  }
});

test('opaque member token is not decoded; refresh, remove and destruction clear it', async () => {
  const { instance: m, component, template } = mount('Members', async action => {
    if (action === 'get-configuration') return { role: 'hub' };
    if (action === 'add-member') return { name: 'office', token: 'csc2.opaque', hub_url: 'https://hub.example' };
    return { members: [{ name: 'office' }] };
  });
  m.name = 'office';
  await m.add();
  assert.equal(m.token, 'csc2.opaque');
  assert.equal(m.hubUrl, 'https://hub.example');
  assert.doesNotMatch(template, /manualSetup|manual\s*}}/);
  assert.match(template, /{{ token }}/);
  assert.equal(Object.hasOwn(component.computed || {}, 'manual'), false);
  await m.load();
  assert.equal(m.token, '');
  m.token = 'secret';
  await m.remove('office');
  assert.equal(m.token, '');
  m.token = 'secret';
  component.beforeDestroy.call(m);
  assert.equal(m.token, '');
  assert.doesNotMatch(template, /bouncer_last_pull|c.lastPull/);
  assert.equal(m.when('not-a-date'), 'not-a-date');
  // The Python backend reports Unix seconds; reading them as milliseconds would show 1970.
  assert.equal(m.when(1795210996.38), new Date(1795210996380).toLocaleString());
  assert.ok(!m.when(1795210996.38).includes('1970'));
});

test('member can list local decisions and unban locally without a hub-role gate', async () => {
  const calls = [];
  let decisions = [{ id: 1, ip: '192.0.2.2', scenario: 'auth', origin: 'local' }];
  const { instance: b } = mount('Bans', async (action, data) => {
    calls.push({ action, data });
    if (action === 'get-configuration') return { role: 'member' };
    if (action === 'unban') { decisions = []; return {}; }
    return { decisions };
  });
  await b.load();
  assert.equal(b.decisions.length, 1);
  b.toggle('192.0.2.2', true);
  await b.unban();
  assert.deepEqual(Array.from(calls.find(c => c.action === 'unban').data.addresses), ['192.0.2.2']);
  assert.equal(b.decisions.length, 0);
});

test('member configuration preserves local allowlist and never submits a TLS bypass', async () => {
  const calls = [];
  const { instance: s, template } = mount('Settings', async (action, data) => {
    calls.push({ action, data });
    return { role: 'member', allowlist: ['192.0.2.1'], ban_duration: '4h', samba_audit: true };
  });
  await s.load();
  s.form.token = ' csc2.opaque-not-base64 ';
  s.allowlist = '192.0.2.1, 2001:db8::/48';
  await s.save();
  const data = calls.find(c => c.action === 'configure-module').data;
  assert.equal(Object.hasOwn(data, 'insecure_skip_verify'), false);
  assert.equal(data.token, 'csc2.opaque-not-base64');
  assert.deepEqual(Array.from(data.allowlist), ['192.0.2.1', '2001:db8::/48']);
  assert.doesNotMatch(template, /:disabled="form.role !== 'hub'"/);
});

test('status view reports unacknowledged and replayed events and flags a stuck backlog', () => {
  const { instance: s, template } = mount('Status', async () => ({}));
  assert(template.includes('c.unackedEvents') && template.includes('c.replayedEvents'), 'template renders both counters');
  s.status = { sync: { event_unacked: 3, event_replayed_total: 12, event_pending: 0 } };
  assert.equal(s.display(s.status.sync.event_unacked), '3');
  assert.equal(s.display(s.status.sync.event_replayed_total), '12');
  assert.equal(s.ackState, 'c.ackWaiting');
  s.status = { sync: { event_unacked: 0, event_replayed_total: 0, event_pending: 0 } };
  assert.equal(s.ackState, 'c.ackIdle');
  s.status = { sync: {} };                      // older module without the counters: not reported, never "0"
  assert.equal(s.ackState, 'c.unknown');
  assert.equal(s.display(s.status.sync.event_unacked), 'c.unknown');
});

// The module UI is rendered inside the NS8 admin shell, whose global stylesheet (ns8-core core/ui/src/styles) is NOT loaded by the
// local fixture. A class that the core styles globally changes this UI in production only: `.hint` there is a zero-size
// tooltip anchor (width:0; height:0), which squeezed every helper paragraph into a one-word column that overlaid the page and
// the side menu. Class names must therefore not collide with the core's, except the shell classes that are meant to match.
test('no class name collides with the NS8 core global stylesheet', () => {
  const core = new Set(fs.readFileSync(path.join(__dirname, 'ns8-core-classes.txt'), 'utf8').split(/\s+/).filter(Boolean));
  const intended = new Set(['app-content', 'app-side-menu-content', 'app-side-nav', 'instance-name', 'current-page']);   // the NS8 app shell, copied on purpose
  const found = new Map();
  const walk = dir => fs.readdirSync(dir, { withFileTypes: true }).forEach(e => {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) return walk(full);
    if (!e.name.endsWith('.vue')) return;
    const text = fs.readFileSync(full, 'utf8');
    const names = new Set();
    for (const m of text.matchAll(/\sclass="([^"]+)"/g)) m[1].split(/\s+/).forEach(c => names.add(c));
    for (const m of text.matchAll(/:class="[^"]*"/g)) for (const q of m[0].matchAll(/'([a-zA-Z0-9_-]+)'/g)) names.add(q[1]);
    for (const c of names) if (core.has(c) && !intended.has(c)) found.set(c, (found.get(c) || []).concat(path.relative(root, full)));
  });
  walk(path.join(root, 'src'));
  assert.deepEqual([...found.entries()], [], 'class names that the NS8 core styles globally: ' + JSON.stringify([...found.entries()]));
});
