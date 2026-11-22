// Run in browser: (await import('/qa/browser-checks.js')).runChecks()
// Tests real view rendering/events with the labelled fixture task boundary.
export async function runChecks() {
  const results = [];
  const assert = (ok, message) => { if (!ok) throw new Error(message); results.push(message); };
  const settle = async () => { await Promise.resolve(); await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))); };
  const navigate = async path => { if (window.__fixtureRouter.currentRoute.path !== path) await window.__fixtureRouter.push(path); await settle(); };
  const button = text => [...document.querySelectorAll('button')].find(el => el.textContent.trim().startsWith(text));
  const input = label => [...document.querySelectorAll('label')].find(el => el.textContent.trim() === label)?.control;
  const setInput = async (label, value) => { const el = input(label); if (!el) throw new Error('Missing input: ' + label); el.value = value; el.dispatchEvent(new Event('input', { bubbles: true })); await settle(); };
  const click = async text => { const el = button(text); if (!el || el.disabled) throw new Error('Missing/disabled button: ' + text); el.click(); await settle(); };
  const text = () => document.body.innerText;
  const fixture = window.__fixture;
  window.confirm = () => true;
  fixture.role = 'member';
  await navigate('/status');
  await navigate('/settings');
  assert(input('Local allowlist') && !input('Local allowlist').disabled, 'Member local allowlist editable');
  assert(!text().includes('untrusted'), 'No insecure certificate checkbox');
  await setInput('Local allowlist', '192.0.2.1\n2001:db8::/48');
  await click('Save');
  const saved = fixture.calls.filter(c => c.action === 'configure-module').at(-1).data;
  assert(saved.allowlist.length === 2 && !('insecure_skip_verify' in saved), 'Member save sends local allowlist without TLS bypass');
  await navigate('/bans');
  assert(text().includes('192.0.2.4'), 'Member displays local decisions');
  document.querySelector('input[aria-label="192.0.2.4"]').click();
  await settle();
  await click('Unban selected');
  assert(!text().includes('192.0.2.4'), 'Member unban updates local list');
  await navigate('/status');
  assert(text().includes('Local CrowdSec API (LAPI)') && text().includes('Unknown / not reported'), 'Local LAPI ready does not imply central or ingress readiness');
  fixture.status.sync = { pending: 3, last_success: 'raw-sync-time', error: '' };
  fixture.status.event_ingress = { endpoint: 'http://fixture/events', pending: 2 };
  await click('Refresh');
  assert(text().includes('Pending') && text().includes('raw-sync-time'), 'Reported sync queue and raw timestamp rendered');
  fixture.status.sync = { pending: 0, last_success: 'raw-sync-time', error: '', stale: true, age_seconds: 3600 };
  await click('Refresh');
  assert(text().includes('Synchronization status is stale') && text().includes('3600'), 'Stale synchronization is explicit even with an empty queue');
  fixture.status.sync = { pending: 3, last_success: 'raw-sync-time', error: '', stale: false, age_seconds: 1 };
  fixture.fail = 'get-companion-status';
  await click('Refresh');
  assert(text().includes('Fixture task failure'), 'Task failure visible');
  fixture.fail = '';
  await click('Refresh');
  assert(!text().includes('Fixture task failure'), 'Refresh recovers from task failure');
  fixture.role = 'hub';
  await navigate('/members');
  await setInput('Name', 'office');
  await click('Create token');
  assert(document.querySelector('.token .secret').textContent === 'csc2.fixture-opaque-not-base64', 'Opaque membership token displayed without decoding');
  assert(!text().includes('local_api_credentials') && !text().includes('api_key:'), 'No remote LAPI credential instructions');
  await navigate('/status');
  await navigate('/members');
  assert(!document.querySelector('.token .secret'), 'Membership secret cleared on navigation');
  await navigate('/event-sources');
  await setInput('Name', 'gitea-auth');
  await setInput('Module instance', 'gitea1');
  const before = fixture.calls.length;
  await click('Create token');
  assert(document.querySelector('.secret').textContent === "<img src=x onerror=alert('fixture')>" && !document.querySelector('.secret img'), 'Source token rendered as escaped plain text');
  assert(fixture.calls.slice(before).some(c => c.action === 'add-event-source' && c.data.module === 'gitea1'), 'Event source uses explicit module identity');
  assert(fixture.calls.filter(c => c.action === 'configure-module').length === 1, 'Provision controls do not submit settings');
  await click('Refresh');
  assert(!document.querySelector('.secret'), 'Source token cleared by refresh');
  await click('Remove');
  assert(!text().includes('gitea-auth'), 'Source removal refreshes registry');
  for (const locale of ['en', 'de']) {
    window.__fixtureI18n.locale = locale;
    const messages = window.__fixtureI18n.getLocaleMessage(locale).c;
    await navigate('/status');
    for (const signal of [{ import_overload: true }, { local_export_overload: true }, { quota_pending: 2 }]) {
      fixture.status.sync = { pending: 0, last_success: 1, stale: true, age_seconds: 3600, ...signal, token: 'never-render-status-secret' };
      await click(messages.refresh);
      assert(text().includes(messages.syncOverload) && !text().includes(messages.syncIdle) && !text().includes(messages.syncStale), locale + ' overload takes precedence: ' + Object.keys(signal)[0]);
      assert(!text().includes('never-render-status-secret'), locale + ' sync metadata is not dumped: ' + Object.keys(signal)[0]);
    }
    fixture.sources = [
      { name: 'interrupted', module: 'gitea1', active: 0, token: 'never-render-list-secret' },
      { name: 'running', module: 'gitea2', active: 1 },
      { name: 'unreported', module: 'gitea3' },
    ];
    await navigate('/event-sources');
    const rows = [...document.querySelectorAll('tbody tr')];
    assert(rows.length === 3, locale + ' pending registrations remain visible');
    for (const [index, state] of [messages.sourcePending, messages.sourceActive, messages.unknown].entries()) {
      const cells = rows[index].querySelectorAll('td');
      assert(cells[2].textContent.trim() === messages.authEvents && cells[3].textContent.includes(state), locale + ' type and registration status separate: ' + index);
      assert(cells[3].textContent.includes(messages.sourcePendingRecovery) === (index === 0), locale + ' recovery only for pending: ' + index);
    }
    assert(!text().includes('never-render-list-secret') && !document.querySelector('.secret'), locale + ' registry never exposes token fields');
    rows[0].querySelector('button').click();
    await settle();
    assert(![...document.querySelectorAll('tbody tr')].some(row => row.textContent.includes('interrupted')), locale + ' pending registration can be removed');
    await setInput(messages.name, 'interrupted');
    await setInput(messages.moduleIdentity, 'gitea1');
    await click(messages.createToken);
    const recreated = [...document.querySelectorAll('tbody tr')].find(row => row.textContent.includes('interrupted'));
    assert(recreated?.textContent.includes(messages.sourceActive) && !recreated.textContent.includes(messages.sourcePendingRecovery) && document.querySelector('.secret'), locale + ' pending registration recreated with one-time token');
    await click(messages.refresh);
    assert(!document.querySelector('.secret'), locale + ' recovered source token cleared on refresh');
  }
  window.__fixtureI18n.locale = 'de';
  await settle();
  assert(text().includes('Ereignisquellen') && text().includes('Adapter für strukturierte Logs'), 'German source guide rendered');
  assert([...document.querySelectorAll('button')].every(el => el.type === 'button'), 'Every rendered non-submit button has button type');
  assert(window.__fixtureErrors.length === 0, 'No Vue runtime errors');
  return results;
}
