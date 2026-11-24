// The NS8 shell only changes the URL of the parent window (#/apps/<id>?page=<page>); the app iframe has to notice that
// itself. The views never registered for it, so menu entries changed the address bar but not the page (reported on node2).
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const root = path.resolve(__dirname, '..');
const load = () => import(pathToFileURL(path.join(root, 'src/pageSync.mjs')).href);

test('pageFromUrl reads the page from the parent hash and ignores everything else', async () => {
  const { pageFromUrl } = await load();
  assert.equal(pageFromUrl('https://node2.own-hub.de/cluster-admin/#/apps/guardian1?page=members'), 'members');
  assert.equal(pageFromUrl('https://h/cluster-admin/#/apps/guardian1?page=event-sources&x=1'), 'event-sources');
  assert.equal(pageFromUrl('https://h/cluster-admin/#/apps/guardian1'), '');
  assert.equal(pageFromUrl('https://h/cluster-admin/?page=evil#/apps/guardian1'), '');
  assert.equal(pageFromUrl('https://h/#/apps/guardian1?page=%3Cscript%3E'), '<script>');
});

test('a URL change is reported once, an unchanged URL never, and stop() ends it', async () => {
  const { startPageSync } = await load();
  const win = { location: { href: 'https://h/#/apps/guardian1?page=settings' } };
  const seen = [];
  let tick;
  const timers = { setInterval: fn => { tick = fn; return 7; }, clearInterval: id => seen.push('cleared ' + id) };
  const stop = startPageSync(win, page => seen.push(page), 500, timers);
  tick(); assert.deepEqual(seen, []);
  win.location.href = 'https://h/#/apps/guardian1?page=members';
  tick(); tick(); assert.deepEqual(seen, ['members']);
  win.location.href = 'https://h/#/apps/guardian1?page=settings';
  tick(); assert.deepEqual(seen, ['members', 'settings']);
  stop(); assert.deepEqual(seen, ['members', 'settings', 'cleared 7']);
});

test('the default timers work in a browser, where setInterval must be called on window (found on node2: "Illegal invocation")', async () => {
  const real = { setInterval: globalThis.setInterval, clearInterval: globalThis.clearInterval };
  const strict = name => function (...args) {
    if (this !== globalThis && this !== undefined) throw new TypeError('Illegal invocation');
    return real[name].apply(globalThis, args);
  };
  globalThis.setInterval = strict('setInterval');
  globalThis.clearInterval = strict('clearInterval');
  try {
    const { startPageSync } = await import(pathToFileURL(path.join(root, 'src/pageSync.mjs')).href + '?strict=' + Date.now());
    const stop = startPageSync({ location: { href: 'https://h/#/apps/guardian1?page=settings' } }, () => {}, 10000);
    stop();
  } finally {
    Object.assign(globalThis, real);
  }
});

test('a menu click switches the page at once and a router move to a page that is already shown does nothing', async () => {
  const { navigateToPage } = await load();
  const calls = [];
  const pages = { members: 'Members', settings: 'Settings' };
  const router = {
    resolve: p => ({ route: { matched: pages[p.slice(1)] ? [1] : [], name: pages[p.slice(1)] }, location: p }),
    replace: l => { calls.push(l); return Promise.reject(new Error('NavigationDuplicated')); },
  };
  const current = { name: 'Settings' };
  assert.equal(navigateToPage(router, current, 'members'), true);   // rejected promise must not leak as an unhandled rejection
  assert.deepEqual(calls, ['/members']);
  assert.equal(navigateToPage(router, current, 'settings'), false); // already shown
  assert.equal(navigateToPage(router, current, 'nonsense'), false); // unknown page: ignored
  assert.equal(navigateToPage(router, current, ''), false);         // empty page = settings = shown
  assert.deepEqual(calls, ['/members']);
});

test('history moves are noticed at once, not only by the poll, and stop() removes every listener', async () => {
  const { startPageSync } = await load();
  const listeners = {};
  const win = {
    location: { href: 'https://h/#/apps/guardian1?page=settings' },
    addEventListener: (e, f) => { listeners[e] = f; },
    removeEventListener: (e, f) => { if (listeners[e] === f) delete listeners[e]; },
  };
  const seen = [];
  const stop = startPageSync(win, page => seen.push(page), 500, { setInterval: () => 1, clearInterval: () => {} });
  assert(listeners.popstate && listeners.hashchange, 'back/forward and manual hash edits are listened for');
  win.location.href = 'https://h/#/apps/guardian1?page=bans';
  listeners.popstate();
  assert.deepEqual(seen, ['bans']);
  stop();
  assert.deepEqual(Object.keys(listeners), []);
});

test('App.vue starts the sync, switches the route for known pages only, and stops it on destroy', () => {
  const app = fs.readFileSync(path.join(root, 'src/App.vue'), 'utf8');
  assert(app.includes('startPageSync('), 'App.vue must watch the parent URL');
  assert(app.includes('appNavigation'), 'the side menu is told about the page change');
  assert(app.includes('beforeDestroy'), 'the watcher is stopped');
  const menu = fs.readFileSync(path.join(root, 'src/components/AppSideMenuContent.vue'), 'utf8');
  assert(!/@click="goToAppPage\(/.test(menu), 'menu entries must switch the page themselves, not only change the parent URL');
  assert(menu.includes('navigateToPage('), 'the menu click uses the shared page switch');
  assert(!menu.includes('getPage()'), 'the menu must use the same default page as the router (settings), not the library default (status)');
});
