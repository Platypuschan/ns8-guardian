// Isolated fixture: actual Vue views/Carbon/router, explicitly fake task API.
// Not a live NS8 host, application hook, event ingress or backend integration.
import Vue from "vue";
import VueI18n from "vue-i18n";
import Carbon from "@carbon/vue";
import "carbon-components/css/carbon-components.min.css";
import router from "../src/router";
const [en, de] = await Promise.all(['en', 'de'].map(locale => fetch('/i18n/' + locale + '/translation.json').then(response => response.json())));
Vue.use(VueI18n);
Vue.use(Carbon);
const fixture = (window.__fixture = {
  role: "member", calls: [], fail: "", status: { role: "member", lapi: "ok", active_bans: 1 },
  decisions: [{ id: 1, ip: "192.0.2.4", scope: "Ip", scenario: "fixture/auth", origin: "local", duration: "4h" }],
  members: [], sources: [],
});
async function task(action, data = {}) {
  fixture.calls.push({ action, data });
  if (fixture.fail === action) throw new Error("Fixture task failure");
  switch (action) {
    case "get-configuration": return { role: fixture.role, allowlist: ["192.0.2.1"], ban_duration: "4h", samba_audit: true, hub_host: "hub.example.test" };
    case "configure-module": return {};
    case "get-companion-status": return { ...fixture.status, role: fixture.role };
    case "list-decisions": return { decisions: [...fixture.decisions] };
    case "unban": fixture.decisions = fixture.decisions.filter(d => !data.addresses.includes(d.ip)); return {};
    case "list-members": return { members: [...fixture.members] };
    case "add-member": fixture.members.push({ name: data.name }); return { name: data.name, token: "csc2.fixture-opaque-not-base64", hub_url: "https://hub.example.test" };
    case "remove-member": fixture.members = fixture.members.filter(m => m.name !== data.name); return {};
    case "list-event-sources": return { sources: [...fixture.sources] };
    case "add-event-source": fixture.sources.push({ ...data, active: 1 }); return { name: data.name, token: "<img src=x onerror=alert('fixture')>", endpoint: "http://127.0.0.1/fixture-events" };
    case "remove-event-source": fixture.sources = fixture.sources.filter(s => s.name !== data.name); return {};
    default: throw new Error("Unexpected fixture action: " + action);
  }
}
// Replace ONLY the task boundary; never alter production task.js.
for (const route of router.options.routes) {
  const component = route.component;
  if (typeof component === "object") {
    component.mixins = [];
    component.methods = { ...component.methods, task };
  }
}
const i18n = new VueI18n({ locale: "en", messages: { en, de } });
window.__fixtureI18n = i18n;
window.__fixtureRouter = router;
window.__fixtureErrors = [];
Vue.config.errorHandler = error => window.__fixtureErrors.push(String(error));
new Vue({ router, i18n, render(h) { return h('main', { style: 'padding:24px' }, [h('strong', 'ISOLATED UI FIXTURE — NOT NS8 / NO LIVE BACKEND'), h('nav', { style: 'display:flex;gap:20px;margin:24px 0;flex-wrap:wrap' }, ['settings', 'status', 'members', 'bans', 'event-sources'].map(page => h('router-link', { props: { to: '/' + page } }, page))), h('router-view')]); } }).$mount("#fixture");
