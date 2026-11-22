# Hybrid UI regression checks

These checks exercise actual view methods and actual Vue/Carbon rendering. The browser fixture **replaces the NS8 task boundary** and is **not** backend integration, live NS8 testing, an application hook, or an ingress/enforcement test. Production `src/task.js` remains unchanged and uses NS8 tasks.

From `ui/`:

```sh
node --test qa/views.test.cjs
npm exec --yes --package=@yarnpkg/cli-dist@4.18.0 -- yarn install --immutable
npm exec --yes --package=@yarnpkg/cli-dist@4.18.0 -- yarn lint
npm exec --yes --package=@yarnpkg/cli-dist@4.18.0 -- yarn build
npm exec --yes --package=@yarnpkg/cli-dist@4.18.0 -- yarn serve --config qa/vite.config.mjs --host 127.0.0.1 --port 5176 --strictPort
```

Open `http://127.0.0.1:5176/qa/index.html#/settings` in a **foreground** browser tab (the checks await rendering animation frames). Run:

```js
window.__browserCheckResult = null;
import('/qa/browser-checks.js')
  .then(module => module.runChecks())
  .then(result => window.__browserCheckResult = result)
  .catch(error => window.__browserCheckResult = { error: String(error), stack: error.stack });
```

Read `window.__browserCheckResult`: success is an array of passed assertions; failures are explicit errors. Reload before rerunning because checks mutate fixture state. Check fixture label and `window.__fixtureErrors` as well. The fixture uses the real production router and views, real Carbon controls and Carbon CSS, not the NS8 host stylesheet or host bridge. Shared desktop/mobile menu wiring is checked by the Node suite, not live NS8 navigation.

The fixture-only Vite config aliases view task imports to `qa/task-boundary.js`, avoiding execution of the host-dependent NS8 bridge. Its explicit dependency optimization prevents Vite from crawling the unrelated production entry and attempting to prebundle Vue SFC imports from ns8-ui-lib. This config is not used for the production build. No fixture is included in the production build entry.

## Consumed task contract

All calls go through production `task(action, data)` outside the fixture. This contract has been verified against fixtures only; backend compatibility must be checked separately once implemented.

| Action | Input | Consumed output |
| --- | --- | --- |
| `get-configuration` | `{}` | `role`, `hub_host`, `lets_encrypt`, `hub_url`, `member_name`, `ban_duration`, `allowlist: string[]`, `samba_audit` |
| `configure-module` | Common: `role`, `ban_duration`, `allowlist`, `samba_audit`; hub: `hub_host`, `lets_encrypt`; member: optional nonempty `token` | completion; configuration is reloaded |
| `get-companion-status` | `{}` | `role`, `hub_url`, `lapi`, `active_bans`, hub `members`, optional `sources`, `services`, `sync: {pending,last_success,error,stale,age_seconds,import_overload,local_export_overload,quota_pending}`, `event_ingress: {endpoint,pending}` |
| `list-members` | `{}` | `{members:[{name,local?,ip_address?,last_push?,last_heartbeat?,...}]}` |
| `add-member` | `{name}` | `{name,token,hub_url}`; opaque csc2 membership token, never decoded |
| `remove-member` | `{name}` | completion; registry reloaded |
| `list-decisions` | `{}` | `{decisions:[{id,ip,scope,scenario,origin,until,duration,machine,country}]}`; local view for both roles |
| `unban` | `{addresses:string[]}` | completion; local decisions reloaded, selection cleared |
| `list-event-sources` | `{}` | `{sources:[{name,module,active,...}]}`; integer `0` is pending/inactive, integer `1` is active registration, absent/other values are unknown; no token read from list output |
| `add-event-source` | `{name,module}` | `{name,token,endpoint}`; source-scoped bearer token, not a membership token |
| `remove-event-source` | `{name}` | completion; registry reloaded |

Validation rejection: `error.validation = [{field|parameter,error}]`; generic errors use `error.message`. Source registration is available on both roles. It provisions an auth-event source identity, not hooks in other app modules. The EN/DE guide distinguishes a true auth hook from a separately installed structured-log adapter and explains fallback login detection versus generic HTTP protection.

Absent optional status fields are unknown, never ready. `lapi === "ok"` applies only to the local API. Sync pending/error/last-success values are separate; a zero queue with a last-success value is explicitly not a connectivity check. Token output is escaped Vue text, never HTML. Refresh, removal, view destruction and reload clear one-time secrets; late add responses after destruction do not reintroduce them. No TLS-bypass field is submitted. Allowlist is local, not global; no fixed reconnect delivery latency is promised.

Sync state precedence is error, capacity overload, stale, pending, idle, unknown. Either overload boolean must be exactly `true`; a numeric `quota_pending > 0` also signals capacity pressure, even with an empty outgoing queue. The overload message is bounded localized guidance, not a dump of sync metadata. Registration state is a separate column from authentication-event type. Pending sources stay removable and show remove/recreate recovery guidance; they cannot submit events or disable fallback login detection. Active registration is not proof of event delivery.

## Verification boundaries

The Node suite first reproduced failures in TLS-bypass submission, member ban gating, membership credential decoding/output, missing optional status handling, missing source provisioning/navigation and late-secret lifecycle handling before the corresponding implementation changes. It also checks role locking, blank-token omission, locale key parity and explicit button types. The browser suite checks real rendered inputs/buttons, local unban, error recovery, optional statuses, opaque/escaped tokens, navigation cleanup, source create/list/remove and German guide rendering. Neither suite validates the backend transport, HTTP ingress payload schema, real application hooks, distributed convergence or firewall enforcement.

Protocol presentation regressions added with separate Node RED/GREEN cycles cover integer source state (including malformed/missing states), conditional localized pending recovery, and each sync overload signal across unknown/idle/stale/pending inputs. The browser fixture additionally exercises all three overload signals and pending/active/unknown source rows in both EN and DE, no metadata token disclosure, pending removal/recreation and one-time-token cleanup. This remains isolated fixture verification, not a live backend test.
