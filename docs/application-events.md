# Connecting application authentication events

The hybrid module offers an integration interface, not automatic modifications to Gitea, Vaultwarden, Organizr or other applications. Keep the existing log-based protection until an adapter for the actual application's login flow has been exercised. The authentication result must come from the application, a supported authentication hook, or a trustworthy structured audit record. An NS8 lifecycle hook cannot infer login outcomes.

## Event contract

Send one event for one failed authentication attempt, not a request to ban an address:

```json
{
  "schema_version": 1,
  "id": "64049a48-4391-4fd4-8101-b1cf83772112",
  "occurred_at": "2026-11-20T20:00:00Z",
  "event": "authentication_failed",
  "source_ip": "198.51.100.42"
}
```

Use the real timestamp and a newly generated UUID; the example timestamp is illustrative. Preserve both unchanged during retries. The receiver assigns source/module identity from its registered credential. Do not add a module field, username, password, access token, raw login body or client-controlled text. The sender must not accept a `source_ip` embedded inside a username. Only trust forwarded addresses from an explicitly configured proxy chain.

## Provisioning

Use the module's **Event sources** page, or its NS8 `add-event-source` action with a source `name` and the owning `module`. Provisioning returns a source token and the local endpoint. Source tokens differ from member enrollment tokens. Store the source token once in a private file readable only by the producer user; never pass it as a command-line argument or include it in logs. Removing the source revokes further submissions.

Provisioning first creates a pending source. It cannot authenticate and does not suppress the application's login fallback while service configuration or credential output is incomplete. Apply/output failure removes the registration and attempts recovery; interrupted pending sources remain visible and can be removed and recreated. After credential output is flushed, the source is activated. Its overlapping login fallback is suppressed on the next normal configuration refresh, not immediately; until that refresh the two paths can overlap. A stdout flush is not proof that a remote UI received the token. If delivery is lost, remove and recreate the source rather than assuming the secret is recoverable.

Registration does not install a hook or prove event delivery. Establish working delivery as part of that change and test positive/negative login controls. Generic web-scan detection is not provided (see README: the stock Traefik parser mis-attributes forwarded chains).

## Durable producer helper

`sdk/report_auth.py` uses Python's standard library. Module packaging also installs it as `bin/report-auth-event`. It has separate enqueue and delivery commands so a callback need not wait for a network request:

```sh
python3 sdk/report_auth.py enqueue \
  --spool /var/lib/my-auth-adapter/private/events.sqlite \
  --ip 198.51.100.42

python3 sdk/report_auth.py flush \
  --spool /var/lib/my-auth-adapter/private/events.sqlite \
  --endpoint http://127.0.0.1:ALLOCATED_GATEWAY_PORT/v1/events \
  --token-file /var/lib/my-auth-adapter/private/source-token
```

`ALLOCATED_GATEWAY_PORT` must be replaced with the endpoint returned by source provisioning, not the local LAPI port. The helper deliberately accepts only literal loopback endpoints; run it in the host context of the adapter. A rootless application container's own `127.0.0.1` is not the host. Use an explicitly designed host-side adapter instead of publishing the ingress publicly or exposing the host network to every application.

`enqueue` performs no HTTP request and returns a queued UUID. `flush` sends a bounded batch, does not follow redirects, does not use environment proxy variables, and deletes a successfully delivered item only after a valid acknowledgement for the same UUID. A failed transport request, malformed acknowledgement, interrupted flush or lost response retains the item for retry. Only a complete, bounded HTTP422 rejection with matching UUID, `permanent: true` and a bounded error code moves the unchanged payload into persistent SQLite quarantine. Arbitrary400/413/422, authentication, overload and redirects retain the pending item. Quarantined rows count against capacity and are not automatically evicted. Schedule `flush` in the owning adapter's worker or timer. Do not run an unbounded flushing loop inside the login request.

Inspect quarantine metadata (not source addresses/payload) with `quarantine-inspect --spool PATH [--limit 100]`. To irreversibly remove one reviewed entry and free its capacity, use `quarantine-discard --spool PATH --id EXACT-UUID --confirm-discard`. There is no bulk/automatic discard or retimestamp/replay command. Existing legacy quarantines remain intact. Upgrade gateway and SDK together: the new SDK deliberately retries an old gateway's ambiguous400 rather than treating it as a permanent loss.

The spool directory must be owned by the sender and not group/world-writable; its database and token file must be private. Default capacity is 10,000 queued plus quarantined events. Queue-full/disk-full errors are explicit; they do not discard older entries. The application integration decides how to record/alert such failures without blocking legitimate application availability. The CLI prints exception classes only, never secret-bearing exception text. Flush output includes the quarantine count. It returns 75 while a flush still has pending work and 65 for retained quarantine or invalid configuration/storage errors.

The receiver accepts new events up to seven days old, with at most300 seconds of future clock skew. Identical retained UUID/body duplicates remain idempotent beyond that age window; changed content for the same retained UUID is rejected. Appended-event deduplication records have bounded one-day retention, not permanent identity storage. Seven days is an ingress replay bound, not a promise that an old attack creates a current-time ban; test the actual detection policy and adapter outage duration.

The production worker waits for the actual Engine to hold the current acquisition file open before appending queued events, and records for every appended line its end offset and the **engine process generation** (boot id, pid, start time of the running `crowdsec` process) that was running. `delivered` in the receiver journal still only means durably appended.

**Consumer acknowledgement.** An event becomes `acked` only when the *same* engine generation has read past the event's end offset and ACK_SETTLE (3 s) has passed; the sync worker re-checks every 5 s. Rotation of a drained log acknowledges its rows. A probe failure changes nothing (no ack, no requeue). The counters `event_pending` (not yet appended), `event_unacked` (appended, not yet consumed) and `event_replayed_total` are part of the companion status.

**Crash windows.** If the engine generation changes before an event is acked (engine crash or restart between append and consumption, including a freshly started engine that tails from EOF), the event is re-appended. After *any* engine restart, events acknowledged within the last REPLAY_WINDOW (120 s) are replayed as well, because CrowdSec's scenario buckets are in memory and are gone; replay skips addresses unbanned (through the module's `unban` action) after the event. The auth-event scenario groups by address and uses `distinct: ns8_event_id`, so a replayed event never counts twice in a live bucket. Replay re-evaluates the detection rule: it can create a ban again only if the replayed events themselves overflow a bucket, and an operator unban is respected.

**Guarantee and limits.** At-least-once into the engine for events younger than the replay window; reading past an event is the strongest consumption signal obtainable without modifying CrowdSec. A crash exactly between the engine's read and the in-memory bucket update is covered by the replay (restart), not by a CrowdSec-side acknowledgement. Events older than the replay window whose bucket state was lost are not re-fed (their detection window has expired anyway). Not exactly-once. A control-server outage alone does not stop local acquisition. Verified by `tests/test_event_ack.py` (real SQLite, a real process holding a real fd for the probe script) and the hosted lab case `engine_restart_event_replay`.

## Adapter acceptance before production

- Wrong password produces exactly one event with the real client address.
- Correct password, login-page visits and internal auth-service errors do not masquerade as wrong-password attempts.
- Test MFA and expired-session flows explicitly; identify distinct auth stages instead of counting the same attempt twice.
- Include IPv6 and the real trusted-proxy/CDN path.
- A username containing newlines or `from <victim IP>` cannot alter the reported address.
- Disconnect/restart the local receiver, queue failures, restart the adapter, then flush the same IDs successfully.
- Verify the old login fallback is suppressed only for this module and unrelated service detection remains unchanged. Generic HTTP scanner detection exists only on the Traefik access log (see README), not through this event path.
- Demonstrate an actual CrowdSec decision and packet drop, plus an unblocked client control. A successful POST is not a ban test.

No application hook in a sibling repository is installed by this development change. Do not describe registering an event source as end-to-end protection for that application until its adapter passes these checks.
