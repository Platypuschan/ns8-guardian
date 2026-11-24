#!/bin/bash
# Runs only inside the disposable CI VM (a fresh single-node NS8 leader).
set -Eeuo pipefail
# Read all input before deciding: "grep -q" exits at the first match, the
# writer then dies of SIGPIPE and pipefail reports the match as a failure.
contains() { grep -c -- "$1" >/dev/null; }
image="${1:?module image}"
step() { printf '\n=== %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
wait_for() { # seconds description command...
    local seconds=$1 what=$2; shift 2
    for _ in $(seq 1 "$seconds"); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done
    fail "timeout waiting for ${what}"
}
json() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }

step "install"
module="$(add-module "$image" 1 | python3 -c 'import ast,sys; print(ast.literal_eval(sys.stdin.read())["module_id"])')"
printf '%s\n' "$module" >/tmp/csc-module-id
echo "module: $module"
hub_host="crowdsec-hub.ns8.test"

step "configure as hub"
api-cli run "module/$module/configure-module" --data "{\"role\":\"hub\",\"hub_host\":\"$hub_host\",\"lets_encrypt\":false,\"ban_duration\":\"30m\",\"allowlist\":[\"192.0.2.0/24\"],\"samba_audit\":true}"
for unit in "$module.service" "$module-bouncer.service" "$module-sync.service" "$module-gateway.service" "$module-refresh.timer"; do
    systemctl is-active --quiet "$unit" || fail "$unit is not active"
done
runagent -m "$module" podman exec "$module" cscli lapi status
runagent -m "$module" podman exec "$module" cscli bouncers list -o json | contains firewall || fail "local bouncer not registered"
wait_for 60 "nftables table" nft list table ip guardian
state=/var/lib/nethserver/$module/state
grep -q 'CONTAINER_NAME=traefik' "$state/crowdsec_config/acquis.yaml" || fail "Traefik journal source not discovered"
cat "$state/discovery.json"
status_json="$(api-cli run "module/$module/get-companion-status")"
echo "$status_json"
[[ "$(echo "$status_json" | json 'd["lapi"]')" == ok ]] || fail "get-status reports no LAPI"
# Validation rejects a role change.
if api-cli run "module/$module/configure-module" --data '{"role":"member","token":"csc2.x"}' >/tmp/csc-val.txt 2>&1; then
    fail "role change was accepted"
fi
grep -q role_is_fixed /tmp/csc-val.txt || { cat /tmp/csc-val.txt; fail "unexpected validation result"; }

step "attacker namespace 198.51.100.2 -> node 198.51.100.1"
# Re-runs on the same VM: remove leftovers of an earlier attempt.
ip netns del csc-attacker 2>/dev/null || true
ip link del csc-test 2>/dev/null || true
ip netns add csc-attacker
ip link add csc-test type veth peer name csc-client
ip link set csc-client netns csc-attacker
ip addr add 198.51.100.1/30 dev csc-test
ip link set csc-test up
ip -n csc-attacker addr add 198.51.100.2/30 dev csc-client
ip -n csc-attacker link set csc-client up
ip -n csc-attacker link set lo up
firewall-cmd --zone=public --add-interface=csc-test
attacker() { ip netns exec csc-attacker "$@"; }
login() {
    attacker curl -sk -o /dev/null -w '%{http_code}' --max-time 5 -H 'Content-Type: application/json' \
        -d '{"username":"admin","password":"wrong-password"}' https://198.51.100.1/cluster-admin/api/login
}
code="$(login)" || true
[[ "$code" == 401 ]] || fail "expected 401 from the NS8 admin login, got '$code'"

step "the agent reads the host journal"
# Same journalctl the agent runs, inside the CrowdSec container.
seen="$(podman exec "$module" journalctl -q --no-pager -o cat -n 3 CONTAINER_NAME=traefik "_UID=$(id -u traefik1)" 2>&1 || true)"
echo "$seen"
grep -q 'cluster-admin' <<<"$seen" || fail "journalctl inside the CrowdSec container cannot read the Traefik journal"
podman logs "$module" 2>&1 | grep -E "journalctl|Starting processing data" | head -5

step "failed NS8 admin logins until banned"
decisions() { runagent -m "$module" podman exec "$module" cscli decisions list -o raw; }
alerts() { runagent -m "$module" podman exec "$module" cscli alerts list -o raw; }
# The stock generic 401 rule also fires on the same requests and its decision may replace the ns8 one in the
# decision list, so require the ban AND the NS8-specific alert separately.
banned() { decisions | contains '198.51.100.2,' && alerts | contains 'ns8/ns8-admin-bf'; }
# Like the upstream CrowdSec module tests: retry, since lines written while
# the agent (re)starts are never read (journalctl -n 0).
for try in 1 2 3 4; do
    for _ in 1 2 3 4 5; do login >/dev/null || true; done
    for _ in $(seq 1 20); do banned && break 2; sleep 1; done
    echo "no ban after attempt $try"
done
banned || fail "198.51.100.2 was not banned"
decisions
wait_for 40 "nftables ban" sh -c "nft list table ip guardian | grep -q 198.51.100.2"
code="$(login)" || true
[[ "$code" == 000 ]] || fail "banned address still reaches Traefik (HTTP $code)"
echo "198.51.100.2 is dropped"

step "member enrollment uses the private sync API through the public route"
token_json="$(api-cli run "module/$module/add-member" --data '{"name":"ci-member"}')"
token="$(echo "$token_json" | json 'd["token"]')"
creds="$(python3 - "$token" <<'PY'
import base64, json, sys
assert sys.argv[1].startswith("csc2."), "token must be a csc2 sync enrollment"
t = sys.argv[1][5:]
d = json.loads(base64.urlsafe_b64decode(t + "=" * (-len(t) % 4)))
assert "machine" not in d and "bouncer_key" not in d, "token must not carry LAPI credentials"
print(d["peer"], d["secret"], d["url"])
PY
)"
read -r _ secret url <<<"$creds"
[[ "$url" == "https://$hub_host/" ]] || fail "unexpected hub URL $url"
resolve=(--resolve "$hub_host:443:127.0.0.1")
sync_code() { # bearer
    curl -sk "${resolve[@]}" -o /tmp/csc-sync.json -w '%{http_code}' -H 'Content-Type: application/json' \
        -H "Authorization: Bearer $1" -d '{"cursor":0,"updates":[]}' "https://$hub_host/v1/sync"
}
[[ "$(sync_code "$secret")" == 200 ]] || { cat /tmp/csc-sync.json; fail "member sync was refused"; }
contains '"changes"' </tmp/csc-sync.json || fail "sync reply carries no change list"
[[ "$(sync_code wrong-token)" == 401 ]] || fail "wrong sync credential was not rejected"
# Only /v1/sync is routed publicly; the LAPI and event ingestion are not.
for path in /v1/watchers/login /v1/events; do
    pub_code="$(curl -sk "${resolve[@]}" -o /dev/null -w '%{http_code}' "https://$hub_host$path" -d '{}')"
    [[ "$pub_code" == 404 || "$pub_code" == 405 ]] || fail "$path reachable through the public route ($pub_code)"
done
api-cli run "module/$module/list-members" | contains ci-member || fail "member not listed"
api-cli run "module/$module/remove-member" --data '{"name":"ci-member"}'
[[ "$(sync_code "$secret")" == 401 ]] || fail "removed member can still synchronize"

step "application event source creates a real local ban"
src_json="$(api-cli run "module/$module/add-event-source" --data '{"name":"ci-app","module":"ci-app1"}')"
src_token="$(echo "$src_json" | json 'd["token"]')"
endpoint="$(echo "$src_json" | json 'd["endpoint"]')"
[[ "$endpoint" == http://127.0.0.1:*/v1/events ]] || fail "unexpected event endpoint $endpoint"
send_event() { # ip token
    curl -s -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' -H "Authorization: Bearer $2" \
        -d "{\"schema_version\":1,\"id\":\"$(cat /proc/sys/kernel/random/uuid)\",\"occurred_at\":\"$(date -u +%FT%TZ)\",\"event\":\"authentication_failed\",\"source_ip\":\"$1\"}" "$endpoint"
}
[[ "$(send_event 198.51.100.77 wrong-token)" == 401 ]] || fail "forged source credential accepted"
for _ in 1 2 3 4 5 6; do [[ "$(send_event 198.51.100.77 "$src_token")" == 202 ]] || fail "event not accepted"; done
wait_for 90 "event-derived decision" sh -c "runagent -m $module podman exec $module cscli decisions list -o raw | grep -q 198.51.100.77"
wait_for 40 "event-derived nftables ban" sh -c "nft list table ip guardian | grep -q 198.51.100.77"
api-cli run "module/$module/remove-event-source" --data '{"name":"ci-app"}'
[[ "$(send_event 198.51.100.78 "$src_token")" == 401 ]] || fail "removed source can still report"
api-cli run "module/$module/unban" --data '{"addresses":["198.51.100.77"]}'

step "unban restores access"
api-cli run "module/$module/list-decisions" | contains 198.51.100.2 || fail "list-decisions misses the ban"
api-cli run "module/$module/unban" --data '{"addresses":["198.51.100.2"]}'
wait_for 40 "nftables unban" sh -c "! nft list table ip guardian | grep -q 198.51.100.2"
code="$(login)" || true
[[ "$code" == 401 ]] || fail "unbanned address cannot reach the login again (HTTP $code)"

step "allowlisted addresses are never banned"
ip -n csc-attacker addr add 192.0.2.9/32 dev csc-client
ip route add 192.0.2.9/32 dev csc-test
for _ in 1 2 3 4 5 6; do
    attacker curl -sk -o /dev/null --interface 192.0.2.9 --max-time 5 -H 'Content-Type: application/json' \
        -d '{"username":"admin","password":"x"}' https://198.51.100.1/cluster-admin/api/login || true
done
sleep 20
if decisions | contains 192.0.2.9; then fail "allowlisted address was banned"; fi

step "community blocklist is an opt-in that can be removed again"
community() { api-cli run "module/$module/get-companion-status" | json "'%s %s %s' % (d['community']['enabled'], d['community']['entries'], d['community']['error'] or '-')"; }
[[ "$(community | cut -d' ' -f1)" == False ]] || fail "community blocklist is not off by default"
api-cli run "module/$module/configure-module" --data '{"community_blocklist":true}'
registered=no
for _ in $(seq 1 60); do
    read -r _ entries error <<<"$(community)"
    if [[ "$entries" =~ ^[0-9]+$ && "$entries" -gt 1000 ]]; then registered=yes; break; fi
    [[ "$error" != - ]] && break
    sleep 5
done
if [[ "$registered" == yes ]]; then
    echo "community blocklist entries: $entries"
    api-cli run "module/$module/list-decisions" | contains '"origin": "CAPI"' && fail "community entries are listed as local bans"
    systemctl is-active --quiet "$module.service" || fail "engine is down with the community blocklist enabled"
else
    # The Central API is an external service: a registration failure must be reported, not break the module.
    echo "WARNING: Central API registration did not complete: $error" >&2
    systemctl is-active --quiet "$module.service" || fail "engine is down after a failed community registration"
fi
api-cli run "module/$module/configure-module" --data '{"community_blocklist":false}'
for _ in $(seq 1 30); do
    read -r _ entries _ <<<"$(community)"
    [[ "$entries" == 0 ]] && break
    sleep 2
done
[[ "$entries" == 0 ]] || fail "community entries remain after switching the option off ($entries)"
[[ ! -e "/var/lib/nethserver/$module/state/crowdsec_config/online_api_credentials.yaml" ]] || fail "credentials remain after switching the option off"
systemctl is-active --quiet "$module.service" || fail "engine is down after disabling the community blocklist"

step "restart keeps working without changes"
systemctl restart "$module.service"
wait_for 120 "LAPI after restart" runagent -m "$module" podman exec "$module" cscli lapi status
runagent -m "$module" systemctl start "$module-refresh.service" 2>/dev/null || systemctl start "$module-refresh.service"
echo "smoke test passed"
# Not covered here (needs two nodes / a reboot): hub-down protection, reconnect
# sync, reboot persistence and backup/restore. See docs/acceptance.md.
