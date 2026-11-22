#!/bin/bash
# Autonomous hybrid end-to-end tests without NS8. Each node is a real engine
# image with its own local LAPI; every firewall action stays in an isolated
# --network none rootless Podman namespace (never the host firewall).
#
# Covers: application event -> local decision -> nftables drop, engine and
# bouncer restart without any controller, reconnect sync without echo/TTL
# renewal, origin unban keeping an independent local ban, IPv6, allowlists.
set -Eeuo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
engine="${DOCKER:-podman}"
"$engine" build --network host -q -t localhost/cscompanion-e2e-tools - >/dev/null <<'CF'
FROM docker.io/library/alpine:3.24.2
RUN apk add --no-cache nftables iproute2 netcat-openbsd curl
CF
cd "$root"
RUN_ENGINE_TESTS=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=imageroot/pypkg \
    python3 -m unittest discover -v -s tests -p 'test_autonomous_engine.py'
