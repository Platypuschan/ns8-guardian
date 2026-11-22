#!/bin/bash
# The digest-pinned image already contains linux/sshd rules and GeoIP data.
# Retain upstream local credentials/bouncer registration and config handling,
# but NEVER refresh/install hub content at boot (even if its index is old).
# Fail closed if a future image changes the expected upstream entry point.
set -eo pipefail
grep -qx 'prepare_hub' /docker_start.sh
source <(sed '/^prepare_hub$/d' /docker_start.sh)
