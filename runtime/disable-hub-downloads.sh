#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Guarded adaptation of the digest-pinned upstream entrypoint. Local database,
# credentials and bouncer registration are retained; only hub downloads stop.
set -Eeuo pipefail
path="${1:-/docker_start.sh}"
text="$(<"$path")"
needle='prepare_hub() {'
if [[ "$text" != *"$needle"* ]]; then
    printf 'upstream prepare_hub function not found\n' >&2
    exit 1
fi
rest="${text#*"$needle"}"
if [[ "$rest" == *"$needle"* ]]; then
    printf 'ambiguous upstream prepare_hub function\n' >&2
    exit 1
fi
replacement=$'prepare_hub() {\n    # Required rule content is bundled in this immutable image.\n    return 0'
text="${text/"$needle"/"$replacement"}"
printf '%s\n' "$text" >"$path"
