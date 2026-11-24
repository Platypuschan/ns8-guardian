#!/bin/bash
# The digest-pinned image already contains linux/sshd rules and GeoIP data.
# Retain upstream local credentials/bouncer registration and config handling,
# but NEVER refresh/install hub content at boot (even if its index is old).
# Fail closed if a future image changes the expected upstream entry point.
set -eo pipefail
grep -qx 'prepare_hub' /docker_start.sh

# Upstream only copies MISSING files from /staging into the persistent config volume, so a newer image would leave
# older hub rules in place on an existing installation. Hub items (parsers, scenarios, collections, contexts,
# post-overflows, hub index and data links) are owned by the image: make the volume follow the image exactly.
# Files that are not hub symlinks (the module's own ns8-* rules, generated config) are never touched.
sync_image_rules() {
    local src=/staging/etc/crowdsec dst=/etc/crowdsec d link name
    [ -d "$src/hub" ] && [ -d "$dst" ] || return 0
    mkdir -p "$dst/hub"
    rsync -a --delete "$src/hub/" "$dst/hub/"
    for d in parsers/s00-raw parsers/s01-parse parsers/s02-enrich scenarios collections contexts \
             postoverflows/s00-enrich postoverflows/s01-whitelist postoverflows/s02-enrich; do
        [ -d "$src/$d" ] || [ -d "$dst/$d" ] || continue
        mkdir -p "$dst/$d"
        for link in "$src/$d"/*; do
            [ -L "$link" ] || continue
            name="$(basename "$link")"
            [ -e "$dst/$d/$name" ] && [ ! -L "$dst/$d/$name" ] && continue   # a regular file is not hub-owned
            ln -sfn "$(readlink "$link")" "$dst/$d/$name"
        done
        for link in "$dst/$d"/*; do
            [ -L "$link" ] || continue
            case "$(readlink "$link")" in /etc/crowdsec/hub/*) ;; *) continue ;; esac
            [ -L "$src/$d/$(basename "$link")" ] || rm -f "$link"      # item no longer shipped by this image
        done
    done
    for link in /staging/var/lib/crowdsec/data/*; do
        name="$(basename "$link")"
        case "$name" in crowdsec.db*) continue ;; esac
        if [ -L "/var/lib/crowdsec/data/$name" ] || [ ! -e "/var/lib/crowdsec/data/$name" ]; then
            ln -sfn "$link" "/var/lib/crowdsec/data/$name"
        fi
    done
}
sync_image_rules
source <(sed '/^prepare_hub$/d' /docker_start.sh)
