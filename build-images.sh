#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Build local candidates only; publication is a separate workflow gate.
set -Eeuo pipefail
repobase="${REPOBASE:-ghcr.io/platypuschan}"
repobase="${repobase,,}"
module="${repobase}/guardian"
revision="$(git rev-parse HEAD)"
if [[ -n "$(git status --porcelain --untracked-files=normal)" ]]; then
    revision="${revision}-dirty"
fi
version="$(<CATALOG_VERSION)"
crowdsec_image="${CROWDSEC_IMAGE:-${repobase}/guardian-engine:sha-${revision:0:12}}"
bouncer_image="${CROWDSEC_FIREWALL_BOUNCER_IMAGE:-ghcr.io/nethserver/crowdsec-firewall-bouncer:1.4.0@sha256:dfe782134f51fb57783456d2ac7ce85470f667207da9c9a628182180d09f06d6}"
if [[ -z "${CROWDSEC_IMAGE:-}" ]]; then
    buildah bud --build-arg "SOURCE_REVISION=${revision}" -f runtime/Containerfile -t "$crowdsec_image" .
fi
builder=""
stage=""
cleanup() {
    if [[ -n "${builder}" ]]; then buildah rm "${builder}" >/dev/null; fi
    if [[ -n "${stage}" ]]; then rm -rf "${stage}"; fi
}
trap cleanup EXIT
# Never infer source freshness from the presence of a previous build directory.
(
    cd ui
    yarn_version="$(node -p 'require("./package.json").packageManager.split("@")[1]')"
    env -u YARN_NO_PROXY npm exec --yes --package="@yarnpkg/cli-dist@${yarn_version}" -- yarn install --immutable
    env -u YARN_NO_PROXY npm exec --yes --package="@yarnpkg/cli-dist@${yarn_version}" -- yarn build
)
builder="$(buildah from scratch)"
# Filter a portable archive: hosted Ubuntu Buildah lacks add --exclude.
# Local test imports must never inject cached executable code into the package.
stage="$(mktemp -d)"
tar --exclude='__pycache__' --exclude='*.pyc' --exclude='*.pyo' -C imageroot -cf "$stage/imageroot.tar" .
buildah add "${builder}" "$stage/imageroot.tar" /imageroot
buildah add --chmod=0755 "${builder}" sdk/report_auth.py /imageroot/bin/report-auth-event
buildah add "${builder}" ui/dist /ui
buildah config --entrypoint=/ \
    --label="org.opencontainers.image.source=https://github.com/Platypuschan/ns8-guardian" \
    --label="org.opencontainers.image.title=NS8 Guardian Hybrid" \
    --label="org.opencontainers.image.version=${version}" \
    --label="org.opencontainers.image.revision=${revision}" \
    --label="org.opencontainers.image.licenses=GPL-3.0-or-later" \
    --label="org.nethserver.authorizations=traefik@node:routeadm node:portsadm" \
    --label="org.nethserver.tcp-ports-demand=3" \
    --label="org.nethserver.rootfull=1" \
    --label="org.nethserver.max-per-node=1" \
    --label="org.nethserver.min-core=3.2.2" \
    --label="org.nethserver.images=${crowdsec_image} ${bouncer_image}" "${builder}"
buildah commit "${builder}" "${module}"
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    printf 'module=%s\nengine=%s\n' "${module}" "$crowdsec_image" >>"${GITHUB_OUTPUT}"
fi
printf 'Built %s with %s\n' "${module}" "$crowdsec_image"
