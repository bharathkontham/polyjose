#!/usr/bin/env bash
# Smoke test of packed @polyjose/node tarballs (feature 0012 H3; ADR 0037 §2 `node`): installs the
# main tarball and this host's platform tarball into a temporary directory, offline and hermetic,
# then imports @polyjose/node by name and round-trips a compact ES256 JWS (RFC 7515 §7.1,
# RFC 7518 §3.4). binding-node.yml's smoke job runs it on linux-x64-gnu and darwin-arm64 over the
# release tarballs; locally it runs over pack.sh's dist/npm/ on the Mac.
#
# Usage: scripts/smoke-install.sh <polyjose-node-<version>.tgz> <polyjose-node-<platform>-<version>.tgz>
#
# The install is the one test/package.test.ts makes: a temporary npm cache and empty user and
# global configs, `npm install --offline`, no lifecycle scripts, no lockfile; npm_* variables and
# NAPI_RS_NATIVE_LIBRARY_PATH are dropped from the environment. The other seven platform packages
# are optional dependencies that do not exist offline, so npm skips them. The import succeeds only
# if the main package's addon-sha256.json pins the installed addon (feature 0007 F07: the loader
# refuses any other), so this also checks the release's hash map for this host.
# No hand-written JavaScript file (ADR 0047): the check is an inline `node --input-type=module`.
# Exits non-zero on any failure. macOS /bin/bash 3.2 and Linux bash.
set -euo pipefail
[ $# -eq 2 ] || { echo "usage: scripts/smoke-install.sh <main.tgz> <platform.tgz>" >&2; exit 2; }
main=$(cd "$(dirname "$1")" && pwd -P)/${1##*/}
platform=$(cd "$(dirname "$2")" && pwd -P)/${2##*/}
[ -f "$main" ] && [ -f "$platform" ] || { echo "smoke-install.sh: $1 or $2 not found" >&2; exit 1; }

dir=$(mktemp -d "${TMPDIR:-/tmp}/polyjose-node-smoke.XXXXXX")
trap 'rm -rf "$dir"' EXIT
printf '{"name":"polyjose-node-smoke","version":"0.0.0","private":true,"type":"module"}\n' >"$dir/package.json"
: >"$dir/user.npmrc"
: >"$dir/global.npmrc"

echo "==> @polyjose/node smoke: npm install --offline ${main##*/} ${platform##*/}"
# shellcheck disable=SC2046 # one unset per variable name
(
  cd "$dir"
  unset NAPI_RS_NATIVE_LIBRARY_PATH $(env | sed -n 's/^\(npm_[A-Za-z0-9_]*\)=.*/\1/p')
  export npm_config_cache=$dir/cache npm_config_userconfig=$dir/user.npmrc \
    npm_config_globalconfig=$dir/global.npmrc npm_config_offline=true npm_config_audit=false \
    npm_config_fund=false npm_config_update_notifier=false npm_config_ignore_scripts=true \
    npm_config_package_lock=false
  npm install --offline --no-audit --no-fund --loglevel=error "$main" "$platform"
  echo "==> @polyjose/node smoke: import by name and round-trip a compact JWS (ES256)"
  # shellcheck disable=SC2016 # JavaScript, not shell: nothing to expand
  node --input-type=module -e '
import * as api from "@polyjose/node";
const key = await api.jwkGenerateEc("P-256");
const payload = new TextEncoder().encode("polyjose release smoke");
const token = await api.jwsSignCompact(payload, key, { protectedHeader: { alg: "ES256" } });
const verified = await api.jwsVerifyCompact(token, await api.jwkToPublic(key), { allowedAlgs: ["ES256"] });
if (verified.alg !== "ES256" || new TextDecoder().decode(verified.payload) !== "polyjose release smoke") {
  throw new Error("the compact JWS did not round-trip");
}
const pkg = JSON.parse((await import("node:fs")).readFileSync("node_modules/@polyjose/node/package.json", "utf8"));
console.log(`@polyjose/node ${pkg.version} on ${process.platform}-${process.arch}: ES256 compact JWS round-trip OK`);
'
)
echo "==> @polyjose/node smoke: OK"
