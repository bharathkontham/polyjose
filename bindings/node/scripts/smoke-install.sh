#!/usr/bin/env bash
# Smoke test of a packed @polyjose/node tarball (feature 0012 H3, feature 0017; ADR 0037 §2
# `node`): installs that one tarball into a temporary directory, offline and hermetic, then loads
# @polyjose/node by name twice, as ES modules (`import`) and as CommonJS (`require`, require(esm),
# Node >= 22.12, ADR 0031 §3), and round-trips a compact ES256 JWS each time (RFC 7515 §7.1,
# RFC 7518 §3.4). binding-node.yml's smoke job runs it on each of the eight targets over the
# release tarball; locally it runs over pack.sh's dist/npm/ tarball on the Mac.
#
# Usage: scripts/smoke-install.sh <polyjose-node-<version>.tgz> [<platform>]
#   platform  the napi-rs platform this host must be detected as (src/backend.ts detectPlatform),
#             e.g. linux-arm64-musl; checked when given
#
# The install is the one test/package.test.ts makes: a temporary npm cache and empty user and
# global configs, `npm install --offline`, no lifecycle scripts, no lockfile; npm_* variables and
# NAPI_RS_NATIVE_LIBRARY_PATH are dropped from the environment. Since feature 0017 the package has
# no dependencies at all, so the install must hold @polyjose/node and nothing else. The import
# succeeds only if the package's addon-sha256.json pins its addon for this host (feature 0007 F07:
# the loader refuses any other), so this also checks the release's hash map for this host.
# No hand-written JavaScript file (ADR 0047): the checks are inline `node -e` scripts.
# Exits non-zero on any failure. macOS /bin/bash 3.2, Linux bash (Alpine too) and Git Bash.
set -euo pipefail
[ $# -ge 1 ] && [ $# -le 2 ] || { echo "usage: scripts/smoke-install.sh <polyjose-node-<version>.tgz> [<platform>]" >&2; exit 2; }
main=$(cd "$(dirname "$1")" && pwd -P)/${1##*/}
expect=${2:-}
[ -f "$main" ] || { echo "smoke-install.sh: $1 not found" >&2; exit 1; }

dir=$(mktemp -d "${TMPDIR:-/tmp}/polyjose-node-smoke.XXXXXX")
# Fail closed (0013 F10): /bin/bash 3.2 runs an EXIT trap with $? = 0 after a syntax error, so an
# exit before the last line, which sets the sentinel, becomes status 2 (see scripts/test-all.sh).
completed=""
# shellcheck disable=SC2154 # rc is assigned by the trap itself (rc=$?)
trap 'rc=$?; rm -rf "$dir"; [ -n "${completed:-}" ] || [ "$rc" -ne 0 ] || { echo "smoke-install.sh: stopped before its last statement (a syntax error?); failing closed" >&2; rc=2; }; exit "$rc"' EXIT
printf '{"name":"polyjose-node-smoke","version":"0.0.0","private":true}\n' >"$dir/package.json"
: >"$dir/user.npmrc"
: >"$dir/global.npmrc"

echo "==> @polyjose/node smoke: npm install --offline ${main##*/}"
# shellcheck disable=SC2046 # one unset per variable name
(
  cd "$dir"
  unset NAPI_RS_NATIVE_LIBRARY_PATH $(env | sed -n 's/^\(npm_[A-Za-z0-9_]*\)=.*/\1/p')
  export npm_config_cache=$dir/cache npm_config_userconfig=$dir/user.npmrc \
    npm_config_globalconfig=$dir/global.npmrc npm_config_offline=true npm_config_audit=false \
    npm_config_fund=false npm_config_update_notifier=false npm_config_ignore_scripts=true \
    npm_config_package_lock=false
  npm install --offline --no-audit --no-fund --loglevel=error "$main"
  installed=$(cd node_modules && find . -maxdepth 3 -name package.json | sed 's|^\./||' | LC_ALL=C sort | tr '\n' ' ')
  [ "$installed" = "@polyjose/node/package.json " ] || { echo "smoke-install.sh: the install holds $installed, not only @polyjose/node" >&2; exit 1; }

  echo "==> @polyjose/node smoke: the platform this host is detected as"
  # backend.js by file URL (it is not an export of the package): detectPlatform is the loader's own.
  # shellcheck disable=SC2016 # JavaScript, not shell: nothing to expand
  platform=$(node --input-type=module -e '
import * as fs from "node:fs";
import { pathToFileURL } from "node:url";
const { detectPlatform } = await import(pathToFileURL("node_modules/@polyjose/node/backend.js").href);
process.stdout.write(detectPlatform(process, fs));
')
  echo "    $platform"
  [ -z "$expect" ] || [ "$platform" = "$expect" ] || { echo "smoke-install.sh: detected $platform, expected $expect" >&2; exit 1; }

  echo "==> @polyjose/node smoke: import by name (ESM) and round-trip a compact JWS (ES256)"
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
console.log(`    ESM: @polyjose/node ${pkg.version} on ${process.platform}-${process.arch}: ES256 compact JWS round-trip OK`);
'

  echo "==> @polyjose/node smoke: require by name (CommonJS, require(esm)) and round-trip a compact JWS (ES256)"
  # shellcheck disable=SC2016 # JavaScript, not shell: nothing to expand
  node --input-type=commonjs -e '
const api = require("@polyjose/node");
(async () => {
  const key = await api.jwkGenerateEc("P-256");
  const payload = new TextEncoder().encode("polyjose release smoke");
  const token = await api.jwsSignCompact(payload, key, { protectedHeader: { alg: "ES256" } });
  const verified = await api.jwsVerifyCompact(token, await api.jwkToPublic(key), { allowedAlgs: ["ES256"] });
  if (verified.alg !== "ES256" || new TextDecoder().decode(verified.payload) !== "polyjose release smoke") {
    throw new Error("the compact JWS did not round-trip");
  }
  const addons = Object.keys(require.cache).filter((k) => k.endsWith(".node"));
  if (addons.length !== 1 || !/[\\/]polyjose-addon-[^\\/]+[\\/]polyjose-[0-9a-f]{32}\.node$/.test(addons[0])) {
    throw new Error(`expected one private, hash-checked copy of the addon, loaded: ${addons.join(", ")}`);
  }
  console.log(`    CJS: @polyjose/node ${require("@polyjose/node/package.json").version}: ES256 compact JWS round-trip OK`);
})().catch((e) => { console.error(e); process.exit(1); });
'
)
echo "==> @polyjose/node smoke: OK"
completed=1; exit 0
