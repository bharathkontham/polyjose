#!/usr/bin/env bash
# Builds @polyjose/node in place, for the host target (ADR 0031 §2, ADR 0047):
#   1. the shared facade: bindings/ts-common's error codes (tools/gen-error-codes.ts, from Error::CODES)
#      and tsc into bindings/ts-common/dist/; bindings/ts-common stays the facade's only source;
#   2. the addon and its declarations: napi build --platform --release --no-js --dts binding.d.ts
#      (polyjose.<platform>.node, binding.d.ts). --no-js: no napi-rs loader is generated, since
#      backend.js loads the pinned addon itself (feature 0017); extra arguments go to napi build,
#      e.g. `scripts/build.sh --target <Rust target>`. Cargo gets `--locked` (after `--`,
#      which napi build hands to cargo build and to its own cargo metadata), so the addon is built
#      from the committed Cargo.lock only (review-code.md SF-3). Under scripts/test-all.sh
#      (POLYJOSE_ADDON_REUSE=1, never set by CI, pack.sh or a release path), the addon is reused
#      instead when scripts/addon-reuse.sh finds its inputs unchanged since the build it recorded
#      and the addon still the one recorded and pinned; POLYJOSE_FORCE_REBUILD=1 always builds;
#   3. addon-sha256.json: scripts/addon-hashes.sh over every polyjose.<platform>.node in the tree
#      (the host's), the addon hash pin that backend.js checks before it loads anything (feature
#      0007 F07); the packed package gets its own map from scripts/pack-main.sh over exactly the
#      addons it ships;
#   4. facade/: the compiled facade (.js and the generated .d.ts) copied from bindings/ts-common/dist/src;
#   5. tsc: src/*.ts to the package root (index.js, backend.js and their .d.ts), then test/*.ts to
#      dist/.
# Idempotent: each step deletes and regenerates its own output. Everything it writes is
# git-ignored. typescript comes from bindings/ts-common (its only dev-dependency, pinned in its lockfile)
# and @napi-rs/cli from this package's lockfile; when either is not installed yet, `npm ci
# --ignore-scripts` installs it, running no dependency's install script (review-code.md N2). It
# never publishes: npm publish and napi pre-publish belong to the human-approved release (Gate 3).
set -euo pipefail
cd "$(dirname "$0")/.."
js=../ts-common
tsc=$js/node_modules/.bin/tsc
napi=node_modules/.bin/napi

[ -x "$tsc" ] || (cd "$js" && npm ci --ignore-scripts --no-audit --no-fund --loglevel=error)
[ -x "$napi" ] || npm ci --ignore-scripts --no-audit --no-fund --loglevel=error

echo "==> @polyjose/node build: the shared facade (bindings/ts-common)"
(cd "$js" && node tools/gen-error-codes.ts && rm -rf dist && node_modules/.bin/tsc -p .)

echo "==> @polyjose/node build: napi build --platform --release --no-js $*"
# A binding.cjs from a build before feature 0017 would be stale output; nothing loads it now.
rm -f binding.cjs
reuse=${POLYJOSE_ADDON_REUSE:-}
if [ "$reuse" = 1 ] && scripts/addon-reuse.sh check "$@"; then
  # The same bytes as a fresh build; newer than their sources, as one (check-binding-api.d/node.sh).
  touch polyjose.*.node binding.d.ts
else
  rm -f addon-inputs.sha256
  # The inputs key before the build: save records the build only if the inputs are still those.
  if [ "$reuse" = 1 ]; then reuse=build; key=$(scripts/addon-reuse.sh key) || key=""; fi
  "$napi" build --platform --release --no-js --dts binding.d.ts "$@" -- --locked
fi

echo "==> @polyjose/node build: addon-sha256.json (scripts/addon-hashes.sh)"
scripts/addon-hashes.sh addon-sha256.json polyjose.*.node
if [ "$reuse" = build ]; then
  scripts/addon-reuse.sh save "$key" "$@" || echo "addon-reuse: could not record the addon's inputs; the next build compiles the addon again"
fi

echo "==> @polyjose/node build: facade/ (compiled .js and .d.ts of bindings/ts-common/dist/src)"
rm -rf facade
mkdir facade
cp "$js"/dist/src/*.js "$js"/dist/src/*.d.ts facade/

echo "==> @polyjose/node build: tsc (src -> package root, test -> dist)"
rm -f index.js index.d.ts backend.js backend.d.ts ./*.js.map ./*.d.ts.map
# dist/ may hold other outputs in subdirectories (packaging); only the compiled tests are ours.
[ ! -d dist ] || find dist -maxdepth 1 -type f -delete
"$tsc" -p tsconfig.json
"$tsc" -p test/tsconfig.json
