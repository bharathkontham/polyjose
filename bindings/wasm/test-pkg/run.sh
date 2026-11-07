#!/usr/bin/env bash
# Tests of the packed @polyjose/wasm tarball (feature 0006 T04; ADR 0031 §3, ADR 0034, ADR 0047):
# the installed package, its `exports` resolution, the runtime entries and the shared facade, run
# through the shared JS conformance runner in Node, headless Chrome and workerd.
#
#   bindings/wasm/test-pkg/run.sh
#
# It needs the tarball dist/npm/polyjose-wasm-<version>.tgz that bindings/wasm/scripts/build-package.sh
# writes, and never builds it. bindings/wasm/test.sh calls this script after the build.
#
#   1. guards: TypeScript only in test-pkg (ADR 0047), exactly one tarball;
#   2. stale results removed: target/conformance/wasm-pkg-{node,chrome,workerd}.json (ADR 0034 §5:
#      a file left by an earlier run must never count);
#   3. a staging copy in target/wasm-test-pkg/ (so no generated .js or node_modules/ lands under
#      bindings/wasm, whose build script rejects JavaScript there): package.json and the lock file,
#      `npm ci --ignore-scripts` (miniflare, pinned), then the tarball installed with
#      `npm install --no-save --ignore-scripts` (it is rebuilt with a new integrity on every build,
#      so it can't be in the lock file);
#   4. the shared facade and runner, compiled from bindings/js with its pinned tsc into the staging
#      copy's js/ (bindings/js/dist is never touched), and test-pkg/src compiled with the same tsc
#      and the ADR 0047 options (extending bindings/js/tsconfig.json);
#   5. Node: node --test over the compiled tests -> target/conformance/wasm-pkg-node.json;
#   6. Chrome: a static page under headless Chrome -> wasm-pkg-chrome.json, or SKIPPED (no Chrome);
#   7. workerd: a worker under miniflare -> wasm-pkg-workerd.json.
#
# Then run scripts/conformance-parity.sh against a fresh rust-core reference
# (cargo test -p polyjose --test conformance).
#
# Exit status: 0 every run passed or was SKIPPED; 1 a run failed; 2 a missing prerequisite.
# Runs on macOS /bin/bash 3.2 and Linux bash 5. Needs node >= 22.12 and npm.
set -euo pipefail
export LC_ALL=C

me=test-pkg
die() { echo "$me: $*" >&2; exit 2; }

here=$(cd "$(dirname "$0")" && pwd -P) || exit 2
repo=$(cd "$here/../../.." && pwd -P) || exit 2
js=$repo/bindings/js
stage=$repo/target/wasm-test-pkg
results=$repo/target/conformance

for tool in node npm; do
  command -v "$tool" >/dev/null 2>&1 || die "$tool not found on PATH"
done

# --- 1. Guards ---------------------------------------------------------------------------------

echo "==> $me: TypeScript only (ADR 0047)"
stray=$(cd "$here" && find . -type f \( -name '*.js' -o -name '*.mjs' -o -name '*.cjs' \) -print)
[ -z "$stray" ] || { echo "$stray"; die "hand-written JavaScript in bindings/wasm/test-pkg (ADR 0047 requires TypeScript)"; }

tarballs=()
for f in "$repo"/dist/npm/polyjose-wasm-*.tgz; do
  [ -e "$f" ] && tarballs+=("$f")
done
[ ${#tarballs[@]} -gt 0 ] || die "no dist/npm/polyjose-wasm-*.tgz: build it first with bindings/wasm/scripts/build-package.sh"
[ ${#tarballs[@]} -eq 1 ] || die "more than one tarball in dist/npm/ (${tarballs[*]}): remove the stale ones"
tarball=${tarballs[0]}
echo "$me: testing ${tarball#"$repo"/}"

# --- 2. Stale results --------------------------------------------------------------------------

mkdir -p "$results" || die "could not create $results"
rm -f "$results/wasm-pkg-node.json" "$results/wasm-pkg-chrome.json" "$results/wasm-pkg-workerd.json"

# --- 3. The staging project --------------------------------------------------------------------

echo "==> $me: staging copy in ${stage#"$repo"/}"
rm -rf "$stage"
mkdir -p "$stage" || die "could not create $stage"
cp "$here/package.json" "$here/package-lock.json" "$stage/"
cp -R "$here/src" "$stage/src"

echo "==> $me: npm ci (miniflare, from package-lock.json; no install scripts)"
(cd "$stage" && npm ci --ignore-scripts --no-audit --no-fund --prefer-offline --loglevel=error) || die "npm ci failed"
echo "==> $me: npm install the tarball (--no-save, no install scripts)"
(cd "$stage" && npm install --no-save --ignore-scripts --no-audit --no-fund --prefer-offline --loglevel=error "$tarball") \
  || die "npm install of the tarball failed"
[ -f "$stage/node_modules/@polyjose/wasm/package.json" ] || die "the tarball did not install as @polyjose/wasm"
cmp -s "$here/package-lock.json" "$stage/package-lock.json" || die "npm changed package-lock.json (the lock file must pin the tree)"

# --- 4. TypeScript -----------------------------------------------------------------------------

echo "==> $me: the shared facade and runner (bindings/js, its pinned tsc)"
if [ ! -x "$js/node_modules/.bin/tsc" ]; then
  (cd "$js" && npm ci --no-audit --no-fund --loglevel=error) || die "npm ci failed in bindings/js"
fi
tsc=$js/node_modules/.bin/tsc
(cd "$js" && node tools/gen-error-codes.ts) || die "node tools/gen-error-codes.ts failed in bindings/js"
"$tsc" -p "$js" --outDir "$stage/js" || die "tsc failed for bindings/js"
[ -f "$stage/js/conformance/runner.js" ] && [ -f "$stage/js/conformance/node-main.js" ] \
  || die "tsc did not produce js/conformance/{runner,node-main}.js"

echo "==> $me: tsc (test-pkg/src, ADR 0047 options)"
# The ADR 0047 options come from bindings/js/tsconfig.json. Added: the DOM library, for the page
# (document, fetch) and the worker (Request, Response); the installed package's declarations use
# it too. `types` stays [] (no @types/node): Node built-ins are typed in src/node.ts.
cat >"$stage/tsconfig.json" <<EOF
{
  "extends": "$js/tsconfig.json",
  "compilerOptions": {
    "rootDir": "src",
    "outDir": "dist",
    "lib": ["es2022", "dom"]
  },
  "include": ["src/**/*.ts"],
  "exclude": []
}
EOF
"$tsc" -p "$stage" || die "tsc failed for test-pkg"

# --- 5-7. The runs -----------------------------------------------------------------------------

export POLYJOSE_REPO=$repo
status=0
summary=()
record() { summary+=("$1: $2"); [ "$2" = FAIL ] && status=1; return 0; }

echo "==> $me: Node (node --test, the compiled tests)"
tests=()
for f in "$stage"/dist/*.test.js; do
  [ -e "$f" ] && tests+=("$f")
done
[ ${#tests[@]} -gt 0 ] || die "no compiled tests in ${stage#"$repo"/}/dist"
if (cd "$stage" && node --test --test-reporter=spec "${tests[@]}"); then record node PASS; else record node FAIL; fi

echo "==> $me: Chrome (headless, --dump-dom)"
if out=$(cd "$stage" && node dist/chrome.js); then
  echo "$out"
  case $out in
    SKIPPED*) record chrome "$(head -n 1 <<<"$out")" ;;
    *) record chrome PASS ;;
  esac
else
  echo "$out"
  record chrome FAIL
fi

echo "==> $me: workerd (miniflare)"
if (cd "$stage" && node dist/workerd.js); then record workerd PASS; else record workerd FAIL; fi

echo
echo "$me: summary"
for line in "${summary[@]}"; do echo "  $line"; done
exit $status
