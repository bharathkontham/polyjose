#!/usr/bin/env bash
# The @polyjose/node suite (feature 0007 T02; ADR 0031 §2, ADR 0034, ADR 0047), run by
# `scripts/test-all.sh node` from the repository root:
#   1. TypeScript only: no hand-written .js, .mjs or .cjs (ADR 0047; the only JavaScript is the
#      napi loader and tsc output, all generated and git-ignored);
#   2. npm ci here (@napi-rs/cli) and in bindings/js (typescript), from the committed lockfiles,
#      with --ignore-scripts: no dependency's install script ever runs (review-code.md N2);
#   3. scripts/build.sh (facade, host addon and loader, tsc);
#   4. the API name check, scripts/check-binding-api.sh node (ADR 0030 §8), on the declarations the
#      build just wrote; it must PASS: after a build, SKIPPED means the check or the build is broken
#      (scripts/test-all.sh also runs it, in its rust step, before any build, where a fresh tree
#      can only skip; feature 0007 B01);
#   5. the rust-core reference run, target/conformance/rust-core.json (cargo test --locked
#      -p polyjose --test conformance, default features, ADR 0034 §4; --locked: review-code.md SF-3): api.test reads Error::CODES from it,
#      and scripts/conformance-parity.sh compares node.json with it;
#   6. node --test over the compiled tests, as an explicit file list (a directory argument fails
#      on Node 24, research §8): dist/<name>.test.js for every test/<name>.test.ts except
#      package.test.ts, which scripts/pack.sh runs on the tarballs it packs (T04).
# Exits non-zero on any failure.
set -euo pipefail
cd "$(dirname "$0")"

echo "==> @polyjose/node: TypeScript only (ADR 0047)"
generated='^\./(binding\.cjs|index\.js|backend\.js)$'
stray=$(find . \( -path ./node_modules -o -path ./dist -o -path ./facade \) -prune -o -type f \
  \( -name '*.js' -o -name '*.mjs' -o -name '*.cjs' \) -print | grep -Ev "$generated" || true)
if [ -n "$stray" ]; then
  echo "hand-written JavaScript in bindings/node (ADR 0047 requires TypeScript):"
  echo "$stray"
  exit 1
fi
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  tracked=$(git ls-files -- '*.js' '*.mjs' '*.cjs')
  if [ -n "$tracked" ]; then echo "tracked JavaScript in bindings/node: $tracked"; exit 1; fi
fi

echo "==> @polyjose/node: npm ci (bindings/node, bindings/js)"
npm ci --ignore-scripts --no-audit --no-fund --loglevel=error
(cd ../js && npm ci --ignore-scripts --no-audit --no-fund --loglevel=error)

echo "==> @polyjose/node: build"
scripts/build.sh

echo "==> @polyjose/node: API names (scripts/check-binding-api.sh node)"
names_rc=0
names=$(cd ../.. && scripts/check-binding-api.sh node </dev/null 2>&1) || names_rc=$?
printf '%s\n' "$names"
names_last=$(printf '%s\n' "$names" | awk 'NF { line = $0 } END { print line }')
case $names_last in
  "check-binding-api: node: PASS ("*) [ "$names_rc" -eq 0 ] || { echo "check-binding-api.sh node exited $names_rc"; exit 1; } ;;
  *) echo "the node API name check did not PASS after the build (FAIL and SKIPPED both fail here)"; exit 1 ;;
esac

echo "==> @polyjose/node: rust-core reference results (ADR 0034 §4)"
(cd ../.. && cargo test --locked --quiet -p polyjose --test conformance)

echo "==> @polyjose/node: node --test (compiled output)"
tests=()
for src in test/*.test.ts; do
  [ -e "$src" ] || { echo "no tests found (test/*.test.ts)"; exit 1; }
  [ "$src" != test/package.test.ts ] || continue # run by scripts/pack.sh on its dist/npm/ tarballs
  name=${src#test/}
  out="dist/${name%.ts}.js"
  [ -f "$out" ] || { echo "$src was not compiled to $out"; exit 1; }
  tests+=("$out")
done
node --test --test-reporter=spec "${tests[@]}"
