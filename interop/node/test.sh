#!/usr/bin/env bash
# Two-way interop of @polyjose/node with panva/jose 6.x (feature 0010 I1), run by
# `scripts/test-all.sh node` as its interop-jose step, from the repository root or anywhere:
#   1. TypeScript only: no .js, .mjs or .cjs here outside node_modules (ADR 0047);
#   2. @polyjose/node from this tree: bindings/node/scripts/build.sh, idempotent, so after
#      bindings/node/test.sh it reuses that build (cargo and the addon are up to date) and on its
#      own it builds the package first; never the registry package;
#   3. npm ci --ignore-scripts here, from the committed lockfile: jose only, no install scripts;
#   4. tsc --noEmit with bindings/js's compiler and options (tsconfig.json);
#   5. node --test over interop.test.ts, with Node's built-in type stripping (Node >= 24).
# Prints `SKIPPED (<reason>)` as its last line and exits 0 when node, npm or cargo is missing;
# exits non-zero on any failure.
set -euo pipefail
cd "$(dirname "$0")"

for tool in node npm cargo; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "SKIPPED ($tool missing)"
    exit 0
  fi
done

echo "==> interop-jose: TypeScript only (ADR 0047)"
stray=$(find . -path ./node_modules -prune -o -type f \( -name '*.js' -o -name '*.mjs' -o -name '*.cjs' \) -print)
if [ -n "$stray" ]; then
  echo "JavaScript in interop/node (ADR 0047 requires TypeScript):"
  echo "$stray"
  exit 1
fi

echo "==> interop-jose: build @polyjose/node from this tree (bindings/node/scripts/build.sh)"
../../bindings/node/scripts/build.sh

echo "==> interop-jose: npm ci (jose, from package-lock.json)"
npm ci --ignore-scripts --no-audit --no-fund --loglevel=error

echo "==> interop-jose: tsc --noEmit"
../../bindings/js/node_modules/.bin/tsc -p tsconfig.json

echo "==> interop-jose: node --test (jose $(node -p 'require("./node_modules/jose/package.json").version'))"
node --test --test-reporter=spec interop.test.ts
