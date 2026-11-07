#!/usr/bin/env bash
# The bindings/js suite (feature 0013 T05; ADR 0031 §1, ADR 0047):
#   1. no hand-written JavaScript: every file we write here is TypeScript;
#   2. npm ci (typescript 7.0.2, the only dev-dependency, from package-lock.json);
#   3. generate src/error-codes.ts from the core's Error::CODES, then tsc (strict, declarations);
#   4. node --test over the compiled tests in dist/ (what ships), never over the sources.
# Exits non-zero on any failure.
set -euo pipefail
cd "$(dirname "$0")"

echo "==> bindings/js: TypeScript only (ADR 0047)"
# find, not only git ls-files: an untracked .js must fail too. tsc output (dist/) and
# node_modules/ are generated.
stray=$(find . \( -path ./node_modules -o -path ./dist \) -prune -o -type f \( -name '*.js' -o -name '*.mjs' -o -name '*.cjs' \) -print)
if [ -n "$stray" ]; then
  echo "hand-written JavaScript in bindings/js (ADR 0047 requires TypeScript):"
  echo "$stray"
  exit 1
fi
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  tracked=$(git ls-files -- '*.js' '*.mjs' '*.cjs')
  if [ -n "$tracked" ]; then echo "tracked JavaScript in bindings/js: $tracked"; exit 1; fi
fi

echo "==> bindings/js: npm ci"
npm ci --no-audit --no-fund --loglevel=error

echo "==> bindings/js: build (generate ErrorCode, tsc)"
node tools/gen-error-codes.ts
rm -rf dist
npx --no-install tsc -p .

echo "==> bindings/js: node --test (compiled output)"
node --test --test-reporter=spec 'dist/test/**/*.test.js'
