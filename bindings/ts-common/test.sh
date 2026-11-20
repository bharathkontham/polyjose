#!/usr/bin/env bash
# The bindings/js suite (feature 0013 T05; ADR 0031 §1, ADR 0047):
#   1. no hand-written JavaScript: every file we write here is TypeScript;
#   2. npm ci (typescript 7.0.2, the only dev-dependency, from package-lock.json);
#   3. generate src/error-codes.ts from the core's Error::CODES, then tsc (strict, declarations);
#   4. declarations are tsc output only; the test/misuse/ project must FAIL to type-check
#      against them, each file with its expected diagnostic (a JWS or JWT verify without
#      allowedAlgs, a compact or JSON JWE decrypt without allowedEnc);
#   5. node --test over the compiled tests in dist/ (what ships), never over the sources.
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

echo "==> bindings/js: declarations are generated, never hand-written (ADR 0047)"
handdts=$(find . \( -path ./node_modules -o -path ./dist \) -prune -o -type f \( -name '*.d.ts' -o -name '*.d.mts' -o -name '*.d.cts' \) -print)
if [ -n "$handdts" ]; then echo "hand-written declarations in bindings/js: $handdts"; exit 1; fi
[ -f dist/src/api.d.ts ] && [ -f dist/src/api.d.ts.map ] || { echo "tsc did not generate dist/src/api.d.ts(.map)"; exit 1; }

echo "==> bindings/js: misuse must not type-check (against the generated .d.ts)"
# Every test/misuse/*.ts holds exactly one misuse and names its diagnostic in
# '// expect-error: <text>' lines; the project must fail with exactly one error per file.
files=(test/misuse/*.ts)
[ -e "${files[0]}" ] || { echo "no misuse files found (test/misuse/*.ts)"; exit 1; }
if out=$(npx --no-install tsc -p test/misuse/tsconfig.json 2>&1); then
  echo "test/misuse type-checked, but every file in it must fail"; exit 1
fi
errors=$(grep -c 'error TS' <<<"$out" || true)
if [ "$errors" -ne "${#files[@]}" ]; then
  echo "test/misuse: expected ${#files[@]} error(s), got $errors:"; echo "$out"; exit 1
fi
for f in "${files[@]}"; do
  want=$(sed -n 's|^// expect-error: ||p' "$f")
  [ -n "$want" ] || { echo "$f: no '// expect-error:' line"; exit 1; }
  while IFS= read -r line; do
    grep -qF -- "$line" <<<"$out" || { echo "$f: expected a diagnostic containing: $line"; echo "$out"; exit 1; }
  done <<<"$want"
done

echo "==> bindings/js: node --test (compiled output)"
node --test --test-reporter=spec 'dist/test/**/*.test.js'
