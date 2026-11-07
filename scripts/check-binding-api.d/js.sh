# shellcheck shell=bash
# shellcheck disable=SC2034,SC2154 # sourced by scripts/check-binding-api.sh, which reads MODE_KINDS
# and sets repo, mode_scratch and camel_awk
# Mode "js" of scripts/check-binding-api.sh: the TypeScript facade bindings/js, shared unchanged by
# @polyjose/node and @polyjose/wasm (ADR 0031 §1). Its public contract is the tsc-generated
# declarations (ADR 0047: there is no hand-written index.d.ts), so this mode builds them first:
#   1. npm ci in bindings/js if its node_modules has no tsc (typescript, the only dev-dependency,
#      pinned in package-lock.json), as bindings/js/test.sh does;
#   2. node tools/gen-error-codes.ts (writes the git-ignored src/error-codes.ts from Error::CODES);
#   3. tsc -p . --emitDeclarationOnly into this mode's scratch directory (bindings/js/dist/ is
#      left alone).
# Without node or npm the mode is SKIPPED, never passed.
#
# It then reads, as text (tsc writes one member per line, indented by four spaces):
#   - operations: the members of `export interface PolyjoseApi` in dist/src/api.d.ts, the object
#     createApi returns and each package's entry spreads into its exports (ADR 0031 §1);
#   - records: every other `export interface` of dist/src/api.d.ts and dist/src/types.d.ts, with
#     its members as fields (`name?:` is optional); api.d.ts must re-export the records
#     (`export type * from "./types.js"`);
#   - codes: the ERROR_CODES tuple of dist/src/error-codes.d.ts, in order (ADR 0030 §5);
#   - and that api.d.ts exports `class PolyjoseError` (ADR 0030 §5).
# In TypeScript a flag is an optional boolean (`detached?: boolean`, absent is false), so
# mode_expect reads the inventory's `= false` fields as optional.
#
# JS_IDIOM lists the facade's names that are host idiom, not inventory entries (ADR 0030 §1, §2,
# §5): the PolyjoseApi container itself, its `PolyjoseError` member, and the plain-object JSON
# types a JS caller may pass instead of JSON text. Adding a name here is a review decision.

MODE_KINDS="op record field code"
JS_IDIOM="PolyjoseApi PolyjoseApi.PolyjoseError JsonObject JwkObject JwkSetObject"

mode_expect() { sed 's/=false$/?/'; }

mode_derive() {
  local out=$1 js=$repo/bindings/js dist=$mode_scratch/dist f
  for f in package.json package-lock.json tsconfig.json tools/gen-error-codes.ts src/api.ts src/types.ts; do
    [ -f "$js/$f" ] || skip "bindings/js/$f missing"
  done
  command -v node >/dev/null 2>&1 || skip "node missing"
  command -v npm >/dev/null 2>&1 || skip "npm missing"
  if [ ! -x "$js/node_modules/.bin/tsc" ]; then
    (cd "$js" && npm ci --no-audit --no-fund --loglevel=error) >"$mode_scratch/npm.log" 2>&1 \
      || { cat "$mode_scratch/npm.log"; mode_fail "npm ci failed in bindings/js"; }
  fi
  (cd "$js" && node tools/gen-error-codes.ts) >"$mode_scratch/gen.log" 2>&1 \
    || { cat "$mode_scratch/gen.log"; mode_fail "node tools/gen-error-codes.ts failed in bindings/js"; }
  (cd "$js" && ./node_modules/.bin/tsc -p . --outDir "$dist" --emitDeclarationOnly --declarationMap false) \
    >"$mode_scratch/tsc.log" 2>&1 || { cat "$mode_scratch/tsc.log"; mode_fail "tsc failed in bindings/js"; }
  for f in api.d.ts types.d.ts error-codes.d.ts; do
    [ -f "$dist/src/$f" ] || mode_fail "tsc did not generate src/$f"
  done
  cat >"$mode_scratch/js.awk" <<'AWK'
BEGIN { n = split(idiom, t, " "); for (i = 1; i <= n; i++) other[t[i]] = 1 }
function base(f) { sub(/.*\//, "", f); return f }
FNR == 1 { block = ""; inblock = 0; file = base(FILENAME) }
inblock && /^}/ { inblock = 0; next }
inblock && block == "" { next }
inblock {
  if ($0 ~ /^    (readonly )?[A-Za-z_$][A-Za-z0-9_$]*\??[(<:]/) {
    name = $0; sub(/^    (readonly )?/, "", name)
    opt = (name ~ /^[A-Za-z0-9_$]*\?/) ? "?" : ""
    sub(/[^A-Za-z0-9_$].*/, "", name)
    if ((block "." name) in other) next
    if (block == "PolyjoseApi") print "op " name
    else if (block != "") print "field " block "." name opt
  } else if ($0 !~ /^    (\/\*\*|\*|\/\/|\[)/ && $0 !~ /^     \*/) {
    print "error " file ":" FNR ": cannot read this member of " block ": " $0
  }
  next
}
(file == "api.d.ts" || file == "types.d.ts") && /^export (declare )?interface [A-Za-z_$][A-Za-z0-9_$]*/ {
  name = $0; sub(/^export (declare )?interface /, "", name); sub(/[^A-Za-z0-9_$].*/, "", name)
  block = (name in other && name != "PolyjoseApi") ? "" : name
  if (block != "" && block != "PolyjoseApi") print "record " name
  if (name == "PolyjoseApi") api = 1
  inblock = ($0 ~ /\{[ \t]*$/)
  next
}
file == "api.d.ts" && /^export declare class PolyjoseError extends Error/ { error_class = 1 }
file == "api.d.ts" && /^export type \* from "\.\/types\.js";/ { reexport = 1 }
file == "error-codes.d.ts" { codes_text = codes_text " " $0 }
END {
  if (!api) print "error api.d.ts: no export interface PolyjoseApi (the operations)"
  if (!error_class) print "error api.d.ts: does not export class PolyjoseError (ADR 0030 §5)"
  if (!reexport) print "error api.d.ts: does not re-export the records (export type * from \"./types.js\")"
  if (!match(codes_text, /ERROR_CODES: readonly \[[^]]*\]/)) { print "error error-codes.d.ts: no ERROR_CODES tuple"; exit }
  list = substr(codes_text, RSTART, RLENGTH)
  while (match(list, /"[^"]*"/)) { print "code " substr(list, RSTART + 1, RLENGTH - 2); list = substr(list, RSTART + RLENGTH) }
}
AWK
  awk -v idiom="$JS_IDIOM" -f "$mode_scratch/js.awk" "$dist/src/api.d.ts" "$dist/src/types.d.ts" "$dist/src/error-codes.d.ts" >"$out" || return 1
}
