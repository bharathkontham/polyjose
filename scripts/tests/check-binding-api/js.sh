#!/usr/bin/env bash
# Negative tests of the js mode of scripts/check-binding-api.sh (feature 0013 T13; ADR 0030 §2,
# §8; ADR 0047): the names in the tsc-generated declarations of bindings/js must equal the
# inventory, so an extra or renamed operation, record or field in the TypeScript sources fails
# with exactly that difference; a tsc error fails; without node, npm or the sources the mode is
# SKIPPED, never passed.
#
# Each case builds the copy's declarations with the real tsc (lib.sh). Without node and npm on
# PATH only the SKIPPED cases run.
#
# Usage: scripts/tests/check-binding-api/js.sh (under /bin/bash 3.2 and bash 5).
set -euo pipefail
export LC_ALL=C
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

api=bindings/js/src/api.ts
types=bindings/js/src/types.ts

# facade_only: removes the facade's tests and conformance runner from the copy. A case whose change
# they would no longer compile against (a rename, a required flag) stands for a change made
# consistently everywhere, so tsc passes and only the name check can catch it.
facade_only() { rm -rf "${case_dir:?}/bindings/js/test" "${case_dir:?}/bindings/js/conformance"; }

# --- Missing inputs ----------------------------------------------------------------------------------

# A PATH with only the tools the main script needs, so node and npm are missing.
nonode=$scratch/bin-nonode
mkdir -p "$nonode" || lib_die "could not create $nonode"
for tool in awk cat cmp comm cp dirname grep mkdir mktemp rm sed sort tr uniq; do
  path=$(command -v "$tool") || lib_die "$tool not found on PATH"
  ln -s "$path" "$nonode/$tool" || lib_die "could not link $tool"
done

new_case no-node
rc=0
(cd "$case_dir" && PATH=$nonode "$BASH" scripts/check-binding-api.sh js) </dev/null >"$scratch/out" 2>&1 || rc=$?
check_last_line "without node the js mode is SKIPPED with the reason" 0 'SKIPPED (js: node missing)'
check_absent "a skipped js mode is not reported as passing" 'PASS'

new_case no-sources
rm -rf "${case_dir:?}/bindings/js"
run_check js
check_last_line "without bindings/js the js mode is SKIPPED with the reason" 0 \
  'SKIPPED (js: bindings/js/package.json missing)'

if ! command -v node >/dev/null 2>&1 || ! command -v npm >/dev/null 2>&1; then
  echo "note: node or npm missing; the cases that build the declarations did not run"
  finish
  exit
fi

# --- The real sources pass ---------------------------------------------------------------------------

new_case pass
use_js_modules
run_check js
check_last_line "the facade's declarations match the inventory" 0 \
  'check-binding-api: js: PASS (32 operations, 13 records, 74 fields, 16 codes)'
dist_ok=1
[ ! -e "$case_dir/bindings/js/dist" ] || dist_ok=0
report "the declarations are built in the mode's scratch directory, not bindings/js/dist" "$dist_ok" \
  "the check wrote bindings/js/dist"

# --- Operations --------------------------------------------------------------------------------------

new_case extra-op
use_js_modules
edit $api '  jwkToDer(jwk: Jwk, format: KeyFormat): Promise<Uint8Array>;' \
  '  jwkToDer(jwk: Jwk, format: KeyFormat): Promise<Uint8Array>;
  jwkPeek?(jwk: Jwk): Promise<string>;'
run_check js
check_diffs "an extra PolyjoseApi member fails" 'extra in js (not in the inventory): op jwkPeek'

new_case renamed-op
use_js_modules
# The interface member and createApi's implementation (facade_only).
edit $api '  jwtVerifyWithJwks(token: string,' '  jwtVerifyJwks(token: string,'
edit $api '    jwtVerifyWithJwks: async (' '    jwtVerifyJwks: async ('
facade_only
run_check js
check_diffs "a renamed operation fails as missing and extra" \
  'missing from js (in the inventory): op jwtVerifyWithJwks' \
  'extra in js (not in the inventory): op jwtVerifyJwks'

# --- Records and fields ------------------------------------------------------------------------------

new_case renamed-field
use_js_modules
edit $types '  keyUse?: string | undefined;' '  keyUsage?: string | undefined;'
run_check js
check_diffs "a renamed record field fails as missing and extra" \
  'missing from js (in the inventory): field JwkSelector.keyUse?' \
  'extra in js (not in the inventory): field JwkSelector.keyUsage?'

new_case required-to-optional
use_js_modules
edit $types '  signatureIndex: number;' '  signatureIndex?: number;'
run_check js
check_diffs "a required field made optional fails" \
  'missing from js (in the inventory): field JwsVerified.signatureIndex' \
  'extra in js (not in the inventory): field JwsVerified.signatureIndex?'

new_case flag-required
use_js_modules
edit $types '  compress?: boolean | undefined;' '  compress: boolean;'
facade_only
run_check js
check_diffs "a flag must be optional in TypeScript (absent is false)" \
  'missing from js (in the inventory): field JweEncryptOptions.compress?' \
  'extra in js (not in the inventory): field JweEncryptOptions.compress'

new_case extra-record
use_js_modules
append $types '
/** Not in the inventory. */
export interface JwsPeeked {
  alg: string;
  kid?: string;
}'
run_check js
check_diffs "an extra exported interface fails with its fields" \
  'extra in js (not in the inventory): record JwsPeeked' \
  'extra in js (not in the inventory): field JwsPeeked.alg' \
  'extra in js (not in the inventory): field JwsPeeked.kid?'

new_case extra-api-interface
use_js_modules
edit $api 'export interface PolyjoseApi {' '/** Not in the inventory. */
export interface InitOptions {
  wasmUrl?: string;
}

export interface PolyjoseApi {'
run_check js
check_diffs "an interface exported from api.ts counts as a record too" \
  'extra in js (not in the inventory): record InitOptions' \
  'extra in js (not in the inventory): field InitOptions.wasmUrl?'

# --- Build and declaration failures ------------------------------------------------------------------

new_case tsc-error
use_js_modules
edit $types '  alg: string;
  payload: Uint8Array;' '  alg: string;
  payload: Uint8Array;
  broken: NoSuchType;'
run_check js
check "a TypeScript error fails the mode" 1 'error TS' '^check-binding-api: js: tsc failed in bindings/js$' '^check-binding-api: js: FAIL$'

new_case no-reexport
use_js_modules
edit $api 'export type * from "./types.js";' ''
facade_only
run_check js
check "api.ts must re-export the records" 1 'does not re-export the records' '^check-binding-api: js: FAIL$'

finish
