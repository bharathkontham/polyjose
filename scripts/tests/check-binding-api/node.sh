#!/usr/bin/env bash
# Tests of the node mode of scripts/check-binding-api.sh (feature 0007 T03; ADR 0030 §2, §5, §8;
# ADR 0031 §2): the names of the generated binding.d.ts and of the package's public index.d.ts must
# equal the inventory, so one renamed export in either fails with exactly that difference; without
# node, without the package or before (or after a stale) build the mode is SKIPPED, never passed.
#
# The cases use the real declarations of the built package (bindings/node/scripts/build.sh), copied
# with the package sources into each case; a case changes the copy only (lib.sh). When the package
# is not built here only the SKIPPED cases run, and a note says so.
#
# Usage: scripts/tests/check-binding-api/node.sh (under /bin/bash 3.2 and bash 5).
set -euo pipefail
export LC_ALL=C
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

pkg=bindings/node
generated="$pkg/binding.d.ts $pkg/facade/api.d.ts $pkg/facade/types.d.ts $pkg/facade/backend.d.ts $pkg/facade/normalize.d.ts $pkg/facade/error-codes.d.ts $pkg/index.d.ts"
built=1
for f in $generated; do [ -f "$repo/$f" ] || built=0; done

# The package's sources, and its generated declarations when built, join the base copy.
(cd "$repo" && tar -cf - $pkg/package.json $pkg/Cargo.toml $pkg/build.rs $pkg/src) | (cd "$base" && tar -xf -) \
  || lib_die "could not copy the bindings/node sources to $base"
if [ "$built" -eq 1 ]; then
  # shellcheck disable=SC2086 # $generated is a list of paths without spaces
  (cd "$repo" && tar -cf - $generated) | (cd "$base" && tar -xf -) || lib_die "could not copy the declarations"
fi

# fresh: makes the case's generated files newer than their sources, in build order (a copy, and
# an edit of one generated file, give files new modification times in no particular order).
fresh() {
  local f
  [ "$built" -eq 1 ] || return 0
  for f in $generated; do touch "$case_dir/$f"; done
}

# node_case <name>: a fresh copy of the base, as if just built.
node_case() { new_case "$1"; fresh; }

# --- Missing inputs ----------------------------------------------------------------------------------

# A PATH with only the tools the main script and the mode need, so node is missing.
nonode=$scratch/bin-nonode
mkdir -p "$nonode" || lib_die "could not create $nonode"
for tool in awk cat cmp comm cp dirname grep mkdir mktemp rm sed sort tr uniq; do
  path=$(command -v "$tool") || lib_die "$tool not found on PATH"
  ln -s "$path" "$nonode/$tool" || lib_die "could not link $tool"
done

node_case no-node
rc=0
(cd "$case_dir" && PATH=$nonode "$BASH" scripts/check-binding-api.sh node) </dev/null >"$scratch/out" 2>&1 || rc=$?
check_last_line "without node the node mode is SKIPPED with the reason" 0 'SKIPPED (node: node missing)'
check_absent "a skipped node mode is not reported as passing" 'PASS'

node_case no-package
rm -rf "${case_dir:?}/$pkg"
run_check node
check_last_line "without bindings/node the node mode is SKIPPED with the reason" 0 'SKIPPED (node: bindings/node missing)'

if ! command -v node >/dev/null 2>&1; then
  echo "note: node missing; the cases that read the declarations did not run"
  finish
  exit
fi

node_case not-built
rm -f "$case_dir/$pkg/binding.d.ts"
run_check node
check_last_line "before the package is built the node mode is SKIPPED with the reason" 0 \
  'SKIPPED (node: bindings/node/binding.d.ts missing (not built: run bindings/node/scripts/build.sh))'
check_absent "an unbuilt package is not reported as passing" 'PASS'

if [ "$built" -eq 0 ]; then
  echo "note: bindings/node is not built (bindings/node/scripts/build.sh); the cases that read its declarations did not run"
  finish
  exit
fi

# --- The real declarations pass ----------------------------------------------------------------------

node_case pass
run_check node
check_last_line "the package's declarations match the inventory" 0 \
  'check-binding-api: node: PASS (32 operations, 13 records, 74 fields, 16 codes)'

# --- A stale build -----------------------------------------------------------------------------------

node_case stale-rust
touch -t 209901010000 "$case_dir/$pkg/src/lib.rs"
run_check node
check_last_line "binding.d.ts older than an adapter source is SKIPPED as stale" 0 \
  'SKIPPED (node: bindings/node/binding.d.ts is older than bindings/node/src/lib.rs (stale build: run bindings/node/scripts/build.sh))'
check_absent "a stale build is not reported as passing" 'PASS'

node_case stale-facade
touch -t 209901010000 "$case_dir/bindings/js/src/types.ts"
run_check node
check_last_line "the shipped facade older than bindings/js/src is SKIPPED as stale" 0 \
  'SKIPPED (node: bindings/node/facade/api.d.ts is older than bindings/js/src/types.ts (stale build: run bindings/node/scripts/build.sh))'

# --- binding.d.ts ------------------------------------------------------------------------------------

node_case renamed-binding-op
edit $pkg/binding.d.ts 'export declare function jwtVerifyWithJwks(' 'export declare function jwtVerifyJwks('
fresh
run_check node
check_diffs "one renamed binding.d.ts export fails as missing and extra" \
  'missing from node (in the inventory): op jwtVerifyWithJwks' \
  'extra in node (not in the inventory): op jwtVerifyJwks'

node_case renamed-field
edit $pkg/binding.d.ts '  keyUse?:' '  keyUsage?:'
fresh
run_check node
check_diffs "a renamed record field fails as missing and extra" \
  'missing from node (in the inventory): field JwkSelector.keyUse?' \
  'extra in node (not in the inventory): field JwkSelector.keyUsage?'

node_case required-to-optional
edit $pkg/binding.d.ts '  signatureIndex: number' '  signatureIndex?: number'
fresh
run_check node
check_diffs "a required field made optional fails" \
  'missing from node (in the inventory): field JwsVerified.signatureIndex' \
  'extra in node (not in the inventory): field JwsVerified.signatureIndex?'

node_case extra-record
append $pkg/binding.d.ts '
export interface JwsPeeked {
  alg: string
  kid?: string
}'
fresh
run_check node
check_diffs "an extra exported interface fails with its fields" \
  'extra in node (not in the inventory): record JwsPeeked' \
  'extra in node (not in the inventory): field JwsPeeked.alg' \
  'extra in node (not in the inventory): field JwsPeeked.kid?'

node_case extra-const
edit $pkg/binding.d.ts 'export declare const __napiBindingTarget' 'export declare const debugKeys: string
export declare const __napiBindingTarget'
fresh
run_check node
check "a binding.d.ts const that is not loader metadata fails" 1 \
  '^check-binding-api: node: binding\.d\.ts:[0-9]+: export debugKeys is neither an operation nor napi loader metadata$' \
  '^check-binding-api: node: FAIL$'

# --- index.d.ts --------------------------------------------------------------------------------------

node_case renamed-index-export
edit $pkg/index.d.ts 'jwtVerifyWithJwks: (' 'jwtVerifyJwks: ('
fresh
run_check node
check "one renamed index.d.ts export fails as missing and extra" 1 \
  '^check-binding-api: node: index\.d\.ts: missing export \(in the inventory or the host idiom\): jwtVerifyWithJwks$' \
  '^check-binding-api: node: index\.d\.ts: extra export \(not in the inventory\): jwtVerifyJwks$' \
  '^check-binding-api: node: FAIL$'

node_case no-error-class
edit $pkg/index.d.ts ', PolyjoseError: typeof import("./facade/api.js").PolyjoseError' ''
fresh
run_check node
check "index.d.ts must export PolyjoseError" 1 \
  '^check-binding-api: node: index\.d\.ts: missing export \(in the inventory or the host idiom\): PolyjoseError$' \
  '^check-binding-api: node: FAIL$'

node_case no-reexport
edit $pkg/index.d.ts 'export type * from "./facade/api.js";' ''
fresh
run_check node
check "index.d.ts must re-export the facade's records" 1 \
  'does not re-export the facade.s records' '^check-binding-api: node: FAIL$'

# --- Codes -------------------------------------------------------------------------------------------

node_case code-order
edit $pkg/facade/error-codes.d.ts '"InvalidBase64", "InvalidJson"' '"InvalidJson", "InvalidBase64"'
fresh
run_check node
check "the shipped ERROR_CODES in another order fail" 1 \
  '^  error codes of node differ from the inventory.s \(same codes, same order\):$' '^check-binding-api: node: FAIL '

finish
