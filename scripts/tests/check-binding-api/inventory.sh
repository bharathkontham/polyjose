#!/usr/bin/env bash
# Negative tests of the inventory checks of scripts/check-binding-api.sh (feature 0013 T13; ADR 0030
# §5, §8): bindings/api-inventory.txt must parse, and its code list must equal polyjose::Error::CODES
# in crates/polyjose/src/error.rs, same codes and same order. Both checks run before any mode.
#
# Usage: scripts/tests/check-binding-api/inventory.sh (under /bin/bash 3.2 and bash 5).
set -euo pipefail
export LC_ALL=C
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

inv=bindings/api-inventory.txt
err=crates/polyjose/src/error.rs

# --- Error codes against the core --------------------------------------------------------------------

new_case codes-pass
run_check surface
check "the inventory's codes equal Error::CODES" 0 '^check-binding-api: surface: PASS '
check_absent "no inventory failure" 'inventory: FAIL'

new_case codes-order
edit $inv 'code TokenExpired
code TokenNotYetValid' 'code TokenNotYetValid
code TokenExpired'
run_check surface
check "codes in another order fail (the order is the core's)" 1 \
  "the inventory's error codes differ from polyjose::Error::CODES" '^check-binding-api: inventory: FAIL$'
check_absent "no mode runs after an inventory failure" 'surface: (PASS|FAIL)'

new_case codes-missing-last
edit $inv 'code NoMatchingKey
' ''
run_check surface
check "an inventory without NoMatchingKey fails" 1 \
  "the inventory's error codes differ" '^  core: .* InvalidFormat NoMatchingKey $'

new_case core-new-code
edit $err '        "NoMatchingKey",
    ];' '        "NoMatchingKey",
        "TokenReplayed",
    ];'
run_check surface
check "a code added to the core but not to the inventory fails" 1 \
  "the inventory's error codes differ" '^  core: .* NoMatchingKey TokenReplayed $'

new_case core-no-codes
edit $err 'pub const CODES: &' 'pub const ALL_CODES: &'
run_check surface
check "an error.rs without the CODES block fails" 1 'no Error::CODES block' '^check-binding-api: inventory: FAIL$'

# --- The inventory's format --------------------------------------------------------------------------

new_case unknown-keyword
edit $inv 'op version' 'operation version'
run_check surface
check "an unknown keyword fails with its line number" 1 \
  '^  bindings/api-inventory\.txt:[0-9]+: unknown entry \(op, record, field or code\): operation version$' \
  'is malformed'

new_case bad-op-name
edit $inv 'op version' 'op Version'
run_check surface
check "an operation not in camelCase fails" 1 'op needs a camelCase name: op Version'

new_case snake-field
edit $inv '  field keyUse?' '  field key_use?'
run_check surface
check "a snake_case field fails" 1 'field needs a camelCase name, then \? or = false: field key_use\?'

new_case flag-true
edit $inv '  field detached = false' '  field detached = true'
run_check surface
check "a flag other than = false fails" 1 'field needs a camelCase name, then \? or = false: field detached = true'

new_case field-outside-record
edit $inv 'op version' 'field version
op version'
run_check surface
check "a field before any record fails" 1 'field outside a record: field version'

new_case duplicate-op
edit $inv 'op jwkToDer' 'op jwkToDer
op jwkToDer'
run_check surface
check "a duplicate operation fails" 1 'duplicate entry: op jwkToDer'

new_case duplicate-field
edit $inv '  field keyUse?' '  field keyUse?
  field keyUse'
run_check surface
check "a field listed twice (even with another marker) fails" 1 'duplicate entry: field JwkSelector\.keyUse'

new_case comments-and-layout
edit $inv 'op version' '   # an indented comment

	op version   '
run_check surface
check "comments, blank lines and surrounding whitespace are layout only" 0 '^check-binding-api: surface: PASS '

new_case no-inventory
rm "$case_dir/$inv"
run_check surface
check "a missing inventory fails, it never skips" 1 'bindings/api-inventory\.txt missing' 'inventory: FAIL'

finish
