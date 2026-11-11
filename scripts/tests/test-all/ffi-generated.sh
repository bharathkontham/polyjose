#!/usr/bin/env bash
# Test of the `api-names: ffi-generated` step of `scripts/test-all.sh rust` (feature 0013 F05,
# review S4): it runs bindings/ffi/tests/generated-names.sh (feature 0013 T12), the check that the
# UniFFI-generated Kotlin and Swift have every bindings/api-inventory.txt name and that the Swift
# type-checks, under the bash that runs test-all.sh. Its exit status decides PASS or FAIL (exit 2,
# a setup error such as a failed bindgen build, FAILs too); `SKIPPED (<reason>)` on a line of its
# output with exit 0 (no xcrun, so no Swift typecheck) reports SKIPPED with that reason, never PASS
# (pipeline rule 9); any other line starting with SKIPPED FAILs, and so does a missing script.
# The step runs right after the other api-names steps; the rest of the rust block keeps its order
# (rsa-symbols after the builds).
#
# A fixture stands in for generated-names.sh, and rust_fixtures (lib.sh) for cargo and the other
# gate scripts, so no build happens. Each case runs test-all.sh in a copy of the working tree, under
# the bash that runs this test. Usage: scripts/tests/test-all/ffi-generated.sh
set -euo pipefail
export LC_ALL=C
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

names=bindings/ffi/tests/generated-names.sh

# rust_case <name>: a new case with a hermetic rust block whose parity holds.
rust_case() {
  new_case "$1"
  rust_fixtures 0 rust-core rust-surface
  parity_fixture 0 'parity: ok'
}

rust_case pass
# shellcheck disable=SC2016 # expanded by the fixture, not here
fixture_append "$names" 'echo "fixture bash: ${BASH_VERSION:-none}"'
run_test_all rust
check "generated-names.sh exiting 0 passes the step" 0 \
  '^==> api-names: ffi-generated$' '^fixture generated-names ran$' '^  api-names: ffi-generated: PASS$'
check "the script runs under test-all.sh's bash (this test's)" 0 "^fixture bash: ${BASH_VERSINFO[0]}\\."
check_order "the step follows the inventory modes" '^  api-names: surface: ' '^  api-names: ffi-generated: PASS$'
check_order "the step runs before the cargo steps" '^  api-names: ffi-generated: PASS$' '^  rust: PASS$'
check_order "rsa-symbols still follows the wasm builds" '^  wasm32-build-deflate: PASS$' '^  rsa-symbols: PASS$'
check_order "rsa-symbols still follows deps" '^  deps: PASS$' '^  rsa-symbols: PASS$'
check_order "the block's negative tests still come last" '^  rsa-symbols: PASS$' '^  negative: check-test-vectors-off/ok\.sh: PASS$'

rust_case fail
fixture "$names" 1 'generated-names: FAIL: kotlin: inventory entries missing or in another form' 'generated-names: FAIL'
run_test_all rust
check "generated-names.sh exiting 1 FAILs the step and the run" 1 '^  api-names: ffi-generated: FAIL$'

rust_case setup-error
fixture "$names" 2 'generated-names: building the bindgen failed'
run_test_all rust
check "a setup error (exit 2, e.g. the bindgen build failed) FAILs the step" 1 '^  api-names: ffi-generated: FAIL$'

rust_case skipped
fixture "$names" 0 'generated-names: kotlin: all 135 inventory entries present' \
  'SKIPPED (swift typecheck: xcrun not found)' 'generated-names: PASS'
run_test_all rust
check "SKIPPED (<reason>) with exit 0 reports SKIPPED with that reason" 0 \
  '^  api-names: ffi-generated: SKIPPED \(swift typecheck: xcrun not found\)$'
check_absent "a skipped typecheck is not reported as passing" '^  api-names: ffi-generated: PASS$'

rust_case skipped-but-failed
fixture "$names" 1 'SKIPPED (swift typecheck: xcrun not found)' 'generated-names: FAIL'
run_test_all rust
check "a SKIPPED line does not hide a non-zero exit status" 1 '^  api-names: ffi-generated: FAIL$'

rust_case skipped-malformed
fixture "$names" 0 'SKIPPED' 'generated-names: PASS'
run_test_all rust
check "a line starting with SKIPPED but without (<reason>) FAILs" 1 '^  api-names: ffi-generated: FAIL$'

rust_case missing
rm -f "$case_dir/$names"
run_test_all rust
check "a missing generated-names.sh FAILs the step" 1 \
  '^  api-names: ffi-generated: FAIL$' 'generated-names\.sh not found'

finish
