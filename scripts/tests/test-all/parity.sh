#!/usr/bin/env bash
# Test of the conformance parity wiring of scripts/test-all.sh (feature 0013 T04, ADR 0034 §5):
# before the platform suites test-all.sh clears target/conformance/, so a results file left by an
# earlier run never counts; after them it runs scripts/conformance-parity.sh (feature 0013 T02) on
# target/conformance when target/conformance/rust-core.json exists, and adds `parity: PASS|FAIL` to
# the summary with the parity script's `SKIPPED (no results: <runner>)` lines under it. Without the
# reference file or the script, parity is reported SKIPPED, never as passing (pipeline rule 9).
#
# A fixture platform script stands in for the runners that write results files (the rust platform
# writes rust-core.json; running it here would build the workspace), and a fixture parity script for
# T02's, so the test does not depend on either. Usage: scripts/tests/test-all/parity.sh
set -euo pipefail
export LC_ALL=C
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

# --- Parity runs after the platform suites --------------------------------------------------------------

new_case pass
fixture bindings/wasm/test.sh 0 'fixture wasm suite ran'
writes_results bindings/wasm/test.sh rust-core
writes_own_results bindings/wasm/test.sh wasm
fixture platforms/android/test.sh 0 'fixture android suite ran'
writes_own_results platforms/android/test.sh android
parity_fixture 0 'SKIPPED (no results: node)' 'SKIPPED (no results: swift-macos)' 'parity: 6 runners match rust-core'
run_test_all wasm android
check "parity runs when rust-core.json exists and passes on exit 0" 0 \
  '^  wasm: PASS$' '^  android: PASS$' '^  parity: PASS$' \
  '^    SKIPPED \(no results: node\)$' '^    SKIPPED \(no results: swift-macos\)$' \
  '^parity fixture args: target/conformance$' '^parity fixture saw: .*jvm\.json rust-core\.json .*wasm-node\.json '
check_order "parity runs after every platform suite" '^fixture android suite ran$' '^==> parity$'
check_order "the parity line follows the platform lines in the summary" '^  android: PASS$' '^  parity: PASS$'
check_order "the SKIPPED runner lines follow the parity line" '^  parity: PASS$' '^    SKIPPED \(no results: node\)$'
tests_run=$((tests_run + 1))
if [ "$(grep -c '^==> parity$' "$scratch/out")" -eq 1 ]; then echo "ok   - parity runs once per test-all.sh run"
else echo "FAIL - parity runs once per test-all.sh run"; tests_failed=$((tests_failed + 1)); fi

new_case fail
fixture bindings/wasm/test.sh 0 'fixture wasm suite ran'
writes_results bindings/wasm/test.sh rust-core
writes_own_results bindings/wasm/test.sh wasm
parity_fixture 1 'SKIPPED (no results: node)' 'wasm-node.json#3: rust-core ok, wasm-node AlgorithmNotAllowed'
run_test_all wasm
check "a parity script that exits non-zero FAILs parity and the run" 1 \
  '^  wasm: PASS$' '^  parity: FAIL$' '^    SKIPPED \(no results: node\)$'

# --- Stale results never count --------------------------------------------------------------------------

new_case stale
mkdir -p "$case_dir/target/conformance"
echo '{}' >"$case_dir/target/conformance/rust-core.json"
echo '{}' >"$case_dir/target/conformance/node.json"
fixture platforms/android/test.sh 0 'fixture android suite ran'
writes_own_results platforms/android/test.sh android
parity_fixture 0 'parity: ok'
run_test_all android
check "results left by an earlier run are cleared, so parity has no reference" 0 \
  '^  android: PASS$' '^  parity: SKIPPED \(no reference results: target/conformance/rust-core\.json'
check_absent "parity does not run on stale results" '^parity fixture'
tests_run=$((tests_run + 1))
if [ ! -e "$case_dir/target/conformance" ]; then echo "ok   - target/conformance/ is removed before the suites"
else echo "FAIL - target/conformance/ still exists: $(ls "$case_dir/target/conformance")"; tests_failed=$((tests_failed + 1)); fi

new_case stale-mixed
mkdir -p "$case_dir/target/conformance"
echo '{}' >"$case_dir/target/conformance/node.json"
fixture bindings/wasm/test.sh 0 'fixture wasm suite ran'
writes_results bindings/wasm/test.sh rust-core
writes_own_results bindings/wasm/test.sh wasm
parity_fixture 0 'parity: ok'
run_test_all wasm
check "only this run's results files reach the parity check" 0 '^  parity: PASS$' '^parity fixture saw: rust-core\.json wasm-'
check_absent "a results file left by an earlier run is not seen" '^parity fixture saw: (.* )?node\.json'

# --- Missing pieces are SKIPPED or FAIL, never PASS ----------------------------------------------------

new_case no-reference
fixture bindings/wasm/test.sh 0 'fixture wasm suite ran'
writes_own_results bindings/wasm/test.sh wasm
parity_fixture 0 'parity: ok'
run_test_all wasm
check "without rust-core.json parity is SKIPPED" 0 '^  parity: SKIPPED \(no reference results: target/conformance/rust-core\.json'
check_absent "parity does not run without the reference" '^parity fixture'

new_case no-script
fixture bindings/wasm/test.sh 0 'fixture wasm suite ran'
writes_results bindings/wasm/test.sh rust-core
writes_own_results bindings/wasm/test.sh wasm
rm -f "$case_dir/scripts/conformance-parity.sh"
run_test_all wasm
check "without scripts/conformance-parity.sh parity is SKIPPED" 0 \
  '^  parity: SKIPPED \(scripts/conformance-parity\.sh missing\)$'

new_case not-executable
fixture bindings/wasm/test.sh 0 'fixture wasm suite ran'
writes_results bindings/wasm/test.sh rust-core
writes_own_results bindings/wasm/test.sh wasm
parity_fixture 0 'parity: ok'
chmod -x "$case_dir/scripts/conformance-parity.sh"
run_test_all wasm
check "a parity script that is not executable FAILs" 1 '^  parity: FAIL$' 'conformance-parity\.sh exists but is not an executable file'

finish
