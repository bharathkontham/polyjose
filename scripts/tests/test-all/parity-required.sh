#!/usr/bin/env bash
# Test of the results-file rule of scripts/test-all.sh's parity step (feature 0013 F05, review S3;
# ADR 0034 §2, §5): a platform that reported PASS must have written a results file for each runner
# its line of the runner table (`results_runners`) names, as target/conformance/<runner>.json or
# <runner>-<suffix>.json; otherwise parity FAILs, naming the runner. When the rust platform ran and
# rust-core.json (the reference; rust-core-<features>.json is not it) is missing, parity FAILs
# instead of being SKIPPED. A SKIPPED platform, and a platform whose line is empty (its binding
# feature has not added its runners yet), is never required to have a file; a platform with no
# line at all FAILs, so every platform's entry is explicit.
#
# The cases edit the runner table of the copy (set_runners), so they hold whatever the real table
# says. Fixture platform scripts and a fixture parity script stand in for the real ones, and the
# rust cases use rust_fixtures (a cargo stub, no build). Each case runs test-all.sh in a copy of the
# working tree, under the bash that runs this test (lib.sh). Usage: scripts/tests/test-all/parity-required.sh
set -euo pipefail
export LC_ALL=C
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

# reference_by_wasm: a passing wasm fixture that writes the reference, so parity has rust-core.json
# without running the rust platform.
reference_by_wasm() {
  set_runners wasm
  fixture bindings/wasm/test.sh 0 'fixture wasm suite ran'
  writes_results bindings/wasm/test.sh rust-core
}

# --- A passing platform must have written its runners' files ------------------------------------------

new_case required-missing
reference_by_wasm
set_runners node node
fixture bindings/node/test.sh 0 'fixture node suite ran'
parity_fixture 0 'SKIPPED (no results: node)' 'parity: ok'
run_test_all wasm node
check "a passing platform without its runner's results file FAILs parity and the run" 1 \
  '^  node: PASS$' '^  parity: FAIL$' '^    FAIL \(no results: node; the node platform passed\)$' \
  '^parity: the node platform passed but wrote no results file for runner node \(target/conformance/node\.json or node-<suffix>\.json\)$'
check "the parity script still runs and reports its own findings" 1 '^parity fixture args: target/conformance$'
check_absent "the runner is not also listed as SKIPPED" '^    SKIPPED \(no results: node\)$'

new_case required-present
reference_by_wasm
set_runners node node
fixture bindings/node/test.sh 0 'fixture node suite ran'
writes_results bindings/node/test.sh node
parity_fixture 0 'parity: ok'
run_test_all wasm node
check "a passing platform with its results file passes" 0 '^  node: PASS$' '^  parity: PASS$'
check_absent "no runner is reported missing" 'no results file|^    FAIL \(no results'

new_case required-suffix
reference_by_wasm
set_runners node node
fixture bindings/node/test.sh 0 'fixture node suite ran'
writes_results bindings/node/test.sh node-x86_64-unknown-linux-musl
parity_fixture 0 'parity: ok'
run_test_all wasm node
check "<runner>-<suffix>.json (a CI matrix run) counts as the runner's file" 0 '^  parity: PASS$'

new_case required-other-runner
reference_by_wasm
set_runners node node
fixture bindings/node/test.sh 0 'fixture node suite ran'
writes_results bindings/node/test.sh wasm-node nodejs
parity_fixture 0 'parity: ok'
run_test_all wasm node
check "another runner's file, or a name that only starts with the runner's, does not count" 1 \
  '^  parity: FAIL$' '^    FAIL \(no results: node; the node platform passed\)$'

new_case required-multi
reference_by_wasm
set_runners android jvm android-emulator
fixture platforms/android/test.sh 0 'fixture android suite ran'
writes_results platforms/android/test.sh jvm
parity_fixture 0 'parity: ok'
run_test_all wasm android
check "each runner of the platform's line is required" 1 \
  '^  parity: FAIL$' '^    FAIL \(no results: android-emulator; the android platform passed\)$'
check_absent "a runner that wrote its file is not reported" 'no results: jvm'

new_case no-reference-required-missing
set_runners node node
fixture bindings/node/test.sh 0 'fixture node suite ran'
parity_fixture 0 'parity: ok'
run_test_all node
check "without the reference, a missing required file still FAILs parity" 1 \
  '^  parity: FAIL$' '^    FAIL \(no results: node; the node platform passed\)$'
check_absent "parity is not SKIPPED when a required file is missing" '^  parity: SKIPPED'

new_case no-script-required-missing
reference_by_wasm
set_runners node node
fixture bindings/node/test.sh 0 'fixture node suite ran'
rm -f "$case_dir/scripts/conformance-parity.sh"
run_test_all wasm node
check "without the parity script, a missing required file still FAILs parity" 1 \
  '^  parity: FAIL$' '^    FAIL \(no results: node; the node platform passed\)$'

# --- What is never required ---------------------------------------------------------------------------

new_case skipped-platform
reference_by_wasm
set_runners apple swift-macos swift-ios-sim
fixture platforms/swift/test.sh 0 'SKIPPED (iOS 27.2 simulator missing)'
parity_fixture 0 'parity: ok'
run_test_all wasm apple
check "a SKIPPED platform without a results file is not a failure" 0 \
  '^  apple: SKIPPED \(iOS 27\.2 simulator missing\)$' '^  parity: PASS$'
check_absent "a SKIPPED platform's runners are not reported missing" '^    FAIL \(no results'

new_case failed-platform
reference_by_wasm
set_runners node node
fixture bindings/node/test.sh 1 'fixture node suite failed'
parity_fixture 0 'parity: ok'
run_test_all wasm node
check "a FAILed platform fails the run by itself; parity does not require its files" 1 \
  '^  node: FAIL$' '^  parity: PASS$'

new_case empty-entry
reference_by_wasm
set_runners node
fixture bindings/node/test.sh 0 'fixture node suite ran'
parity_fixture 0 'parity: ok'
run_test_all wasm node
check "a platform whose line is empty is not checked yet" 0 '^  node: PASS$' '^  parity: PASS$'

new_case no-table-line
reference_by_wasm
remove_runner_line node
fixture bindings/node/test.sh 0 'fixture node suite ran'
parity_fixture 0 'parity: ok'
run_test_all wasm node
check "a platform with no line in the runner table FAILs parity" 1 \
  '^  parity: FAIL$' '^    FAIL \(no line for node in the runner table\)$'

# --- The rust platform and the reference --------------------------------------------------------------

new_case rust-pass
rust_fixtures 0 rust-core rust-surface
set_runners rust rust-core rust-surface
parity_fixture 0 'parity: ok'
run_test_all rust
check "rust writing rust-core.json and rust-surface.json passes parity" 0 \
  '^  rust: PASS$' '^  parity: PASS$' \
  '^parity fixture saw: rust-core-deflate-fixed-rng\.json rust-core\.json rust-surface\.json $'

new_case rust-no-reference
rust_fixtures 0 rust-surface
set_runners rust rust-core rust-surface
parity_fixture 0 'parity: ok'
run_test_all rust
check "rust passed without rust-core.json: parity FAILs (rust-core-<features>.json is not the reference)" 1 \
  '^  rust: PASS$' '^  parity: FAIL$' '^    FAIL \(no results: rust-core; the rust platform passed\)$'
check_absent "parity is not SKIPPED when rust ran" '^  parity: SKIPPED'
check_absent "the parity script does not run without the reference" '^parity fixture'

new_case rust-no-surface
rust_fixtures 0 rust-core
set_runners rust rust-core rust-surface
parity_fixture 0 'parity: ok'
run_test_all rust
check "rust passed without rust-surface.json: parity FAILs" 1 \
  '^  parity: FAIL$' '^    FAIL \(no results: rust-surface; the rust platform passed\)$'

new_case rust-failed
rust_fixtures 1
set_runners rust rust-core rust-surface
parity_fixture 0 'parity: ok'
run_test_all rust
check "rust ran and failed without rust-core.json: parity FAILs, not SKIPPED" 1 \
  '^  rust: FAIL$' '^  parity: FAIL$' '^    FAIL \(no results: rust-core; the rust platform ran\)$'
check_absent "parity is not SKIPPED when rust ran and failed" '^  parity: SKIPPED'

finish
