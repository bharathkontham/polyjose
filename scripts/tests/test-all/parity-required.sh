#!/usr/bin/env bash
# Test of the results-file rule of scripts/test-all.sh's parity step (feature 0013 F05, review S3;
# ADR 0034 §2, §5). The runner table (`results_runners`) gives each platform its runners: a plain
# name is required, a trailing `?` marks a runner that is optional on a host. A platform that reported
# PASS must have written target/conformance/<runner>.json or <runner>-<suffix>.json for each runner
# on its line, except an optional runner its own script waived with the line
# `SKIPPED-RUNNER (<runner>: host:<token>)`, which is reported SKIPPED under parity. Otherwise parity
# FAILs, naming the runner, and so does a declared skip of a required runner, a declaration with
# another reason or form, and one for a runner not on the platform's line. When the rust platform
# ran and rust-core.json (the reference; rust-core-<features>.json is not it) is missing, parity
# FAILs instead of being SKIPPED. A SKIPPED platform is never required to have a file; a platform
# with no line, or an empty one, FAILs.
#
# The behaviour cases set the copy's table lines they rely on (set_runners); one case pins the real
# table. Fixture platform scripts and a fixture parity script stand in for the real ones, and the
# rust cases use rust_fixtures (a cargo stub, no build). Each case runs test-all.sh in a copy of the
# working tree, under the bash that runs this test (lib.sh). Usage: scripts/tests/test-all/parity-required.sh
set -euo pipefail
export LC_ALL=C
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

# reference_by_wasm: a passing wasm fixture that writes the reference and its own runners' files, so
# parity has rust-core.json without running the rust platform.
reference_by_wasm() {
  fixture bindings/wasm/test.sh 0 'fixture wasm suite ran'
  writes_results bindings/wasm/test.sh rust-core
  writes_own_results bindings/wasm/test.sh wasm
}

# apple_case <name> <line>...: apple's line is `swift-macos swift-ios-sim?`; its passing fixture
# prints the lines and writes swift-macos.json. The reference comes from wasm.
apple_case() {
  new_case "$1"
  shift
  reference_by_wasm
  set_runners apple swift-macos 'swift-ios-sim?'
  fixture platforms/swift/test.sh 0 'fixture apple suite ran' "$@"
  writes_results platforms/swift/test.sh swift-macos
  parity_fixture 0 'SKIPPED (no results: swift-ios-sim)' 'parity: ok'
}

# --- The real table -----------------------------------------------------------------------------------

tests_run=$((tests_run + 1))
table=$(sed -n "/^results_runners='\$/,/^'\$/p" "$repo/scripts/test-all.sh")
want="results_runners='
rust: rust-core rust-surface
node: node
wasm: wasm-node wasm-chrome? wasm-pkg-node wasm-pkg-chrome? wasm-pkg-workerd
android: jvm android-emulator?
apple: swift-macos swift-ios-sim?
'"
if [ "$table" = "$want" ]; then echo "ok   - the runner table names ADR 0034 §2's runners, the host-optional ones marked ?"
else echo "FAIL - the runner table is not the agreed one:"; printf '%s\n' "$table" | sed 's/^/       /'; tests_failed=$((tests_failed + 1)); fi

# --- The real wasm line: wasm-pkg-workerd is required (F10) -------------------------------------------
# workerd comes from the pinned miniflare dev-dependency, so it runs wherever npm does (0006 lead);
# only the browser runners stay optional on a host. These cases use the copy's real table.

# wasm_real_case <name> <runner whose file is written>... -- <line>...: a passing wasm fixture that
# writes the reference and the named runners' files and prints the lines.
wasm_real_case() {
  local name=$1 r
  shift
  new_case "$name"
  fixture bindings/wasm/test.sh 0 'fixture wasm suite ran'
  writes_results bindings/wasm/test.sh rust-core
  while [ $# -gt 0 ] && [ "$1" != -- ]; do writes_results bindings/wasm/test.sh "$1"; shift; done
  [ $# -gt 0 ] && shift
  for r in "$@"; do fixture_append bindings/wasm/test.sh "echo '$r'"; done
  parity_fixture 0 'parity: ok'
}

wasm_real_case workerd-declared wasm-node wasm-chrome wasm-pkg-node wasm-pkg-chrome -- \
  'SKIPPED-RUNNER (wasm-pkg-workerd: host:no-workerd)'
run_test_all wasm
check "SKIPPED-RUNNER for wasm-pkg-workerd, a required runner, FAILs parity" 1 \
  '^  wasm: PASS$' '^  parity: FAIL$' '^    FAIL \(SKIPPED-RUNNER for wasm-pkg-workerd, a required runner of wasm\)$'
check_absent "wasm-pkg-workerd is not reported as skipped" '^    SKIPPED \(wasm-pkg-workerd: '

wasm_real_case workerd-missing wasm-node wasm-chrome wasm-pkg-node wasm-pkg-chrome --
run_test_all wasm
check "a passing wasm without wasm-pkg-workerd.json FAILs parity" 1 \
  '^  parity: FAIL$' '^    FAIL \(no results: wasm-pkg-workerd; the wasm platform passed\)$'

wasm_real_case workerd-browsers-skipped wasm-node wasm-pkg-node wasm-pkg-workerd -- \
  'SKIPPED-RUNNER (wasm-chrome: host:no-chrome)' 'SKIPPED-RUNNER (wasm-pkg-chrome: host:no-chrome)'
run_test_all wasm
check "the browser runners stay optional: waived, parity passes" 0 \
  '^  parity: PASS$' '^    SKIPPED \(wasm-chrome: host:no-chrome\)$' '^    SKIPPED \(wasm-pkg-chrome: host:no-chrome\)$'

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
check_absent "no runner is reported missing" 'no results file|^    FAIL \('

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

# --- Optional runners and SKIPPED-RUNNER --------------------------------------------------------------

apple_case optional-skip 'SKIPPED-RUNNER (swift-ios-sim: host:no-ios-simulator)' 'fixture apple suite done'
run_test_all wasm apple
check "an optional runner declared SKIPPED-RUNNER (<runner>: host:<token>) is reported SKIPPED, parity passes" 0 \
  '^  apple: PASS$' '^  parity: PASS$' '^    SKIPPED \(swift-ios-sim: host:no-ios-simulator\)$'
check_absent "the waived runner is not listed twice" '^    SKIPPED \(no results: swift-ios-sim\)$'
check_absent "the waived runner is never reported as passing" 'swift-ios-sim.*PASS'

apple_case optional-skip-last-line 'SKIPPED-RUNNER (swift-ios-sim: host:no-ios-simulator)'
run_test_all wasm apple
check "a SKIPPED-RUNNER line as the script's last line is not a platform SKIPPED line" 0 \
  '^  apple: PASS$' '^  parity: PASS$' '^    SKIPPED \(swift-ios-sim: host:no-ios-simulator\)$'

apple_case optional-absent-undeclared
run_test_all wasm apple
check "an optional runner absent with no SKIPPED-RUNNER line FAILs parity" 1 \
  '^  apple: PASS$' '^  parity: FAIL$' '^    FAIL \(no results: swift-ios-sim; the apple platform passed\)$'

apple_case optional-present
writes_results platforms/swift/test.sh swift-ios-sim
run_test_all wasm apple
check "an optional runner that wrote its file passes" 0 '^  parity: PASS$'
check_absent "an optional runner that wrote its file is not reported" '^    (SKIPPED|FAIL) \(swift-ios-sim'

apple_case required-declared 'SKIPPED-RUNNER (swift-macos: host:no-macos)'
writes_results platforms/swift/test.sh swift-ios-sim
run_test_all wasm apple
check "a declared skip of a required runner FAILs parity" 1 \
  '^  parity: FAIL$' '^    FAIL \(SKIPPED-RUNNER for swift-macos, a required runner of apple\)$'
check_absent "a required runner is never reported SKIPPED" '^    SKIPPED \(swift-macos'

apple_case unknown-runner 'SKIPPED-RUNNER (swift-tvos-sim: host:no-tvos-simulator)'
writes_results platforms/swift/test.sh swift-ios-sim
run_test_all wasm apple
check "a declared runner that is not on the platform's line FAILs parity" 1 \
  '^  parity: FAIL$' '^    FAIL \(SKIPPED-RUNNER for swift-tvos-sim, not a runner of apple\)$'

apple_case other-platforms-runner 'SKIPPED-RUNNER (android-emulator: host:no-emulator)'
writes_results platforms/swift/test.sh swift-ios-sim
run_test_all wasm apple
check "another platform's optional runner is not this platform's to waive" 1 \
  '^  parity: FAIL$' '^    FAIL \(SKIPPED-RUNNER for android-emulator, not a runner of apple\)$'

n=0
for bad in 'SKIPPED-RUNNER (swift-ios-sim: no simulator)' 'SKIPPED-RUNNER (swift-ios-sim: host:)' \
  'SKIPPED-RUNNER (swift-ios-sim: host:No_Sim)' 'SKIPPED-RUNNER (swift-ios-sim: host:no sim)' \
  'SKIPPED-RUNNER (swift-ios-sim)' 'SKIPPED-RUNNER swift-ios-sim: host:no-sim' 'SKIPPED-RUNNER' \
  '  SKIPPED-RUNNER (swift-ios-sim: host:no-sim)' 'SKIPPED-RUNNER (swift-ios-sim: host:no-sim) extra'; do
  n=$((n + 1))
  apple_case "bad-line-$n" "$bad"
  run_test_all wasm apple
  check "a malformed SKIPPED-RUNNER line or reason FAILs parity: \"$bad\"" 1 \
    '^  parity: FAIL$' '^    FAIL \(bad SKIPPED-RUNNER line from apple: .*; the form is SKIPPED-RUNNER \(<runner>: host:<token>\)\)$'
  check_absent "a bad declaration waives nothing: \"$bad\"" '^    SKIPPED \(swift-ios-sim'
done

# --- What is never required ---------------------------------------------------------------------------

new_case skipped-platform
reference_by_wasm
set_runners apple swift-macos 'swift-ios-sim?'
fixture platforms/swift/test.sh 0 'SKIPPED-RUNNER (swift-macos: anything)' 'SKIPPED (iOS 27.2 simulator missing)'
parity_fixture 0 'parity: ok'
run_test_all wasm apple
check "a SKIPPED platform without results files is not a failure, whatever it declared" 0 \
  '^  apple: SKIPPED \(iOS 27\.2 simulator missing\)$' '^  parity: PASS$'
check_absent "a SKIPPED platform's runners are not reported missing" '^    FAIL \('

new_case failed-platform
reference_by_wasm
set_runners node node
fixture bindings/node/test.sh 1 'fixture node suite failed'
parity_fixture 0 'parity: ok'
run_test_all wasm node
check "a FAILed platform fails the run by itself; parity does not require its files" 1 \
  '^  node: FAIL$' '^  parity: PASS$'

# --- Every platform has a non-empty line --------------------------------------------------------------

new_case empty-entry
reference_by_wasm
set_runners node
fixture bindings/node/test.sh 0 'fixture node suite ran'
parity_fixture 0 'parity: ok'
run_test_all wasm node
check "a platform whose line names no runner FAILs parity" 1 \
  '^  parity: FAIL$' '^    FAIL \(no runners for node in the runner table\)$'

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
