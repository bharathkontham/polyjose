#!/usr/bin/env bash
# Adversarial inputs for the results-file rule of scripts/test-all.sh's parity step (feature 0013 F05,
# review S3): a passing platform's missing results file must never go unnoticed, whatever its
# SKIPPED-RUNNER lines, duplicate declarations, file names or sibling platforms do. Complements
# parity-required.sh. Usage: scripts/tests/test-all/parity-adversarial.sh
set -euo pipefail
export LC_ALL=C
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

# ref_by_node: a passing node fixture writing the reference and node.json (the reference needs a platform).
ref_by_node() {
  set_runners node node
  fixture bindings/node/test.sh 0 'fixture node suite ran'
  writes_results bindings/node/test.sh rust-core node
}

# wasm_case <name> <runner>...: wasm's line is `wasm-node wasm-chrome? wasm-pkg-node`; its script writes
# the given files and prints the lines in $decls.
wasm_case() {
  new_case "$1"
  ref_by_node
  set_runners wasm wasm-node 'wasm-chrome?' wasm-pkg-node
  shift
  fixture bindings/wasm/test.sh 0 'fixture wasm suite ran' ${decls[@]+"${decls[@]}"}
  writes_results bindings/wasm/test.sh "$@"
  parity_fixture 0 'parity: ok'
}

decls=()
wasm_case suffix-prefix-collision wasm-pkg-node-x wasm-pkg-node
run_test_all node wasm
check "wasm-pkg-node-x.json does not satisfy wasm-node" 1 \
  '^  parity: FAIL$' '^    FAIL \(no results: wasm-node; the wasm platform passed\)$'
check_absent "wasm-pkg-node is satisfied by its own file" 'no results: wasm-pkg-node;'

wasm_case suffix-ok wasm-node-linux-x64 wasm-pkg-node-linux-x64 wasm-chrome-linux-x64
run_test_all node wasm
check "wasm-node-<suffix>.json, wasm-pkg-node-<suffix>.json and wasm-chrome-<suffix>.json count" 0 '^  wasm: PASS$' '^  parity: PASS$'

wasm_case optional-undeclared wasm-node-linux-x64 wasm-pkg-node-linux-x64
run_test_all node wasm
check "an optional runner that is absent and undeclared FAILs, naming only that runner" 1 \
  '^  wasm: PASS$' '^  parity: FAIL$' '^    FAIL \(no results: wasm-chrome; the wasm platform passed\)$'
check_absent "the runners that wrote files are not reported" 'no results: wasm-(node|pkg-node);'

decls=('SKIPPED-RUNNER (wasm-chrome: host:no-chrome)' 'SKIPPED-RUNNER (wasm-chrome: host:no-chrome)')
wasm_case declared-twice wasm-node wasm-pkg-node
run_test_all node wasm
check "the same optional runner declared twice is reported SKIPPED once" 0 \
  '^  parity: PASS$' '^    SKIPPED \(wasm-chrome: host:no-chrome\)$'
tests_run=$((tests_run + 1))
n=$(grep -c '^    SKIPPED (wasm-chrome' "$scratch/out" || true)
if [ "$n" -eq 1 ]; then echo "ok   - exactly one SKIPPED summary line for the doubled declaration"
else echo "FAIL - $n SKIPPED lines for a doubled declaration"; tests_failed=$((tests_failed + 1)); fi

decls=('SKIPPED-RUNNER (wasm-chrome: host:no-chrome)' 'SKIPPED-RUNNER (wasm-chrome: host:other)')
wasm_case declared-twice-different-reason wasm-node wasm-pkg-node
run_test_all node wasm
check "two declarations with different reasons for one optional runner are reported SKIPPED once" 0 '^  parity: PASS$' '^    SKIPPED \(wasm-chrome: host:no-chrome\)$'

decls=('SKIPPED-RUNNER (wasm-chrome: host:no-chrome)')
wasm_case declared-and-written wasm-node wasm-pkg-node wasm-chrome
run_test_all node wasm
check "a declared-skipped optional runner that also wrote its file passes as a run (never as SKIPPED)" 0 '^  parity: PASS$'
check_absent "no SKIPPED line for a runner that has a file" '^    SKIPPED \(wasm-chrome'

decls=('SKIPPED-RUNNER (wasm-chrome: host:no-chrome)')
wasm_case waiver-does-not-cover-required wasm-pkg-node
run_test_all node wasm
check "a valid waiver for one optional runner does not hide a missing required runner" 1 \
  '^  parity: FAIL$' '^    FAIL \(no results: wasm-node; the wasm platform passed\)$' '^    SKIPPED \(wasm-chrome: host:no-chrome\)$'

decls=('SKIPPED-RUNNER (wasm-chrome: host:no-chrome)' 'SKIPPED-RUNNER (wasm-node: host:no-node)')
wasm_case waiver-plus-required-waiver wasm-pkg-node
run_test_all node wasm
check "a declared skip of a required runner FAILs even beside a valid waiver" 1 \
  '^  parity: FAIL$' '^    FAIL \(SKIPPED-RUNNER for wasm-node, a required runner of wasm\)$'

# A SKIPPED sibling's declaration must not waive a passing platform's runner of the same name.
decls=()
new_case skipped-sibling-declares
ref_by_node
set_runners wasm wasm-node 'wasm-chrome?'
set_runners android jvm 'android-emulator?'
fixture bindings/wasm/test.sh 0 'fixture wasm suite ran'
writes_results bindings/wasm/test.sh wasm-node
fixture platforms/android/test.sh 0 'SKIPPED-RUNNER (wasm-chrome: host:no-chrome)' 'SKIPPED (no emulator)'
parity_fixture 0 'parity: ok'
run_test_all node wasm android
check "a SKIPPED platform's declaration does not waive another platform's optional runner" 1 \
  '^  android: SKIPPED \(no emulator\)$' '^  parity: FAIL$' '^    FAIL \(no results: wasm-chrome; the wasm platform passed\)$'

# A passing sibling declaring another platform's optional runner cannot waive it either.
new_case passing-sibling-declares
ref_by_node
set_runners wasm wasm-node 'wasm-chrome?'
set_runners android jvm 'android-emulator?'
fixture bindings/wasm/test.sh 0 'fixture wasm suite ran'
writes_results bindings/wasm/test.sh wasm-node
fixture platforms/android/test.sh 0 'fixture android suite ran' 'SKIPPED-RUNNER (wasm-chrome: host:no-chrome)'
writes_results platforms/android/test.sh jvm android-emulator
parity_fixture 0 'parity: ok'
run_test_all node wasm android
check "a passing sibling's declaration for another platform's runner FAILs, and waives nothing" 1 \
  '^  parity: FAIL$' '^    FAIL \(SKIPPED-RUNNER for wasm-chrome, not a runner of android\)$' \
  '^    FAIL \(no results: wasm-chrome; the wasm platform passed\)$'

# A results file for an unrelated runner never satisfies a platform.
new_case unrelated-file
ref_by_node
set_runners android jvm 'android-emulator?'
fixture platforms/android/test.sh 0 'fixture android suite ran'
writes_results platforms/android/test.sh android-emulator-extra swift-macos jvmx
parity_fixture 0 'parity: ok'
run_test_all node android
check "files of unrelated runners (jvmx) do not satisfy jvm" 1 \
  '^  parity: FAIL$' '^    FAIL \(no results: jvm; the android platform passed\)$'

# The same platform named twice on the command line is checked, not skipped the second time.
new_case platform-twice
ref_by_node
fixture bindings/wasm/test.sh 0 'fixture wasm suite ran'
set_runners wasm wasm-node
parity_fixture 0 'parity: ok'
run_test_all node wasm wasm
check "a passing platform named twice and missing its file FAILs" 1 '^  parity: FAIL$' '^    FAIL \(no results: wasm-node;'

finish
