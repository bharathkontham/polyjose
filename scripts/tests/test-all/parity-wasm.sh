#!/usr/bin/env bash
# Test of scripts/test-all.sh's results-file rule on the real `wasm` line of its runner table
# (feature 0006 T06; ADR 0060 §7, ADR 0034 §2): `wasm-node wasm-chrome? wasm-pkg-node
# wasm-pkg-chrome? wasm-pkg-workerd?`. parity-required.sh (0013 F05) tests the rule itself on other
# lines; this one keeps the wasm platform's own contract with it:
#   - a passing wasm platform that wrote every runner's file passes;
#   - one missing a required runner's file (wasm-node, wasm-pkg-node) FAILs, naming the runner;
#   - without Chrome, the two waiver lines bindings/wasm/test.sh and test-pkg/run.sh print waive
#     wasm-chrome and wasm-pkg-chrome: parity passes and reports both SKIPPED, never passing;
#   - a missing wasm-chrome (or wasm-pkg-chrome) file without its waiver line FAILs;
#   - a waiver of a required runner (wasm-node) FAILs.
# The waiver lines used here are checked to be exactly the ones the real scripts print. Fixture
# platform and parity scripts stand in for the real ones; each case runs test-all.sh in a copy of the
# working tree, under the bash that runs this test (lib.sh). No cargo or wasm-pack build happens.
# Usage: scripts/tests/test-all/parity-wasm.sh. Runs on macOS /bin/bash 3.2 and Linux bash.
set -euo pipefail
export LC_ALL=C
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

chrome_waiver='SKIPPED-RUNNER (wasm-chrome: host:no-chrome)'
pkg_chrome_waiver='SKIPPED-RUNNER (wasm-pkg-chrome: host:no-chrome)'
all="wasm-node wasm-chrome wasm-pkg-node wasm-pkg-chrome wasm-pkg-workerd"

# --- The waiver lines are the real scripts' ------------------------------------------------------

# printed_by <file> <line>: the script echoes exactly this line.
printed_by() {
  tests_run=$((tests_run + 1))
  if grep -Fq "echo \"$2\"" "$repo/$1"; then echo "ok   - $1 prints \"$2\""
  else echo "FAIL - $1 does not print \"$2\""; tests_failed=$((tests_failed + 1)); fi
}
printed_by bindings/wasm/test.sh "$chrome_waiver"
printed_by bindings/wasm/test-pkg/run.sh "$pkg_chrome_waiver"

# wasm_case <name> <the runners whose files it writes> <line>...: a passing wasm fixture that prints the
# lines, then its PASS line, and writes the reference and the named runners' files.
wasm_case() {
  local name=$1 files=$2 r
  shift 2
  new_case "$name"
  fixture bindings/wasm/test.sh 0 'fixture wasm suite ran' "$@" 'wasm: PASS (fixture)'
  writes_results bindings/wasm/test.sh rust-core
  for r in $files; do writes_results bindings/wasm/test.sh "$r"; done
}

# without <runner>...: the five runners minus these.
without() {
  local r out=""
  for r in $all; do
    case " $* " in *" $r "*) ;; *) out="$out $r" ;; esac
  done
  echo "$out"
}

# --- Chrome present: all five files --------------------------------------------------------------

wasm_case all-five "$all"
parity_fixture 0 'parity: ok'
run_test_all wasm
check "a passing wasm platform with all five runners' files passes parity" 0 '^  wasm: PASS$' '^  parity: PASS$'
check_absent "no wasm runner is reported missing or skipped" '^    (FAIL|SKIPPED) \('

# --- A required runner's file missing -----------------------------------------------------------

for r in wasm-node wasm-pkg-node; do
  wasm_case "required-missing-$r" "$(without "$r")"
  parity_fixture 0 "SKIPPED (no results: $r)" 'parity: ok'
  run_test_all wasm
  check "a passing wasm platform without $r.json (required) FAILs parity" 1 \
    '^  wasm: PASS$' '^  parity: FAIL$' "^    FAIL \\(no results: $r; the wasm platform passed\\)$"
done

# --- Chrome absent: three files and two waivers --------------------------------------------------

wasm_case no-chrome-waived "$(without wasm-chrome wasm-pkg-chrome)" \
  'wasm: wasm-chrome not run: no Google Chrome found' "$chrome_waiver" '  chrome: SKIPPED (Chrome not found)' "$pkg_chrome_waiver"
parity_fixture 0 'SKIPPED (no results: wasm-chrome)' 'SKIPPED (no results: wasm-pkg-chrome)' 'parity: ok'
run_test_all wasm
check "without Chrome, the two waivers keep wasm and parity passing" 0 '^  wasm: PASS$' '^  parity: PASS$' \
  '^    SKIPPED \(wasm-chrome: host:no-chrome\)$' '^    SKIPPED \(wasm-pkg-chrome: host:no-chrome\)$'
check_absent "a waived Chrome runner is never reported as passing" 'wasm(-pkg)?-chrome.*PASS'
check_absent "a waived Chrome runner is not listed twice" '^    SKIPPED \(no results: wasm(-pkg)?-chrome\)$'

wasm_case no-chrome-undeclared "$(without wasm-chrome)"
parity_fixture 0 'SKIPPED (no results: wasm-chrome)' 'parity: ok'
run_test_all wasm
check "a missing wasm-chrome.json without its waiver line FAILs parity" 1 \
  '^  wasm: PASS$' '^  parity: FAIL$' '^    FAIL \(no results: wasm-chrome; the wasm platform passed\)$'

wasm_case no-pkg-chrome-undeclared "$(without wasm-chrome wasm-pkg-chrome)" "$chrome_waiver"
parity_fixture 0 'SKIPPED (no results: wasm-chrome)' 'SKIPPED (no results: wasm-pkg-chrome)' 'parity: ok'
run_test_all wasm
check "wasm-chrome's waiver does not cover a missing wasm-pkg-chrome.json" 1 \
  '^  parity: FAIL$' '^    FAIL \(no results: wasm-pkg-chrome; the wasm platform passed\)$' \
  '^    SKIPPED \(wasm-chrome: host:no-chrome\)$'

wasm_case required-waived "$(without wasm-node)" 'SKIPPED-RUNNER (wasm-node: host:no-chrome)'
parity_fixture 0 'SKIPPED (no results: wasm-node)' 'parity: ok'
run_test_all wasm
check "a waiver of wasm-node, a required runner, FAILs parity" 1 \
  '^  parity: FAIL$' '^    FAIL \(SKIPPED-RUNNER for wasm-node, a required runner of wasm\)$'
check_absent "a required runner is never reported SKIPPED" '^    SKIPPED \(wasm-node'

finish
