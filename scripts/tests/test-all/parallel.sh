#!/usr/bin/env bash
# Test of the parallel platform lanes, the step times and the work-reuse switches of
# scripts/test-all.sh (chore/test-speed):
#   - consecutive wasm, node, android and swift arguments run in lanes (wasm and node in one), each
#     platform's output printed whole and in argument order, even when a later one finishes first;
#     the output, summary and exit status equal a TEST_ALL_SERIAL=1 run's, apart from the line that
#     announces the lanes and the times;
#   - wasm and node, which share bindings/js, never run at the same time;
#   - a failing platform FAILs the run as in a sequential run, and a lane that dies before its
#     platform finished FAILs that platform (never a pass), and so does a lane whose summary line
#     could not be written or was lost;
#   - when test-all.sh is stopped, each lane's whole process group goes with it: no platform
#     script or child of one keeps running;
#   - each summary line of a step that ran ends with its wall time, a step recorded without running
#     has none, and the summary ends with `Total: <time>`;
#   - POLYJOSE_ADDON_REUSE=1 reaches the platform scripts, and POLYJOSE_RUST_CORE_FRESH=1 only after
#     this run's rust step passed, never from the caller's environment.
# No assertion is about how long anything takes. Each case runs test-all.sh in a copy of the
# working tree with fixture scripts (lib.sh), under the bash that runs this test.
# Usage: scripts/tests/test-all/parallel.sh
set -euo pipefail
export LC_ALL=C
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

# all_fixtures <android exit status>: passing fixtures for the four platforms (android's with the
# status), each writing its runners' results files.
all_fixtures() {
  fixture bindings/wasm/test.sh 0 'fixture wasm suite ran'
  fixture bindings/node/test.sh 0 'fixture node suite ran'
  fixture platforms/android/test.sh "$1" 'fixture android suite ran'
  fixture platforms/swift/test.sh 0 'fixture swift suite ran'
  writes_own_results bindings/wasm/test.sh wasm
  writes_own_results bindings/node/test.sh node
  writes_own_results platforms/android/test.sh android
  writes_own_results platforms/swift/test.sh swift
}

# same_as_serial <description> <platform>...: runs them again with TEST_ALL_SERIAL=1 and compares:
# the two outputs (times removed, Total and the lanes line dropped) and exit statuses are equal.
same_as_serial() {
  local what=$1 prc=$rc
  shift
  grep -v -e '^Total: ' -e 'in parallel lanes (TEST_ALL_SERIAL=1' "$scratch/out" >"$scratch/parallel.out"
  export TEST_ALL_SERIAL=1
  run_test_all "$@"
  unset TEST_ALL_SERIAL
  grep -v -e '^Total: ' "$scratch/out" >"$scratch/serial.out"
  tests_run=$((tests_run + 1))
  if [ "$rc" -eq "$prc" ] && cmp -s "$scratch/parallel.out" "$scratch/serial.out"; then
    echo "ok   - $what"
  else
    echo "FAIL - $what: parallel exit $prc, serial exit $rc; diff parallel serial:"
    diff "$scratch/parallel.out" "$scratch/serial.out" | sed 's/^/       /' || true
    tests_failed=$((tests_failed + 1))
  fi
  check_absent "TEST_ALL_SERIAL=1 runs no lanes" 'in parallel lanes'
}

# --- Lanes, order and equivalence ----------------------------------------------------------------------

new_case lanes
all_fixtures 0
# android finishes last; its output still comes before swift's.
fixture_append platforms/android/test.sh 'sleep 2'
run_test_all wasm node android swift
check "the four platforms run in three lanes and pass" 0 \
  '^test-all\.sh: running wasm node \| android \| swift in parallel lanes \(TEST_ALL_SERIAL=1 runs them one at a time\)$' \
  '^  wasm: PASS$' '^  node: PASS$' '^  android: PASS$' '^  swift: PASS$' '^  parity: '
check_order "android's output comes before swift's though it finished later" \
  '^fixture android suite ran$' '^==> swift \(platforms/swift/test\.sh\)$'
check_order "wasm's output before node's (one lane, in argument order)" \
  '^fixture wasm suite ran$' '^==> rsa-oaep-oracle$'
check_order "the summary keeps argument order" '^  android: PASS$' '^  swift: PASS$'
same_as_serial "the output and exit status equal a TEST_ALL_SERIAL=1 run's" wasm node android swift

new_case order
all_fixtures 0
run_test_all swift wasm android node
check "any argument order runs in lanes" 0 'running wasm node \| android \| swift in parallel lanes' '^  swift: PASS$'
check_order "swift first, as named" '^  swift: PASS$' '^  wasm: PASS$'
check_order "node after android, as named" '^  android: PASS$' '^  node: PASS$'
same_as_serial "in that order too, the same output as one at a time" swift wasm android node

new_case one-lane
all_fixtures 0
run_test_all wasm node
check "wasm and node alone run as before, in this shell" 0 '^  wasm: PASS$' '^  node: PASS$'
check_absent "a single lane is not announced as parallel" 'in parallel lanes'

new_case twice
all_fixtures 0
run_test_all android swift android
check "a platform named twice runs everything one at a time" 0 '^  android: PASS$' '^  swift: PASS$'
check_absent "and runs no lanes" 'in parallel lanes'

# --- Failures -----------------------------------------------------------------------------------------

new_case fail
all_fixtures 1
run_test_all wasm node android swift
check "a failing platform in a lane FAILs the run; the others still pass" 1 \
  '^  android: FAIL$' '^  wasm: PASS$' '^  swift: PASS$' 'platforms/android/test\.sh exited 1'
same_as_serial "a failing run equals its TEST_ALL_SERIAL=1 run" wasm node android swift

new_case lane-dies
all_fixtures 0
# The fixture's parent is its lane's shell (test-all.sh's run_script): killing it ends the lane.
# shellcheck disable=SC2016 # expanded by the fixture, not here
fixture_append platforms/android/test.sh 'kill -9 $PPID'
run_test_all wasm node android swift
check "a lane that dies before its platform finished FAILs that platform" 1 \
  '^test-all\.sh: the android block stopped before it finished \(its lane exited\)$' '^  android: FAIL$' \
  '^  swift: PASS$' '^  wasm: PASS$'
check_absent "the dead lane's platform is not reported as passing" '^  android: PASS$'

new_case no-overlap
all_fixtures 0
# Each js-lane suite logs its start and end; wasm takes a while, so an overlap would show.
fixture_append bindings/wasm/test.sh "echo 'wasm start' >>$scratch/js-lane.log; sleep 2; echo 'wasm end' >>$scratch/js-lane.log"
fixture_append bindings/node/test.sh "echo 'node start' >>$scratch/js-lane.log; echo 'node end' >>$scratch/js-lane.log"
rm -f "$scratch/js-lane.log"
run_test_all wasm node android swift
tests_run=$((tests_run + 1))
if [ "$rc" -eq 0 ] && [ "$(tr '\n' ' ' <"$scratch/js-lane.log")" = "wasm start wasm end node start node end " ]; then
  echo "ok   - wasm and node run one after the other, never at the same time"
else
  echo "FAIL - wasm and node run one after the other, never at the same time (exit $rc):"
  sed 's/^/       /' "$scratch/js-lane.log"; tests_failed=$((tests_failed + 1))
fi

# lost_records <case> <shell line run by the android fixture, with $T the run's TMPDIR>: test-all.sh
# under its own TMPDIR, so the fixture can reach the lane's records file.
lost_records() {
  new_case "$1"
  all_fixtures 0
  mkdir -p "$scratch/tmp-$1"
  fixture_append platforms/android/test.sh "T=$scratch/tmp-$1; $2"
  local saved=${TMPDIR:-}
  export TMPDIR="$scratch/tmp-$1"
  run_test_all wasm node android swift
  if [ -n "$saved" ]; then export TMPDIR=$saved; else unset TMPDIR; fi
}
# shellcheck disable=SC2016 # expanded by the fixture, not here
lost_records records-unwritable 'chmod 0 "$T"/test-all.*/block-android.records'
check "a summary line that cannot be written ends the lane and FAILs the platform" 1 \
  '^test-all\.sh: could not write .*block-android\.records$' \
  '^test-all\.sh: the android block stopped before it finished \(its lane exited\)$' '^  android: FAIL$' '^  swift: PASS$'
check_absent "never as passing" '^  android: PASS$'
# shellcheck disable=SC2016 # expanded by the fixture, not here
lost_records records-lost 'f=$(ls "$T"/test-all.*/block-android.records) && rm -f "$f" && ln -s /dev/null "$f"'
check "a block that finished without its own summary line FAILs the platform" 1 \
  '^test-all\.sh: the android block finished without a summary line for android$' '^  android: FAIL$' '^  swift: PASS$'
check_absent "never as passing" '^  android: PASS$'

new_case stopped
all_fixtures 0
# The android suite starts a child that would outlive a lane killed alone, and records its pid.
fixture_append platforms/android/test.sh "sleep 120 & echo \$! >$scratch/child.pid; wait"
rm -f "$scratch/child.pid"
(cd "$case_dir" && exec "${BASH:-bash}" scripts/test-all.sh wasm node android swift) </dev/null >"$scratch/out.raw" 2>&1 &
tpid=$!
n=0
while [ ! -s "$scratch/child.pid" ] && [ "$n" -lt 600 ]; do sleep 0.1; n=$((n + 1)); done
child=$(cat "$scratch/child.pid" 2>/dev/null || true)
kill -TERM "$tpid" 2>/dev/null || true
wait "$tpid" 2>/dev/null || true
# Signals are delivered asynchronously: up to 10 s for the child to be gone.
n=0
while [ -n "$child" ] && kill -0 "$child" 2>/dev/null && [ "$n" -lt 100 ]; do sleep 0.1; n=$((n + 1)); done
tests_run=$((tests_run + 1))
if [ -n "$child" ] && ! kill -0 "$child" 2>/dev/null; then
  echo "ok   - stopping test-all.sh ends the lanes' process groups: the suite's child is gone"
else
  echo "FAIL - stopping test-all.sh ends the lanes' process groups: child ${child:-never started} still runs"
  [ -z "$child" ] || kill "$child" 2>/dev/null || true
  sed 's/^/       /' "$scratch/out.raw"; tests_failed=$((tests_failed + 1))
fi

# --- Times --------------------------------------------------------------------------------------------

new_case times
all_fixtures 0
rm -f "$case_dir/platforms/swift/test.sh" "$case_dir/Package.swift"
run_test_all wasm android swift
tests_run=$((tests_run + 1))
if grep -Eq '^  wasm: PASS \([0-9]+s\)$' "$scratch/out.raw" && grep -Eq '^  android: PASS \([0-9]+s\)$' "$scratch/out.raw" \
  && grep -Eq '^  parity: [A-Z].* \([0-9]+s\)$' "$scratch/out.raw" && grep -Eq '^  syntax: PASS \([0-9]+s\)$' "$scratch/out.raw"; then
  echo "ok   - each step that ran ends its summary line with its wall time"
else
  echo "FAIL - each step that ran ends its summary line with its wall time"; sed 's/^/       /' "$scratch/out.raw"
  tests_failed=$((tests_failed + 1))
fi
tests_run=$((tests_run + 1))
if grep -qx '  swift: SKIPPED (swift or Package.swift missing)' "$scratch/out.raw"; then
  echo "ok   - a step recorded without running has no time"
else
  echo "FAIL - a step recorded without running has no time"; sed 's/^/       /' "$scratch/out.raw"
  tests_failed=$((tests_failed + 1))
fi
tests_run=$((tests_run + 1))
if awk 'NF { line = $0 } END { exit !(line ~ /^Total: ([0-9]+h[0-9][0-9]m[0-9][0-9]s|[0-9]+m[0-9][0-9]s|[0-9]+s)$/) }' "$scratch/out.raw"; then
  echo "ok   - the summary ends with the total wall time"
else
  echo "FAIL - the summary ends with the total wall time"; sed 's/^/       /' "$scratch/out.raw"
  tests_failed=$((tests_failed + 1))
fi

# --- The work-reuse switches -----------------------------------------------------------------------------

new_case switches
rust_fixtures 0 rust-core rust-surface
parity_fixture 0 'parity: fixture'
fixture bindings/node/test.sh 0 'fixture node suite ran'
# shellcheck disable=SC2016 # expanded by the fixture, not here
fixture_append bindings/node/test.sh 'echo "switches: reuse=${POLYJOSE_ADDON_REUSE:-unset} fresh=${POLYJOSE_RUST_CORE_FRESH:-unset}"'
writes_own_results bindings/node/test.sh node
run_test_all rust node
check "after a passing rust step the node suite gets both switches" 0 '^  rust: PASS$' '^switches: reuse=1 fresh=1$'

new_case switches-rust-failed
rust_fixtures 1 rust-core rust-surface
fixture bindings/node/test.sh 0 'fixture node suite ran'
# shellcheck disable=SC2016 # expanded by the fixture, not here
fixture_append bindings/node/test.sh 'echo "switches: reuse=${POLYJOSE_ADDON_REUSE:-unset} fresh=${POLYJOSE_RUST_CORE_FRESH:-unset}"'
writes_own_results bindings/node/test.sh node
run_test_all rust node
check "after a failing rust step the node suite runs its own reference" 1 '^  rust: FAIL$' '^switches: reuse=1 fresh=unset$'

new_case switches-inherited
fixture bindings/node/test.sh 0 'fixture node suite ran'
# shellcheck disable=SC2016 # expanded by the fixture, not here
fixture_append bindings/node/test.sh 'echo "switches: reuse=${POLYJOSE_ADDON_REUSE:-unset} fresh=${POLYJOSE_RUST_CORE_FRESH:-unset}"'
writes_own_results bindings/node/test.sh node
export POLYJOSE_RUST_CORE_FRESH=1
run_test_all node
unset POLYJOSE_RUST_CORE_FRESH
check "the rust-core switch is never taken from the caller's environment" 0 '^switches: reuse=1 fresh=unset$'

finish
