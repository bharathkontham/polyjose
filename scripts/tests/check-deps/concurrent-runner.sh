#!/usr/bin/env bash
# Self-test of lib.sh's concurrent case runner (concurrent_cases), which rsa-guard.sh uses, with
# stub gates: no cargo runs. Each inner test below sources lib.sh, swaps the gate for a stub that
# reads ./behaviour in its copy, and is run and checked from here. It must hold that:
#   - every wrong result FAILs its case, as one at a time: an expected pass that exits 1, an
#     expected fail that passes, exits 2, prints another FAIL line or misses the required pattern, a
#     gate killed by a signal (exit 137), and a job killed before it records a status (no .rc);
#   - verdicts come out in the order the cases were started, with a slow first case;
#   - the same cases give the same output concurrently and one at a time;
#   - lib_die with a gate run still pending exits 2 only after that run has finished, and the
#     scratch directory is gone;
#   - concurrent_cases refuses (exit 2) under a helper that redefines finish (as
#     scripts/tests/test-all/lib.sh does) or replaces the EXIT trap.
# Usage: scripts/tests/check-deps/concurrent-runner.sh
# shellcheck disable=SC2016 # the inner tests' code and sh -c scripts are single-quoted on purpose
set -euo pipefail
export LC_ALL=C
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

lib_sh="$repo/scripts/tests/check-deps/lib.sh"
mkdir "$scratch/tmp" "$scratch/inner" || lib_die "could not create the inner directories"

# check <description> <command>...: one case of this test, passing when the command succeeds.
check() {
  local desc=$1
  shift
  tests_run=$((tests_run + 1))
  if "$@"; then
    echo "ok   - $desc"
  else
    echo "FAIL - $desc"
    tests_failed=$((tests_failed + 1))
  fi
}

# inner <name> <jobs> <script body>: writes an inner test of the body, which sources lib.sh (given as
# $1) or a helper that does, and runs it under this bash with CHECK_DEPS_TEST_JOBS=<jobs>, its
# scratch under ours. Output in $scratch/<name>.out, exit status in $scratch/<name>.rc.
inner() {
  local rc=0
  {
    printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' 'export LC_ALL=C'
    printf '%s\n' "$3"
  } >"$scratch/inner/$1.sh" || lib_die "could not write the inner test $1"
  CHECK_DEPS_TEST_JOBS=$2 TMPDIR="$scratch/tmp" MARK_DIR="$scratch/inner" \
    "$BASH" "$scratch/inner/$1.sh" "$lib_sh" </dev/null >"$scratch/$1.out" 2>&1 || rc=$?
  echo "$rc" >"$scratch/$1.rc"
}

# The stub gate and the cases. killjob kills the background job around the gate (the parent of the
# gate's subshell), so it can run concurrently only: one at a time, that parent is the test itself.
# The copies start from a tiny base: the stubs read only ./behaviour.
stub='. "$1"
concurrent_cases
gate_name=stub
base=$scratch/tiny
mkdir "$base"
run_gate() {
  read -r s a <./behaviour
  sleep "$s"
  case $a in
    pass) echo "all fine"; return 0 ;;
    fail1) echo "FAIL: expected thing"; return 1 ;;
    fail1-other) echo "FAIL: expected thing"; echo "FAIL: other check"; return 1 ;;
    fail1-nomatch) echo "FAIL: something else"; return 1 ;;
    exit2) echo "ERROR: could not run"; return 2 ;;
    killjob) sh -c '"'"'kill -9 $(ps -o ppid= -p $PPID)'"'"'; sleep 1; return 0 ;;
    killgate) sh -c '"'"'kill -9 $PPID'"'"'; return 0 ;;
  esac
}
c() { new_case "$1"; echo "$2 $3" >"$case_dir/behaviour"; }'
cases='c slow 2 pass; expect_pass "slow first case"
c pass-exit1 0 fail1; expect_pass "expected pass, exit 1"
c fail-ok 0 fail1; expect_fail "expected fail" "expected thing" "^FAIL: expected"
c fail-passes 0 pass; expect_fail "expected fail, passes" "expected thing" "^FAIL: expected"
c fail-exit2 0 exit2; expect_fail "expected fail, exit 2" "ERROR" "."
c fail-other 0 fail1-other; expect_fail "expected fail, another FAIL line" "expected thing" "^FAIL: expected"
c fail-nomatch 0 fail1-nomatch; expect_fail "expected fail, pattern missing" "expected thing" "^FAIL: "
c pass-killgate 0 killgate; expect_pass "expected pass, gate killed"'
kill_cases='c pass-killjob 0 killjob; expect_pass "expected pass, job killed"
c fail-killjob 0 killjob; expect_fail "expected fail, job killed" "." "."'
last='c last 0 pass; expect_pass "last case"
finish'

# --- Every wrong result fails, in start order ------------------------------------------------------
inner all 4 "$stub
$cases
$kill_cases
$last"
check "concurrent: the run exits 1 (cases failed)" [ "$(cat "$scratch/all.rc")" = 1 ]
grep -E '^(ok  |FAIL) - |cases passed$' "$scratch/all.out" >"$scratch/all.verdicts" || true
printf '%s\n' \
  'ok   - slow first case: stub passes' \
  'FAIL - expected pass, exit 1: stub exited 1, expected 0' \
  'ok   - expected fail: stub fails as expected' \
  'FAIL - expected fail, passes: exit 0 (expected 1), wanted output matching /expected thing/ and only FAIL lines matching /^FAIL: expected/' \
  'FAIL - expected fail, exit 2: exit 2 (expected 1), wanted output matching /ERROR/ and only FAIL lines matching /./' \
  'FAIL - expected fail, another FAIL line: exit 1 (expected 1), wanted output matching /expected thing/ and only FAIL lines matching /^FAIL: expected/' \
  'FAIL - expected fail, pattern missing: exit 1 (expected 1), wanted output matching /expected thing/ and only FAIL lines matching /^FAIL: /' \
  'FAIL - expected pass, gate killed: stub exited 137, expected 0' \
  'FAIL - expected pass, job killed: stub exited unknown (no exit status recorded), expected 0' \
  'FAIL - expected fail, job killed: exit unknown (no exit status recorded) (expected 1), wanted output matching /./ and only FAIL lines matching /./' \
  'ok   - last case: stub passes' \
  '3/11 cases passed' >"$scratch/all.want"
check "concurrent: each verdict, in start order with a slow first case, and the summary" \
  cmp -s "$scratch/all.want" "$scratch/all.verdicts"
cmp -s "$scratch/all.want" "$scratch/all.verdicts" || diff "$scratch/all.want" "$scratch/all.verdicts" | sed 's/^/       /' || true

# --- Concurrently and one at a time: the same output -------------------------------------------------
inner same-concurrent 4 "$stub
$cases
$last"
inner same-sequential 1 "$stub
$cases
$last"
check "the same cases exit 1 concurrently and one at a time" \
  [ "$(cat "$scratch/same-concurrent.rc") $(cat "$scratch/same-sequential.rc")" = "1 1" ]
# The kernel's "Killed: 9" notice names the line and PID, so it is left out of the comparison.
grep -v 'Killed' "$scratch/same-concurrent.out" >"$scratch/same-concurrent.cmp" || true
grep -v 'Killed' "$scratch/same-sequential.out" >"$scratch/same-sequential.cmp" || true
check "the same cases print the same output concurrently and one at a time" \
  cmp -s "$scratch/same-concurrent.cmp" "$scratch/same-sequential.cmp"

# --- lib_die with a gate run pending -------------------------------------------------------------
inner die 4 '. "$1"
concurrent_cases
base=$scratch/tiny
mkdir "$base"
echo "$scratch" >"$MARK_DIR/die.scratch"
run_gate() { sleep 2; echo done >"$MARK_DIR/die.gate-finished"; }
new_case slow
expect_pass "slow"
lib_die "planted stop"
finish'
check "lib_die with a run pending: exit 2 with its message" \
  sh -c '[ "$(cat "$1")" = 2 ] && grep -qx "ERROR: planted stop" "$2"' sh "$scratch/die.rc" "$scratch/die.out"
check "lib_die with a run pending: the run finished before the test exited" [ -f "$scratch/inner/die.gate-finished" ]
check "lib_die with a run pending: the scratch directory is gone" \
  sh -c '[ -s "$1" ] && [ ! -e "$(cat "$1")" ]' sh "$scratch/inner/die.scratch"

# --- concurrent_cases refuses a redefined finish or a replaced EXIT trap -----------------------------
inner test-all-lib 4 ". \"\$(dirname \"\$1\")/../test-all/lib.sh\"
concurrent_cases
echo started
finish"
check "under scripts/tests/test-all/lib.sh (finish redefined): concurrent_cases exits 2" \
  sh -c '[ "$(cat "$1")" = 2 ] && grep -q "^ERROR: concurrent_cases needs .*finish" "$2" && ! grep -q started "$2"' \
  sh "$scratch/test-all-lib.rc" "$scratch/test-all-lib.out"
# (The replacing trap is spliced in, so that no line here reads as an EXIT trap of this test.)
replace_trap="trap 'exit \$?' EXIT"
inner own-trap 4 '. "$1"
'"$replace_trap"'
concurrent_cases
echo started
finish'
check "under a replaced EXIT trap: concurrent_cases exits 2" \
  sh -c '[ "$(cat "$1")" = 2 ] && grep -q "^ERROR: concurrent_cases needs .*EXIT trap" "$2" && ! grep -q started "$2"' \
  sh "$scratch/own-trap.rc" "$scratch/own-trap.out"

finish
