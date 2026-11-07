#!/usr/bin/env bash
# Test of the per-platform dispatcher of scripts/test-all.sh (feature 0013 T04, ADR 0030 §1):
# `test-all.sh wasm|node|android|apple` runs bindings/wasm/test.sh, bindings/node/test.sh,
# platforms/android/test.sh or platforms/swift/test.sh when it exists. Its exit status decides PASS or
# FAIL, and `SKIPPED (<reason>)` as its last line (with exit 0) reports SKIPPED, which never counts
# as passing (pipeline rule 9). Without a script the platform keeps its inline commands and their
# SKIPPED reasons (0001 T14).
#
# Each case runs test-all.sh in a copy of the working tree (scripts/tests/check-deps/lib.sh) with
# fixture scripts in place of the real ones, under the bash that runs this test ($BASH), so
# `/bin/bash scripts/tests/test-all/dispatch.sh` checks bash 3.2 and a Linux bash checks bash 5.
# Only non-rust platforms run, so no cargo build happens. Usage: scripts/tests/test-all/dispatch.sh
set -euo pipefail
export LC_ALL=C
# shellcheck source=../check-deps/lib.sh
. "$(dirname "$0")/../check-deps/lib.sh"

gate_name=test-all.sh

# fixture <path in the copy> <exit status> <line>...: an executable sh script that prints each line
# and exits with the status. It replaces the real script if the owning feature has created one.
fixture() {
  local path=$1 rc=$2 line
  shift 2
  mkdir -p "$(dirname "$case_dir/$path")" || lib_die "could not create the directory of $path"
  {
    echo '#!/bin/sh'
    for line in "$@"; do printf "printf '%%s\\\\n' '%s'\n" "$line"; done
    echo "exit $rc"
  } >"$case_dir/$path" || lib_die "could not write $path in the copy"
  chmod +x "$case_dir/$path"
}

# run_test_all <platform>...: runs the copy's test-all.sh under this test's bash; sets $rc and
# leaves its output in $scratch/out.
run_test_all() {
  rc=0
  (cd "$case_dir" && "${BASH:-bash}" scripts/test-all.sh "$@") </dev/null >"$scratch/out" 2>&1 || rc=$?
}

# check <description> <expected exit status> <ERE>...: the last run exited with the status and its
# output has a line matching each ERE.
check() {
  local what=$1 want=$2 pattern ok=1
  shift 2
  tests_run=$((tests_run + 1))
  [ "$rc" -eq "$want" ] || ok=0
  for pattern in "$@"; do grep -Eq -- "$pattern" "$scratch/out" || ok=0; done
  if [ "$ok" -eq 1 ]; then
    echo "ok   - $what"
  else
    echo "FAIL - $what: exit $rc (expected $want), wanted lines matching: $*"
    sed 's/^/       /' "$scratch/out"
    tests_failed=$((tests_failed + 1))
  fi
}

# check_absent <description> <ERE>: no line of the last run's output matches the ERE.
check_absent() {
  tests_run=$((tests_run + 1))
  if grep -Eq -- "$2" "$scratch/out"; then
    echo "FAIL - $1: unexpected output matching /$2/"
    sed 's/^/       /' "$scratch/out"
    tests_failed=$((tests_failed + 1))
  else
    echo "ok   - $1"
  fi
}

# --- Each platform runs its own script ----------------------------------------------------------------

new_case all-pass
fixture bindings/wasm/test.sh 0 'fixture wasm suite ran'
fixture bindings/node/test.sh 0 'fixture node suite ran'
fixture platforms/android/test.sh 0 'fixture android suite ran'
fixture platforms/swift/test.sh 0 'fixture apple suite ran'
run_test_all wasm node android apple
check "each platform runs its script and passes on exit 0" 0 \
  '^fixture wasm suite ran$' '^fixture node suite ran$' '^fixture android suite ran$' '^fixture apple suite ran$' \
  '^  wasm: PASS$' '^  node: PASS$' '^  android: PASS$' '^  apple: PASS$'
check_absent "no platform falls back to its inline commands" 'wasm-pack test|npm ci|gradlew test|swift test'

# The independent RSA-OAEP-256 oracle (feature 0003 T11) is not a binding suite: it still runs.
if command -v node >/dev/null 2>&1; then
  check "the node platform still runs the RSA-OAEP-256 oracle" 0 '^  rsa-oaep-oracle: PASS$'
else
  check "the node platform still reports the RSA-OAEP-256 oracle" 0 '^  rsa-oaep-oracle: SKIPPED \(node missing\)$'
fi

# --- Exit status and the SKIPPED line -----------------------------------------------------------------

new_case fail
fixture platforms/android/test.sh 3 'fixture android suite failed'
run_test_all android
check "a script that exits non-zero FAILs the platform and the run" 1 \
  '^fixture android suite failed$' '^  android: FAIL$'

new_case skipped
fixture platforms/swift/test.sh 0 'no iOS simulator found' 'SKIPPED (iOS 27.2 simulator missing)'
run_test_all apple
check "SKIPPED (<reason>) as the last line with exit 0 reports SKIPPED with that reason" 0 \
  '^  apple: SKIPPED \(iOS 27\.2 simulator missing\)$'
check_absent "a skipped platform is not reported as passing" '^  apple: PASS$'

new_case skipped-trailing-blank
fixture bindings/wasm/test.sh 0 'SKIPPED (no Chrome)' ''
run_test_all wasm
check "trailing blank lines after the SKIPPED line still report SKIPPED" 0 '^  wasm: SKIPPED \(no Chrome\)$'

new_case skipped-but-failed
fixture bindings/node/test.sh 1 'SKIPPED (npm missing)'
run_test_all node
check "a SKIPPED line does not hide a non-zero exit status" 1 '^  node: FAIL$'

new_case skipped-not-last
fixture bindings/wasm/test.sh 0 'SKIPPED (one browser missing)' 'node tests passed'
run_test_all wasm
check "SKIPPED on an earlier line is ordinary output: exit 0 passes" 0 '^  wasm: PASS$'

new_case skipped-malformed
fixture platforms/android/test.sh 0 'SKIPPED'
run_test_all android
check "a last line starting with SKIPPED but without (<reason>) FAILs" 1 \
  '^  android: FAIL$' 'SKIPPED \(<reason>\)'

new_case not-executable
fixture platforms/swift/test.sh 0 'fixture apple suite ran'
chmod -x "$case_dir/platforms/swift/test.sh"
run_test_all apple
check "a script that exists but is not executable FAILs instead of falling back" 1 \
  '^  apple: FAIL$' 'platforms/swift/test\.sh exists but is not an executable file'
check_absent "a non-executable script is not run" '^fixture apple suite ran$'

new_case stdin
fixture bindings/wasm/test.sh 0 'fixture wasm suite ran'
# (Inserted before the fixture's final exit.)
python3 -I -c '
import sys
path = sys.argv[1]
lines = open(path).read().splitlines(True)
lines.insert(-1, "read -r line && echo \"read stdin: $line\"\n")
open(path, "w").write("".join(lines))
' "$case_dir/bindings/wasm/test.sh" || lib_die "could not edit the fixture"
rc=0
(cd "$case_dir" && "${BASH:-bash}" scripts/test-all.sh wasm) <<<"caller input" >"$scratch/out" 2>&1 || rc=$?
check "a script reading stdin still runs" 0 '^  wasm: PASS$'
check_absent "a script gets no stdin from the caller" '^read stdin:'

# --- Without a script: today's behaviour --------------------------------------------------------------

# No platforms/android/test.sh and no Gradle wrapper: the inline check reports it SKIPPED, as before.
new_case android-fallback
rm -f "$case_dir/platforms/android/test.sh" "$case_dir/platforms/android/gradlew"
run_test_all android
check "without a script, a platform keeps its inline SKIPPED reason" 0 \
  '^  android: SKIPPED \(cargo-ndk or Gradle project missing\)$'

new_case apple-fallback
rm -f "$case_dir/platforms/swift/test.sh" "$case_dir/Package.swift"
run_test_all apple
check "without a script, apple keeps its inline SKIPPED reason" 0 '^  apple: SKIPPED \(swift or Package\.swift missing\)$'

finish
