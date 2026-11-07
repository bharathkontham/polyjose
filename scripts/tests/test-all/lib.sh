# shellcheck shell=bash
# Shared helpers for the tests of scripts/test-all.sh. Sourced, not run.
#
# Each case runs test-all.sh in a copy of the working tree (scripts/tests/check-deps/lib.sh: tracked
# and untracked files, not ignored ones, so no target/) with fixture scripts in place of the real
# ones, under the bash that runs the test ($BASH), so `/bin/bash scripts/tests/test-all/<test>.sh`
# checks bash 3.2 and a Linux bash checks bash 5. Only non-rust platforms run, so no cargo build
# happens. Runs on macOS /bin/bash 3.2 and Linux bash.

# shellcheck source=../check-deps/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/../check-deps/lib.sh"

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

# fixture_append <path in the copy> <shell line>: adds a line to a fixture, before its final exit.
fixture_append() {
  python3 -I -c '
import sys
path, line = sys.argv[1], sys.argv[2]
with open(path, encoding="utf-8") as f:
    lines = f.read().splitlines(True)
if not lines or not lines[-1].startswith("exit "):
    sys.exit("%s does not end with an exit line" % path)
lines.insert(len(lines) - 1, line + "\n")
with open(path, "w", encoding="utf-8") as f:
    f.write("".join(lines))
' "$case_dir/$1" "$2" || lib_die "could not edit the fixture $1"
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
