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

# The node platform's interop-jose step (feature 0010 I1) builds @polyjose/node and runs jose: in
# the base copy it is a passing stub, so the cases stay hermetic and build nothing.
if [ -f "$base/interop/node/test.sh" ]; then
  printf '#!/bin/sh\necho "fixture interop-jose ran"\n' >"$base/interop/node/test.sh" \
    || lib_die "could not stub interop/node/test.sh in the base copy"
fi

gate_name=test-all.sh

# Fail closed on a syntax error under bash 3.2 (feature 0013 F10; see scripts/test-all.sh): the
# EXIT trap of check-deps/lib.sh again, with the sentinel, which finish (each test's last
# statement) sets, so a test that stops before finish never exits 0.
completed=""
trap 'rc=$?; rm -rf "$scratch"; [ -n "${completed:-}" ] || [ "$rc" -ne 0 ] || { echo "${0##*/}: stopped before finish (a syntax error?): failing closed" >&2; rc=2; }; exit "$rc"' EXIT

# finish: prints the summary, sets the sentinel and exits non-zero if any case failed.
finish() {
  echo "$((tests_run - tests_failed))/$tests_run cases passed"
  completed=1
  [ "$tests_failed" -eq 0 ]
}

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

# writes_results <platform script> <runner>...: the fixture also writes target/conformance/<runner>.json.
writes_results() {
  local script=$1 runner
  shift
  for runner in "$@"; do
    fixture_append "$script" "mkdir -p target/conformance && echo '{}' >target/conformance/$runner.json"
  done
}

# writes_own_results <platform script> <platform>: the fixture also writes the results file of every
# runner (required or optional) on the platform's line of the copy's runner table.
writes_own_results() {
  local line runners r
  line=$(grep -E "^$2:" "$case_dir/scripts/test-all.sh") || lib_die "no runner-table line for $2 in the copy"
  read -r -a runners <<<"${line#*:}"
  for r in ${runners[@]+"${runners[@]}"}; do writes_results "$1" "${r%\?}"; done
}

# parity_fixture <exit status> <line>...: a fixture scripts/conformance-parity.sh that also prints its
# arguments and which results files it found.
parity_fixture() {
  fixture scripts/conformance-parity.sh "$@"
  fixture_append scripts/conformance-parity.sh 'echo "parity fixture args: $*"'
  # shellcheck disable=SC2016 # expanded by the fixture, not here
  fixture_append scripts/conformance-parity.sh 'echo "parity fixture saw: $(cd target/conformance && ls | tr "\n" " ")"'
}

# set_runners <platform> [<runner>...]: sets the platform's line of the copy's runner table
# (`results_runners` in scripts/test-all.sh) to these runners; with none, to the empty entry.
set_runners() {
  local platform=$1
  shift
  runner_table_edit "$platform" "$platform:${1:+ $*}"
}

# remove_runner_line <platform>: removes the platform's line from the copy's runner table.
remove_runner_line() { runner_table_edit "$1" ""; }

# runner_table_edit <platform> <new line, empty to remove it>: replaces the one line `<platform>:...`
# of the copy's scripts/test-all.sh; dies unless there is exactly one.
runner_table_edit() {
  python3 -I -c '
import re, sys
path, platform, new = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path, encoding="utf-8") as f:
    text = f.read()
pattern = re.compile("^" + re.escape(platform) + ":[^\n]*\n", re.M)
if len(pattern.findall(text)) != 1:
    sys.exit("%s: not exactly one runner-table line for %s" % (path, platform))
text = pattern.sub(lambda m: new + "\n" if new else "", text)
with open(path, "w", encoding="utf-8") as f:
    f.write(text)
' "$case_dir/scripts/test-all.sh" "$1" "$2" || lib_die "could not edit the runner table of the copy's test-all.sh"
}

# rust_fixtures <exit status of cargo test --workspace> [<results file stem>...]: makes
# `test-all.sh rust` cheap and hermetic in the copy. Every gate script of the rust block is a passing
# fixture (bindings/ffi/tests/generated-names.sh too; a case replaces it to test that step), one
# passing fixture stands in for scripts/tests/ (so this test does not run itself), and a cargo stub,
# first on PATH in run_test_all, does nothing and exits 0, except that `cargo test --workspace`
# writes target/conformance/<stem>.json for each stem and exits with the given status, and
# `cargo test -p polyjose --all-features` writes rust-core-deflate-fixed-rng.json, as the real
# runs do (a rust-core-<features>.json file is never the reference).
rust_fixtures() {
  local rc=$1 bin stem script
  shift
  for script in scripts/check-no-cargo-config.sh scripts/check-binding-api.sh scripts/check-test-vectors-off.sh \
    scripts/check-deps.sh scripts/check-rsa-symbols.sh; do
    fixture "$script" 0 "fixture ${script#scripts/} ran"
  done
  fixture bindings/ffi/tests/generated-names.sh 0 'fixture generated-names ran' 'generated-names: PASS'
  rm -rf "$case_dir/scripts/tests" || lib_die "could not remove the copy's scripts/tests"
  fixture scripts/tests/fixture/ok.sh 0 'fixture negative test ran'
  bin="$scratch/bin-${case_dir##*/}"
  rm -rf "$bin"; mkdir -p "$bin" || lib_die "could not create $bin"
  {
    echo '#!/bin/sh'
    echo 'case " $* " in'
    printf '  *" test --workspace "*)\n    mkdir -p target/conformance\n'
    for stem in "$@"; do printf "    echo '{}' >target/conformance/%s.json\n" "$stem"; done
    printf '    exit %s ;;\n' "$rc"
    printf "  *\" test -p polyjose --all-features \"*)\n    mkdir -p target/conformance && echo '{}' >target/conformance/rust-core-deflate-fixed-rng.json ;;\n"
    echo 'esac'
    echo 'exit 0'
  } >"$bin/cargo" || lib_die "could not write the cargo stub"
  chmod +x "$bin/cargo"
}

# run_test_all <platform>...: runs the copy's test-all.sh under this test's bash, with the case's
# cargo stub first on PATH if rust_fixtures made one; sets $rc and leaves its output in $scratch/out.
run_test_all() {
  local path=$PATH bin="$scratch/bin-${case_dir##*/}"
  [ -d "$bin" ] && path="$bin:$PATH"
  rc=0
  (cd "$case_dir" && PATH=$path "${BASH:-bash}" scripts/test-all.sh "$@") </dev/null >"$scratch/out" 2>&1 || rc=$?
}

# line_of <ERE>: the number of the first line of the last output that matches, or nothing.
line_of() { grep -nE -- "$1" "$scratch/out" | head -1 | cut -d: -f1 || true; }

# check_order <description> <ERE before> <ERE after>: both match, the first one earlier.
check_order() {
  local a b
  tests_run=$((tests_run + 1))
  a=$(line_of "$2"); b=$(line_of "$3")
  if [ -n "$a" ] && [ -n "$b" ] && [ "$a" -lt "$b" ]; then
    echo "ok   - $1"
  else
    echo "FAIL - $1: wanted /$2/ (line ${a:-none}) before /$3/ (line ${b:-none})"
    sed 's/^/       /' "$scratch/out"
    tests_failed=$((tests_failed + 1))
  fi
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
