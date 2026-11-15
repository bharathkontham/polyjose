# shellcheck shell=bash
# Shared helpers for the negative tests of scripts/check-deps.sh and the gates beside it (such as
# scripts/check-rsa-symbols.sh). Sourced, not run.
#
# Each test copies the repository's working tree (tracked and untracked files, not ignored ones,
# so no target/) into a temporary git repository, changes one thing in the copy, runs the copy's
# gate (check-deps.sh unless the test redefines run_gate) and checks that it fails for that reason
# and no other. The real checkout is
# never modified. Cargo resolves an added dependency from the local registry cache first
# (--offline), and from crates.io only if that fails.
#
# Runs on macOS /bin/bash 3.2 and Linux bash.

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd -P)
tests_failed=0
tests_run=0

lib_die() { echo "ERROR: $*" >&2; exit 2; }

command -v git >/dev/null 2>&1 || lib_die "git not found on PATH"
command -v cargo >/dev/null 2>&1 || lib_die "cargo not found on PATH"
command -v python3 >/dev/null 2>&1 || lib_die "python3 not found on PATH"

scratch=$(mktemp -d "${TMPDIR:-/tmp}/check-deps-test.XXXXXX") || lib_die "mktemp failed"
# Fail closed on a syntax error under bash 3.2 (feature 0013 F10, F11; see scripts/test-all.sh): with
# errexit, bash 3.2 runs the EXIT trap with $? = 0 after a parse error, in a test or in this file.
# finish (each test's last statement) sets the sentinel, so a test that stops before it never exits 0.
completed=""
# shellcheck disable=SC2154 # rc is assigned by the trap itself (rc=$?)
# The wait lets gate runs still in the background (concurrent_cases) finish before their copies go.
trap 'rc=$?; wait; rm -rf "$scratch"; [ -n "${completed:-}" ] || [ "$rc" -ne 0 ] || { echo "${0##*/}: stopped before finish (a syntax error?): failing closed" >&2; rc=2; }; exit "$rc"' EXIT

# A pristine copy of the working tree that each case starts from.
base="$scratch/base"
mkdir "$base"
(cd "$repo" && git ls-files -z --cached --others --exclude-standard) >"$scratch/files.z" \
  || lib_die "git ls-files failed in $repo"
# Tracked files deleted from the working tree are skipped.
python3 -I -c '
import os, sys
root, listing = sys.argv[1], sys.argv[2]
with open(listing, "rb") as f:
    names = [n for n in f.read().split(b"\0") if n]
sys.stdout.buffer.write(b"".join(n + b"\0" for n in names if os.path.lexists(os.path.join(root.encode(), n))))
' "$repo" "$scratch/files.z" >"$scratch/present.z" || lib_die "could not list the working tree"
(cd "$repo" && tar --null -T "$scratch/present.z" -cf -) | (cd "$base" && tar -xf -) \
  || lib_die "could not copy the working tree to $base"
# check-deps.sh (through check-no-cargo-config.sh) needs a git work tree; the index is enough.
git -C "$base" init -q || lib_die "git init failed"
git -C "$base" add -A || lib_die "git add failed"

# The gate under test: run_gate runs it in the current directory (a copy), and gate_name names it
# in the results. A test of another gate redefines both after sourcing this file.
gate_name=check-deps.sh
run_gate() { scripts/check-deps.sh; }

# Concurrent cases (opt-in): a test whose cases each have their own copy and read nothing but the
# results of expect_pass and expect_fail may call `concurrent_cases` after sourcing this file. Its
# gate runs then start in the background, up to $CHECK_DEPS_TEST_JOBS at a time (default 4), and
# each is judged, with the same assertions and in the same order as one at a time, when it is the
# oldest one running and a slot is needed, or at finish. Every case's output goes to its own file.
# A copy is never changed once its gate has started (the next case is a new copy); a case name
# used twice is an error in this mode.
case_jobs=1
# The pending gate runs, oldest first: q_head..q_tail-1 of the q_* arrays.
q_head=0
q_tail=0
concurrent_cases() {
  case_jobs=${CHECK_DEPS_TEST_JOBS:-4}
  case $case_jobs in '' | 0 | *[!0-9]*) lib_die "CHECK_DEPS_TEST_JOBS must be a positive integer, not '$case_jobs'" ;; esac
}

# new_case <name>: a fresh copy of the base in $case_dir.
new_case() {
  case_dir="$scratch/case-$1"
  if [ "$case_jobs" -gt 1 ] && [ -e "$case_dir" ]; then lib_die "case $1 is used twice"; fi
  rm -rf "$case_dir"
  cp -R "$base" "$case_dir" || lib_die "could not copy the base tree"
}

# add_core_dependency <toml line>: adds a line to [dependencies] of the copy's core manifest and
# updates the copy's Cargo.lock for it.
add_core_dependency() {
  python3 -I -c '
import sys
path, line = sys.argv[1], sys.argv[2]
with open(path, encoding="utf-8") as f:
    text = f.read()
if "\n[dependencies]\n" not in text:
    sys.exit("no [dependencies] table in %s" % path)
text = text.replace("\n[dependencies]\n", "\n[dependencies]\n" + line + "\n", 1)
with open(path, "w", encoding="utf-8") as f:
    f.write(text)
' "$case_dir/crates/polyjose/Cargo.toml" "$1" || lib_die "could not edit the copy's crates/polyjose/Cargo.toml"
  relock
}

# relock: updates the copy's Cargo.lock after a manifest change, offline first.
relock() {
  (cd "$case_dir" && cargo metadata --offline --format-version 1 >/dev/null 2>"$scratch/relock.err") \
    || (cd "$case_dir" && cargo metadata --format-version 1 >/dev/null 2>"$scratch/relock.err") \
    || { cat "$scratch/relock.err" >&2; lib_die "cargo could not resolve the changed manifest"; }
}

# expect_pass <description>: the copy's gate exits 0.
expect_pass() { gate_case pass "$1" "" ""; }

# expect_fail <description> <required ERE> <ERE every FAIL line must match>: the copy's
# gate exits 1 (a check failed, not an error), its output matches the required pattern,
# and every FAIL line is the expected kind, so no other check is what caught the change.
expect_fail() { gate_case fail "$1" "$2" "$3"; }

# gate_case <pass|fail> <description> <required ERE> <FAIL-line ERE>: runs the copy's gate and
# judges it (judge_case), at once, or in the background under concurrent_cases. The gate's output
# goes to $scratch/out one case at a time, to $case_dir.out (beside the copy) concurrently.
gate_case() {
  local rc=0
  if [ "$case_jobs" -le 1 ]; then
    (cd "$case_dir" && run_gate) >"$scratch/out" 2>&1 || rc=$?
    judge_case "$1" "$2" "$3" "$4" "$scratch/out" "$rc"
    return 0
  fi
  # The gate's status goes to $case_dir.rc once it has finished; judge_oldest fails a case with none.
  rm -f "$case_dir.rc"
  { (cd "$case_dir" && run_gate) >"$case_dir.out" 2>&1 || rc=$?; echo "$rc" >"$case_dir.rc"; } &
  q_pid[q_tail]=$!; q_dir[q_tail]=$case_dir
  q_kind[q_tail]=$1; q_desc[q_tail]=$2; q_req[q_tail]=$3; q_only[q_tail]=$4
  q_tail=$((q_tail + 1))
  if [ $((q_tail - q_head)) -ge "$case_jobs" ]; then judge_oldest; fi
}

# judge_oldest: waits for the oldest gate run still pending and judges it.
judge_oldest() {
  local i=$q_head rc
  [ "$i" -lt "$q_tail" ] || return 0
  q_head=$((i + 1))
  wait "${q_pid[i]}" || true
  rc=$(cat "${q_dir[i]}.rc" 2>/dev/null) || rc=""
  case $rc in '' | *[!0-9]*) rc="unknown (no exit status recorded)" ;; esac
  judge_case "${q_kind[i]}" "${q_desc[i]}" "${q_req[i]}" "${q_only[i]}" "${q_dir[i]}.out" "$rc"
}

# judge_case <pass|fail> <description> <required ERE> <FAIL-line ERE> <output file> <exit status>:
# the assertions of expect_pass and expect_fail.
judge_case() {
  local bad
  tests_run=$((tests_run + 1))
  if [ "$1" = pass ]; then
    if [ "$6" = 0 ]; then
      echo "ok   - $2: $gate_name passes"
    else
      echo "FAIL - $2: $gate_name exited $6, expected 0"
      sed 's/^/       /' "$5"
      tests_failed=$((tests_failed + 1))
    fi
    return 0
  fi
  bad=$(grep '^FAIL: ' "$5" | grep -Ev -- "$4" || true)
  if [ "$6" = 1 ] && grep -Eq -- "$3" "$5" && [ -z "$bad" ]; then
    echo "ok   - $2: $gate_name fails as expected"
    grep -E -- "$3" "$5" | head -3 | sed 's/^/       /'
  else
    echo "FAIL - $2: exit $6 (expected 1), wanted output matching /$3/ and only FAIL lines matching /$4/"
    sed 's/^/       /' "$5"
    tests_failed=$((tests_failed + 1))
  fi
}

# finish: judges the gate runs still pending, prints the summary, sets the sentinel and exits
# non-zero if any case failed.
finish() {
  while [ "$q_head" -lt "$q_tail" ]; do judge_oldest; done
  echo "$((tests_run - tests_failed))/$tests_run cases passed"
  completed=1
  [ "$tests_failed" -eq 0 ]
}

# append_to <path in the copy> <text>: appends the text (and a newline) to a file of the copy,
# creating it if needed.
append_to() {
  mkdir -p "$(dirname "$case_dir/$1")" || lib_die "could not create the directory of $1"
  printf '%s\n' "$2" >>"$case_dir/$1" || lib_die "could not write $1 in the copy"
}

# replace_in <path in the copy> <old> <new>: replaces the one occurrence of <old>, then relocks.
replace_in() {
  python3 -I -c '
import sys
path, old, new = sys.argv[1:4]
with open(path, encoding="utf-8") as f:
    text = f.read()
if text.count(old) != 1:
    sys.exit("expected exactly one %r in %s" % (old, path))
with open(path, "w", encoding="utf-8") as f:
    f.write(text.replace(old, new))
' "$case_dir/$1" "$2" "$3" || lib_die "could not edit $1 in the copy"
  relock
}
