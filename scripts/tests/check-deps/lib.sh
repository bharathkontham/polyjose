# Shared helpers for the negative tests of scripts/check-deps.sh. Sourced, not run.
#
# Each test copies the repository's working tree (tracked and untracked files, not ignored ones,
# so no target/) into a temporary git repository, changes one thing in the copy, runs the copy's
# check-deps.sh and checks that it fails for that reason and no other. The real checkout is
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
trap 'rm -rf "$scratch"' EXIT

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

# new_case <name>: a fresh copy of the base in $case_dir.
new_case() {
  case_dir="$scratch/case-$1"
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

# expect_pass <description>: the copy's check-deps.sh exits 0.
expect_pass() {
  local rc=0
  tests_run=$((tests_run + 1))
  (cd "$case_dir" && scripts/check-deps.sh) >"$scratch/out" 2>&1 || rc=$?
  if [ "$rc" -eq 0 ]; then
    echo "ok   - $1: check-deps.sh passes"
  else
    echo "FAIL - $1: check-deps.sh exited $rc, expected 0"
    sed 's/^/       /' "$scratch/out"
    tests_failed=$((tests_failed + 1))
  fi
}

# expect_fail <description> <required ERE> <ERE every FAIL line must match>: the copy's
# check-deps.sh exits 1 (a check failed, not an error), its output matches the required pattern,
# and every FAIL line is the expected kind, so no other check is what caught the change.
expect_fail() {
  local rc=0 bad
  tests_run=$((tests_run + 1))
  (cd "$case_dir" && scripts/check-deps.sh) >"$scratch/out" 2>&1 || rc=$?
  bad=$(grep '^FAIL: ' "$scratch/out" | grep -Ev -- "$3" || true)
  if [ "$rc" -eq 1 ] && grep -Eq -- "$2" "$scratch/out" && [ -z "$bad" ]; then
    echo "ok   - $1: check-deps.sh fails as expected"
    grep -E -- "$2" "$scratch/out" | head -3 | sed 's/^/       /'
  else
    echo "FAIL - $1: exit $rc (expected 1), wanted output matching /$2/ and only FAIL lines matching /$3/"
    sed 's/^/       /' "$scratch/out"
    tests_failed=$((tests_failed + 1))
  fi
}

# finish: prints the summary and exits non-zero if any case failed.
finish() {
  echo "$((tests_run - tests_failed))/$tests_run cases passed"
  [ "$tests_failed" -eq 0 ]
}
