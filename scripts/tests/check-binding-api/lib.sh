# shellcheck shell=bash
# Shared helpers for the negative tests of scripts/check-binding-api.sh. Sourced, not run.
#
# Each case copies what the name check reads (the script and its modes, the inventory, the
# surface sources, the core's error.rs and the bindings/js sources) into a temporary directory,
# changes one thing in the copy by exact text replacement, runs the copy's check under the bash
# that runs the test ($BASH), and checks the exit status and the output. A failing case must print
# exactly the expected difference lines, so no other check is what caught the change. The real
# checkout is never modified.
#
# The js cases need node and npm. They reuse bindings/js/node_modules when its tsc runs on this
# machine, and otherwise install it once with npm ci into the scratch directory (a Linux container
# cannot run a macOS tsc binary).
#
# Runs on macOS /bin/bash 3.2 and Linux bash 5.

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd -P)
tests_failed=0
tests_run=0

lib_die() { echo "ERROR: $*" >&2; exit 2; }

command -v python3 >/dev/null 2>&1 || lib_die "python3 not found on PATH"
[ -x "$repo/scripts/check-binding-api.sh" ] || lib_die "$repo/scripts/check-binding-api.sh is not executable"

scratch=$(mktemp -d "${TMPDIR:-/tmp}/check-binding-api-test.XXXXXX") || lib_die "mktemp failed"
# Fail closed on a syntax error under bash 3.2 (feature 0013 F10, F11; see scripts/test-all.sh): with
# errexit, bash 3.2 runs the EXIT trap with $? = 0 after a parse error, in a test or in this file.
# finish (each test's last statement) sets the sentinel, so a test that stops before it never exits 0.
completed=""
# shellcheck disable=SC2154 # rc is assigned by the trap itself (rc=$?)
trap 'rc=$?; rm -rf "$scratch"; [ -n "${completed:-}" ] || [ "$rc" -ne 0 ] || { echo "${0##*/}: stopped before finish (a syntax error?): failing closed" >&2; rc=2; }; exit "$rc"' EXIT

# A pristine copy that each case starts from (working-tree files, so uncommitted changes count).
base="$scratch/base"
mkdir -p "$base" || lib_die "could not create $base"
(cd "$repo" && tar --exclude 'bindings/js/node_modules' --exclude 'bindings/js/dist' \
  --exclude 'bindings/js/src/error-codes.ts' -cf - \
  scripts/check-binding-api.sh scripts/check-binding-api.d bindings/api-inventory.txt \
  bindings/surface/src crates/polyjose/src/error.rs bindings/js) | (cd "$base" && tar -xf -) \
  || lib_die "could not copy the inputs of the name check to $base"

# Expected counts come from the copied sources, never from numbers written into a case, so a code
# or an operation added to the API does not break the tests (B08).

# core_codes: polyjose::Error::CODES of the base, in order, one per line. Parsed here with Python,
# independently of the awk parse of the main script, so a mistake in that parse is not repeated.
core_codes() {
  python3 -I -c '
import re, sys
with open(sys.argv[1], encoding="utf-8") as f:
    text = f.read()
blocks = re.findall(r"pub const CODES: &\x27static \[&\x27static str\] = &\[(.*?)\];", text, re.S)
if len(blocks) != 1:
    sys.exit("expected exactly one Error::CODES block in %s, found %d" % (sys.argv[1], len(blocks)))
codes = re.findall(r"\"([^\"]*)\"", blocks[0])
if not codes:
    sys.exit("the Error::CODES block of %s has no codes" % sys.argv[1])
print("\n".join(codes))
' "$base/crates/polyjose/src/error.rs" || lib_die "could not read Error::CODES from the copy"
}

# inventory_count <kind>: the number of <kind> entries (op, record, field, code) in the base's
# inventory. Leading whitespace is layout and '#' starts a comment line (the inventory's format).
inventory_count() {
  awk -v kind="$1" '$1 == kind { n++ } END { print n + 0 }' "$base/bindings/api-inventory.txt" \
    || lib_die "could not count the inventory's $1 entries"
}

# js_modules: a bindings/js/node_modules whose tsc runs here, set up on first use (needs node, npm).
js_modules=""
need_js_modules() {
  [ -z "$js_modules" ] || return 0
  if "$repo/bindings/js/node_modules/.bin/tsc" --version >/dev/null 2>&1; then
    js_modules=$repo/bindings/js/node_modules
    return 0
  fi
  mkdir -p "$scratch/js-install" || lib_die "could not create $scratch/js-install"
  cp "$repo/bindings/js/package.json" "$repo/bindings/js/package-lock.json" "$scratch/js-install/" \
    || lib_die "could not copy bindings/js/package*.json"
  (cd "$scratch/js-install" && npm ci --no-audit --no-fund --loglevel=error) >"$scratch/npm.log" 2>&1 \
    || { cat "$scratch/npm.log" >&2; lib_die "npm ci failed for the js cases"; }
  js_modules=$scratch/js-install/node_modules
}

# new_case <name> [<base>]: a fresh copy of the base (or of the given directory, a changed copy of
# the base) in $case_dir.
new_case() {
  case_dir="$scratch/case-$1"
  rm -rf "$case_dir"
  cp -R "${2:-$base}" "$case_dir" || lib_die "could not copy ${2:-the base}"
}

# use_js_modules: links the case's bindings/js/node_modules to $js_modules.
use_js_modules() {
  need_js_modules
  ln -s "$js_modules" "$case_dir/bindings/js/node_modules" || lib_die "could not link node_modules"
}

# edit <path in the copy> <old> <new>: replaces the one occurrence of <old> with <new>.
edit() {
  python3 -I -c '
import sys
path, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path, encoding="utf-8") as f:
    text = f.read()
count = text.count(old)
if count != 1:
    sys.exit("expected exactly one %r in %s, found %d" % (old, path, count))
with open(path, "w", encoding="utf-8") as f:
    f.write(text.replace(old, new, 1))
' "$case_dir/$1" "$2" "$3" || lib_die "edit of $1 failed"
}

# append <path in the copy> <text>: adds the text (and a newline) at the end of the file.
append() { printf '%s\n' "$2" >>"$case_dir/$1" || lib_die "could not append to $1"; }

# run_check [mode...]: runs the copy's check under this test's bash; sets $rc and leaves its output
# in $scratch/out.
run_check() {
  rc=0
  (cd "$case_dir" && "${BASH:-bash}" scripts/check-binding-api.sh "$@") </dev/null >"$scratch/out" 2>&1 || rc=$?
}

report() {
  tests_run=$((tests_run + 1))
  if [ "$2" -eq 1 ]; then
    echo "ok   - $1"
  else
    echo "FAIL - $1: $3"
    sed 's/^/       /' "$scratch/out"
    tests_failed=$((tests_failed + 1))
  fi
}

# check <description> <expected exit status> <ERE>...: the last run exited with the status and its
# output has a line matching each ERE.
check() {
  local what=$1 want=$2 pattern ok=1
  shift 2
  [ "$rc" -eq "$want" ] || ok=0
  for pattern in "$@"; do grep -Eq -- "$pattern" "$scratch/out" || ok=0; done
  report "$what" "$ok" "exit $rc (expected $want), wanted lines matching: $*"
}

# check_diffs <description> <line>...: the last run exited 1, and its difference lines (indented
# "missing from", "extra in", "defined twice in") are exactly the given lines, in any order.
check_diffs() {
  local what=$1 ok=1
  shift
  [ "$rc" -eq 1 ] || ok=0
  { grep -E '^  (missing from|extra in|defined twice in) ' "$scratch/out" || true; } | sed 's/^  //' | sort >"$scratch/got"
  printf '%s\n' "$@" | sort >"$scratch/want"
  cmp -s "$scratch/got" "$scratch/want" || ok=0
  report "$what" "$ok" "exit $rc (expected 1); wanted exactly these differences: $(tr '\n' ';' <"$scratch/want")"
}

# check_absent <description> <ERE>: no line of the last run's output matches the ERE.
check_absent() {
  local ok=1
  grep -Eq -- "$2" "$scratch/out" && ok=0
  report "$1" "$ok" "unexpected output matching /$2/"
}

# check_last_line <description> <expected exit status> <exact line>: the last non-blank line.
check_last_line() {
  local last ok=1
  last=$(awk 'NF { line = $0 } END { print line }' "$scratch/out")
  [ "$rc" -eq "$2" ] || ok=0
  [ "$last" = "$3" ] || ok=0
  report "$1" "$ok" "exit $rc (expected $2), last line \"$last\" (expected \"$3\")"
}

# finish: prints the summary, sets the sentinel and fails if any check failed.
finish() {
  echo "$tests_run checks, $tests_failed failed"
  completed=1
  [ "$tests_failed" -eq 0 ]
}
