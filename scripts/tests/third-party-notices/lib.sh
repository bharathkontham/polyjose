# shellcheck shell=bash
# Shared helpers for the tests of scripts/third-party-notices.sh (ADR 0020 §4). Sourced, not run.
#
# The tests run the script on the real workspace (read only: it writes nothing but its -o file,
# which goes to a scratch directory) and on small fixture workspaces of path crates built in the
# scratch directory, so no case needs the network. Run `cargo fetch --locked` once beforehand if
# the local registry does not have the workspace's crates yet.
#
# Runs on macOS /bin/bash 3.2 and Linux bash.

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd -P)
notices="$repo/scripts/third-party-notices.sh"
tests_failed=0
tests_run=0

lib_die() { echo "ERROR: $*" >&2; exit 2; }

command -v cargo >/dev/null 2>&1 || lib_die "cargo not found on PATH"
command -v python3 >/dev/null 2>&1 || lib_die "python3 not found on PATH"

scratch=$(mktemp -d "${TMPDIR:-/tmp}/third-party-notices-test.XXXXXX") || lib_die "mktemp failed"
trap 'rm -rf "$scratch"' EXIT

pass() { tests_run=$((tests_run + 1)); echo "ok   - $1"; }
fail() { tests_run=$((tests_run + 1)); tests_failed=$((tests_failed + 1)); echo "FAIL - $1"; }

# run_notices <output file> <args...>: runs the script with -o <output file> and the other
# arguments, keeping its stdout and stderr in $scratch/last.log and its exit status in $rc.
# shellcheck disable=SC2034 # rc is read by the tests that source this file
run_notices() {
  local out=$1; shift
  rc=0
  "$notices" "$@" -o "$out" >"$scratch/last.log" 2>&1 || rc=$?
}

show_log() { sed 's/^/    | /' "$scratch/last.log"; }

# The 80-character rule line that opens and closes every section heading of a notices file.
rule=$(printf '%080d' 0 | tr 0 =)

# has_crate <notices file> <crate>: the file has a section for <crate> (any version): a heading
# line "<name> <version>" right after a rule line. (The summary list repeats each name with its
# license, and license texts may hold shorter rules, so neither can match.)
has_crate() {
  awk -v rule="$rule" -v name="$2" '
    prev == rule && index($0, name " ") == 1 && substr($0, length(name) + 2) ~ /^[0-9][^ ]*$/ { found = 1 }
    { prev = $0 }
    END { exit !found }' "$1"
}

# expect_crates <label> <notices file> <present|absent> <crate...>
expect_crates() {
  local label=$1 file=$2 mode=$3 c missing=""
  shift 3
  for c in "$@"; do
    if has_crate "$file" "$c"; then [ "$mode" = absent ] && missing="$missing $c"
    else [ "$mode" = present ] && missing="$missing $c"; fi
  done
  if [ -z "$missing" ]; then pass "$label"
  else fail "$label (wrongly $([ "$mode" = present ] && echo missing || echo present):$missing)"; fi
}

# expect_text <label> <notices file> <fixed string>
expect_text() {
  if grep -qF -- "$3" "$2"; then pass "$1"; else fail "$1 (no line contains: $3)"; fi
}

# crate_section <notices file> <name> <version>: prints that crate's section, from its heading
# to the rule line that opens the next section.
crate_section() {
  awk -v rule="$rule" -v want="$2 $3" '
    prev == rule && $0 == want { on = 1 }
    on && $0 == rule && body { exit }
    on { print; if ($0 != rule && $0 != want) body = 1 }
    { prev = $0 }' "$1"
}

finish() {
  echo "$tests_run checks, $tests_failed failed"
  [ "$tests_failed" -eq 0 ]
}
