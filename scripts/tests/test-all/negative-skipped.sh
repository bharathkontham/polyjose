#!/usr/bin/env bash
# Test of how `scripts/test-all.sh rust` reports a negative test that skips (feature 0013 F10;
# pipeline rule 9: a SKIPPED test is never PASS). A negative test (scripts/tests/<gate>/*.sh) whose
# last non-blank line is `SKIPPED (host:<tool>)`, with exit 0, is reported
# `negative: <gate>/<test>: SKIPPED (host:<tool>)` when <tool> is in test-all.sh's commented
# allowlist (negative_skip_tools); for any other tool, any other reason and any other line starting
# with SKIPPED (no reason, a bare reason, leading blanks) the test FAILs, and so does the run. A
# non-zero exit status FAILs whatever the last line says; a SKIPPED line before the last line is
# ordinary output.
#
# rust_fixtures (lib.sh) stands in for cargo and the gate scripts, and fixture negative tests for
# the real ones, so no build happens. Each case runs test-all.sh in a copy of the working tree,
# under the bash that runs this test. Usage: scripts/tests/test-all/negative-skipped.sh
set -euo pipefail
export LC_ALL=C
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

# --- The real allowlist -------------------------------------------------------------------------------

tests_run=$((tests_run + 1))
tools=$(sed -n 's/^negative_skip_tools="\(.*\)"$/\1/p' "$repo/scripts/test-all.sh")
if [ "$tools" = actionlint ]; then echo "ok   - the allowlist of host tools a negative test may lack is actionlint"
else echo "FAIL - the allowlist (negative_skip_tools in scripts/test-all.sh) is not the agreed one: '$tools'"; tests_failed=$((tests_failed + 1)); fi

# skip_case <name> <exit status> <line>...: a hermetic rust block whose parity holds, plus the
# negative test scripts/tests/fixture/skip.sh printing the lines and exiting with the status.
skip_case() {
  local name=$1
  shift
  new_case "$name"
  rust_fixtures 0 rust-core rust-surface
  parity_fixture 0 'parity: ok'
  fixture scripts/tests/fixture/skip.sh "$@"
}
step='negative: fixture/skip\.sh'

# --- An allowlisted host tool ---------------------------------------------------------------------------

skip_case allowed 0 'text cases ran' 'SKIPPED (host:actionlint)'
run_test_all rust
check "SKIPPED (host:<tool>) for an allowlisted tool reports SKIPPED" 0 "^  $step: SKIPPED \\(host:actionlint\\)$"
check_absent "a skipped negative test is not reported as passing" "^  $step: PASS$"
check "the other negative tests still pass" 0 '^  negative: fixture/ok\.sh: PASS$'

skip_case allowed-trailing 0 'SKIPPED (host:actionlint)' ''
fixture_append scripts/tests/fixture/skip.sh "printf 'SKIPPED (host:actionlint)\\r\\n   \\n'"
run_test_all rust
check "trailing blanks and a CR after the SKIPPED line still report SKIPPED" 0 "^  $step: SKIPPED \\(host:actionlint\\)$"

# The allowlist is data: a tool added to the copy's list is accepted.
skip_case allowlist-edited 0 'SKIPPED (host:f10-tool)'
python3 -I -c '
import sys
path = sys.argv[1]
with open(path, encoding="utf-8") as f:
    text = f.read()
old = "\nnegative_skip_tools=\"actionlint\"\n"
if text.count(old) != 1:
    sys.exit("no negative_skip_tools line in %s" % path)
with open(path, "w", encoding="utf-8") as f:
    f.write(text.replace(old, "\nnegative_skip_tools=\"actionlint f10-tool\"\n"))
' "$case_dir/scripts/test-all.sh" || lib_die "could not edit the copy's allowlist"
run_test_all rust
check "a tool added to the allowlist is accepted" 0 "^  $step: SKIPPED \\(host:f10-tool\\)$"

# --- Every other skip FAILs -----------------------------------------------------------------------------

skip_case other-tool 0 'SKIPPED (host:docker)'
run_test_all rust
check "SKIPPED (host:<tool>) for a tool not in the allowlist FAILs" 1 "^  $step: FAIL$" 'negative_skip_tools'
check_absent "it is not reported SKIPPED" "^  $step: SKIPPED"

skip_case other-reason 0 'SKIPPED (actionlint missing)'
run_test_all rust
check "a SKIPPED (<reason>) without host:<tool> FAILs" 1 "^  $step: FAIL$" 'SKIPPED \(host:<tool>\)'

# malformed_case <name> <line>: the SKIPPED line is not of the form; the test FAILs.
malformed_case() {
  skip_case "$1" 0 "$2"
  run_test_all rust
  check "a last line \"$2\" FAILs" 1 "^  $step: FAIL$"
  check_absent "\"$2\" is not reported as passing or skipped" "^  $step: (PASS|SKIPPED)"
}
malformed_case bare 'SKIPPED'
malformed_case colon 'SKIPPED: host:actionlint'
malformed_case empty-tool 'SKIPPED (host:)'
malformed_case upper-tool 'SKIPPED (host:Actionlint)'
malformed_case two-words 'SKIPPED (host:actionlint extra)'
malformed_case suffix 'SKIPPED (host:actionlint) later'
malformed_case leading-blank '  SKIPPED (host:actionlint)'
malformed_case lower-case 'skipped (host:actionlint)'

# --- Exit status and earlier lines ----------------------------------------------------------------------

skip_case skipped-but-failed 1 'SKIPPED (host:actionlint)'
run_test_all rust
check "a SKIPPED line does not hide a non-zero exit status" 1 "^  $step: FAIL$"

skip_case skipped-not-last 0 'SKIPPED (host:docker)' '3/3 cases passed'
run_test_all rust
check "SKIPPED on an earlier line is ordinary output: exit 0 passes" 0 "^  $step: PASS$"

skip_case stdin 0 'fixture skip test ran'
# shellcheck disable=SC2016 # expanded by the fixture, not here
fixture_append scripts/tests/fixture/skip.sh 'read -r line && echo "read stdin: $line"'
rc=0
(cd "$case_dir" && PATH="$scratch/bin-${case_dir##*/}:$PATH" "${BASH:-bash}" scripts/test-all.sh rust) \
  <<<"caller input" >"$scratch/out" 2>&1 || rc=$?
check "a negative test reading stdin still runs" 0 "^  $step: PASS$"
check_absent "a negative test gets no stdin from the caller" '^read stdin:'

finish
