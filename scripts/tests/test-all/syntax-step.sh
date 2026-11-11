#!/usr/bin/env bash
# Test of the `syntax` step of scripts/test-all.sh (feature 0013 F10; pipeline rule 9): before any
# other step, and for any platforms named, it runs `bash -n` (test-all.sh's own bash) over
# scripts/*.sh, scripts/check-binding-api.d/*.sh, scripts/tests/**/*.sh, and, when present,
# bindings/*/test.sh, bindings/*/tests/*.sh, bindings/*/scripts/*.sh and platforms/*/test.sh. A file
# that does not parse FAILs the step, which names it, and the run; the other steps still run. So a
# syntax error that a script's own exit status would hide (macOS /bin/bash 3.2 exits 0 from an EXIT
# trap after one) still fails the gate.
#
# Each case runs test-all.sh in a copy of the working tree, under the bash that runs this test
# (lib.sh), with a broken script added or put in place of a real one. The platform a case names is
# a passing fixture (android_fixture): the cases test the syntax step and its place among the other
# steps, not the Android suite, so no Gradle build or emulator run happens. Usage:
# scripts/tests/test-all/syntax-step.sh
set -euo pipefail
export LC_ALL=C
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

broken='echo this file does not parse
if then'

# broken_file <path in the copy>: writes a script that bash -n rejects.
broken_file() {
  mkdir -p "$(dirname "$case_dir/$1")" || lib_die "could not create the directory of $1"
  printf '#!/usr/bin/env bash\n%s\n' "$broken" >"$case_dir/$1" || lib_die "could not write $1"
}

# android_fixture: the copy's android suite is a passing fixture that writes its runners' results.
android_fixture() {
  fixture platforms/android/test.sh 0 'fixture android suite ran'
  writes_own_results platforms/android/test.sh android
}

# --- A tree that parses ---------------------------------------------------------------------------------

new_case clean
android_fixture
run_test_all android
check "every script parses: the step passes" 0 '^==> syntax$' '^  syntax: PASS$'
check_order "it is the first step" '^==> syntax$' '^==> parity$'
check_order "it is the first line of the summary" '^Summary:$' '^  syntax: PASS$'
check_order "and nothing is reported before it" '^  syntax: PASS$' '^  android: '

new_case clean-rust
rust_fixtures 0 rust-core rust-surface
parity_fixture 0 'parity: ok'
run_test_all rust
check "with the rust platform the step passes too" 0 '^  syntax: PASS$'
check_order "it runs before the rust block's first step" '^==> syntax$' '^==> no-cargo-config$'

# --- Each place a broken script can be ------------------------------------------------------------------

# broken_case <name> <path in the copy>: a copy with a broken script at the path; the step FAILs
# naming it, the run exits 1, and the other steps still ran.
broken_case() {
  new_case "$1"
  android_fixture
  broken_file "$2"
  run_test_all android
  check "a broken $2 FAILs the step and the run" 1 '^  syntax: FAIL$' "$2"
  check_absent "a broken $2 is not reported as passing" '^  syntax: PASS$'
  check "the other steps still run after a broken $2" 1 '^fixture android suite ran$' '^  android: PASS$'
}

broken_case scripts scripts/f10-broken.sh
broken_case modes scripts/check-binding-api.d/f10-broken.sh
broken_case tests scripts/tests/f10/broken.sh
broken_case tests-nested scripts/tests/f10/deeper/broken.sh
broken_case tests-space "scripts/tests/f10 dir/broken.sh"
broken_case binding-suite bindings/js/test.sh
broken_case binding-tests bindings/ffi/tests/f10-broken.sh
broken_case binding-scripts bindings/f10/scripts/broken.sh
broken_case platform-suite platforms/f10/test.sh

# The gate itself: a syntax error in test-all.sh stops it with bash's own status 2 (it is parsed
# before its trap is installed; one after the trap is scripts/tests/syntax/guards.sh's case).
new_case self
python3 -I -c '
import sys
path = sys.argv[1]
with open(path, encoding="utf-8") as f:
    text = f.read()
anchor = "\nhave() {"
if text.count(anchor) != 1:
    sys.exit("no unique have() in %s" % path)
with open(path, "w", encoding="utf-8") as f:
    f.write(text.replace(anchor, "\nf10_unused() {\n  if then\n}" + anchor))
' "$case_dir/scripts/test-all.sh" || lib_die "could not edit the copy's test-all.sh"
run_test_all android
check "a syntax error in test-all.sh itself exits 2, never 0" 2 'syntax error'

# --- What is not a shell script -------------------------------------------------------------------------

new_case not-shell
mkdir -p "$case_dir/scripts/tests/f10"
printf 'if then\n' >"$case_dir/scripts/tests/f10/notes.txt"
printf 'if then\n' >"$case_dir/bindings/js/f10.sh"
android_fixture
run_test_all android
check "files outside the listed globs are not checked" 0 '^  syntax: PASS$'

finish
