#!/usr/bin/env bash
# One notices file for one artifact built for several targets (feature 0013 F14, ADR 0020 §4): a
# JVM jar that bundles one host library per target contains exactly the union of their crate trees.
#   - repeated --target: the union of each target's crates (the same selection as one target),
#     each crate once, sorted by name, then version; byte-identical whatever the order of the
#     --target arguments; a repeated --target counts once (deduplicated, not rejected);
#   - fail closed: a crate that breaks the license policy in any one target's tree (GPL, no
#     license expression, Unlicense alone) fails the whole run, naming the crate and its target;
#     an unknown target, `all` or an empty --target fails it too; nothing is written or replaced;
#   - the real workspace: polyjose-ffi over the five host targets of the JVM jar (feature 0008)
#     lists exactly the union of their cargo trees.
#
# Offline (cargo --offline): run `cargo fetch --locked` first if the registry cache is cold.
set -uo pipefail
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
export LC_ALL=C

darwin=aarch64-apple-darwin android=aarch64-linux-android linux=x86_64-unknown-linux-gnu

# section_count <notices file> <crate>: how many sections that crate has (any version).
section_count() { headings "$1" | awk -v name="$2" '$1 == name { n++ } END { print n + 0 }'; }

# expect_once <label> <notices file> <crate...>: each crate has exactly one section.
expect_once() {
  local label=$1 file=$2 c bad=""
  shift 2
  for c in "$@"; do
    [ "$(section_count "$file" "$c")" = 1 ] || bad="$bad $c($(section_count "$file" "$c"))"
  done
  if [ -z "$bad" ]; then pass "$label"; else fail "$label (sections:$bad)"; fi
}

# expect_same <label> <file a> <file b>: both exist and are byte-identical.
expect_same() {
  if [ -s "$2" ] && [ -s "$3" ] && cmp -s "$2" "$3"; then pass "$1"
  else
    fail "$1"
    if [ -s "$2" ] && [ -s "$3" ]; then diff "$2" "$3" | head -20 | sed 's/^/    | /'; fi
  fi
}

# expect_reject_in <label> <crate label> <target>...: the last run failed with status 1, wrote no
# output file ($out), and one line of its log names the crate together with each given target.
expect_reject_in() {
  local label=$1 crate=$2 t missing=""
  shift 2
  grep -F -- "$crate" "$scratch/last.log" >"$scratch/lines.txt" || true
  for t in "$@"; do grep -qF -- "$t" "$scratch/lines.txt" || missing="$missing [$t]"; done
  if [ "$rc" -eq 1 ] && [ -s "$scratch/lines.txt" ] && [ -z "$missing" ] && [ ! -e "$out" ]; then pass "$label"
  else
    fail "$label (exit $rc, no line names $crate with:${missing:- -}, output $([ -e "$out" ] && echo written || echo absent))"
    show_log
  fi
}

# ---------------------------------------------------------------------------------------------
# Two targets with different trees: android-only and linux-only crates, one crate (shared) in
# both trees, one (common) in every tree.
new_fixture union
vendor_crate common MIT
crate_file common LICENSE "MARKER common"
vendor_crate shared MIT
crate_file shared LICENSE "MARKER shared"
vendor_crate androidonly MIT shared
crate_file androidonly LICENSE "MARKER androidonly"
vendor_crate linuxonly MIT shared
crate_file linuxonly LICENSE "MARKER linuxonly"
app_dep deps common
app_dep android-deps androidonly
app_dep linux-deps linuxonly
lock_fixture

fixture_run "$scratch/android.txt" "$android"
rc_android=$rc
fixture_run "$scratch/linux.txt" "$linux"
if [ "$rc_android" -eq 0 ] && [ "$rc" -eq 0 ] \
  && has_crate "$scratch/android.txt" androidonly && ! has_crate "$scratch/android.txt" linuxonly \
  && has_crate "$scratch/linux.txt" linuxonly && ! has_crate "$scratch/linux.txt" androidonly; then
  pass "the two fixture targets have different trees"
else fail "the two fixture targets have different trees (exit $rc_android, $rc)"; show_log; fi

out="$scratch/union.txt"
fixture_run "$out" "$android" "$linux"
if [ "$rc" -eq 0 ] && [ -s "$out" ]; then pass "two --target: the run succeeds"
else fail "two --target: the run fails (exit $rc)"; show_log; fi
if [ -s "$out" ]; then
  expect_crates "the union has both targets' own crates" "$out" present androidonly linuxonly common shared
  expect_once "each crate once, also one in both trees" "$out" androidonly linuxonly common shared
  { headings "$scratch/android.txt"; headings "$scratch/linux.txt"; } | sort -u >"$scratch/want.txt"
  headings "$out" >"$scratch/got.txt"
  if cmp -s "$scratch/got.txt" "$scratch/want.txt"; then pass "exactly the union of the two single-target files"
  else fail "not the union of the two single-target files (< union, > want)"; diff "$scratch/got.txt" "$scratch/want.txt" | sed 's/^/    | /'; fi
  expect_text "the third-party count is the union's" "$out" "Third-party crates (4)"
  expect_text "the header names both targets, sorted" "$out" "Targets: $android, $linux"
  if grep -q '^Target: ' "$out"; then fail "no single-target header line"; else pass "no single-target header line"; fi
  expect_text "the workspace's own crates are polyjose's" "$out" "Crates: app 0.1.0"
  expect_text "an android-only crate's license text" "$out" "MARKER androidonly"
  expect_text "a linux-only crate's license text" "$out" "MARKER linuxonly"
  awk -v rule="$rule" 'prev == rule && $0 ~ /^[A-Za-z0-9_-]+ [0-9][^ ]*$/ { print } { prev = $0 }' "$out" >"$scratch/order.txt"
  if sort "$scratch/order.txt" | cmp -s - "$scratch/order.txt"; then pass "sections sorted by name"
  else fail "sections sorted by name"; fi
fi

fixture_run "$scratch/union-reversed.txt" "$linux" "$android"
expect_same "the order of the --target arguments does not matter" "$out" "$scratch/union-reversed.txt"
fixture_run "$scratch/union3-a.txt" "$darwin" "$linux" "$android"
fixture_run "$scratch/union3-b.txt" "$android" "$darwin" "$linux"
expect_same "three targets in two orders are byte-identical" "$scratch/union3-a.txt" "$scratch/union3-b.txt"
if [ -s "$scratch/union3-a.txt" ]; then
  expect_text "three targets: the header names all three, sorted" "$scratch/union3-a.txt" \
    "Targets: $darwin, $android, $linux"
fi
fixture_run "$scratch/union-again.txt" "$android" "$linux" "$android"
expect_same "a repeated --target counts once (with another target)" "$out" "$scratch/union-again.txt"
fixture_run "$scratch/android-twice.txt" "$android" "$android"
expect_same "a repeated --target counts once (alone: the single-target file)" \
  "$scratch/android.txt" "$scratch/android-twice.txt"
fixture_run "$scratch/union-run2.txt" "$android" "$linux"
expect_same "two union runs are byte-identical" "$out" "$scratch/union-run2.txt"

# ---------------------------------------------------------------------------------------------
# Fail closed: an offender reachable on one target only fails the union run.
new_fixture second
vendor_crate common MIT
crate_file common LICENSE "MARKER common"
vendor_crate gpl-linux GPL-3.0-only
crate_file gpl-linux COPYING "GPL text"
app_dep deps common
app_dep linux-deps gpl-linux
lock_fixture
out="$scratch/second-darwin.txt"
fixture_run "$out" "$darwin"
if [ "$rc" -eq 0 ]; then pass "the GPL crate is not in the first target's tree: alone, it succeeds"
else fail "the first target alone fails (exit $rc)"; show_log; fi
rm -f "$out"
out="$scratch/second.txt"
fixture_run "$out" "$darwin" "$linux"
expect_reject_in "a GPL crate only on the second target fails, naming it and the target" "gpl-linux 0.1.0" "$linux"
fixture_run "$out" "$linux" "$darwin"
expect_reject_in "... in either argument order" "gpl-linux 0.1.0" "$linux"
printf 'previous notices\n' >"$out"
fixture_run "$out" "$darwin" "$linux"
if [ "$rc" -eq 1 ] && [ "$(cat "$out")" = "previous notices" ]; then pass "a failed union run leaves an existing output file unchanged"
else fail "a failed union run leaves an existing output file unchanged (exit $rc)"; fi
rm -f "$out"

# Several offenders on different targets: each named with the targets whose tree holds it.
new_fixture several
vendor_crate gpl-linux GPL-3.0-only
crate_file gpl-linux COPYING "GPL text"
vendor_crate unlicensed -
crate_file unlicensed LICENSE "some text"
vendor_crate lone-unlicense Unlicense
crate_file lone-unlicense LICENSE "unlicense text"
app_dep linux-deps gpl-linux
app_dep linux-deps lone-unlicense
app_dep android-deps unlicensed
app_dep android-deps lone-unlicense
lock_fixture
out="$scratch/several.txt"
fixture_run "$out" "$darwin" "$android" "$linux"
expect_reject_in "a GPL crate on one target is named with that target" "gpl-linux 0.1.0" "$linux"
expect_reject_in "a crate without a license expression on another target is named with it" "unlicensed 0.1.0" "$android"
expect_reject_in "Unlicense alone (F06's OR-only rule) on two targets is named with both" "lone-unlicense 0.1.0" "$android" "$linux"

# Unknown, `all` and empty targets.
out="$scratch/unknown.txt"
fixture_run "$out" "$darwin" bogus-unknown-none
expect_reject_in "an unknown target fails, naming it" "bogus-unknown-none"
fixture_run "$out" "$darwin" all
expect_reject_in "--target all among others fails" "--target all"
fixture_run "$out" "$darwin" ""
if [ "$rc" -eq 2 ] && [ ! -e "$out" ]; then pass "an empty --target is a usage error"
else fail "an empty --target is a usage error (exit $rc)"; show_log; fi

# ---------------------------------------------------------------------------------------------
# The real workspace: polyjose-ffi in the JVM jar of feature 0008, one host library per target.
jvm_targets="aarch64-apple-darwin x86_64-apple-darwin aarch64-unknown-linux-gnu x86_64-unknown-linux-gnu
x86_64-pc-windows-msvc"
out="$scratch/ffi-jvm.txt"
set --
for t in $jvm_targets; do set -- "$@" --target "$t"; done
run_notices "$out" -p polyjose-ffi "$@"
if [ "$rc" -eq 0 ] && [ -s "$out" ]; then pass "polyjose-ffi, five JVM host targets: the run succeeds"
else fail "polyjose-ffi, five JVM host targets: the run fails (exit $rc)"; show_log; fi
if [ -s "$out" ]; then
  for t in $jvm_targets; do tree_crates polyjose-ffi "$t"; done | sort -u >"$scratch/want.txt"
  headings "$out" >"$scratch/got.txt"
  n=$(wc -l <"$scratch/want.txt" | tr -d ' ')
  if [ -s "$scratch/want.txt" ] && cmp -s "$scratch/got.txt" "$scratch/want.txt"; then
    pass "polyjose-ffi JVM: exactly the union of the five cargo trees ($n crates)"
  else
    fail "polyjose-ffi JVM: crate sections differ from the union of the cargo trees (< notices, > union)"
    diff "$scratch/got.txt" "$scratch/want.txt" | sed 's/^/    | /'
  fi
  expect_text "polyjose-ffi JVM: the third-party count is the union's" "$out" "Third-party crates ($n)"
  # shellcheck disable=SC2086 # a word list
  sorted=$(printf '%s\n' $jvm_targets | sort | awk '{ printf "%s%s", sep, $0; sep = ", " }')
  expect_text "polyjose-ffi JVM: the header names the five targets, sorted" "$out" "Targets: $sorted"
  expect_once "polyjose-ffi JVM: framework and crypto crates once each" "$out" uniffi uniffi_core p256 rsa
fi

finish
