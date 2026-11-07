#!/usr/bin/env bash
# The parity job of .github/workflows/binding-android.yml (feature 0008 T05; ADR 0034 §5,
# ADR 0060): every Kotlin runner's results from the CI run against a fresh rust-core reference of
# the same checkout. Runs locally the same way.
#
#   platforms/android/scripts/ci-parity.sh <results-dir> [<expected-file>...]
#
# <results-dir> holds the downloaded conformance-* artifacts' files, flat (download-artifact with
# merge-multiple): jvm-<prefix>.json from each host-natives entry and android-emulator-ci.json from
# the emulator job. <expected-file>... are the file names that must be there; the default is the
# whole CI set:
#   jvm-darwin-aarch64.json jvm-linux-x86-64.json jvm-linux-aarch64.json jvm-win32-x86-64.json
#   android-emulator-ci.json
# darwin-x86-64 is cross-built and not tested in this workflow (ci-host-natives.sh), so it has no
# results file. A missing expected file is a FAIL, never a skip (ADR 0060 §7): a job that passed
# without its results must not pass parity.
#
# 1. `cargo test -p polyjose --test conformance --locked` (default features) writes the reference
#    target/conformance/rust-core.json (ADR 0034 §4).
# 2. A fresh directory, target/ci-parity/, gets rust-core.json and every *.json of <results-dir>;
#    nothing else, so no stale local results file takes part.
# 3. scripts/conformance-parity.sh on that directory, which compares ids, statuses, outcomes,
#    error codes, the polyjose version and vectors_digest (ADR 0060 §6). Each expected file must be
#    reported `PASS: <file>`.
#
# Exit status: 0 parity holds for every expected file; 1 a missing file, a parity failure or a
# failed reference run; 2 usage.
set -uo pipefail
# shellcheck source=ci-lib.sh source-path=SCRIPTDIR
. "$(dirname "$0")/ci-lib.sh"

fail() { echo "ci-parity: FAILED: $*"; exit 1; }
[ $# -ge 1 ] || { echo "usage: ${0##*/} <results-dir> [<expected-file>...]" >&2; exit 2; }
src=$1; shift
[ -d "$src" ] || ci_die "$src is not a directory"
src=$(cd "$src" && pwd -P) || exit 2
if [ $# -gt 0 ]; then expected=$*
else expected="jvm-darwin-aarch64.json jvm-linux-x86-64.json jvm-linux-aarch64.json jvm-win32-x86-64.json android-emulator-ci.json"; fi
for f in $expected; do
  case $f in rust-core*.json | */* | *[!A-Za-z0-9._-]* | [!a-z]*) ci_die "not a results file name: $f" ;; *.json) ;; *) ci_die "not a results file name: $f" ;; esac
done

missing=""
for f in $expected; do [ -f "$src/$f" ] && [ ! -L "$src/$f" ] || missing="$missing $f"; done
[ -z "$missing" ] || fail "no results for${missing} in $src (a job did not upload them)"
for f in "$src"/rust-core*.json; do
  [ ! -e "$f" ] || fail "$src holds $(basename "$f"); the reference is computed here, never downloaded"
done

echo "==> ci-parity: cargo test -p polyjose --test conformance --locked (the rust-core reference)"
rm -f "$ci_repo/target/conformance/rust-core.json"
(cd "$ci_repo" && cargo test -p polyjose --test conformance --locked) || fail "the rust-core reference run"
reference=$ci_repo/target/conformance/rust-core.json
problem=$(ci_check_results "$reference" rust-core) || fail "$problem"

dir=$ci_repo/target/ci-parity
{ rm -rf "$dir" && mkdir -p "$dir"; } || fail "cannot create $dir"
cp "$reference" "$dir/" || fail "cannot copy $reference"
names=""
for f in "$src"/*.json; do
  [ -f "$f" ] && [ ! -L "$f" ] || continue
  cp "$f" "$dir/" || fail "cannot copy $f"
  names="$names $(basename "$f")"
done

echo "==> ci-parity: scripts/conformance-parity.sh target/ci-parity (rust-core.json$names)"
log=$dir.log
"$ci_repo/scripts/conformance-parity.sh" "$dir" >"$log" 2>&1
rc=$?
cat "$log"
[ "$rc" -eq 0 ] || fail "scripts/conformance-parity.sh exited $rc"
for f in $expected; do
  grep -q "^PASS: $f " "$log" || fail "parity did not report PASS for $f"
done
echo "ci-parity: PASS ($(echo "$expected" | wc -w | tr -d ' ') expected file(s) equal to rust-core: $expected)"
