#!/usr/bin/env bash
# The license policy and crate selection of scripts/third-party-notices.sh (ADR 0020 §4), on
# fixture workspaces of local path crates (no registry, no network):
#   - a crate whose license expression names a license outside the allowlist (GPL, also inside
#     an OR; CC0-1.0, which deny.toml does not allow either), uses another WITH exception, is
#     malformed, or is missing (license-file only) fails the run, naming the crate, and no output
#     file is written or replaced;
#   - Unlicense passes only as an OR alternative to an allowed license (`Unlicense OR MIT`), not
#     alone, under an AND, or next to a license outside the allowlist;
#   - a crate without a license file passes only when its license is exactly MIT, Apache-2.0 or
#     MPL-2.0, and then gets the standard text from scripts/licenses/;
#   - only linked crates are listed: build-dependencies, dev-dependencies, proc-macros and the
#     dependencies of other targets are not (a GPL crate there does not fail the run);
#   - license files are found in every accepted spelling, CRLF is normalized to LF.
set -uo pipefail
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
export LC_ALL=C

# new_fixture <name>: an empty fixture: a workspace $fx/ws whose one member `app` (MIT, the
# workspace LICENSE is polyjose's) gets its dependencies from app_dep, and a directory
# $fx/vendor for its path dependencies, outside the workspace so they are not members.
new_fixture() {
  fx="$scratch/fixture-$1"
  rm -rf "$fx"
  mkdir -p "$fx/ws/app/src" "$fx/vendor"
  cp "$repo/LICENSE" "$fx/ws/LICENSE"
  printf '[workspace]\nresolver = "2"\nmembers = ["app"]\n' >"$fx/ws/Cargo.toml"
  : >"$fx/ws/app/src/lib.rs"
  app_license=MIT
  : >"$fx/deps"; : >"$fx/build-deps"; : >"$fx/dev-deps"; : >"$fx/android-deps"
}

# vendor_crate <name> <license expression | - (none) | file:<path> (license-file only)>
#              [proc-macro] [dep...]: a path crate in $fx/vendor depending on other vendor crates.
vendor_crate() {
  local name=$1 license=$2 kind="" d dir
  shift 2
  if [ "${1:-}" = proc-macro ]; then kind=proc-macro; shift; fi
  dir="$fx/vendor/$name"
  mkdir -p "$dir/src"
  : >"$dir/src/lib.rs"
  {
    printf '[package]\nname = "%s"\nversion = "0.1.0"\nedition = "2021"\n' "$name"
    printf 'repository = "https://example.invalid/%s"\n' "$name"
    case $license in
      -) ;;
      file:*) printf 'license-file = "%s"\n' "${license#file:}" ;;
      *) printf 'license = "%s"\n' "$license" ;;
    esac
    [ "$kind" = proc-macro ] && printf '\n[lib]\nproc-macro = true\n'
    printf '\n[dependencies]\n'
    for d in "$@"; do printf '%s = { path = "../%s" }\n' "$d" "$d"; done
  } >"$dir/Cargo.toml"
}

# crate_file <crate> <relative path> <text>: a file in that vendor crate's directory.
crate_file() {
  mkdir -p "$(dirname "$fx/vendor/$1/$2")"
  printf '%s\n' "$3" >"$fx/vendor/$1/$2"
}

# app_dep <deps|build-deps|dev-deps|android-deps> <crate>
app_dep() { printf '%s = { path = "../../vendor/%s" }\n' "$2" "$2" >>"$fx/$1"; }

# lock_fixture: writes app's manifest and the fixture's Cargo.lock (offline, path crates only).
lock_fixture() {
  {
    printf '[package]\nname = "app"\nversion = "0.1.0"\nedition = "2021"\nlicense = "%s"\n' "$app_license"
    printf 'repository = "https://example.invalid/app"\n'
    printf '\n[dependencies]\n'; cat "$fx/deps"
    printf '\n[build-dependencies]\n'; cat "$fx/build-deps"
    printf '\n[dev-dependencies]\n'; cat "$fx/dev-deps"
    printf '\n[target.'\''cfg(target_os = "android")'\''.dependencies]\n'; cat "$fx/android-deps"
  } >"$fx/ws/app/Cargo.toml"
  cargo generate-lockfile --offline --manifest-path "$fx/ws/Cargo.toml" >"$scratch/lock.log" 2>&1 \
    || { cat "$scratch/lock.log" >&2; lib_die "could not lock fixture $fx"; }
}

# fixture_run <output file> <target>
fixture_run() { run_notices "$1" -p app --target "$2" --manifest-path "$fx/ws/Cargo.toml"; }

# expect_reject <label> <crate label...>: the last run failed with status 1, its log names every
# given "<name> <version>", and it wrote no output file ($out).
expect_reject() {
  local label=$1 c missing=""
  shift
  for c in "$@"; do grep -qF -- "$c" "$scratch/last.log" || missing="$missing [$c]"; done
  if [ "$rc" -eq 1 ] && [ -z "$missing" ] && [ ! -e "$out" ]; then pass "$label"
  else
    fail "$label (exit $rc, crates not named:${missing:- none}, output $([ -e "$out" ] && echo written || echo absent))"
    show_log
  fi
}

# ---------------------------------------------------------------------------------------------
# Accepted: every allowlisted form, files in every spelling, only linked crates.
new_fixture ok
vendor_crate deep MIT
crate_file deep LICENSE "MARKER deep license"
vendor_crate mitfile MIT deep
printf 'MARKER mitfile line one\r\nMARKER mitfile line two\r\n' >"$fx/vendor/mitfile/LICENSE"
vendor_crate mitnofile MIT
vendor_crate apachenofile Apache-2.0
vendor_crate mplnofile MPL-2.0
vendor_crate llvm "Apache-2.0 WITH LLVM-exception"
crate_file llvm LICENSE-Apache-2.0_WITH_LLVM-exception "MARKER llvm license"
vendor_crate legacy "MIT/Apache-2.0"
crate_file legacy license-mit "MARKER legacy mit"
crate_file legacy LICENSE-APACHE.md "MARKER legacy apache"
vendor_crate paren "(MIT OR Apache-2.0) AND Unicode-3.0"
crate_file paren LICENSE-UNICODE "MARKER paren unicode"
vendor_crate others "BSD-3-Clause OR BSD-2-Clause OR ISC OR Zlib OR Unlicense"
crate_file others COPYING "MARKER others copying"
# Unlicense as an OR alternative to an allowed license, as memchr ships it (security audit I6).
vendor_crate unlicense-or "Unlicense OR MIT"
crate_file unlicense-or LICENSE-MIT "MARKER unlicense-or mit"
vendor_crate lowercase "mit OR apache-2.0"
crate_file lowercase LICENCE "MARKER lowercase licence"
vendor_crate licdir MIT
crate_file licdir LICENSES/MIT.txt "MARKER licdir LICENSES MIT"
crate_file licdir NOTICE "MARKER licdir notice"
crate_file licdir README.md "MARKER licdir readme"
vendor_crate pmdep GPL-3.0-only
vendor_crate pmacro GPL-3.0-only proc-macro pmdep
vendor_crate builddep GPL-3.0-only
vendor_crate devdep GPL-3.0-only
vendor_crate androidonly MIT
crate_file androidonly LICENSE "MARKER androidonly"
for c in mitfile mitnofile apachenofile mplnofile llvm legacy paren others unlicense-or lowercase licdir pmacro; do
  app_dep deps "$c"
done
app_dep build-deps builddep
app_dep dev-deps devdep
app_dep android-deps androidonly
lock_fixture

out="$scratch/ok-darwin.txt"
fixture_run "$out" aarch64-apple-darwin
if [ "$rc" -eq 0 ]; then pass "allowlisted licenses: the run succeeds"
else fail "allowlisted licenses: the run fails (exit $rc)"; show_log; fi
if [ -f "$out" ]; then
  expect_crates "linked crates are listed, transitive ones too" "$out" present \
    deep mitfile mitnofile apachenofile mplnofile llvm legacy paren others unlicense-or lowercase licdir
  expect_crates "proc-macros, their dependencies, build- and dev-dependencies are not" "$out" absent \
    pmacro pmdep builddep devdep
  expect_crates "another target's dependency is not" "$out" absent androidonly
  expect_text "the workspace's own crates are polyjose's" "$out" "Crates: app 0.1.0"
  expect_text "a license file's full text" "$out" "MARKER deep license"
  # Sections go through a file: `grep -q` after a pipe could SIGPIPE the writer (pipefail).
  crate_section "$out" mitfile 0.1.0 >"$scratch/sec.txt"
  if grep -qxF 'MARKER mitfile line two' "$scratch/sec.txt" \
    && ! LC_ALL=C grep -q "$(printf '\r')" "$out"; then pass "CRLF license text is written with LF"
  else fail "CRLF license text is written with LF"; fi
  crate_section "$out" mitnofile 0.1.0 >"$scratch/sec.txt"
  if grep -q '^--- License text: standard MIT ' "$scratch/sec.txt" \
    && grep -qxF 'MIT License' "$scratch/sec.txt" && grep -q '^Permission is hereby granted' "$scratch/sec.txt"; then
    pass "MIT, no license file: the standard MIT text"
  else fail "MIT, no license file: the standard MIT text"; fi
  crate_section "$out" apachenofile 0.1.0 >"$scratch/sec.txt"
  if grep -q '^--- License text: standard Apache-2.0 ' "$scratch/sec.txt" \
    && grep -q 'Version 2.0, January 2004' "$scratch/sec.txt"; then
    pass "Apache-2.0, no license file: the standard Apache-2.0 text"
  else fail "Apache-2.0, no license file: the standard Apache-2.0 text"; fi
  crate_section "$out" mplnofile 0.1.0 >"$scratch/sec.txt"
  if grep -q '^--- License text: standard MPL-2.0 ' "$scratch/sec.txt" \
    && grep -qxF 'Mozilla Public License Version 2.0' "$scratch/sec.txt"; then
    pass "MPL-2.0, no license file: the standard MPL-2.0 text"
  else fail "MPL-2.0, no license file: the standard MPL-2.0 text"; fi
  crate_section "$out" licdir 0.1.0 >"$scratch/sec.txt"
  if grep -qxF -- '--- License text: LICENSES/MIT.txt ---' "$scratch/sec.txt" \
    && grep -qxF -- '--- License text: NOTICE ---' "$scratch/sec.txt" \
    && ! grep -qF 'MARKER licdir readme' "$scratch/sec.txt"; then
    pass "LICENSES/ directory and NOTICE are included, README is not"
  else fail "LICENSES/ directory and NOTICE are included, README is not"; fi
  for m in "legacy mit" "legacy apache" "llvm license" "paren unicode" "others copying" "lowercase licence"; do
    expect_text "license file spelling ($m)" "$out" "MARKER $m"
  done
  if grep -qF "$scratch" "$out"; then fail "no local path of a path crate"; else pass "no local path of a path crate"; fi
fi

out="$scratch/ok-android.txt"
fixture_run "$out" aarch64-linux-android
if [ "$rc" -eq 0 ] && has_crate "$out" androidonly; then pass "the target's own dependency is listed"
else fail "the target's own dependency is listed (exit $rc)"; show_log; fi

# ---------------------------------------------------------------------------------------------
# Rejected, one case per rule. Each fixture: app -> the offending crate (with a license file, so
# only the expression is at fault, unless the case is about files).
reject_case() { # reject_case <case> <license> [no-file]
  new_fixture "$1"
  vendor_crate bad-crate "$2"
  [ "${3:-}" = no-file ] || crate_file bad-crate LICENSE "license text"
  app_dep deps bad-crate
  lock_fixture
  out="$scratch/$1.txt"
  fixture_run "$out" aarch64-apple-darwin
}
reject_case gpl GPL-3.0-only;                       expect_reject "GPL-3.0-only fails" "bad-crate 0.1.0"
reject_case gpl-or "MIT OR GPL-2.0-or-later";       expect_reject "a GPL alternative in an OR fails" "bad-crate 0.1.0"
reject_case lgpl-and "MIT AND LGPL-2.1-only";       expect_reject "LGPL inside an AND fails" "bad-crate 0.1.0"
reject_case agpl AGPL-3.0-only;                     expect_reject "AGPL fails" "bad-crate 0.1.0"
reject_case plus "Apache-2.0+";                     expect_reject "an or-later + suffix fails" "bad-crate 0.1.0"
reject_case exception "Apache-2.0 WITH Classpath-exception-2.0"; expect_reject "another WITH exception fails" "bad-crate 0.1.0"
reject_case with-mit "MIT WITH LLVM-exception";     expect_reject "LLVM-exception on a license other than Apache-2.0 fails" "bad-crate 0.1.0"
reject_case malformed "MIT OR";                     expect_reject "a malformed expression fails" "bad-crate 0.1.0"
reject_case unbalanced "(MIT OR Apache-2.0";        expect_reject "unbalanced parentheses fail" "bad-crate 0.1.0"
reject_case lowercase-op "MIT or Apache-2.0";       expect_reject "a lower-case operator fails" "bad-crate 0.1.0"
reject_case none -;                                 expect_reject "no license expression fails" "bad-crate 0.1.0"
reject_case license-file file:LICENSE;              expect_reject "license-file without an expression fails" "bad-crate 0.1.0"
reject_case dual-no-file "MIT OR Apache-2.0" no-file; expect_reject "no license file and not a single standard license fails" "bad-crate 0.1.0"
reject_case bsd-no-file BSD-3-Clause no-file;       expect_reject "BSD-3-Clause without its license file fails" "bad-crate 0.1.0"
# deny.toml [licenses].allow has no CC0-1.0, so neither has the notices allowlist (security audit I6).
reject_case cc0 CC0-1.0;                           expect_reject "a CC0-1.0-only crate fails" "bad-crate 0.1.0"
reject_case cc0-or "MIT OR CC0-1.0";               expect_reject "a CC0-1.0 alternative in an OR fails" "bad-crate 0.1.0"
# Nor has it Unlicense: the notices accept it only as an OR alternative to an allowed license.
reject_case unlicense Unlicense;                   expect_reject "an Unlicense-only crate fails" "bad-crate 0.1.0"
reject_case unlicense-and "Unlicense AND MIT";     expect_reject "Unlicense inside an AND fails" "bad-crate 0.1.0"
reject_case unlicense-nested "(Unlicense AND MIT) OR Apache-2.0"; expect_reject "Unlicense inside an AND within an OR fails" "bad-crate 0.1.0"
reject_case unlicense-or-gpl "Unlicense OR GPL-3.0-only"; expect_reject "Unlicense OR a license outside the allowlist fails" "bad-crate 0.1.0"

# A GPL crate deep in the tree, next to a second offender: both named, nothing written, and an
# existing output file is left as it was.
new_fixture deep
vendor_crate gpl-deep GPL-2.0-only
crate_file gpl-deep COPYING "GPL text"
vendor_crate middle MIT gpl-deep
crate_file middle LICENSE "MIT text"
vendor_crate unlicensed -
crate_file unlicensed LICENSE "some text"
app_dep deps middle
app_dep deps unlicensed
lock_fixture
out="$scratch/deep.txt"
fixture_run "$out" aarch64-apple-darwin
expect_reject "a transitive GPL crate and a second offender are both named" "gpl-deep 0.1.0" "unlicensed 0.1.0"
printf 'previous notices\n' >"$out"
fixture_run "$out" aarch64-apple-darwin
if [ "$rc" -eq 1 ] && [ "$(cat "$out")" = "previous notices" ]; then pass "a failed run leaves an existing output file unchanged"
else fail "a failed run leaves an existing output file unchanged (exit $rc)"; fi
rm -f "$out"

# The workspace's own crates must be MIT (ADR 0015).
new_fixture own-license
app_license=Apache-2.0
lock_fixture
out="$scratch/own-license.txt"
fixture_run "$out" aarch64-apple-darwin
expect_reject "a workspace crate that is not MIT fails" "app 0.1.0"

# Usage errors exit 2.
rc=0; "$notices" -p app -o "$scratch/usage.txt" --manifest-path "$fx/ws/Cargo.toml" >/dev/null 2>&1 || rc=$?
if [ "$rc" -eq 2 ]; then pass "a missing --target is a usage error"; else fail "a missing --target is a usage error (exit $rc)"; fi
rc=0; "$notices" -p app --target aarch64-apple-darwin -o "$scratch/usage.txt" --bogus >/dev/null 2>&1 || rc=$?
if [ "$rc" -eq 2 ]; then pass "an unknown argument is a usage error"; else fail "an unknown argument is a usage error (exit $rc)"; fi

finish
