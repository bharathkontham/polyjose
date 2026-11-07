#!/usr/bin/env bash
# The guards of platforms/swift/scripts/package.sh (ADR 0032 §1, §6), on stand-in XCFrameworks
# built in a scratch directory; the real build is not read. Covers:
#   - the script never publishes: no `gh`, no `git push`, nothing that uploads (ADR 0037 §2: only
#     the release workflow's draft job creates a release; feature 0009 T04);
#   - a development build (`arm64_32: missing`) is refused unless --allow-dev is given, and an
#     unreadable or unknown build stamp is refused even with it (ADR 0032 §1);
#   - a stale build (its stamp names a commit the checkout does not have) is refused;
#   - an XCFramework without all 9 libraries of ADR 0032 §1 is refused;
#   - a zip of 25 MB or more is refused (feature 0009 T04, the hard size stop);
#   - a refusal leaves the output directory as it was;
#   - with --allow-dev, a development build is packaged, with its `watchos-arm64` library.
# Usage: platforms/swift/scripts/tests/test-package-guard.sh (needs macOS, cargo, swift, python3).
set -uo pipefail
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

# --- The script never publishes ---------------------------------------------------------------
[ -f "$package_sh" ] || lib_die "no $package_sh"
check "package.sh has no gh command" "! grep -Ewq 'gh' '$package_sh'"
check "package.sh has no git push" "! grep -Eq 'git[[:space:]]+push' '$package_sh'"
check "package.sh has no upload step (no 'upload' anywhere, case-insensitive)" \
  "! grep -iq 'upload' '$package_sh'"
check "package.sh has no curl or scp" "! grep -Ewq 'curl|scp|rsync' '$package_sh'"

# --- Usage ------------------------------------------------------------------------------------
run_package --help
check "--help exits 0" "[ $rc -eq 0 ]"
check "--help names the default output directory dist/apple" "log_has 'dist/apple'"
run_package --no-such-flag
check "an unknown argument exits 2" "[ $rc -eq 2 ]"

# --- Stand-in XCFrameworks --------------------------------------------------------------------
head_commit=$(git -C "$repo" rev-parse HEAD)

# fake_xcframework <dir> <libraries> <stamp text> [<bytes of each library>]: an XCFramework
# whose Info.plist lists <libraries>, each with a small (or <bytes>-long, incompressible)
# libpolyjose_ffi.a and its headers, and whose polyjose-build.txt is <stamp text>.
fake_xcframework() {
  local dir=$1 libs=$2 stamp=$3 bytes=${4:-64} id
  rm -rf "$dir"
  mkdir -p "$dir"
  {
    echo '<?xml version="1.0" encoding="UTF-8"?>'
    echo '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">'
    echo '<plist version="1.0"><dict><key>AvailableLibraries</key><array>'
    for id in $libs; do
      mkdir -p "$dir/$id/Headers/PolyjoseFFI"
      head -c "$bytes" /dev/urandom >"$dir/$id/libpolyjose_ffi.a"
      echo '/* stand-in */' >"$dir/$id/Headers/PolyjoseFFI/PolyjoseFFI.h"
      echo 'module PolyjoseFFI {}' >"$dir/$id/Headers/PolyjoseFFI/module.modulemap"
      printf '<dict><key>LibraryIdentifier</key><string>%s</string><key>LibraryPath</key><string>libpolyjose_ffi.a</string><key>HeadersPath</key><string>Headers</string></dict>\n' "$id"
    done
    echo '</array><key>CFBundlePackageType</key><string>XFWK</string><key>XCFrameworkFormatVersion</key><string>1.0</string></dict></plist>'
  } >"$dir/Info.plist"
  printf '%s\n' "$stamp" >"$dir/polyjose-build.txt"
}

stamp_for() { printf 'arm64_32: %s\nrustc: test\ncommit: %s\n' "$1" "${2:-$head_commit}"; }

out="$scratch/out"
mkdir -p "$out"
echo sentinel >"$out/PolyjoseFFI.xcframework.zip"
untouched() { [ "$(ls "$out")" = PolyjoseFFI.xcframework.zip ] && [ "$(cat "$out/PolyjoseFFI.xcframework.zip")" = sentinel ]; }

xcf="$scratch/fake/PolyjoseFFI.xcframework"

# shellcheck disable=SC2086 # word lists
fake_xcframework "$xcf" "$dev_libraries" "$(stamp_for missing)"
run_package --xcframework "$xcf" --out-dir "$out"
check "a development build is refused without --allow-dev" "[ $rc -eq 1 ]"
check "the refusal says it is a development build and names --allow-dev" \
  "log_has 'development build' && log_has '--allow-dev'"
check "the refusal leaves the output directory as it was" untouched

rm -f "$xcf/polyjose-build.txt"
run_package --allow-dev --xcframework "$xcf" --out-dir "$out"
check "a build without polyjose-build.txt is refused, even with --allow-dev" \
  "[ $rc -eq 1 ] && log_has 'polyjose-build.txt'"

fake_xcframework "$xcf" "$release_libraries" "$(printf 'rustc: test\ncommit: %s' "$head_commit")"
run_package --allow-dev --xcframework "$xcf" --out-dir "$out"
check "a stamp without an arm64_32 line is refused, even with --allow-dev" "[ $rc -eq 1 ] && log_has 'arm64_32'"

fake_xcframework "$xcf" "$release_libraries" "$(stamp_for unknown)"
run_package --allow-dev --xcframework "$xcf" --out-dir "$out"
check "an unknown arm64_32 value is refused, even with --allow-dev" "[ $rc -eq 1 ] && log_has 'arm64_32'"

run_package --xcframework "$scratch/none/PolyjoseFFI.xcframework" --out-dir "$out"
check "a missing XCFramework is refused and named" "[ $rc -eq 1 ] && log_has 'build-xcframework.sh'"

fake_xcframework "$xcf" "$release_libraries" "$(stamp_for present 0000000000000000000000000000000000000000)"
run_package --xcframework "$xcf" --out-dir "$out"
check "a stale build (a commit the checkout lacks) is refused" "[ $rc -eq 1 ] && log_has 'stale'"

# shellcheck disable=SC2086 # a word list
fake_xcframework "$xcf" "$(printf '%s\n' $release_libraries | grep -v '^xros-arm64$')" "$(stamp_for present)"
run_package --allow-dev --xcframework "$xcf" --out-dir "$out"
check "an XCFramework missing a library (xros-arm64) is refused" "[ $rc -eq 1 ] && log_has 'xros-arm64'"

fake_xcframework "$xcf" "$release_libraries" "$(stamp_for present)"
rm -f "$xcf/tvos-arm64/libpolyjose_ffi.a"
run_package --allow-dev --xcframework "$xcf" --out-dir "$out"
check "a library whose archive is missing is refused" "[ $rc -eq 1 ] && log_has 'tvos-arm64'"
check "the refusals left the output directory as it was" untouched

# --- One crate set on every Apple target (ADR 0032 §6, ADR 0020 §4) ---------------------------
# The notices are generated for aarch64-apple-ios only, so a target that compiles another crate
# set must be refused. The stand-in cargo of lib.sh adds one crate to the `cargo tree` of one
# target, as a dependency only that target compiles would (feature 0009 F03). --allow-dev keeps
# the stale check out of the way on a checkout with uncommitted Rust inputs; it must not let
# differing crate sets through.
fake_xcframework "$xcf" "$release_libraries" "$(stamp_for present)"
run_package_fake_cargo aarch64-apple-tvos --allow-dev --xcframework "$xcf" --out-dir "$out"
check "a target with an extra crate (aarch64-apple-tvos) is refused, even with --allow-dev" "[ $rc -eq 1 ]"
check "the refusal says aarch64-apple-tvos compiles other crates than aarch64-apple-ios" \
  "log_has 'aarch64-apple-tvos compiles other crates than aarch64-apple-ios'"
check "the refusal shows the extra crate of aarch64-apple-tvos" "log_has '> $fake_extra_crate'"
check "the crate-set refusal leaves the output directory as it was" untouched
[ "$rc" -eq 1 ] || show_log

# The last target of package.sh's list: the check covers every target, not only the first.
run_package_fake_cargo arm64_32-apple-watchos --allow-dev --xcframework "$xcf" --out-dir "$out"
check "a differing crate set on the last target (arm64_32-apple-watchos) is refused" \
  "[ $rc -eq 1 ] && log_has 'arm64_32-apple-watchos compiles other crates than aarch64-apple-ios'"
check "that refusal leaves the output directory as it was" untouched

# The other direction: aarch64-apple-ios itself has the extra crate, so the other targets lack it.
run_package_fake_cargo aarch64-apple-ios --allow-dev --xcframework "$xcf" --out-dir "$out"
check "a crate that only aarch64-apple-ios compiles is refused" \
  "[ $rc -eq 1 ] && log_has 'compiles other crates than aarch64-apple-ios' && log_has '< $fake_extra_crate'"
check "that refusal leaves the output directory as it was, too" untouched

# 9 incompressible libraries of 2.9 MB each: about 26 MB zipped, over the 25,000,000-byte stop.
# --allow-dev also lets the stale check pass when this checkout has uncommitted Rust inputs.
fake_xcframework "$xcf" "$release_libraries" "$(stamp_for present)" 2900000
run_package --allow-dev --xcframework "$xcf" --out-dir "$out"
check "a zip of 25 MB or more is refused" "[ $rc -eq 1 ] && log_has '25000000'"
check "the oversized zip is not written" untouched
[ "$rc" -eq 1 ] || show_log

# --- --allow-dev packages a development build -------------------------------------------------
# shellcheck disable=SC2086
fake_xcframework "$xcf" "$dev_libraries" "$(stamp_for missing)"
dev_out="$scratch/dev-out"
run_package --allow-dev --xcframework "$xcf" --out-dir "$dev_out"
check "--allow-dev packages a development build" "[ $rc -eq 0 ]"
[ "$rc" -eq 0 ] || show_log
check "it warns that the zip must not be released" "log_has 'must not be released'"
# Listed into a file first: under pipefail, `unzip | grep -q` fails when grep exits before unzip.
unzip -Z1 "$dev_out/PolyjoseFFI.xcframework.zip" >"$scratch/dev-entries.txt" 2>/dev/null || true
check "the zip holds the watchos-arm64 library" \
  "grep -qxF 'PolyjoseFFI.xcframework/watchos-arm64/libpolyjose_ffi.a' '$scratch/dev-entries.txt'"
check "the output directory holds exactly the zip, its .sha256 and the stanza" \
  "[ \"\$(ls -A '$dev_out' | tr '\n' ' ')\" = 'PolyjoseFFI.xcframework.zip PolyjoseFFI.xcframework.zip.sha256 binaryTarget.swift.txt ' ]"

finish
