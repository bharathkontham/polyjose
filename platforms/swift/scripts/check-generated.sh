#!/usr/bin/env bash
# Checks that the committed platforms/swift/Sources/Polyjose/Polyjose.swift is exactly what
# uniffi-bindgen generates from the current polyjose-ffi (ADR 0032 §4: the generated Swift is
# committed because SwiftPM cannot run the bindgen, and this check keeps it fresh).
#
# Usage: platforms/swift/scripts/check-generated.sh
#
# Regenerates the Swift sources the way platforms/swift/scripts/build-xcframework.sh does (ADR
# 0032 §2): the macOS arm64 cdylib (`cargo rustc -p polyjose-ffi --release --target
# aarch64-apple-darwin --crate-type cdylib`, with the same deployment targets, so the two scripts
# share one cargo build), then `uniffi-bindgen generate --language swift --no-format` in library
# mode, into a temporary directory. --no-format keeps the output independent of whether
# swiftformat is installed, as in build-xcframework.sh.
#
# Fails (exit 1) when:
#   - the regenerated Polyjose.swift differs from the committed one (the diff is printed, with the
#     command that updates the committed file);
#   - platforms/swift/build/PolyjoseFFI.xcframework exists and one of its libraries carries a
#     PolyjoseFFI.h that differs from the regenerated header: the XCFramework was built from other
#     Rust sources than the Swift it would be linked with (rerun build-xcframework.sh).
# Exit 2 on a setup error (no cargo, a failed build or generation).
#
# Runs from any directory. Needs cargo and diff. Bash 3.2 compatible (macOS /bin/bash).
set -euo pipefail

me=check-generated
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
swift_dir="$(dirname "$script_dir")"
root="$(cd "$swift_dir/../.." && pwd)"
cd "$root"

committed="platforms/swift/Sources/Polyjose/Polyjose.swift"
xcframework="$swift_dir/build/PolyjoseFFI.xcframework"
[ -f "$committed" ] || { echo "$me: $committed is missing"; exit 1; }
command -v cargo >/dev/null 2>&1 || { echo "$me: error: cargo is not on PATH"; exit 2; }

target_dir="${CARGO_TARGET_DIR:-target}"
case "$target_dir" in /*) ;; *) target_dir="$root/$target_dir" ;; esac

# The deployment targets of build-xcframework.sh (ADR 0032 §1), so this build reuses its cargo
# fingerprints instead of rebuilding.
export MACOSX_DEPLOYMENT_TARGET=13.0
export IPHONEOS_DEPLOYMENT_TARGET=16.0
export TVOS_DEPLOYMENT_TARGET=16.0
export WATCHOS_DEPLOYMENT_TARGET=9.0
export XROS_DEPLOYMENT_TARGET=1.0

scratch="$(mktemp -d "${TMPDIR:-/tmp}/polyjose-check-generated.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT

cargo rustc -p polyjose-ffi --release --target aarch64-apple-darwin --crate-type cdylib >&2 ||
  { echo "$me: error: building the polyjose-ffi cdylib failed"; exit 2; }
dylib="$target_dir/aarch64-apple-darwin/release/libpolyjose_ffi.dylib"
[ -f "$dylib" ] || { echo "$me: error: cargo did not produce $dylib"; exit 2; }
cargo run -p polyjose-uniffi-bindgen -- generate "$dylib" --language swift --no-format \
  --out-dir "$scratch/generated" >&2 || { echo "$me: error: uniffi-bindgen failed"; exit 2; }
for f in Polyjose.swift PolyjoseFFI.h; do
  [ -f "$scratch/generated/$f" ] || { echo "$me: error: uniffi-bindgen did not write $f"; exit 2; }
done

failed=0
if ! diff -u "$committed" "$scratch/generated/Polyjose.swift" >"$scratch/swift.diff"; then
  cat "$scratch/swift.diff"
  echo "$me: FAIL: $committed is not what uniffi-bindgen generates from polyjose-ffi."
  echo "$me: update it with: platforms/swift/scripts/build-xcframework.sh &&"
  echo "$me:   cp platforms/swift/build/generated/Polyjose.swift $committed"
  failed=1
fi

if [ -d "$xcframework" ]; then
  stale=""
  for header in "$xcframework"/*/Headers/PolyjoseFFI/PolyjoseFFI.h; do
    [ -f "$header" ] || continue # bash 3.2 has no nullglob: an unmatched glob stays literal
    cmp -s "$header" "$scratch/generated/PolyjoseFFI.h" || stale="$stale ${header#"$xcframework"/}"
  done
  if [ -n "$stale" ]; then
    echo "$me: FAIL: the XCFramework's C header differs from the current polyjose-ffi in:$stale"
    echo "$me: rebuild it with: platforms/swift/scripts/build-xcframework.sh"
    failed=1
  fi
fi

[ "$failed" -eq 0 ] || exit 1
echo "$me: PASS ($committed is up to date)"
