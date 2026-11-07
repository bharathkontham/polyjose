#!/usr/bin/env bash
# Builds platforms/swift/build/PolyjoseFFI.xcframework, the static XCFramework of the Swift (iOS)
# binding (ADR 0032 §1-§3, ADR 0046 §3), from polyjose-ffi.
#
# Usage: platforms/swift/scripts/build-xcframework.sh [--release]
#
#   --release  fail unless every library, including arm64_32-apple-watchos, can be built. Without
#              it, a machine without the pinned nightly gets a development build (see below).
#
# Runs from any directory. Idempotent and incremental: a second run with no change recompiles no
# Rust crate (cargo's fingerprints), and only the XCFramework itself is reassembled.
#
# The 9 libraries (ADR 0032 §1); two Rust targets are merged with lipo where a library has two:
#   macos-arm64_x86_64          aarch64-apple-darwin + x86_64-apple-darwin
#   ios-arm64                   aarch64-apple-ios
#   ios-arm64_x86_64-simulator  aarch64-apple-ios-sim + x86_64-apple-ios
#   tvos-arm64                  aarch64-apple-tvos
#   tvos-arm64-simulator        aarch64-apple-tvos-sim
#   xros-arm64                  aarch64-apple-visionos
#   xros-arm64-simulator        aarch64-apple-visionos-sim
#   watchos-arm64_arm64_32      aarch64-apple-watchos + arm64_32-apple-watchos
#   watchos-arm64-simulator     aarch64-apple-watchos-sim
# Every target is tier 2 on the stable toolchain of rust-toolchain.toml (the aarch64 tvOS,
# visionOS and watchOS targets since Rust 1.95.0) except arm64_32-apple-watchos, which is tier 3
# and is built with the nightly named in platforms/swift/nightly-toolchain and
# `-Zbuild-std=std,panic_abort` (ADR 0032 §1, amending ADR 0004).
#
# Development build: when that nightly (with rust-src) is not installed, the watchOS device
# library is aarch64 alone (`watchos-arm64`), PolyjoseFFI.xcframework/polyjose-build.txt says
# `arm64_32: missing`, and the script warns and exits 0. Such a framework breaks consumers whose
# watchOS deployment target is below 26 (Apple Watch Series 4-8 run arm64_32), so packaging
# refuses it (ADR 0032 §1); --release fails here instead.
#
# Static archives: `cargo rustc -p polyjose-ffi --release --target <t> --crate-type staticlib`.
# Overriding the crate types drops the rlib, so the release profile's fat LTO applies (with `lib`
# in crate-type the staticlib is not LTO'd: 24 MB instead of about 6.3 MB per target, ADR 0032 §1).
# `-p polyjose-ffi` alone keeps uniffi's `cli` feature, which only polyjose-uniffi-bindgen
# enables, out of the archives; the bindgen is a separate cargo invocation, and the nm check below
# proves no uniffi_bindgen code was linked in. Deployment targets are set explicitly to the
# `platforms:` of Package.swift (ADR 0032 §1); Rust's defaults differ per target. rustc raises
# aarch64-apple-watchos to its own minimum, watchOS 26.0, the first release for arm64 watches.
#
# Debug info (owner decision 2026-11-07, feature 0009 F02): each archive carries about 3.2 MB of
# DWARF, mostly std's line tables pulled in by LTO, and the release profile's `strip` applies only
# to linked outputs, never to a staticlib. So every per-target archive, arm64_32 included, is
# copied through `xcrun strip -S -D` into the staging directory before lipo and
# -create-xcframework. -S removes only debug info: global and local symbols stay, so consumers
# link as before and their crash reports name polyjose frames, without file and line. -D gives
# the archive header fixed defaults, so the output is byte-stable. cargo's own archive in target/
# is never modified, which keeps its fingerprints and the no-op run intact.
#
# Headers (ADR 0032 §2): polyjose-uniffi-bindgen generates the Swift sources from the macOS
# arm64 dylib in library mode; PolyjoseFFI.h and module.modulemap go under
# Headers/PolyjoseFFI/ of every library (a subdirectory avoids header collisions with other
# XCFrameworks). The generated Polyjose.swift is left in platforms/swift/build/generated/.
#
# Checks (any failure exits non-zero): each per-target archive cargo builds is under 10 MB; its
# stripped copy contains polyjose-ffi's UniFFI exports but no uniffi_bindgen symbol; the
# XCFramework's Info.plist lists exactly the expected library identifiers. Prints the size of
# every archive before and after stripping, the size of every library, the time each Rust target
# took, and the XCFramework's size.
#
# Needs macOS with Xcode (xcodebuild, lipo, nm, plutil, xcrun strip) and cargo; rustup for the nightly slice.
# Bash 3.2 compatible (macOS /bin/bash).
set -euo pipefail

die() { printf 'build-xcframework: error: %s\n' "$*" >&2; exit 1; }
warn() { printf 'build-xcframework: warning: %s\n' "$*" >&2; }
log() { printf 'build-xcframework: %s\n' "$*" >&2; }

require_full=0
while [ $# -gt 0 ]; do
  case "$1" in
    --release) require_full=1 ;;
    -h|--help) sed -n '2,/^set -euo/{/^set -euo/d;s/^# \{0,1\}//;p;}' "$0"; exit 0 ;;
    *) die "unknown argument '$1' (usage: build-xcframework.sh [--release])" ;;
  esac
  shift
done

[ "$(uname -s)" = Darwin ] || die "the XCFramework can only be built on macOS"
for tool in cargo xcodebuild lipo nm plutil xcrun; do
  command -v "$tool" >/dev/null 2>&1 || die "'$tool' is not on PATH"
done

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
swift_dir="$(dirname "$script_dir")"
root="$(cd "$swift_dir/../.." && pwd)"
cd "$root"

build_dir="$swift_dir/build"
out="$build_dir/PolyjoseFFI.xcframework"
generated="$build_dir/generated"
target_dir="${CARGO_TARGET_DIR:-target}"
case "$target_dir" in /*) ;; *) target_dir="$root/$target_dir" ;; esac
nightly="$(tr -d '[:space:]' < "$swift_dir/nightly-toolchain")"
[ -n "$nightly" ] || die "platforms/swift/nightly-toolchain is empty"
nightly_install="rustup toolchain install $nightly --profile minimal --component rust-src"

# ADR 0032 §1: the platform minimums of Package.swift. Exported for the whole run, so every cargo
# invocation (host build scripts included) sees the same values and none is rebuilt for a change.
export MACOSX_DEPLOYMENT_TARGET=13.0
export IPHONEOS_DEPLOYMENT_TARGET=16.0
export TVOS_DEPLOYMENT_TARGET=16.0
export WATCHOS_DEPLOYMENT_TARGET=9.0
export XROS_DEPLOYMENT_TARGET=1.0

max_archive_bytes=$((10 * 1024 * 1024))

mb() { awk -v b="$1" 'BEGIN { printf "%.2f MB", b / 1048576 }'; }
size_of() { stat -f %z "$1"; }

have_nightly() {
  command -v rustup >/dev/null 2>&1 || return 1
  rustup toolchain list 2>/dev/null | grep -q "^$nightly-" || return 1
  rustup "+$nightly" component list --installed 2>/dev/null | grep -q '^rust-src'
}

if have_nightly; then
  with_arm64_32=1
elif [ "$require_full" = 1 ]; then
  die "--release needs the pinned nightly for arm64_32-apple-watchos; install it with: $nightly_install"
else
  with_arm64_32=0
  warn "the pinned nightly $nightly (with rust-src) is not installed, so arm64_32-apple-watchos is"
  warn "not built: this is a development build (polyjose-build.txt: 'arm64_32: missing') that"
  warn "breaks consumers supporting watchOS below 26. Install it with: $nightly_install"
fi

mkdir -p "$build_dir"
stage="$(mktemp -d "$build_dir/.stage.XXXXXX")"
trap 'rm -rf "$stage"' EXIT

# Builds one Rust target's LTO'd static archive, strips its debug info into the staging directory
# and checks it (see the header).
# $1: target triple; $2: "stable" or "nightly". Prints the stripped archive's path on stdout.
build_target() {
  local triple="$1" toolchain="$2" start="$SECONDS" archive stripped syms
  log "building $triple ($toolchain)"
  if [ "$toolchain" = nightly ]; then
    cargo "+$nightly" rustc -Zbuild-std=std,panic_abort -p polyjose-ffi --release \
      --target "$triple" --crate-type staticlib >&2
  else
    cargo rustc -p polyjose-ffi --release --target "$triple" --crate-type staticlib >&2
  fi
  archive="$target_dir/$triple/release/libpolyjose_ffi.a"
  [ -f "$archive" ] || die "cargo did not produce $archive"
  local bytes; bytes="$(size_of "$archive")"
  [ "$bytes" -lt "$max_archive_bytes" ] ||
    die "$triple: $(mb "$bytes") archive is not under 10 MB (is LTO off, or is uniffi/cli linked in?)"
  stripped="$stage/archives/$triple/libpolyjose_ffi.a"
  mkdir -p "$(dirname "$stripped")"
  xcrun strip -S -D -o "$stripped" "$archive" ||
    die "$triple: xcrun strip -S could not strip $archive"
  [ -f "$stripped" ] || die "$triple: xcrun strip -S did not write $stripped"
  # --no-llvm-bc: the prebuilt compiler_builtins objects embed LLVM bitcode (__LLVM,__bitcode)
  # from Rust's newer LLVM, which Xcode's nm cannot parse; the Mach-O symbol tables are what the
  # linker reads (it ignores embedded bitcode), so those are what is checked.
  syms="$(nm --no-llvm-bc "$stripped" 2>/dev/null)" || die "$triple: nm could not read $stripped"
  case "$syms" in *uniffi_polyjose_ffi_*) ;; *) die "$triple: no polyjose-ffi UniFFI export in $stripped" ;; esac
  case "$syms" in *uniffi_bindgen*) die "$triple: uniffi_bindgen symbols are linked into $stripped" ;; esac
  log "  $triple: $(mb "$(size_of "$stripped")") stripped, $(mb "$bytes") before strip -S, in $((SECONDS - start)) s"
  printf '%s\n' "$stripped"
}

# One XCFramework library: lipo-merges the given archives into stage/libs/<id>/.
# $1: library identifier; $2...: archives.
libraries=()
add_library() {
  local id="$1"; shift
  local lib="$stage/libs/$id/libpolyjose_ffi.a"
  mkdir -p "$(dirname "$lib")"
  if [ $# -eq 1 ]; then cp "$1" "$lib"; else lipo -create "$@" -output "$lib"; fi
  libraries+=("$id")
}

core_start="$SECONDS"
a_macos_arm64="$(build_target aarch64-apple-darwin stable)"
a_macos_x86_64="$(build_target x86_64-apple-darwin stable)"
a_ios="$(build_target aarch64-apple-ios stable)"
a_ios_sim_arm64="$(build_target aarch64-apple-ios-sim stable)"
a_ios_sim_x86_64="$(build_target x86_64-apple-ios stable)"
core_seconds=$((SECONDS - core_start))

extra_start="$SECONDS"
a_tvos="$(build_target aarch64-apple-tvos stable)"
a_tvos_sim="$(build_target aarch64-apple-tvos-sim stable)"
a_xros="$(build_target aarch64-apple-visionos stable)"
a_xros_sim="$(build_target aarch64-apple-visionos-sim stable)"
a_watchos_sim="$(build_target aarch64-apple-watchos-sim stable)"
a_watchos_arm64="$(build_target aarch64-apple-watchos stable)"
if [ "$with_arm64_32" = 1 ]; then
  a_watchos_arm64_32="$(build_target arm64_32-apple-watchos nightly)"
fi
extra_seconds=$((SECONDS - extra_start))

# Swift sources and C headers (ADR 0032 §2), from the macOS arm64 dylib in UniFFI library mode.
# The cdylib is a separate cargo unit from the staticlib, so neither invalidates the other.
# --no-format keeps the output independent of whether swiftformat is installed.
gen_start="$SECONDS"
log "generating the Swift sources"
cargo rustc -p polyjose-ffi --release --target aarch64-apple-darwin --crate-type cdylib >&2
dylib="$target_dir/aarch64-apple-darwin/release/libpolyjose_ffi.dylib"
[ -f "$dylib" ] || die "cargo did not produce $dylib"
rm -rf "$stage/generated"
cargo run -p polyjose-uniffi-bindgen -- generate "$dylib" --language swift --no-format \
  --out-dir "$stage/generated" >&2
for f in Polyjose.swift PolyjoseFFI.h PolyjoseFFI.modulemap; do
  [ -f "$stage/generated/$f" ] || die "uniffi-bindgen did not write $f"
done
headers="$stage/headers"
mkdir -p "$headers/PolyjoseFFI"
cp "$stage/generated/PolyjoseFFI.h" "$headers/PolyjoseFFI/PolyjoseFFI.h"
cp "$stage/generated/PolyjoseFFI.modulemap" "$headers/PolyjoseFFI/module.modulemap"
gen_seconds=$((SECONDS - gen_start))

add_library macos-arm64_x86_64 "$a_macos_arm64" "$a_macos_x86_64"
add_library ios-arm64 "$a_ios"
add_library ios-arm64_x86_64-simulator "$a_ios_sim_arm64" "$a_ios_sim_x86_64"
add_library tvos-arm64 "$a_tvos"
add_library tvos-arm64-simulator "$a_tvos_sim"
add_library xros-arm64 "$a_xros"
add_library xros-arm64-simulator "$a_xros_sim"
if [ "$with_arm64_32" = 1 ]; then
  add_library watchos-arm64_arm64_32 "$a_watchos_arm64" "$a_watchos_arm64_32"
else
  add_library watchos-arm64 "$a_watchos_arm64"
fi
add_library watchos-arm64-simulator "$a_watchos_sim"

log "creating the XCFramework"
args=()
for id in "${libraries[@]}"; do
  args+=(-library "$stage/libs/$id/libpolyjose_ffi.a" -headers "$headers")
done
xcodebuild -create-xcframework "${args[@]}" -output "$stage/PolyjoseFFI.xcframework" >&2

# The Info.plist must list exactly the libraries added.
expected="$(printf '%s\n' "${libraries[@]}" | sort)"
actual="$(plutil -p "$stage/PolyjoseFFI.xcframework/Info.plist" |
  sed -n 's/^ *"LibraryIdentifier" => "\(.*\)"$/\1/p' | sort)"
[ "$actual" = "$expected" ] ||
  die "Info.plist lists [$(tr '\n' ' ' <<<"$actual")], expected [$(tr '\n' ' ' <<<"$expected")]"
for id in "${libraries[@]}"; do
  for f in PolyjoseFFI.h module.modulemap; do
    [ -f "$stage/PolyjoseFFI.xcframework/$id/Headers/PolyjoseFFI/$f" ] ||
      die "$id is missing Headers/PolyjoseFFI/$f"
  done
done

# Build provenance, read by the packaging script: a development build (arm64_32 missing) is
# never released (ADR 0032 §1). No timestamp, so an unchanged rebuild writes the same file.
{
  if [ "$with_arm64_32" = 1 ]; then
    echo "arm64_32: present"
  else
    echo "arm64_32: missing"
  fi
  echo "rustc: $(rustc --version)"
  if [ "$with_arm64_32" = 1 ]; then echo "nightly: $(rustc "+$nightly" --version)"; fi
  echo "commit: $(git -C "$root" rev-parse HEAD 2>/dev/null || echo unknown)$(
    git -C "$root" diff --quiet HEAD 2>/dev/null || echo ' (uncommitted changes)')"
  echo "deployment targets: macOS $MACOSX_DEPLOYMENT_TARGET, iOS $IPHONEOS_DEPLOYMENT_TARGET," \
    "tvOS $TVOS_DEPLOYMENT_TARGET, watchOS $WATCHOS_DEPLOYMENT_TARGET, visionOS $XROS_DEPLOYMENT_TARGET"
} > "$stage/PolyjoseFFI.xcframework/polyjose-build.txt"

# Replace the previous output only once everything above succeeded.
rm -rf "$out" "$generated"
mv "$stage/PolyjoseFFI.xcframework" "$out"
mv "$stage/generated" "$generated"

echo "PolyjoseFFI.xcframework libraries:"
for id in "${libraries[@]}"; do
  printf '  %-28s %s\n' "$id" "$(mb "$(size_of "$out/$id/libpolyjose_ffi.a")")"
done
echo "Rust targets: core (macOS, iOS, iOS Simulator) ${core_seconds} s; others (tvOS, visionOS, watchOS) ${extra_seconds} s; Swift generation ${gen_seconds} s"
echo "$out: $(mb $(( $(du -sk "$out" | cut -f1) * 1024 )))"
echo "Swift sources: $generated/Polyjose.swift"
if [ "$with_arm64_32" = 0 ]; then
  warn "development build: arm64_32-apple-watchos is missing (install: $nightly_install)"
fi
