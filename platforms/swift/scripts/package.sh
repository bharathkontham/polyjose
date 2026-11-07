#!/usr/bin/env bash
# Packages the Swift (iOS) binding's XCFramework for a release (ADR 0032 §6, ADR 0011, ADR 0020
# §4): writes, into dist/apple/ (ADR 0037 §3 names these assets; feature 0012 relies on the paths),
#   PolyjoseFFI.xcframework.zip         the XCFramework, with THIRD-PARTY-NOTICES.txt and LICENSE
#   PolyjoseFFI.xcframework.zip.sha256  `swift package compute-checksum` of that zip, one line
#   binaryTarget.swift.txt              the binaryTarget(url:checksum:) stanza for Package.swift
#
# Usage: platforms/swift/scripts/package.sh [--allow-dev] [--xcframework <dir>] [--out-dir <dir>]
#
#   --allow-dev        package a development build (`arm64_32: missing`) or a stale one anyway,
#                      with a warning. Such a zip must not be released.
#   --xcframework <d>  the XCFramework to package
#                      (default: platforms/swift/build/PolyjoseFFI.xcframework)
#   --out-dir <d>      where the three files go (default: <repository>/dist/apple)
#
# Refuses (exit 1, the output directory unchanged):
#   - a development build, whose polyjose-build.txt says `arm64_32: missing`: its watchOS library
#     lacks arm64_32 and breaks apps that support watchOS below 26 (ADR 0032 §1). --allow-dev
#     lets it through; a missing stamp, or an arm64_32 line other than present/missing, never;
#   - a stale build: the Rust inputs differ from the commit it was built from, or it was built
#     from uncommitted changes (platforms/swift/scripts/xcframework-stale.sh, as test.sh uses it);
#     --allow-dev lets it through;
#   - an XCFramework whose Info.plist does not list exactly the 9 libraries of ADR 0032 §1 (with
#     `watchos-arm64` in place of `watchos-arm64_arm64_32` for a development build), or whose
#     library archive is missing;
#   - Apple targets whose crate sets differ: the notices are generated once, for
#     aarch64-apple-ios, so every Rust target the XCFramework is built from must compile exactly
#     the same crates (`cargo tree -e normal,no-proc-macro`, ADR 0032 §6);
#   - a zip of 25,000,000 bytes or more (feature 0009 T04: the hard size stop; the stricter
#     reading of "25 MB", so it holds in MB and in MiB).
#
# The zip is made with `ditto -c -k --keepParent` from a copy of the XCFramework that also holds
# THIRD-PARTY-NOTICES.txt (scripts/third-party-notices.sh -p polyjose-ffi --target
# aarch64-apple-ios) and polyjose's LICENSE. So its one top-level entry is
# PolyjoseFFI.xcframework/, which is what SwiftPM looks for in a binary target's archive, and the
# two text files travel inside it. --norsrc, --noextattr, --noacl and --noqtn keep resource forks,
# extended attributes, ACLs and quarantine out, so there are no `._*` or `__MACOSX` entries
# (checked). Two builds may list the Info.plist libraries in a different order, so two zips of the
# same commit need not be byte-identical; the checksum is always computed on the zip this run
# writes, after it is in place (ADR 0037 §2 reuses the candidate zip on the tag, never a rebuild).
#
# Nothing leaves this machine: the release workflow (feature 0012) attaches the zip to the draft
# GitHub Release, and the release agent commits the stanza to Package.swift in the release PR.
#
# Staging is a `mktemp -d` directory under $TMPDIR, removed on exit. Needs macOS with Xcode
# (ditto, plutil, swift), cargo and python3. Bash 3.2 compatible (macOS /bin/bash).
set -euo pipefail
export LC_ALL=C

me=package.sh
die() { printf '%s: error: %s\n' "$me" "$*" >&2; exit 1; }
warn() { printf '%s: warning: %s\n' "$me" "$*" >&2; }
log() { printf '%s: %s\n' "$me" "$*"; }
usage() { sed -n '2,/^set -euo/{/^set -euo/d;s/^# \{0,1\}//;p;}' "$0"; }

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
swift_dir="$(dirname "$script_dir")"
root="$(cd "$swift_dir/../.." && pwd)"

allow_dev=0
xcf="$swift_dir/build/PolyjoseFFI.xcframework"
out_dir="$root/dist/apple"
while [ $# -gt 0 ]; do
  case "$1" in
    --allow-dev) allow_dev=1 ;;
    --xcframework) [ $# -ge 2 ] || { usage >&2; exit 2; }; xcf=$2; shift ;;
    --out-dir) [ $# -ge 2 ] || { usage >&2; exit 2; }; out_dir=$2; shift ;;
    -h | --help) usage; exit 0 ;;
    *) printf '%s: unknown argument: %s\n' "$me" "$1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

[ "$(uname -s)" = Darwin ] || die "the XCFramework can only be packaged on macOS"
for tool in ditto plutil swift cargo python3 shasum unzip; do
  command -v "$tool" >/dev/null 2>&1 || die "'$tool' is not on PATH"
done

zip_name=PolyjoseFFI.xcframework.zip
max_zip_bytes=25000000
# The Rust targets of the 9 libraries (ADR 0032 §1; build-xcframework.sh builds them).
apple_targets="aarch64-apple-darwin x86_64-apple-darwin aarch64-apple-ios aarch64-apple-ios-sim
x86_64-apple-ios aarch64-apple-tvos aarch64-apple-tvos-sim aarch64-apple-visionos
aarch64-apple-visionos-sim aarch64-apple-watchos aarch64-apple-watchos-sim arm64_32-apple-watchos"
notices_target=aarch64-apple-ios
release_libraries="ios-arm64 ios-arm64_x86_64-simulator macos-arm64_x86_64 tvos-arm64
tvos-arm64-simulator watchos-arm64-simulator watchos-arm64_arm64_32 xros-arm64
xros-arm64-simulator"

# --- The build stamp: refuse a development build (ADR 0032 §1) --------------------------------
[ -d "$xcf" ] || die "no XCFramework at $xcf; build it with platforms/swift/scripts/build-xcframework.sh --release"
xcf="$(cd "$xcf" && pwd)"
stamp="$xcf/polyjose-build.txt"
[ -f "$stamp" ] || die "$xcf has no polyjose-build.txt, so whether it is a release build is unknown; rebuild it with build-xcframework.sh --release"
arm64_32=$(sed -n 's/^arm64_32: //p' "$stamp")
case "$arm64_32" in
  present) libraries=$release_libraries ;;
  missing)
    [ "$allow_dev" -eq 1 ] || die "$xcf is a development build (polyjose-build.txt: arm64_32: missing): its watchOS library lacks arm64_32, which apps supporting watchOS below 26 need (ADR 0032 §1). Install the nightly of platforms/swift/nightly-toolchain and run build-xcframework.sh --release, or pass --allow-dev for a zip that must not be released"
    warn "packaging a development build (arm64_32: missing): this zip must not be released"
    # shellcheck disable=SC2086 # a word list
    libraries=$(printf '%s\n' $release_libraries | sed 's/^watchos-arm64_arm64_32$/watchos-arm64/') ;;
  *) die "polyjose-build.txt must have exactly one line 'arm64_32: present' or 'arm64_32: missing', not '${arm64_32:-<none>}'" ;;
esac

# --- Stale builds ----------------------------------------------------------------------------
# shellcheck source=xcframework-stale.sh
. "$script_dir/xcframework-stale.sh"
if reason=$(xcframework_stale "$root" "$xcf"); then
  [ "$allow_dev" -eq 1 ] || die "the XCFramework is stale: $reason. Rebuild it with build-xcframework.sh --release from a clean checkout, or pass --allow-dev for a zip that must not be released"
  warn "packaging a stale XCFramework ($reason): this zip must not be released"
fi

# --- The 9 libraries (ADR 0032 §1) -----------------------------------------------------------
listed="" i=0
while id=$(plutil -extract "AvailableLibraries.$i.LibraryIdentifier" raw -o - "$xcf/Info.plist" 2>/dev/null); do
  path=$(plutil -extract "AvailableLibraries.$i.LibraryPath" raw -o - "$xcf/Info.plist" 2>/dev/null) \
    || die "Info.plist library $id has no LibraryPath"
  [ -f "$xcf/$id/$path" ] || die "Info.plist lists $id, but $id/$path is missing"
  listed="$listed$id"$'\n'
  i=$((i + 1))
done
# shellcheck disable=SC2086 # a word list
want=$(printf '%s\n' $libraries | sort)
got=$(printf '%s' "$listed" | sort)
[ "$got" = "$want" ] || die "Info.plist must list exactly the libraries of ADR 0032 §1. Missing: $(comm -23 <(echo "$want") <(echo "$got") | tr '\n' ' ')extra: $(comm -13 <(echo "$want") <(echo "$got") | tr '\n' ' ')"

# --- Version ---------------------------------------------------------------------------------
version=$(cd "$root" && cargo metadata --locked --offline --no-deps --format-version 1 |
  python3 -I -c 'import json, sys
print("".join(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"] == "polyjose-ffi"))') \
  || die "cargo metadata failed (offline: run \`cargo fetch --locked\` first)"
printf '%s\n' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$' \
  || die "polyjose-ffi's version '$version' is not SemVer"

stage=$(mktemp -d "${TMPDIR:-/tmp}/polyjose-package.XXXXXX") || die "mktemp failed"
trap 'rm -rf "$stage"' EXIT

# --- One crate set on every Apple target (ADR 0032 §6) ---------------------------------------
crates() {
  (cd "$root" && cargo tree --locked --offline -p polyjose-ffi --target "$1" -e normal,no-proc-macro \
    --prefix none -f '{p}') | sed 's/ (\*)$//' | sort -u
}
crates "$notices_target" >"$stage/crates-$notices_target.txt" || die "cargo tree failed for $notices_target"
n=0
for t in $apple_targets; do
  n=$((n + 1))
  [ "$t" = "$notices_target" ] && continue
  crates "$t" >"$stage/crates-$t.txt" || die "cargo tree failed for $t"
  cmp -s "$stage/crates-$notices_target.txt" "$stage/crates-$t.txt" || {
    diff "$stage/crates-$notices_target.txt" "$stage/crates-$t.txt" >&2 || true
    die "$t compiles other crates than $notices_target, so one notices file does not cover the XCFramework (above: < $notices_target, > $t)"
  }
done
log "same crate set on all $n Apple targets ($(wc -l <"$stage/crates-$notices_target.txt" | tr -d ' ') crates)"

# --- Stage and zip ---------------------------------------------------------------------------
copy="$stage/zip/PolyjoseFFI.xcframework"
mkdir -p "$stage/zip"
ditto --norsrc --noextattr --noacl --noqtn "$xcf" "$copy"
"$root/scripts/third-party-notices.sh" -p polyjose-ffi --target "$notices_target" \
  -o "$copy/THIRD-PARTY-NOTICES.txt" >&2
cp "$root/LICENSE" "$copy/LICENSE"
ditto -c -k --norsrc --noextattr --noacl --noqtn --keepParent "$copy" "$stage/$zip_name"

unzip -Z1 "$stage/$zip_name" >"$stage/entries.txt"
if grep -Eq '(^|/)\._|__MACOSX' "$stage/entries.txt"; then
  die "the zip has AppleDouble or __MACOSX entries: $(grep -E '(^|/)\._|__MACOSX' "$stage/entries.txt" | head -3 | tr '\n' ' ')"
fi
size=$(stat -f %z "$stage/$zip_name")
[ "$size" -lt "$max_zip_bytes" ] || die "the zip is $size bytes, not under the $max_zip_bytes bytes (25 MB) limit; nothing written"

# --- Into the output directory, then the checksum of the zip written --------------------------
mkdir -p "$out_dir"
out_dir="$(cd "$out_dir" && pwd)"
rm -f "$out_dir/$zip_name" "$out_dir/$zip_name.sha256" "$out_dir/binaryTarget.swift.txt"
mv "$stage/$zip_name" "$out_dir/$zip_name"
zip="$out_dir/$zip_name"
checksum=$(swift package compute-checksum "$zip") || die "swift package compute-checksum failed"
[ "$checksum" = "$(shasum -a 256 "$zip" | cut -d' ' -f1)" ] \
  || die "swift package compute-checksum ($checksum) is not the zip's SHA-256"
printf '%s\n' "$checksum" >"$zip.sha256"
url="https://github.com/bharathkontham/polyjose/releases/download/v$version/$zip_name"
cat >"$out_dir/binaryTarget.swift.txt" <<EOF
    // Swift (iOS): the PolyjoseFFI XCFramework of polyjose $version, the GitHub Release asset
    // (ADR 0011, ADR 0032 §4). Generated by platforms/swift/scripts/package.sh; it replaces the
    // url form of the PolyjoseFFI binaryTarget in Package.swift in the release PR.
    .binaryTarget(
        name: "PolyjoseFFI",
        url: "$url",
        checksum: "$checksum"
    )
EOF

log "wrote $zip ($size bytes, $(awk -v b="$size" 'BEGIN { printf "%.2f MB", b / 1000000 }'))"
log "sha256 $checksum"
log "wrote $zip.sha256 and $out_dir/binaryTarget.swift.txt"
