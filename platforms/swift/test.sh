#!/usr/bin/env bash
# The Swift (iOS) binding's test suite (ADR 0032 §5, ADR 0046 §2), run by `scripts/test-all.sh
# swift` (feature 0013 T04's dispatcher) or directly, from any directory.
#
# Steps, each failing the suite on error:
#   1. (re)builds platforms/swift/build/PolyjoseFFI.xcframework with
#      platforms/swift/scripts/build-xcframework.sh when it is missing or stale, and prints why:
#      its polyjose-build.txt records the commit it was built from, and it is stale when that
#      commit is missing or unknown, or the Rust inputs differ from it in a later commit or in the
#      working tree (platforms/swift/scripts/xcframework-stale.sh, whose own test runs first). An
#      old library would otherwise pass: it reports the same version and vectors digest. A build
#      made while any file is uncommitted is stamped so, and is rebuilt (incrementally) next time;
#   2. platforms/swift/scripts/check-generated.sh: the committed Polyjose.swift is what the bindgen
#      generates (ADR 0032 §4);
#   3. `swift test` at the repository root with POLYJOSE_LOCAL_XCFRAMEWORK=1, in Swift 6 language
#      mode with warnings as errors, which runs every conformance vector on the macOS host and
#      writes target/conformance/swift-macos.json (ADR 0034 §2, ADR 0060; POLYJOSE_CONFORMANCE_OUT).
#      The suite fails unless that file was written. The test's one-line copy of the document
#      (POLYJOSE-CONFORMANCE-RESULTS ...) is left out of this script's output;
#   4. the packaging tests, platforms/swift/scripts/tests/test-*.sh (feature 0009 T04): the guards
#      of package.sh on stand-in XCFrameworks, and the zip package.sh makes from the build of step 1
#      (contents, notices, checksum, binaryTarget stanza, a consumer `swift run`), each into its own
#      temporary directory, so dist/apple/ is not written;
#   5. platforms/swift/scripts/test-simulators.sh, when it exists (feature 0009 T03: the iOS
#      Simulator run, swift-ios-sim).
#
# Not on macOS, or without swift, the suite cannot run: it prints `SKIPPED (<reason>)` as its last
# line and exits 0, which scripts/test-all.sh reports as SKIPPED, never as passing.
# Bash 3.2 compatible (macOS /bin/bash).
set -euo pipefail

me=platforms/swift/test.sh
swift_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$swift_dir/../.." && pwd)"
cd "$root"

if [ "$(uname -s)" != Darwin ]; then
  echo "SKIPPED (Swift (iOS) suite: needs macOS with Xcode)"
  exit 0
fi
for tool in swift xcodebuild cargo; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "SKIPPED (Swift (iOS) suite: $tool missing)"
    exit 0
  fi
done

xcframework="$swift_dir/build/PolyjoseFFI.xcframework"
echo "==> $me: test-xcframework-stale.sh"
"$swift_dir/scripts/test-xcframework-stale.sh"
# shellcheck source=scripts/xcframework-stale.sh
. "$swift_dir/scripts/xcframework-stale.sh"
if reason=$(xcframework_stale "$root" "$xcframework"); then
  echo "==> $me: rebuilding the XCFramework: $reason"
  "$swift_dir/scripts/build-xcframework.sh"
else
  echo "$me: the XCFramework is up to date with the Rust inputs"
fi

echo "==> $me: check-generated"
"$swift_dir/scripts/check-generated.sh"

results="$root/target/conformance/swift-macos.json"
rm -f "$results"
echo "==> $me: swift test (macOS, Swift 6, warnings as errors)"
POLYJOSE_LOCAL_XCFRAMEWORK=1 POLYJOSE_CONFORMANCE_OUT="$results" \
  swift test -Xswiftc -warnings-as-errors 2>&1 | grep -v '^POLYJOSE-CONFORMANCE-RESULTS '
[ -f "$results" ] || { echo "$me: swift test passed but wrote no $results"; exit 1; }
echo "$me: wrote $results"

for packaging_test in "$swift_dir"/scripts/tests/test-*.sh; do
  echo "==> $me: ${packaging_test#"$root"/}"
  "$packaging_test"
done

simulators="$swift_dir/scripts/test-simulators.sh"
if [ -e "$simulators" ]; then
  echo "==> $me: $simulators"
  "$simulators"
fi
echo "$me: PASS"
