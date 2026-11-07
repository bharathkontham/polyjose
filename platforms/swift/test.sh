#!/usr/bin/env bash
# The Swift (iOS) binding's test suite (ADR 0032 §5, ADR 0046 §2), run by `scripts/test-all.sh
# swift` (feature 0013 T04's dispatcher) or directly, from any directory.
#
# Steps, each failing the suite on error:
#   1. builds platforms/swift/build/PolyjoseFFI.xcframework with
#      platforms/swift/scripts/build-xcframework.sh when it is missing (an existing one is reused;
#      step 2 fails if its C header no longer matches polyjose-ffi);
#   2. platforms/swift/scripts/check-generated.sh: the committed Polyjose.swift is what the bindgen
#      generates (ADR 0032 §4);
#   3. `swift test` at the repository root with POLYJOSE_LOCAL_XCFRAMEWORK=1, in Swift 6 language
#      mode with warnings as errors, which runs every conformance vector on the macOS host and
#      writes target/conformance/swift-macos.json (ADR 0034 §2, ADR 0060; POLYJOSE_CONFORMANCE_OUT).
#      The suite fails unless that file was written. The test's one-line copy of the document
#      (POLYJOSE-CONFORMANCE-RESULTS ...) is left out of this script's output;
#   4. platforms/swift/scripts/test-simulators.sh, when it exists (feature 0009 T03: the iOS
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
if [ ! -d "$xcframework" ]; then
  echo "==> $me: building the XCFramework (missing)"
  "$swift_dir/scripts/build-xcframework.sh"
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

simulators="$swift_dir/scripts/test-simulators.sh"
if [ -e "$simulators" ]; then
  echo "==> $me: $simulators"
  "$simulators"
fi
echo "$me: PASS"
