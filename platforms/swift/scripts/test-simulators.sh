#!/usr/bin/env bash
# The Swift (iOS) binding on the iOS Simulator, and the Apple device link checks (ADR 0032 §5 as
# amended by ADR 0046 §2-§4; feature 0009 T03). Run by platforms/swift/test.sh after `swift test`,
# or directly, from any directory.
#
# Steps, each failing the script on error:
#   0. platforms/swift/scripts/test-simulator-lib.sh, the fixture tests of the helpers below
#      (simulator-lib.sh).
#   1. iOS device link check: `xcodebuild build-for-testing` for `generic/platform=iOS` with
#      CODE_SIGNING_ALLOWED=NO (iOS is the main target, ADR 0046 §1). Build only, no test run.
#   2. watchOS link check, build only: the same for `generic/platform=watchOS`, at the package's
#      watchOS 9 deployment target (Xcode links the test bundle at watchOS 10, XCTest's minimum).
#      It links both slices, arm64_32 (minos 9.0) and arm64, whose objects have minos 26.0 (Rust's
#      default for aarch64-apple-watchos, ADR 0032 §1). An error fails the check; the linker's
#      warnings are printed. Xcode 27.2's ld (ld-27106.1) gives none (measured 2026-11-07). Not a
#      per-platform suite (ADR 0046 §2); tvOS and visionOS are checked by the XCFramework build
#      only (ADR 0046 §3).
#   3. The iOS Simulator run (ADR 0046 §2): `xcodebuild test -scheme polyjose` on a disposable
#      iPhone simulator on the iOS 27.2 runtime (com.apple.CoreSimulator.SimRuntime.iOS-27-2), with
#      POLYJOSE_LOCAL_XCFRAMEWORK=1. The destination is that device's UDID, never a generic one
#      (a generic simulator destination links x86_64, ADR 0032 §5). Every XCTest must pass, and the
#      conformance test's results document becomes target/conformance/swift-ios-sim.json
#      (ADR 0034 §2: an off-host run hands its results to the host-side driver):
#      - the document is the one line of the test output that starts with
#        `POLYJOSE-CONFORMANCE-RESULTS `; there must be exactly one;
#      - the simulator also writes the document to a host file (POLYJOSE_CONFORMANCE_OUT, passed as
#        TEST_RUNNER_POLYJOSE_CONFORMANCE_OUT, see `man xcodebuild`), and the extracted line plus LF
#        must equal that file byte for byte, so a line split or cut in the console is caught;
#      - its `runner` is swift-ios-sim, and its `vectors_digest`, computed in the simulator over the
#        bundled vector bytes (ADR 0060 §2, §5), equals the ADR 0060 §4 shell reference over this
#        checkout's conformance/vectors/, so the iOS test bundle matches the checkout byte for byte.
#        scripts/conformance-parity.sh then compares the file with rust-core.json.
#
# Simulator hygiene (a shared machine): the script creates one simulator device with
# `xcrun simctl create`, uses it by UDID, and on exit (also on failure or interrupt) shuts it down
# and deletes it. It never shuts down, erases or deletes any other device. Parallel testing is off,
# so xcodebuild makes no clones of it.
#
# Without the iOS 27.2 runtime the simulator run cannot happen: after the link checks the script
# prints `SKIPPED-RUNNER (swift-ios-sim: host:no-ios-runtime)`, which waives the optional
# swift-ios-sim runner in scripts/test-all.sh (its runner table), then `SKIPPED (no iOS simulator
# runtime)` as its last line, and exits 0. That is the only waiver; every other problem fails.
#
# The xcodebuild logs stay in target/swift-xcode/logs/. DerivedData and the result bundle go to a
# temporary directory that is deleted on exit.
# Needs macOS with Xcode (xcodebuild, xcrun simctl, plutil, shasum). Bash 3.2 compatible.
set -euo pipefail
export LC_ALL=C

me=platforms/swift/scripts/test-simulators.sh
scripts="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$scripts/../../.." && pwd)"
cd "$root"
# shellcheck source-path=SCRIPTDIR source=simulator-lib.sh
. "$scripts/simulator-lib.sh"

runner=swift-ios-sim
runtime_id=com.apple.CoreSimulator.SimRuntime.iOS-27-2
marker='POLYJOSE-CONFORMANCE-RESULTS '
results="$root/target/conformance/$runner.json"
logs="$root/target/swift-xcode/logs"

for tool in xcodebuild xcrun plutil shasum; do
  command -v "$tool" >/dev/null 2>&1 || { echo "$me: $tool missing (needs macOS with Xcode)"; exit 1; }
done
xcrun simctl help >/dev/null 2>&1 || { echo "$me: xcrun simctl is not available"; exit 1; }

rm -f "$results"
mkdir -p "$logs" "$(dirname "$results")"
work="$(mktemp -d "${TMPDIR:-/tmp}/polyjose-simulators.XXXXXX")"
derived="$work/DerivedData"
udid=

# On exit: shuts down and deletes the device this script created (by UDID), and nothing else;
# removes the temporary directory.
cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  if [ -n "$udid" ]; then
    xcrun simctl shutdown "$udid" >/dev/null 2>&1 || true # not booted: nothing to shut down
    if xcrun simctl delete "$udid"; then
      echo "$me: deleted the simulator $udid"
    else
      echo "$me: could not delete the simulator $udid; delete it with: xcrun simctl delete $udid"
      [ "$rc" -ne 0 ] || rc=1
    fi
  fi
  rm -rf "$work"
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo "==> $me: test-simulator-lib.sh"
"$scripts/test-simulator-lib.sh" >"$logs/test-simulator-lib.log" 2>&1 ||
  { cat "$logs/test-simulator-lib.log"; echo "$me: test-simulator-lib.sh failed"; exit 1; }
tail -1 "$logs/test-simulator-lib.log"

# xcb <log name> <xcodebuild arguments...>: runs xcodebuild on the root package with the local
# XCFramework, its output in $logs/<log name>.log; on failure prints the log's errors and fails.
xcb() {
  local name=$1 rc=0
  shift
  POLYJOSE_LOCAL_XCFRAMEWORK=1 xcodebuild -scheme polyjose -derivedDataPath "$derived" "$@" \
    >"$logs/$name.log" 2>&1 || rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "$me: xcodebuild ($name) exited $rc; errors (full log: $logs/$name.log):"
    grep -E 'error:|\*\* .* FAILED \*\*|Testing failed|Test Case .* failed' "$logs/$name.log" | head -50 || true
    exit 1
  fi
}

echo "==> $me: iOS device link check (build-for-testing, generic/platform=iOS)"
xcb ios-device build-for-testing -destination 'generic/platform=iOS' CODE_SIGNING_ALLOWED=NO
echo "$me: iOS device build-for-testing succeeded"

echo "==> $me: watchOS link check (build-for-testing, generic/platform=watchOS, watchOS 9 target)"
xcb watchos-device build-for-testing -destination 'generic/platform=watchOS' CODE_SIGNING_ALLOWED=NO
echo "$me: watchOS device build-for-testing succeeded; linker warnings:"
grep -E '^ld: warning|ld: warning:|built for newer' "$logs/watchos-device.log" | sort -u || echo "  (none)"

xcrun simctl list runtimes -j >"$work/runtimes.json"
if ! sim_runtime_available "$work/runtimes.json" "$runtime_id"; then
  echo "$me: the iOS 27.2 simulator runtime ($runtime_id) is not installed or not available"
  echo "SKIPPED-RUNNER ($runner: host:no-ios-runtime)"
  echo "SKIPPED (no iOS simulator runtime)"
  exit 0
fi
device_type=$(sim_iphone_type "$work/runtimes.json" "$runtime_id") ||
  { echo "$me: the runtime $runtime_id supports no iPhone device type"; exit 1; }

udid=$(xcrun simctl create "polyjose-$runner-$$" "$device_type" "$runtime_id")
echo "==> $me: iOS Simulator run on a disposable ${device_type##*.} ($runtime_id), $udid"
direct="$work/direct.json"
# xcodebuild passes TEST_RUNNER_<name> to the test process as <name> (man xcodebuild).
export TEST_RUNNER_POLYJOSE_CONFORMANCE_OUT="$direct"
start=$(date +%s)
xcb ios-sim test -destination "platform=iOS Simulator,id=$udid" -resultBundlePath "$work/ios-sim.xcresult" \
  -parallel-testing-enabled NO
echo "$me: xcodebuild test passed on the iOS Simulator ($(($(date +%s) - start)) s)"
grep -E '^conformance \(' "$logs/ios-sim.log" || true

extracted="$work/extracted.json"
extract_results "$logs/ios-sim.log" "$marker" "$extracted" || exit 1
[ -f "$direct" ] || { echo "$me: the simulator wrote no $direct (POLYJOSE_CONFORMANCE_OUT)"; exit 1; }
cmp -s "$extracted" "$direct" ||
  { echo "$me: the extracted results line differs from the document the simulator wrote"; exit 1; }
echo "$me: the extracted results line equals the simulator's document ($(wc -c <"$direct" | tr -d ' ') bytes)"

got_runner=$(plutil -extract runner raw -o - "$extracted")
[ "$got_runner" = "$runner" ] || { echo "$me: the results document names runner $got_runner, not $runner"; exit 1; }
digest=$(plutil -extract vectors_digest raw -o - "$extracted")
reference=$(vectors_digest_reference "$root/conformance/vectors") ||
  { echo "$me: no vector file under conformance/vectors (ADR 0060 §3)"; exit 1; }
[ "$digest" = "$reference" ] || {
  echo "$me: vectors_digest $digest (the iOS test bundle) differs from $reference (conformance/vectors, ADR 0060 §4)"
  exit 1
}
mv "$extracted" "$results"
echo "$me: wrote $results (vectors_digest $digest, equal to the checkout's)"
echo "$me: PASS"
