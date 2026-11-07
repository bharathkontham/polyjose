#!/usr/bin/env bash
# Tests of platforms/swift/scripts/simulator-lib.sh, the helpers of test-simulators.sh (feature
# 0009 T03), on fixtures only: no simulator, no xcodebuild. Run first by test-simulators.sh.
#   - sim_runtime_available / sim_iphone_type over `xcrun simctl list runtimes -j` documents;
#   - vectors_digest_reference on the ADR 0060 §4 worked example;
#   - extract_results: exactly one marked line, its payload written byte for byte with one LF.
# Prints one line per case and `test-simulator-lib.sh: N/N passed`; exits 1 on any failure.
# Needs plutil and shasum (macOS). Bash 3.2 compatible.
set -euo pipefail
export LC_ALL=C

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=simulator-lib.sh
. "$here/simulator-lib.sh"

tmp="$(mktemp -d "${TMPDIR:-/tmp}/polyjose-simlib-test.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT
pass=0 total=0
ok() { total=$((total + 1)); pass=$((pass + 1)); echo "ok   $1"; }
bad() { total=$((total + 1)); echo "FAIL $1"; }
check() { # check <name> <command...>: the command must succeed
  local name=$1; shift
  if "$@"; then ok "$name"; else bad "$name"; fi
}
refute() { # refute <name> <command...>: the command must fail
  local name=$1; shift
  if "$@"; then bad "$name"; else ok "$name"; fi
}

rt=com.apple.CoreSimulator.SimRuntime.iOS-27-2
# runtime <identifier> <isAvailable> <device types JSON array>
runtime() { printf '{"identifier":"%s","isAvailable":%s,"platform":"iOS","supportedDeviceTypes":%s}' "$1" "$2" "$3"; }
types_ipad_first='[{"identifier":"com.apple.CoreSimulator.SimDeviceType.iPad-Air","productFamily":"iPad"},
 {"identifier":"com.apple.CoreSimulator.SimDeviceType.iPhone-18-Pro","productFamily":"iPhone"},
 {"identifier":"com.apple.CoreSimulator.SimDeviceType.iPhone-17","productFamily":"iPhone"}]'
types_no_iphone='[{"identifier":"com.apple.CoreSimulator.SimDeviceType.iPad-Air","productFamily":"iPad"}]'

# The runtime installed and available, after a device-specific runtime with a longer identifier.
printf '{"runtimes":[%s,%s,%s]}' \
  "$(runtime "$rt-iPhone19-4" true '[{"identifier":"com.apple.CoreSimulator.SimDeviceType.iPhone-Duo","productFamily":"iPhone"}]')" \
  "$(runtime com.apple.CoreSimulator.SimRuntime.tvOS-27-0 true '[]')" \
  "$(runtime "$rt" true "$types_ipad_first")" >"$tmp/present.json"
check "runtime present and available" sim_runtime_available "$tmp/present.json" "$rt"
got=$(sim_iphone_type "$tmp/present.json" "$rt" || true)
check "first iPhone device type of that runtime (not the iPad, not the iPhone-19-4 runtime's)" \
  test "$got" = com.apple.CoreSimulator.SimDeviceType.iPhone-18-Pro

printf '{"runtimes":[%s]}' "$(runtime "$rt" false "$types_ipad_first")" >"$tmp/unavailable.json"
refute "runtime listed but not available" sim_runtime_available "$tmp/unavailable.json" "$rt"

printf '{"runtimes":[%s,%s]}' "$(runtime "$rt-iPhone19-4" true '[]')" \
  "$(runtime com.apple.CoreSimulator.SimRuntime.iOS-26-4 true "$types_ipad_first")" >"$tmp/missing.json"
refute "runtime missing (only other iOS runtimes)" sim_runtime_available "$tmp/missing.json" "$rt"
printf '{"runtimes":[]}' >"$tmp/empty.json"
refute "no runtime at all" sim_runtime_available "$tmp/empty.json" "$rt"
printf 'not json' >"$tmp/garbage.json"
refute "unreadable runtimes document" sim_runtime_available "$tmp/garbage.json" "$rt"

printf '{"runtimes":[%s]}' "$(runtime "$rt" true "$types_no_iphone")" >"$tmp/no-iphone.json"
check "runtime without iPhones is still available" sim_runtime_available "$tmp/no-iphone.json" "$rt"
refute "no iPhone device type on the runtime" sim_iphone_type "$tmp/no-iphone.json" "$rt"

# ADR 0060 §4 worked example.
mkdir -p "$tmp/vectors/jws" "$tmp/vectors/jws-x"
printf '{}' >"$tmp/vectors/a.json"
printf '{}\n' >"$tmp/vectors/jws/b.json"
printf '\357\273\277{}' >"$tmp/vectors/jws-x/c.json"
printf 'notes' >"$tmp/vectors/README.md"
got=$(vectors_digest_reference "$tmp/vectors")
check "vectors_digest_reference = the ADR 0060 §4 worked example" \
  test "$got" = 9a06f1efdd269176088cb0e6bfc6a7e4d4f74aa3d1b1b8fc6c879fdbb82ac7d1
ln -s a.json "$tmp/vectors/link.json"
got=$(vectors_digest_reference "$tmp/vectors")
check "a symbolic link gets no line (ADR 0060 §2)" \
  test "$got" = 9a06f1efdd269176088cb0e6bfc6a7e4d4f74aa3d1b1b8fc6c879fdbb82ac7d1
mkdir -p "$tmp/novectors"
printf 'notes' >"$tmp/novectors/README.md"
refute "an empty corpus has no digest (ADR 0060 §3)" vectors_digest_reference "$tmp/novectors"

m='POLYJOSE-CONFORMANCE-RESULTS '
printf 'Test Case started\n%s{"runner":"swift-ios-sim","a":"x y"}\nTest Case passed\n' "$m" >"$tmp/one.log"
check "one marked line is extracted" extract_results "$tmp/one.log" "$m" "$tmp/one.json"
printf '{"runner":"swift-ios-sim","a":"x y"}\n' >"$tmp/one.expected"
check "the payload is written byte for byte with one LF" cmp -s "$tmp/one.json" "$tmp/one.expected"
printf 'Test Case started\n' >"$tmp/none.log"
refute "no marked line" extract_results "$tmp/none.log" "$m" "$tmp/none.json"
printf '%s{}\nnoise\n%s{}\n' "$m" "$m" >"$tmp/two.log"
refute "two marked lines" extract_results "$tmp/two.log" "$m" "$tmp/two.json"
printf 'prefix %s{}\n' "$m" >"$tmp/inline.log"
refute "a marker not at the start of a line does not count" extract_results "$tmp/inline.log" "$m" "$tmp/inline.json"
printf '%s{"a":"x/y&z\\\\"}\n' "$m" >"$tmp/meta.log"
extract_results "$tmp/meta.log" "$m" "$tmp/meta.json" || true
printf '{"a":"x/y&z\\\\"}\n' >"$tmp/meta.expected"
check "slashes, ampersands and backslashes are kept" cmp -s "$tmp/meta.json" "$tmp/meta.expected"

echo "test-simulator-lib.sh: $pass/$total passed"
[ "$pass" -eq "$total" ]
