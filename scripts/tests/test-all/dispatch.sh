#!/usr/bin/env bash
# Test of the per-platform dispatcher of scripts/test-all.sh (feature 0013 T04, ADR 0030 §1):
# `test-all.sh wasm|node|android|swift` (`apple` is an alias of swift, ADR 0046 §1) runs
# bindings/wasm/test.sh, bindings/node/test.sh, platforms/android/test.sh or
# platforms/swift/test.sh when it exists. Its exit status decides PASS or
# FAIL, and `SKIPPED (<reason>)` as its last line (with exit 0) reports SKIPPED, which never counts
# as passing (pipeline rule 9). Without a script the platform keeps its inline commands and their
# SKIPPED reasons (0001 T14).
#
# Each case runs test-all.sh in a copy of the working tree with fixture scripts (lib.sh), under the
# bash that runs this test. Usage: scripts/tests/test-all/dispatch.sh
set -euo pipefail
export LC_ALL=C
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

# --- Each platform runs its own script ----------------------------------------------------------------

new_case all-pass
fixture bindings/wasm/test.sh 0 'fixture wasm suite ran'
fixture bindings/node/test.sh 0 'fixture node suite ran'
fixture platforms/android/test.sh 0 'fixture android suite ran'
fixture platforms/swift/test.sh 0 'fixture swift suite ran'
# Each passing platform writes its runners' results files, which the parity step requires (F05).
writes_own_results bindings/wasm/test.sh wasm
writes_own_results bindings/node/test.sh node
writes_own_results platforms/android/test.sh android
writes_own_results platforms/swift/test.sh swift
run_test_all wasm node android swift
check "each platform runs its script and passes on exit 0" 0 \
  '^fixture wasm suite ran$' '^fixture node suite ran$' '^fixture android suite ran$' '^fixture swift suite ran$' \
  '^  wasm: PASS$' '^  node: PASS$' '^  android: PASS$' '^  swift: PASS$'
check_absent "no platform falls back to its inline commands" 'wasm-pack test|npm ci|gradlew test|swift test'

# The independent RSA-OAEP-256 oracle (feature 0003 T11) is not a binding suite: it still runs.
if command -v node >/dev/null 2>&1; then
  check "the node platform still runs the RSA-OAEP-256 oracle" 0 '^  rsa-oaep-oracle: PASS$'
else
  check "the node platform still reports the RSA-OAEP-256 oracle" 0 '^  rsa-oaep-oracle: SKIPPED \(node missing\)$'
fi

# The shared facade's suite (bindings/js/test.sh) is a step of the node platform, before its suite.
if command -v node >/dev/null 2>&1 && command -v npm >/dev/null 2>&1; then
  check "the node platform runs the facade suite" 0 '^==> js-facade \(bindings/js/test\.sh\)$' '^  js-facade: PASS$'
  check_order "before the node suite" '^  js-facade: PASS$' '^  node: PASS$'
else
  check "the node platform reports the facade suite" 0 '^  js-facade: SKIPPED \(node or npm missing\)$'
fi

new_case facade-fail
fixture bindings/node/test.sh 0 'fixture node suite ran'
writes_own_results bindings/node/test.sh node
fixture bindings/js/test.sh 1 'fixture facade suite failed'
run_test_all node
if command -v node >/dev/null 2>&1 && command -v npm >/dev/null 2>&1; then
  check "a failing facade suite FAILs the run; the node suite still runs" 1 '^  js-facade: FAIL$' '^  node: PASS$'
else
  check "without node or npm the facade suite is SKIPPED, never passing" 0 '^  js-facade: SKIPPED \(node or npm missing\)$'
fi

# --- Exit status and the SKIPPED line -----------------------------------------------------------------

new_case fail
fixture platforms/android/test.sh 3 'fixture android suite failed'
run_test_all android
check "a script that exits non-zero FAILs the platform and the run" 1 \
  '^fixture android suite failed$' '^  android: FAIL$'

new_case skipped
fixture platforms/swift/test.sh 0 'no iOS simulator found' 'SKIPPED (iOS 27.2 simulator missing)'
run_test_all swift
check "SKIPPED (<reason>) as the last line with exit 0 reports SKIPPED with that reason" 0 \
  '^  swift: SKIPPED \(iOS 27\.2 simulator missing\)$'
check_absent "a skipped platform is not reported as passing" '^  swift: PASS$'

new_case skipped-trailing-blank
fixture bindings/wasm/test.sh 0 'SKIPPED (no Chrome)' ''
run_test_all wasm
check "trailing blank lines after the SKIPPED line still report SKIPPED" 0 '^  wasm: SKIPPED \(no Chrome\)$'

new_case skipped-but-failed
fixture bindings/node/test.sh 1 'SKIPPED (npm missing)'
run_test_all node
check "a SKIPPED line does not hide a non-zero exit status" 1 '^  node: FAIL$'

new_case skipped-not-last
fixture bindings/wasm/test.sh 0 'SKIPPED (one browser missing)' 'node tests passed'
writes_own_results bindings/wasm/test.sh wasm
run_test_all wasm
check "SKIPPED on an earlier line is ordinary output: exit 0 passes" 0 '^  wasm: PASS$'

new_case skipped-malformed
fixture platforms/android/test.sh 0 'SKIPPED'
run_test_all android
check "a last line starting with SKIPPED but without (<reason>) FAILs" 1 \
  '^  android: FAIL$' 'SKIPPED \(<reason>\)'

new_case not-executable
fixture platforms/swift/test.sh 0 'fixture swift suite ran'
chmod -x "$case_dir/platforms/swift/test.sh"
run_test_all swift
check "a script that exists but is not executable FAILs instead of falling back" 1 \
  '^  swift: FAIL$' 'platforms/swift/test\.sh exists but is not an executable file'
check_absent "a non-executable script is not run" '^fixture swift suite ran$'

new_case stdin
fixture bindings/wasm/test.sh 0 'fixture wasm suite ran'
# shellcheck disable=SC2016 # expanded by the fixture, not here
fixture_append bindings/wasm/test.sh 'read -r line && echo "read stdin: $line"'
writes_own_results bindings/wasm/test.sh wasm
rc=0
(cd "$case_dir" && "${BASH:-bash}" scripts/test-all.sh wasm) <<<"caller input" >"$scratch/out" 2>&1 || rc=$?
check "a script reading stdin still runs" 0 '^  wasm: PASS$'
check_absent "a script gets no stdin from the caller" '^read stdin:'

# --- Without a script: today's behaviour --------------------------------------------------------------

# No platforms/android/test.sh and no Gradle wrapper: the inline check reports it SKIPPED, as before.
new_case android-fallback
rm -f "$case_dir/platforms/android/test.sh" "$case_dir/platforms/android/gradlew"
run_test_all android
check "without a script, a platform keeps its inline SKIPPED reason" 0 \
  '^  android: SKIPPED \(cargo-ndk or Gradle project missing\)$'

new_case swift-fallback
rm -f "$case_dir/platforms/swift/test.sh" "$case_dir/Package.swift"
run_test_all swift
check "without a script, swift keeps its inline SKIPPED reason" 0 '^  swift: SKIPPED \(swift or Package\.swift missing\)$'

# --- The apple alias (ADR 0046 §1: the platform key is swift; apple was its key before) -----------

new_case apple-alias
fixture platforms/swift/test.sh 0 'fixture swift suite ran'
writes_own_results platforms/swift/test.sh swift
run_test_all apple
check "apple is an alias of swift: it runs the swift suite, reported as swift" 0 \
  '^fixture swift suite ran$' '^==> swift \(platforms/swift/test\.sh\)$' '^  swift: PASS$' '^  parity: '
check_absent "the alias is not reported under its old name" '^  apple: |unknown platform'

new_case apple-alias-skipped
fixture platforms/swift/test.sh 0 'SKIPPED (iOS 27.2 simulator missing)'
run_test_all apple
check "the alias keeps the swift suite's SKIPPED reason" 0 '^  swift: SKIPPED \(iOS 27\.2 simulator missing\)$'

finish
