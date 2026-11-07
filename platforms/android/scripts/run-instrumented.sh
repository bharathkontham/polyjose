#!/usr/bin/env bash
# The instrumented suite of :polyjose on an Android emulator (feature 0008 T03; ADR 0033 §5,
# ADR 0034 §2, ADR 0060): the shared Kotlin conformance runner as `android-emulator`, plus the
# on-device security tests, through the generated Kotlin API and libpolyjose_ffi.so over JNA.
#
#   platforms/android/scripts/run-instrumented.sh      (from any directory; test.sh runs it)
#
# 1. Device. An emulator that `adb devices` lists as `device` is used as it is and never stopped
#    (the machine is shared). Otherwise this script boots the AVD headless on a free console port,
#      emulator -avd <avd> -port <port> -no-window -no-audio -no-snapshot -gpu swiftshader_indirect
#    and stops that emulator, and only that one, with `adb -s <serial> emu kill` when it exits,
#    also on an error or an interrupt (a trap). Nothing is ever stopped by process pattern.
#    Either way it waits, at most POLYJOSE_EMULATOR_BOOT_TIMEOUT seconds in all, until the device
#    is ready for Gradle: sys.boot_completed = 1, init.svc.bootanim = stopped (when the property
#    exists) and `pm path android` answers (pending_readiness; feature 0008 F02). Each of those
#    adb shell calls is bounded to 10 s by timeout/gtimeout where available (F06).
# 2. One Gradle call with ANDROID_SERIAL=<serial>:
#      ./gradlew --no-daemon --continue :polyjose:connectedDebugAndroidTest \
#        :sample-minified:connectedReleaseAndroidTest
#    the instrumented suite, then the R8 consumer-rules proof: the minified release build of
#    :sample-minified, shrunk under the AAR's consumer-rules.pro alone (ADR 0033 §2; review S5,
#    feature 0008 F06). --continue runs the second task when the first fails, so both are judged.
# 3. Judged by the JUnit XML, not by Gradle's exit status alone (AGP can report BUILD SUCCESSFUL
#    when the instrumentation crashed, feature 0008 T04), by the same rules for each task's XML
#    under <module>/build/outputs/androidTest-results/connected/: FAIL when it is missing, names no
#    test, has a failure, an error or a skipped test, or lacks a required test case. Required:
#    ConformanceInstrumentedTest.everyVectorRunsOnTheEmulator for :polyjose, and the three
#    R8ProbeTest cases for :sample-minified. Gradle's exit status must be 0 as well.
# 4. The results document: the test writes it to the test app's files dir and to AGP's additional
#    test output dir on the device, which AGP pulls to
#    polyjose/build/outputs/connected_android_test_additional_output/ before it uninstalls the test
#    APK; this script copies it to target/conformance/android-emulator.json (repository root,
#    ADR 0034 §2). FAIL when it was not pulled or is not android-emulator's document.
#
# When there is no emulator to run on, the JVM tests have still run (test.sh runs them first), so
# the platform is not SKIPPED: the runner is waived with the last line, exactly
#   SKIPPED-RUNNER (android-emulator: host:<token>)        (scripts/test-all.sh, 0013 F05)
# and exit 0. Tokens: no-android-sdk (no ANDROID_HOME/ANDROID_SDK_ROOT, adb or emulator binary),
# no-avd (the AVD does not exist), emulator-boot-timeout (not ready within the budget),
# emulator-exited (the emulator this script started stopped before it was ready).
#
# Only arm64-v8a runs on this Apple Silicon host's AVD; x86_64 is NOT RUN (no x86_64 system image).
# The AVD has 4 KB pages, so 16 KB page-size runtime testing is SKIPPED with that reason (the
# 16 KB alignment of the .so files is checked statically, scripts/check-artifacts.sh).
#
# Environment: ANDROID_HOME (or ANDROID_SDK_ROOT); POLYJOSE_AVD (default polyjose-api36);
# POLYJOSE_EMULATOR_BOOT_TIMEOUT (seconds, default 300).
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
android_dir=$(pwd)
repo=$(cd ../.. && pwd) || exit 2

avd=${POLYJOSE_AVD:-polyjose-api36}
boot_timeout=${POLYJOSE_EMULATOR_BOOT_TIMEOUT:-300}
case $boot_timeout in '' | *[!0-9]*)
  echo "POLYJOSE_EMULATOR_BOOT_TIMEOUT must be a whole number of seconds, not \"$boot_timeout\""; exit 2 ;;
esac
results=$repo/target/conformance/android-emulator.json
outputs=$android_dir/polyjose/build/outputs
xml_dir=$outputs/androidTest-results/connected
r8_xml_dir=$android_dir/sample-minified/build/outputs/androidTest-results/connected
pulled_dir=$outputs/connected_android_test_additional_output

# The emulator this script started (its serial and PID) and its log dir, removed on exit.
serial="" started_pid="" work=""
cleanup() {
  if [ -n "$started_pid" ]; then
    echo "android-emulator: stopping the emulator this script started ($serial)"
    "$adb" -s "$serial" emu kill >/dev/null 2>&1
    local _
    for _ in $(seq 1 30); do kill -0 "$started_pid" 2>/dev/null || break; sleep 1; done
    # Still there: our own child, stopped by its PID.
    if kill -0 "$started_pid" 2>/dev/null; then kill "$started_pid" 2>/dev/null; fi
    started_pid=""
  fi
  [ -z "$work" ] || rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# waive <token> <reason>: no emulator to run on (see the header). The emulator this script
# started, if any, is stopped first, so the waiver is the last line.
waive() {
  cleanup
  echo "android-emulator: NOT RUN: $2"
  echo "SKIPPED-RUNNER (android-emulator: host:$1)"
  exit 0
}
# finish <status> <line>: stops this script's emulator, then prints the final line.
finish() { cleanup; echo "$2"; exit "$1"; }

# A stale file from an earlier run must never stand in for this one (ADR 0060).
rm -f "$results"

sdk=${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}
[ -n "$sdk" ] || waive no-android-sdk "neither ANDROID_HOME nor ANDROID_SDK_ROOT is set"
adb=$sdk/platform-tools/adb
emulator=$sdk/emulator/emulator
[ -x "$adb" ] || waive no-android-sdk "no adb at $adb"

# The serials adb lists, in any state (device, offline, unauthorized).
listed_serials() { "$adb" devices 2>/dev/null | awk 'NR > 1 && NF >= 2 { print $1 }'; }
# ready_shell <serial> <command...>: `adb -s <serial> shell <command...>` for the readiness wait,
# bounded to 10 s by `timeout` (coreutils, Linux) or `gtimeout` (Homebrew coreutils, macOS) where
# one exists, so a wedged adb server cannot hold the wait past POLYJOSE_EMULATOR_BOOT_TIMEOUT
# (feature 0008 F06, review N2); a call that times out counts as not ready yet. Without either
# tool the call is made unbounded, as before. stdin is /dev/null: timeout runs the command outside
# the terminal's foreground process group, where reading the terminal would stop it.
adb_timeout=""
for t in timeout gtimeout; do command -v "$t" >/dev/null 2>&1 && { adb_timeout=$t; break; }; done
ready_shell() {
  local s=$1; shift
  if [ -n "$adb_timeout" ]; then "$adb_timeout" 10 "$adb" -s "$s" shell "$@" </dev/null
  else "$adb" -s "$s" shell "$@" </dev/null; fi
}
boot_completed() { [ "$(ready_shell "$1" getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ]; }
# pending_readiness <serial>: returns 0 when the device is ready for Gradle; otherwise prints what
# it still waits for and returns 1. sys.boot_completed alone is not enough: right after it the
# package manager may not answer yet, and AGP then reports "No compatible devices connected" on a
# cold boot (feature 0008 F02). Ready is, in order: sys.boot_completed = 1, init.svc.bootanim =
# stopped (only when the image has that property), and `pm path android` exits 0 printing package:.
pending_readiness() {
  local v
  boot_completed "$1" || { echo "sys.boot_completed"; return 1; }
  v=$(ready_shell "$1" getprop init.svc.bootanim 2>/dev/null | tr -d '\r') ||
    { echo "init.svc.bootanim (adb shell failed)"; return 1; }
  [ -z "$v" ] || [ "$v" = stopped ] || { echo "the boot animation (init.svc.bootanim=$v)"; return 1; }
  if ! v=$(ready_shell "$1" pm path android 2>/dev/null | tr -d '\r') ||
    ! printf '%s\n' "$v" | grep -q '^package:'; then
    echo "the package manager (pm path android)"; return 1
  fi
}

serial=$("$adb" devices 2>/dev/null | awk 'NR > 1 && $1 ~ /^emulator-[0-9]+$/ && $2 == "device" { print $1; exit }')
if [ -n "$serial" ]; then
  echo "android-emulator: using the running emulator $serial (left running)"
  # The same readiness wait and budget as a boot; on a timeout it is waived, never stopped.
  start=$SECONDS
  until pending=$(pending_readiness "$serial"); do
    [ $((SECONDS - start)) -lt "$boot_timeout" ] ||
      waive emulator-boot-timeout "the running emulator $serial was not ready within ${boot_timeout} s (still waiting for $pending)"
    sleep 2
  done
else
  [ -x "$emulator" ] || waive no-android-sdk "no emulator binary at $emulator"
  "$emulator" -list-avds 2>/dev/null | tr -d '\r' | grep -qxF "$avd" ||
    waive no-avd "no AVD named $avd (emulator -list-avds)"
  # A console port no listed device uses (the emulator takes it and the next one for adb).
  listed=" $(listed_serials | tr '\n' ' ') "
  port=""
  for p in $(seq 5554 2 5584); do
    case $listed in *" emulator-$p "* | *" emulator-$((p + 1)) "*) ;; *) port=$p; break ;; esac
  done
  [ -n "$port" ] || { echo "android-emulator: no free emulator console port in 5554-5584"; exit 1; }
  serial=emulator-$port
  work=$(mktemp -d "${TMPDIR:-/tmp}/polyjose-emulator.XXXXXX") || exit 1
  echo "android-emulator: booting $avd headless as $serial (at most ${boot_timeout} s)"
  "$emulator" -avd "$avd" -port "$port" -no-window -no-audio -no-snapshot -gpu swiftshader_indirect \
    </dev/null >"$work/emulator.log" 2>&1 &
  started_pid=$!
  start=$SECONDS
  # One budget for the whole wait: sys.boot_completed and then the rest of pending_readiness.
  until pending=$(pending_readiness "$serial"); do
    if ! kill -0 "$started_pid" 2>/dev/null; then
      started_pid=""
      echo "android-emulator: the emulator exited before it was ready; the end of its log:"
      tail -n 15 "$work/emulator.log" | sed 's/^/    /'
      waive emulator-exited "the emulator $avd exited while waiting for $pending"
    fi
    [ $((SECONDS - start)) -lt "$boot_timeout" ] ||
      waive emulator-boot-timeout "$avd was not ready within ${boot_timeout} s (still waiting for $pending)"
    sleep 2
  done
  echo "android-emulator: $serial booted and ready in $((SECONDS - start)) s"
fi

prop() { "$adb" -s "$serial" shell getprop "$1" 2>/dev/null | tr -d '\r'; }
abi=$(prop ro.product.cpu.abi)
page_size=$("$adb" -s "$serial" shell getconf PAGE_SIZE 2>/dev/null | tr -d '\r')
echo "android-emulator: device $serial: $(prop ro.product.model), API $(prop ro.build.version.sdk), ABI $abi, page size $page_size"
echo "android: ABIs run: ${abi:-unknown}; x86_64: NOT RUN (no x86_64 system image on this host)"
if [ "$page_size" = 16384 ]; then
  echo "android: 16 KB page-size runtime: run on this device"
else
  echo "android: 16 KB page-size runtime: SKIPPED (the device has ${page_size:-unknown}-byte pages; 16 KB alignment is checked statically)"
fi

rm -rf "$xml_dir" "$r8_xml_dir" "$pulled_dir"
tasks=":polyjose:connectedDebugAndroidTest :sample-minified:connectedReleaseAndroidTest"
echo "==> android: ./gradlew --continue $tasks (ANDROID_SERIAL=$serial)"
# shellcheck disable=SC2086 # $tasks is two task names
ANDROID_SERIAL=$serial ./gradlew --no-daemon --continue $tasks
gradle_rc=$?

# judge_xml <label> <dir> <classname> <test case>...: the JUnit XML rules of the header for one
# task's results. Prints the counts and every problem; returns 1 on any problem.
judge_xml() {
  local label=$1 dir=$2 class=$3 files counts tests failures errors skipped bad=0 name; shift 3
  files=$(find "$dir" -type f -name 'TEST-*.xml' 2>/dev/null)
  if [ -z "$files" ]; then echo "$label: no JUnit XML under ${dir#"$android_dir/"}"; return 1; fi
  counts=$(printf '%s\n' "$files" | while IFS= read -r f; do grep -o '<testsuite [^>]*>' "$f"; done | awk '
    { for (i = 1; i <= NF; i++) if (split($i, kv, "=") == 2) { gsub(/"/, "", kv[2]); n[kv[1]] += kv[2] } }
    END { printf "%d %d %d %d\n", n["tests"], n["failures"], n["errors"], n["skipped"] }')
  read -r tests failures errors skipped <<<"$counts"
  echo "$label: JUnit XML: $tests tests, $failures failures, $errors errors, $skipped skipped"
  if [ "$tests" -eq 0 ] || [ "$failures" -ne 0 ] || [ "$errors" -ne 0 ] || [ "$skipped" -ne 0 ]; then bad=1; fi
  for name in "$@"; do
    if ! printf '%s\n' "$files" | while IFS= read -r f; do cat "$f"; done |
      grep -q "<testcase name=\"$name\" classname=\"$class\""; then
      echo "$label: the JUnit XML has no ${class##*.}.$name"; bad=1
    fi
  done
  return "$bad"
}

failed=0
judge_xml android-emulator "$xml_dir" dev.polyjose.ConformanceInstrumentedTest everyVectorRunsOnTheEmulator || failed=1
if judge_xml "android-r8" "$r8_xml_dir" dev.polyjose.sample.R8ProbeTest theLibraryLoadsAndReportsItsVersion \
  anEs256RoundTripReturnsThePayload anInvalidJwkIsReportedByItsCode; then
  echo "android-r8: the minified :sample-minified release passed R8ProbeTest (consumer-rules.pro, ADR 0033 §2)"
else
  failed=1
fi
[ "$gradle_rc" -eq 0 ] || { echo "android-emulator: ./gradlew $tasks exited $gradle_rc"; failed=1; }

# The results document AGP pulled (see the header).
pulled=$(find "$pulled_dir" -type f -name android-emulator.json 2>/dev/null)
if [ -z "$pulled" ] || [ "$(printf '%s\n' "$pulled" | wc -l)" -ne 1 ]; then
  finish 1 "android-emulator: expected one pulled android-emulator.json under ${pulled_dir#"$android_dir/"}, found ${pulled:-none}"
fi
if ! grep -q '^  "runner": "android-emulator",$' "$pulled" ||
  ! grep -Eq '^  "vectors_digest": "[0-9a-f]{64}",$' "$pulled"; then
  finish 1 "android-emulator: the pulled file is not android-emulator's results document: $pulled"
fi
{ mkdir -p "$(dirname "$results")" && cp "$pulled" "$results"; } || finish 1 "android-emulator: cannot write $results"
digest=$(sed -n 's/^  "vectors_digest": "\([0-9a-f]*\)",$/\1/p' "$results")
count() { grep -c "\"status\":\"$1\"" "$results"; }
summary="$(count pass) passed, $(count fail) failed, $(count skipped) skipped; vectors_digest $digest"
[ "$failed" -eq 0 ] || finish 1 "android-emulator: FAILED ($summary; wrote ${results#"$repo/"})"
finish 0 "android-emulator: $summary; wrote ${results#"$repo/"}"
