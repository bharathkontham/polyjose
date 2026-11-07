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
#    exists) and `pm path android` answers (pending_readiness; feature 0008 F02).
# 2. `./gradlew --no-daemon :polyjose:connectedDebugAndroidTest` with ANDROID_SERIAL=<serial>.
# 3. Judged by the JUnit XML under polyjose/build/outputs/androidTest-results/connected/, not by
#    Gradle's exit status alone (AGP can report BUILD SUCCESSFUL when the instrumentation crashed,
#    feature 0008 T04): FAIL when it is missing, names no test, has a failure, an error or a skipped
#    test, or lacks the conformance test case.
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
boot_completed() { [ "$("$adb" -s "$1" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ]; }
# pending_readiness <serial>: returns 0 when the device is ready for Gradle; otherwise prints what
# it still waits for and returns 1. sys.boot_completed alone is not enough: right after it the
# package manager may not answer yet, and AGP then reports "No compatible devices connected" on a
# cold boot (feature 0008 F02). Ready is, in order: sys.boot_completed = 1, init.svc.bootanim =
# stopped (only when the image has that property), and `pm path android` exits 0 printing package:.
pending_readiness() {
  local v
  boot_completed "$1" || { echo "sys.boot_completed"; return 1; }
  v=$("$adb" -s "$1" shell getprop init.svc.bootanim 2>/dev/null | tr -d '\r') ||
    { echo "init.svc.bootanim (adb shell failed)"; return 1; }
  [ -z "$v" ] || [ "$v" = stopped ] || { echo "the boot animation (init.svc.bootanim=$v)"; return 1; }
  if ! v=$("$adb" -s "$1" shell pm path android 2>/dev/null | tr -d '\r') ||
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

rm -rf "$xml_dir" "$pulled_dir"
echo "==> android: ./gradlew :polyjose:connectedDebugAndroidTest (ANDROID_SERIAL=$serial)"
ANDROID_SERIAL=$serial ./gradlew --no-daemon :polyjose:connectedDebugAndroidTest
gradle_rc=$?

failed=0
# The JUnit XML (see the header).
xml_files=$(find "$xml_dir" -type f -name 'TEST-*.xml' 2>/dev/null)
if [ -z "$xml_files" ]; then
  echo "android-emulator: no JUnit XML under ${xml_dir#"$android_dir/"}"; failed=1
else
  counts=$(printf '%s\n' "$xml_files" | while IFS= read -r f; do grep -o '<testsuite [^>]*>' "$f"; done | awk '
    { for (i = 1; i <= NF; i++) if (split($i, kv, "=") == 2) { gsub(/"/, "", kv[2]); n[kv[1]] += kv[2] } }
    END { printf "%d %d %d %d\n", n["tests"], n["failures"], n["errors"], n["skipped"] }')
  read -r tests failures errors skipped <<<"$counts"
  echo "android-emulator: JUnit XML: $tests tests, $failures failures, $errors errors, $skipped skipped"
  if [ "$tests" -eq 0 ] || [ "$failures" -ne 0 ] || [ "$errors" -ne 0 ] || [ "$skipped" -ne 0 ]; then failed=1; fi
  if ! printf '%s\n' "$xml_files" | while IFS= read -r f; do cat "$f"; done |
    grep -q '<testcase name="everyVectorRunsOnTheEmulator" classname="dev.polyjose.ConformanceInstrumentedTest"'; then
    echo "android-emulator: the JUnit XML has no ConformanceInstrumentedTest.everyVectorRunsOnTheEmulator"; failed=1
  fi
fi
[ "$gradle_rc" -eq 0 ] || { echo "android-emulator: :polyjose:connectedDebugAndroidTest exited $gradle_rc"; failed=1; }

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
