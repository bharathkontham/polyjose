#!/usr/bin/env bash
# The Kotlin/Android suite: what `scripts/test-all.sh android` runs (feature 0013 T04 dispatch).
#
#   bindings/kotlin/test.sh        (from any directory; test-all.sh runs it from the repo root)
#
# 0. `scripts/ci-check-workflow.sh` and its negative suite `scripts/ci-check-workflow-test.sh`
#    (feature 0008 T05, F06): .github/workflows/binding-android.yml stays dispatch-only, with no
#    secrets, publishing or signing (owner decision 2026-11-07; ADR 0044). They need only bash, awk
#    and grep, so they run first, before the toolchain checks and Gradle; either failing fails the
#    platform. Then the wrapper jar's SHA-256 must be the one Gradle publishes, pinned in
#    scripts/ci-lib.sh (audit M2), before any `./gradlew`.
# 1. `./gradlew :polyjose-jvm:test`: the generated Kotlin on the host JVM through JNA and the host
#    library (ADR 0033 §5). Always runs when its toolchain exists.
# 2. With an Android SDK (ANDROID_HOME or ANDROID_SDK_ROOT): `./gradlew :polyjose:lintRelease`
#    (Android lint of the AAR at minSdk 23; any error fails, NewApi included: the Keystore classes
#    of feature 0025 T04 call API 28-35 methods behind version checks), then
#    `scripts/check-artifacts.sh` (the AAR, jar, APK and publication checks: 16 KB alignment, the
#    5 MB AAR limit, the POM's dependencies). Without an SDK they are NOT RUN, and the instrumented
#    script below waives its runner (no-android-sdk).
# 3. `scripts/run-instrumented.sh` (feature 0008 T03): the instrumented suite on an emulator
#    (polyjose-api36), runner `android-emulator`, and in the same Gradle call the R8
#    consumer-rules proof, :sample-minified's minified release test (ADR 0033 §2). Its output and
#    exit status are this script's.
#
# Dispatch contract (scripts/test-all.sh): the exit status decides PASS or FAIL. When nothing can
# run (no JDK, no cargo) the script exits 0 with `SKIPPED (<reason>)` as its last line, which is
# reported as SKIPPED, never as passing (pipeline rule 9). When the JVM tests passed but there is
# no emulator to run on (no SDK, no AVD, a boot timeout), the platform is not SKIPPED: the
# instrumented script's last line, passed through unchanged, is
#   SKIPPED-RUNNER (android-emulator: host:<token>)
# which waives that host-optional runner (results_runners `android: jvm android-emulator?`,
# 0013 F05); test-all.sh reports the runner SKIPPED under parity, never as passing. Gradle runs
# without a daemon, so the script leaves no Gradle process behind on this shared machine.
set -uo pipefail
cd "$(dirname "$0")" || exit 2

have() { command -v "$1" >/dev/null 2>&1; }

for check in scripts/ci-check-workflow.sh scripts/ci-check-workflow-test.sh; do
  echo "==> android: $check"
  "./$check" || { echo "android: $check FAILED"; exit 1; }
done

# The wrapper jar is the first code ./gradlew runs: it must be Gradle's (audit M2, ci-lib.sh).
# shellcheck source=scripts/ci-lib.sh source-path=SCRIPTDIR
. scripts/ci-lib.sh
echo "==> android: gradle wrapper jar SHA-256 (Gradle $ci_gradle_wrapper_version)"
ci_check_gradle_wrapper || { echo "android: the Gradle wrapper jar check FAILED"; exit 1; }

# gradlew uses $JAVA_HOME/bin/java, else java on PATH. `-version` must run: macOS has a /usr/bin/java
# stub that exists without any JDK installed.
java=java; [ -n "${JAVA_HOME:-}" ] && java=$JAVA_HOME/bin/java
if ! "$java" -version >/dev/null 2>&1; then
  echo "SKIPPED (no JDK: $java -version failed; JDK 21 is needed, see .toolchain-env.sh)"; exit 0
fi
if ! have cargo; then echo "SKIPPED (cargo missing: the JVM tests build polyjose-ffi for the host)"; exit 0; fi

echo "==> android: ./gradlew :polyjose-jvm:test"
./gradlew --no-daemon :polyjose-jvm:test || { echo "android: :polyjose-jvm:test FAILED"; exit 1; }

if [ -n "${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}" ]; then
  echo "==> android: ./gradlew :polyjose:lintRelease"
  ./gradlew --no-daemon :polyjose:lintRelease || { echo "android: :polyjose:lintRelease FAILED"; exit 1; }
  echo "==> android: scripts/check-artifacts.sh"
  scripts/check-artifacts.sh || { echo "android: scripts/check-artifacts.sh FAILED"; exit 1; }
else
  echo "android: lint and scripts/check-artifacts.sh: NOT RUN (no Android SDK: neither ANDROID_HOME nor ANDROID_SDK_ROOT is set)"
fi

instrumented=scripts/run-instrumented.sh
if [ ! -f "$instrumented" ] || [ -L "$instrumented" ] || [ ! -x "$instrumented" ]; then
  echo "bindings/kotlin/$instrumented is missing or not an executable regular file"; exit 1
fi
echo "==> android: $instrumented"
exec "./$instrumented"
