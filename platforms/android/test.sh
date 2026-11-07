#!/usr/bin/env bash
# The Kotlin/Android suite: what `scripts/test-all.sh android` runs (feature 0013 T04 dispatch).
#
#   platforms/android/test.sh        (from any directory; test-all.sh runs it from the repo root)
#
# 1. `./gradlew :polyjose-jvm:test`: the generated Kotlin on the host JVM through JNA and the host
#    library (ADR 0033 §5). Always runs when its toolchain exists.
# 2. `scripts/run-instrumented.sh` (feature 0008 T03): the instrumented suite on an emulator
#    (polyjose-api36), runner `android-emulator`. Its output and exit status are this script's.
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
# gradlew uses $JAVA_HOME/bin/java, else java on PATH. `-version` must run: macOS has a /usr/bin/java
# stub that exists without any JDK installed.
java=java; [ -n "${JAVA_HOME:-}" ] && java=$JAVA_HOME/bin/java
if ! "$java" -version >/dev/null 2>&1; then
  echo "SKIPPED (no JDK: $java -version failed; JDK 21 is needed, see .toolchain-env.sh)"; exit 0
fi
if ! have cargo; then echo "SKIPPED (cargo missing: the JVM tests build polyjose-ffi for the host)"; exit 0; fi

echo "==> android: ./gradlew :polyjose-jvm:test"
./gradlew --no-daemon :polyjose-jvm:test || { echo "android: :polyjose-jvm:test FAILED"; exit 1; }

instrumented=scripts/run-instrumented.sh
if [ ! -f "$instrumented" ] || [ -L "$instrumented" ] || [ ! -x "$instrumented" ]; then
  echo "platforms/android/$instrumented is missing or not an executable regular file"; exit 1
fi
echo "==> android: $instrumented"
exec "./$instrumented"
