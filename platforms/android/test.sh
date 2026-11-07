#!/usr/bin/env bash
# The Kotlin/Android suite: what `scripts/test-all.sh android` runs (feature 0013 T04 dispatch).
#
#   platforms/android/test.sh        (from any directory; test-all.sh runs it from the repo root)
#
# 1. `./gradlew :polyjose-jvm:test`: the generated Kotlin on the host JVM through JNA and the host
#    library (ADR 0033 §5). Always runs when its toolchain exists.
# 2. `scripts/run-instrumented.sh` (feature 0008 T03), when it exists: the instrumented suite on
#    the polyjose-api36 emulator. Its own output, including a final `SKIPPED (<reason>)` line when
#    it cannot boot an emulator, is this script's output and exit status.
#
# Dispatch contract (scripts/test-all.sh): the exit status decides PASS or FAIL. A suite that
# cannot run (no JDK, no cargo) exits 0 with `SKIPPED (<reason>)` as its last line, which is
# reported as SKIPPED, never as passing (pipeline rule 9). Gradle runs without a daemon, so the
# script leaves no Gradle process behind on this shared machine.
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
if [ -e "$instrumented" ] || [ -L "$instrumented" ]; then
  if [ ! -f "$instrumented" ] || [ ! -x "$instrumented" ]; then
    echo "platforms/android/$instrumented exists but is not an executable file (chmod +x)"; exit 1
  fi
  echo "==> android: $instrumented"
  exec "./$instrumented"
fi
echo "android: instrumented suite NOT RUN: platforms/android/$instrumented does not exist yet (feature 0008 T03)"
echo "android: :polyjose-jvm:test passed"
