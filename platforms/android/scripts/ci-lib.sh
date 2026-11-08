# shellcheck shell=bash
# The variables below are read by the scripts that source this file.
# shellcheck disable=SC2034
# Shared by the platforms/android/scripts/ci-*.sh scripts of .github/workflows/binding-android.yml
# (feature 0008 T05; ADR 0033 §4, §5; ADR 0037 §1). Sourced, never run: it defines variables and
# functions and changes nothing. Runs on macOS /bin/bash 3.2, Linux bash and Git Bash on Windows.
#
#   ci_android  platforms/android (absolute)       ci_repo  the repository root (absolute)
#   ci_out      where the scripts put what the workflow uploads, one folder per artifact named as
#               the artifact (ADR 0037 §1: jvm-natives-<prefix>, conformance-<runner>, android-aar,
#               jvm-jar, maven-repo): $POLYJOSE_CI_OUT, default target/ci at the repository root.

ci_android=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P) || exit 2
ci_repo=$(cd "$ci_android/../.." && pwd -P) || exit 2
ci_out=${POLYJOSE_CI_OUT:-$ci_repo/target/ci}

# The five JNA resource prefixes of the release jar (ADR 0033 §3a, §4), as polyjose-jvm/build.gradle.kts.
ci_prefixes="darwin-aarch64 darwin-x86-64 linux-aarch64 linux-x86-64 win32-x86-64"

# Pinned Android SDK packages (installed by ci-android-sdk.sh): the compile SDK of
# gradle/libs.versions.toml, the build-tools whose zipalign check-artifacts.sh runs, and the NDK of
# the workspace's .toolchain-env.sh (README: NDK 28.2). cargo-ndk is the version used locally.
ci_build_tools=36.0.0
ci_ndk=28.2.13676358
ci_cargo_ndk=4.1.2
# The emulator job's system image (ADR 0033 §5 runs API 36; CI uses x86_64 on KVM) and AVD name.
ci_default_image="system-images;android-36;google_apis;x86_64"
ci_default_avd=polyjose-ci-api36

ci_die() { echo "${0##*/}: $*" >&2; exit 2; }

# The SHA-256 of gradle/wrapper/gradle-wrapper.jar (feature 0008 F06, audit M2): the value Gradle
# publishes for the 9.8.2 wrapper jar,
#   https://services.gradle.org/distributions/gradle-9.8.2-wrapper.jar.sha256
# (fetched 2026-11-07; equal to the committed jar, as T01 found). The wrapper jar is the code
# `./gradlew` runs first, so a jar that is not Gradle's must never run (Gradle's user manual, "The
# Gradle Wrapper", verifying the wrapper JAR). Upgrading the wrapper means updating this pin from
# the new version's published .sha256.
ci_gradle_wrapper_version=9.8.2
ci_gradle_wrapper_sha256=3b8a25775a69158b5ad2b1d17a80a88dc7b40a352a73eb27d06c612a7ce68e98

# ci_check_gradle_wrapper [<jar>]: returns 0 when the jar (default: platforms/android's
# gradle/wrapper/gradle-wrapper.jar) has the pinned SHA-256; otherwise prints why and returns 1.
# Called before any `./gradlew` (platforms/android/test.sh; the workflow jobs, feature 0008 F08).
ci_check_gradle_wrapper() {
  local jar=${1:-$ci_android/gradle/wrapper/gradle-wrapper.jar} sum
  [ -f "$jar" ] || { echo "gradle wrapper: no jar at $jar"; return 1; }
  if command -v sha256sum >/dev/null 2>&1; then sum=$(sha256sum "$jar") || sum=""
  elif command -v shasum >/dev/null 2>&1; then sum=$(shasum -a 256 "$jar") || sum=""
  else echo "gradle wrapper: neither sha256sum nor shasum is available to hash $jar"; return 1
  fi
  sum=${sum%% *}; sum=${sum#\\}
  if [ "$sum" != "$ci_gradle_wrapper_sha256" ]; then
    echo "gradle wrapper: $jar has SHA-256 ${sum:-unknown}, not Gradle $ci_gradle_wrapper_version's $ci_gradle_wrapper_sha256"
    return 1
  fi
}

# ci_triple_of <prefix>: the Rust target triple of a JNA prefix; empty for an unknown prefix.
ci_triple_of() {
  case $1 in
    darwin-aarch64) echo aarch64-apple-darwin ;;
    darwin-x86-64) echo x86_64-apple-darwin ;;
    linux-aarch64) echo aarch64-unknown-linux-gnu ;;
    linux-x86-64) echo x86_64-unknown-linux-gnu ;;
    win32-x86-64) echo x86_64-pc-windows-msvc ;;
  esac
}

# ci_library_of <prefix>: the file name cargo gives the polyjose-ffi cdylib on that platform.
ci_library_of() {
  case $1 in
    darwin-*) echo libpolyjose_ffi.dylib ;;
    win32-*) echo polyjose_ffi.dll ;;
    *) echo libpolyjose_ffi.so ;;
  esac
}

# ci_file_pattern <prefix>: an extended regex that `file` prints for a library of that platform.
ci_file_pattern() {
  case $1 in
    darwin-aarch64) echo 'Mach-O 64-bit .*arm64' ;;
    darwin-x86-64) echo 'Mach-O 64-bit .*x86_64' ;;
    linux-aarch64) echo 'ELF 64-bit .*(aarch64|ARM aarch64)' ;;
    linux-x86-64) echo 'ELF 64-bit .*x86-64' ;;
    win32-x86-64) echo 'PE32\+ .*x86-64' ;;
  esac
}

# ci_host_prefix: this machine's JNA prefix, the one Gradle's assembleJvmNatives uses; empty when
# polyjose ships no JVM library for it.
ci_host_prefix() {
  local os arch
  case $(uname -s) in
    Darwin) os=darwin ;;
    Linux) os=linux ;;
    MINGW* | MSYS* | CYGWIN*) os=win32 ;;
    *) return 0 ;;
  esac
  case $(uname -m) in
    arm64 | aarch64) arch=aarch64 ;;
    x86_64 | amd64) arch=x86-64 ;;
    *) return 0 ;;
  esac
  case " $ci_prefixes " in *" $os-$arch "*) echo "$os-$arch" ;; esac
}

# ci_is_prefix <word>: whether it is one of the five prefixes.
ci_is_prefix() { case " $ci_prefixes " in *" $1 "*) return 0 ;; esac; return 1; }

# ci_sha256 <file>: the lowercase hex SHA-256 of a file.
ci_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

# ci_cargo_target: cargo's target directory, CARGO_TARGET_DIR (relative to the workspace) or target.
ci_cargo_target() {
  case ${CARGO_TARGET_DIR:-} in
    "") echo "$ci_repo/target" ;;
    /*) echo "$CARGO_TARGET_DIR" ;;
    *) echo "$ci_repo/$CARGO_TARGET_DIR" ;;
  esac
}

# ci_copy <file> <dir>: copies a file into a directory, creating it.
ci_copy() { mkdir -p "$2" && cp "$1" "$2/"; }

# ci_check_results <file> <runner>: the ADR 0034 §2 results document of <runner>, with a 64-hex
# vectors_digest (ADR 0060 §1) and no failed vector. Parity checks the rest. Prints the problem.
ci_check_results() {
  local file=$1 runner=$2
  [ -f "$file" ] && [ ! -L "$file" ] || { echo "no results file $file"; return 1; }
  grep -Eq "\"runner\": *\"$runner\"" "$file" || { echo "$file is not runner $runner's results"; return 1; }
  grep -Eq '"vectors_digest": *"[0-9a-f]{64}"' "$file" || { echo "$file has no 64-hex vectors_digest"; return 1; }
  if grep -Eq '"status": *"fail"' "$file"; then echo "$file holds failed vectors"; return 1; fi
  return 0
}
