#!/usr/bin/env bash
# Android SDK setup for the emulator and assembly jobs of .github/workflows/binding-android.yml
# (feature 0008 T05; ADR 0033 §1, §2). Uses only the SDK's own sdkmanager and cargo, no third-party
# action.
#
#   platforms/android/scripts/ci-android-sdk.sh [--emulator]
#
# 1. With sdkmanager from $ANDROID_HOME (or $ANDROID_SDK_ROOT)/cmdline-tools/latest/bin, installs
#    each pinned package that is not installed yet (ci-lib.sh): platform-tools,
#    platforms;android-<compileSdk of gradle/libs.versions.toml>, build-tools;36.0.0 and
#    ndk;28.2.13676358; with --emulator also `emulator` and the system image
#    $POLYJOSE_CI_SYSTEM_IMAGE (default system-images;android-36;google_apis;x86_64). A package that
#    is already installed is never reinstalled or updated, so on a developer machine (the SDK is
#    shared) the script changes nothing that exists. It accepts the SDK licenses only when it has
#    something to install.
# 2. cargo-ndk 4.1.2 (the version used locally) with `cargo install --locked` when
#    `cargo ndk --version` is not that version.
# 3. In GitHub Actions ($GITHUB_ENV set), exports ANDROID_HOME, ANDROID_SDK_ROOT and
#    ANDROID_NDK_HOME (cargo-ndk and check-artifacts.sh read it) to the later steps.
#
# Exit status: 0 set up; 1 an install failed; 2 usage or no SDK.
set -uo pipefail
# shellcheck source=ci-lib.sh source-path=SCRIPTDIR
. "$(dirname "$0")/ci-lib.sh"

emulator=0
case ${1:-} in
  "") ;;
  --emulator) emulator=1 ;;
  *) echo "usage: ${0##*/} [--emulator]" >&2; exit 2 ;;
esac
fail() { echo "ci-android-sdk: FAILED: $*"; exit 1; }

sdk=${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}
[ -n "$sdk" ] && [ -d "$sdk" ] || ci_die "neither ANDROID_HOME nor ANDROID_SDK_ROOT names an SDK directory"
sdkmanager=$sdk/cmdline-tools/latest/bin/sdkmanager
[ -x "$sdkmanager" ] || ci_die "no sdkmanager at $sdkmanager (install the SDK command-line tools)"

compile_sdk=$(sed -n 's/^androidCompileSdk = "\([0-9]*\)"$/\1/p' "$ci_android/gradle/libs.versions.toml")
[ -n "$compile_sdk" ] || ci_die "no androidCompileSdk in gradle/libs.versions.toml"
packages="platform-tools platforms;android-$compile_sdk build-tools;$ci_build_tools ndk;$ci_ndk"
image=${POLYJOSE_CI_SYSTEM_IMAGE:-$ci_default_image}
[ "$emulator" = 0 ] || packages="$packages emulator $image"

# The installed package paths, `;`-separated whichever sdkmanager prints (older ones print
# `build-tools;36.0.0 | ...`, the Android CLI wrapper prints `build-tools/36.0.0  36.0.0 ...`).
installed=$("$sdkmanager" --list_installed 2>/dev/null |
  awk '/^Installed packages:/{f=1; next} f && NF {print $1}' | tr '/' ';') ||
  fail "sdkmanager --list_installed"
missing=""
for p in $packages; do
  if printf '%s\n' "$installed" | grep -qxF "$p"; then echo "ci-android-sdk: $p: installed (left as it is)"
  else missing="$missing $p"; fi
done
if [ -n "$missing" ]; then
  echo "==> ci-android-sdk: sdkmanager --install${missing}"
  # `yes` answers every license prompt; it is ended by SIGPIPE when sdkmanager exits.
  yes 2>/dev/null | "$sdkmanager" --licenses >/dev/null || true
  # shellcheck disable=SC2086 # one word per package path; no path contains a space
  "$sdkmanager" --install $missing || fail "sdkmanager --install${missing}"
fi

ndk_home=$sdk/ndk/$ci_ndk
[ -d "$ndk_home" ] || fail "no NDK at $ndk_home after the install"

if [ "$(cargo ndk --version 2>/dev/null)" = "cargo-ndk $ci_cargo_ndk" ]; then
  echo "ci-android-sdk: cargo-ndk $ci_cargo_ndk: installed"
else
  echo "==> ci-android-sdk: cargo install --locked cargo-ndk --version $ci_cargo_ndk"
  cargo install --locked cargo-ndk --version "$ci_cargo_ndk" || fail "cargo install cargo-ndk $ci_cargo_ndk"
fi

if [ -n "${GITHUB_ENV:-}" ]; then
  {
    echo "ANDROID_HOME=$sdk"
    echo "ANDROID_SDK_ROOT=$sdk"
    echo "ANDROID_NDK_HOME=$ndk_home"
  } >>"$GITHUB_ENV"
  echo "ci-android-sdk: exported ANDROID_HOME, ANDROID_SDK_ROOT and ANDROID_NDK_HOME=$ndk_home"
fi
echo "ci-android-sdk: ready ($packages; cargo-ndk $ci_cargo_ndk)"
