#!/usr/bin/env bash
# The emulator job of .github/workflows/binding-android.yml (feature 0008 T05; ADR 0033 §5,
# ADR 0034 §2, ADR 0060): the instrumented suite of :polyjose on an emulator, through feature 0008
# T03's scripts/run-instrumented.sh, which this script wraps and does not change. Run
# ci-android-sdk.sh --emulator first.
#
#   platforms/android/scripts/ci-emulator.sh
#
# Environment (each optional):
#   POLYJOSE_CI_SYSTEM_IMAGE  the system image (default system-images;android-36;google_apis;x86_64,
#                             the CI image on KVM); its last `;` field is the ABI the device must
#                             report
#   POLYJOSE_AVD              the AVD to boot (default polyjose-ci-api36); passed to run-instrumented.sh
#   POLYJOSE_EMULATOR_BOOT_TIMEOUT  passed through (seconds, default 300)
#   POLYJOSE_CI_DATA_PARTITION  the userdata partition of an AVD this script creates (default 4G;
#                             the pixel_6 profile asks for 12 GB, more than a runner may have free)
#
# 1. KVM (Linux in GitHub Actions only): the udev rule that lets the runner user open /dev/kvm,
#    as GitHub documents for hardware-accelerated Android emulators. Then /dev/kvm must be
#    readable and writable. Nothing is changed outside GitHub Actions.
# 2. The AVD: an existing AVD of that name is used as it is (never changed or deleted). Otherwise
#    `avdmanager create avd -n <avd> -k <image> -d pixel_6` with disk.dataPartition.size set in its
#    config.ini; that AVD, created by this run, is deleted when the script exits.
# 3. `POLYJOSE_AVD=<avd> scripts/run-instrumented.sh`, which boots the AVD headless, runs
#    :polyjose:connectedDebugAndroidTest, judges it by the JUnit XML and writes
#    target/conformance/android-emulator.json, and stops only the emulator it started. A running
#    emulator is used instead of booting one (that is run-instrumented.sh's rule; the ABI check
#    below still applies).
# 4. Stricter than a local run: here the instrumented suite is the job, so its waiver line
#    `SKIPPED-RUNNER (android-emulator: host:<token>)` (no SDK, no AVD, a boot timeout) is a
#    FAILURE, and the device must report the image's ABI.
# 5. The results: target/conformance/android-emulator.json is renamed android-emulator-ci.json
#    (a CI run; parity compares it as runner android-emulator, ADR 0034 §2) and copied to
#    <out>/conformance-android-emulator/ (ci-lib.sh).
#
# Exit status: 0 the suite passed on the expected ABI; 1 anything else; 2 usage or setup error.
set -uo pipefail
# shellcheck source=ci-lib.sh source-path=SCRIPTDIR
. "$(dirname "$0")/ci-lib.sh"

[ $# -eq 0 ] || { echo "usage: ${0##*/}   (settings come from the environment, see the header)" >&2; exit 2; }
image=${POLYJOSE_CI_SYSTEM_IMAGE:-$ci_default_image}
avd=${POLYJOSE_AVD:-$ci_default_avd}
abi=${image##*;}
case $image in system-images\;android-*\;*\;*) ;; *) ci_die "POLYJOSE_CI_SYSTEM_IMAGE is not a system image path: $image" ;; esac
case $avd in '' | *[!A-Za-z0-9._-]*) ci_die "POLYJOSE_AVD is not an AVD name: $avd" ;; esac
data_partition=${POLYJOSE_CI_DATA_PARTITION:-4G}
case $data_partition in [1-9]*[GM]) ;; *) ci_die "POLYJOSE_CI_DATA_PARTITION is not a size like 4G: $data_partition" ;; esac

sdk=${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}
[ -n "$sdk" ] && [ -d "$sdk" ] || ci_die "neither ANDROID_HOME nor ANDROID_SDK_ROOT names an SDK directory"
avdmanager=$sdk/cmdline-tools/latest/bin/avdmanager
emulator=$sdk/emulator/emulator
[ -x "$avdmanager" ] || ci_die "no avdmanager at $avdmanager"
[ -x "$emulator" ] || ci_die "no emulator at $emulator (ci-android-sdk.sh --emulator installs it)"

results=$ci_repo/target/conformance
out=$ci_out/conformance-android-emulator
rm -f "$results/android-emulator.json" "$results/android-emulator-ci.json"
rm -rf "$out"

created=""
log=""
cleanup() {
  if [ -n "$created" ]; then
    echo "ci-emulator: deleting the AVD this run created ($created)"
    "$avdmanager" delete avd -n "$created" >/dev/null 2>&1 || echo "ci-emulator: could not delete the AVD $created"
    created=""
  fi
  [ -z "$log" ] || rm -f "$log"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
fail() { echo "ci-emulator: FAILED: $*"; exit 1; }

# 1. KVM.
if [ "$(uname -s)" = Linux ]; then
  if [ "${GITHUB_ACTIONS:-}" = true ]; then
    echo "==> ci-emulator: enabling KVM for the runner user (udev rule)"
    echo 'KERNEL=="kvm", GROUP="kvm", MODE="0666", OPTIONS+="static_node=kvm"' |
      sudo tee /etc/udev/rules.d/99-kvm4all.rules >/dev/null || fail "cannot write the KVM udev rule"
    { sudo udevadm control --reload-rules && sudo udevadm trigger --name-match=kvm; } || fail "udevadm"
  fi
  [ -r /dev/kvm ] && [ -w /dev/kvm ] || fail "/dev/kvm is not readable and writable: no hardware acceleration"
  echo "ci-emulator: /dev/kvm is usable"
else
  echo "ci-emulator: KVM: not applicable on $(uname -s) (the emulator uses the host's hypervisor)"
fi

# 2. The AVD.
if "$emulator" -list-avds 2>/dev/null | tr -d '\r' | grep -qxF "$avd"; then
  echo "ci-emulator: using the existing AVD $avd (left as it is)"
else
  echo "==> ci-emulator: avdmanager create avd -n $avd -k \"$image\" -d pixel_6"
  echo no | "$avdmanager" create avd -n "$avd" -k "$image" -d pixel_6 >/dev/null || fail "avdmanager create avd"
  created=$avd
  # The AVD's folder, from <avd home>/<avd>.ini (avdmanager writes path=<folder>).
  avd_home=${ANDROID_AVD_HOME:-${ANDROID_USER_HOME:-$HOME/.android}/avd}
  avd_dir=$(sed -n 's/^path=//p' "$avd_home/$avd.ini" 2>/dev/null | tr -d '\r')
  config=$avd_dir/config.ini
  [ -n "$avd_dir" ] && [ -f "$config" ] || fail "no config.ini for the new AVD (looked in $avd_home/$avd.ini)"
  { grep -v '^disk\.dataPartition\.size=' "$config"; echo "disk.dataPartition.size=$data_partition"; } >"$config.new" ||
    fail "cannot write $config.new"
  mv "$config.new" "$config" || fail "cannot set disk.dataPartition.size in $config"
  echo "ci-emulator: created AVD $avd ($image, userdata $data_partition)"
fi

# 3. The instrumented run.
log=$(mktemp "${TMPDIR:-/tmp}/polyjose-ci-emulator.XXXXXX") || fail "mktemp"
POLYJOSE_AVD=$avd "$ci_android/scripts/run-instrumented.sh" 2>&1 | tee "$log"
rc=${PIPESTATUS[0]}
last=$(tail -n 1 "$log")

# 4. No waiver, the expected ABI.
case $last in SKIPPED-RUNNER*) fail "the emulator did not run ($last); CI requires the instrumented suite" ;; esac
[ "$rc" -eq 0 ] || fail "run-instrumented.sh exited $rc ($last)"
device=$(grep -E '^android-emulator: device [^ ]+: ' "$log" | tail -n 1)
case $device in
  *", ABI $abi, "*) echo "ci-emulator: the device reports ABI $abi, as $image" ;;
  *) fail "the device is not $abi as $image: ${device:-no device line}" ;;
esac

# 5. The results.
problem=$(ci_check_results "$results/android-emulator.json" android-emulator) || fail "$problem"
mv "$results/android-emulator.json" "$results/android-emulator-ci.json" || fail "cannot rename the results"
ci_copy "$results/android-emulator-ci.json" "$out" || fail "cannot copy the results to $out"
echo "ci-emulator: PASS ($abi, AVD $avd); wrote target/conformance/android-emulator-ci.json"
