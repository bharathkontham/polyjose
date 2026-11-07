# shellcheck shell=bash
# Shared helpers for the packaging tests of platforms/swift/scripts/package.sh (ADR 0032 §6,
# ADR 0020 §4). Sourced by the tests/test-*.sh files, not run.
#
# Every test writes only to its own scratch directory, which is removed on exit together with any
# consumer package and its .build directory, so the checkout (and its dist/apple/) is never
# touched. Bash 3.2 compatible (macOS /bin/bash).

export LC_ALL=C
tests_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
swift_dir="$(cd "$tests_dir/../.." && pwd)"
# shellcheck disable=SC2034 # repo, release_libraries and dev_libraries are read by the tests
repo="$(cd "$swift_dir/../.." && pwd -P)"
package_sh="$swift_dir/scripts/package.sh"
tests_run=0
tests_failed=0

lib_die() { echo "ERROR: $*" >&2; exit 2; }

scratch=$(mktemp -d "${TMPDIR:-/tmp}/polyjose-package-test.XXXXXX") || lib_die "mktemp failed"
trap 'rm -rf "$scratch"' EXIT
# SwiftPM leaves a lock file per package path in $TMPDIR; keep those inside the scratch directory.
mkdir -p "$scratch/tmp"
# shellcheck disable=SC2034 # read by the tests
swift_tmp="$scratch/tmp"

pass() { tests_run=$((tests_run + 1)); echo "ok   - $1"; }
fail() { tests_run=$((tests_run + 1)); tests_failed=$((tests_failed + 1)); echo "FAIL - $1"; }
check() { if eval "$2"; then pass "$1"; else fail "$1"; fi; }

# run_package <args...>: runs package.sh, keeping its stdout and stderr in $scratch/last.log and
# its exit status in $rc.
# shellcheck disable=SC2034 # rc is read by the tests that source this file
run_package() {
  rc=0
  "$package_sh" "$@" >"$scratch/last.log" 2>&1 || rc=$?
}

show_log() { sed 's/^/    | /' "$scratch/last.log"; }

# log_has <fixed string>: the last package.sh output contains the string.
log_has() { grep -qF -- "$1" "$scratch/last.log"; }

# The XCFramework library identifiers of ADR 0032 §1. A development build (`arm64_32: missing`,
# no nightly) has `watchos-arm64` instead of `watchos-arm64_arm64_32`.
release_libraries="ios-arm64 ios-arm64_x86_64-simulator macos-arm64_x86_64 tvos-arm64
tvos-arm64-simulator watchos-arm64-simulator watchos-arm64_arm64_32 xros-arm64
xros-arm64-simulator"
# shellcheck disable=SC2034,SC2086 # read by the tests; a word list
dev_libraries=$(printf '%s\n' $release_libraries | sed 's/^watchos-arm64_arm64_32$/watchos-arm64/' | tr '\n' ' ')

finish() {
  echo "$tests_run checks, $tests_failed failed"
  [ "$tests_failed" -eq 0 ]
}
