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
# Fail closed (0013 F10, F11; see scripts/test-all.sh): /bin/bash 3.2 runs the EXIT trap with $? = 0
# after a syntax error, in a test or in this file. finish (each test's last statement) sets the
# sentinel, so a test that stops before it never exits 0.
completed=""
# shellcheck disable=SC2154 # rc is assigned by the trap itself (rc=$?)
trap 'rc=$?; rm -rf "$scratch"; [ -n "${completed:-}" ] || [ "$rc" -ne 0 ] || { echo "${0##*/}: stopped before finish (a syntax error?): failing closed" >&2; rc=2; }; exit "$rc"' EXIT
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

# A stand-in `cargo` for the same-crate-set check of package.sh (ADR 0032 §6, ADR 0020 §4;
# feature 0009 F03). It runs the real cargo for every command, so nothing needs the network.
# For `cargo tree` with `--target <T>`, where T is the target given to run_package_fake_cargo,
# it also prints the line $fake_extra_crate, as a dependency that only T compiles would add. It
# appends `tree <target>` to $fake_cargo_log for every `cargo tree`, so a test can see which
# targets package.sh asked about.
# shellcheck disable=SC2034 # fake_extra_crate and fake_cargo_log are read by the tests
fake_extra_crate="polyjose-f03-one-target-only v0.0.1"
# shellcheck disable=SC2034
fake_cargo_log="$scratch/fake-cargo.log"
fake_cargo_dir="$scratch/fake-cargo"

make_fake_cargo() {
  [ -x "$fake_cargo_dir/cargo" ] && return 0
  real_cargo=$(command -v cargo) || lib_die "cargo is not on PATH"
  mkdir -p "$fake_cargo_dir"
  cat >"$fake_cargo_dir/cargo" <<'EOF'
#!/bin/bash
# Stand-in cargo of platforms/swift/scripts/tests/lib.sh (make_fake_cargo).
set -uo pipefail
real=${POLYJOSE_FAKE_CARGO_REAL:?}
if [ "${1:-}" = tree ]; then
  target="" prev=""
  for arg in "$@"; do
    case $arg in --target=*) target=${arg#--target=} ;; esac
    [ "$prev" = --target ] && target=$arg
    prev=$arg
  done
  printf 'tree %s\n' "$target" >>"${POLYJOSE_FAKE_CARGO_LOG:?}"
  if [ -n "$target" ] && [ "$target" = "${POLYJOSE_FAKE_CARGO_TARGET:-}" ]; then
    "$real" "$@" || exit
    printf '%s\n' "${POLYJOSE_FAKE_CARGO_EXTRA:?}"
    exit 0
  fi
fi
exec "$real" "$@"
EOF
  chmod 755 "$fake_cargo_dir/cargo"
}

# run_package_fake_cargo <target> <args...>: run_package with the stand-in cargo first on PATH,
# adding $fake_extra_crate to the `cargo tree` of <target> only. $fake_cargo_log starts empty.
# shellcheck disable=SC2034 # rc is read by the tests that source this file
run_package_fake_cargo() {
  local target=$1
  shift
  make_fake_cargo
  : >"$fake_cargo_log"
  rc=0
  env PATH="$fake_cargo_dir:$PATH" POLYJOSE_FAKE_CARGO_REAL="$real_cargo" \
    POLYJOSE_FAKE_CARGO_TARGET="$target" POLYJOSE_FAKE_CARGO_EXTRA="$fake_extra_crate" \
    POLYJOSE_FAKE_CARGO_LOG="$fake_cargo_log" "$package_sh" "$@" >"$scratch/last.log" 2>&1 || rc=$?
}

show_log() { sed 's/^/    | /' "$scratch/last.log"; }

# log_has <fixed string>: the last package.sh output contains the string.
log_has() { grep -qF -- "$1" "$scratch/last.log"; }

# The XCFramework library identifiers of ADR 0032 §1. A development build (`arm64_32: missing`,
# no nightly) has `watchos-arm64` instead of `watchos-arm64_arm64_32`.
release_libraries="ios-arm64 ios-arm64_x86_64-simulator macos-arm64_x86_64 watchos-arm64-simulator
watchos-arm64_arm64_32"
# shellcheck disable=SC2034,SC2086 # read by the tests; a word list
dev_libraries=$(printf '%s\n' $release_libraries | sed 's/^watchos-arm64_arm64_32$/watchos-arm64/' | tr '\n' ' ')

# finish: prints the summary, sets the sentinel and returns non-zero if any case failed.
finish() {
  echo "$tests_run checks, $tests_failed failed"
  completed=1
  [ "$tests_failed" -eq 0 ]
}
