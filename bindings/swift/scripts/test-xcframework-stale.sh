#!/usr/bin/env bash
# Test of xcframework_stale (platforms/swift/scripts/xcframework-stale.sh), the decision of
# platforms/swift/test.sh to rebuild the XCFramework. Each case builds a scratch git repository
# with the inputs and a stand-in XCFramework whose polyjose-build.txt records a commit, then checks
# the verdict and its reason. The real checkout is never touched. Run by platforms/swift/test.sh;
# usage: platforms/swift/scripts/test-xcframework-stale.sh (bash 3.2 and 5; needs git).
set -euo pipefail

# shellcheck source=xcframework-stale.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/xcframework-stale.sh"

scratch=$(mktemp -d "${TMPDIR:-/tmp}/polyjose-xcframework-stale.XXXXXX")
# Fail closed (0013 F10): /bin/bash 3.2 runs an EXIT trap with $? = 0 after a syntax error, so an
# exit before the last line, which sets the sentinel, becomes status 2 (see scripts/test-all.sh).
completed=""
# shellcheck disable=SC2154 # rc is assigned by the trap itself (rc=$?)
trap 'rc=$?; rm -rf "$scratch"; [ -n "${completed:-}" ] || [ "$rc" -ne 0 ] || { echo "test-xcframework-stale.sh: stopped before its last statement (a syntax error?); failing closed" >&2; rc=2; }; exit "$rc"' EXIT
run=0 failed=0

g() { git -C "$repo" -c user.name=test -c user.email=test@invalid -c commit.gpgsign=false "$@"; }

# new_repo: a repository with every input and a non-input file, one commit, and a fresh stamp.
new_repo() {
  repo="$scratch/repo-$run"
  mkdir -p "$repo/crates/polyjose/src" "$repo/bindings/ffi" "$repo/platforms/swift/scripts" "$repo/docs"
  echo '[workspace]' >"$repo/Cargo.toml"
  echo 'lock' >"$repo/Cargo.lock"
  echo 'toolchain' >"$repo/rust-toolchain.toml"
  echo 'pub fn f() {}' >"$repo/crates/polyjose/src/lib.rs"
  echo 'ffi' >"$repo/bindings/ffi/lib.rs"
  echo 'nightly' >"$repo/platforms/swift/nightly-toolchain"
  echo 'build' >"$repo/platforms/swift/scripts/build-xcframework.sh"
  echo 'notes' >"$repo/docs/notes.md"
  printf 'build/\n' >"$repo/.gitignore"
  g init -q
  g add -A
  g commit -q -m init
  xcf="$repo/build/PolyjoseFFI.xcframework"
  mkdir -p "$xcf"
  stamp "commit: $(g rev-parse HEAD)"
}

stamp() { printf 'arm64_32: present\n%s\n' "$1" >"$xcf/polyjose-build.txt"; }

# expect <description> stale|fresh [<reason ERE>]
expect() {
  local what=$1 want=$2 pattern=${3:-} reason verdict
  run=$((run + 1))
  if reason=$(xcframework_stale "$repo" "$xcf"); then verdict=stale; else verdict=fresh; fi
  if [ "$verdict" = "$want" ] && { [ -z "$pattern" ] || printf '%s\n' "$reason" | grep -Eq -- "$pattern"; }; then
    echo "ok   - $what"
  else
    echo "FAIL - $what: $verdict (expected $want) reason \"$reason\" (expected /$pattern/)"
    failed=$((failed + 1))
  fi
}

new_repo
expect "a build at HEAD with a clean tree is fresh" fresh '^$'

new_repo
echo notes2 >"$repo/docs/notes.md"
g commit -q -am "docs only"
echo dirty >>"$repo/docs/notes.md"
expect "a changed or dirty file that is not an input keeps it fresh" fresh '^$'

new_repo
echo lock2 >"$repo/Cargo.lock"
g commit -q -am "one Cargo.lock line"
expect "an input changed in a later commit is stale" stale '^inputs changed since the build commit [0-9a-f]+: Cargo\.lock$'

new_repo
echo 'pub fn g() {}' >>"$repo/crates/polyjose/src/lib.rs"
expect "an uncommitted change in an input is stale" stale '^uncommitted changes in the inputs: crates/polyjose/src/lib\.rs$'

new_repo
echo new >"$repo/bindings/ffi/new.rs"
expect "an untracked file in an input is stale" stale '^uncommitted changes in the inputs: bindings/ffi/new\.rs$'

new_repo
rm "$xcf/polyjose-build.txt"
expect "a missing stamp is stale" stale 'polyjose-build\.txt is missing$'

new_repo
rm -rf "$xcf"
expect "a missing XCFramework is stale" stale '^the XCFramework is missing$'

new_repo
stamp "commit: unknown"
expect "an unknown commit is stale" stale '^polyjose-build\.txt records no commit$'

new_repo
stamp "deployment targets: macOS 13.0"
expect "a stamp without a commit line is stale" stale '^polyjose-build\.txt records no commit$'

new_repo
stamp "commit: 0123456789abcdef0123456789abcdef01234567"
expect "a commit git does not know is stale" stale 'which git does not know$'

new_repo
stamp "commit: $(g rev-parse HEAD) (uncommitted changes)"
expect "a build from uncommitted changes is stale" stale '^the XCFramework was built from uncommitted changes at '

echo "$run checks, $failed failed"
completed=1; exit "$((failed > 0))"
