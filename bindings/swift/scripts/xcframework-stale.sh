# shellcheck shell=bash
# Sourced by platforms/swift/test.sh (and its test, test-xcframework-stale.sh): decides whether
# platforms/swift/build/PolyjoseFFI.xcframework is stale, i.e. built from other Rust inputs than
# the checkout's, so that test.sh never tests an old library. Parity cannot catch that: an old
# library reports the same polyjose version and the same vectors digest (ADR 0060).
#
# xcframework_stale <repository root> <XCFramework directory>
#   Prints the reason and returns 0 when the XCFramework must be rebuilt; prints nothing and
#   returns 1 when it is fresh. It is stale when any of these holds:
#     - the XCFramework, or its polyjose-build.txt, is missing;
#     - polyjose-build.txt has no `commit:` line, or its commit is `unknown`, or not a commit git
#       knows;
#     - polyjose-build.txt says the build was made from uncommitted changes (its commit does not
#       describe the inputs then);
#     - `git diff --quiet <commit> HEAD -- <inputs>` fails: an input changed in a later commit;
#     - the working tree has uncommitted changes (staged, unstaged or untracked) in the inputs.
#   The inputs are what build-xcframework.sh builds from (XCFRAMEWORK_INPUTS).
#
# Bash 3.2 compatible (macOS /bin/bash). Needs git.

XCFRAMEWORK_INPUTS="Cargo.toml Cargo.lock rust-toolchain.toml crates bindings platforms/swift/nightly-toolchain platforms/swift/scripts/build-xcframework.sh"

xcframework_stale() {
  local root=$1 xcframework=$2 stamp line commit changed dirty
  # shellcheck disable=SC2086 # the input list is split on purpose
  set -- $XCFRAMEWORK_INPUTS
  stamp="$xcframework/polyjose-build.txt"
  if [ ! -d "$xcframework" ]; then echo "the XCFramework is missing"; return 0; fi
  if [ ! -f "$stamp" ]; then echo "$stamp is missing"; return 0; fi
  line=$(sed -n 's/^commit: //p' "$stamp" | head -n 1)
  commit=${line%% *}
  if [ -z "$commit" ] || [ "$commit" = unknown ]; then
    echo "polyjose-build.txt records no commit"; return 0
  fi
  if ! git -C "$root" cat-file -e "$commit^{commit}" 2>/dev/null; then
    echo "polyjose-build.txt records commit $commit, which git does not know"; return 0
  fi
  case $line in *"(uncommitted changes)"*)
    echo "the XCFramework was built from uncommitted changes at $commit"; return 0 ;;
  esac
  if ! git -C "$root" diff --quiet "$commit" HEAD -- "$@"; then
    changed=$(git -C "$root" diff --name-only "$commit" HEAD -- "$@" | head -n 5 | tr '\n' ' ')
    echo "inputs changed since the build commit $commit: ${changed% }"; return 0
  fi
  dirty=$(git -C "$root" status --porcelain --untracked-files=normal -- "$@" | head -n 5 | cut -c4- | tr '\n' ' ')
  if [ -n "$dirty" ]; then
    echo "uncommitted changes in the inputs: ${dirty% }"; return 0
  fi
  return 1
}
