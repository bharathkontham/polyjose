#!/usr/bin/env bash
# One entry of the host-natives matrix of .github/workflows/binding-android.yml (feature 0008 T05;
# ADR 0033 §4, §5; ADR 0034 §2; ADR 0037 §1). Runs locally the same way.
#
#   bindings/kotlin/scripts/ci-host-natives.sh <host-prefix>
#
# <host-prefix> is this machine's JNA resource prefix (darwin-aarch64, linux-x86-64, linux-aarch64
# or win32-x86-64); any other value is a usage error, so a matrix entry on the wrong runner fails
# instead of uploading a library under the wrong name. Each of the jar's four libraries is built
# and tested on its own native runner; nothing is cross-built (ADR 0073 §2).
#
# 1. `./gradlew --no-daemon :polyjose-jvm:test`: builds polyjose-ffi for this host (the root
#    project's cargoHostBuild, release profile, `-p polyjose-ffi`) and runs the JVM suite through
#    JNA with that library, including the conformance runner `jvm` (ADR 0033 §5).
# 2. The results: target/conformance/jvm.json is renamed target/conformance/jvm-<prefix>.json, the
#    CI matrix name that parity compares as runner `jvm` (ADR 0034 §2). It must be runner jvm's
#    document with a vectors_digest (ADR 0060) and no failed vector. Copied to
#    <out>/conformance-jvm-<prefix>/.
# 3. The library: the file the tests loaded (build/jvm-natives/<prefix>/<library>), checked with
#    `file` to be this platform's, is copied to <out>/jvm-natives-<prefix>/<library>.
#
# <out> is $POLYJOSE_CI_OUT, default target/ci at the repository root (ci-lib.sh). Stale outputs of
# this prefix are removed first, so nothing of an earlier run is uploaded.
#
# Exit status: 0 everything above passed; 1 a build, a test or a check failed; 2 usage.
set -uo pipefail
# shellcheck source=ci-lib.sh source-path=SCRIPTDIR
. "$(dirname "$0")/ci-lib.sh"

usage() { echo "usage: ${0##*/} <host-prefix>   (prefixes: $ci_prefixes)" >&2; exit 2; }
fail() { echo "ci-host-natives: FAILED: $*"; exit 1; }

[ $# -eq 1 ] || usage
host=$1
ci_is_prefix "$host" || usage
this=$(ci_host_prefix)
[ "$host" = "$this" ] || ci_die "$host is not this machine's prefix (${this:-none: $(uname -s) $(uname -m)})"
command -v file >/dev/null 2>&1 || ci_die "file(1) not found (the library architecture check needs it)"

results=$ci_repo/target/conformance
rm -f "$results/jvm.json" "$results/jvm-$host.json"
rm -rf "$ci_out/jvm-natives-$host"
rm -rf "$ci_out/conformance-jvm-$host"

# check_library <prefix> <file>: the file exists and `file` names that platform's format.
check_library() {
  [ -f "$2" ] || fail "no $1 library at $2"
  local kind
  kind=$(file -b "$2")
  echo "$kind" | grep -Eq "$(ci_file_pattern "$1")" || fail "$2 is not a $1 library: $kind"
  echo "ci-host-natives: $1/$(basename "$2"): $(wc -c <"$2" | tr -d ' ') bytes, sha256 $(ci_sha256 "$2") ($kind)"
}

echo "==> ci-host-natives: ./gradlew --no-daemon :polyjose-jvm:test ($host)"
(cd "$ci_android" && ./gradlew --no-daemon :polyjose-jvm:test) || fail ":polyjose-jvm:test on $host"

problem=$(ci_check_results "$results/jvm.json" jvm) || fail "$problem"
mv "$results/jvm.json" "$results/jvm-$host.json" || fail "cannot rename $results/jvm.json"
ci_copy "$results/jvm-$host.json" "$ci_out/conformance-jvm-$host" ||
  fail "cannot copy the results to $ci_out/conformance-jvm-$host"
echo "ci-host-natives: wrote target/conformance/jvm-$host.json (runner jvm)"

lib=$(ci_library_of "$host")
tested=$ci_android/build/jvm-natives/$host/$lib
check_library "$host" "$tested"
ci_copy "$tested" "$ci_out/jvm-natives-$host" ||
  fail "cannot copy $tested to $ci_out/jvm-natives-$host"

echo "ci-host-natives: $host: PASS (tested and built); outputs in $ci_out"
