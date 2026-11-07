#!/usr/bin/env bash
# Builds, tests and packs one @polyjose/node prebuild (feature 0007 T05; ADR 0031 §2, ADR 0034 §2,
# ADR 0037 §1). .github/workflows/binding-node.yml runs it once per napi target on a native runner;
# locally it runs for the host (aarch64-apple-darwin on the owner's Mac).
#
# Usage: scripts/ci-build.sh <target> [<label>]
#   target  a Rust target of package.json `napi.targets` (the table below). It must be this host's
#           platform: the suite loads the addon it builds, so a cross-built addon cannot be tested
#           here (an x86_64-apple-darwin addon does not load on an Apple-silicon Mac without
#           Rosetta).
#   label   the results-file suffix (default: <target>), a CI matrix label of ADR 0034 §2: the
#           file is target/conformance/node-<label>.json and its `runner` stays `node`. The
#           Node-version runs pass x86_64-unknown-linux-gnu-node<N>, so each writes its own file.
#
# Steps:
#   1. checks <target> and <label>, and that <target> is this host: Node's platform and arch, and
#      on Linux its libc (glibc or musl, as the napi loader decides);
#   2. test.sh, the whole package suite (TypeScript only, npm ci, build, API names, the rust-core
#      reference, node --test), with
#        CARGO_BUILD_TARGET=<target>          napi build and cargo both read it, so the addon and
#                                             the reference run are built for exactly <target>
#        POLYJOSE_CONFORMANCE_SUFFIX=<label>  test/conformance.test.ts writes node-<label>.json
#   3. checks that target/conformance/node-<label>.json was written;
#   4. scripts/pack-platform.sh <platform> <target> dist/npm/ (shared with scripts/pack.sh):
#      dist/npm/polyjose-node-<platform>-<version>.tgz, then checks its file list.
#
# Packing only. Publishing is the human-approved release (ADR 0011, Gate 3): this script must not
# call npm's or napi's publishing commands, and test/ci.test.ts greps it to keep it so.
# Runs on macOS /bin/bash 3.2, Linux bash (Alpine too) and Git Bash on Windows; exits non-zero on
# any failure.
set -euo pipefail
cd "$(dirname "$0")/.."

die() { echo "ci-build.sh: $*" >&2; exit 1; }
[ $# -ge 1 ] && [ $# -le 2 ] || { echo "usage: scripts/ci-build.sh <target> [<label>]" >&2; exit 2; }
target=$1
label=${2:-$1}

# <Rust target>) platform=<npm/ directory and napi --platform suffix>. test/ci.test.ts checks that
# this table is exactly package.json napi.targets and npm/*/.
case $target in
  x86_64-apple-darwin) platform=darwin-x64 ;;
  aarch64-apple-darwin) platform=darwin-arm64 ;;
  x86_64-unknown-linux-gnu) platform=linux-x64-gnu ;;
  aarch64-unknown-linux-gnu) platform=linux-arm64-gnu ;;
  x86_64-unknown-linux-musl) platform=linux-x64-musl ;;
  aarch64-unknown-linux-musl) platform=linux-arm64-musl ;;
  x86_64-pc-windows-msvc) platform=win32-x64-msvc ;;
  aarch64-pc-windows-msvc) platform=win32-arm64-msvc ;;
  *) die "unknown target '$target' (not in package.json napi.targets)" ;;
esac
# The shared runner's rule for a suffix (bindings/js/conformance/node-main.ts): never a path.
[[ $label =~ ^[a-z0-9][a-z0-9_.-]*$ ]] || die "label '$label' is not a CI target label ([a-z0-9][a-z0-9_.-]*)"

command -v node >/dev/null 2>&1 || die "node not found on PATH"
# The platform the napi loader (binding.cjs) picks on this host: <platform>-<arch>, plus -gnu or
# -musl on Linux (a glibc runtime version in the process report means glibc) and -msvc on Windows.
host=$(node -e '
const { platform, arch } = process;
let name = `${platform}-${arch}`;
if (platform === "linux") name += process.report.getReport().header.glibcVersionRuntime ? "-gnu" : "-musl";
if (platform === "win32") name += "-msvc";
process.stdout.write(name);
')
[ "$host" = "$platform" ] || die "$target ($platform) is not this host ($host); run it on a native $platform runner"

echo "==> @polyjose/node ci-build: $target ($platform), results node-$label.json"
CARGO_BUILD_TARGET=$target POLYJOSE_CONFORMANCE_SUFFIX=$label ./test.sh

results=../../target/conformance/node-$label.json
[ -f "$results" ] || die "$results was not written"

echo "==> @polyjose/node ci-build: pack @polyjose/node-$platform"
scripts/pack-platform.sh "$platform" "$target" dist/npm
version=$(node -p 'require("./package.json").version')
tarball=dist/npm/polyjose-node-$platform-$version.tgz
[ -f "$tarball" ] || die "$tarball was not packed"
expected=$(printf '%s\n' package/LICENSE package/README.md package/THIRD-PARTY-NOTICES.txt \
  package/package.json "package/polyjose.$platform.node")
actual=$(tar -tzf "$tarball" | LC_ALL=C sort)
[ "$actual" = "$expected" ] || die "$tarball holds:
$actual
expected:
$expected"

echo "==> @polyjose/node ci-build: OK: $results, $tarball ($(wc -c <"$tarball" | tr -d ' ') bytes)"
