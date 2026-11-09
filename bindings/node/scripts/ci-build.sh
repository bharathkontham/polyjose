#!/usr/bin/env bash
# Builds and tests one @polyjose/node prebuild (feature 0007 T05, feature 0017; ADR 0031 §2,
# ADR 0034 §2, ADR 0037 §1). .github/workflows/binding-node.yml runs it once per napi target on a native runner;
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
#   0. `cargo metadata --locked` first, so a Cargo.lock that does not match the manifests fails
#      fast instead of being re-resolved on the runner (review-code.md SF-3); every cargo and napi
#      build and test below passes --locked too (test.sh, scripts/build.sh), as ci.yml does;
#   1. checks <target> and <label>, and that <target> is this host: Node's platform and arch, and
#      on Linux its libc (glibc or musl, as src/backend.ts detectPlatform decides);
#   2. test.sh, the whole package suite (TypeScript only, npm ci, build, API names, the rust-core
#      reference, node --test), with
#        CARGO_BUILD_TARGET=<target>          napi build and cargo both read it, so the addon and
#                                             the reference run are built for exactly <target>
#        POLYJOSE_CONFORMANCE_SUFFIX=<label>  test/conformance.test.ts writes node-<label>.json
#      and, for the two *-pc-windows-msvc targets, RUSTFLAGS with -C target-feature=+crt-static
#      (review-code.md SF-1);
#   3. checks that target/conformance/node-<label>.json was written, for msvc that the addon
#      imports no VCRUNTIME*.dll or MSVCP*.dll (python3 -I scripts/pe-imports.py --deny-crt), and
#      for the two *-unknown-linux-gnu targets that it requires no GLIBC_ symbol version above the
#      floor, 2.28 (scripts/glibc-floor.sh; review-code.md SF-2);
#   4. leaves the tested addon, polyjose.<platform>.node, in bindings/node: binding-node.yml uploads
#      it as artifact addon-<target>, and its pack-main job packs all eight into the one
#      @polyjose/node tarball (scripts/pack-main.sh). Since feature 0017 there is no platform
#      package to pack here.
#
# No packing and no publishing. Publishing is the human-approved release (ADR 0011, Gate 3): this script must not
# call npm's or napi's publishing commands, and test/ci.test.ts greps it to keep it so.
# Runs on macOS /bin/bash 3.2, Linux bash (Alpine too) and Git Bash on Windows; exits non-zero on
# any failure.
set -euo pipefail
cd "$(dirname "$0")/.."

die() { echo "ci-build.sh: $*" >&2; exit 1; }
[ $# -ge 1 ] && [ $# -le 2 ] || { echo "usage: scripts/ci-build.sh <target> [<label>]" >&2; exit 2; }
target=$1
label=${2:-$1}

# The committed Cargo.lock, unchanged, or nothing runs (SF-3). test/ci.test.ts checks that this is
# the first tool the script runs.
cargo metadata --locked --format-version 1 >/dev/null

# <Rust target>) platform=<napi --platform suffix>. test/ci.test.ts checks that this table is
# exactly package.json napi.targets, the addons package.json files lists, and scripts/pack-main.sh's.
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
# The platform src/backend.ts (detectPlatform) picks on this host: <platform>-<arch>, plus -gnu or
# -musl on Linux and -msvc on Windows. On Linux, musl is decided exactly as backend.ts decides it,
# in its order (review-code.md N4), so this guard and the loader cannot disagree (for example on
# Alpine with gcompat): /usr/bin/ldd names musl or not; if it cannot be read, the process report
# (a glibc runtime version means glibc, else a libc.musl-/ld-musl- shared object means musl); with
# no report the host cannot be named, and this fails, as the loader refuses.
# test/ci.test.ts checks this order against src/backend.ts.
# shellcheck disable=SC2016 # the ${...} below are JavaScript template literals, not shell expansions
host=$(node -e '
const { platform, arch } = process;
function isMusl() {
  try {
    return require("fs").readFileSync("/usr/bin/ldd", "utf8").includes("musl");
  } catch {}
  let report = null;
  if (process.report && typeof process.report.getReport === "function") {
    process.report.excludeNetwork = true;
    report = process.report.getReport();
  }
  if (!report) {
    console.error("ci-build.sh: cannot tell glibc from musl (no /usr/bin/ldd, no process report)");
    process.exit(1);
  }
  if (report.header && report.header.glibcVersionRuntime) return false;
  return Array.isArray(report.sharedObjects) && report.sharedObjects.some((f) => f.includes("libc.musl-") || f.includes("ld-musl-"));
}
let name = `${platform}-${arch}`;
if (platform === "linux") name += isMusl() ? "-musl" : "-gnu";
if (platform === "win32") name += "-msvc";
process.stdout.write(name);
')
[ "$host" = "$platform" ] || die "$target ($platform) is not this host ($host); run it on a native $platform runner"

# The msvc addons link the C runtime statically (review-code.md SF-1). Rust's *-pc-windows-msvc
# targets link it dynamically (/MD) by default, so the addon would import VCRUNTIME140.dll, which
# comes from the VC++ Redistributable, not from Windows: official Node builds link their CRT
# statically and don't ship it, so the addon would not load on a clean machine, Server Core or a
# nanoserver container. napi-rs's project template sets the same flag in .cargo/config.toml, which
# this repository forbids (scripts/check-no-cargo-config.sh). napi build appends its own flags to
# RUSTFLAGS and always passes --target, so the flag reaches the target's crates only, never build
# scripts or proc macros. test.sh's rust-core reference run is built with it too.
crt_static=false
case $target in *-pc-windows-msvc) crt_static=true ;; esac
if [ "$crt_static" = true ]; then
  export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }-C target-feature=+crt-static"
fi

echo "==> @polyjose/node ci-build: $target ($platform), results node-$label.json"
CARGO_BUILD_TARGET=$target POLYJOSE_CONFORMANCE_SUFFIX=$label ./test.sh

results=../../target/conformance/node-$label.json
[ -f "$results" ] || die "$results was not written"

# The static CRT took effect: the addon imports no VCRUNTIME*.dll or MSVCP*.dll (SF-1). The
# reader, scripts/pe-imports.py (python3 standard library only), prints every imported DLL and
# fails closed on anything it cannot parse; test/ci.test.ts checks it on test/fixtures/pe/.
if [ "$crt_static" = true ]; then
  echo "==> @polyjose/node ci-build: polyjose.$platform.node imports no VC++ runtime DLL"
  python3 -I scripts/pe-imports.py --deny-crt "polyjose.$platform.node"
fi

# The glibc floor of the gnu addons (review-code.md SF-2, feature 0007 F04): the addon must
# require no GLIBC_ symbol version above 2.28, the floor the README states, or it would not load
# on the distributions the README lists (the loader then reports "Cannot find native binding").
# binding-node.yml builds these targets inside the manylinux_2_28 images, whose glibc is 2.28;
# this check fails any gnu build that needs more, for example one on the runner itself (glibc
# 2.39 there; a build on glibc 2.41 measured GLIBC_2.34). 2.28 is also Node 22's own Linux floor
# (Node's BUILDING.md: glibc >= 2.28), so no distribution that runs official Node 22 or later is
# left out. scripts/glibc-floor.sh reads readelf (or objdump) output, compares as integers and
# fails closed; test/ci.test.ts checks it on test/fixtures/glibc/. Skipped on every other target.
glibc_floor=2.28
glibc_check=false
case $target in *-unknown-linux-gnu) glibc_check=true ;; esac
if [ "$glibc_check" = true ]; then
  echo "==> @polyjose/node ci-build: polyjose.$platform.node requires glibc $glibc_floor at most"
  scripts/glibc-floor.sh "$glibc_floor" "polyjose.$platform.node"
fi

# The tested addon is what the pack-main job ships: it must be the only one in the tree and the
# one build.sh pinned (scripts/addon-hashes.sh), so the upload is exactly what the suite loaded.
addon=polyjose.$platform.node
left=$(find . -maxdepth 1 -name 'polyjose.*.node' -print | sed 's|^\./||' | LC_ALL=C sort | tr '\n' ' ')
[ "$left" = "$addon " ] || die "bindings/node holds $left, not only $addon"
pinned=$(node -p "require('./addon-sha256.json')['$platform']")
actual=$(node -p "require('crypto').createHash('sha256').update(require('fs').readFileSync('$addon')).digest('hex')")
[ "$pinned" = "$actual" ] || die "$addon has SHA-256 $actual, but addon-sha256.json pins $pinned"

echo "==> @polyjose/node ci-build: OK: $results, $addon ($(wc -c <"$addon" | tr -d ' ') bytes, SHA-256 $actual)"
