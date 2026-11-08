#!/usr/bin/env bash
# Packs the @polyjose/node tarballs a Mac can build into dist/npm/ (feature 0007 T04; ADR 0031 §2
# and §4, ADR 0020 §4, ADR 0011), and checks them with test/package.test.ts:
#   dist/npm/polyjose-node-<version>.tgz               the main package (facade, entry, loader)
#   dist/npm/polyjose-node-darwin-arm64-<version>.tgz  the aarch64-apple-darwin addon
#   dist/npm/polyjose-node-darwin-x64-<version>.tgz    the x86_64-apple-darwin addon
# The linux, musl and Windows platform tarballs are built and packed in CI (T05).
#
# Steps:
#   1. scripts/build.sh --target <the other darwin target> (cross-compiled), then scripts/build.sh
#      for the host. On an Apple-silicon Mac without Rosetta the x86_64 addon is built but cannot
#      be loaded; the package test checks its tarball by contents only.
#   2. dist/npm/ is emptied, then each package is assembled in a temporary staging directory,
#      never in the source tree, and npm packed into it (npm pack writes fixed timestamps):
#      - each darwin platform: scripts/pack-platform.sh <platform> <triple> dist/npm/ (shared with
#        scripts/ci-build.sh): npm/<platform>/package.json, the addon, the repository's LICENSE,
#        a short README.md, and THIRD-PARTY-NOTICES.txt from
#        scripts/third-party-notices.sh -p polyjose-node --target <triple> (ADR 0020 §4);
#      - main: scripts/pack-main.sh dist/npm/ <the two darwin tarballs> (shared with
#        binding-node.yml's pack-main job): the package.json `files` of the build, without source
#        maps, with LICENSE and THIRD-PARTY-NOTICES.txt, and an addon-sha256.json (feature 0007
#        F07) over the addons inside the two darwin tarballs and no other platform: on linux or
#        Windows this main tarball refuses to load. The release's main package is packed by the
#        same script over all eight prebuilt tarballs (feature 0012 H3).
#   3. node --test dist/package.test.js (compiled by build.sh): file lists, contents, notices,
#      versions, and an offline install of the main and host tarballs into a temporary directory
#      with a temporary npm cache, which imports the package and round-trips a compact JWS.
#   4. the cross-built addon is removed (also on failure), and the script checks that the host
#      addon is the only one left and rewrites addon-sha256.json for it alone: the tree ends as
#      test.sh's build leaves it, so test.sh passes right after (feature 0007 F03, F07).
#
# Packing only. Publishing is the human-approved release (ADR 0011, Gate 3): this script must not
# call npm's or napi's publishing commands, and the package test greps it to keep it so.
# Runs on macOS only; exits non-zero on any failure.
set -euo pipefail
cd "$(dirname "$0")/.."
pkg_dir=$(pwd -P)
out=$pkg_dir/dist/npm

[ "$(uname -s)" = Darwin ] || { echo "pack.sh: builds the darwin packages, so it runs on macOS only" >&2; exit 1; }
case $(uname -m) in
  arm64) host=aarch64-apple-darwin host_addon=polyjose.darwin-arm64.node other=x86_64-apple-darwin other_addon=polyjose.darwin-x64.node ;;
  x86_64) host=x86_64-apple-darwin host_addon=polyjose.darwin-x64.node other=aarch64-apple-darwin other_addon=polyjose.darwin-arm64.node ;;
  *) echo "pack.sh: unknown macOS architecture $(uname -m)" >&2; exit 1 ;;
esac
command -v python3 >/dev/null 2>&1 || { echo "pack.sh: python3 not found on PATH" >&2; exit 1; }

# "<npm/ directory> <Rust target>" for each package packed here.
platforms="darwin-arm64:aarch64-apple-darwin darwin-x64:x86_64-apple-darwin"

# The cross-built addon is needed only until the package test has compared its tarball with it.
# Left next to the host's, it would make the tree differ from test.sh's (one host addon, which
# test/loader.test.ts requires), so it is removed on every exit, success or failure.
cleanup() { rm -f "$pkg_dir/$other_addon"; }
# Fail closed (0013 F10): /bin/bash 3.2 runs an EXIT trap with $? = 0 after a syntax error, so an
# exit before the last line, which sets the sentinel, becomes status 2 (see scripts/test-all.sh).
completed=""
# shellcheck disable=SC2154 # rc is assigned by the trap itself (rc=$?)
trap 'rc=$?; cleanup; [ -n "${completed:-}" ] || [ "$rc" -ne 0 ] || { echo "pack.sh: stopped before its last statement (a syntax error?); failing closed" >&2; rc=2; }; exit "$rc"' EXIT

json_field() { # json_field <file> <key>...: prints the string at that key path
  python3 -I -c 'import json, sys
v = json.load(open(sys.argv[1], encoding="utf-8"))
for k in sys.argv[2:]:
    v = v[k]
print(v)' "$@"
}

echo "==> @polyjose/node pack: build $other (cross-compiled)"
scripts/build.sh --target "$other"
echo "==> @polyjose/node pack: build $host (host)"
scripts/build.sh

version=$(json_field package.json version)
rm -rf "$out"
mkdir -p "$out"

for entry in $platforms; do
  name=${entry%%:*}
  triple=${entry#*:}
  echo "==> @polyjose/node pack: stage and pack @polyjose/node-$name ($triple)"
  scripts/pack-platform.sh "$name" "$triple" "$out"
done

echo "==> @polyjose/node pack: stage and pack @polyjose/node $version (scripts/pack-main.sh)"
main_with=()
for entry in $platforms; do
  main_with+=("$out/polyjose-node-${entry%%:*}-$version.tgz")
done
scripts/pack-main.sh "$out" "${main_with[@]}"

echo "==> @polyjose/node pack: dist/npm/"
(cd "$out" && for t in *.tgz; do echo "    $t $(wc -c <"$t" | tr -d ' ') bytes"; done)

echo "==> @polyjose/node pack: node --test dist/package.test.js"
node --test --test-reporter=spec dist/package.test.js

# The tree ends as test.sh's build leaves it: the host addon is the only one.
cleanup
left=$(find "$pkg_dir" -maxdepth 1 -name 'polyjose.*.node' -print | sed 's|.*/||' | LC_ALL=C sort | tr '\n' ' ')
[ "$left" = "$host_addon " ] || { echo "pack.sh: bindings/node holds $left, not only $host_addon" >&2; exit 1; }
scripts/addon-hashes.sh addon-sha256.json "$host_addon"
echo "==> @polyjose/node pack: OK (bindings/node holds only $host_addon)"
completed=1; exit 0
