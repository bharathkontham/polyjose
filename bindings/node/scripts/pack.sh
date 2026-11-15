#!/usr/bin/env bash
# Packs @polyjose/node with the addon an Apple-silicon Mac builds into dist/npm/ (feature 0007 T04,
# feature 0017; ADR 0031 §2 and §4 as superseded by ADR 0066, ADR 0020 §4, ADR 0011, ADR 0073 §2),
# and checks it with test/package.test.ts:
#   dist/npm/polyjose-node-<version>.tgz   facade, entry, backend, and the aarch64-apple-darwin addon
# The release package holds all seven addons: binding-node.yml's pack-main job packs it from the
# prebuild jobs' addons with the same script.
#
# The macOS addon is arm64 only (ADR 0073 §2), so this script runs on an Apple-silicon Mac only.
# On an x86_64 macOS host (an Intel Mac, or a shell under Rosetta 2) it exits non-zero before it
# builds anything, rather than pack a package without a macOS addon for its own host.
#
# Steps:
#   1. scripts/build.sh for the host, aarch64-apple-darwin.
#   2. dist/npm/ is emptied, then scripts/pack-main.sh dist/npm/ <the darwin-arm64 addon> (shared
#      with binding-node.yml's pack-main job) stages the package in a temporary directory, never
#      in the source tree, and npm packs it: the package.json `files` of the build, without source
#      maps, the addon, an addon-sha256.json (feature 0007 F07) over exactly that addon, the
#      repository's LICENSE and a THIRD-PARTY-NOTICES.txt for aarch64-apple-darwin. On Linux or
#      Windows this local tarball refuses to load: it has no addon or pin for them.
#   3. node --test dist/package.test.js (compiled by build.sh): file list, contents, notices,
#      versions, and an offline install of the tarball into a temporary directory with a
#      temporary npm cache, which imports the package and round-trips a compact JWS.
#   4. the script checks that the host addon is the only one in bindings/node: the tree ends as
#      test.sh's build leaves it, so test.sh passes right after (feature 0007 F03, F07).
#
# Packing only. Publishing is the human-approved release (ADR 0011, Gate 3): this script must not
# call npm's or napi's publishing commands, and the package test greps it to keep it so.
# Runs on macOS only; exits non-zero on any failure.
set -euo pipefail
cd "$(dirname "$0")/.."
pkg_dir=$(pwd -P)
out=$pkg_dir/dist/npm

[ "$(uname -s)" = Darwin ] || { echo "pack.sh: builds the macOS package, so it runs on macOS only" >&2; exit 1; }
case $(uname -m) in
  arm64) host_addon=polyjose.darwin-arm64.node ;;
  x86_64)
    echo "pack.sh: the macOS package is arm64 only (ADR 0073 §2): run it on an Apple-silicon Mac, not on an x86_64 host or under Rosetta 2" >&2
    exit 1
    ;;
  *) echo "pack.sh: unknown macOS architecture $(uname -m)" >&2; exit 1 ;;
esac
command -v python3 >/dev/null 2>&1 || { echo "pack.sh: python3 not found on PATH" >&2; exit 1; }

# Fail closed (0013 F10): /bin/bash 3.2 runs an EXIT trap with $? = 0 after a syntax error, so an
# exit before the last line, which sets the sentinel, becomes status 2 (see scripts/test-all.sh).
completed=""
# shellcheck disable=SC2154 # rc is assigned by the trap itself (rc=$?)
trap 'rc=$?; [ -n "${completed:-}" ] || [ "$rc" -ne 0 ] || { echo "pack.sh: stopped before its last statement (a syntax error?); failing closed" >&2; rc=2; }; exit "$rc"' EXIT

json_field() { # json_field <file> <key>...: prints the string at that key path
  python3 -I -c 'import json, sys
v = json.load(open(sys.argv[1], encoding="utf-8"))
for k in sys.argv[2:]:
    v = v[k]
print(v)' "$@"
}

echo "==> @polyjose/node pack: build aarch64-apple-darwin (host)"
scripts/build.sh

version=$(json_field package.json version)
rm -rf "$out"
mkdir -p "$out"

echo "==> @polyjose/node pack: stage and pack @polyjose/node $version (scripts/pack-main.sh)"
scripts/pack-main.sh "$out" "$pkg_dir/$host_addon"

echo "==> @polyjose/node pack: dist/npm/"
(cd "$out" && for t in *.tgz; do echo "    $t $(wc -c <"$t" | tr -d ' ') bytes"; done)

echo "==> @polyjose/node pack: node --test dist/package.test.js"
node --test --test-reporter=spec dist/package.test.js

# The tree ends as test.sh's build leaves it: the host addon is the only one.
left=$(find "$pkg_dir" -maxdepth 1 -name 'polyjose.*.node' -print | sed 's|.*/||' | LC_ALL=C sort | tr '\n' ' ')
[ "$left" = "$host_addon " ] || { echo "pack.sh: bindings/node holds $left, not only $host_addon" >&2; exit 1; }
echo "==> @polyjose/node pack: OK (bindings/node holds only $host_addon)"
completed=1; exit 0
