#!/usr/bin/env bash
# Packs the main package, @polyjose/node, into <out-dir> with an addon-sha256.json that pins the
# addons of the given platform tarballs (feature 0007 F07, feature 0012 H3; ADR 0031 §2 and §4,
# ADR 0020 §4, ADR 0011). Shared by scripts/pack.sh (the two darwin tarballs it packs) and by
# .github/workflows/binding-node.yml's pack-main job (all eight prebuilt tarballs, --all-platforms),
# so the local and the release main package are packed the same way.
#
# Usage: scripts/pack-main.sh [--all-platforms] <out-dir> <polyjose-node-<platform>-<version>.tgz>...
#   --all-platforms  require a tarball for every npm/<platform>/ (the release main package)
#
# The package's JavaScript must already be built (scripts/build.sh: facade/, index.js, backend.js,
# binding.cjs and their declarations). Steps:
#   1. each tarball is checked: its name is polyjose-node-<platform>-<version>.tgz for a
#      published platform (npm/*/) and package.json's version, at most once per platform, and its
#      package/package.json names @polyjose/node-<platform> at that version; its
#      package/polyjose.<platform>.node is extracted;
#   2. scripts/addon-hashes.sh writes addon-sha256.json over exactly those extracted addons, so the
#      map pins the bytes users install from the platform packages, never a tree build;
#   3. the main package is staged in a temporary directory, never in the source tree: what
#      `npm pack --dry-run` selects in bindings/node (package.json and its `files`), with the
#      generated addon-sha256.json in place of the tree's, the repository's LICENSE, and a
#      THIRD-PARTY-NOTICES.txt written here: polyjose's MIT license, @napi-rs/cli's MIT license
#      (binding.cjs and binding.d.ts are generated from its loader template), and the platform
#      packages that carry the addon's crate notices. The JS facade has no third-party code. The
#      trailing `//# sourceMappingURL=` line tsc writes is removed from each staged .js and .d.ts:
#      the maps, and the .ts sources they point at, are not shipped (ADR 0047). The build in the
#      tree keeps them;
#   4. npm pack of the staged directory into <out-dir>: polyjose-node-<version>.tgz. npm pack
#      writes fixed timestamps into the tarball entries.
#
# Packing only. Publishing is the human-approved release (ADR 0011, Gate 3): this script must not
# call npm's or napi's publishing commands, and test/package.test.ts greps it to keep it so.
# Runs on macOS /bin/bash 3.2 and Linux bash; exits non-zero on any failure.
set -euo pipefail
cd "$(dirname "$0")/.."
repo=$(cd ../.. && pwd -P)
RULE=$(printf "%080d" 0 | tr 0 =) # the 80-column rule of scripts/third-party-notices.sh

usage() { echo "usage: scripts/pack-main.sh [--all-platforms] <out-dir> <polyjose-node-<platform>-<version>.tgz>..." >&2; exit 2; }
die() { echo "pack-main.sh: $*" >&2; exit 1; }
all=0
if [ "${1:-}" = --all-platforms ]; then all=1; shift; fi
[ $# -ge 2 ] || usage
mkdir -p "$1"
out=$(cd "$1" && pwd -P)
shift
command -v python3 >/dev/null 2>&1 || die "python3 not found on PATH"

json_field() { # json_field <file> <key>...: prints the string at that key path
  python3 -I -c 'import json, sys
v = json.load(open(sys.argv[1], encoding="utf-8"))
for k in sys.argv[2:]:
    v = v[k]
print(v)' "$@"
}

for f in index.js backend.js binding.cjs binding.d.ts facade; do
  [ -e "$f" ] || die "$f is missing: run scripts/build.sh first"
done
version=$(json_field package.json version)
platforms=$(for d in npm/*/; do d=${d%/}; echo "${d#npm/}"; done)

stage=$(mktemp -d "${TMPDIR:-/tmp}/polyjose-node-main.XXXXXX")
# Fail closed (0013 F10): /bin/bash 3.2 runs an EXIT trap with $? = 0 after a syntax error, so an
# exit before the last line, which sets the sentinel, becomes status 2 (see scripts/test-all.sh).
completed=""
# shellcheck disable=SC2154 # rc is assigned by the trap itself (rc=$?)
trap 'rc=$?; rm -rf "$stage"; [ -n "${completed:-}" ] || [ "$rc" -ne 0 ] || { echo "pack-main.sh: stopped before its last statement (a syntax error?); failing closed" >&2; rc=2; }; exit "$rc"' EXIT

echo "==> @polyjose/node pack-main: the addons of $# platform tarballs"
addons=()
seen=" "
for tgz in "$@"; do
  base=${tgz##*/}
  platform=${base#polyjose-node-}
  platform=${platform%-"$version".tgz}
  [ "$base" = "polyjose-node-$platform-$version.tgz" ] || die "$base is not polyjose-node-<platform>-$version.tgz"
  printf '%s\n' "$platforms" | grep -xF "$platform" >/dev/null || die "$base: '$platform' is not a platform of npm/*/ ($(printf '%s\n' "$platforms" | tr '\n' ' '))"
  case $seen in *" $platform "*) die "two tarballs for $platform" ;; esac
  seen="$seen$platform "
  [ -f "$tgz" ] || die "$tgz not found"
  dir=$stage/addons/$platform
  mkdir -p "$dir"
  tar -xzf "$tgz" -C "$dir" package/package.json "package/polyjose.$platform.node" || die "$base has no package/polyjose.$platform.node"
  [ "$(json_field "$dir/package/package.json" name)" = "@polyjose/node-$platform" ] || die "$base: package.json name is not @polyjose/node-$platform"
  [ "$(json_field "$dir/package/package.json" version)" = "$version" ] || die "$base: package.json version is not $version"
  addons+=("$dir/package/polyjose.$platform.node")
done
if [ "$all" -eq 1 ]; then
  for p in $platforms; do
    case $seen in *" $p "*) ;; *) die "--all-platforms: no tarball for $p" ;; esac
  done
fi

echo "==> @polyjose/node pack-main: stage @polyjose/node $version"
main=$stage/node
mkdir "$main"
npm pack --dry-run --json --ignore-scripts --loglevel=error >"$stage/main-files.json"
python3 -I -c 'import json, sys
for f in json.load(open(sys.argv[1], encoding="utf-8"))[0]["files"]:
    print(f["path"])' "$stage/main-files.json" >"$stage/main-files.txt"
while IFS= read -r f; do
  [ "$f" != addon-sha256.json ] || continue
  mkdir -p "$main/$(dirname "$f")"
  cp "$f" "$main/$f"
done <"$stage/main-files.txt"
echo "==> @polyjose/node pack-main: addon-sha256.json (scripts/addon-hashes.sh over the tarballs' addons)"
scripts/addon-hashes.sh "$main/addon-sha256.json" "${addons[@]}"
cp "$repo/LICENSE" "$main/LICENSE"
find "$main" -type f \( -name '*.js' -o -name '*.d.ts' \) -print | while IFS= read -r f; do
  sed '/^\/\/# sourceMappingURL=[^[:space:]]*\.map$/d' "$f" >"$f.tmp"
  mv "$f.tmp" "$f"
done

napi_cli=node_modules/@napi-rs/cli
napi_version=$(json_field "$napi_cli/package.json" version)
napi_license=$(json_field "$napi_cli/package.json" license)
[ "$napi_license" = MIT ] || die "@napi-rs/cli is $napi_license, not MIT; review its notice"
{
  echo "THIRD-PARTY NOTICES"
  echo
  echo "Artifact: @polyjose/node $version"
  echo
  echo "This package is polyjose's JavaScript layer for Node.js: the shared facade (facade/), the"
  echo "package entry (index.js, backend.js), their TypeScript declarations, and the Node-API loader"
  echo "(binding.cjs, binding.d.ts). It contains no native code. The facade and the entry are"
  echo "polyjose's own code. binding.cjs and binding.d.ts are generated by @napi-rs/cli $napi_version"
  echo "from its loader template; its license is reproduced below."
  echo
  echo "The native addon, and the Rust crates compiled into it, ship in one platform package per"
  echo "target, each with its own THIRD-PARTY-NOTICES.txt:"
  for p in $platforms; do
    echo "@polyjose/node-$p"
  done
  echo
  echo "Generated by bindings/node/scripts/pack-main.sh; do not edit."
  echo
  echo "$RULE"
  echo "polyjose"
  echo "$RULE"
  echo "License: MIT"
  echo "Repository: $(json_field package.json repository url | sed 's/^git+//; s/\.git$//')"
  echo
  echo "--- License text: LICENSE ---"
  cat "$repo/LICENSE"
  echo
  echo "$RULE"
  echo "@napi-rs/cli $napi_version (generated binding.cjs and binding.d.ts)"
  echo "$RULE"
  echo "License: MIT"
  echo "Repository: $(json_field "$napi_cli/package.json" repository url | sed 's/^git+//; s/\.git$//')"
  echo
  echo "--- License text: LICENSE ---"
  cat "$napi_cli/LICENSE"
} >"$main/THIRD-PARTY-NOTICES.txt"

rm -f "$out/polyjose-node-$version.tgz"
(cd "$main" && npm pack --ignore-scripts --loglevel=error --pack-destination "$out" >/dev/null)
[ -f "$out/polyjose-node-$version.tgz" ] || die "npm pack wrote no $out/polyjose-node-$version.tgz"
echo "==> @polyjose/node pack-main: OK: $out/polyjose-node-$version.tgz ($(wc -c <"$out/polyjose-node-$version.tgz" | tr -d ' ') bytes; addon-sha256.json pins $# addons)"
completed=1; exit 0
