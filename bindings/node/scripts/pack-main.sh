#!/usr/bin/env bash
# Packs @polyjose/node, polyjose's one npm package for Node.js, into <out-dir> with the given
# prebuilt addons inside it and an addon-sha256.json that pins exactly those addons (feature 0017;
# feature 0007 F07; ADR 0031 §2 and §4 as superseded by ADR 0066, ADR 0020 §4, ADR 0011). Shared
# by scripts/pack.sh (the two darwin addons a Mac builds) and by .github/workflows/binding-node.yml's
# pack-main job (the eight addons of the prebuild jobs, --all-platforms: the release package), so
# the local and the release package are packed the same way.
#
# Usage: scripts/pack-main.sh [--all-platforms] <out-dir> <polyjose.<platform>.node>...
#   --all-platforms  require an addon for every polyjose.<platform>.node that package.json
#                    `files` lists (the eight shipped targets)
#
# The package's JavaScript must already be built (scripts/build.sh: facade/, index.js, backend.js
# and their declarations). Steps:
#   1. each addon is checked: its file name is polyjose.<platform>.node for a platform whose addon
#      package.json `files` lists, at most once per platform;
#   2. the package is staged in a temporary directory, never in the source tree: what
#      `npm pack --dry-run` selects in bindings/node (package.json and its `files`), except any
#      addon and addon-sha256.json of the tree (a tree build is never shipped), plus the given
#      addons, the repository's LICENSE, and:
#      - addon-sha256.json from scripts/addon-hashes.sh over the staged addons, so the map pins
#        exactly the bytes users install (src/backend.ts refuses any other);
#      - THIRD-PARTY-NOTICES.txt from scripts/third-party-notices.sh -p polyjose-node with one
#        --target per staged addon: the union of the crates compiled into them (ADR 0020 §4; the
#        script's multi-target mode, feature 0013 F14). The JavaScript is polyjose's own code
#        (facade, entry, backend) and carries no third-party code: no napi-rs loader is shipped
#        since feature 0017. `cargo fetch --locked` first, since the notices read the crate
#        sources of every target offline;
#      The trailing `//# sourceMappingURL=` line tsc writes is removed from each staged .js and
#      .d.ts: the maps, and the .ts sources they point at, are not shipped (ADR 0047). The build in
#      the tree keeps them;
#   3. npm pack of the staged directory into <out-dir>: polyjose-node-<version>.tgz (npm pack
#      writes fixed timestamps into the tarball entries), and its addon entries are checked
#      against the staged ones.
#
# Packing only. Publishing is the human-approved release (ADR 0011, Gate 3): this script must not
# call npm's or napi's publishing commands, and test/package.test.ts greps it to keep it so.
# Runs on macOS /bin/bash 3.2 and Linux bash; exits non-zero on any failure.
set -euo pipefail
cd "$(dirname "$0")/.."
repo=$(cd ../.. && pwd -P)

usage() { echo "usage: scripts/pack-main.sh [--all-platforms] <out-dir> <polyjose.<platform>.node>..." >&2; exit 2; }
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

# <napi platform>) the Rust target its addon is built for. test/ci.test.ts checks that this table
# is scripts/ci-build.sh's, package.json napi.targets and the addons of package.json files.
triple_of() {
  case $1 in
    darwin-x64) echo x86_64-apple-darwin ;;
    darwin-arm64) echo aarch64-apple-darwin ;;
    linux-x64-gnu) echo x86_64-unknown-linux-gnu ;;
    linux-arm64-gnu) echo aarch64-unknown-linux-gnu ;;
    linux-x64-musl) echo x86_64-unknown-linux-musl ;;
    linux-arm64-musl) echo aarch64-unknown-linux-musl ;;
    win32-x64-msvc) echo x86_64-pc-windows-msvc ;;
    win32-arm64-msvc) echo aarch64-pc-windows-msvc ;;
    *) return 1 ;;
  esac
}

for f in index.js backend.js facade; do
  [ -e "$f" ] || die "$f is missing: run scripts/build.sh first"
done
version=$(json_field package.json version)
# The shipped platforms: the polyjose.<platform>.node entries of package.json files.
platforms=$(python3 -I -c 'import json, re
for f in json.load(open("package.json", encoding="utf-8"))["files"]:
    m = re.fullmatch(r"polyjose\.([a-z0-9-]+)\.node", f)
    if m:
        print(m.group(1))')
[ -n "$platforms" ] || die "package.json files lists no polyjose.<platform>.node"

stage=$(mktemp -d "${TMPDIR:-/tmp}/polyjose-node-main.XXXXXX")
# Fail closed (0013 F10): /bin/bash 3.2 runs an EXIT trap with $? = 0 after a syntax error, so an
# exit before the last line, which sets the sentinel, becomes status 2 (see scripts/test-all.sh).
completed=""
# shellcheck disable=SC2154 # rc is assigned by the trap itself (rc=$?)
trap 'rc=$?; rm -rf "$stage"; [ -n "${completed:-}" ] || [ "$rc" -ne 0 ] || { echo "pack-main.sh: stopped before its last statement (a syntax error?); failing closed" >&2; rc=2; }; exit "$rc"' EXIT

echo "==> @polyjose/node pack-main: stage @polyjose/node $version"
main=$stage/node
mkdir "$main"
npm pack --dry-run --json --ignore-scripts --loglevel=error >"$stage/main-files.json"
python3 -I -c 'import json, sys
for f in json.load(open(sys.argv[1], encoding="utf-8"))[0]["files"]:
    print(f["path"])' "$stage/main-files.json" >"$stage/main-files.txt"
while IFS= read -r f; do
  case $f in addon-sha256.json | polyjose.*.node) continue ;; esac
  mkdir -p "$main/$(dirname "$f")"
  cp "$f" "$main/$f"
done <"$stage/main-files.txt"

echo "==> @polyjose/node pack-main: $# addons"
seen=" "
targets=()
for addon in "$@"; do
  base=${addon##*/}
  platform=${base#polyjose.}
  platform=${platform%.node}
  [ "$base" = "polyjose.$platform.node" ] || die "$base is not polyjose.<platform>.node"
  printf '%s\n' "$platforms" | grep -xF "$platform" >/dev/null || die "$base: '$platform' is not a shipped platform ($(printf '%s\n' "$platforms" | tr '\n' ' '))"
  case $seen in *" $platform "*) die "two addons for $platform" ;; esac
  seen="$seen$platform "
  [ -f "$addon" ] || die "$addon not found"
  triple=$(triple_of "$platform") || die "no Rust target for $platform"
  targets+=(--target "$triple")
  cp "$addon" "$main/$base"
  echo "    $platform ($triple)"
done
if [ "$all" -eq 1 ]; then
  for p in $platforms; do
    case $seen in *" $p "*) ;; *) die "--all-platforms: no addon for $p" ;; esac
  done
fi

echo "==> @polyjose/node pack-main: addon-sha256.json (scripts/addon-hashes.sh over the staged addons)"
staged=()
for p in $seen; do staged+=("$main/polyjose.$p.node"); done
scripts/addon-hashes.sh "$main/addon-sha256.json" "${staged[@]}"
cp "$repo/LICENSE" "$main/LICENSE"
find "$main" -type f \( -name '*.js' -o -name '*.d.ts' \) -print | while IFS= read -r f; do
  sed '/^\/\/# sourceMappingURL=[^[:space:]]*\.map$/d' "$f" >"$f.tmp"
  mv "$f.tmp" "$f"
done

echo "==> @polyjose/node pack-main: THIRD-PARTY-NOTICES.txt (scripts/third-party-notices.sh ${targets[*]})"
(cd "$repo" && cargo fetch --locked --quiet)
"$repo/scripts/third-party-notices.sh" -p polyjose-node "${targets[@]}" -o "$main/THIRD-PARTY-NOTICES.txt"

rm -f "$out/polyjose-node-$version.tgz"
(cd "$main" && npm pack --ignore-scripts --loglevel=error --pack-destination "$out" >/dev/null)
tgz=$out/polyjose-node-$version.tgz
[ -f "$tgz" ] || die "npm pack wrote no $tgz"
want=$(for p in $seen; do echo "package/polyjose.$p.node"; done | LC_ALL=C sort)
have=$(tar -tzf "$tgz" | grep -E '^package/polyjose\.[a-z0-9-]+\.node$' | LC_ALL=C sort || true)
[ "$have" = "$want" ] || die "$tgz holds the addons:
$have
expected:
$want"
echo "==> @polyjose/node pack-main: OK: $tgz ($(wc -c <"$tgz" | tr -d ' ') bytes; $# addons, pinned in addon-sha256.json)"
completed=1; exit 0
