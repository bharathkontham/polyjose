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
#      for the host, so the tree ends in the same state as after test.sh's build. On an
#      Apple-silicon Mac without Rosetta the x86_64 addon is built but cannot be loaded; the
#      package test checks its tarball by contents only.
#   2. Each package is assembled in a temporary staging directory, never in the source tree:
#      - main: what `npm pack --dry-run` selects in bindings/node (package.json and its `files`),
#        the repository's LICENSE, and a THIRD-PARTY-NOTICES.txt written here: polyjose's MIT
#        license, @napi-rs/cli's MIT license (binding.cjs and binding.d.ts are generated from its
#        loader template), and the platform packages that carry the addon's crate notices. The
#        JS facade has no third-party code. The trailing `//# sourceMappingURL=` line tsc writes
#        is removed from each staged .js and .d.ts: the maps, and the .ts sources they point at,
#        are not shipped (ADR 0047, package.json `files`). The build in the tree keeps them.
#      - each darwin platform: npm/<platform>/package.json, the addon, the repository's LICENSE,
#        a short README.md written here, and THIRD-PARTY-NOTICES.txt from
#        scripts/third-party-notices.sh -p polyjose-node --target <triple> (ADR 0020 §4).
#   3. npm pack of each staged directory into dist/npm/, which is emptied first. npm pack writes
#      fixed timestamps into the tarball entries.
#   4. node --test dist/package.test.js (compiled by build.sh): file lists, contents, notices,
#      versions, and an offline install of the main and host tarballs into a temporary directory
#      with a temporary npm cache, which imports the package and round-trips a compact JWS.
#
# Packing only. Publishing is the human-approved release (ADR 0011, Gate 3): this script must not
# call npm's or napi's publishing commands, and the package test greps it to keep it so.
# Runs on macOS only; exits non-zero on any failure.
set -euo pipefail
cd "$(dirname "$0")/.."
pkg_dir=$(pwd -P)
repo=$(cd ../.. && pwd -P)
out=$pkg_dir/dist/npm
RULE=$(printf "%080d" 0 | tr 0 =) # the 80-column rule of scripts/third-party-notices.sh

[ "$(uname -s)" = Darwin ] || { echo "pack.sh: builds the darwin packages, so it runs on macOS only" >&2; exit 1; }
case $(uname -m) in
  arm64) host=aarch64-apple-darwin other=x86_64-apple-darwin ;;
  x86_64) host=x86_64-apple-darwin other=aarch64-apple-darwin ;;
  *) echo "pack.sh: unknown macOS architecture $(uname -m)" >&2; exit 1 ;;
esac
command -v python3 >/dev/null 2>&1 || { echo "pack.sh: python3 not found on PATH" >&2; exit 1; }

# "<npm/ directory> <Rust target>" for each package packed here.
platforms="darwin-arm64:aarch64-apple-darwin darwin-x64:x86_64-apple-darwin"

stage=$(mktemp -d "${TMPDIR:-/tmp}/polyjose-node-pack.XXXXXX")
trap 'rm -rf "$stage"' EXIT

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
pack() { # pack <staged directory>: npm pack it into dist/npm/
  (cd "$1" && npm pack --ignore-scripts --loglevel=error --pack-destination "$out" >/dev/null)
}

echo "==> @polyjose/node pack: stage and pack @polyjose/node $version"
main=$stage/node
mkdir "$main"
npm pack --dry-run --json --ignore-scripts --loglevel=error >"$stage/main-files.json"
python3 -I -c 'import json, sys
for f in json.load(open(sys.argv[1], encoding="utf-8"))[0]["files"]:
    print(f["path"])' "$stage/main-files.json" >"$stage/main-files.txt"
while IFS= read -r f; do
  mkdir -p "$main/$(dirname "$f")"
  cp "$f" "$main/$f"
done <"$stage/main-files.txt"
cp "$repo/LICENSE" "$main/LICENSE"
find "$main" -type f \( -name '*.js' -o -name '*.d.ts' \) -print | while IFS= read -r f; do
  sed '/^\/\/# sourceMappingURL=[^[:space:]]*\.map$/d' "$f" >"$f.tmp"
  mv "$f.tmp" "$f"
done

napi_cli=node_modules/@napi-rs/cli
napi_version=$(json_field "$napi_cli/package.json" version)
napi_license=$(json_field "$napi_cli/package.json" license)
[ "$napi_license" = MIT ] || { echo "pack.sh: @napi-rs/cli is $napi_license, not MIT; review its notice" >&2; exit 1; }
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
  for d in npm/*/; do
    d=${d%/}
    echo "@polyjose/node-${d#npm/}"
  done
  echo
  echo "Generated by bindings/node/scripts/pack.sh; do not edit."
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
pack "$main"

for entry in $platforms; do
  name=${entry%%:*}
  triple=${entry#*:}
  echo "==> @polyjose/node pack: stage and pack @polyjose/node-$name ($triple)"
  dir=$stage/$name
  mkdir "$dir"
  addon=polyjose.$name.node
  [ -f "$addon" ] || { echo "pack.sh: $addon was not built" >&2; exit 1; }
  cp "npm/$name/package.json" "$addon" "$dir/"
  cp "$repo/LICENSE" "$dir/LICENSE"
  cat >"$dir/README.md" <<EOF
# @polyjose/node-$name

The \`$triple\` native addon of [\`@polyjose/node\`](https://www.npmjs.com/package/@polyjose/node).
Install \`@polyjose/node\`, not this package: it loads this addon on this platform.

MIT; see \`LICENSE\`. \`THIRD-PARTY-NOTICES.txt\` lists the Rust crates compiled into the addon.
EOF
  "$repo/scripts/third-party-notices.sh" -p polyjose-node --target "$triple" -o "$dir/THIRD-PARTY-NOTICES.txt"
  pack "$dir"
done

echo "==> @polyjose/node pack: dist/npm/"
(cd "$out" && for t in *.tgz; do echo "    $t $(wc -c <"$t" | tr -d ' ') bytes"; done)

echo "==> @polyjose/node pack: node --test dist/package.test.js"
node --test --test-reporter=spec dist/package.test.js
