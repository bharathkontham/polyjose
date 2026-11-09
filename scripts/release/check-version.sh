#!/usr/bin/env bash
# The version check of release.yml's `verify` job (feature 0012 H3; ADR 0037 §2): every manifest
# that carries the release version holds exactly <version>.
#
#   scripts/release/check-version.sh <version> [--notes <file>]
#
#   <version>      X.Y.Z (SemVer 2.0.0 core; no pre-release or build part)
#   --notes <f>    also require a CHANGELOG.md section for <version> (a `## [X.Y.Z]` or
#                  `## X.Y.Z` heading, Keep a Changelog style) with at least one non-blank line,
#                  and write that section's body to <f> (the draft release notes). Tag mode.
#
# Checked:
#   - [workspace.package] version of Cargo.toml, and the version of every workspace member
#     (`cargo metadata --no-deps --locked`); the Gradle build reads the same field
#     (platforms/android/build-logic PackagingPlugin), so the AAR and the jar follow it;
#   - bindings/node/package.json: version (the one Node package; it has no optionalDependencies
#     since 0.1.2, feature 0017);
#   - bindings/js/package.json: version (the shared facade, not published);
#   - bindings/wasm/package.template.json keeps its "@VERSION@" placeholder (build-package.sh
#     fills it from Cargo.toml);
#   - Package.swift: the binaryTarget url is .../releases/download/v<version>/PolyjoseFFI.xcframework.zip.
#
# Exit status: 0 all equal; 1 a mismatch (each printed); 2 usage. Needs cargo and python3.
set -euo pipefail
export LC_ALL=C
me=check-version
repo=$(cd "$(dirname "$0")/../.." && pwd -P)
# shellcheck source-path=SCRIPTDIR source=lib.sh
. "$repo/scripts/release/lib.sh"

usage() { echo "usage: scripts/release/check-version.sh <version> [--notes <file>]" >&2; exit 2; }
[ $# -eq 1 ] || [ $# -eq 3 ] || usage
version=$1
notes=""
if [ $# -eq 3 ]; then
  [ "$2" = --notes ] && [ -n "$3" ] || usage
  notes=$3
fi
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || rel_die "'$version' is not X.Y.Z"

bad=0
check() { # check <what> <found>
  if [ "$2" = "$version" ]; then
    echo "  ok   $1: $2"
  else
    echo "  FAIL $1: '$2', expected '$version'"
    bad=1
  fi
}

json() { # json <file> <python expression over `d`>: prints one value per line
  python3 -I -c 'import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
v = eval(sys.argv[2], {"d": d})
for x in (v if isinstance(v, list) else [v]):
    print(x)' "$1" "$2"
}

cd "$repo"
echo "==> $me: $version"

check "Cargo.toml [workspace.package] version" \
  "$(awk '/^\[/ { t = ($0 == "[workspace.package]") } t && /^version *=/ { gsub(/.*= *"|".*/, ""); print; exit }' Cargo.toml)"
while IFS=' ' read -r name ver; do
  check "crate $name" "$ver"
done < <(cargo metadata --no-deps --locked --format-version 1 |
  python3 -I -c 'import json, sys
for p in json.load(sys.stdin)["packages"]:
    print(p["name"], p["version"])')

check "bindings/node/package.json version" "$(json bindings/node/package.json 'd["version"]')"
check "bindings/js/package.json version" "$(json bindings/js/package.json 'd["version"]')"
if [ "$(json bindings/wasm/package.template.json 'd["version"]')" = "@VERSION@" ]; then
  echo "  ok   bindings/wasm/package.template.json: @VERSION@ (filled from Cargo.toml)"
else
  echo "  FAIL bindings/wasm/package.template.json: the version must stay @VERSION@"
  bad=1
fi
url=$(sed -n 's|^ *url: "\(https://github.com/[^"]*\)",$|\1|p' Package.swift)
want_url="https://github.com/${GITHUB_REPOSITORY:-bharathkontham/polyjose}/releases/download/v$version/PolyjoseFFI.xcframework.zip"
if [ "$url" = "$want_url" ]; then
  echo "  ok   Package.swift binaryTarget url: $url"
else
  echo "  FAIL Package.swift binaryTarget url: '$url', expected '$want_url'"
  bad=1
fi

if [ -n "$notes" ]; then
  [ -f CHANGELOG.md ] || { echo "  FAIL CHANGELOG.md does not exist"; exit 1; }
  awk -v v="$version" '
    function heading(s) { return s ~ /^## / }
    function is_ours(s) { sub(/^## +/, "", s); sub(/^\[/, "", s); return index(s, v) == 1 && substr(s, length(v) + 1) ~ /^(\]|[[:space:]]|$)/ }
    heading($0) { if (inside) exit; if (is_ours($0)) { inside = 1; next } }
    inside { print }
  ' CHANGELOG.md >"$notes"
  if grep -q '[^[:space:]]' "$notes"; then
    echo "  ok   CHANGELOG.md has a section for $version ($(grep -c '' "$notes") lines, written to $notes)"
  else
    echo "  FAIL CHANGELOG.md has no non-empty section for $version (a '## [$version]' heading)"
    bad=1
  fi
fi

[ "$bad" -eq 0 ] || { echo "$me: FAILED"; exit 1; }
echo "$me: PASS ($version)"
