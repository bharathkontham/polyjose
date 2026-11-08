#!/usr/bin/env bash
# Packs one @polyjose/node platform package, @polyjose/node-<platform>, into <out-dir> (ADR 0031
# §2 and §4, ADR 0020 §4, ADR 0011). Shared by scripts/pack.sh (the two darwin packages, T04) and
# scripts/ci-build.sh (one package per CI matrix target, T05), so both pack it the same way.
#
# Usage: scripts/pack-platform.sh <platform> <triple> <out-dir>
#   platform  the npm/<platform>/ directory, e.g. darwin-arm64
#   triple    its Rust target, e.g. aarch64-apple-darwin
#   out-dir   where npm pack writes polyjose-node-<platform>-<version>.tgz (created if missing)
#
# The addon, polyjose.<platform>.node, must already be built (scripts/build.sh). The package is
# assembled in a temporary staging directory, never in the source tree: npm/<platform>/package.json,
# the addon, the repository's LICENSE, a short README.md written here, and THIRD-PARTY-NOTICES.txt
# from scripts/third-party-notices.sh -p polyjose-node --target <triple> (ADR 0020 §4). npm pack
# writes fixed timestamps into the tarball entries.
#
# Packing only. Publishing is the human-approved release (ADR 0011, Gate 3): this script must not
# call npm's or napi's publishing commands, and test/ci.test.ts greps it to keep it so.
# Runs on macOS /bin/bash 3.2, Linux bash and Git Bash; exits non-zero on any failure.
set -euo pipefail
cd "$(dirname "$0")/.."
repo=$(cd ../.. && pwd -P)

[ $# -eq 3 ] || { echo "usage: scripts/pack-platform.sh <platform> <triple> <out-dir>" >&2; exit 2; }
name=$1 triple=$2
mkdir -p "$3"
out=$(cd "$3" && pwd -P)

[ -f "npm/$name/package.json" ] || { echo "pack-platform.sh: no npm/$name/package.json" >&2; exit 1; }
addon=polyjose.$name.node
[ -f "$addon" ] || { echo "pack-platform.sh: $addon was not built" >&2; exit 1; }

dir=$(mktemp -d "${TMPDIR:-/tmp}/polyjose-node-$name.XXXXXX")
# Fail closed (0013 F10): /bin/bash 3.2 runs an EXIT trap with $? = 0 after a syntax error, so an
# exit before the last line, which sets the sentinel, becomes status 2 (see scripts/test-all.sh).
completed=""
# shellcheck disable=SC2154 # rc is assigned by the trap itself (rc=$?)
trap 'rc=$?; rm -rf "$dir"; [ -n "${completed:-}" ] || [ "$rc" -ne 0 ] || { echo "pack-platform.sh: stopped before its last statement (a syntax error?); failing closed" >&2; rc=2; }; exit "$rc"' EXIT

cp "npm/$name/package.json" "$addon" "$dir/"
cp "$repo/LICENSE" "$dir/LICENSE"
cat >"$dir/README.md" <<EOF
# @polyjose/node-$name

The \`$triple\` native addon of [\`@polyjose/node\`](https://www.npmjs.com/package/@polyjose/node).
Install \`@polyjose/node\`, not this package: it loads this addon on this platform.

MIT; see \`LICENSE\`. \`THIRD-PARTY-NOTICES.txt\` lists the Rust crates compiled into the addon.
EOF
"$repo/scripts/third-party-notices.sh" -p polyjose-node --target "$triple" -o "$dir/THIRD-PARTY-NOTICES.txt"
(cd "$dir" && npm pack --ignore-scripts --loglevel=error --pack-destination "$out" >/dev/null)
completed=1; exit 0
