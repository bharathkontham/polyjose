#!/usr/bin/env bash
# Tag mode of release.yml's Apple job (feature 0012 H3; ADR 0037 §2 option 4a, ADR 0032 §4): the
# XCFramework zip is never rebuilt on the tag. It is the zip of the candidate run that the release
# PR recorded, checked here against what the tag commits to.
#
#   scripts/release/apple-candidate.sh <zip-dir> <tag>
#
#   <zip-dir>  the candidate run's apple-xcframework artifact (PolyjoseFFI.xcframework.zip and
#              its .sha256), downloaded by release.yml from the run platforms/swift/
#              release-candidate.json names
#   <tag>      vX.Y.Z, the tag being released; the repository is checked out at it, with the
#              candidate commit fetched
#
# platforms/swift/release-candidate.json (written by the release agent in the release PR, in the
# commit that also writes Package.swift's url and checksum):
#   { "run_id": <the candidate release.yml run>, "commit": "<its 40-hex commit>",
#     "sha256": "<64-hex SHA-256 of its PolyjoseFFI.xcframework.zip>" }
#
# Passes only when all of these hold:
#   1. the zip's SHA-256 equals the recorded sha256, the artifact's .sha256 file, and the
#      Package.swift binaryTarget checksum at the tag (SwiftPM's checksum is the SHA-256 of the
#      zip, `swift package compute-checksum`);
#   2. Package.swift's binaryTarget url is https://github.com/<repo>/releases/download/<tag>/
#      PolyjoseFFI.xcframework.zip;
#   3. the tag commit differs from the candidate commit only in Package.swift and
#      platforms/swift/release-candidate.json, and the Package.swift change touches only its
#      `url:` and `checksum:` lines. So the zip was built from exactly the tree being tagged,
#      except for the two files that can only be written after the build. (ADR 0037 §2 says the
#      trees are equal; they cannot be, since the checksum is committed after the build: this is
#      the narrowest rule that allows that commit. decisions.md, 2026-11-08, H3.)
# The run itself (release.yml, that commit, success) is checked by the workflow with the API.
# Exit 1 on any mismatch, 2 on usage. Needs git, python3 and sha256sum or shasum.
set -euo pipefail
export LC_ALL=C
me=apple-candidate
repo=$(cd "$(dirname "$0")/../.." && pwd -P)
# shellcheck source-path=SCRIPTDIR source=lib.sh
. "$repo/scripts/release/lib.sh"

[ $# -eq 2 ] || { echo "usage: scripts/release/apple-candidate.sh <zip-dir> <tag>" >&2; exit 2; }
dir=$1 tag=$2
[[ $tag =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || rel_die "tag '$tag' is not vX.Y.Z"
cd "$repo"
json=platforms/swift/release-candidate.json
[ -f "$json" ] || rel_die "$json is missing: the release PR must record the candidate run (run_id, commit, sha256)"
read -r run_id commit recorded < <(python3 -I -c 'import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
if set(d) != {"run_id", "commit", "sha256"}:
    sys.exit("keys must be exactly run_id, commit, sha256")
print(d["run_id"], d["commit"], d["sha256"])' "$json") || rel_die "$json is not valid"
[[ $run_id =~ ^[0-9]+$ ]] || rel_die "$json: run_id '$run_id' is not a run id"
[[ $commit =~ ^[0-9a-f]{40}$ ]] || rel_die "$json: commit '$commit' is not a 40-hex commit"
[[ $recorded =~ ^[0-9a-f]{64}$ ]] || rel_die "$json: sha256 '$recorded' is not 64 hex digits"

zip=$dir/PolyjoseFFI.xcframework.zip
[ -f "$zip" ] && [ -f "$zip.sha256" ] || rel_die "$dir must hold PolyjoseFFI.xcframework.zip and its .sha256"
actual=$(rel_sha256 "$zip")
checksum=$(sed -n 's/^ *checksum: "\([0-9a-f]*\)"$/\1/p' Package.swift)
url=$(sed -n 's|^ *url: "\(https://[^"]*\)",$|\1|p' Package.swift)
want_url="https://github.com/${GITHUB_REPOSITORY:-bharathkontham/polyjose}/releases/download/$tag/PolyjoseFFI.xcframework.zip"
echo "==> $me: $tag, candidate run $run_id at $commit"
[ "$actual" = "$recorded" ] || rel_die "the zip's SHA-256 $actual is not the recorded $recorded"
[ "$(tr -d '[:space:]' <"$zip.sha256")" = "$actual" ] || rel_die "the artifact's .sha256 is not the zip's SHA-256"
[ "$checksum" = "$actual" ] || rel_die "Package.swift's checksum '$checksum' is not the zip's SHA-256 $actual"
[ "$url" = "$want_url" ] || rel_die "Package.swift's url '$url' is not $want_url"
echo "  ok   SHA-256 $actual = recorded = .sha256 = Package.swift checksum; url $url"

git cat-file -e "$commit^{commit}" 2>/dev/null || rel_die "the candidate commit $commit is not in this clone (fetch it)"
changed=$(git diff --name-only "$commit" HEAD)
other=$(printf '%s\n' "$changed" | grep -vxE 'Package\.swift|platforms/swift/release-candidate\.json' | grep . || true)
[ -z "$other" ] || rel_die "the tag differs from the candidate commit in more than Package.swift and $json:
$other"
swift_lines=$(git diff -U0 "$commit" HEAD -- Package.swift | grep -E '^[-+]' | grep -vE '^(\+\+\+|---) ' || true)
bad_lines=$(printf '%s\n' "$swift_lines" | grep . | grep -vE '^[-+] *(url|checksum): "[^"]*",?$' || true)
[ -z "$bad_lines" ] || rel_die "Package.swift changed in more than its url: and checksum: lines since the candidate:
$bad_lines"
echo "  ok   the tag's tree is the candidate's, except $(printf '%s\n' "$changed" | grep -c .) file(s): $(printf '%s\n' "$changed" | tr '\n' ' ')"
echo "$me: PASS"
