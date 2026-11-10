#!/usr/bin/env bash
# Tag mode of release.yml (feature 0012 H3; ADR 0037 §2 option 4a, ADR 0068 §1): nothing is
# rebuilt on the tag. Every artifact the sums job assembles comes from the candidate run that the
# release PR recorded, checked here against what the tag commits to.
#
#   scripts/release/candidate.sh <out-dir> <tag>
#
#   <out-dir>  must not exist; receives one directory per artifact, under the fixed artifact names
#              release.yml's sums job downloads: crate/, npm-node/, npm-wasm/, maven-repo/,
#              apple-xcframework/
#   <tag>      vX.Y.Z, the tag being released; the repository is checked out at it (release.yml's
#              verify job checked that), with full history
#
# Needs git, gh (GH_TOKEN with actions: read; GITHUB_REPOSITORY, default
# bharathkontham/polyjose), python3, tar, diff, sha256sum or shasum, and cargo for the pinned
# toolchain.
#
# platforms/swift/release-candidate.json (written by the release agent in the release PR, in the
# commit that also writes Package.swift's url and checksum):
#   { "run_id": <the candidate release.yml run>, "commit": "<its 40-hex commit>",
#     "sha256": "<64-hex SHA-256 of its PolyjoseFFI.xcframework.zip>" }
#
# Passes only when all of these hold, checked in this order (nothing is downloaded before 1-2):
#   1. the run is a release.yml run of this repository, started by workflow_dispatch, completed
#      with success, at the recorded commit (GitHub REST API, GET /repos/{owner}/{repo}/actions/
#      runs/{run_id});
#   2. the tag commit differs from the candidate commit only in Package.swift and
#      platforms/swift/release-candidate.json, and the Package.swift change touches only its
#      `url:` and `checksum:` lines. So every artifact was built and tested from exactly the tree
#      being tagged, except for the two files that can only be written after the build, and that
#      none of the reused artifacts reads. (ADR 0037 §2 says the trees are equal; they cannot be,
#      since the checksum is committed after the build: this is the narrowest rule that allows
#      that commit. decisions.md, 2026-11-08, H3.)
#   3. the Apple zip's SHA-256 equals the recorded sha256, the artifact's .sha256 file, and the
#      Package.swift binaryTarget checksum at the tag (SwiftPM's checksum is the SHA-256 of the
#      zip, `swift package compute-checksum`), and Package.swift's binaryTarget url is
#      https://github.com/<repo>/releases/download/<tag>/PolyjoseFFI.xcframework.zip;
#   4. the crate: `cargo package -p polyjose --locked --no-verify` at the tag (no compile; the
#      candidate's crate job ran cargo's verify build of this source) has exactly the files and
#      bytes of the candidate's .crate, except .cargo_vcs_info.json, whose git sha1 is the
#      packaging commit (the candidate's must be the recorded commit). The tag's .crate replaces
#      the candidate's in <out-dir>/crate, because publish.yml requires the draft's .crate to be
#      `cargo package` of the tag byte for byte.
# The npm tarballs and the Maven repository are reused as they are; their names, versions and
# contents are checked by scripts/release/assemble.sh in the sums job.
# Exit 1 on any mismatch, 2 on usage.
set -euo pipefail
export LC_ALL=C
me=candidate
repo=$(cd "$(dirname "$0")/../.." && pwd -P)
# shellcheck source-path=SCRIPTDIR source=lib.sh
. "$repo/scripts/release/lib.sh"

[ $# -eq 2 ] || { echo "usage: scripts/release/candidate.sh <out-dir> <tag>" >&2; exit 2; }
out=$1 tag=$2
[[ $tag =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || rel_die "tag '$tag' is not vX.Y.Z"
version=${tag#v}
[ ! -e "$out" ] || rel_die "$out already exists"
gh_repo=${GITHUB_REPOSITORY:-bharathkontham/polyjose}
artifacts="crate npm-node npm-wasm maven-repo apple-xcframework"
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
echo "==> $me: $tag, candidate run $run_id at $commit"

# 1. The run.
info=$(gh api "repos/$gh_repo/actions/runs/$run_id" \
  --jq '[.path, .head_sha, .event, .status, .conclusion, .repository.full_name] | @tsv') ||
  rel_die "cannot read run $run_id of $gh_repo"
IFS=$'\t' read -r path head event status conclusion run_repo <<<"$info"
echo "  run  $run_id: $path $head $event $status $conclusion $run_repo"
[ "$path" = .github/workflows/release.yml ] || rel_die "run $run_id is not a release.yml run"
[ "$run_repo" = "$gh_repo" ] || rel_die "run $run_id is not in $gh_repo"
[ "$event" = workflow_dispatch ] || rel_die "run $run_id was not dispatched"
[ "$status" = completed ] && [ "$conclusion" = success ] || rel_die "run $run_id did not succeed"
[ "$head" = "$commit" ] || rel_die "run $run_id built $head, not the recorded $commit"
echo "  ok   a successful workflow_dispatch of release.yml in $gh_repo at the recorded commit"

# 2. The tree rule.
git cat-file -e "$commit^{commit}" 2>/dev/null || git fetch --quiet --no-tags origin "$commit" ||
  rel_die "cannot fetch the candidate commit $commit"
changed=$(git diff --name-only "$commit" HEAD)
other=$(printf '%s\n' "$changed" | grep -vxE 'Package\.swift|platforms/swift/release-candidate\.json' | grep . || true)
[ -z "$other" ] || rel_die "the tag differs from the candidate commit in more than Package.swift and $json:
$other"
swift_lines=$(git diff -U0 "$commit" HEAD -- Package.swift | grep -E '^[-+]' | grep -vE '^(\+\+\+|---) ' || true)
bad_lines=$(printf '%s\n' "$swift_lines" | grep . | grep -vE '^[-+] *(url|checksum): "[^"]*",?$' || true)
[ -z "$bad_lines" ] || rel_die "Package.swift changed in more than its url: and checksum: lines since the candidate:
$bad_lines"
echo "  ok   the tag's tree is the candidate's, except $(printf '%s\n' "$changed" | grep -c .) file(s): $(printf '%s\n' "$changed" | tr '\n' ' ')"

# The artifacts, each into its own directory under its fixed name.
mkdir -p "$out"
for name in $artifacts; do
  gh run download "$run_id" --repo "$gh_repo" --name "$name" --dir "$out/$name" ||
    rel_die "cannot download artifact $name of run $run_id (expired? candidate artifacts live about 90 days)"
  [ -n "$(find "$out/$name" -type f -print -quit)" ] || rel_die "artifact $name of run $run_id is empty"
done

# 3. The Apple zip.
zip=$out/apple-xcframework/PolyjoseFFI.xcframework.zip
[ -f "$zip" ] && [ -f "$zip.sha256" ] || rel_die "apple-xcframework must hold PolyjoseFFI.xcframework.zip and its .sha256"
actual=$(rel_sha256 "$zip")
checksum=$(sed -n 's/^ *checksum: "\([0-9a-f]*\)"$/\1/p' Package.swift)
url=$(sed -n 's|^ *url: "\(https://[^"]*\)",$|\1|p' Package.swift)
want_url="https://github.com/$gh_repo/releases/download/$tag/PolyjoseFFI.xcframework.zip"
[ "$actual" = "$recorded" ] || rel_die "the zip's SHA-256 $actual is not the recorded $recorded"
[ "$(tr -d '[:space:]' <"$zip.sha256")" = "$actual" ] || rel_die "the artifact's .sha256 is not the zip's SHA-256"
[ "$checksum" = "$actual" ] || rel_die "Package.swift's checksum '$checksum' is not the zip's SHA-256 $actual"
[ "$url" = "$want_url" ] || rel_die "Package.swift's url '$url' is not $want_url"
echo "  ok   SHA-256 $actual = recorded = .sha256 = Package.swift checksum; url $url"

# 4. The crate.
cand_crate=$out/crate/polyjose-$version.crate
[ "$(find "$out/crate" -type f | wc -l | tr -d ' ')" = 1 ] && [ -f "$cand_crate" ] ||
  rel_die "artifact crate must hold exactly polyjose-$version.crate"
cargo package -p polyjose --locked --no-verify --quiet
tag_crate=target/package/polyjose-$version.crate
[ -f "$tag_crate" ] || rel_die "cargo package wrote no $tag_crate"
work=$(mktemp -d "${TMPDIR:-/tmp}/candidate.XXXXXX")
trap 'rm -rf "$work"' EXIT
mkdir "$work/candidate" "$work/tag"
tar -xzf "$cand_crate" -C "$work/candidate"
tar -xzf "$tag_crate" -C "$work/tag"
vcs_sha1=$(python3 -I -c 'import json, sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["git"]["sha1"])' \
  "$work/candidate/polyjose-$version/.cargo_vcs_info.json") || rel_die "the candidate .crate has no readable .cargo_vcs_info.json"
[ "$vcs_sha1" = "$commit" ] || rel_die "the candidate .crate was packaged at $vcs_sha1, not the recorded $commit"
diff -r --exclude=.cargo_vcs_info.json "$work/candidate" "$work/tag" >&2 ||
  rel_die "cargo package of $tag differs from the candidate's polyjose-$version.crate beyond .cargo_vcs_info.json"
cp "$tag_crate" "$cand_crate"
echo "  ok   cargo package of $tag = the candidate's .crate except .cargo_vcs_info.json; the tag's .crate $(rel_sha256 "$cand_crate")"

for name in $artifacts; do
  if [ "$name" = maven-repo ]; then
    echo "  $name: $(find "$out/$name" -type f | wc -l | tr -d ' ') files"
  else
    echo "  $name: $(cd "$out/$name" && find . -type f | sed 's|^\./||' | sort | tr '\n' ' ')"
  fi
done
echo "$me: PASS"
