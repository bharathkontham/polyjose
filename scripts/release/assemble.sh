#!/usr/bin/env bash
# Assembles the release assets of release.yml (feature 0012 H3; ADR 0037 §2-§3, ADR 0038 §2) from
# the build jobs' artifacts, checks them, and writes SHA256SUMS. In tag mode (--sign) it also signs
# the Maven artifacts and SHA256SUMS with the release key.
#
#   scripts/release/assemble.sh [--sign] <in-dir> <out-dir> <version>
#
# <in-dir> holds what release.yml downloads:
#   crate/polyjose-<v>.crate        `cargo package -p polyjose --locked`
#   npm/*.tgz                       @polyjose/node, with the 8 addons inside, and @polyjose/wasm
#                                   (binding-node.yml, binding-wasm.yml; feature 0017)
#   maven-repo/                     the Gradle build-local repository (binding-android.yml)
#   apple/                          PolyjoseFFI.xcframework.zip and .zip.sha256 (binding-apple.yml,
#                                   or in tag mode the verified candidate zip)
# <out-dir> must not exist or be empty. It receives exactly the assets of ADR 0037 §3:
#   polyjose-<v>.crate
#   polyjose-node-<v>.tgz, polyjose-wasm-<v>.tgz
#   polyjose-<v>.aar, polyjose-<v>.pom, polyjose-jvm-<v>.jar, polyjose-jvm-<v>.pom
#     (and with --sign their .asc), polyjose-maven-<v>.zip
#   PolyjoseFFI.xcframework.zip, PolyjoseFFI.xcframework.zip.sha256
#   SHA256SUMS (and with --sign SHA256SUMS.asc)
#
# Checks (any failure stops with exit 1 and leaves no SHA256SUMS):
#   - exactly the expected input files, each package's package.json name and version;
#   - THIRD-PARTY-NOTICES.txt in every binary package (ADR 0020 §4): each npm tarball
#     (package/THIRD-PARTY-NOTICES.txt), the AAR's classes.jar and the JVM jar
#     (META-INF/polyjose/THIRD-PARTY-NOTICES.txt) and the XCFramework zip
#     (PolyjoseFFI.xcframework/THIRD-PARTY-NOTICES.txt). The .crate is source only, with no
#     third-party code in it, so it carries none (ADR 0020 §4 covers binary packages);
#   - @polyjose/node holds exactly the 8 addons package.json `files` lists (package/polyjose.<platform>.node),
#     and its addon-sha256.json pins exactly those 8 platforms, each to the SHA-256 of the addon it
#     holds (feature 0007 F07: the package loads only those);
#   - the XCFramework's .sha256 file is the zip's SHA-256 (the SPM checksum is SHA-256 of the zip);
#   - the Maven repository holds exactly dev/polyjose/polyjose/<v>/ and
#     dev/polyjose/polyjose-jvm/<v>/ (plus Gradle's maven-metadata.xml files, left out of the
#     bundle), and every file there has a matching .md5 and .sha1, which the Central Portal
#     requires (https://central.sonatype.org/publish/requirements/). Unsigned input only: any .asc
#     in it fails, since signatures are made here.
#
# The Maven bundle polyjose-maven-<v>.zip is the two <v>/ directories in Maven layout, the
# Central Portal upload format (https://central.sonatype.org/publish/publish-portal-upload/).
# With --sign, every file there except checksums gets a detached armored signature (.asc;
# checksum files need none, signatures need no checksum) before it is zipped.
#
# --sign needs gpg with the release key in $GNUPGHOME, RELEASE_GPG_FPR (its fingerprint) and
# GPG_SIGNING_KEY_PASSWORD (scripts/release/lib.sh rel_sign). Without --sign nothing is signed:
# that is the candidate build, whose assets are never released.
# Needs tar, unzip, zipinfo, zip, python3 and sha256sum or shasum. Bash 3.2 compatible.
set -euo pipefail
export LC_ALL=C
me=assemble
repo=$(cd "$(dirname "$0")/../.." && pwd -P)
# shellcheck source-path=SCRIPTDIR source=lib.sh
. "$repo/scripts/release/lib.sh"

usage() { echo "usage: scripts/release/assemble.sh [--sign] <in-dir> <out-dir> <version>" >&2; exit 2; }
sign=0
if [ "${1:-}" = --sign ]; then sign=1; shift; fi
[ $# -eq 3 ] || usage
in=$(cd "$1" && pwd -P) || rel_die "no input directory $1"
out=$2
v=$3
[[ $v =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || rel_die "'$v' is not X.Y.Z"
if [ -e "$out" ]; then
  [ -d "$out" ] && [ -z "$(ls -A "$out")" ] || rel_die "$out exists and is not an empty directory"
fi
mkdir -p "$out"
out=$(cd "$out" && pwd -P)
work=$(mktemp -d "${TMPDIR:-/tmp}/polyjose-assemble.XXXXXX")
trap 'rm -rf "$work"' EXIT

pyjson() { # pyjson <file> <key>: the top-level string <key> of a JSON file
  python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1], encoding="utf-8"))[sys.argv[2]])' "$1" "$2"
}
names() { # names <dir>: the entries of <dir>, sorted, one per line
  (cd "$1" && find . -mindepth 1 -maxdepth 1 | sed 's|^\./||' | sort)
}
has_entry() { # has_entry <zip> <entry>: the zip lists exactly that entry (no grep -q: with pipefail, an early
  # exit of grep would fail the pipe)
  zipinfo -1 "$1" | grep -xF "$2" >/dev/null
}

# --- the crate --------------------------------------------------------------------------------------
echo "==> $me: crate"
[ "$(names "$in/crate")" = "polyjose-$v.crate" ] || rel_die "crate/ must hold exactly polyjose-$v.crate, it holds: $(names "$in/crate" | tr '\n' ' ')"
cp "$in/crate/polyjose-$v.crate" "$out/"
tar -tzf "$out/polyjose-$v.crate" | grep -xF "polyjose-$v/Cargo.toml" >/dev/null || rel_die "polyjose-$v.crate has no polyjose-$v/Cargo.toml"

# --- npm ----------------------------------------------------------------------------------------------
echo "==> $me: npm tarballs"
# The shipped platforms: the polyjose.<platform>.node entries of bindings/node/package.json files.
platforms=$(python3 -I -c 'import json, re, sys
for f in json.load(open(sys.argv[1], encoding="utf-8"))["files"]:
    m = re.fullmatch(r"polyjose\.([a-z0-9-]+)\.node", f)
    if m:
        print(m.group(1))' "$repo/bindings/node/package.json" | sort)
[ "$(printf '%s\n' "$platforms" | grep -c .)" -eq 8 ] || rel_die "bindings/node/package.json files does not list 8 addons"
want_npm=$(printf '%s\n' "polyjose-node-$v.tgz" "polyjose-wasm-$v.tgz" | sort)
have_npm=$(names "$in/npm")
[ "$have_npm" = "$want_npm" ] || rel_die "npm/ holds:
$have_npm
expected exactly:
$want_npm"
npm_name() { # npm_name <tgz>: the package name of a tarball whose package.json version is $v
  local dir=$work/pkg-${1##*/}
  mkdir -p "$dir"
  tar -xzf "$1" -C "$dir" package/package.json
  [ "$(pyjson "$dir/package/package.json" version)" = "$v" ] || rel_die "${1##*/}: package.json version is not $v"
  pyjson "$dir/package/package.json" name
}
for f in $want_npm; do
  case $f in
    polyjose-node-"$v".tgz) want=@polyjose/node ;;
    polyjose-wasm-"$v".tgz) want=@polyjose/wasm ;;
    *) rel_die "unexpected npm tarball $f" ;;
  esac
  [ "$(npm_name "$in/npm/$f")" = "$want" ] || rel_die "$f: package.json name is not $want"
  tar -tzf "$in/npm/$f" | grep -xF package/THIRD-PARTY-NOTICES.txt >/dev/null || rel_die "$f has no package/THIRD-PARTY-NOTICES.txt"
  cp "$in/npm/$f" "$out/"
  echo "  ok   $f ($want $v, THIRD-PARTY-NOTICES.txt)"
done
# @polyjose/node holds the 8 addons, and addon-sha256.json pins each by its SHA-256 (feature 0007
# F07, feature 0017).
want_addons=$(for p in $platforms; do echo "package/polyjose.$p.node"; done | sort)
have_addons=$(tar -tzf "$out/polyjose-node-$v.tgz" | grep -E '^package/[^/]*\.node$' | sort || true)
[ "$have_addons" = "$want_addons" ] || rel_die "polyjose-node-$v.tgz holds the addons:
$have_addons
expected exactly:
$want_addons"
mkdir -p "$work/main"
# shellcheck disable=SC2086 # one tar member per addon
tar -xzf "$out/polyjose-node-$v.tgz" -C "$work/main" package/addon-sha256.json $want_addons ||
  rel_die "polyjose-node-$v.tgz has no package/addon-sha256.json"
for p in $platforms; do
  printf '%s %s\n' "$p" "$(rel_sha256 "$work/main/package/polyjose.$p.node")"
done | sort >"$work/addons.txt"
python3 -I -c 'import json, sys
pins = json.load(open(sys.argv[1], encoding="utf-8"))
print("\n".join(f"{k} {pins[k]}" for k in sorted(pins)))' "$work/main/package/addon-sha256.json" >"$work/pins.txt"
cmp -s "$work/addons.txt" "$work/pins.txt" || rel_die "@polyjose/node's addon-sha256.json does not pin exactly the 8 addons it holds:
$(diff "$work/pins.txt" "$work/addons.txt" || true)"
echo "  ok   polyjose-node-$v.tgz holds the 8 addons; addon-sha256.json pins each by its SHA-256"

# --- Apple --------------------------------------------------------------------------------------------
echo "==> $me: XCFramework"
zip=PolyjoseFFI.xcframework.zip
[ -f "$in/apple/$zip" ] && [ -f "$in/apple/$zip.sha256" ] || rel_die "apple/ must hold $zip and $zip.sha256"
sum=$(rel_sha256 "$in/apple/$zip")
[ "$(tr -d '[:space:]' <"$in/apple/$zip.sha256")" = "$sum" ] || rel_die "$zip.sha256 is not the zip's SHA-256 ($sum)"
has_entry "$in/apple/$zip" PolyjoseFFI.xcframework/THIRD-PARTY-NOTICES.txt || rel_die "$zip has no PolyjoseFFI.xcframework/THIRD-PARTY-NOTICES.txt"
cp "$in/apple/$zip" "$in/apple/$zip.sha256" "$out/"
echo "  ok   $zip ($sum, THIRD-PARTY-NOTICES.txt)"

# --- Maven --------------------------------------------------------------------------------------------
echo "==> $me: Maven bundle"
mrepo=$work/maven
mkdir -p "$mrepo"
cp -R "$in/maven-repo/." "$mrepo/"
unexpected=$(cd "$mrepo" && find . -type f | sed 's|^\./||' |
  grep -vE "^dev/polyjose/polyjose(-jvm)?/($v/[^/]+|maven-metadata\.xml(\.(md5|sha1|sha256|sha512))?)$" || true)
[ -z "$unexpected" ] || rel_die "unexpected files in the Maven repository:
$unexpected"
[ -z "$(cd "$mrepo" && find . -name '*.asc')" ] || rel_die "the Maven repository is already signed; it must come unsigned (signatures are made here)"
artifacts=$(cd "$mrepo" && find "dev/polyjose/polyjose/$v" "dev/polyjose/polyjose-jvm/$v" -type f |
  grep -vE '\.(md5|sha1|sha256|sha512)$' | sort)
for a in $artifacts; do
  for alg in md5 sha1; do
    [ -f "$mrepo/$a.$alg" ] || rel_die "$a has no .$alg"
    case $alg in
      md5) got=$(python3 -I -c 'import hashlib, sys; print(hashlib.md5(open(sys.argv[1], "rb").read()).hexdigest())' "$mrepo/$a") ;;
      sha1) got=$(python3 -I -c 'import hashlib, sys; print(hashlib.sha1(open(sys.argv[1], "rb").read()).hexdigest())' "$mrepo/$a") ;;
    esac
    [ "$(tr -d '[:space:]' <"$mrepo/$a.$alg")" = "$got" ] || rel_die "$a.$alg does not match the file"
  done
done
for f in "dev/polyjose/polyjose/$v/polyjose-$v.aar" "dev/polyjose/polyjose/$v/polyjose-$v.pom" \
  "dev/polyjose/polyjose-jvm/$v/polyjose-jvm-$v.jar" "dev/polyjose/polyjose-jvm/$v/polyjose-jvm-$v.pom"; do
  [ -f "$mrepo/$f" ] || rel_die "the Maven repository has no $f"
done
unzip -p "$mrepo/dev/polyjose/polyjose/$v/polyjose-$v.aar" classes.jar >"$work/classes.jar" || rel_die "the AAR has no classes.jar"
has_entry "$work/classes.jar" META-INF/polyjose/THIRD-PARTY-NOTICES.txt || rel_die "the AAR's classes.jar has no META-INF/polyjose/THIRD-PARTY-NOTICES.txt"
has_entry "$mrepo/dev/polyjose/polyjose-jvm/$v/polyjose-jvm-$v.jar" META-INF/polyjose/THIRD-PARTY-NOTICES.txt ||
  rel_die "polyjose-jvm-$v.jar has no META-INF/polyjose/THIRD-PARTY-NOTICES.txt"
echo "  ok   $(printf '%s\n' "$artifacts" | grep -c .) artifacts with matching .md5 and .sha1; notices in the AAR and the jar"
if [ "$sign" -eq 1 ]; then
  for a in $artifacts; do rel_sign "$mrepo/$a"; done
  echo "  ok   signed $(printf '%s\n' "$artifacts" | grep -c .) artifacts with the primary key $RELEASE_GPG_FPR"
fi
(cd "$mrepo" && find "dev/polyjose/polyjose/$v" "dev/polyjose/polyjose-jvm/$v" -type f | sort |
  zip -q -X -D "$out/polyjose-maven-$v.zip" -@) || rel_die "zip failed"
for f in "polyjose/$v/polyjose-$v.aar" "polyjose/$v/polyjose-$v.pom" "polyjose-jvm/$v/polyjose-jvm-$v.jar" "polyjose-jvm/$v/polyjose-jvm-$v.pom"; do
  cp "$mrepo/dev/polyjose/$f" "$out/"
  [ "$sign" -eq 0 ] || cp "$mrepo/dev/polyjose/$f.asc" "$out/"
done
echo "  ok   polyjose-maven-$v.zip ($(zipinfo -1 "$out/polyjose-maven-$v.zip" | grep -c .) entries)"

# --- the asset set and SHA256SUMS -----------------------------------------------------------------------
echo "==> $me: asset set"
want=$( { printf '%s\n' "polyjose-$v.crate" "$want_npm" "polyjose-maven-$v.zip" "$zip" "$zip.sha256"
  for f in "polyjose-$v.aar" "polyjose-$v.pom" "polyjose-jvm-$v.jar" "polyjose-jvm-$v.pom"; do
    echo "$f"
    [ "$sign" -eq 0 ] || echo "$f.asc"
  done; } | sort)
have=$(names "$out")
[ "$have" = "$want" ] || rel_die "the assets are:
$have
expected exactly:
$want"
(cd "$out" && for f in $have; do printf '%s  %s\n' "$(rel_sha256 "$f")" "$f"; done) >"$work/SHA256SUMS"
mv "$work/SHA256SUMS" "$out/SHA256SUMS"
if [ "$sign" -eq 1 ]; then
  rel_sign "$out/SHA256SUMS"
fi
echo "==> $me: $(grep -c . "$out/SHA256SUMS") assets in SHA256SUMS$([ "$sign" -eq 0 ] || echo ", signed (SHA256SUMS.asc)")"
cat "$out/SHA256SUMS"
echo "$me: PASS ($out)"
