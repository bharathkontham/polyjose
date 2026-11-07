#!/usr/bin/env bash
# The assembly job of .github/workflows/binding-android.yml (feature 0008 T05; ADR 0033 §4,
# ADR 0020 §4, ADR 0037 §1): the release AAR and the five-platform JVM jar from the libraries the
# host-natives matrix built and tested, checked by feature 0008 T04's scripts/check-artifacts.sh.
# Nothing is published or signed: the only repository is the file repository build/repo. Run
# ci-android-sdk.sh first (NDK, build-tools, cargo-ndk).
#
#   platforms/android/scripts/ci-assemble-jar.sh <natives-dir> [--require-all]
#
# <natives-dir> holds one jvm-natives-<prefix>/<library> folder per platform, the layout of the
# downloaded jvm-natives-* artifacts and of ci-host-natives.sh's output (ci-lib.sh); other entries
# (such as the conformance-* folders next to them locally) are ignored.
#
# 1. Each folder must be a JNA prefix of the jar holding exactly that platform's library (file(1)).
#    The prefixes this host builds itself (on macOS both darwin ones, ADR 0033 §4; elsewhere the
#    host's) are rebuilt by Gradle and not passed in, since the jar build rejects a platform it
#    gets twice; step 3 compares the rebuilt library with the CI one. Every other prefix is passed
#    to the jar build with -Ppolyjose.jvmNativesDir (T04's hook in polyjose-jvm/build.gradle.kts).
# 2. `./gradlew --no-daemon :polyjose:assembleRelease :polyjose-jvm:jar
#    :sample-minified:assembleRelease publishAllPublicationsToBuildLocalRepository`, then
#    `scripts/check-artifacts.sh --no-build` (AAR contents, 16 KB alignment, size, notices, the
#    jar's libraries and Polyjose-Native-Platforms, the APK, the POMs, no Central configuration).
#    The notices (feature 0008 F01): the jar's thirdPartyNotices task writes one file over the
#    union of the crate trees of every platform in the jar (scripts/third-party-notices.sh with a
#    --target per platform; 75 crates for the five today: the Linux libraries add linux-raw-sys,
#    the Windows one windows-link and windows-sys). The task and check-artifacts.sh both fail,
#    naming the target and the crates, when a library in the jar compiles a crate the shipped
#    file does not list or its target is not in the file's Targets: line.
# 3. The jar must carry what CI tested, byte for byte: each passed-in library, and each library
#    this host rebuilt for a prefix CI also built (printing both SHA-256s; a mismatch fails, as
#    the jar would ship a library the host-natives tests never loaded). With --require-all, all
#    five platforms and no Polyjose-Native-Platforms-Missing attribute.
# 4. Outputs, one folder per artifact (ADR 0037 §1): <out>/android-aar/polyjose-<v>.aar,
#    <out>/jvm-jar/polyjose-jvm-<v>.jar, <out>/maven-repo/ (a copy of build/repo).
#
# Exit status: 0 assembled and checked; 1 a build or a check failed; 2 usage.
set -uo pipefail
# shellcheck source=ci-lib.sh source-path=SCRIPTDIR
. "$(dirname "$0")/ci-lib.sh"
export LC_ALL=C

usage() { echo "usage: ${0##*/} <natives-dir> [--require-all]" >&2; exit 2; }
fail() { echo "ci-assemble-jar: FAILED: $*"; exit 1; }
[ $# -ge 1 ] && [ $# -le 2 ] || usage
natives=$1
require_all=0
case ${2:-} in "") ;; --require-all) require_all=1 ;; *) usage ;; esac
[ -d "$natives" ] || ci_die "$natives is not a directory"
natives=$(cd "$natives" && pwd -P) || exit 2
command -v file >/dev/null 2>&1 || ci_die "file(1) not found"
command -v unzip >/dev/null 2>&1 || ci_die "unzip not found"

host=$(ci_host_prefix)
[ -n "$host" ] || ci_die "polyjose builds no JVM library on $(uname -s) $(uname -m)"
case $host in darwin-*) built_here="darwin-aarch64 darwin-x86-64" ;; *) built_here=$host ;; esac

version=$(awk '/^\[/{t=($0=="[workspace.package]")} t&&/^version *=/{gsub(/.*= *"|".*/,"");print;exit}' "$ci_repo/Cargo.toml")
[ -n "$version" ] || ci_die "no [workspace.package] version in Cargo.toml"

# 1. The natives.
stage=$ci_android/build/ci-jvm-natives
rm -rf "$stage" "$ci_out/android-aar" "$ci_out/jvm-jar" "$ci_out/maven-repo"
mkdir -p "$stage" || fail "cannot create $stage"
passed=""
rebuilt=""
found=0
for d in "$natives"/*; do
  [ -e "$d" ] || continue
  name=${d##*/}
  case $name in jvm-natives-*) ;; *) echo "ci-assemble-jar: $name: not a jvm-natives-<prefix> folder, ignored"; continue ;; esac
  prefix=${name#jvm-natives-}
  ci_is_prefix "$prefix" || fail "$name: $prefix is not a JNA prefix of the jar ($ci_prefixes)"
  [ -d "$d" ] && [ ! -L "$d" ] || fail "$name is not a directory"
  lib=$(ci_library_of "$prefix")
  entries=$(find "$d" -mindepth 1 -maxdepth 1 -exec basename {} \; | sort | paste -sd' ' -)
  [ "$entries" = "$lib" ] || fail "$name must hold exactly $lib, it holds: ${entries:-nothing}"
  [ -f "$d/$lib" ] && [ ! -L "$d/$lib" ] || fail "$name/$lib is not a regular file"
  kind=$(file -b "$d/$lib")
  echo "$kind" | grep -Eq "$(ci_file_pattern "$prefix")" || fail "$name/$lib is not a $prefix library: $kind"
  found=$((found + 1))
  case " $built_here " in
    *" $prefix "*)
      rebuilt="$rebuilt $prefix"
      echo "ci-assemble-jar: $prefix: built on this host by the jar build (CI library sha256 $(ci_sha256 "$d/$lib")), compared after the build" ;;
    *)
      ci_copy "$d/$lib" "$stage/$prefix" || fail "cannot stage $name"
      passed="$passed $prefix"
      echo "ci-assemble-jar: $prefix: from $name (sha256 $(ci_sha256 "$d/$lib"))" ;;
  esac
done
[ "$found" -gt 0 ] || fail "no jvm-natives-<prefix> folder in $natives"

# 2. Build and T04's checks.
property=()
[ -z "$passed" ] || property=("-Ppolyjose.jvmNativesDir=$stage")
echo "==> ci-assemble-jar: ./gradlew --no-daemon ${property[*]+${property[*]} }:polyjose:assembleRelease :polyjose-jvm:jar :sample-minified:assembleRelease publishAllPublicationsToBuildLocalRepository"
if ! (cd "$ci_android" && ./gradlew --no-daemon ${property[@]+"${property[@]}"} :polyjose:assembleRelease :polyjose-jvm:jar \
  :sample-minified:assembleRelease publishAllPublicationsToBuildLocalRepository); then
  fail "the Gradle build (a thirdPartyNotices failure naming crates means the jar's libraries compile crates the shipped notices do not list; see the header)"
fi
echo "==> ci-assemble-jar: scripts/check-artifacts.sh --no-build"
"$ci_android/scripts/check-artifacts.sh" --no-build || fail "scripts/check-artifacts.sh"

# 3. The jar carries what CI built, and every platform when required.
jar=$ci_android/polyjose-jvm/build/libs/polyjose-jvm-$version.jar
aar=$ci_android/polyjose/build/outputs/aar/polyjose-release.aar
[ -f "$jar" ] || fail "no $jar"
[ -f "$aar" ] || fail "no $aar"
work=$ci_android/build/ci-assemble-jar
{ rm -rf "$work" && mkdir -p "$work" && unzip -q -o "$jar" -d "$work"; } || fail "cannot unpack $jar"
for prefix in $passed; do
  lib=$(ci_library_of "$prefix")
  cmp -s "$stage/$prefix/$lib" "$work/$prefix/$lib" || fail "the jar's $prefix/$lib is not the CI library"
  echo "ci-assemble-jar: jar: $prefix/$lib is the CI library"
done
for prefix in $rebuilt; do
  lib=$(ci_library_of "$prefix")
  tested=$natives/jvm-natives-$prefix/$lib
  [ -f "$work/$prefix/$lib" ] || fail "the jar has no $prefix/$lib, which this host should have built"
  echo "ci-assemble-jar: jar: $prefix/$lib sha256 $(ci_sha256 "$work/$prefix/$lib") (rebuilt here), CI library sha256 $(ci_sha256 "$tested")"
  cmp -s "$tested" "$work/$prefix/$lib" \
    || fail "the jar's $prefix/$lib (rebuilt on this host) is not byte for byte the jvm-natives-$prefix library CI tested"
  echo "ci-assemble-jar: jar: $prefix/$lib is the CI library (rebuilt here, byte for byte)"
done
present=""
for prefix in $ci_prefixes; do
  [ -f "$work/$prefix/$(ci_library_of "$prefix")" ] && present="$present $prefix"
done
echo "ci-assemble-jar: jar platforms:${present:- none}"
if [ "$require_all" = 1 ]; then
  [ "${present# }" = "$ci_prefixes" ] || fail "--require-all: the jar carries${present:- none}, not all of $ci_prefixes"
  if grep -q '^Polyjose-Native-Platforms-Missing:' "$work/META-INF/MANIFEST.MF"; then
    fail "--require-all: the manifest has Polyjose-Native-Platforms-Missing"
  fi
  echo "ci-assemble-jar: jar: all five platforms, no Polyjose-Native-Platforms-Missing"
fi

# 4. Outputs.
{ mkdir -p "$ci_out/android-aar" && cp "$aar" "$ci_out/android-aar/polyjose-$version.aar"; } || fail "cannot copy the AAR"
ci_copy "$jar" "$ci_out/jvm-jar" || fail "cannot copy the jar"
{ mkdir -p "$ci_out/maven-repo" && cp -R "$ci_android/build/repo/." "$ci_out/maven-repo/"; } || fail "cannot copy build/repo"
echo "ci-assemble-jar: PASS (AAR polyjose-$version.aar, jar polyjose-jvm-$version.jar with${present}); outputs in $ci_out"
