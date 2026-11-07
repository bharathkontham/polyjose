#!/usr/bin/env bash
# Packaging checks of the Kotlin binding (feature 0008 T04; ADR 0033 §2, §4; ADR 0020 §4):
# the release AAR, the desktop JVM jar, the minified sample APK and the build-local Maven
# publication. Nothing is published: the only repository is the file repository build/repo.
#
#   platforms/android/scripts/check-artifacts.sh [--no-build]
#
# Without --no-build it first runs, from platforms/android and without a Gradle daemon:
#   :polyjose:assembleRelease :polyjose-jvm:jar :sample-minified:assembleRelease
#   publishAllPublicationsToBuildLocalRepository
# The R8 sample's instrumented test needs the emulator and is not run here
# (`./gradlew :sample-minified:connectedReleaseAndroidTest`).
#
# Checks:
#   AAR      classes.jar, jni/{arm64-v8a,armeabi-v7a,x86,x86_64}/libpolyjose_ffi.so, proguard.txt
#            (= consumer-rules.pro); LOAD alignment >= 0x4000 for the 64-bit libraries
#            (llvm-readelf -l from the NDK; Google Play's 16 KB page-size requirement); the AAR
#            under 4 MB (4,000,000 bytes; ADR 0033 §1); each .so size and the AAR size printed.
#   notices  META-INF/polyjose/THIRD-PARTY-NOTICES.txt in the AAR's classes.jar and in the JVM
#            jar, byte-identical to a fresh scripts/third-party-notices.sh run for the shipped
#            target, and every other library's crate set a subset of the shipped file's (it fails
#            naming the crates; ADR 0020 §4).
#   jar      the classes, the host libraries under their JNA prefixes (each of the right
#            architecture), and a Polyjose-Native-Platforms manifest attribute listing exactly
#            the prefixes present; no native library or notices file in the sources jar.
#   APK      zipalign -c -P 16 4 on the minified sample APK, and R8 has run (mapping.txt).
#   Maven    both publications in build/repo with POM (name, description, URL, MIT license,
#            SCM, developer), sources and javadoc jars and Gradle module metadata; the POMs list
#            JNA (type aar for the AAR). No Central credential, Central task or signing secret
#            in the build (grep), and no publishing task except to BuildLocal and MavenLocal.
#
# Exit status: 0 every check passed; 1 a check failed (each one is printed with FAIL); 2 usage
# or a missing tool.
set -uo pipefail
export LC_ALL=C

cd "$(dirname "$0")/.." || exit 2
android=$(pwd -P)
repo=$(cd ../.. && pwd -P)

build=1
case ${1:-} in
  "") ;;
  --no-build) build=0 ;;
  *) echo "usage: $0 [--no-build]" >&2; exit 2 ;;
esac

failures=0
pass() { echo "ok    $*"; }
fail() { echo "FAIL  $*"; failures=$((failures + 1)); }
die() { echo "check-artifacts: $*" >&2; exit 2; }
size() { wc -c <"$1" | tr -d ' '; }

: "${ANDROID_HOME:?ANDROID_HOME is not set (source .toolchain-env.sh)}"
: "${ANDROID_NDK_HOME:?ANDROID_NDK_HOME is not set (source .toolchain-env.sh)}"
readelf=$(ls "$ANDROID_NDK_HOME"/toolchains/llvm/prebuilt/*/bin/llvm-readelf 2>/dev/null | head -n 1)
[ -x "$readelf" ] || die "no llvm-readelf in the NDK at $ANDROID_NDK_HOME"
zipalign=$(ls "$ANDROID_HOME"/build-tools/*/zipalign 2>/dev/null | sort -V | tail -n 1)
[ -x "$zipalign" ] || die "no zipalign in $ANDROID_HOME/build-tools"
for tool in unzip python3 cargo; do command -v "$tool" >/dev/null 2>&1 || die "$tool not found"; done

version=$(awk '/^\[/{t=($0=="[workspace.package]")} t&&/^version *=/{gsub(/.*= *"|".*/,"");print;exit}' "$repo/Cargo.toml")
[ -n "$version" ] || die "no [workspace.package] version in $repo/Cargo.toml"

work="$android/build/check-artifacts"
rm -rf "$work"; mkdir -p "$work" || die "cannot create $work"

if [ "$build" = 1 ]; then
  echo "==> ./gradlew :polyjose:assembleRelease :polyjose-jvm:jar :sample-minified:assembleRelease publishAllPublicationsToBuildLocalRepository"
  ./gradlew --no-daemon -q :polyjose:assembleRelease :polyjose-jvm:jar :sample-minified:assembleRelease \
    publishAllPublicationsToBuildLocalRepository || { echo "FAIL  the Gradle build"; exit 1; }
fi

notices_path=META-INF/polyjose/THIRD-PARTY-NOTICES.txt

# The "name version  license" lines of the "Third-party crates (N)" list of a notices file.
crate_list() {
  awk '/^Third-party crates \(/{f=1; getline; next} f&&/^$/{exit} f' "$1" | sort
}

# check_notices <label> <shipped file> <shipped target> <other target>...
check_notices() {
  local label=$1 file=$2 primary=$3; shift 3
  local fresh="$work/notices-$primary.txt"
  if ! grep -qx "Target: $primary" "$file"; then
    fail "$label notices: not generated for $primary"; return
  fi
  if ! grep -qx "Artifact: polyjose-ffi $version" "$file"; then
    fail "$label notices: not for polyjose-ffi $version"
  fi
  "$repo/scripts/third-party-notices.sh" -p polyjose-ffi --target "$primary" -o "$fresh" >/dev/null \
    || { fail "$label notices: third-party-notices.sh failed for $primary"; return; }
  if cmp -s "$file" "$fresh"; then
    pass "$label notices: $notices_path is current for $primary ($(crate_list "$file" | wc -l | tr -d ' ') third-party crates)"
  else
    fail "$label notices: $notices_path differs from a fresh run for $primary (stale build?)"
  fi
  local target missing
  for target in "$@"; do
    "$repo/scripts/third-party-notices.sh" -p polyjose-ffi --target "$target" -o "$work/notices-$target.txt" >/dev/null \
      || { fail "$label notices: third-party-notices.sh failed for $target"; continue; }
    missing=$(comm -13 <(crate_list "$file") <(crate_list "$work/notices-$target.txt") | awk '{print $1" "$2}' | paste -sd, -)
    if [ -n "$missing" ]; then
      fail "$label notices: $target compiles crates the $primary file does not list: $missing"
    else
      pass "$label notices: $target is covered by $primary"
    fi
  done
}

# --- AAR ----------------------------------------------------------------------------------------
echo "==> AAR"
aar="$android/polyjose/build/outputs/aar/polyjose-release.aar"
abis="arm64-v8a armeabi-v7a x86 x86_64"
if [ ! -f "$aar" ]; then
  fail "AAR: $aar does not exist"
else
  unzip -Z1 "$aar" >"$work/aar.list"
  for entry in classes.jar proguard.txt $(for a in $abis; do echo "jni/$a/libpolyjose_ffi.so"; done); do
    if grep -qx "$entry" "$work/aar.list"; then pass "AAR: $entry"; else fail "AAR: no $entry"; fi
  done
  mkdir -p "$work/aar" && unzip -q -o "$aar" -d "$work/aar"
  if cmp -s "$work/aar/proguard.txt" "$android/polyjose/consumer-rules.pro"; then
    pass "AAR: proguard.txt is consumer-rules.pro"
  else
    fail "AAR: proguard.txt is not consumer-rules.pro"
  fi
  if unzip -Z1 "$work/aar/classes.jar" | grep -qx 'dev/polyjose/UniffiLib.class'; then
    pass "AAR: classes.jar holds the generated Kotlin (dev/polyjose/UniffiLib.class)"
  else
    fail "AAR: classes.jar has no dev/polyjose/UniffiLib.class"
  fi
  if unzip -p "$work/aar/classes.jar" "$notices_path" >"$work/aar-notices.txt" 2>/dev/null && [ -s "$work/aar-notices.txt" ]; then
    pass "AAR: classes.jar holds $notices_path"
    check_notices AAR "$work/aar-notices.txt" aarch64-linux-android \
      armv7-linux-androideabi x86_64-linux-android i686-linux-android
  else
    fail "AAR: classes.jar has no $notices_path"
  fi
  for abi in $abis; do
    so="$work/aar/jni/$abi/libpolyjose_ffi.so"
    [ -f "$so" ] || continue
    aligns=$("$readelf" -lW "$so" | awk '$1=="LOAD"{print $NF}' | sort -u | paste -sd, -)
    echo "      jni/$abi/libpolyjose_ffi.so: $(size "$so") bytes, LOAD alignment $aligns"
    case $abi in
      arm64-v8a | x86_64)
        small=$("$readelf" -lW "$so" | awk '$1=="LOAD"{print $NF}' | while read -r a; do
          [ $((a)) -lt $((0x4000)) ] && echo "$a"; done)
        if [ -z "$aligns" ]; then
          fail "AAR: jni/$abi: no LOAD segments read"
        elif [ -n "$small" ]; then
          fail "AAR: jni/$abi LOAD alignment below 0x4000 ($aligns)"
        else
          pass "AAR: jni/$abi LOAD alignment >= 0x4000 ($aligns)"
        fi
        ;;
    esac
  done
  aar_size=$(size "$aar")
  if [ "$aar_size" -lt 4000000 ]; then
    pass "AAR: $aar_size bytes, under 4 MB (4,000,000 bytes)"
  else
    fail "AAR: $aar_size bytes, not under 4 MB: the ADR 0033 §1 size override is needed"
  fi
fi

# --- JVM jar ------------------------------------------------------------------------------------
echo "==> JVM jar"
jar="$android/polyjose-jvm/build/libs/polyjose-jvm-$version.jar"
host_triple=$(rustc -vV | awk '/^host:/{print $2}')
# JNA's resource prefix for a Rust target triple (ADR 0033 §3a).
triple_of() {
  case $1 in
    darwin-aarch64) echo aarch64-apple-darwin ;;
    darwin-x86-64) echo x86_64-apple-darwin ;;
    linux-x86-64) echo x86_64-unknown-linux-gnu ;;
    linux-aarch64) echo aarch64-unknown-linux-gnu ;;
    win32-x86-64) echo x86_64-pc-windows-msvc ;;
    *) echo unknown ;;
  esac
}
if [ ! -f "$jar" ]; then
  fail "jar: $jar does not exist"
else
  unzip -Z1 "$jar" >"$work/jar.list"
  if grep -qx 'dev/polyjose/UniffiLib.class' "$work/jar.list"; then
    pass "jar: holds the generated Kotlin (dev/polyjose/UniffiLib.class)"
  else
    fail "jar: no dev/polyjose/UniffiLib.class"
  fi
  present=$(grep -E '^[a-z0-9-]+/(libpolyjose_ffi\.(dylib|so)|polyjose_ffi\.dll)$' "$work/jar.list" | cut -d/ -f1 | sort -u)
  case $(uname -s) in
    Darwin) expected_local="darwin-aarch64 darwin-x86-64" ;;
    *) expected_local="" ;;
  esac
  for prefix in $expected_local; do
    if echo "$present" | grep -qx "$prefix"; then pass "jar: $prefix/ library"; else fail "jar: no $prefix/ library"; fi
  done
  mkdir -p "$work/jar" && unzip -q -o "$jar" -d "$work/jar"
  for prefix in $present; do
    lib=$(ls "$work/jar/$prefix"/* | head -n 1)
    echo "      $prefix/$(basename "$lib"): $(size "$lib") bytes"
    want=""
    case $prefix in darwin-aarch64) want=arm64 ;; darwin-x86-64) want=x86_64 ;; esac
    if [ -n "$want" ] && command -v lipo >/dev/null 2>&1; then
      got=$(lipo -archs "$lib" 2>/dev/null)
      if [ "$got" = "$want" ]; then pass "jar: $prefix/ is $want"; else fail "jar: $prefix/ is '$got', not $want"; fi
    fi
  done
  # The manifest attribute, with the 72-byte continuation lines of the jar format joined.
  attr=$(python3 -I -c '
import sys
lines, out = open(sys.argv[1], encoding="utf-8").read().replace("\r\n", "\n").split("\n"), []
for l in lines:
    if l.startswith(" ") and out: out[-1] += l[1:]
    else: out.append(l)
for l in out:
    if l.startswith("Polyjose-Native-Platforms: "): print(l.split(": ", 1)[1])
' "$work/jar/META-INF/MANIFEST.MF")
  want_attr=$(echo "$present" | paste -sd, -)
  if [ -n "$attr" ] && [ "$attr" = "$want_attr" ]; then
    pass "jar: Polyjose-Native-Platforms: $attr (exactly the libraries present)"
  else
    fail "jar: Polyjose-Native-Platforms is '$attr', the libraries present are '$want_attr'"
  fi
  if [ -s "$work/jar/$notices_path" ]; then
    pass "jar: holds $notices_path"
    others=""
    for prefix in $present; do
      t=$(triple_of "$prefix"); [ "$t" = "$host_triple" ] || others="$others $t"
    done
    # shellcheck disable=SC2086
    check_notices jar "$work/jar/$notices_path" "$host_triple" $others
  else
    fail "jar: no $notices_path"
  fi
fi

# --- Minified sample APK ------------------------------------------------------------------------
echo "==> R8 sample APK"
apk="$android/sample-minified/build/outputs/apk/release/sample-minified-release.apk"
if [ ! -f "$apk" ]; then
  fail "APK: $apk does not exist"
else
  if "$zipalign" -c -P 16 4 "$apk" >"$work/zipalign.txt" 2>&1; then
    pass "APK: zipalign -c -P 16 4 ($(size "$apk") bytes)"
  else
    fail "APK: zipalign -c -P 16 4 failed: $(grep -v '(OK' "$work/zipalign.txt" | tail -n 5 | paste -sd' ' -)"
  fi
  if [ -s "$android/sample-minified/build/outputs/mapping/release/mapping.txt" ]; then
    pass "APK: R8 ran (mapping.txt)"
  else
    fail "APK: no R8 mapping.txt; is the release build minified?"
  fi
  if unzip -Z1 "$apk" | grep -qx 'lib/arm64-v8a/libpolyjose_ffi.so'; then
    pass "APK: lib/arm64-v8a/libpolyjose_ffi.so"
  else
    fail "APK: no lib/arm64-v8a/libpolyjose_ffi.so"
  fi
fi

# --- Build-local Maven publication --------------------------------------------------------------
echo "==> Maven publication (build/repo)"
mrepo="$android/build/repo/dev/polyjose"
check_publication() {
  local artifact=$1 packaging=$2 dir="$mrepo/$1/$version" base="$1-$version"
  local f
  for f in "$base.$packaging" "$base.pom" "$base.module" "$base-sources.jar" "$base-javadoc.jar"; do
    if [ -s "$dir/$f" ]; then pass "Maven: $artifact/$version/$f"; else fail "Maven: no $artifact/$version/$f"; fi
  done
  [ -s "$dir/$base.pom" ] || return
  local out
  if out=$(python3 -I - "$dir/$base.pom" "$artifact" "$packaging" "$version" <<'PY'
import sys
import xml.etree.ElementTree as ET
pom_path, artifact, packaging, version = sys.argv[1:5]
ns = {"m": "http://maven.apache.org/POM/4.0.0"}
root = ET.parse(pom_path).getroot()
def text(path):
    el = root.find(path, ns)
    return (el.text or "").strip() if el is not None else ""
problems = []
want = {
    "m:groupId": "dev.polyjose", "m:artifactId": artifact, "m:version": version,
    "m:licenses/m:license/m:name": "MIT",
}
if packaging == "aar":
    want["m:packaging"] = "aar"
for path, value in want.items():
    if text(path) != value:
        problems.append("%s is %r, not %r" % (path, text(path), value))
for path in ["m:name", "m:description", "m:url", "m:licenses/m:license/m:url", "m:scm/m:url",
             "m:scm/m:connection", "m:developers/m:developer/m:id"]:
    if not text(path):
        problems.append("no %s" % path)
jna = [d for d in root.findall("m:dependencies/m:dependency", ns)
       if (d.findtext("m:groupId", "", ns), d.findtext("m:artifactId", "", ns)) == ("net.java.dev.jna", "jna")]
if len(jna) != 1:
    problems.append("JNA is listed %d times" % len(jna))
else:
    d = jna[0]
    jtype = d.findtext("m:type", "jar", ns)
    want_type = "aar" if packaging == "aar" else "jar"
    if jtype != want_type:
        problems.append("JNA has type %r, not %r" % (jtype, want_type))
    if d.findtext("m:scope", "compile", ns) != "compile":
        problems.append("JNA scope is %r, not compile (the API mentions JNA types)" % d.findtext("m:scope", "", ns))
    print("JNA %s %s scope %s" % (d.findtext("m:version", "", ns), jtype, d.findtext("m:scope", "compile", ns)))
if problems:
    print("; ".join(problems))
    sys.exit(1)
PY
  ); then
    pass "Maven: $artifact POM metadata; dependency $out"
  else
    fail "Maven: $artifact POM: $out"
  fi
}
check_publication polyjose aar
check_publication polyjose-jvm jar
if [ -f "$mrepo/polyjose-jvm/$version/polyjose-jvm-$version-sources.jar" ]; then
  if unzip -Z1 "$mrepo/polyjose-jvm/$version/polyjose-jvm-$version-sources.jar" | grep -qE '(\.dylib|\.so|\.dll|THIRD-PARTY-NOTICES\.txt)$'; then
    fail "Maven: the polyjose-jvm sources jar holds native libraries or notices"
  else
    pass "Maven: the polyjose-jvm sources jar holds sources only"
  fi
fi

# --- Nothing is published to Central, nothing is signed with a secret ---------------------------
echo "==> no Central publishing"
self="scripts/check-artifacts.sh"
hits=$(git -C "$android" ls-files -co --exclude-standard | grep -vx "$self" | while read -r f; do
  [ -f "$f" ] && grep -nHE 'publishToMavenCentral|mavenCentralUsername|mavenCentralPassword|mavenCentralPublishing|mavenCentralAutomaticPublishing|SONATYPE_|centralPortal|signingInMemoryKey[A-Za-z]*[[:space:]]*=|signing\.(password|secretKeyRingFile)' "$f"
done)
if [ -z "$hits" ]; then
  pass "grep: no Central credential, Central publishing or signing secret in platforms/android"
else
  fail "grep: Central or signing configuration found: $hits"
fi
if ./gradlew --no-daemon -q tasks --all >"$work/tasks.txt" 2>&1; then
  bad=$(grep -oE '^[A-Za-z0-9:_-]*publish[A-Za-z0-9]*To[A-Za-z0-9]+' "$work/tasks.txt" \
    | grep -vE '(ToBuildLocalRepository|ToMavenLocal)$' | sort -u | paste -sd, -)
  if [ -z "$bad" ]; then
    pass "Gradle: publishing tasks go only to BuildLocal (build/repo) and MavenLocal"
  else
    fail "Gradle: publishing tasks to other repositories: $bad"
  fi
else
  fail "Gradle: './gradlew tasks --all' failed"
fi

echo
if [ "$failures" -eq 0 ]; then
  echo "check-artifacts: all checks passed"
  exit 0
fi
echo "check-artifacts: $failures check(s) FAILED"
exit 1
