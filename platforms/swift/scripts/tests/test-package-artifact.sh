#!/usr/bin/env bash
# The packaged Swift (iOS) artifact (ADR 0032 §4, §6; ADR 0020 §4; ADR 0011), made by
# platforms/swift/scripts/package.sh from the real platforms/swift/build/PolyjoseFFI.xcframework
# into a scratch output directory (the checkout's dist/apple/ is not touched). Checks:
#   - the zip holds one top-level PolyjoseFFI.xcframework/ with the 9 libraries of ADR 0032 §1
#     (each with its headers and module map), THIRD-PARTY-NOTICES.txt and LICENSE, and no
#     AppleDouble (`._*`) or `__MACOSX` entries; it is under 25,000,000 bytes;
#   - the notices are polyjose-ffi's for aarch64-apple-ios: they name uniffi_core and the crypto
#     crates, and no napi or wasm-bindgen crate; LICENSE is polyjose's;
#   - the .sha256 is `swift package compute-checksum` of the zip (= its SHA-256), and the
#     binaryTarget stanza carries the release URL of this version and that checksum, and is a
#     valid package manifest fragment (`swift package dump-package`);
#   - a consumer package builds against the artifact and `swift run` does one ES256 sign/verify
#     round trip (RFC 7515 §3.1, RFC 7518 §3.4) and rejects a tampered token: once with
#     binaryTarget(path:) on the unzipped XCFramework (the criterion), and once on the zip itself,
#     which SwiftPM extracts the way it extracts the release asset.
# A development build (`arm64_32: missing`) is packaged with --allow-dev and checked for its
# `watchos-arm64` library instead. Takes a minute or two: two consumer builds.
# Usage: platforms/swift/scripts/tests/test-package-artifact.sh (needs macOS with Xcode, cargo,
# python3 and a built XCFramework: platforms/swift/scripts/build-xcframework.sh).
set -uo pipefail
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

xcf="$swift_dir/build/PolyjoseFFI.xcframework"
[ -f "$xcf/polyjose-build.txt" ] || lib_die "no built XCFramework at $xcf (run platforms/swift/scripts/build-xcframework.sh)"
libraries=$release_libraries
allow=""
if grep -qx 'arm64_32: missing' "$xcf/polyjose-build.txt"; then
  echo "note: the XCFramework is a development build (arm64_32: missing); packaging it with --allow-dev"
  libraries=$dev_libraries
  allow=--allow-dev
fi
version=$(cd "$repo" && cargo metadata --locked --offline --no-deps --format-version 1 |
  python3 -I -c 'import json,sys; print([p["version"] for p in json.load(sys.stdin)["packages"] if p["name"] == "polyjose-ffi"][0])')

out="$scratch/out"
# shellcheck disable=SC2086 # $allow is empty or one flag
run_package $allow --out-dir "$out"
check "package.sh succeeds on the built XCFramework" "[ $rc -eq 0 ]"
if [ "$rc" -ne 0 ]; then show_log; finish; exit 1; fi
check "it checked that every Apple target gives the same crate set" "log_has 'same crate set on all 12 Apple targets'"

zip="$out/PolyjoseFFI.xcframework.zip"
check "the output directory holds exactly the zip, its .sha256 and the stanza" \
  "[ \"\$(ls -A '$out' | tr '\n' ' ')\" = 'PolyjoseFFI.xcframework.zip PolyjoseFFI.xcframework.zip.sha256 binaryTarget.swift.txt ' ]"

# --- Contents ---------------------------------------------------------------------------------
unzip -Z1 "$zip" >"$scratch/entries.txt" 2>/dev/null || fail "unzip cannot list the zip"
entries="$scratch/entries.txt"
has_entry() { grep -qxF -- "$1" "$entries"; }
missing=""
for id in $libraries; do
  for f in libpolyjose_ffi.a Headers/PolyjoseFFI/PolyjoseFFI.h Headers/PolyjoseFFI/module.modulemap; do
    has_entry "PolyjoseFFI.xcframework/$id/$f" || missing="$missing $id/$f"
  done
done
check "unzip lists the 9 libraries, each with its header and module map${missing:+ (missing:$missing)}" "[ -z '$missing' ]"
check "exactly 9 static libraries" "[ \"\$(grep -c '\\.a\$' '$entries')\" -eq 9 ]"
check "unzip lists THIRD-PARTY-NOTICES.txt" "has_entry PolyjoseFFI.xcframework/THIRD-PARTY-NOTICES.txt"
check "unzip lists LICENSE" "has_entry PolyjoseFFI.xcframework/LICENSE"
check "unzip lists Info.plist and polyjose-build.txt" \
  "has_entry PolyjoseFFI.xcframework/Info.plist && has_entry PolyjoseFFI.xcframework/polyjose-build.txt"
check "one top-level entry, PolyjoseFFI.xcframework/ (what SwiftPM looks for in the asset)" \
  "[ -z \"\$(grep -v '^PolyjoseFFI\\.xcframework/' '$entries')\" ]"
check "no AppleDouble ._* entries" "! grep -Eq '(^|/)\\._' '$entries'"
check "no __MACOSX entries" "! grep -q '__MACOSX' '$entries'"
size=$(stat -f %z "$zip")
check "the zip is under 25,000,000 bytes ($size bytes)" "[ $size -lt 25000000 ]"

unzipped="$scratch/unzipped"
mkdir -p "$unzipped"
unzip -q "$zip" -d "$unzipped" || fail "unzip cannot extract the zip"
u="$unzipped/PolyjoseFFI.xcframework"
plist_ids=$(i=0; while id=$(plutil -extract "AvailableLibraries.$i.LibraryIdentifier" raw -o - "$u/Info.plist" 2>/dev/null); do
  echo "$id"; i=$((i + 1)); done | sort | tr '\n' ' ')
# shellcheck disable=SC2086 # a word list
want_ids=$(printf '%s\n' $libraries | sort | tr '\n' ' ')
check "Info.plist lists exactly the 9 libraries (in any order)" "[ '$plist_ids' = '$want_ids' ]"
check "LICENSE is polyjose's LICENSE" "cmp -s '$u/LICENSE' '$repo/LICENSE'"
if [ -z "$allow" ]; then
  check "the packaged build is a release build (arm64_32: present)" \
    "grep -qx 'arm64_32: present' '$u/polyjose-build.txt'"
fi
check "polyjose-build.txt is the packaged build's" "cmp -s '$u/polyjose-build.txt' '$xcf/polyjose-build.txt'"

# --- Notices (ADR 0020 §4) --------------------------------------------------------------------
notices="$u/THIRD-PARTY-NOTICES.txt"
rule=$(printf '%080d' 0 | tr 0 =)
# has_crate <crate>: the notices have a section for <crate>: "<name> <version>" after a rule line.
has_crate() {
  awk -v rule="$rule" -v name="$1" '
    prev == rule && index($0, name " ") == 1 && substr($0, length(name) + 2) ~ /^[0-9][^ ]*$/ { found = 1 }
    { prev = $0 }
    END { exit !found }' "$notices"
}
check "the notices are polyjose-ffi's ($version) for aarch64-apple-ios" \
  "grep -qxF 'Artifact: polyjose-ffi $version' '$notices' && grep -qxF 'Target: aarch64-apple-ios' '$notices'"
crypto="aes aes-gcm aes-kw cbc hmac sha2 pbkdf2 p256 p384 p521 k256 ecdsa elliptic-curve rsa
crypto-bigint zeroize curve25519-dalek ed25519-dalek x25519-dalek subtle getrandom"
missing=""
for c in uniffi_core $crypto; do has_crate "$c" || missing="$missing $c"; done
check "the notices name uniffi_core and the crypto crates${missing:+ (missing:$missing)}" "[ -z '$missing' ]"
present=""
for c in napi napi-sys napi-derive wasm-bindgen js-sys wasm-bindgen-macro sha1 uniffi_bindgen; do
  has_crate "$c" && present="$present $c"
done
check "the notices name no napi, wasm-bindgen, sha1 or uniffi_bindgen crate${present:+ (present:$present)}" "[ -z '$present' ]"

# --- Checksum and stanza (ADR 0032 §6, ADR 0011) ----------------------------------------------
sha=$(shasum -a 256 "$zip" | cut -d' ' -f1)
spm_sha=$(TMPDIR=$swift_tmp swift package compute-checksum "$zip" 2>/dev/null)
check "the .sha256 file is one line, the zip's SHA-256 ($sha)" \
  "[ \"\$(cat '$zip.sha256')\" = '$sha' ] && [ \"\$(wc -l <'$zip.sha256' | tr -d ' ')\" = 1 ]"
check "swift package compute-checksum agrees" "[ '$spm_sha' = '$sha' ]"
stanza="$out/binaryTarget.swift.txt"
url="https://github.com/bharathkontham/polyjose/releases/download/v$version/PolyjoseFFI.xcframework.zip"
check "the stanza has the release URL of v$version" "grep -qF 'url: \"$url\"' '$stanza'"
check "the stanza has the checksum" "grep -qF 'checksum: \"$sha\"' '$stanza'"
check "the stanza names the binary target PolyjoseFFI" "grep -qF 'name: \"PolyjoseFFI\"' '$stanza'"
check "the stanza says Swift (iOS), never 'Apple platforms' (ADR 0046)" \
  "grep -qF 'Swift (iOS)' '$stanza' && ! grep -qi 'apple platforms' '$stanza'"

manifest="$scratch/stanza-manifest"
mkdir -p "$manifest"
{
  echo '// swift-tools-version: 6.0'
  echo 'import PackageDescription'
  echo 'let package = Package(name: "stanza", products: [.library(name: "PolyjoseFFI", targets: ["PolyjoseFFI"])], targets: ['
  cat "$stanza"
  echo '])'
} >"$manifest/Package.swift"
if TMPDIR=$swift_tmp swift package --package-path "$manifest" dump-package >"$scratch/dump.json" 2>"$scratch/dump.err"; then
  check "the stanza is a valid binaryTarget in a manifest (dump-package)" \
    "python3 -I -c 'import json,sys; t=json.load(open(sys.argv[1]))[\"targets\"][0]; sys.exit(not (t[\"type\"]==\"binary\" and t[\"url\"]==sys.argv[2] and t[\"checksum\"]==sys.argv[3]))' '$scratch/dump.json' '$url' '$sha'"
else
  fail "swift package dump-package rejects the stanza"; sed 's/^/    | /' "$scratch/dump.err"
fi

# --- Consumer smoke test (swift run on macOS) -------------------------------------------------
# consumer <dir> <binaryTarget path>: a package with the committed Polyjose.swift, the binary
# target at <path> (relative to <dir>) and an executable that signs and verifies.
consumer() {
  local dir=$1 path=$2
  mkdir -p "$dir/Sources/Polyjose" "$dir/Sources/Smoke"
  cp "$swift_dir/Sources/Polyjose/Polyjose.swift" "$dir/Sources/Polyjose/"
  cat >"$dir/Package.swift" <<EOF
// swift-tools-version: 6.0
import PackageDescription
let package = Package(
    name: "consumer",
    platforms: [.macOS(.v13)],
    targets: [
        .binaryTarget(name: "PolyjoseFFI", path: "$path"),
        .target(name: "Polyjose", dependencies: ["PolyjoseFFI"]),
        .executableTarget(name: "Smoke", dependencies: ["Polyjose"]),
    ],
    swiftLanguageModes: [.v6]
)
EOF
  cat >"$dir/Sources/Smoke/main.swift" <<'EOF'
import Foundation
import Polyjose

// One JWS Compact Serialization round trip (RFC 7515 §3.1, §5.1, §5.2) with ES256 (RFC 7518
// §3.4), then the same token with another payload must fail with InvalidSignature.
func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data("polyjose-consumer: FAIL \(message)\n".utf8))
    exit(1)
}

do {
    let key = try jwkGenerateForAlg(alg: "ES256")
    let publicKey = try jwkToPublic(jwk: key)
    let payload = Data("polyjose consumer smoke test".utf8)
    let token = try jwsSignCompact(
        payload: payload, key: key, options: JwsSignOptions(protectedHeader: #"{"alg":"ES256"}"#))
    let verified = try jwsVerifyCompact(
        token: token, key: publicKey, options: JwsVerifyOptions(allowedAlgs: ["ES256"]))
    guard verified.payload == payload, verified.alg == "ES256" else { fail("round trip mismatch") }

    let parts = token.split(separator: ".", omittingEmptySubsequences: false)
    guard parts.count == 3 else { fail("not a compact JWS: \(parts.count) parts") }
    let other = base64urlEncode(data: Data("another payload".utf8))
    let tampered = "\(parts[0]).\(other).\(parts[2])"
    do {
        _ = try jwsVerifyCompact(
            token: tampered, key: publicKey, options: JwsVerifyOptions(allowedAlgs: ["ES256"]))
        fail("a tampered token verified")
    } catch PolyjoseError.InvalidSignature {
    }
    print("polyjose-consumer: OK polyjose \(Polyjose.version()) ES256 sign/verify")
} catch {
    fail("\(error)")
}
EOF
}

smoke() {
  local label=$1 dir=$2
  if TMPDIR=$swift_tmp swift run --package-path "$dir" Smoke >"$scratch/smoke.log" 2>&1 \
    && grep -qxF "polyjose-consumer: OK polyjose $version ES256 sign/verify" "$scratch/smoke.log"; then
    pass "$label: swift run signs and verifies, and rejects a tampered token"
  else
    fail "$label: the consumer smoke test failed"
    tail -30 "$scratch/smoke.log" | sed 's/^/    | /'
  fi
  rm -rf "$dir/.build"
}

c1="$scratch/consumer-unzipped"
consumer "$c1" PolyjoseFFI.xcframework
mv "$u" "$c1/PolyjoseFFI.xcframework"
smoke "binaryTarget(path:) on the unzipped XCFramework" "$c1"

c2="$scratch/consumer-zip"
consumer "$c2" PolyjoseFFI.xcframework.zip
cp "$zip" "$c2/"
smoke "binaryTarget(path:) on the zip (extracted by SwiftPM)" "$c2"

finish
