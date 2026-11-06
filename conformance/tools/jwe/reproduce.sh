#!/usr/bin/env bash
# Re-runs every JWE vector generator in conformance/tools/jwe/ into a temporary directory and
# compares each file it writes with the committed vector, byte for byte (feature 0003 T18).
#
# Usage: conformance/tools/jwe/reproduce.sh <rfc-dir>
#   <rfc-dir> holds rfc7516.txt and rfc7517.txt from https://www.rfc-editor.org/rfc/ (checked
#   against the SHA-256 values below). Needs node and python3 only; no network, no cargo.
#
# Prints one line per generator: PASS (every file it writes is identical), HISTORICAL (see
# conformance/README.md, Tools) or FAIL. Exits 1 on any FAIL. The Node generators write the Node
# and OpenSSL versions into `source`/`description`, so they reproduce byte for byte only with the
# versions named in the committed files (Node.js 24.21.0 when this was written).
# Runs on macOS /bin/bash 3.2 and Linux bash.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
rfc=${1:?usage: reproduce.sh <rfc-dir with rfc7516.txt and rfc7517.txt>}
cookbook="$root/crates/polyjose/tests/third_party/ietf-jose-cookbook"
vectors="$root/conformance/vectors/jwe"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/polyjose-jwe-reproduce.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
status=0

sha() { shasum -a 256 "$1" | cut -d' ' -f1; }
want_7516=722cfcddc15f58e746891ba4b846853d3711153a774e4dd55ad6db100474a21f
want_7517=681c19b92a85068716b7e89c5815aa821bd3f11c755ff1c641b40ae9851bb33c
[ "$(sha "$rfc/rfc7516.txt")" = "$want_7516" ] || { echo "FAIL: $rfc/rfc7516.txt is not the RFC Editor text"; exit 1; }
[ "$(sha "$rfc/rfc7517.txt")" = "$want_7517" ] || { echo "FAIL: $rfc/rfc7517.txt is not the RFC Editor text"; exit 1; }

# compare <label> <generated dir> <committed dir>: every generated *.json equals its committed twin.
compare() {
  local label=$1 out=$2 committed=$3 n=0 bad=0 f
  for f in "$out"/*.json; do
    [ -e "$f" ] || continue
    n=$((n + 1))
    if ! cmp -s "$f" "$committed/$(basename "$f")"; then
      echo "  differs: $committed/$(basename "$f")"
      bad=$((bad + 1))
    fi
  done
  if [ "$n" -eq 0 ] || [ "$bad" -ne 0 ]; then
    echo "FAIL $label: $bad of $n files differ"; status=1
  else
    echo "PASS $label: $n files identical"
  fi
}

# A tree with only the vendored cookbook, for the generators that write under <repo-root>.
skeleton() {
  mkdir -p "$1/crates/polyjose/tests/third_party" "$1/conformance/vectors/jwe/json" \
    "$1/conformance/vectors/jwe/negative-json" "$1/conformance/vectors/jwe/zip"
  cp -R "$cookbook" "$1/crates/polyjose/tests/third_party/"
}

# T09: only the RFC inputs extractor survives; its four compact JWEs are in four vectors.
python3 -I "$here/t09-extract-rfc-inputs.py" "$rfc/rfc7516.txt" "$cookbook/jwe" "$tmp/t09.json" > /dev/null
if python3 -I - "$tmp/t09.json" "$vectors/negative-structure" <<'EOF'
import json, sys
got = json.load(open(sys.argv[1]))
files = {"a1": "rfc7516-a1-rsa-oaep-unsupported", "a2": "rfc7516-a2-rsa1-5-unsupported",
         "c51": "rfc7520-5-1-rsa1-5-unsupported", "c52": "rfc7520-5-2-rsa-oaep-unsupported"}
for k, f in files.items():
    v = json.load(open(f"{sys.argv[2]}/{f}.json"))
    assert v["input"]["jwe"] == got[k]["compact"], f
    assert {m: v["input"]["key"][m] for m in ("n", "e")} == {m: got[k]["key"][m] for m in ("n", "e")}, f
EOF
then echo "HISTORICAL t09 (compact/, negative-structure/): writer not preserved; the 4 extracted RFC inputs match their vectors"
else echo "FAIL t09: extracted RFC inputs differ from the vectors"; status=1; fi

# T10: gcmkw/ (24 of its files; T18 adds the per-recipient ones).
node "$here/t10-gcmkw.mjs" "$cookbook/jwe/5_7.key_wrap_using_aes-gcm_keywrap_with_aes-cbc-hmac-sha2.json" "$tmp/t10" > /dev/null
compare "t10-gcmkw.mjs (gcmkw/)" "$tmp/t10" "$vectors/gcmkw"

# T11: the six rsa-oaep-256/*-reproduced.json; it writes next to keys/, so run in a copy.
mkdir -p "$tmp/t11/conformance/vectors/jwe/rsa-oaep-256" "$tmp/t11/conformance/tools" "$tmp/t11-out"
cp "$root/conformance/tools/rsa-oaep-oracle.mjs" "$tmp/t11/conformance/tools/"
cp -R "$vectors/rsa-oaep-256/keys" "$tmp/t11/conformance/vectors/jwe/rsa-oaep-256/"
node "$here/t11-rsa-oaep-256.mjs" "$tmp/t11" > /dev/null
cp "$tmp/t11/conformance/vectors/jwe/rsa-oaep-256/"*.json "$tmp/t11-out/"
compare "t11-rsa-oaep-256.mjs (rsa-oaep-256/)" "$tmp/t11-out" "$vectors/rsa-oaep-256"

# T12: the RFC 7517 App. C extract, then pbes2/.
python3 -I "$here/t12-rfc7517c-extract.py" "$rfc/rfc7517.txt" > "$tmp/t12-rfc7517c.json"
if cmp -s "$tmp/t12-rfc7517c.json" "$here/t12-rfc7517c.json"; then
  echo "PASS t12-rfc7517c-extract.py: t12-rfc7517c.json identical"
else
  echo "FAIL t12-rfc7517c-extract.py: t12-rfc7517c.json differs"; status=1
fi
python3 -I "$here/t12-pbes2.py" \
  "$cookbook/jwe/5_3.key_wrap_using_pbes2-aes-keywrap_with-aes-cbc-hmac-sha2.json" \
  "$here/t12-rfc7517c.json" "$tmp/t12"
compare "t12-pbes2.py (pbes2/)" "$tmp/t12" "$vectors/pbes2"

# T13: ecdh-es/ (it needs its output directory to exist).
mkdir -p "$tmp/t13"
node "$here/t13-ecdh-es.js" "$cookbook/jwe" "$tmp/t13" > /dev/null
compare "t13-ecdh-es.js (ecdh-es/)" "$tmp/t13" "$vectors/ecdh-es"

# T14: json/ and negative-json/ (json/ also holds T18's §5.7 flattened pair).
skeleton "$tmp/t14"
python3 -I "$here/t14-json.py" "$tmp/t14" "$rfc/rfc7516.txt" > /dev/null
compare "t14-json.py (json/)" "$tmp/t14/conformance/vectors/jwe/json" "$vectors/json"
compare "t14-json.py (negative-json/)" "$tmp/t14/conformance/vectors/jwe/negative-json" "$vectors/negative-json"

# T15: zip/ from the recorded tokens (the token program itself is historical).
skeleton "$tmp/t15"
python3 -I "$here/t15-zip.py" "$tmp/t15" "$here/t15-zip-tokens.txt"
compare "t15-zip.py (zip/)" "$tmp/t15/conformance/vectors/jwe/zip" "$vectors/zip"
echo "HISTORICAL t15-zip-tokens.rs: bound64 and empty were encrypted on the OS CSPRNG"

# T18: rfc7520-multi/, negative-crypto/ and its additions to json/, zip/ and gcmkw/.
node "$here/t18-cross-family.mjs" "$root" "$tmp/t18" > /dev/null
for d in rfc7520-multi negative-crypto json zip gcmkw; do
  compare "t18-cross-family.mjs ($d/)" "$tmp/t18/conformance/vectors/jwe/$d" "$vectors/$d"
done

# F06: negative-cross-mode/ (ADR 0050 §1).
node "$here/f06-cross-mode.mjs" "$tmp/f06" > /dev/null
compare "f06-cross-mode.mjs (negative-cross-mode/)" "$tmp/f06" "$vectors/negative-cross-mode"

exit "$status"
