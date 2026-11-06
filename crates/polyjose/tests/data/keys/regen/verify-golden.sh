#!/bin/sh
# Cross-checks every RFC golden fixture in ../rfc with OpenSSL: OpenSSL must
# parse each positive file, and the key values it reports must equal the JWK
# built from the RFC text. RFC 9500 EC keys get their expected JWK from here.
set -eu
O=${OPENSSL:-/opt/homebrew/bin/openssl}
H=$(cd "$(dirname "$0")" && pwd); R=$(cd "$H/.." && pwd)/rfc
rm -rf "$R/text" "$R/expected"; mkdir -p "$R/text"
for f in "$R"/*.pem; do
  b=$(basename "$f" .pem); case "$b" in reject-*) continue;; esac
  "$O" pkey -in "$f" -text -noout > "$R/text/$b.txt" 2>/dev/null \
    || "$O" pkey -pubin -in "$f" -text -noout > "$R/text/$b.txt" 2>/dev/null \
    || "$O" rsa -RSAPublicKey_in -in "$f" -text -noout > "$R/text/$b.txt"
done
python3 -I "$H/expected-jwks.py" "$R"
fail=0
for e in "$R"/expected/*.jwk.json; do
  b=$(basename "$e" .jwk.json)
  if [ -f "$R/$b.jwk.json" ]; then
    python3 -I -c 'import json,sys; a,b=(json.load(open(p)) for p in sys.argv[1:]); sys.exit(a!=b)' "$e" "$R/$b.jwk.json" \
      && echo "MATCH $b" || { echo "MISMATCH $b"; fail=1; }
  else
    cp "$e" "$R/$b.jwk.json"; echo "DERIVED $b (no RFC JWK; expected values from OpenSSL)"
  fi
done
rm -rf "$R/text" "$R/expected"
( cd "$R" && shasum -a 256 *.pem *.der > SHA256SUMS )
exit $fail
