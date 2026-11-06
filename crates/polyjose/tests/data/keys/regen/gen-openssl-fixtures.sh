#!/bin/sh
# Regenerates the OpenSSL key fixtures of the keys module.
# These are TEST DATA only: OpenSSL is never a dependency of polyjose.
# Run from anywhere; writes into ../openssl (the openssl/ sibling of regen/).
# Recorded run: 2026-11-05, OpenSSL 4.1.0 23 Oct 2026 (Homebrew, /opt/homebrew/bin/openssl).
set -eu
O=${OPENSSL:-/opt/homebrew/bin/openssl}
D=$(cd "$(dirname "$0")/.." && pwd)/openssl
rm -rf "$D" && mkdir -p "$D" && cd "$D"
"$O" version > OPENSSL_VERSION

# ---------- RSA (ADR 0021: public keys only in 0.1.0) ----------
# A private key is generated only as the source of the public halves and as
# rejection data: every RSA private key, in any format, must fail with
# UnsupportedAlgorithm.
"$O" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out reject-rsa2048-private-pkcs8.pem
"$O" pkey -in reject-rsa2048-private-pkcs8.pem -outform DER -out reject-rsa2048-private-pkcs8.der
"$O" pkey -in reject-rsa2048-private-pkcs8.pem -traditional -out reject-rsa2048-private-pkcs1.pem      # RSA PRIVATE KEY
"$O" pkey -in reject-rsa2048-private-pkcs8.pem -traditional -outform DER -out reject-rsa2048-private-pkcs1.der
# positive: public halves
"$O" pkey -in reject-rsa2048-private-pkcs8.pem -pubout -out rsa2048-spki.pem                   # PUBLIC KEY
"$O" pkey -in reject-rsa2048-private-pkcs8.pem -pubout -outform DER -out rsa2048-spki.der
"$O" rsa -in reject-rsa2048-private-pkcs8.pem -RSAPublicKey_out -out rsa2048-pkcs1-pub.pem     # RSA PUBLIC KEY
"$O" rsa -in reject-rsa2048-private-pkcs8.pem -RSAPublicKey_out -outform DER -out rsa2048-pkcs1-pub.der
"$O" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out reject-rsa3072-private-pkcs8.pem
"$O" pkey -in reject-rsa3072-private-pkcs8.pem -pubout -out rsa3072-spki.pem
"$O" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out reject-rsa4096-private-pkcs8.pem
"$O" pkey -in reject-rsa4096-private-pkcs8.pem -pubout -out rsa4096-spki.pem
"$O" rsa -in reject-rsa4096-private-pkcs8.pem -RSAPublicKey_out -out rsa4096-pkcs1-pub.pem
# other rejections
"$O" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:1024 -out reject-rsa1024-private-pkcs8.pem
"$O" pkey -in reject-rsa1024-private-pkcs8.pem -pubout -out reject-rsa1024-spki.pem              # too small: InvalidKey
"$O" rsa -in reject-rsa1024-private-pkcs8.pem -RSAPublicKey_out -out reject-rsa1024-pkcs1-pub.pem
"$O" genpkey -algorithm RSA-PSS -pkeyopt rsa_keygen_bits:2048 -out reject-rsapss2048-private-pkcs8.pem
"$O" pkey -in reject-rsapss2048-private-pkcs8.pem -pubout -out reject-rsapss2048-spki.pem         # id-RSASSA-PSS OID
"$O" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_primes:3 -out reject-rsa2048-3prime-private-pkcs8.pem
"$O" pkey -in reject-rsa2048-3prime-private-pkcs8.pem -traditional -out reject-rsa2048-3prime-private-pkcs1.pem

# ---------- EC (PKCS#8, SEC1, SPKI) ----------
for c in P-256 P-384 P-521 secp256k1; do
  n=$(echo "$c" | tr 'A-Z' 'a-z' | tr -d '-')            # p256 p384 p521 secp256k1
  "$O" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:"$c" -pkeyopt ec_param_enc:named_curve -out ec-$n-pkcs8.pem
  "$O" pkey -in ec-$n-pkcs8.pem -outform DER -out ec-$n-pkcs8.der
  "$O" pkey -in ec-$n-pkcs8.pem -traditional -out ec-$n-sec1.pem               # EC PRIVATE KEY (params + public key)
  "$O" pkey -in ec-$n-pkcs8.pem -traditional -outform DER -out ec-$n-sec1.der
  "$O" ec -in ec-$n-pkcs8.pem -no_public -out ec-$n-sec1-nopub.pem 2>/dev/null  # EC PRIVATE KEY without [1] publicKey
  "$O" pkey -in ec-$n-pkcs8.pem -pubout -out ec-$n-spki.pem
  "$O" pkey -in ec-$n-pkcs8.pem -pubout -outform DER -out ec-$n-spki.der
  "$O" ec -in ec-$n-pkcs8.pem -pubout -conv_form compressed -out ec-$n-spki-compressed.pem 2>/dev/null
done
# rejections: explicit (specifiedCurve) parameters, unsupported curve
"$O" ecparam -name prime256v1 -param_enc explicit -genkey -noout -out reject-ec-p256-explicit-sec1.pem
"$O" pkcs8 -topk8 -nocrypt -in reject-ec-p256-explicit-sec1.pem -out reject-ec-p256-explicit-pkcs8.pem
"$O" pkey -in reject-ec-p256-explicit-sec1.pem -pubout -out reject-ec-p256-explicit-spki.pem
"$O" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:brainpoolP256r1 -out reject-ec-brainpoolp256r1-pkcs8.pem
"$O" pkey -in reject-ec-brainpoolp256r1-pkcs8.pem -pubout -out reject-ec-brainpoolp256r1-spki.pem

# ---------- OKP (RFC 8410) ----------
for a in ED25519 X25519; do
  n=$(echo "$a" | tr 'A-Z' 'a-z')
  "$O" genpkey -algorithm "$a" -out $n-pkcs8.pem
  "$O" pkey -in $n-pkcs8.pem -outform DER -out $n-pkcs8.der
  "$O" pkey -in $n-pkcs8.pem -pubout -out $n-spki.pem
  "$O" pkey -in $n-pkcs8.pem -pubout -outform DER -out $n-spki.der
done
# rejections: out-of-scope curves (ADR 0006)
"$O" genpkey -algorithm ED448 -out reject-ed448-pkcs8.pem
"$O" pkey -in reject-ed448-pkcs8.pem -pubout -out reject-ed448-spki.pem
"$O" genpkey -algorithm X448 -out reject-x448-pkcs8.pem

# ---------- encrypted keys: always rejected (out of scope) ----------
"$O" pkcs8 -topk8 -in ec-p256-pkcs8.pem -v2 aes-256-cbc -passout pass:polyjose-test -out reject-ec-p256-pkcs8-encrypted.pem
"$O" pkcs8 -topk8 -in ec-p256-pkcs8.pem -v2 aes-256-cbc -passout pass:polyjose-test -outform DER -out reject-ec-p256-pkcs8-encrypted.der
"$O" pkcs8 -topk8 -in reject-rsa2048-private-pkcs8.pem -v2 aes-256-cbc -passout pass:polyjose-test -out reject-rsa2048-pkcs8-encrypted.pem
"$O" pkcs8 -topk8 -in ed25519-pkcs8.pem -v2 aes-128-cbc -passout pass:polyjose-test -out reject-ed25519-pkcs8-encrypted.pem
# legacy RFC 1421 encrypted PEM (Proc-Type/DEK-Info headers)
"$O" ec -in ec-p256-pkcs8.pem -aes256 -passout pass:polyjose-test -out reject-ec-p256-sec1-legacy-encrypted.pem 2>/dev/null
"$O" rsa -in reject-rsa2048-private-pkcs8.pem -traditional -aes256 -passout pass:polyjose-test -out reject-rsa2048-pkcs1-legacy-encrypted.pem 2>/dev/null

# ---------- not a key ----------
"$O" req -x509 -new -key ec-p256-pkcs8.pem -subj /CN=polyjose-test -days 1 -out reject-ec-p256-cert.pem

# ---------- text dumps (expected values for the JWK side; generated, not hand-edited) ----------
mkdir -p text
for f in *.pem; do
  case "$f" in reject-*encrypted*|reject-*cert*) continue;; esac
  "$O" pkey -in "$f" -text -noout > "text/${f%.pem}.txt" 2>/dev/null \
    || "$O" pkey -pubin -in "$f" -text -noout > "text/${f%.pem}.txt" 2>/dev/null \
    || "$O" rsa -RSAPublicKey_in -in "$f" -text -noout > "text/${f%.pem}.txt" 2>/dev/null \
    || rm -f "text/${f%.pem}.txt"
done
shasum -a 256 *.pem *.der > SHA256SUMS
