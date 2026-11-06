#!/bin/sh
# Regenerates the RSA public keys of tests/jwe_rsa_bound_import.rs: one key
# per modulus size at and around the 2048..=8192-bit range of JWK import
# (RFC 7518 §3.3, §4.3; ADR 0007; ADR 0026 §2 step 8).
#
# The keys come from OpenSSL and Node's built-in crypto, never from
# polyjose. Each private key lives only in a temporary directory and is
# deleted; only public keys are written here (ADR 0021: polyjose has no
# RSA private-key support, and no RSA private key is committed).
#
# Per size <bits>:
#   rsa<bits>-spki.pem / .der    SubjectPublicKeyInfo (RFC 5280 §4.1.2.7)
#   rsa<bits>-pkcs1.pem / .der   RSAPublicKey (RFC 8017 App. A.1.1)
#   rsa<bits>.jwk.json           the JWK (RFC 7518 §6.3.1), from Node
# Node checks that the modulus has exactly <bits> bits and that the four
# encodings hold the same key. SHA256SUMS pins every file.
#
# Usage: sh regen.sh   (OpenSSL 3 or later, Node 16 or later)
set -eu
here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
for bits in 1024 2047 2048 8192 8193 8200; do
  # OpenSSL's two-prime keygen above 8192 bits gives only even sizes (asked
  # for 8193 it returns 8192), so the 8193-bit key has three primes
  # (RFC 8017 §3.1 multi-prime). Its public key is still just n and e.
  primes=2
  [ "$bits" = 8193 ] && primes=3
  openssl genpkey -quiet -algorithm RSA -pkeyopt "rsa_keygen_bits:$bits" \
    -pkeyopt "rsa_keygen_primes:$primes" -pkeyopt rsa_keygen_pubexp:65537 \
    -out "$tmp/private.pem"
  openssl pkey -in "$tmp/private.pem" -pubout -out "$here/rsa$bits-spki.pem"
  openssl pkey -in "$tmp/private.pem" -pubout -outform DER -out "$here/rsa$bits-spki.der"
  openssl rsa -in "$tmp/private.pem" -RSAPublicKey_out -out "$here/rsa$bits-pkcs1.pem" 2>/dev/null
  openssl rsa -in "$tmp/private.pem" -RSAPublicKey_out -outform DER \
    -out "$here/rsa$bits-pkcs1.der" 2>/dev/null
  rm -f "$tmp/private.pem"
  node -e '
    const crypto = require("node:crypto");
    const fs = require("node:fs");
    const dir = process.argv[1];
    const bits = Number(process.argv[2]);
    const read = (f) => fs.readFileSync(`${dir}/rsa${bits}-${f}`);
    const keys = [
      crypto.createPublicKey(read("spki.pem")),
      crypto.createPublicKey({ key: read("spki.der"), format: "der", type: "spki" }),
      crypto.createPublicKey(read("pkcs1.pem")),
      crypto.createPublicKey({ key: read("pkcs1.der"), format: "der", type: "pkcs1" }),
    ];
    const jwks = keys.map((k) => {
      if (k.asymmetricKeyDetails.modulusLength !== bits) {
        throw new Error(`rsa${bits}: not ${bits} bits`);
      }
      const { n, e } = k.export({ format: "jwk" });
      return JSON.stringify({ kty: "RSA", n, e });
    });
    if (new Set(jwks).size !== 1) throw new Error(`rsa${bits}: the encodings disagree`);
    fs.writeFileSync(`${dir}/rsa${bits}.jwk.json`, jwks[0] + "\n");
  ' "$here" "$bits"
done
openssl version > "$here/OPENSSL_VERSION"
node --version > "$here/NODE_VERSION"
(cd "$here" && shasum -a 256 rsa* OPENSSL_VERSION NODE_VERSION > SHA256SUMS)
