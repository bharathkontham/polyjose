#!/usr/bin/env python3
"""Derive the expected JWK for every positive OpenSSL fixture.

Input: openssl/text/*.txt, the output of `openssl pkey -text -noout`
(written by gen-openssl-fixtures.sh). Output: openssl/expected/<name>.jwk.json.
The values come only from OpenSSL's own parse of each file, so a JWK produced
by polyjose from the PEM/DER can be compared member by member.

Members follow RFC 7518 §6.2 (EC: crv, x, y [, d], each the full field size),
§6.3.1 (RSA: n, e as Base64urlUInt, minimal octets) and RFC 8037 §2 (OKP: crv,
x [, d]). No optional members (kid, alg, use) are emitted.
Run: python3 -I expected-jwks.py [fixture-dir]   (default: ../openssl)
"""
import base64, json, os, re, sys

# The fixture directories (openssl/, rfc/, negative/) are siblings of regen/.
HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "openssl")
TXT = os.path.join(BASE, "text")
OUT = os.path.join(BASE, "expected")

CURVES = {"prime256v1": ("P-256", 32), "P-256": ("P-256", 32),
          "secp384r1": ("P-384", 48), "P-384": ("P-384", 48),
          "secp521r1": ("P-521", 66), "P-521": ("P-521", 66),
          "secp256k1": ("secp256k1", 32)}

def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def block(text, label):
    """Hex bytes of an indented `label:` block (openssl's aa:bb:cc layout)."""
    m = re.search(r"^" + re.escape(label) + r":?\s*\n((?:\s+[0-9a-f:]+\n)+)", text, re.M)
    if not m: return None
    return bytes.fromhex(re.sub(r"[\s:]", "", m.group(1)))

def minimal(b):
    b = b.lstrip(b"\x00")
    return b if b else b"\x00"

def convert(name, text):
    if "ED25519" in text or "X25519" in text:
        crv = "Ed25519" if "ED25519" in text else "X25519"
        jwk = {"kty": "OKP", "crv": crv, "x": b64u(block(text, "pub"))}
        priv = block(text, "priv")
        if priv is not None: jwk["d"] = b64u(priv)
        return jwk
    m = re.search(r"(?:ASN1 OID|NIST CURVE): (\S+)", text)
    if m and (block(text, "pub") is not None):
        crv, size = CURVES[m.group(1)]
        pub = block(text, "pub")
        if pub[0] != 4:
            return None  # compressed dumps: expected JWK is the uncompressed sibling
        x, y = pub[1:1 + size], pub[1 + size:]
        assert len(x) == size and len(y) == size, name
        jwk = {"kty": "EC", "crv": crv, "x": b64u(x), "y": b64u(y)}
        priv = block(text, "priv")
        if priv is not None:
            d = priv.rjust(size, b"\x00")[-size:]
            jwk["d"] = b64u(d)
        return jwk
    if "Modulus" in text or "modulus" in text:
        if re.search(r"^privateExponent", text, re.M):
            return None  # ADR 0021: RSA private keys are rejection data only
        n = block(text, "Modulus") or block(text, "modulus")
        e = int(re.search(r"Exponent: (\d+)", text).group(1))
        return {"kty": "RSA", "n": b64u(minimal(n)), "e": b64u(minimal(e.to_bytes(8, "big")))}
    return None

def main():
    os.makedirs(OUT, exist_ok=True)
    written = 0
    for f in sorted(os.listdir(TXT)):
        if f.startswith("reject-"): continue
        name = f[:-4]
        jwk = convert(name, open(os.path.join(TXT, f)).read())
        if jwk is None: continue
        with open(os.path.join(OUT, name + ".jwk.json"), "w") as fh:
            json.dump(jwk, fh, indent=2); fh.write("\n")
        written += 1
    print("wrote", written, "expected JWKs", file=sys.stderr)

main()
