#!/usr/bin/env python3
"""Negative (must-reject) DER and PEM vectors for the keys module.

Each vector is a byte-level mutation of a golden fixture in ../rfc, written
here and not by polyjose, so the rejection tests don't depend on the code under
test. Output: ../negative/<id>-<slug>.{der,pem} and ../negative/manifest.json.
Each manifest row has: file, base, mutation, expect (a stable polyjose error
code) and cite (the rule broken).

Error-code rule (ADR 0018):
- InvalidKey: malformed, non-canonical or inconsistent input (bad DER, bad
  PEM, wrong lengths, off-curve points, mismatched public key, weak key).
- UnsupportedAlgorithm: well-formed, but a key type or format polyjose 0.1.0
  doesn't support (encrypted PKCS#8, RSA private keys per ADR 0021, Ed448,
  RSA-PSS OID, unsupported curves, certificates, unknown labels).

Run: python3 -I negative-vectors.py   (after rfc-golden.py)
"""
import base64, json, os

# The fixture directories (openssl/, rfc/, negative/) are siblings of regen/.
HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RFC = os.path.join(HERE, "rfc")
OUT = os.path.join(HERE, "negative")
rows = []

def tlv(tag, body):
    n = len(body)
    if n < 0x80: return bytes([tag, n]) + body
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(b)]) + b + body
def seq(*xs): return tlv(0x30, b"".join(xs))
def read(name): return open(os.path.join(RFC, name), "rb").read()
def pem(label, der, width=64):
    b = base64.b64encode(der).decode()
    return "-----BEGIN %s-----\n%s\n-----END %s-----\n" % (
        label, "\n".join(b[i:i + width] for i in range(0, len(b), width)), label)

def der(id_, slug, base, data, mutation, expect, cite):
    f = "%s-%s.der" % (id_, slug)
    open(os.path.join(OUT, f), "wb").write(data)
    rows.append(dict(id=id_, file=f, base=base, mutation=mutation, expect=expect, cite=cite))
def txt(id_, slug, base, text, mutation, expect, cite):
    f = "%s-%s.pem" % (id_, slug)
    open(os.path.join(OUT, f), "w", newline="").write(text)
    rows.append(dict(id=id_, file=f, base=base, mutation=mutation, expect=expect, cite=cite))

X690_LEN = "X.690 §10.1 (DER: definite form, minimum number of length octets)"
IK, UA = "InvalidKey", "UnsupportedAlgorithm"

def main():
    os.makedirs(OUT, exist_ok=True)
    ed = read("rfc8037-a1-ed25519-pkcs8.der")          # 30 2e 02 01 00 30 05 06 03 2b 65 70 04 22 04 20 <32>
    assert ed[:16] == bytes.fromhex("302e020100300506032b657004220420")
    body = ed[2:]
    B = "rfc8037-a1-ed25519-pkcs8.der"

    # ---- DER framing (BER-only encodings, trailing data, truncation) ----
    der("N01", "len-long-form-for-short", B, b"\x30\x81\x2e" + body, "outer length 0x2e written as 81 2e", IK, X690_LEN)
    der("N02", "len-leading-zero", B, b"\x30\x82\x00\x2e" + body, "outer length written as 82 00 2e", IK, X690_LEN)
    der("N03", "len-indefinite", B, b"\x30\x80" + body + b"\x00\x00", "indefinite length with end-of-contents", IK, "X.690 §10.1, §8.1.3.6 (indefinite form is BER only)")
    v = b"\x02\x02\x00\x00" + body[3:]
    der("N04", "int-version-nonminimal", B, tlv(0x30, v), "version INTEGER 0 encoded as 02 02 00 00", IK, "X.690 §8.3.2 (INTEGER minimal octets)")
    priv = body[-32:]
    cons = tlv(0x24, tlv(0x04, b"\x04\x20" + priv[:16]) + tlv(0x04, priv[16:]))
    der("N05", "octet-string-constructed", B, seq(body[:3], body[3:10], cons), "privateKey OCTET STRING split into a constructed (0x24) BER string", IK, "X.690 §10.2 (DER: string types use the primitive form)")
    der("N06", "trailing-zero-byte", B, ed + b"\x00", "one 0x00 byte after the outer SEQUENCE", IK, "X.690 §8.1.1 / RFC 5958 §2: exactly one PrivateKeyInfo; no data may follow")
    der("N07", "trailing-second-key", B, ed + ed, "the whole key repeated twice", IK, "RFC 5958 §2: exactly one OneAsymmetricKey")
    der("N08", "truncated", B, ed[:-1], "last content byte removed", IK, "X.690 §8.1.3: length exceeds the available content")
    der("N09", "len-exceeds-input", B, b"\x30\x2f" + body, "outer length one larger than the content", IK, "X.690 §8.1.3")
    der("N10", "high-tag-number", B, b"\x3f\x10\x2e" + body, "outer tag in high-tag-number form (0x3f 0x10)", IK, "X.690 §8.1.2.4 (only SEQUENCE 0x30 is valid here)")
    der("N11", "len-five-octets", B, b"\x30\x85\x00\x00\x00\x00\x2e" + body, "length in 5 octets", IK, X690_LEN)
    der("N12", "empty", B, b"", "zero bytes", IK, "RFC 5958 §2")

    # ---- PKCS#8 / RFC 8410 structure ----
    der("N20", "ed25519-params-null", B, seq(body[:3], seq(bytes.fromhex("06032b6570"), b"\x05\x00"), body[10:]),
        "AlgorithmIdentifier for id-Ed25519 carries NULL parameters", IK, "RFC 8410 §3: parameters MUST be absent")
    der("N21", "oid-ed448", B, seq(body[:3], seq(bytes.fromhex("06032b6571")), body[10:]),
        "OID changed to id-Ed448 (1.3.101.113)", UA, "ADR 0006: Ed448 out of scope; RFC 8410 §3")
    der("N22", "oid-nonminimal-subid", B, seq(body[:3], seq(bytes.fromhex("06042b806570")), body[10:]),
        "OID 1.3.101.112 with subidentifier 101 encoded as 80 65", IK, "X.690 §8.19.2 (subidentifier uses the fewest octets; 0x80 lead byte forbidden)")
    der("N23", "version-2", B, seq(b"\x02\x01\x02", body[3:]), "version 2", IK, "RFC 5958 §2: version is v1(0) or v2(1)")
    der("N24", "v1-with-public-key", B, seq(body, b"\x81\x21\x00" + b"\x11" * 32),
        "version 0 but [1] publicKey present", IK, "RFC 5958 §2: publicKey only in v2")
    der("N25", "curve-private-31-bytes", B, seq(body[:3], body[3:10], tlv(0x04, tlv(0x04, priv[:31]))),
        "CurvePrivateKey of 31 octets", IK, "RFC 8410 §7; RFC 8032 §5.1.5 (32 octets)")
    der("N26", "curve-private-not-octet-string", B, seq(body[:3], body[3:10], tlv(0x04, tlv(0x02, b"\x01" + priv))),
        "CurvePrivateKey wrapped in INTEGER instead of OCTET STRING", IK, "RFC 8410 §7: CurvePrivateKey ::= OCTET STRING")
    v2 = base64.b64decode("".join(l for l in open(os.path.join(RFC, "rfc8410-10.3-ed25519-pkcs8-v2-attr-pub.pem")).read().splitlines() if not l.startswith("-----")))
    bad = bytearray(v2); bad[-1] ^= 0x01
    der("N27", "v2-public-key-mismatch", "rfc8410-10.3-ed25519-pkcs8-v2-attr-pub.pem", bytes(bad),
        "last byte of the v2 [1] publicKey flipped", IK, "RFC 5958 §2 (publicKey is the key's public half); ADR 0018 consistency check")

    # ---- SPKI / EC (RFC 5480) ----
    ecs = read("rfc7517-a1-ec-p256-spki.der")
    E = "rfc7517-a1-ec-p256-spki.der"
    alg = bytes.fromhex("301306072a8648ce3d020106082a8648ce3d030107")
    assert ecs.startswith(b"\x30\x59" + alg + b"\x03\x42\x00\x04")
    pt = ecs[len(alg) + 5:]          # 04 || x || y
    def spki(a, p, unused=0): return seq(a, tlv(0x03, bytes([unused]) + p))
    der("N30", "bitstring-unused-bits", E, spki(alg, pt, 1), "subjectPublicKey BIT STRING with 1 unused bit", IK, "RFC 5480 §2.2 / X.690 §11.2.1 (key is a whole number of octets)")
    off = bytearray(pt); off[-1] ^= 0x01
    der("N31", "point-off-curve", E, spki(alg, bytes(off)), "last byte of y flipped", IK, "RFC 8725 §3.4; SEC 1 v2 §3.2.2.1 (point must be on the curve)")
    der("N32", "ec-no-parameters", E, spki(bytes.fromhex("300906072a8648ce3d0201"), pt), "id-ecPublicKey without namedCurve", IK, "RFC 5480 §2.1.1: parameters MUST be present")
    der("N33", "curve-secp224r1", E, spki(bytes.fromhex("301006072a8648ce3d020106052b81040021"), pt), "namedCurve changed to secp224r1 (1.3.132.0.33)", UA, "ADR 0006 curve set; IANA JOSE EC registry")
    der("N34", "point-short", E, spki(alg, pt[:-1]), "uncompressed point one byte short", IK, "SEC 1 v2 §2.3.3 (uncompressed point is 1 + 2*32 octets)")
    der("N35", "point-hybrid-prefix", E, spki(alg, b"\x06" + pt[1:]), "point prefix 0x06 (hybrid form)", IK, "RFC 5480 §2.2 (only uncompressed and compressed forms)")
    der("N36", "point-identity", E, spki(alg, b"\x00"), "point at infinity (single 0x00)", IK, "SEC 1 v2 §2.3.3; RFC 8725 §3.4")
    der("N37", "params-null-for-ec", E, spki(bytes.fromhex("300b06072a8648ce3d02010500"), pt), "id-ecPublicKey with NULL parameters", IK, "RFC 5480 §2.1.1 (implicitCurve NULL MUST NOT be used)")
    der("N38", "spki-trailing-field", E, seq(alg, tlv(0x03, b"\x00" + pt), b"\x05\x00"), "extra NULL after subjectPublicKey", IK, "RFC 5280 §4.1.2.7 (exactly two fields)")

    # ---- SEC1 ECPrivateKey (RFC 5915) ----
    s1 = read("rfc7517-a2-ec-p256-sec1.der")
    S = "rfc7517-a2-ec-p256-sec1.der"
    assert s1[:7] == bytes.fromhex("307702010104 20".replace(" ", ""))
    d = s1[7:39]; params = s1[39:51]; pub = s1[51:]
    def sec1(ver=b"\x02\x01\x01", dd=d, pr=params, pu=pub): return seq(ver, tlv(0x04, dd), pr, pu)
    der("N40", "sec1-version-0", S, sec1(ver=b"\x02\x01\x00"), "version 0", IK, "RFC 5915 §3: version ecPrivkeyVer1(1)")
    der("N41", "sec1-d-zero", S, sec1(dd=b"\x00" * 32, pu=b""), "private key 0 (publicKey dropped)", IK, "SEC 1 v2 §3.2.1: d in [1, n-1]")
    n256 = bytes.fromhex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")
    der("N42", "sec1-d-equals-n", S, sec1(dd=n256, pu=b""), "private key = group order n", IK, "SEC 1 v2 §3.2.1: d in [1, n-1]")
    der("N43", "sec1-d-31-bytes", S, sec1(dd=d[1:], pu=b""), "privateKey of 31 octets", IK, "RFC 5915 §3: ceiling(log2(n)/8) octets")
    p2 = bytearray(pub); p2[-1] ^= 0x01
    der("N44", "sec1-public-mismatch", S, sec1(pu=bytes(p2)), "[1] publicKey y last byte flipped", IK, "RFC 5915 §3 (publicKey is d*G); ADR 0018 consistency check")
    der("N45", "sec1-params-p384", S, sec1(pr=bytes.fromhex("a00706052b81040022")), "[0] namedCurve says P-384 for a P-256 key", IK, "RFC 5915 §3; RFC 5480 §2.1.1")
    der("N46", "sec1-no-params", S, sec1(pr=b""), "standalone EC PRIVATE KEY without [0] parameters", IK, "RFC 5915 §3: implementations MUST always include the parameters field")
    der("N47", "sec1-params-implicit-tag", S, sec1(pr=bytes.fromhex("8008") + params[4:]), "[0] tagged IMPLICIT instead of EXPLICIT", IK, "RFC 5915 §3 / App. A (EXPLICIT tags)")

    # ---- PKCS#8 EC: inner/outer consistency ----
    P = "rfc7517-a2-ec-p256-pkcs8.der"
    inner_bad = seq(b"\x02\x01\x01", tlv(0x04, d), bytes.fromhex("a00706052b81040022"), pub)
    der("N50", "pkcs8-ec-inner-params-disagree", P, seq(b"\x02\x01\x00", alg, tlv(0x04, inner_bad)),
        "AlgorithmIdentifier says P-256, inner ECPrivateKey [0] says P-384", IK, "RFC 5915 §1 a); RFC 5480 §2.1.1")
    der("N51", "pkcs8-ec-oid-with-ed25519-body", P, seq(b"\x02\x01\x00", alg, tlv(0x04, tlv(0x04, priv))),
        "id-ecPublicKey AlgorithmIdentifier with an RFC 8410 CurvePrivateKey body", IK, "RFC 5915 §3 (privateKey must hold an ECPrivateKey)")

    # ---- RSA public (RFC 8017 App. A.1.1, RFC 3279 §2.3.1) ----
    rs = read("rfc7517-a1-rsa-spki.der")
    R = "rfc7517-a1-rsa-spki.der"
    ralg = bytes.fromhex("300d06092a864886f70d0101010500")
    pk = read("rfc7517-a1-rsa-pkcs1-pub.der")       # 30 82 01 0a 02 82 01 01 00 <256> 02 03 01 00 01
    nb = pk[9:9 + 256]; assert pk[4:9] == bytes.fromhex("0282010100")
    def rpub(n_tlv, e_tlv=bytes.fromhex("0203010001")): return seq(n_tlv, e_tlv)
    der("N60", "rsa-params-absent", R, seq(bytes.fromhex("300b06092a864886f70d010101"), tlv(0x03, b"\x00" + pk)),
        "rsaEncryption without the NULL parameters", IK, "RFC 3279 §2.3.1 (MUST be NULL); RFC 8017 App. A.1 (SHALL be NULL)")
    der("N61", "rsa-modulus-negative", R, seq(ralg, tlv(0x03, b"\x00" + rpub(tlv(0x02, nb)))),
        "modulus without its leading 0x00, so it reads as negative", IK, "RFC 8017 App. A.1.1 (n is a positive INTEGER); X.690 §8.3.3")
    der("N62", "rsa-modulus-nonminimal", R, seq(ralg, tlv(0x03, b"\x00" + rpub(tlv(0x02, b"\x00\x00" + nb)))),
        "modulus with a redundant extra 0x00", IK, "X.690 §8.3.2")
    der("N63", "rsa-exponent-one", R, seq(ralg, tlv(0x03, b"\x00" + rpub(tlv(0x02, b"\x00" + nb), b"\x02\x01\x01"))),
        "publicExponent 1", IK, "RFC 8017 §3.1 (3 <= e <= n-1, odd)")
    der("N64", "rsa-modulus-1024", R, seq(ralg, tlv(0x03, b"\x00" + rpub(tlv(0x02, b"\x00" + nb[:128])))),
        "modulus cut to 1024 bits", IK, "RFC 7518 §3.3/§4.2 and ADR 0007 (RSA >= 2048 bits)")
    der("N65", "rsa-pkcs1-pub-extra-field", "rfc7517-a1-rsa-pkcs1-pub.der", seq(pk[4:], b"\x02\x01\x00"),
        "RSAPublicKey with a third INTEGER", IK, "RFC 8017 App. A.1.1 (exactly modulus, publicExponent)")
    der("N66", "rsa-oid-with-ec-point", R, seq(ralg, tlv(0x03, b"\x00" + pt)),
        "rsaEncryption AlgorithmIdentifier with an EC point as the key", IK, "RFC 3279 §2.3.1 (key MUST be an RSAPublicKey)")
    der("N67", "rsa-private-pkcs8-minimal", R,
        seq(b"\x02\x01\x00", ralg, tlv(0x04, seq(b"\x02\x01\x00", tlv(0x02, b"\x00" + nb), b"\x02\x03\x01\x00\x01"))),
        "PKCS#8 with rsaEncryption (any RSA private key)", UA, "ADR 0021: RSA private keys are not supported in 0.1.0")

    # ---- PEM (RFC 7468) ----
    edpem = open(os.path.join(RFC, "rfc8037-a1-ed25519-pkcs8.pem")).read()
    G = "rfc8037-a1-ed25519-pkcs8.pem"
    lines = edpem.splitlines()
    big = read("rfc7517-a1-rsa-spki.der")     # 294 bytes: several 64-char lines
    GB = "rfc7517-a1-rsa-spki.der"
    txt("P01", "label-mismatch", G, edpem.replace("END PRIVATE KEY", "END PUBLIC KEY"), "END label differs from BEGIN label", IK, "RFC 7468 §2 (labels must match)")
    txt("P02", "header-line", G, "\n".join([lines[0], "Comment: polyjose", ""] + lines[1:]) + "\n", "RFC 1421-style header inside the block", IK, "RFC 7468 §2 (no headers; stricttextualmsg)")
    txt("P03", "line-65-chars", GB, pem("PUBLIC KEY", big, 65), "base64 lines wrapped at 65 characters", IK, "RFC 7468 §3 strict grammar (64-character lines)")
    txt("P04", "line-48-chars", GB, pem("PUBLIC KEY", big, 48), "base64 lines wrapped at 48 characters", IK, "RFC 7468 §3 strict grammar (64-character lines; only the last may be shorter)")
    ecpem = open(os.path.join(RFC, "rfc7517-a1-ec-p256-spki.pem")).read()   # 91 bytes: body ends in "=="
    EP = "rfc7517-a1-ec-p256-spki.pem"
    assert "==\n-----END" in ecpem
    txt("P05", "missing-padding", EP, ecpem.replace("==\n-----END", "\n-----END"), "trailing == padding removed", IK, "RFC 7468 §3; RFC 4648 §4 (padding required)")
    txt("P06", "text-after-end", G, edpem + "garbage\n", "non-whitespace text after the END line", IK, "ADR 0018 strict parser (RFC 7468 §2 permits explanatory text; we reject it)")
    txt("P07", "text-before-begin", G, "Bag Attributes\n" + edpem, "explanatory text before the BEGIN line", IK, "ADR 0018 strict parser (RFC 7468 §2 permits it; we reject it)")
    txt("P08", "two-blocks", G, edpem + edpem, "two PEM blocks", IK, "ADR 0018: exactly one block")
    txt("P09", "space-in-base64", G, edpem.replace(lines[1], lines[1][:10] + " " + lines[1][10:]), "space inside a base64 line", IK, "RFC 7468 §3 strict grammar")
    txt("P10", "lowercase-label", G, edpem.replace("PRIVATE KEY", "private key"), "label in lower case", IK, "RFC 7468 §2 / §3 (label characters)")
    txt("P11", "four-dashes", G, edpem.replace("-----BEGIN", "----BEGIN"), "BEGIN line with four dashes", IK, "RFC 7468 §2")
    txt("P12", "empty-body", G, "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n", "no base64 body", IK, "RFC 5958 §2 (empty is not a key)")
    txt("P13", "label-dsa", G, edpem.replace("PRIVATE KEY", "DSA PRIVATE KEY"), "label DSA PRIVATE KEY", UA, "unsupported label (ADR 0018 label table)")
    txt("P14", "label-public-key-body-pkcs8", G, edpem.replace("PRIVATE KEY", "PUBLIC KEY"), "PUBLIC KEY label around a PKCS#8 body", IK, "RFC 7468 §13 (PUBLIC KEY is SubjectPublicKeyInfo)")
    last = ecpem.split("==")[0][-1]                 # carries 2 data bits + 4 unused bits
    alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    bumped = alpha[alpha.index(last) + 1]           # sets the lowest (unused) bit
    txt("P15", "noncanonical-pad-bits", EP, ecpem.replace(last + "==", bumped + "=="), "last base64 char before == changed so an unused bit is 1", IK, "RFC 4648 §3.5 (canonical encoding); ADR 0018")
    txt("P16", "trailing-der-garbage", G, pem("PRIVATE KEY", ed + b"\x00"), "valid PEM armor around DER with a trailing 0x00", IK, "RFC 5958 §2; X.690 §8.1.1")

    # ---- PEM positives that MUST be accepted (strict but not hostile) ----
    acc = [("A01", "crlf", edpem.replace("\n", "\r\n"), "CRLF line endings", "RFC 7468 §3 (eol may be CRLF, CR or LF)"),
           ("A02", "no-final-newline", edpem.rstrip("\n"), "no newline after END line", "RFC 7468 §3"),
           ("A03", "surrounding-whitespace", "\n\n" + edpem + "\n  \n", "blank lines before and after", "ADR 0018: only whitespace may surround the block")]
    for id_, slug, text, mut, cite in acc:
        f = "%s-accept-%s.pem" % (id_, slug)
        open(os.path.join(OUT, f), "w", newline="").write(text)
        rows.append(dict(id=id_, file=f, base=G, mutation=mut, expect="ok", jwk="rfc8037-a1-ed25519-pkcs8.jwk.json", cite=cite))

    rows.sort(key=lambda r: r["id"])
    with open(os.path.join(OUT, "manifest.json"), "w") as fh:
        json.dump(rows, fh, indent=2); fh.write("\n")
    print("wrote", len(rows), "vectors")

main()
