#!/usr/bin/env python3
"""Golden PEM/DER <-> JWK pairs taken from the RFCs (test data for the keys module).

Usage: python3 -I rfc-golden.py <dir-with-rfc-txt-files>
Needs rfc7468.txt, rfc7517.txt, rfc8037.txt, rfc8410.txt, rfc9500.txt from
https://www.rfc-editor.org/rfc/rfcNNNN.txt. Writes ../rfc/ (the rfc/ sibling of regen/).

Two kinds of output:
1. VERBATIM: PEM blocks copied byte-for-byte out of RFC 8410 §10.1/§10.3 and
   RFC 9500 §2.1/§2.3 and RFC 7468 §10 Figure 12 / §13 Figure 15 (only the
   RFC's indentation is removed).
2. BUILT: DER for JWKs published in RFC 7517 App. A and RFC 8037 App. A,
   encoded here with a tiny DER writer, then cross-checked by
   verify-golden.sh with OpenSSL (`openssl pkey -text`), which must report the
   same key values. Structure matches what OpenSSL itself emits:
   - SPKI: RFC 5280 §4.1.2.7; EC per RFC 5480 §2 (namedCurve, uncompressed point)
   - PKCS#8 v1 (RFC 5208 §5 / RFC 5958 §2 version 0)
   - EC private key inside PKCS#8: RFC 5915 ECPrivateKey without [0]
     parameters (the AlgorithmIdentifier carries them) and with [1] publicKey
   - SEC1 "EC PRIVATE KEY": RFC 5915 §3 with [0] namedCurve and [1] publicKey
   - OKP: RFC 8410 §4 (SPKI) and §7 (CurvePrivateKey inside PKCS#8 v1)
   - RSA public: RFC 8017 App. A.1.1 RSAPublicKey; rsaEncryption with NULL
"""
import base64, json, os, re, sys

# The fixture directories (openssl/, rfc/, negative/) are siblings of regen/.
HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(HERE, "rfc")

# ---- minimal DER writer (fixture generation only) ----
def tlv(tag, body):
    n = len(body)
    if n < 0x80: ln = bytes([n])
    else:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big"); ln = bytes([0x80 | len(b)]) + b
    return bytes([tag]) + ln + body
def seq(*xs): return tlv(0x30, b"".join(xs))
def integer(v):
    b = v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big")   # always room for sign bit
    while len(b) > 1 and b[0] == 0 and b[1] < 0x80: b = b[1:]
    return tlv(0x02, b)
def octets(b): return tlv(0x04, b)
def bits(b): return tlv(0x03, b"\x00" + b)
NULL = tlv(0x05, b"")
def oid(dotted):
    a = [int(x) for x in dotted.split(".")]
    out = bytes([40 * a[0] + a[1]])
    for v in a[2:]:
        enc = [v & 0x7F]; v >>= 7
        while v: enc.append(0x80 | (v & 0x7F)); v >>= 7
        out += bytes(reversed(enc))
    return tlv(0x06, out)
def ctx(n, body): return tlv(0xA0 | n, body)

OID_RSA, OID_EC = "1.2.840.113549.1.1.1", "1.2.840.10045.2.1"
OID_P256, OID_ED25519, OID_X25519 = "1.2.840.10045.3.1.7", "1.3.101.112", "1.3.101.110"

def b64u_dec(s):
    s = re.sub(r"\s", "", s); return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
def pem(label, der):
    b = base64.b64encode(der).decode()
    lines = [b[i:i + 64] for i in range(0, len(b), 64)]
    return "-----BEGIN %s-----\n%s\n-----END %s-----\n" % (label, "\n".join(lines), label)

def write(name, der=None, label=None, text=None, jwk=None):
    if der is not None:
        open(os.path.join(OUT, name + ".der"), "wb").write(der)
        open(os.path.join(OUT, name + ".pem"), "w").write(pem(label, der))
    if text is not None:
        open(os.path.join(OUT, name + ".pem"), "w").write(text)
    if jwk is not None:
        with open(os.path.join(OUT, name + ".jwk.json"), "w") as fh:
            json.dump(jwk, fh, indent=2); fh.write("\n")

def member(text, name, after):
    """JSON string member `name` in `text` after offset `after`; joins RFC line breaks."""
    m = re.compile(r'"%s":\s*"([^"]+)"' % name, re.S).search(text, after)
    return re.sub(r"\s", "", m.group(1))

def heading(text, h):
    """Offset of the section heading line `h` (skips the table of contents)."""
    return text.index("\n" + h + "\n")

def pem_blocks(text):
    """Every PEM block in an RFC text, with the RFC's own indentation removed."""
    out = []
    for m in re.finditer(r"(?m)^( *)-----BEGIN ([A-Z ]+)-----\n(?:.*\n)*?\1-----END \2-----", text):
        ind = m.group(1)
        out.append("\n".join(l[len(ind):] if l.startswith(ind) else l for l in m.group(0).split("\n")) + "\n")
    return out

def main(src):
    os.makedirs(OUT, exist_ok=True)
    r7517 = open(os.path.join(src, "rfc7517.txt")).read()
    r8037 = open(os.path.join(src, "rfc8037.txt")).read()
    r8410 = open(os.path.join(src, "rfc8410.txt")).read()
    r9500 = open(os.path.join(src, "rfc9500.txt")).read()

    # --- RFC 7517 App. A.1 RSA public key (kid 2011-04-29) ---
    a1 = heading(r7517, "A.1.  Example Public Keys")
    n_b = b64u_dec(member(r7517, "n", a1)); e_b = b64u_dec(member(r7517, "e", a1))
    n, e = int.from_bytes(n_b, "big"), int.from_bytes(e_b, "big")
    rsapub = seq(integer(n), integer(e))
    jwk_rsa = {"kty": "RSA", "n": base64.urlsafe_b64encode(n_b).rstrip(b"=").decode(), "e": "AQAB"}
    write("rfc7517-a1-rsa-spki", seq(seq(oid(OID_RSA), NULL), bits(rsapub)), "PUBLIC KEY", jwk=jwk_rsa)
    write("rfc7517-a1-rsa-pkcs1-pub", rsapub, "RSA PUBLIC KEY", jwk=jwk_rsa)

    # --- RFC 7517 App. A.1 / A.2 EC P-256 ---
    a2 = heading(r7517, "A.2.  Example Private Keys")
    x, y, d = (b64u_dec(member(r7517, k, a2)) for k in ("x", "y", "d"))
    assert len(x) == len(y) == len(d) == 32
    point = b"\x04" + x + y
    jx = {"kty": "EC", "crv": "P-256", "x": member(r7517, "x", a2), "y": member(r7517, "y", a2)}
    write("rfc7517-a1-ec-p256-spki", seq(seq(oid(OID_EC), oid(OID_P256)), bits(point)), "PUBLIC KEY", jwk=jx)
    jd = dict(jx, d=member(r7517, "d", a2))
    sec1_full = seq(integer(1), octets(d), ctx(0, oid(OID_P256)), ctx(1, bits(point)))
    sec1_inner = seq(integer(1), octets(d), ctx(1, bits(point)))
    write("rfc7517-a2-ec-p256-sec1", sec1_full, "EC PRIVATE KEY", jwk=jd)
    write("rfc7517-a2-ec-p256-pkcs8",
          seq(integer(0), seq(oid(OID_EC), oid(OID_P256)), octets(sec1_inner)), "PRIVATE KEY", jwk=jd)

    # --- RFC 8037 App. A.1/A.2 Ed25519 ---
    i = heading(r8037, "A.1.  Ed25519 Private Key")
    ed_d, ed_x = member(r8037, "d", i), member(r8037, "x", i)
    write("rfc8037-a1-ed25519-pkcs8",
          seq(integer(0), seq(oid(OID_ED25519)), octets(octets(b64u_dec(ed_d)))), "PRIVATE KEY",
          jwk={"kty": "OKP", "crv": "Ed25519", "x": ed_x, "d": ed_d})
    write("rfc8037-a2-ed25519-spki", seq(seq(oid(OID_ED25519)), bits(b64u_dec(ed_x))), "PUBLIC KEY",
          jwk={"kty": "OKP", "crv": "Ed25519", "x": ed_x})

    # --- RFC 8037 App. A.6 X25519 (ephemeral key = RFC 7748 §6.1 Alice) ---
    i = heading(r8037, "A.6.  ECDH-ES with X25519")
    hexes = re.findall(r"((?:[0-9a-f]{2} ){15}[0-9a-f]{2}\n\s+(?:[0-9a-f]{2} ){15}[0-9a-f]{2})", r8037[i:])
    bob_pub, eph_priv, eph_pub = (bytes.fromhex(re.sub(r"\s", "", h)) for h in hexes[:3])
    enc = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
    assert enc(eph_pub) == "hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo"
    assert enc(bob_pub) == "3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08"
    write("rfc8037-a6-x25519-pkcs8", seq(integer(0), seq(oid(OID_X25519)), octets(octets(eph_priv))),
          "PRIVATE KEY", jwk={"kty": "OKP", "crv": "X25519", "x": enc(eph_pub), "d": enc(eph_priv)})
    write("rfc8037-a6-x25519-spki", seq(seq(oid(OID_X25519)), bits(eph_pub)), "PUBLIC KEY",
          jwk={"kty": "OKP", "crv": "X25519", "x": enc(eph_pub)})
    write("rfc8037-a6-x25519-bob-spki", seq(seq(oid(OID_X25519)), bits(bob_pub)), "PUBLIC KEY",
          jwk={"kty": "OKP", "crv": "X25519", "x": enc(bob_pub)})

    # --- RFC 8410 §10.1 and §10.3, verbatim ---
    s10 = r8410[heading(r8410, "10.  Examples"):heading(r8410, "11.  IANA Considerations")]
    b = [x for x in pem_blocks(s10)]
    pub101 = [x for x in b if "PUBLIC KEY" in x][0]
    privs = [x for x in b if "PRIVATE KEY" in x]
    pub_x = "Gb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE"
    priv_d = enc(bytes.fromhex("D4EE72DBF913584AD5B6D8F1F769F8AD3AFE7C28CBF1D4FBE097A88F44755842"))
    write("rfc8410-10.1-ed25519-spki", text=pub101, jwk={"kty": "OKP", "crv": "Ed25519", "x": pub_x})
    write("rfc8410-10.3-ed25519-pkcs8-v1", text=privs[0], jwk={"kty": "OKP", "crv": "Ed25519", "x": pub_x, "d": priv_d})
    write("rfc8410-10.3-ed25519-pkcs8-v2-attr-pub", text=privs[1], jwk={"kty": "OKP", "crv": "Ed25519", "x": pub_x, "d": priv_d})
    cert = [x for x in b if "CERTIFICATE" in x]
    if cert: write("reject-rfc8410-10.2-x25519-cert-66col", text=cert[0])   # erratum 6936: 66-char lines; also not a key

    # --- RFC 9500 §2.1 / §2.3, verbatim ---
    blocks = pem_blocks(r9500)
    rsa = [x for x in blocks if "RSA PRIVATE KEY" in x]
    ecc = [x for x in blocks if "EC PRIVATE KEY" in x]
    names = ["testRSA1024", "testRSA2048", "testRSA4096"]
    for nm, t in zip(names, rsa):
        write("reject-rfc9500-%s-private-pkcs1" % nm, text=t)     # ADR 0021: RSA private keys are rejected
    for nm, t in zip(["testECCP256", "testECCP384", "testECCP521"], ecc):
        write("rfc9500-%s-sec1" % nm, text=t)                      # expected JWK: verify-golden.sh writes it
    # --- RFC 7468 §10 Figure 12 (secp256k1 PKCS#8, inner ECPrivateKey without [0]) and §13 Figure 15 (P-384 SPKI) ---
    r7468 = open(os.path.join(src, "rfc7468.txt")).read()
    b68 = pem_blocks(r7468)
    fig12 = [x for x in b68 if x.startswith("-----BEGIN PRIVATE KEY-----") and "MIGEAgEAMBAGByqGSM49AgEGBSuBBAAK" in x]
    fig15 = [x for x in b68 if x.startswith("-----BEGIN PUBLIC KEY-----") and "MHYwEAYHKoZIzj0CAQYFK4EEACID" in x]
    assert len(fig12) == 1 and len(fig15) == 1, (len(fig12), len(fig15))
    write("rfc7468-fig12-secp256k1-pkcs8", text=fig12[0])          # expected JWK: verify-golden.sh derives it
    write("rfc7468-fig15-p384-spki", text=fig15[0])

    # --- RFC 8410 §7 copy of the v2 key: END line has six dashes (erratum 5459) ---
    s7 = r8410[heading(r8410, "7.  Private Key Format"):heading(r8410, "8.  Human-Readable Algorithm Names")]
    m = re.search(r"(?m)^( *)-----BEGIN PRIVATE KEY-----\n(?:.*\n)*?\1-----END PRIVATE KEY------", s7)
    assert m, "RFC 8410 §7 six-dash example not found"
    ind = m.group(1)
    write("reject-rfc8410-7-six-dash-end", text="\n".join(l[len(ind):] for l in m.group(0).split("\n")) + "\n")
    print("ok", file=sys.stderr)

main(sys.argv[1])
