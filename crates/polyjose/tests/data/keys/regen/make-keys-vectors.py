"""Writes conformance/vectors/keys/*.json, the shared keys.* conformance
vectors, from the committed key fixtures in this directory's siblings
(../openssl, ../rfc, ../negative).

Expected JWKs are the committed .jwk.json files (OpenSSL's own text dumps or
the RFCs) and expected PEM texts the committed fixture files, so nothing comes
from polyjose. The RSA private JWKs (ADR 0067) are read here from committed
fixtures too: an OpenSSL key's from its `openssl pkey -text` dump
(../openssl/text/), the RFC 9500 key's from the nine INTEGERs of its
RSAPrivateKey DER (RFC 8017 App. A.1.2), and each is checked with integer
arithmetic (n = p * q, d * e = 1 mod lcm(p - 1, q - 1), the CRT values). DER-only negative vectors are wrapped in PEM here with the
label of the structure they hold (RFC 7468 §2: 64-column base64, LF). The
keys.*_der vectors carry the same fixtures' DER, the body of each PEM file
decoded here, as canonical base64url (der_b64u), with the format its label
names.

Run from anywhere: python3 -I make-keys-vectors.py
It deletes every *.json in conformance/vectors/keys/ first, so the directory
holds exactly what this script writes.
"""
import base64, json, math, os, re

here = os.path.dirname(os.path.abspath(__file__))
data = os.path.dirname(here)                       # tests/data/keys
repo = os.path.normpath(os.path.join(data, '..', '..', '..', '..', '..'))
out = os.path.join(repo, 'conformance', 'vectors', 'keys')
os.makedirs(out, exist_ok=True)
for f in os.listdir(out):
    if f.endswith('.json'):
        os.remove(os.path.join(out, f))

def text(d, f): return open(os.path.join(data, d, f), encoding='ascii').read()
def jwk(d, f): return json.load(open(os.path.join(data, d, f)))
def wrap(label, der):
    b = base64.b64encode(der).decode()
    lines = [b[i:i+64] for i in range(0, len(b), 64)]
    return f'-----BEGIN {label}-----\n' + '\n'.join(lines) + f'\n-----END {label}-----\n'
def neg_der(f): return open(os.path.join(data, 'negative', f), 'rb').read()
def neg_pem(f, label): return wrap(label, neg_der(f))
def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b'=').decode()
# The structure each RFC 7468 label names, as a keys.* format.
# An EncryptedPrivateKeyInfo is offered where a PKCS#8 is expected (RFC 5958 §3).
FORMATS = {'ENCRYPTED PRIVATE KEY': 'pkcs8', 'PRIVATE KEY': 'pkcs8', 'EC PRIVATE KEY': 'sec1', 'PUBLIC KEY': 'spki', 'RSA PUBLIC KEY': 'pkcs1', 'RSA PRIVATE KEY': 'pkcs1'}
def unwrap(pem):
    """The label and DER of a single strict PEM block (RFC 7468 §3)."""
    lines = pem.split('\n')
    assert lines[-1] == '' and lines[0].startswith('-----BEGIN ') and lines[0].endswith('-----'), pem[:40]
    label = lines[0][len('-----BEGIN '):-len('-----')]
    assert lines[-2] == f'-----END {label}-----', pem[-40:]
    return label, base64.b64decode(''.join(lines[1:-2]), validate=True)
def der_input(pem, fmt=None):
    label, der = unwrap(pem)
    return {'der_b64u': b64u(der), 'format': fmt or FORMATS[label]}

# --- RSA private JWKs (RFC 7518 §6.3.2) from the committed fixtures ------
def uint(i): return b64u(i.to_bytes((i.bit_length() + 7) // 8, 'big'))   # Base64urlUInt, RFC 7518 §2
def rsa_private_jwk(n, e, d, p, q, dp, dq, qi):
    """The JWK of a two-prime RSA key, after checking it (RFC 8017 §3.2)."""
    assert n == p * q and (d * e) % math.lcm(p - 1, q - 1) == 1
    assert dp == d % (p - 1) and dq == d % (q - 1) and (qi * q) % p == 1
    return {'kty': 'RSA', 'n': uint(n), 'e': uint(e), 'd': uint(d), 'p': uint(p), 'q': uint(q), 'dp': uint(dp), 'dq': uint(dq), 'qi': uint(qi)}
def der_integers(der):
    """The INTEGERs of a DER SEQUENCE of non-negative INTEGERs (X.690 §8.3), as RSAPrivateKey is."""
    def read(buf, i):
        tag, k = buf[i], buf[i + 1]; i += 2
        if k & 0x80:
            octets = k & 0x7f; k = int.from_bytes(buf[i:i + octets], 'big'); i += octets
        return tag, buf[i:i + k], i + k
    tag, body, end = read(der, 0)
    assert tag == 0x30 and end == len(der)
    out, i = [], 0
    while i < len(body):
        tag, value, i = read(body, i)
        assert tag == 0x02 and not value[0] & 0x80
        out.append(int.from_bytes(value, 'big'))
    return out
def rsa_jwk_from_pkcs1(pem):
    """RFC 8017 App. A.1.2: version 0 (two-prime), n, e, d, p, q, dp, dq, qi."""
    label, der = unwrap(pem)
    assert label == 'RSA PRIVATE KEY'
    version, *values = der_integers(der)
    assert version == 0 and len(values) == 8
    return rsa_private_jwk(*values)
def rsa_jwk_from_openssl_text(f):
    """OpenSSL's own parse of a two-prime key (`openssl pkey -text -noout`)."""
    t = text('openssl', os.path.join('text', f))
    assert '2 primes' in t
    def block(label):
        m = re.search(r'^' + label + r':\s*\n((?:\s+[0-9a-f:]+\n)+)', t, re.M)
        return int(re.sub(r'[\s:]', '', m.group(1)), 16)
    e = int(re.search(r'^publicExponent: (\d+)', t, re.M).group(1))
    return rsa_private_jwk(block('modulus'), e, block('privateExponent'), block('prime1'), block('prime2'), block('exponent1'), block('exponent2'), block('coefficient'))
rfc9500_rsa2048 = rsa_jwk_from_pkcs1(text('rfc', 'reject-rfc9500-testRSA2048-private-pkcs1.pem'))
ossl_rsa2048 = rsa_jwk_from_openssl_text('reject-rsa2048-private-pkcs8.txt')
assert ossl_rsa2048 == rsa_jwk_from_openssl_text('reject-rsa2048-private-pkcs1.txt')
assert ossl_rsa2048 == rsa_jwk_from_pkcs1(text('openssl', 'reject-rsa2048-private-pkcs1.pem'))
def expected_jwk(jd, jf):
    """A committed .jwk.json file, or (jd None) a JWK derived above."""
    return jf if jd is None else jwk(jd, jf)

OSSL = 'OpenSSL 4.1.0 (polyjose key fixtures)'
n = 0
def write(name, source, description, op, inp, expect):
    global n
    v = {'source': source, 'description': description, 'operation': op, 'input': inp, 'expect': expect}
    with open(os.path.join(out, name + '.json'), 'w', encoding='utf-8') as fh:
        json.dump(v, fh, indent=2, ensure_ascii=False); fh.write('\n')
    n += 1

# --- imports: one per key type and format -------------------------------
imports = [
  # (name, source, dir, pem file, jwk dir, jwk file, what)
  ('import-ec-p256-pkcs8', 'RFC 7517 App. A.2', 'rfc', 'rfc7517-a2-ec-p256-pkcs8.pem', 'rfc', 'rfc7517-a2-ec-p256-pkcs8.jwk.json', 'the RFC 7517 A.2 P-256 private key as PKCS#8 (RFC 5958 §2, inner RFC 5915 ECPrivateKey); the PEM was built from the published JWK and checked with OpenSSL'),
  ('import-ec-p256-sec1', 'RFC 9500 §2.3', 'rfc', 'rfc9500-testECCP256-sec1.pem', 'rfc', 'rfc9500-testECCP256-sec1.jwk.json', 'RFC 9500 testECCP256 as a SEC1 EC PRIVATE KEY (RFC 5915 §3)'),
  ('import-ec-p256-spki', 'RFC 7517 App. A.1', 'rfc', 'rfc7517-a1-ec-p256-spki.pem', 'rfc', 'rfc7517-a1-ec-p256-spki.jwk.json', 'the RFC 7517 A.1 P-256 public key as SPKI (RFC 5480 §2); the PEM was built from the published JWK and checked with OpenSSL'),
  ('import-ec-p256-spki-compressed', OSSL, 'openssl', 'ec-p256-spki-compressed.pem', 'openssl/expected', 'ec-p256-spki.jwk.json', 'a P-256 SPKI with a compressed point (RFC 5480 §2.2), decompressed into x and y; expected JWK from openssl pkey -text'),
  ('import-ec-p256-sec1-no-public-key', OSSL, 'openssl', 'ec-p256-sec1-nopub.pem', 'openssl/expected', 'ec-p256-sec1-nopub.jwk.json', 'a SEC1 ECPrivateKey without the optional [1] publicKey (RFC 5915 §3): x and y are derived from d; expected JWK from openssl pkey -text'),
  ('import-ec-p384-pkcs8', OSSL, 'openssl', 'ec-p384-pkcs8.pem', 'openssl/expected', 'ec-p384-pkcs8.jwk.json', 'a P-384 private key as PKCS#8 (RFC 5958 §2); expected JWK from openssl pkey -text'),
  ('import-ec-p384-sec1', 'RFC 9500 §2.3', 'rfc', 'rfc9500-testECCP384-sec1.pem', 'rfc', 'rfc9500-testECCP384-sec1.jwk.json', 'RFC 9500 testECCP384 as a SEC1 EC PRIVATE KEY (RFC 5915 §3)'),
  ('import-ec-p384-spki', 'RFC 7468 §13', 'rfc', 'rfc7468-fig15-p384-spki.pem', 'rfc', 'rfc7468-fig15-p384-spki.jwk.json', 'RFC 7468 Figure 15, a P-384 SPKI'),
  ('import-ec-p521-pkcs8', OSSL, 'openssl', 'ec-p521-pkcs8.pem', 'openssl/expected', 'ec-p521-pkcs8.jwk.json', 'a P-521 private key as PKCS#8 (RFC 5958 §2); expected JWK from openssl pkey -text'),
  ('import-ec-p521-sec1', 'RFC 9500 §2.3', 'rfc', 'rfc9500-testECCP521-sec1.pem', 'rfc', 'rfc9500-testECCP521-sec1.jwk.json', 'RFC 9500 testECCP521 as a SEC1 EC PRIVATE KEY (RFC 5915 §3); y is padded to 66 octets (RFC 7518 §6.2.1.3)'),
  ('import-ec-p521-spki', OSSL, 'openssl', 'ec-p521-spki.pem', 'openssl/expected', 'ec-p521-spki.jwk.json', 'a P-521 public key as SPKI (RFC 5480 §2); expected JWK from openssl pkey -text'),
  ('import-ec-secp256k1-pkcs8', 'RFC 7468 §10', 'rfc', 'rfc7468-fig12-secp256k1-pkcs8.pem', 'rfc', 'rfc7468-fig12-secp256k1-pkcs8.jwk.json', 'RFC 7468 Figure 12, a secp256k1 PKCS#8 whose inner ECPrivateKey omits [0] (RFC 5915 erratum 5008)'),
  ('import-ec-secp256k1-sec1', OSSL, 'openssl', 'ec-secp256k1-sec1.pem', 'openssl/expected', 'ec-secp256k1-sec1.jwk.json', 'a secp256k1 private key (RFC 8812 §3.1) as SEC1 (RFC 5915 §3); expected JWK from openssl pkey -text'),
  ('import-ec-secp256k1-spki', OSSL, 'openssl', 'ec-secp256k1-spki.pem', 'openssl/expected', 'ec-secp256k1-spki.jwk.json', 'a secp256k1 public key as SPKI; expected JWK from openssl pkey -text'),
  ('import-ed25519-pkcs8', 'RFC 8410 §10.3', 'rfc', 'rfc8410-10.3-ed25519-pkcs8-v1.pem', 'rfc', 'rfc8410-10.3-ed25519-pkcs8-v1.jwk.json', 'the RFC 8410 §10.3 Ed25519 PKCS#8 v1 key; x is derived from d (RFC 8032 §5.1.5) and equals the §10.1 key'),
  ('import-ed25519-pkcs8-v2', 'RFC 8410 §10.3', 'rfc', 'rfc8410-10.3-ed25519-pkcs8-v2-attr-pub.pem', 'rfc', 'rfc8410-10.3-ed25519-pkcs8-v2-attr-pub.jwk.json', 'the RFC 8410 §10.3 v2 key with an attribute (ignored) and a publicKey that must match d (RFC 5958 §2)'),
  ('import-ed25519-spki', 'RFC 8410 §10.1', 'rfc', 'rfc8410-10.1-ed25519-spki.pem', 'rfc', 'rfc8410-10.1-ed25519-spki.jwk.json', 'the RFC 8410 §10.1 Ed25519 SPKI'),
  ('import-x25519-pkcs8', 'RFC 8037 App. A.6', 'rfc', 'rfc8037-a6-x25519-pkcs8.pem', 'rfc', 'rfc8037-a6-x25519-pkcs8.jwk.json', 'the RFC 8037 A.6 ephemeral X25519 key (RFC 7748 §6.1 Alice) as PKCS#8 (RFC 8410 §7); built from the published JWK and checked with OpenSSL'),
  ('import-x25519-spki', 'RFC 8037 App. A.6', 'rfc', 'rfc8037-a6-x25519-bob-spki.pem', 'rfc', 'rfc8037-a6-x25519-bob-spki.jwk.json', "the RFC 8037 A.6 recipient's X25519 public key (RFC 7748 §6.1 Bob) as SPKI (RFC 8410 §4); built from the published JWK and checked with OpenSSL"),
  ('import-rsa-spki', 'RFC 7517 App. A.1', 'rfc', 'rfc7517-a1-rsa-spki.pem', 'rfc', 'rfc7517-a1-rsa-spki.jwk.json', 'the RFC 7517 A.1 RSA public key as SPKI with rsaEncryption and NULL (RFC 3279 §2.3.1); built from the published JWK and checked with OpenSSL'),
  ('import-rsa-pkcs1', 'RFC 7517 App. A.1', 'rfc', 'rfc7517-a1-rsa-pkcs1-pub.pem', 'rfc', 'rfc7517-a1-rsa-pkcs1-pub.jwk.json', 'the RFC 7517 A.1 RSA public key as a PKCS#1 RSA PUBLIC KEY (RFC 8017 App. A.1.1)'),
  ('import-rsa-private-pkcs1', 'RFC 9500 §2.1; ADR 0067', 'rfc', 'reject-rfc9500-testRSA2048-private-pkcs1.pem', None, rfc9500_rsa2048, 'RFC 9500 testRSA2048, a two-prime RSA PRIVATE KEY (RFC 8017 App. A.1.2), as an RSA private JWK with all eight members (RFC 7518 §6.3.2; ADR 0067 §2); the expected members are the INTEGERs of the RFC\'s DER, read and checked (n = p q, the CRT values) by the generator'),
  ('import-rsa-private-pkcs8', OSSL + '; ADR 0067', 'openssl', 'reject-rsa2048-private-pkcs8.pem', None, ossl_rsa2048, 'a 2048-bit two-prime RSA private key as PKCS#8 with rsaEncryption (RFC 5958 §2, RFC 8017 App. A.1.2), as an RSA private JWK (RFC 7518 §6.3.2; ADR 0067 §2); expected JWK from openssl pkey -text'),
]
for name, source, d, pem, jd, jf, what in imports:
    write(name, source, 'PEM import of ' + what + '.', 'keys.import_pem', {'pem': text(d, pem)}, {'ok': True, 'jwk': expected_jwk(jd, jf)})

# --- exports: one per key type, plus each format ------------------------
exports = [
  ('export-ec-p256-pkcs8', 'RFC 7517 App. A.2', 'rfc', 'rfc7517-a2-ec-p256-pkcs8.jwk.json', 'pkcs8', 'rfc', 'rfc7517-a2-ec-p256-pkcs8.pem', 'the RFC 7517 A.2 P-256 private JWK as PKCS#8 v1 with the inner [1] and no [0] (ADR 0018 §3, OpenSSL 4 layout)'),
  ('export-ec-p256-sec1', 'RFC 7517 App. A.2', 'rfc', 'rfc7517-a2-ec-p256-sec1.jwk.json', 'sec1', 'rfc', 'rfc7517-a2-ec-p256-sec1.pem', 'the RFC 7517 A.2 P-256 private JWK as SEC1 with [0] and [1] (RFC 5915 §3)'),
  ('export-ec-p256-private-to-spki', 'RFC 7517 App. A.2', 'rfc', 'rfc7517-a2-ec-p256-pkcs8.jwk.json', 'spki', 'rfc', 'rfc7517-a1-ec-p256-spki.pem', 'the RFC 7517 A.2 private JWK as SPKI: its public half, the A.1 key, with an uncompressed point (RFC 5480 §2.2)'),
  ('export-ec-p384-sec1', 'RFC 9500 §2.3', 'rfc', 'rfc9500-testECCP384-sec1.jwk.json', 'sec1', 'rfc', 'rfc9500-testECCP384-sec1.pem', 'RFC 9500 testECCP384 as SEC1, byte for byte the RFC text'),
  ('export-ec-p521-sec1', 'RFC 9500 §2.3', 'rfc', 'rfc9500-testECCP521-sec1.jwk.json', 'sec1', 'rfc', 'rfc9500-testECCP521-sec1.pem', 'RFC 9500 testECCP521 as SEC1, byte for byte the RFC text'),
  ('export-ec-secp256k1-pkcs8', 'RFC 7468 §10', 'rfc', 'rfc7468-fig12-secp256k1-pkcs8.jwk.json', 'pkcs8', 'rfc', 'rfc7468-fig12-secp256k1-pkcs8.pem', 'the RFC 7468 Figure 12 secp256k1 key as PKCS#8, byte for byte the RFC text'),
  ('export-ed25519-pkcs8', 'RFC 8410 §10.3', 'rfc', 'rfc8410-10.3-ed25519-pkcs8-v1.jwk.json', 'pkcs8', 'rfc', 'rfc8410-10.3-ed25519-pkcs8-v1.pem', 'the RFC 8410 §10.3 Ed25519 key as PKCS#8 v1 (RFC 8410 §7), byte for byte the RFC text'),
  ('export-ed25519-spki', 'RFC 8410 §10.1', 'rfc', 'rfc8410-10.1-ed25519-spki.jwk.json', 'spki', 'rfc', 'rfc8410-10.1-ed25519-spki.pem', 'the RFC 8410 §10.1 Ed25519 public key as SPKI, byte for byte the RFC text'),
  ('export-x25519-pkcs8', 'RFC 8037 App. A.6', 'rfc', 'rfc8037-a6-x25519-pkcs8.jwk.json', 'pkcs8', 'rfc', 'rfc8037-a6-x25519-pkcs8.pem', 'the RFC 8037 A.6 X25519 private key as PKCS#8 v1 (RFC 8410 §7)'),
  ('export-x25519-spki', 'RFC 8037 App. A.6', 'rfc', 'rfc8037-a6-x25519-bob-spki.jwk.json', 'spki', 'rfc', 'rfc8037-a6-x25519-bob-spki.pem', 'the RFC 8037 A.6 X25519 public key as SPKI (RFC 8410 §4)'),
  ('export-rsa-spki', 'RFC 7517 App. A.1', 'rfc', 'rfc7517-a1-rsa-spki.jwk.json', 'spki', 'rfc', 'rfc7517-a1-rsa-spki.pem', 'the RFC 7517 A.1 RSA public key as SPKI (RFC 3279 §2.3.1)'),
  ('export-rsa-pkcs1', 'RFC 7517 App. A.1', 'rfc', 'rfc7517-a1-rsa-pkcs1-pub.jwk.json', 'pkcs1', 'rfc', 'rfc7517-a1-rsa-pkcs1-pub.pem', 'the RFC 7517 A.1 RSA public key as PKCS#1 RSAPublicKey (RFC 8017 App. A.1.1)'),
  ('export-rsa-private-pkcs8', OSSL + '; ADR 0067', None, ossl_rsa2048, 'pkcs8', 'openssl', 'reject-rsa2048-private-pkcs8.pem', 'a 2048-bit RSA private JWK (its members from openssl pkey -text) as PKCS#8 with rsaEncryption and NULL around its RSAPrivateKey (RFC 5958 §2, RFC 8017 App. A.1.2; ADR 0067 §2), byte for byte the OpenSSL fixture it came from'),
  ('export-rsa-private-to-spki', OSSL + '; ADR 0067', None, ossl_rsa2048, 'spki', 'openssl', 'rsa2048-spki.pem', 'the same RSA private JWK as SPKI: its public half (RFC 3279 §2.3.1), byte for byte openssl pkey -pubout of the fixture'),
]
for name, source, jd, jf, fmt, d, pem, what in exports:
    write(name, source, 'PEM export of ' + what + '.', 'keys.export_pem', {'jwk': expected_jwk(jd, jf), 'format': fmt}, {'ok': True, 'pem': text(d, pem)})

# --- export refusals (ADR 0018 §3 format matrix) -------------------------
oct_a3 = {"kty": "oct", "alg": "A128KW", "k": "GawgguFyGrWKav7AX4VKUg"}
p256_pub = jwk('rfc', 'rfc7517-a1-ec-p256-spki.jwk.json')
ed_priv = jwk('rfc', 'rfc8410-10.3-ed25519-pkcs8-v1.jwk.json')
p256_priv = jwk('rfc', 'rfc7517-a2-ec-p256-pkcs8.jwk.json')
export_refusals = []
for name, j, fmt, code, what in [
  ('reject-export-oct-pkcs8', oct_a3, 'pkcs8', 'UnsupportedAlgorithm', 'the RFC 7517 A.3 oct key cannot be exported as PKCS#8: oct keys never cross PEM/DER, so no text can become an HMAC secret (RFC 8725 §2.1, ADR 0018 §3)'),
  ('reject-export-oct-spki', oct_a3, 'spki', 'UnsupportedAlgorithm', 'the RFC 7517 A.3 oct key cannot be exported as SPKI (RFC 8725 §2.1, ADR 0018 §3)'),
  ('reject-export-ec-public-pkcs8', p256_pub, 'pkcs8', 'InvalidKey', 'a public EC key cannot be exported as PKCS#8, a private-key structure (RFC 5958 §2; ADR 0018 §3)'),
  ('reject-export-ed25519-sec1', ed_priv, 'sec1', 'UnsupportedAlgorithm', 'an Ed25519 key cannot be exported as SEC1, which holds only EC keys (RFC 5915 §3)'),
  ('reject-export-ec-pkcs1', p256_priv, 'pkcs1', 'UnsupportedAlgorithm', 'an EC key cannot be exported as PKCS#1, which holds only RSA keys (RFC 8017 App. A.1)'),
]:
    src = 'RFC 7517 App. A.3' if 'oct' in name else 'polyjose'
    write(name, src, 'Export refusal: ' + what + '.', 'keys.export_pem', {'jwk': j, 'format': fmt}, {'ok': False, 'error': code})
    export_refusals.append((name, src, j, fmt, code, what))

# --- the representative import negatives ---------------------------------
negs = [
  ('reject-pkcs8-encrypted', 'polyjose', text('openssl', 'reject-ec-p256-pkcs8-encrypted.pem'), 'UnsupportedAlgorithm', 'an ENCRYPTED PRIVATE KEY (EncryptedPrivateKeyInfo, RFC 5958 §3; RFC 7468 §11, made by OpenSSL 4.1.0 with PBES2/AES-256-CBC): encrypted keys are out of scope (ADR 0018 §4)'),
  ('reject-pem-legacy-encrypted', 'polyjose', text('openssl', 'reject-ec-p256-sec1-legacy-encrypted.pem'), 'UnsupportedAlgorithm', 'a legacy Proc-Type: 4,ENCRYPTED EC PRIVATE KEY (RFC 1421 §4.6.1.1, made by OpenSSL 4.1.0): encrypted keys are out of scope (ADR 0018 §4)'),
  ('reject-rsa-private-pkcs8-truncated', 'polyjose', neg_pem('N67-rsa-private-pkcs8-minimal.der', 'PRIVATE KEY'), 'InvalidKey', 'a PKCS#8 PRIVATE KEY with rsaEncryption whose RSAPrivateKey holds only version, n (RFC 7517 A.1\'s) and e, without the private INTEGERs RFC 8017 App. A.1.2 requires: malformed (ADR 0067 §2)'),
  ('reject-rsa-3-prime-pkcs1', 'polyjose', text('openssl', 'reject-rsa2048-3prime-private-pkcs1.pem'), 'UnsupportedAlgorithm', 'a 2048-bit three-prime RSA PRIVATE KEY (version 1 with otherPrimeInfos, RFC 8017 App. A.1.2), made by OpenSSL 4.1.0: multi-prime RSA keys are not supported (ADR 0067 §3)'),
  ('reject-rsa-3-prime-pkcs8', 'polyjose', text('openssl', 'reject-rsa2048-3prime-private-pkcs8.pem'), 'UnsupportedAlgorithm', 'a 2048-bit three-prime RSA private key as PKCS#8 (RFC 5958 §2, RFC 8017 App. A.1.2), made by OpenSSL 4.1.0: multi-prime RSA keys are not supported (ADR 0067 §3)'),
  ('reject-rsa-private-1024-bits', 'RFC 9500 §2.1', text('rfc', 'reject-rfc9500-testRSA1024-private-pkcs1.pem'), 'InvalidKey', 'RFC 9500 testRSA1024, a 1024-bit RSA PRIVATE KEY: RSA keys must be at least 2048 bits, private ones too (RFC 7518 §3.3, §4.2; ADR 0007, ADR 0067 §2)'),
  ('reject-ber-indefinite-length', 'polyjose', neg_pem('N03-len-indefinite.der', 'PRIVATE KEY'), 'InvalidKey', 'the RFC 8037 A.1 Ed25519 PKCS#8 with an indefinite outer length, a BER-only encoding (X.690 §10.1, §8.1.3.6; ADR 0018 §2)'),
  ('reject-trailing-der-garbage', 'polyjose', text('negative', 'P16-trailing-der-garbage.pem'), 'InvalidKey', 'valid PEM armor around the RFC 8037 A.1 Ed25519 PKCS#8 followed by one 0x00 octet: no data may follow the outermost element (X.690 §8.1.1, RFC 5958 §2)'),
  ('reject-text-before-begin', 'polyjose', text('negative', 'P07-text-before-begin.pem'), 'InvalidKey', 'explanatory text before the BEGIN line, which RFC 7468 §2 permits and polyjose deliberately rejects (ADR 0018 §2)'),
  ('reject-public-key-label-around-pkcs8', 'polyjose', text('negative', 'P14-label-public-key-body-pkcs8.pem'), 'InvalidKey', 'a PUBLIC KEY label (RFC 7468 §13) around a PKCS#8 body: the label selects SPKI and the body is not one, so the private key is never read (ADR 0018 §2)'),
  ('reject-ec-point-off-curve', 'polyjose', neg_pem('N31-point-off-curve.der', 'PUBLIC KEY'), 'InvalidKey', 'the RFC 7517 A.1 P-256 SPKI with the last octet of y flipped, a point not on the curve (RFC 8725 §3.4, ADR 0041 §4)'),
  ('reject-rsa-1024-bits', 'polyjose', text('openssl', 'reject-rsa1024-spki.pem'), 'InvalidKey', 'a 1024-bit RSA SPKI made by OpenSSL 4.1.0: RSA keys must be at least 2048 bits (RFC 7518 §3.3, §4.2; ADR 0007)'),
  ('reject-ed448', 'polyjose', text('openssl', 'reject-ed448-pkcs8.pem'), 'UnsupportedAlgorithm', 'an Ed448 PKCS#8 (id-Ed448, RFC 8410 §3) made by OpenSSL 4.1.0: Ed448 is not supported (ADR 0006)'),
  ('reject-certificate', 'polyjose', text('openssl', 'reject-ec-p256-cert.pem'), 'UnsupportedAlgorithm', 'a CERTIFICATE block (RFC 7468 §5): not a key label, refused from the BEGIN line (ADR 0018 §2)'),
]
for name, src, pem, code, what in negs:
    write(name, src, 'PEM import rejects ' + what + '.', 'keys.import_pem', {'pem': pem}, {'ok': False, 'error': code})

# --- DER imports: the same fixtures, as DER in the format of their label ---
for name, source, d, pem, jd, jf, what in imports:
    write(name.replace('import-', 'import-der-', 1), source, 'DER import of ' + what + '.', 'keys.import_der', der_input(text(d, pem)), {'ok': True, 'jwk': expected_jwk(jd, jf)})

# --- DER import negatives: the import negatives whose fault is in the DER --
der_negs = {
  'reject-pkcs8-encrypted': 'an EncryptedPrivateKeyInfo (RFC 5958 §3, made by OpenSSL 4.1.0 with PBES2/AES-256-CBC) as pkcs8: encrypted keys are out of scope (ADR 0018 §4)',
  'reject-rsa-private-pkcs8-truncated': 'a PKCS#8 with rsaEncryption whose RSAPrivateKey holds only version, n (RFC 7517 A.1\'s) and e, without the private INTEGERs RFC 8017 App. A.1.2 requires: malformed (ADR 0067 §2)',
  'reject-rsa-3-prime-pkcs1': 'a 2048-bit three-prime RSAPrivateKey (version 1 with otherPrimeInfos, RFC 8017 App. A.1.2), made by OpenSSL 4.1.0, as pkcs1: multi-prime RSA keys are not supported (ADR 0067 §3)',
  'reject-rsa-3-prime-pkcs8': 'a 2048-bit three-prime RSA private key as PKCS#8 (RFC 5958 §2), made by OpenSSL 4.1.0: multi-prime RSA keys are not supported (ADR 0067 §3)',
  'reject-rsa-private-1024-bits': 'RFC 9500 testRSA1024, a 1024-bit RSAPrivateKey, as pkcs1: RSA keys must be at least 2048 bits, private ones too (RFC 7518 §3.3, §4.2; ADR 0007, ADR 0067 §2)',
  'reject-ber-indefinite-length': 'the RFC 8037 A.1 Ed25519 PKCS#8 with an indefinite outer length, a BER-only encoding (X.690 §10.1, §8.1.3.6; ADR 0018 §2)',
  'reject-trailing-der-garbage': 'the RFC 8037 A.1 Ed25519 PKCS#8 followed by one 0x00 octet: no data may follow the outermost element (X.690 §8.1.1, RFC 5958 §2)',
  'reject-ec-point-off-curve': 'the RFC 7517 A.1 P-256 SPKI with the last octet of y flipped, a point not on the curve (RFC 8725 §3.4, ADR 0041 §4)',
  'reject-rsa-1024-bits': 'a 1024-bit RSA SPKI made by OpenSSL 4.1.0: RSA keys must be at least 2048 bits (RFC 7518 §3.3, §4.2; ADR 0007)',
  'reject-ed448': 'an Ed448 PKCS#8 (id-Ed448, RFC 8410 §3) made by OpenSSL 4.1.0: Ed448 is not supported (ADR 0006)',
}
for name, src, pem, code, what in negs:
    if name in der_negs:
        write(name.replace('reject-', 'reject-der-', 1), src, 'DER import rejects ' + der_negs[name] + '.', 'keys.import_der', der_input(pem), {'ok': False, 'error': code})

# --- DER exports and export refusals: the PEM ones, as DER ----------------
for name, source, jd, jf, fmt, d, pem, what in exports:
    write(name.replace('export-', 'export-der-', 1), source, 'DER export of ' + what + '.', 'keys.export_der', {'jwk': expected_jwk(jd, jf), 'format': fmt}, {'ok': True, 'der_b64u': der_input(text(d, pem))['der_b64u']})
for name, src, j, fmt, code, what in export_refusals:
    write(name.replace('reject-export-', 'reject-export-der-', 1), src, 'DER export refusal: ' + what + '.', 'keys.export_der', {'jwk': j, 'format': fmt}, {'ok': False, 'error': code})

# --- generate_for: shapes and refusals (ADR 0018 §5) -----------------------
# A generated key is random, so a success vector expects only its shape. The
# shapes are the RFC sizes and curves per algorithm, written out here.
def oct_shape(alg, octets): return {'kty': 'oct', 'alg': alg, 'k_octets': octets}
def curve_shape(kty, crv, alg): return {'kty': kty, 'crv': crv, 'alg': alg}
gen_ok = [
  ('hs256', 'RFC 7518 §3.2', oct_shape('HS256', 32), 'an HS256 key is 32 octets, the size of the SHA-256 output (RFC 7518 §3.2)'),
  ('hs384', 'RFC 7518 §3.2', oct_shape('HS384', 48), 'an HS384 key is 48 octets, the size of the SHA-384 output (RFC 7518 §3.2)'),
  ('hs512', 'RFC 7518 §3.2', oct_shape('HS512', 64), 'an HS512 key is 64 octets, the size of the SHA-512 output (RFC 7518 §3.2)'),
  ('a128kw', 'RFC 7518 §4.4', oct_shape('A128KW', 16), 'an A128KW key is a 128-bit AES key (RFC 7518 §4.4)'),
  ('a192kw', 'RFC 7518 §4.4', oct_shape('A192KW', 24), 'an A192KW key is a 192-bit AES key (RFC 7518 §4.4)'),
  ('a256kw', 'RFC 7518 §4.4', oct_shape('A256KW', 32), 'an A256KW key is a 256-bit AES key (RFC 7518 §4.4)'),
  ('a128gcmkw', 'RFC 7518 §4.7', oct_shape('A128GCMKW', 16), 'an A128GCMKW key is a 128-bit AES key (RFC 7518 §4.7)'),
  ('a192gcmkw', 'RFC 7518 §4.7', oct_shape('A192GCMKW', 24), 'an A192GCMKW key is a 192-bit AES key (RFC 7518 §4.7)'),
  ('a256gcmkw', 'RFC 7518 §4.7', oct_shape('A256GCMKW', 32), 'an A256GCMKW key is a 256-bit AES key (RFC 7518 §4.7)'),
  ('a128gcm', 'RFC 7518 §5.3', oct_shape('A128GCM', 16), 'an A128GCM content encryption key is 128 bits (RFC 7518 §5.3)'),
  ('a192gcm', 'RFC 7518 §5.3', oct_shape('A192GCM', 24), 'an A192GCM content encryption key is 192 bits (RFC 7518 §5.3)'),
  ('a256gcm', 'RFC 7518 §5.3', oct_shape('A256GCM', 32), 'an A256GCM content encryption key is 256 bits (RFC 7518 §5.3)'),
  ('a128cbc-hs256', 'RFC 7518 §5.2.3', oct_shape('A128CBC-HS256', 32), 'an A128CBC-HS256 key is 32 octets, MAC_KEY then ENC_KEY (RFC 7518 §5.2.3)'),
  ('a192cbc-hs384', 'RFC 7518 §5.2.4', oct_shape('A192CBC-HS384', 48), 'an A192CBC-HS384 key is 48 octets (RFC 7518 §5.2.4)'),
  ('a256cbc-hs512', 'RFC 7518 §5.2.5', oct_shape('A256CBC-HS512', 64), 'an A256CBC-HS512 key is 64 octets (RFC 7518 §5.2.5)'),
  ('es256', 'RFC 7518 §3.4', curve_shape('EC', 'P-256', 'ES256'), 'ES256 uses the P-256 curve (RFC 7518 §3.4)'),
  ('es384', 'RFC 7518 §3.4', curve_shape('EC', 'P-384', 'ES384'), 'ES384 uses the P-384 curve (RFC 7518 §3.4)'),
  ('es512', 'RFC 7518 §3.4', curve_shape('EC', 'P-521', 'ES512'), 'ES512 uses the P-521 curve (RFC 7518 §3.4)'),
  ('es256k', 'RFC 8812 §3.2', curve_shape('EC', 'secp256k1', 'ES256K'), 'ES256K uses the secp256k1 curve (RFC 8812 §3.2)'),
  ('eddsa', 'RFC 8037 §3.1', curve_shape('OKP', 'Ed25519', 'EdDSA'), 'EdDSA is generated on Ed25519 (RFC 8037 §3.1), the only EdDSA curve polyjose supports (ADR 0006)'),
  ('ed25519', 'RFC 9864', curve_shape('OKP', 'Ed25519', 'Ed25519'), 'the fully-specified Ed25519 algorithm uses the Ed25519 curve (RFC 9864)'),
]
for name, source, shape, what in gen_ok:
    write('generate-' + name, source, 'Key generation for an algorithm: ' + what + '; the key is random, so only its shape is compared.', 'keys.generate_for', {'alg': shape['alg']}, {'ok': True, 'shape': shape})
gen_refusals = [
  ('ecdh-es', 'ECDH-ES', 'InvalidKey', 'ECDH-ES works on several curves (RFC 7518 §4.6), so a key for it needs a curve, and polyjose never picks one for the caller (ADR 0018 §5)'),
  ('ecdh-es-a128kw', 'ECDH-ES+A128KW', 'InvalidKey', 'ECDH-ES+A128KW works on several curves (RFC 7518 §4.6), so a key for it needs a curve (ADR 0018 §5)'),
  ('rs256', 'RS256', 'UnsupportedAlgorithm', 'RSA keys are never generated (ADR 0067 §3)'),
  ('ps256', 'PS256', 'UnsupportedAlgorithm', 'RSA keys are never generated (ADR 0067 §3)'),
  ('rsa-oaep-256', 'RSA-OAEP-256', 'UnsupportedAlgorithm', 'RSA keys are never generated (ADR 0067 §3)'),
  ('dir', 'dir', 'UnsupportedAlgorithm', 'a dir key is the content encryption key of its enc (RFC 7518 §4.5), so its size is not known from dir'),
  ('pbes2-hs256-a128kw', 'PBES2-HS256+A128KW', 'UnsupportedAlgorithm', 'a PBES2 key is a password (RFC 7518 §4.8), which polyjose does not generate'),
  ('none', 'none', 'UnsupportedAlgorithm', 'none has no key (RFC 7518 §3.6)'),
  ('rsa-oaep', 'RSA-OAEP', 'UnsupportedAlgorithm', 'RSA-OAEP is not implemented (ADR 0022)'),
  ('ed448', 'Ed448', 'UnsupportedAlgorithm', 'Ed448 is not supported (ADR 0006)'),
  ('lowercase', 'es256', 'UnsupportedAlgorithm', 'algorithm names are case-sensitive (RFC 7518 §7.1), so es256 is not ES256'),
  ('empty', '', 'UnsupportedAlgorithm', 'the empty string names no algorithm'),
]
for name, alg, code, what in gen_refusals:
    write('reject-generate-' + name, 'polyjose', 'Key generation refuses ' + json.dumps(alg) + ': ' + what + '.', 'keys.generate_for', {'alg': alg}, {'ok': False, 'error': code})

# --- contract vectors from the 0005 review fixes (B01, F02, F03) -----------
# B01: no format sniffing (ADR 0007); an SPKI is not a OneAsymmetricKey.
write('reject-der-spki-as-pkcs8', 'polyjose', 'DER import rejects the RFC 7517 A.1 P-256 SPKI offered as pkcs8: the caller names the structure and an SPKI is not a OneAsymmetricKey (RFC 5958 §2; ADR 0007, ADR 0018 §2).', 'keys.import_der', der_input(text('rfc', 'rfc7517-a1-ec-p256-spki.pem'), 'pkcs8'), {'ok': False, 'error': 'InvalidKey'})

# F03, as amended by ADR 0067: a PKCS#1 RSAPrivateKey (RFC 8017 App. A.1.2)
# imports only as pkcs1 or under RSA PRIVATE KEY (import-der-rsa-private-pkcs1,
# import-rsa-private-pkcs1). Offered as another structure, or under another
# label, it is that structure's malformed input: no format sniffing (ADR 0007).
rsa_private = open(os.path.join(data, 'openssl', 'reject-rsa2048-private-pkcs1.der'), 'rb').read()
assert neg_der('N68-rsa-private-pkcs1-as-pkcs8.der') == rsa_private == neg_der('N69-rsa-private-pkcs1-as-sec1.der')
for fmt, structure in [('pkcs8', 'a OneAsymmetricKey (RFC 5958 §2)'), ('sec1', 'an ECPrivateKey (RFC 5915 §3)')]:
    write('reject-der-rsa-private-pkcs1-as-' + fmt, 'polyjose', f'DER import rejects a 2048-bit PKCS#1 RSAPrivateKey (RFC 8017 App. A.1.2, made by OpenSSL 4.1.0) offered as {fmt}: the caller names the structure, {structure} is expected and the octets are not one, so it is InvalidKey (ADR 0007, ADR 0018 §2, ADR 0067 §2); the same octets import as pkcs1.', 'keys.import_der', {'der_b64u': b64u(rsa_private), 'format': fmt}, {'ok': False, 'error': 'InvalidKey'})
for f, label, structure in [('P17-label-private-key-body-rsa-pkcs1.pem', 'PRIVATE KEY', 'PKCS#8 (RFC 7468 §10)'), ('P18-label-ec-private-key-body-rsa-pkcs1.pem', 'EC PRIVATE KEY', 'SEC1 (RFC 5915 §4)')]:
    pem = text('negative', f)
    assert unwrap(pem) == (label, rsa_private)
    write('reject-rsa-private-pkcs1-under-' + label.lower().replace(' ', '-') + '-label', 'polyjose', f'PEM import rejects a {label} label around a 2048-bit PKCS#1 RSAPrivateKey body (RFC 8017 App. A.1.2, made by OpenSSL 4.1.0): the label selects {structure} and the body is not one, so it is InvalidKey (ADR 0018 §2, ADR 0067 §2); under RSA PRIVATE KEY the body imports.', 'keys.import_pem', {'pem': pem}, {'ok': False, 'error': 'InvalidKey'})

# F02: RSA moduli are 2048 to 8192 bits (RFC 7518 §3.3 floor; ADR 0007 and
# ADR 0026 §2 ceiling) on every import path. The keys are built here, as in
# tests/keys_rsa_modulus_bounds.rs: an odd modulus of exactly `bits` bits
# (top bit set, 0xA5 filler) and e = 65537. They are structurally valid only,
# which is all an import checks.
def modulus(bits):
    m = bytearray([0xA5] * ((bits + 7) // 8))
    top = (bits - 1) % 8
    m[0] = (1 << top) | (0xA5 & ((1 << top) - 1))
    m[-1] |= 1
    assert int.from_bytes(m, 'big').bit_length() == bits
    return bytes(m)
def tlv(tag, contents):
    """A DER element (X.690 §8.1), its length in the fewest octets (§10.1)."""
    k = len(contents)
    if k < 0x80: return bytes([tag, k]) + contents
    octets = k.to_bytes((k.bit_length() + 7) // 8, 'big')
    return bytes([tag, 0x80 | len(octets)]) + octets + contents
def integer(magnitude):
    """A non-negative DER INTEGER (X.690 §8.3)."""
    return tlv(0x02, (b'\x00' if magnitude[0] & 0x80 else b'') + magnitude)
F4 = b'\x01\x00\x01'
def rsa_pkcs1(m): return tlv(0x30, integer(m) + integer(F4))     # RFC 8017 App. A.1.1
def rsa_spki(m):                                                  # RFC 3279 §2.3.1
    alg = tlv(0x30, tlv(0x06, bytes.fromhex('2a864886f70d010101')) + b'\x05\x00')
    return tlv(0x30, alg + tlv(0x03, b'\x00' + rsa_pkcs1(m)))
def rsa_jwk(m): return {'kty': 'RSA', 'n': b64u(m), 'e': b64u(F4)}
ceiling, over = modulus(8192), modulus(8193)
BOUND = 'RSA moduli are at most 8192 bits (ADR 0007, ADR 0026 §2)'
BUILT = 'built by this generator (odd, top bit set, e = 65537)'
write('import-der-rsa-8192-bits', 'polyjose', f'DER import of an SPKI whose RSA modulus is exactly 8192 bits, the largest accepted ({BOUND}; RFC 7518 §3.3 sets the 2048-bit floor), {BUILT}; the expected JWK holds the same n and e (RFC 7518 §6.3.1).', 'keys.import_der', {'der_b64u': b64u(rsa_spki(ceiling)), 'format': 'spki'}, {'ok': True, 'jwk': rsa_jwk(ceiling)})
write('reject-rsa-8193-bits', 'polyjose', f'PEM import rejects a PUBLIC KEY (an RSA SPKI) whose modulus is 8193 bits, {BUILT}: {BOUND}.', 'keys.import_pem', {'pem': wrap('PUBLIC KEY', rsa_spki(over))}, {'ok': False, 'error': 'InvalidKey'})
write('reject-der-rsa-8193-bits-spki', 'polyjose', f'DER import rejects an SPKI whose RSA modulus is 8193 bits, {BUILT}: {BOUND}.', 'keys.import_der', {'der_b64u': b64u(rsa_spki(over)), 'format': 'spki'}, {'ok': False, 'error': 'InvalidKey'})
write('reject-der-rsa-8193-bits-pkcs1', 'polyjose', f'DER import rejects a PKCS#1 RSAPublicKey whose modulus is 8193 bits, {BUILT}: {BOUND}.', 'keys.import_der', {'der_b64u': b64u(rsa_pkcs1(over)), 'format': 'pkcs1'}, {'ok': False, 'error': 'InvalidKey'})
write('reject-export-der-rsa-8193-bits', 'polyjose', f'An RSA JWK whose n is 8193 bits, {BUILT}, fails at the JWK import before any export: {BOUND}.', 'keys.export_der', {'jwk': rsa_jwk(over), 'format': 'spki'}, {'ok': False, 'error': 'InvalidKey'})
print(n, 'vectors written')
