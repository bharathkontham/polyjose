"""Writes conformance/vectors/keys/*.json, the shared keys.* conformance
vectors, from the committed key fixtures in this directory's siblings
(../openssl, ../rfc, ../negative).

Expected JWKs are the committed .jwk.json files (OpenSSL's own text dumps or
the RFCs) and expected PEM texts the committed fixture files, so nothing comes
from polyjose. DER-only negative vectors are wrapped in PEM here with the
label of the structure they hold (RFC 7468 §2: 64-column base64, LF).

Run from anywhere: python3 -I make-keys-vectors.py
It deletes every *.json in conformance/vectors/keys/ first, so the directory
holds exactly what this script writes.
"""
import base64, json, os

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
def neg_pem(f, label): return wrap(label, open(os.path.join(data, 'negative', f), 'rb').read())

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
]
for name, source, d, pem, jd, jf, what in imports:
    write(name, source, 'PEM import of ' + what + '.', 'keys.import_pem', {'pem': text(d, pem)}, {'ok': True, 'jwk': jwk(jd, jf)})

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
]
for name, source, jd, jf, fmt, d, pem, what in exports:
    write(name, source, 'PEM export of ' + what + '.', 'keys.export_pem', {'jwk': jwk(jd, jf), 'format': fmt}, {'ok': True, 'pem': text(d, pem)})

# --- export refusals (ADR 0018 §3 format matrix) -------------------------
oct_a3 = {"kty": "oct", "alg": "A128KW", "k": "GawgguFyGrWKav7AX4VKUg"}
p256_pub = jwk('rfc', 'rfc7517-a1-ec-p256-spki.jwk.json')
ed_priv = jwk('rfc', 'rfc8410-10.3-ed25519-pkcs8-v1.jwk.json')
p256_priv = jwk('rfc', 'rfc7517-a2-ec-p256-pkcs8.jwk.json')
for name, j, fmt, code, what in [
  ('reject-export-oct-pkcs8', oct_a3, 'pkcs8', 'UnsupportedAlgorithm', 'the RFC 7517 A.3 oct key cannot be exported as PKCS#8: oct keys never cross PEM/DER, so no text can become an HMAC secret (RFC 8725 §2.1, ADR 0018 §3)'),
  ('reject-export-oct-spki', oct_a3, 'spki', 'UnsupportedAlgorithm', 'the RFC 7517 A.3 oct key cannot be exported as SPKI (RFC 8725 §2.1, ADR 0018 §3)'),
  ('reject-export-ec-public-pkcs8', p256_pub, 'pkcs8', 'InvalidKey', 'a public EC key cannot be exported as PKCS#8, a private-key structure (RFC 5958 §2; ADR 0018 §3)'),
  ('reject-export-ed25519-sec1', ed_priv, 'sec1', 'UnsupportedAlgorithm', 'an Ed25519 key cannot be exported as SEC1, which holds only EC keys (RFC 5915 §3)'),
  ('reject-export-ec-pkcs1', p256_priv, 'pkcs1', 'UnsupportedAlgorithm', 'an EC key cannot be exported as PKCS#1, which holds only RSA keys (RFC 8017 App. A.1)'),
]:
    src = 'RFC 7517 App. A.3' if 'oct' in name else 'polyjose'
    write(name, src, 'Export refusal: ' + what + '.', 'keys.export_pem', {'jwk': j, 'format': fmt}, {'ok': False, 'error': code})

# --- the 12 representative import negatives ------------------------------
negs = [
  ('reject-pkcs8-encrypted', 'polyjose', text('openssl', 'reject-ec-p256-pkcs8-encrypted.pem'), 'UnsupportedAlgorithm', 'an ENCRYPTED PRIVATE KEY (EncryptedPrivateKeyInfo, RFC 5958 §3; RFC 7468 §11, made by OpenSSL 4.1.0 with PBES2/AES-256-CBC): encrypted keys are out of scope (ADR 0018 §4)'),
  ('reject-pem-legacy-encrypted', 'polyjose', text('openssl', 'reject-ec-p256-sec1-legacy-encrypted.pem'), 'UnsupportedAlgorithm', 'a legacy Proc-Type: 4,ENCRYPTED EC PRIVATE KEY (RFC 1421 §4.6.1.1, made by OpenSSL 4.1.0): encrypted keys are out of scope (ADR 0018 §4)'),
  ('reject-rsa-private-pkcs1', 'RFC 9500 §2.1', text('rfc', 'reject-rfc9500-testRSA2048-private-pkcs1.pem'), 'UnsupportedAlgorithm', 'RFC 9500 testRSA2048, an RSA PRIVATE KEY (RFC 8017 App. A.1.2): RSA private keys are not supported (ADR 0021)'),
  ('reject-rsa-private-pkcs8', 'polyjose', neg_pem('N67-rsa-private-pkcs8-minimal.der', 'PRIVATE KEY'), 'UnsupportedAlgorithm', 'a PKCS#8 PRIVATE KEY with rsaEncryption, i.e. an RSA private key: refused from the AlgorithmIdentifier (ADR 0021)'),
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
print(n, 'vectors written')
