# Key fixtures for the keys module

Test data for PEM/DER key import and export (`crates/polyjose/src/keys/`). The data lives in `tests/data/keys/{openssl,rfc,negative}`; this `regen/` directory holds the scripts that produced it. OpenSSL and Python are used only to **produce** data. Neither is a dependency of polyjose, and no test runs them: the tests read the committed files, and `tests/keys_fixtures.rs` checks them against each directory's `SHA256SUMS`.

| Dir | Made by | What |
|---|---|---|
| `openssl/` | `gen-openssl-fixtures.sh` (OpenSSL 4.1.0, see `openssl/OPENSSL_VERSION`) | Keys OpenSSL generated: EC P-256/P-384/P-521/secp256k1 as PKCS#8, SEC1 (with and without publicKey) and SPKI (uncompressed and compressed); Ed25519/X25519 as PKCS#8 and SPKI; RSA **public** keys (2048/3072/4096) as SPKI and PKCS#1 RSAPublicKey. `reject-*` files were made to fail; since ADR 0067 the two-prime RSA private ones (2048 bits and more) import, under their old names (see below). `text/` holds `openssl pkey -text` dumps. |
| `openssl/expected/` | `expected-jwks.py` | The expected JWK for each positive OpenSSL file, taken from OpenSSL's own text dump. |
| `rfc/` | `rfc-golden.py`, checked by `verify-golden.sh` | Golden pairs from the RFCs. Verbatim: RFC 8410 §10.1 and §10.3 (PKCS#8 v1, plus v2 with an attribute and publicKey) and RFC 9500 §2.3 (testECCP256/384/521, SEC1) and RFC 7468 §10 Fig. 12 (secp256k1 PKCS#8 whose inner ECPrivateKey has no [0]) and §13 Fig. 15 (P-384 SPKI). Built from published JWKs: RFC 7517 App. A.1/A.2 (EC P-256, RSA public), RFC 8037 App. A.1/A.2 (Ed25519) and A.6 (X25519). Each built file's values match what OpenSSL parses from it (`verify-golden.sh` prints MATCH). RFC 9500's testECCP521 C array lists `qy` as 65 bytes; the JWK pads `y` to 66 octets (RFC 7518 §6.2.1.3). |
| `negative/` | `negative-vectors.py` | 68 must-reject vectors and 3 must-accept PEM variants (the 71 entries of `manifest.json`). `manifest.json` gives each vector's expected stable error code and the rule it breaks. |
| `conformance/vectors/keys/` (repository root) | `make-keys-vectors.py` | The 151 shared `keys.*` conformance vectors (see the table below), built only from the committed files above: expected JWKs are the `.jwk.json` files (the RSA private ones, ADR 0067: OpenSSL's `text/` dump, or the INTEGERs of the RFC 9500 key's DER, checked with integer arithmetic), expected PEM texts the fixture files, expected DER the bodies of those PEM files, DER-only negative vectors are wrapped in PEM with their structure's label, and `generate_for` shapes are the RFC sizes and curves. The only keys it builds itself are the RSA modulus-bound ones (8192 and 8193 bits), with their JWK. |

## Conformance vectors per operation

| Operation | Success | Failure | Total |
|---|---|---|---|
| `keys.import_pem` | 23 | 17 | 40 |
| `keys.export_pem` | 14 | 5 | 19 |
| `keys.import_der` | 24 | 15 | 39 |
| `keys.export_der` | 14 | 6 | 20 |
| `keys.generate_for` | 21 (shape only) | 12 | 33 |
| **All** | **96** | **55** | **151** |

## Expected outcomes for `reject-*` OpenSSL files

| File pattern | Expect | Why |
|---|---|---|
| `reject-rsa2048-3prime-private-*` | `UnsupportedAlgorithm` | ADR 0067 §3: multi-prime RSA private keys (RFC 8017 App. A.1.2 version `multi`) are not supported |
| `reject-*-encrypted*` | `UnsupportedAlgorithm` | Encrypted PKCS#8 (RFC 5958 §3) and legacy RFC 1421 encrypted PEM are out of scope |
| `reject-ed448-*`, `reject-x448-*` | `UnsupportedAlgorithm` | ADR 0006 |
| `reject-ec-brainpoolp256r1-*` | `UnsupportedAlgorithm` | Not a JOSE curve (IANA JWK EC registry) |
| `reject-ec-p256-explicit-*` | `UnsupportedAlgorithm` | specifiedCurve parameters; RFC 5480 §2.1.1 requires namedCurve |
| `reject-rsapss2048-*` (public and private) | `UnsupportedAlgorithm` | id-RSASSA-PSS key OID (RFC 4055) is not supported |
| `reject-rsa1024-*`, `reject-rfc9500-testRSA1024-private-pkcs1.pem` (public and private) | `InvalidKey` | Under 2048 bits (RFC 7518 §3.3, §4.2; ADR 0007; ADR 0067 keeps the bound for private keys) |
| `reject-rfc8410-7-six-dash-end.pem` | `InvalidKey` | RFC 8410 §7's copy of the v2 key ends with six dashes (erratum 5459); RFC 7468 §2 says exactly five |
| `reject-ec-p256-cert.pem`, `reject-rfc8410-10.2-x25519-cert-66col.pem` | `UnsupportedAlgorithm` | `CERTIFICATE` is not a key label (X.509 is out of scope, ADR 0006). The RFC 8410 one also has 66-character lines (erratum 6936) |
| `reject-rsa{2048,3072,4096}-private-*`, `reject-rfc9500-testRSA{2048,4096}-private-pkcs1.pem` | `ok` | ADR 0067: two-prime RSA private keys (PKCS#1 RSAPrivateKey and PKCS#8) import. The files keep the `reject-` names they had under ADR 0021 (fixtures are never renamed); `tests/keys_negative.rs` checks each one imports as a private key whose public half is the matching public fixture, and that PKCS#8 export reproduces the OpenSSL file byte for byte |

## Regenerate
Run from this `regen/` directory; each script writes into its sibling data directory (`../openssl`, `../rfc`, `../negative`).
```sh
sh gen-openssl-fixtures.sh && python3 -I expected-jwks.py
python3 -I rfc-golden.py <dir with rfc7468.txt rfc7517.txt rfc8037.txt rfc8410.txt rfc9500.txt> && sh verify-golden.sh
python3 -I negative-vectors.py
python3 -I make-keys-vectors.py   # after any of the above: rewrites conformance/vectors/keys/
```
`make-keys-vectors.py` is deterministic: rerunning it over unchanged fixtures reproduces the committed vectors byte for byte, and it prints how many it wrote (139). Regenerating the OpenSSL keys gives **new random keys**, so commit the outputs and don't regenerate them in CI. `SHA256SUMS` in each directory pins the committed key files (`*.pem`, `*.der`, and in `negative/` also `manifest.json`). The derived files (`*.jwk.json`, `openssl/expected/`, `openssl/text/`, `openssl/OPENSSL_VERSION`) are not pinned: they are expectations and provenance, and a wrong one fails the test that reads it.
