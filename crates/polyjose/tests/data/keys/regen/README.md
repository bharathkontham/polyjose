# Key fixtures for the keys module

Test data for PEM/DER key import and export (`crates/polyjose/src/keys/`). The data lives in `tests/data/keys/{openssl,rfc,negative}`; this `regen/` directory holds the scripts that produced it. OpenSSL and Python are used only to **produce** data. Neither is a dependency of polyjose, and no test runs them: the tests read the committed files, and `tests/keys_fixtures.rs` checks them against each directory's `SHA256SUMS`.

| Dir | Made by | What |
|---|---|---|
| `openssl/` | `gen-openssl-fixtures.sh` (OpenSSL 4.1.0, see `openssl/OPENSSL_VERSION`) | Keys OpenSSL generated: EC P-256/P-384/P-521/secp256k1 as PKCS#8, SEC1 (with and without publicKey) and SPKI (uncompressed and compressed); Ed25519/X25519 as PKCS#8 and SPKI; RSA **public** keys (2048/3072/4096) as SPKI and PKCS#1 RSAPublicKey. `reject-*` files must fail (see below). `text/` holds `openssl pkey -text` dumps. |
| `openssl/expected/` | `expected-jwks.py` | The expected JWK for each positive OpenSSL file, taken from OpenSSL's own text dump. |
| `rfc/` | `rfc-golden.py`, checked by `verify-golden.sh` | Golden pairs from the RFCs. Verbatim: RFC 8410 §10.1 and §10.3 (PKCS#8 v1, plus v2 with an attribute and publicKey) and RFC 9500 §2.3 (testECCP256/384/521, SEC1) and RFC 7468 §10 Fig. 12 (secp256k1 PKCS#8 whose inner ECPrivateKey has no [0]) and §13 Fig. 15 (P-384 SPKI). Built from published JWKs: RFC 7517 App. A.1/A.2 (EC P-256, RSA public), RFC 8037 App. A.1/A.2 (Ed25519) and A.6 (X25519). Each built file's values match what OpenSSL parses from it (`verify-golden.sh` prints MATCH). RFC 9500's testECCP521 C array lists `qy` as 65 bytes; the JWK pads `y` to 66 octets (RFC 7518 §6.2.1.3). |
| `negative/` | `negative-vectors.py` | 63 must-reject vectors and 3 must-accept PEM variants. `manifest.json` gives each vector's expected stable error code and the rule it breaks. |
| `conformance/vectors/keys/` (repository root) | `make-keys-vectors.py` | The shared `keys.import_pem`/`keys.export_pem` conformance vectors, built only from the committed files above: expected JWKs are the `.jwk.json` files, expected PEM texts the fixture files, and DER-only negative vectors are wrapped in PEM with their structure's label. |

## Expected outcomes for `reject-*` OpenSSL files

| File pattern | Expect | Why |
|---|---|---|
| `reject-rsa*-private-*`, `reject-rfc9500-testRSA*-private-pkcs1.pem` | `UnsupportedAlgorithm` | ADR 0021: no RSA private keys in 0.1.0 |
| `reject-*-encrypted*` | `UnsupportedAlgorithm` | Encrypted PKCS#8 (RFC 5958 §3) and legacy RFC 1421 encrypted PEM are out of scope |
| `reject-ed448-*`, `reject-x448-*` | `UnsupportedAlgorithm` | ADR 0006 |
| `reject-ec-brainpoolp256r1-*` | `UnsupportedAlgorithm` | Not a JOSE curve (IANA JWK EC registry) |
| `reject-ec-p256-explicit-*` | `UnsupportedAlgorithm` | specifiedCurve parameters; RFC 5480 §2.1.1 requires namedCurve |
| `reject-rsapss2048-spki.pem` | `UnsupportedAlgorithm` | id-RSASSA-PSS key OID (RFC 4055) is not supported in 0.1.0 |
| `reject-rsa1024-*` (public) | `InvalidKey` | Under 2048 bits (RFC 7518 §3.3, §4.2; ADR 0007) |
| `reject-rfc8410-7-six-dash-end.pem` | `InvalidKey` | RFC 8410 §7's copy of the v2 key ends with six dashes (erratum 5459); RFC 7468 §2 says exactly five |
| `reject-ec-p256-cert.pem`, `reject-rfc8410-10.2-x25519-cert-66col.pem` | `UnsupportedAlgorithm` | `CERTIFICATE` is not a key label (X.509 is out of scope, ADR 0006). The RFC 8410 one also has 66-character lines (erratum 6936) |

## Regenerate
Run from this `regen/` directory; each script writes into its sibling data directory (`../openssl`, `../rfc`, `../negative`).
```sh
sh gen-openssl-fixtures.sh && python3 -I expected-jwks.py
python3 -I rfc-golden.py <dir with rfc7468.txt rfc7517.txt rfc8037.txt rfc8410.txt rfc9500.txt> && sh verify-golden.sh
python3 -I negative-vectors.py
python3 -I make-keys-vectors.py   # after any of the above: rewrites conformance/vectors/keys/
```
`make-keys-vectors.py` is deterministic: rerunning it over unchanged fixtures reproduces the committed vectors byte for byte. Regenerating the OpenSSL keys gives **new random keys**, so commit the outputs and don't regenerate them in CI. `SHA256SUMS` in each directory pins the committed key files (`*.pem`, `*.der`, and in `negative/` also `manifest.json`). The derived files (`*.jwk.json`, `openssl/expected/`, `openssl/text/`, `openssl/OPENSSL_VERSION`) are not pinned: they are expectations and provenance, and a wrong one fails the test that reads it.
