# Conformance vectors

These are shared test vectors. **Every platform's test suite runs all of them**: Rust, WASM, Node, Kotlin/Android and Swift (ADR 0008, layer 4). That's how polyjose guarantees identical behaviour everywhere.

The format is defined by [`schema.json`](schema.json) (JSON Schema draft 2020-12). Each `*.json` file under `vectors/`, at any depth, holds **exactly one vector**:

```json
{
  "source": "RFC 7638 §3.1",
  "description": "The RFC 7638 §3.1 example: only \"e\", \"kty\" and \"n\" are hashed",
  "operation": "jwk.thumbprint",
  "input": {
    "jwk": { "kty": "RSA", "n": "0vx7agoe...", "e": "AQAB", "alg": "RS256", "kid": "2011-04-29" },
    "hash": "sha-256"
  },
  "expect": {
    "ok": true,
    "thumbprint": "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
    "thumbprint_uri": "urn:ietf:params:oauth:jwk-thumbprint:sha-256:NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
  }
}
```

(`n` is shortened here; the real file is `vectors/jwk-thumbprint/rfc7638-3-1-rsa.json`.) A failure is expected as `"expect": { "ok": false, "error": "InvalidBase64" }`.

## Members

All five top-level members are required and no others are allowed. Every object the schema defines is closed (`additionalProperties: false`).

| Member | Meaning |
|---|---|
| `source` | Where the expected value comes from: an RFC section (`"RFC 4648 §10"`), an upstream suite, or `"polyjose"` for a project-defined negative vector (whose `description` then cites the RFC rule). Every failure message names it. |
| `description` | What the vector checks, in one sentence. If an RFC does not print the expected value, say how it was derived. |
| `operation` | One of the operations below. |
| `input` | The operation's input. |
| `expect` | `{ "ok": true, ...outputs }`, or `{ "ok": false, "error": <code> }` where `<code>` is one of the stable error codes (`Error::CODES` in `crates/polyjose/src/error.rs`). |

## Operations

| Operation | `input` | `expect` when `ok` is true | Can fail |
|---|---|---|---|
| `b64url.encode` | `bytes_hex` | `b64u` | no |
| `b64url.decode` | `b64u` (any string) | `bytes_hex` | yes |
| `jwk.thumbprint` | `jwk` (a JSON object), `hash` (`"sha-256"`) | `thumbprint`, `thumbprint_uri` | yes |
| `jws.sign` | `serialization`, `payload_b64u`, `detached`, `signers` ([below](#jwssign)) | `jws` (exact), or `verify_with` (round trip) | yes |
| `jws.verify` | `jws`, `key`, `allowed_algs`, and optionally `detached_payload_b64u`, `max_input_len`, `max_signatures` ([below](#jwsverify)) | `payload_b64u`, `alg`, `signature_index` | yes |
| `keys.import_pem` | `pem` (any string) ([below](#keysimport_pem)) | `jwk` (a JSON object) | yes |
| `keys.export_pem` | `jwk` (a JSON object), `format` (`"pkcs8"`, `"sec1"`, `"spki"` or `"pkcs1"`) ([below](#keysexport_pem)) | `pem` (exact text) | yes |
| `jwe.encrypt`, `jwe.decrypt`, `jwt.validate` | reserved | reserved | |

A reserved operation's input and output members are defined by the feature that implements it, which adds them to `schema.json` and to every runner. Until then no runner implements it, so a vector that uses it fails.

### How bytes are written

- **Codec operations (`b64url.*`, `jwk.thumbprint`): lowercase hex** (`bytes_hex`: two digits per octet, `""` for none), never base64url, so the base64url codec is never checked against itself.
- **`keys.*` operations: PEM text and JWK objects**, never raw octets. A PEM block is a JSON string with `\n` line endings; JWK members are canonical base64url as RFC 7518 §6 and RFC 8037 §2 define them.
- **`jws.*` operations: canonical base64url** (members ending in `_b64u`). This is deliberate: the codec is no longer under test there (it has its own vectors), and every JWS field is natively base64url (RFC 7515 §2), so the RFC's values are copied as printed. A runner decodes `payload_b64u` and `detached_payload_b64u` to hand octets to the library; a value that doesn't decode canonically fails the vector, it is never an outcome. `protected_b64u` is passed to the library as text, unchanged.

## `jws.sign`

Signs `payload_b64u` (RFC 7515 §5.1) in one serialization.

| Input member | Meaning |
|---|---|
| `serialization` | `"compact"` (RFC 7515 §7.1), `"flattened"` (§7.2.2) or `"general"` (§7.2.1). |
| `payload_b64u` | The JWS Payload octets. With `"b64": false` (RFC 7797) these octets themselves are signed. |
| `detached` | `true` leaves the payload out of the output (RFC 7515 Appendix F). Required, so every vector says which. |
| `signers` | One or more signers, in output order. Each is `{ "protected_b64u"?, "header"?, "key" }`: |
| `signers[].protected_b64u` | The JWS Protected Header as **exact octets**, `BASE64URL(UTF8(JWS Protected Header))`. The library signs over them verbatim (RFC 7515 §5.1 step 3), which is the only way to reproduce a header such as RFC 7515 A.1's, with its CRLF. |
| `signers[].header` | The JWS Unprotected Header, a JSON object (JSON serializations only). Not signed, so its member order never matters. |
| `signers[].key` | The signing JWK, a JSON object. |

The schema also enforces the serialization's shape: `compact` has exactly one signer, which has `protected_b64u` and no `header`; `flattened` has exactly one signer; `general` has one or more. A JSON signer may have neither header (the library then fails with `InvalidHeader`, no `alg`) or no protected header (RFC 7520 §4.7).

Expect one of:

- **`{ "ok": true, "jws": <jws> }`** for a deterministic algorithm (HMAC, EdDSA): the exact output. A compact JWS is a string, compared exactly. A JSON JWS is an object, compared as a JSON value: member order is ignored (RFC 8259 §4), every string must match octet for octet.
- **`{ "ok": true, "verify_with": { "key", "allowed_algs" } }`** for a randomized algorithm (ECDSA). The runner checks its own output: it has the requested serialization's shape (three compact parts; `signature` without `signatures` for flattened; one `signatures` entry per signer for general), it verifies with `verify_with.key` and `verify_with.allowed_algs` (with the payload passed separately when `detached`), and the verified payload equals `payload_b64u`. Any failure there fails the vector, as does a `verify_with` key that doesn't import.
- **`{ "ok": false, "error": <code> }`.**

RSA signing is not supported (ADR 0021): an RSA private JWK fails at JWK import with `UnsupportedAlgorithm`, and an `RS*`/`PS*` header with a public key fails at sign with `UnsupportedAlgorithm`.

## `jws.verify`

Verifies a JWS with one key and an allow-list (RFC 7515 §5.2, RFC 8725 §3.1), under ADR 0026's processing order.

| Input member | Meaning |
|---|---|
| `jws` | A **string** is a compact JWS (RFC 7515 §7.1). An **object** is a flattened or general JSON JWS (§7.2); the runner passes its JSON text to the library's JSON verify. Otherwise unconstrained, since malformed JWSs are under test. |
| `key` | The verifying JWK, a JSON object. |
| `allowed_algs` | The allow-list: an array of `alg` names, passed as given. An empty list, `"none"` or an unknown name is refused with `AlgorithmNotAllowed`. |
| `detached_payload_b64u` | Optional. The detached payload (RFC 7515 Appendix F); the JWS must then carry none. |
| `max_input_len`, `max_signatures` | Optional limits (ADR 0026 §7). Absent means the library default (1 MiB and 16). |

Expect `{ "ok": true, "payload_b64u", "alg", "signature_index" }`: the payload, the `alg` of the signature that verified, and its index (`0` for compact and flattened; for general, the first signature in array order that verifies with the key, ADR 0026 §3). Or `{ "ok": false, "error": <code> }`.

## Rules for `jws.*` runners

- **Step order.** The first error is the vector's outcome:
  1. `jws.sign`: for each signer in order, import `key` (the library's JWK import), then parse `protected_b64u`, then parse `header`. `jws.verify`: import `key`, then build the options from `allowed_algs`, `detached_payload_b64u` and the limits.
  2. Call the library.

  So a **JWK import error is the vector's result**, compared like any other (for example the RSA private key of RFC 7515 A.2 → `UnsupportedAlgorithm`, ADR 0021).
- **One fault per failure vector.** A failure vector breaks one thing, so the step order above never decides its outcome. The exceptions are vectors that pin ADR 0026's precedence; they put every fault inside `jws` itself.
- **JSON-object `jws`.** Pass the object's JSON text in any formatting. The serialized length then depends on the platform's JSON writer, so a `max_input_len` vector uses a compact `jws` or a limit far from the boundary. A JSON-object `jws` can't contain duplicate member names, because the vector file itself must be I-JSON. Duplicate members can therefore be tested only inside a base64url-encoded protected header.
- Map `serialization` to the binding's compact, flattened and general sign functions, `detached` to its detached option, and the limits to its verify options. Never substitute defaults of your own: an absent limit means the library default (ADR 0030).

## `keys.import_pem`

Imports one RFC 7468 PEM block with the library's PEM key import (ADR 0018 §3). The label selects the structure:

| Label | Structure |
|---|---|
| `PRIVATE KEY` | PKCS#8 (RFC 5958 §2): EC or OKP private key |
| `PUBLIC KEY` | SubjectPublicKeyInfo (RFC 5280 §4.1.2.7): EC, OKP or RSA public key |
| `EC PRIVATE KEY` | SEC1 ECPrivateKey (RFC 5915 §3) |
| `RSA PUBLIC KEY` | PKCS#1 RSAPublicKey (RFC 8017 App. A.1.1) |

Expect `{ "ok": true, "jwk": <object> }`, compared as a JSON value: member order is ignored (RFC 8259 §4) and every string must match exactly. An imported key never has `kty` `oct` and has no `alg`; a runner fails a vector whose import returns an `oct` key, whatever it expects (RFC 8725 §2.1). Or `{ "ok": false, "error": <code> }`:

- `UnsupportedAlgorithm` for well-formed input polyjose does not support: encrypted keys (`ENCRYPTED PRIVATE KEY`, RFC 5958 §3; legacy `Proc-Type: 4,ENCRYPTED`), RSA private keys (ADR 0021), Ed448/X448, non-JOSE curves, specifiedCurve, and labels such as `CERTIFICATE`;
- `InvalidKey` for anything malformed (BER, trailing data, explanatory text around the block, a label around the wrong structure) or invalid (an off-curve point, RSA under 2048 bits).

## `keys.export_pem`

Imports `jwk` with the library's JWK import, then exports it as PEM in `format` (ADR 0018 §3). A JWK import error is the vector's outcome. Expect `{ "ok": true, "pem": <text> }`, compared as a string: 64-character lines, LF line endings and a final newline, in OpenSSL 4's DER layout. Or a failure, by the format matrix:

| `format` | Private key | Public key | `oct` |
|---|---|---|---|
| `spki` | its public half | yes | `UnsupportedAlgorithm` |
| `pkcs8` | EC, OKP | `InvalidKey` | `UnsupportedAlgorithm` |
| `sec1` | EC only; other types `UnsupportedAlgorithm` | `InvalidKey` (EC) | `UnsupportedAlgorithm` |
| `pkcs1` | — | RSA only; other types `UnsupportedAlgorithm` | `UnsupportedAlgorithm` |

The checks run in that order: `oct`, then a key type the format cannot hold, then a public key in a private-key format. Only the key material is exported; `kid`, `use`, `alg` and the other JWK members are dropped.

## Binding readiness

Every vector under `jws-*/`, `third_party/**/jws/` and `keys/`, and every `jws.*` or `keys.*` vector anywhere, must be readable by every binding's own JSON parser unchanged. The Rust runner's `jws_and_keys_vectors_are_binding_ready` test checks it:

- every number is a plain integer (no fraction, no exponent) of magnitude at most 2^32 − 1 (`count` in the schema is a `u32`, as in ADR 0030), so no binding needs a 64-bit-only type or reads a double;
- octets are base64url strings (`*_b64u`), never `*_hex` or raw bytes, and every one a runner decodes is canonical;
- in a `keys.*` vector, every base64url member (`x`, `y`, `d`, `n`, `e`, `k`) of a `jwk` object is canonical.

## Rules for every runner

Each platform's runner (Rust: `crates/polyjose/tests/conformance.rs`) must:

- load every `*.json` file under `vectors/`, recursively, `third_party/` included;
- **fail** on a file that is not schema-valid, including a misspelled or unknown member anywhere: every object the schema defines is closed;
- **fail** on a vector whose `operation` it does not implement, whether `schema.json` reserves it or not. Nothing is skipped;
- **fail** when it finds no vector files, so a wrong path can't pass vacuously;
- run every vector and report every failure, not only the first, each naming the file and its `source`.

The Rust runner also checks `schema.json` against its own tables (`schema_and_runner_agree`), so the schema and the runner can't drift apart.

## Writing vectors

- Name files after what they check, grouped by operation: `vectors/b64url/encode-rfc4648-10-foo.json`, `vectors/jwk-thumbprint/reject-oct-k-padded.json`.
- Key vectors live in `keys/`: `import-*` and `export-*` for successes, `reject-*` for failures. Their expected JWKs and PEM texts are the committed key fixtures (`crates/polyjose/tests/data/keys/`: OpenSSL 4.1.0 output and the RFC golden files), never polyjose output; `source` names the RFC, or OpenSSL for a generated key. `crates/polyjose/tests/data/keys/regen/make-keys-vectors.py` writes them (`python3 -I`); edit the script, not the files. **Until features 0006–0009 bind the keys API, test reports list WASM, Node, Kotlin and Swift as `SKIPPED (API not yet bound)` for them; each binding's runner implements `keys.*` when it binds the API, and the never-skip rule above then applies.**
- JWS vectors are grouped by origin: `jws-rfc7515/` (RFC 7515 Appendix A and F; `source` "RFC 7515 App. A.x" or "RFC 7515 App. F"), `jws-rfc7797/`, `jws-rfc8037/`, `jws-oracle/` (generated independently of polyjose; `source` names the tool and its versions), `jws-negative/` (`source` names the RFC section, CVE or ADR enforced), and `third_party/rfc7520/jws/` (the RFC 7520 §4 cookbook).
- Check every expected value against the RFC text yourself. If the RFC doesn't print the value, derive it independently of polyjose (for example with Python's `hashlib` over the hand-built input) and say so in `description`.
- **Deterministic algorithms** (HMAC, EdDSA) also have `sign` vectors with an exact expected output. **Randomized ones** (ECDSA, JWE) are checked by round trip (`verify_with`) plus a `verify`/`decrypt` vector of the RFC's published output. RS\*/PS\* are verify-only (ADR 0021): only `verify` vectors, and `sign` vectors that expect `UnsupportedAlgorithm`.
- **Negative vectors are mandatory:** tampered signatures, `alg: none`, alg/key mismatch, wrong `crit`, expired JWTs, invalid curve points, non-canonical encodings.
- Imported upstream suites that every platform runs (the RFC 7520 cookbook) live in `vectors/third_party/`, converted to this format, with their licenses alongside them (non-JSON files are ignored).
- **Wycheproof is not here.** It lives in `crates/polyjose/tests/third_party/wycheproof/`, in its upstream format, because it is a Rust-layer suite (ADR 0008 layer 1): it exercises the primitives through polyjose's JOSE layer, and the bindings add nothing to that.
