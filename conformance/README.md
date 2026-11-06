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

The five members below are required, `features` is optional, and no others are allowed. Every object the schema defines is closed (`additionalProperties: false`).

| Member | Meaning |
|---|---|
| `source` | Where the expected value comes from: an RFC section (`"RFC 4648 §10"`), an upstream suite, or `"polyjose"` for a project-defined negative vector (whose `description` then cites the RFC rule). Every failure message names it. |
| `description` | What the vector checks, in one sentence. If an RFC does not print the expected value, say how it was derived. |
| `operation` | One of the operations below. |
| `input` | The operation's input. |
| `expect` | `{ "ok": true, ...outputs }`, or `{ "ok": false, "error": <code> }` where `<code>` is one of the stable error codes (`Error::CODES` in `crates/polyjose/src/error.rs`). |
| `features` | Optional. The polyjose cargo features the vector needs, each at most once: `"fixed-rng"` (the cargo feature `insecure-test-vectors`, ADR 0041 §3) or `"deflate"` (ADR 0017). See [Features](#features). |

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
| `jwe.encrypt` | `serialization`, `enc`, `plaintext_b64u`, `recipients`, and optionally `protected`, `protected_b64u`, `unprotected`, `aad_b64u`, `compress`, `rng_b64u` ([below](#jweencrypt)) | `jwe` (exact), or `decrypt_with` (round trip) | yes |
| `jwe.decrypt` | `jwe`, `key`, `allowed_algs`, `allowed_enc`, and optionally `understood_crit`, `max_input_len`, `max_recipients`, `max_pbes2_count`, `max_decompressed_len` ([below](#jwedecrypt)) | `plaintext_b64u`, `recipient` | yes |
| `jwt.validate` | reserved | reserved | |

A reserved operation's input and output members are defined by the feature that implements it, which adds them to `schema.json` and to every runner. Until then no runner implements it, so a vector that uses it fails.

### How bytes are written

- **Codec operations (`b64url.*`, `jwk.thumbprint`): lowercase hex** (`bytes_hex`: two digits per octet, `""` for none), never base64url, so the base64url codec is never checked against itself.
- **`keys.*` operations: PEM text and JWK objects**, never raw octets. A PEM block is a JSON string with `\n` line endings; JWK members are canonical base64url as RFC 7518 §6 and RFC 8037 §2 define them.
- **`jws.*` and `jwe.*` operations: canonical base64url** (members ending in `_b64u`). This is deliberate: the codec is no longer under test there (it has its own vectors), and every JWS field is natively base64url (RFC 7515 §2), so the RFC's values are copied as printed. A runner decodes `payload_b64u` and `detached_payload_b64u` to hand octets to the library; a value that doesn't decode canonically fails the vector, it is never an outcome. `protected_b64u` is passed to the library as text, unchanged.

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

## `jwe.encrypt`

Encrypts `plaintext_b64u` (RFC 7516 §5.1) in one serialization.

| Input member | Meaning |
|---|---|
| `serialization` | `"compact"` (RFC 7516 §7.1), `"flattened"` (§7.2.2) or `"general"` (§7.2.1). Unlike `jws.sign`, the schema does not limit the recipients per serialization: the library's refusal (`InvalidFormat`) is what such a vector tests. |
| `enc` | The content encryption algorithm (RFC 7516 §4.1.2), passed as given. |
| `plaintext_b64u` | The plaintext octets. |
| `recipients` | One or more recipients, in output order. Each is `{ "alg", "key", "header"?, "apu_b64u"?, "apv_b64u"?, "p2c"?, "p2s_len"? }`: the key management `alg`, the recipient's JWK (a public key, or the `oct` key of `dir`, A\*KW, A\*GCMKW or the PBES2 password), its Per-Recipient Unprotected Header (§7.2.1, JSON only), the ECDH-ES `apu`/`apv` octets (RFC 7518 §4.6.1.2–§4.6.1.3), and the PBES2 iteration count and salt length (§4.8.1.1–§4.8.1.2; library defaults when absent). |
| `protected` | Extra JWE Protected Header parameters (`typ`, `cty`, `kid`, …). polyjose sets `alg`, `enc`, `zip` and the key management parameters itself, and refuses them here (`InvalidHeader`). For compact and flattened output, `alg` and the key management parameters go in the protected header; for general, in each recipient's header (as RFC 7520 §5.13). |
| `protected_b64u` | The exact encoded protected header to reproduce. Used verbatim for the AAD and the output only if it decodes to a header JSON-equal to the one polyjose builds (member order aside), otherwise `InvalidFormat`. Needs `"fixed-rng"`. |
| `unprotected` | The JWE Shared Unprotected Header (§7.2.1), JSON only. |
| `aad_b64u` | The JWE AAD octets (§7.2.1), JSON only. |
| `compress` | `true` compresses with `zip: "DEF"` (§4.1.3). Needs `"deflate"`. |
| `rng_b64u` | The octets the encryption draws instead of the OS CSPRNG, in the documented order: the CEK (when the `alg` needs a random one), then each recipient's key management values in order (ECDH ephemeral key, PBES2 salt, AES-GCM key wrap IV), then the content IV. Every octet must be drawn; a leftover fails the vector, so the vector pins the order. Needs `"fixed-rng"`. |

The runner calls the library's reproducible encryption when `rng_b64u` or `protected_b64u` is present (both need `"fixed-rng"`, and a vector using them without listing it is schema-invalid), and its ordinary encrypt on the OS CSPRNG otherwise.

Expect one of:

- **`{ "ok": true, "jwe": <jwe> }`** for a reproducible encryption: the exact output. A compact JWE is a string, compared exactly; a JSON JWE is an object, compared as a JSON value.
- **`{ "ok": true, "decrypt_with": { "key", "allowed_algs", "allowed_enc" } }`** for an encryption on the OS CSPRNG. The runner checks its own output: it has the requested serialization's shape (five compact parts; `ciphertext` without `recipients` for flattened; one `recipients` entry per recipient for general), it decrypts with `decrypt_with`, and the plaintext equals `plaintext_b64u`.
- **`{ "ok": false, "error": <code> }`.**

## `jwe.decrypt`

Decrypts a JWE with one key and the allow-lists (RFC 7516 §5.2, RFC 8725 §3.1), under the error order of the JWE plan (ADR 0026 §2 applied to JWE): limits, structure, base64url, headers, `crit`, then the support check over every recipient, the allow-list, the key binding, and only then the cryptography, after which every failure is the one detail-free `DecryptionFailed` (RFC 7516 §11.4–§11.5).

| Input member | Meaning |
|---|---|
| `jwe` | A **string** is a compact JWE (RFC 7516 §7.1). An **object** is a flattened or general JSON JWE (§7.2); the runner passes its JSON text to the library's JSON decrypt. Otherwise unconstrained. |
| `key` | The decrypting JWK, a JSON object. |
| `allowed_algs`, `allowed_enc` | The allow-lists, arrays of names passed as given. An empty list is `AlgorithmNotAllowed`. An unknown or unimplemented name (`RSA1_5`, `RSA-OAEP`, `RSA-OAEP-256`) may be listed, but never decrypts: the support check comes first (`UnsupportedAlgorithm`). |
| `understood_crit` | Optional. The `crit` extension names the caller understands (§4.1.13); none when absent. |
| `max_input_len`, `max_recipients`, `max_pbes2_count`, `max_decompressed_len` | Optional limits; absent means the library default (1 MiB, 16, 10,000 (ADR 0023), 250,000 (ADR 0017)). |

Expect `{ "ok": true, "plaintext_b64u", "recipient" }`: the plaintext and the index of the recipient that decrypted (`0` for compact and flattened; for general, the first in array order whose key management and content decryption succeed). Or `{ "ok": false, "error": <code> }`.

## Rules for `jwe.*` runners

- **Step order**, the first error being the outcome:
  1. `jwe.encrypt`: for each recipient in order, import `key`, then parse `header`; then parse `protected`, then `unprotected`. `jwe.decrypt`: import `key`, then build the policy from the allow-lists and the optional members.
  2. Call the library.
- **One fault per failure vector**, as for `jws.*`; the precedence vectors put every fault inside `jwe` itself.
- Map `serialization` to the binding's compact and JSON encrypt functions, and the limits to its decrypt policy. Never substitute defaults of your own.

## Features

A vector may need a cargo feature of polyjose, written in `features` as:

| Name in a vector | Cargo feature | Needed by |
|---|---|---|
| `"fixed-rng"` | `insecure-test-vectors` (ADR 0041 §3) | a byte-exact `jwe.encrypt` (`rng_b64u`, `protected_b64u`) |
| `"deflate"` | `deflate` (ADR 0017) | `zip` (`compress`, and the `zip` decrypt vectors) |

The test RNG's cargo name may appear only in `crates/polyjose`, `scripts/check-test-vectors-off.sh` and Markdown (that script fails the build otherwise, so no build file can switch it on, ADR 0005); vector files therefore use `"fixed-rng"`. A runner whose build does not enable every listed feature:

- still validates the vector against the schema, and fails it if invalid;
- does not run it, and reports it **SKIPPED with the missing feature names** (the Rust runner prints the cargo name: ``<file>: SKIPPED (needs feature `insecure-test-vectors`)``);
- never counts it as passing.

The bindings never enable `insecure-test-vectors` (ADR 0005), so `fixed-rng` vectors are Rust-only; every RFC output they reproduce also has a `jwe.decrypt` vector that every platform runs.

## Binding readiness

Every vector under `jws-*/`, `third_party/**/jws/`, `jwe/` and `keys/`, and every `jws.*`, `jwe.*` or `keys.*` vector anywhere, must be readable by every binding's own JSON parser unchanged. The Rust runner's `jws_and_keys_vectors_are_binding_ready` and `jwe_vectors_are_binding_ready` tests check it:

- every number is a plain integer (no fraction, no exponent) of magnitude at most 2^32 − 1 (`count` in the schema is a `u32`, as in ADR 0030), so no binding needs a 64-bit-only type or reads a double;
- octets are base64url strings (`*_b64u`), never `*_hex` or raw bytes, and every one a runner decodes is canonical;
- in a `keys.*` vector, every base64url member (`x`, `y`, `d`, `n`, `e`, `k`) of a `jwk` object is canonical.

## Rules for every runner

Each platform's runner (Rust: `crates/polyjose/tests/conformance.rs`) must:

- load every `*.json` file under `vectors/`, recursively, `third_party/` included;
- **fail** on a file that is not schema-valid, including a misspelled or unknown member anywhere: every object the schema defines is closed;
- **fail** on a vector whose `operation` it does not implement, whether `schema.json` reserves it or not. The only vectors not run are those whose `features` the build lacks, reported SKIPPED by name ([Features](#features));
- **fail** when it finds no vector files, so a wrong path can't pass vacuously;
- run every vector and report every failure, not only the first, each naming the file and its `source`.

The Rust runner also checks `schema.json` against its own tables (`schema_and_runner_agree`), so the schema and the runner can't drift apart.

## Writing vectors

- Name files after what they check, grouped by operation: `vectors/b64url/encode-rfc4648-10-foo.json`, `vectors/jwk-thumbprint/reject-oct-k-padded.json`.
- Key vectors live in `keys/`: `import-*` and `export-*` for successes, `reject-*` for failures. Their expected JWKs and PEM texts are the committed key fixtures (`crates/polyjose/tests/data/keys/`: OpenSSL 4.1.0 output and the RFC golden files), never polyjose output; `source` names the RFC, or OpenSSL for a generated key. `crates/polyjose/tests/data/keys/regen/make-keys-vectors.py` writes them (`python3 -I`); edit the script, not the files. **Until features 0006–0009 bind the keys API, test reports list WASM, Node, Kotlin and Swift as `SKIPPED (API not yet bound)` for them; each binding's runner implements `keys.*` when it binds the API, and the never-skip rule above then applies.**
- JWE vectors live under `jwe/`, one directory per task and kind: `jwe/compact/` (RFC 7516 Appendix A, RFC 7520 §5.6 and §5.8, round trips), `jwe/negative-structure/` (the error contract, one vector per rule; `source` "polyjose" or the RFC whose vector is refused), and the per-family and JSON directories of the later JWE tasks. RFC 7520 values are generated from the vendored ietf-jose cookbook (`crates/polyjose/tests/third_party/ietf-jose-cookbook/`), not transcribed.
- JWS vectors are grouped by origin: `jws-rfc7515/` (RFC 7515 Appendix A and F; `source` "RFC 7515 App. A.x" or "RFC 7515 App. F"), `jws-rfc7797/`, `jws-rfc8037/`, `jws-oracle/` (generated independently of polyjose; `source` names the tool and its versions), `jws-negative/` (`source` names the RFC section, CVE or ADR enforced), and `third_party/rfc7520/jws/` (the RFC 7520 §4 cookbook).
- Check every expected value against the RFC text yourself. If the RFC doesn't print the value, derive it independently of polyjose (for example with Python's `hashlib` over the hand-built input) and say so in `description`.
- **Deterministic algorithms** (HMAC, EdDSA) also have `sign` vectors with an exact expected output. **Randomized ones** (ECDSA, JWE) are checked by round trip (`verify_with`) plus a `verify`/`decrypt` vector of the RFC's published output. RS\*/PS\* are verify-only (ADR 0021): only `verify` vectors, and `sign` vectors that expect `UnsupportedAlgorithm`.
- **Negative vectors are mandatory:** tampered signatures, `alg: none`, alg/key mismatch, wrong `crit`, expired JWTs, invalid curve points, non-canonical encodings.
- Imported upstream suites that every platform runs (the RFC 7520 cookbook) live in `vectors/third_party/`, converted to this format, with their licenses alongside them (non-JSON files are ignored).
- **Wycheproof is not here.** It lives in `crates/polyjose/tests/third_party/wycheproof/`, in its upstream format, because it is a Rust-layer suite (ADR 0008 layer 1): it exercises the primitives through polyjose's JOSE layer, and the bindings add nothing to that.

## Tools

The scripts that generated or check vectors live in [`tools/`](tools/). They read only data (the vendored ietf-jose cookbook and Wycheproof files, the RFC text, committed key files) and use only Node's built-ins (node:crypto, which is OpenSSL) and Python's standard library: no npm or pip packages, and none of them calls polyjose. Paths below are relative to this directory (`conformance/`). The index of the JWE vectors, with the generator of each directory, is [`vectors/jwe/README.md`](vectors/jwe/README.md).

- **`tools/jwe/reproduce.sh <rfc-dir>`** re-runs every JWE generator below into a temporary directory and compares each file it writes with the committed vector, byte for byte; a historical generator is reported as such. `<rfc-dir>` holds `rfc7516.txt` and `rfc7517.txt` from `https://www.rfc-editor.org/rfc/` (the script checks their SHA-256). The Node generators write the Node and OpenSSL versions into `source` or `description`, so they reproduce byte for byte with the versions named in the committed files (Node.js 24.21.0, OpenSSL 3.5.8); another version changes only that text.
- **`tools/rsa-oaep-oracle.mjs [vector-dir]`** checks every exact RSA-OAEP-256 `jwe.encrypt` vector in `vectors/jwe/rsa-oaep-256/` against its test-only private key (`keys/*.private.jwk`) with Node's built-in RSA, independently of polyjose, which has no RSA private-key code (ADR 0021).
- **`tools/jwe/t09-extract-rfc-inputs.py <rfc7516.txt> <cookbook jwe dir> <out.json>`**: *historical.* Extracts the RFC 7516 App. A.1 and A.2 and RFC 7520 §5.1 and §5.2 compact JWEs and RSA public keys used by four `negative-structure/` vectors. The script that wrote `compact/` and `negative-structure/` (0003 T09) was not preserved, so those 60 files have no generator; `reproduce.sh` checks that the four extracted inputs match their vectors.
- **`tools/jwe/t10-gcmkw.mjs <cookbook 5_7 json> <out-dir>`** writes the 24 0003 T10 files of `gcmkw/`: RFC 7520 §5.7 decrypt and exact encrypt from the cookbook, and A\*GCMKW tokens and negatives built with node:crypto from SHA-256-derived bytes.
- **`tools/jwe/t11-rsa-oaep-256.mjs <repo-root>`** writes the six `rsa-oaep-256/*-reproduced.json` exact encrypt vectors into `<repo-root>/conformance/vectors/jwe/rsa-oaep-256/`, from `rsa-oaep-oracle.mjs`'s own EME-OAEP encoding and Node's raw RSA with the test keys in `keys/`. The other nine files of that directory (0003 T11 negatives) have no preserved generator: *historical*.
- **`tools/jwe/t12-pbes2.py <cookbook 5_3 json> tools/jwe/t12-rfc7517c.json <out-dir>`** writes the 21 files of `pbes2/` from RFC 7520 §5.3 (cookbook) and RFC 7517 App. C. **`tools/jwe/t12-rfc7517c-extract.py <rfc7517.txt>`** prints `t12-rfc7517c.json`, the App. C values, cross-checking C.1–C.9 against each other and C.4 against Python's `hashlib.pbkdf2_hmac`.
- **`tools/jwe/t13-ecdh-es.js <cookbook jwe dir> <out-dir>`** writes the 39 files of `ecdh-es/`: RFC 7520 §5.4 and §5.5 from the cookbook, and X25519, P-256 (RFC 7518 App. C) and P-521 known answers and `epk` negatives computed with node:crypto. It reads the test keys `t13-p521-key.json` and `t13-p384-key.json` (their `d` is in the committed vectors).
- **`tools/jwe/t14-json.py <repo-root> <rfc7516.txt>`** writes the 0003 T14 files of `json/` (28) and `negative-json/` (45) under `<repo-root>/conformance/vectors/jwe/`, from the cookbook (RFC 7520 §5.6, §5.8, §5.10–§5.12) and the RFC 7516 text (App. A.3–A.5).
- **`tools/jwe/t15-zip.py <repo-root> tools/jwe/t15-zip-tokens.txt`** writes the 11 0003 T15 files of `zip/` under `<repo-root>/conformance/vectors/jwe/zip/`, from RFC 7520 §5.9 (cookbook) and the recorded tokens. **`tools/jwe/t15-zip-tokens.rs`** printed those tokens: *historical.* It was a scratch binary against polyjose (feature `deflate`) and the aes-gcm crate, not part of the workspace; its `bound64` and `empty` tokens were encrypted on the OS CSPRNG, so a rerun gives other IVs. Its forged tokens (fixed key and IV, hand-built DEFLATE streams) and the key reproduce exactly.
- **`tools/jwe/t18-cross-family.mjs <repo-root> [<out-root>]`** writes `rfc7520-multi/` (6, RFC 7520 §5.13), `negative-crypto/` (38), the RFC 7520 §5.7 flattened pair in `json/` (erratum 4802), the §5.9 JSON pair in `zip/` and the five per-recipient `iv`/`tag` files in `gcmkw/` (0003 T18), from the cookbook, the vendored Wycheproof ECDH webcrypto files (invalid P-384 and P-521 points by `tcId`) and tokens built with node:crypto from SHA-256-derived bytes. It cross-checks the cookbook values it uses (key unwraps, content tags) before writing.
