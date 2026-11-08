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

The five members below are required, `features` and `features_absent` are optional, and no others are allowed. Every object the schema defines is closed (`additionalProperties: false`).

| Member | Meaning |
|---|---|
| `source` | Where the expected value comes from: an RFC section (`"RFC 4648 §10"`), an upstream suite, or `"polyjose"` for a project-defined negative vector (whose `description` then cites the RFC rule). Every failure message names it. |
| `description` | What the vector checks, in one sentence. If an RFC does not print the expected value, say how it was derived. |
| `operation` | One of the operations below. |
| `input` | The operation's input. |
| `expect` | `{ "ok": true, ...outputs }`, or `{ "ok": false, "error": <code> }` where `<code>` is one of the stable error codes (`Error::CODES` in `crates/polyjose/src/error.rs`). |
| `features` | Optional. The polyjose cargo features the vector needs, each at most once: `"fixed-rng"` (the cargo feature `insecure-test-vectors`, ADR 0041 §3) or `"deflate"` (ADR 0017). See [Features](#features). |
| `features_absent` | Optional. The polyjose cargo features the vector must run **without** (ADR 0056), by the same names: at least one, each at most once, none also in `features`. See [Features](#features). |

## Operations

| Operation | `input` | `expect` when `ok` is true | Can fail |
|---|---|---|---|
| `b64url.encode` | `bytes_hex` | `b64u` | no |
| `b64url.decode` | `b64u` (any string) | `bytes_hex` | yes |
| `jwk.thumbprint` | `jwk` (a JSON object), and optionally `hash` (any string; ADR 0054 §8.2 names, [below](#jwkthumbprint)) | `thumbprint`, `thumbprint_uri` | yes |
| `jwks.select` | `jwks` (a JSON object), `selector` (`{ "kid"?, "alg"?, "key_use"? }`, each any string) ([below](#jwksselect)) | `jwk` (a JSON object, compared as a JSON value) | yes |
| `jws.sign` | `serialization`, `payload_b64u`, `detached`, `signers` ([below](#jwssign)) | `jws` (exact), or `verify_with` (round trip) | yes |
| `jws.verify` | `jws`, `key`, `allowed_algs`, and optionally `detached_payload_b64u`, `max_input_len`, `max_signatures` ([below](#jwsverify)) | `payload_b64u`, `alg`, `signature_index` | yes |
| `keys.import_pem` | `pem` (any string) ([below](#keysimport_pem)) | `jwk` (a JSON object) | yes |
| `keys.export_pem` | `jwk` (a JSON object), `format` (`"pkcs8"`, `"sec1"`, `"spki"` or `"pkcs1"`) ([below](#keysexport_pem)) | `pem` (exact text) | yes |
| `keys.import_der` | `der_b64u`, `format` (as `keys.export_pem`) ([below](#keysimport_der)) | `jwk` (a JSON object) | yes |
| `keys.export_der` | `jwk` (a JSON object), `format` (as `keys.export_pem`) ([below](#keysexport_der)) | `der_b64u` (exact) | yes |
| `keys.generate_for` | `alg` (any string) ([below](#keysgenerate_for)) | `shape` (the key without its random material), and optionally `use_with` | yes |
| `keys.generate_oct` | `len_bytes` (a count) ([below](#keysgenerate_oct-keysgenerate_ec-keysgenerate_okp)) | `shape`, `use_with` | yes |
| `keys.generate_ec` | `crv` (`"P-256"`, `"P-384"`, `"P-521"` or `"secp256k1"`) | `shape`, `use_with` | no |
| `keys.generate_okp` | `crv` (`"Ed25519"` or `"X25519"`) | `shape`, `use_with` | no |
| `jwe.encrypt` | `serialization`, `enc`, `plaintext_b64u`, `recipients`, and optionally `protected`, `protected_b64u`, `unprotected`, `aad_b64u`, `compress`, `rng_b64u` ([below](#jweencrypt)) | `jwe` (exact), or `decrypt_with` (round trip) | yes |
| `jwe.decrypt` | `jwe`, `key`, `allowed_algs`, `allowed_enc`, and optionally `understood_crit`, `max_input_len`, `max_recipients`, `max_pbes2_count`, `max_decompressed_len` ([below](#jwedecrypt)) | `plaintext_b64u`, `recipient` | yes |
| `jwt.validate` | `token`, `now`, `allowed_algs`, exactly one of `key` or `jwks`, and optionally `policy`, `decrypt` ([below](#jwtvalidate)) | `claims`, `alg`, and `key_index` exactly when the input has `jwks` | yes |
| `jwt.issue` | `claims`, `alg`, `key`, and optionally `typ`, `encrypt`, `validate` ([below](#jwtissue)) | `token` (exact), or nothing (the runner validates the token itself) | yes |

`schema.json` may also reserve an operation for a later feature: its name is in the `operation` enum, but its input and output members are defined only by the feature that implements it, which adds them to `schema.json` and to every runner. Until then no runner implements it, so a vector that uses it fails. No operation is reserved today.

A success expectation lists **exactly** the outputs: a runner fails a vector whose operation produced an output the expectation leaves out, as well as one that lacks an expected output.

### How bytes are written

- **Codec operations (`b64url.*`, `jwk.thumbprint`): lowercase hex** (`bytes_hex`: two digits per octet, `""` for none), never base64url, so the base64url codec is never checked against itself.
- **`keys.*` operations: PEM text, JWK objects and DER as canonical base64url** (`der_b64u`), never hex. A PEM block is a JSON string with `\n` line endings; JWK members are canonical base64url as RFC 7518 §6 and RFC 8037 §2 define them. A runner decodes `der_b64u` to hand octets to the library; a value that doesn't decode canonically fails the vector, it is never an outcome.
- **`jwks.select`: JWK Set, selector and JWK as JSON objects**, as `jwt.*` gives keys. No octets are decoded; the selected key is compared as a JSON value.
- **`jwt.*` operations: tokens as text, keys as JWK and JWK Set objects, claims as a JSON object, time as integer seconds.** A token is passed to the library exactly as written (malformed tokens are under test), and claims under test that a JSON vector can't hold (duplicate names, `1e400`, non-UTF-8 octets) live inside the token's base64url payload.
- **`jws.*` and `jwe.*` operations: canonical base64url** (members ending in `_b64u`). This is deliberate: the codec is no longer under test there (it has its own vectors), and every JWS field is natively base64url (RFC 7515 §2), so the RFC's values are copied as printed. A runner decodes `payload_b64u` and `detached_payload_b64u` to hand octets to the library; a value that doesn't decode canonically fails the vector, it is never an outcome. `protected_b64u` is passed to the library as text, unchanged.

## `jwk.thumbprint`

Imports `jwk` and computes its JWK Thumbprint (RFC 7638 §3) and JWK Thumbprint URI (RFC 9278 §3).

| Input member | Meaning |
|---|---|
| `jwk` | The key, as a JSON object. Its members are unconstrained: invalid keys are under test. |
| `hash` | Optional, any string. Absent means the core default, SHA-256 (RFC 9278 §5); a runner passes no name rather than supplying one. The accepted names are exactly `sha-256`, `SHA-256`, `sha256` and the 384 and 512 forms, case-sensitive (ADR 0054 §8.2). Any other name, the empty string included, is a vector outcome (`UnsupportedAlgorithm`), never a schema error. |

`thumbprint_uri` always carries the IANA Hash Name String (`sha-256`, `sha-384` or `sha-512`, RFC 9278 §4), whatever spelling `hash` uses. The SHA-384, SHA-512 and hash-name vectors (`jwk-thumbprint/sha384-*`, `sha512-*`, `hash-*`) come from [`tools/jwk-oracle/thumbprints.mjs`](tools/jwk-oracle/README.md).

**Error order (ADR 0057 §2).** A runner imports `jwk` first and parses `hash` second, so the outcome is:

1. the JWK import error (`InvalidJson`, `InvalidKey`, `InvalidBase64`, `UnsupportedAlgorithm` for an RSA private JWK, and so on)
2. then `UnsupportedAlgorithm` for a `hash` name that isn't accepted

`jwk-thumbprint/hash-reject-invalid-key-p256-off-curve.json` has both an invalid key and an invalid name, and expects the import error. This matches the `jwks.select` step order below (ADR 0054 §4: import, then the selector).

## `jwks.select`

Selects exactly one key from a JWK Set (RFC 7517 §5) with a selector, under ADR 0054 §1–§4. It is the binding operation `jwks_select(jwks, JwkSelector { kid?, alg?, key_use? }) -> jwk` of ADR 0030 §4, as amended by ADR 0054 §9.

| Input member | Meaning |
|---|---|
| `jwks` | The JWK Set, a JSON object. Unconstrained: import errors and the members import skips are under test. A missing or non-array `keys` is `InvalidKey`, and an RSA private member fails the whole set with `UnsupportedAlgorithm` (ADR 0021, ADR 0029 §3). Members with an unknown `kty`/`crv`, or that are otherwise invalid, are skipped (ADR 0041 §2). |
| `selector` | **Required**, closed: `kid`, `alg` and `key_use`, each optional and any string. `{}` selects every member (ADR 0054 §1.3). There is no `key_op` (ADR 0054 §9), so a vector with one is a broken vector. |

Expect `{ "ok": true, "jwk" }`: the one matching member as the library serializes it, compared as a JSON value (member order ignored). It may hold private members (`EC` and `OKP` `d`, `oct` `k`, ADR 0054 §3). Or `{ "ok": false, "error": <code> }`.

**Step order**, the first error being the outcome. This is ADR 0054 §4's precedence:

1. Import `jwks` (Rust: `JwkSet::from_object`; a binding: the set's JSON text). Set import errors come first.
2. Build the selector from an empty one, in the order `kid`, then `alg`, then `key_use`, calling the setter only for a member that is present. `alg` and `key_use` are passed **as given** (Rust: `KeyAlg::from`, `KeyUse::from`). The setters refuse an unsupported `alg` (`none`, `RSA1_5`, `RSA-OAEP`, an `enc` name, an unregistered or case-variant name, `""`) or a `key_use` other than `sig` or `enc` with `UnsupportedAlgorithm` (ADR 0054 §1.1). A runner never maps, normalizes or rejects a name itself, and never supplies a member the vector leaves out.
3. Select: one match, or `NoMatchingKey` (none, an empty set included), or `MultipleMatchingKeys` (two or more; RFC 7517 §5.1 gives set order no meaning).

A binding runner maps `selector` to its binding `JwkSelector` member by member, and parses the returned key (a secret-bearing string) as JSON before comparing it. The schema is closed at every level, as for `jwt.*`: a misspelled member anywhere fails the run.

The vectors live in `jwks-select/`, one per file, named by outcome: `select-*`, `no-match-*`, `multiple-*`, `unsupported-*`, `invalid-key-*`, and `precedence-*` for the §4 order. Each `description` states the ADR 0054 rule that decides it. They come from [`tools/jwk-oracle/select.mjs`](tools/jwk-oracle/README.md) and its hand-written spec.

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

## `keys.import_der`

Imports DER with the library's DER key import in the structure `format` names (ADR 0018 §3). There is no format sniffing (ADR 0007): DER of another structure fails, so an SPKI offered as `pkcs8` is `InvalidKey`. `format` selects the structure as the PEM label does for `keys.import_pem`: `pkcs8` (RFC 5958 §2), `sec1` (RFC 5915 §3), `spki` (RFC 5280 §4.1.2.7), `pkcs1` (RFC 8017 App. A.1.1). The expectations and error codes are those of `keys.import_pem`, compared the same way, and an `oct` result fails the vector whatever it expects. Only the PEM-level faults (armor, labels, explanatory text) have no DER counterpart.

## `keys.export_der`

`keys.export_pem` without the armor: imports `jwk` with the library's JWK import (whose error is the vector's outcome), then exports it as DER in `format` (ADR 0018 §3). Expect `{ "ok": true, "der_b64u": <octets> }`, the exact DER in OpenSSL 4's layout as canonical base64url, compared as a string; or a failure, by the format matrix of `keys.export_pem`, with its check order.

## `keys.generate_for`

Generates a private key for `alg` with the library's `generate_for` (ADR 0018 §5; ADR 0030 `jwk_generate_for_alg`). `alg` is a JWS `alg`, a JWE `alg` or a JWE `enc` name. RFC 7518 §7.1 registers all three in one registry whose names are unique and case-sensitive, so a runner resolves the name in whichever of the three it belongs to, and passes a name none of them knows to the library as unknown. It never normalizes case or picks a substitute.

A generated key is random, so there is no exact output. A success vector expects only the key's **shape**:

| `shape` member | Meaning |
|---|---|
| `kty` | `"EC"`, `"OKP"` or `"oct"` |
| `crv` | EC and OKP only: the curve, for example `"P-256"` or `"Ed25519"` |
| `alg` | The `alg` member the key is bound to (RFC 7517 §4.4): the requested name |
| `k_octets` | `oct` only: the length of `k` in octets |

The runner builds the generated key's shape and compares it with `shape` as a JSON value. A member the key has and the vector omits fails, so an EC vector must name `crv` and an `oct` vector `k_octets`. Before that the runner checks what a shape can't say, and any failure there fails the vector:

- the key is private;
- its members are exactly those RFC 7518 §6.2.1–§6.2.2 (EC: `kty`, `crv`, `x`, `y`, `d`), RFC 8037 §2 (OKP: `kty`, `crv`, `x`, `d`) or RFC 7518 §6.4.1 (`oct`: `kty`, `k`) define, plus `alg`;
- it imports back with the library's JWK import to the same JWK.

The expected shapes are the RFC sizes and curves per algorithm: HMAC keys the size of the hash output (RFC 7518 §3.2), AES key wrap and AES-GCM keys their AES key size (§4.4, §4.7, §5.3), AES-CBC-HMAC keys both halves (§5.2.3–§5.2.5), ECDSA keys their curve (§3.4, RFC 8812 §3.2) and EdDSA keys Ed25519 (RFC 8037 §3.1, ADR 0006).

The failures are:

- `InvalidKey` for `ECDH-ES` and `ECDH-ES+A*KW`. They work on several curves (RFC 7518 §4.6), so the request lacks a curve, and polyjose never picks one. A binding must not substitute a default;
- `UnsupportedAlgorithm` for the RSA algorithms (ADR 0021), `dir` (its key size depends on `enc`, RFC 7518 §4.5), `PBES2-*` (passwords aren't generated), `none`, and any unknown or wrongly cased name.

A success expectation may also have **`use_with`**, a round trip the runner runs with the generated key (ADR 0034 §6). It is a check, never an outcome, and the runner echoes it back as an output, as it does `verify_with`:

| `use_with` member | Meaning |
|---|---|
| `alg` | Required. Without `enc`: the JWS `alg`. The runner signs a compact JWS (RFC 7515 §7.1) of the payload `polyjose` (`cG9seWpvc2U`) under the protected header `{"alg": alg}` with the key, then verifies it with the key's public form and the allow-list `[alg]`. With `enc`: the JWE key management `alg`. |
| `enc` | Optional. The runner encrypts a compact JWE (RFC 7516 §7.1) of the same plaintext to one recipient with `alg` and the key's public form, then decrypts it with the key and the allow-lists `[alg]` and `[enc]`. |

The "public form" is the key itself for `oct` (RFC 7518 §6.4). Any failure in the round trip, or a payload that comes back different, fails the vector.

## `keys.generate_oct`, `keys.generate_ec`, `keys.generate_okp`

Generate a key with the library's generator (ADR 0018 §5; ADR 0030 §4 `jwk_generate_oct`, `jwk_generate_ec`, `jwk_generate_okp`) from the OS CSPRNG: an `oct` key of `len_bytes` octets (RFC 7518 §6.4.1), or a key pair on `crv` (EC: RFC 7518 §6.2, RFC 8812 §3.1; OKP: RFC 8037 §2). Such a key is bound to no algorithm, so it has no `alg`.

Expect `{ "ok": true, "shape", "use_with" }`, both required: one vector per generator, by shape and by a use round trip (ADR 0034 §6). `shape` is the `keys.generate_for` shape **without** `alg` (`kty`; `crv` for EC and OKP; `k_octets` for `oct`), and the runner checks the key as it does there, with the members of the RFC sections above and no `alg`. `use_with` is the round trip of [`keys.generate_for`](#keysgenerate_for).

Only `keys.generate_oct` can fail: the core generates `oct` keys of 16 to 512 octets, and another length is `InvalidKey`. The schema allows only the curves polyjose generates, so `keys.generate_ec` and `keys.generate_okp` always succeed.

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
| `compress` | `true` compresses with `zip: "DEF"` (§4.1.3). Needs `"deflate"` in `features`; or, in `features_absent`, the vector pins `UnsupportedAlgorithm` without the codec (ADR 0056, ADR 0030 §4). |
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

## `jwt.validate`

Validates a JWT (RFC 7519 §7.2) at the time `now`, with an allow-list (RFC 8725 §3.1) and the caller's keys (ADR 0029 §1), under ADR 0027's policy and processing order (§9). A three-part token goes to the library's signed-JWT validation; with `decrypt`, the token is a nested JWT (a compact JWE around a signed JWT, ADR 0027 §7) and goes to its nested validation.

| Input member | Meaning |
|---|---|
| `token` | The token as given, any string (malformed tokens are under test). |
| `now` | **Required.** The current time in whole seconds since the epoch (RFC 7519 §2), an integer within ±(2^53 − 1) (ADR 0027 §2). The runner builds a **fixed clock** from it and never reads its platform's clock (ADR 0028 §4), so every platform gives the same verdict on every day. |
| `allowed_algs` | The JWS allow-list, names passed as given. An empty list, `"none"` or an unknown name is refused with `AlgorithmNotAllowed`. |
| `key` | One verification JWK, a JSON object. Its `kid` is not compared with the header's (ADR 0029 §1). |
| `jwks` | A JWK Set (RFC 7517 §5), a JSON object. Candidates are selected and tried in set order (ADR 0029 §2–§4). Exactly one of `key` and `jwks` is required (the schema's `oneOf`). |
| `policy` | Optional; the [policy](#the-jwt-policy). Absent means the library defaults. |
| `decrypt` | Optional; the outer JWE layer of a nested JWT: `{ "key", "allowed_algs", "allowed_enc", "max_pbes2_count"? }`, the decrypting JWK and allow-lists as `jwe.decrypt` takes them, and the PBES2 bound (ADR 0023; 10,000 when absent). |

Expect `{ "ok": true, "claims", "alg", "key_index"? }`:

- `claims`: the validated JWT Claims Set, a JSON object, compared as a JSON value: member order is ignored and numbers are compared as doubles (so `1300819380` and `1300819380.0` are equal), every string octet for octet;
- `alg`: the JWS `alg` that verified (for a nested JWT, the inner one's);
- `key_index`: the zero-based position in `jwks` of the member that verified (ADR 0029 §4). It is present **exactly** when the input has `jwks`.

Or `{ "ok": false, "error": <code> }`.

### The JWT policy

Every member is optional. An absent member, or a boolean member set to `false`, keeps the library default; a runner never restates a default of its own.

| Member | Meaning | Library default |
|---|---|---|
| `issuer` | The accepted issuer, a string, or a list of them (RFC 7519 §4.1.1, RFC 8725 §3.8). `iss` must equal one exactly. | none checked |
| `audience` | The accepted audiences, an array (RFC 7519 §4.1.3). `aud` must contain one. | none accepted: a token **with** `aud` is rejected (ADR 0027 §4) |
| `subject` | The expected `sub` (RFC 7519 §4.1.2). | not checked |
| `leeway` | Clock skew in whole seconds on `exp`, `nbf` and `iat` (RFC 7519 §4.1.4–§4.1.5). Over 600 is refused with `InvalidClaim`. | 60 |
| `max_age` | The oldest accepted `iat`, in seconds; makes `iat` required (RFC 7519 §4.1.6). | `iat` type-checked only |
| `require` | Claim names that must be present, with any value (RFC 7519 §4). | none |
| `allow_missing_exp` | `true` accepts a token without `exp` (the explicit opt-out of ADR 0007). | `exp` required |
| `ignore_audience` | `true` accepts a token with `aud` when no audience is configured (RFC 8725 §3.9 warns against it). | rejected |
| `typ` | `{ "mode": "default" }` (absent or `JWT`), `{ "mode": "exact", "value": <type> }` (present and equal as a media type, RFC 7515 §4.1.9) or `{ "mode": "any" }` (no check). `value` is required with `exact` and allowed with nothing else (ADR 0027 §5). | `default` |
| `profile` | `"access_token"`: a JWT access token (RFC 9068 §4): `typ` `at+jwt`, the RFC 9068 §2.2 claims, `issuer` and `audience` both required (the library refuses the policy without them, `InvalidClaim`). A `typ` member then overrides the profile's `at+jwt`; mode `default` contradicts the profile and is a **broken vector**. | none |
| `max_key_candidates` | The most `jwks` members tried for one token; more is `NoMatchingKey` (ADR 0029 §4). | 8 |

## `jwt.issue`

Issues a signed JWT (RFC 7519 §7.1; ADR 0027 §8) and, with `encrypt`, encrypts it as a nested JWT (sign-then-encrypt, RFC 7519 §11.2; ADR 0027 §7).

| Input member | Meaning |
|---|---|
| `claims` | The JWT Claims Set, a JSON object. The library serializes the registered claims first, then the others in order (ADR 0027 §1). |
| `alg` | The JWS `alg`, passed as given. RS\*/PS\* are `UnsupportedAlgorithm` (ADR 0021); `none` is `AlgorithmNotAllowed`. |
| `key` | The signing JWK, a JSON object. |
| `typ` | Optional. Absent: the library default `JWT`. A string sets it (`at+jwt` for an access token, RFC 9068 §2.1). `null` omits it (RFC 7519 §5.1). |
| `encrypt` | Optional; `{ "alg", "enc", "key" }`: one recipient's key management `alg` and JWK (a public key, or an `oct` key) and the content encryption `enc`. The library puts `cty: "JWT"` in the protected header itself (RFC 7519 §5.2). |
| `validate` | Optional; how the runner validates the token it issued: the `jwt.validate` input members other than `token`, with the same rules (`now` required, exactly one of `key` and `jwks`; `decrypt` for an encrypted token). |

Expect one of:

- **`{ "ok": true, "token": <token> }`** for a deterministic signature (HMAC, EdDSA): the exact compact token, compared as a string. Not allowed with `encrypt`, whose output is randomized (RFC 7516 §5.1). With `validate`, the runner also validates it.
- **`{ "ok": true }`**: the runner checks the token itself. It must have three compact parts (a JWS, RFC 7515 §7.1), or five with `encrypt` (a JWE, RFC 7516 §7.1); then it must validate with `validate`, with the `alg` it was issued with, giving back the issued `claims` (compared as a JSON value). Any failure there, including a `validate` the library refuses, fails the vector. `validate` is required, unless `encrypt` is set: a recipient polyjose can't decrypt for (RSA-OAEP-256, ADR 0021) can only be checked by shape.
- **`{ "ok": false, "error": <code> }`**, with no `validate`.

## Rules for `jwt.*` runners

- **The clock.** A runner builds a fixed clock from `now` (in Rust, `FixedClock(now)`; in each binding, its validate call's `now` option, ADR 0028 §4) and never reads its platform's clock. The Rust runner's `jwt_runner_never_reads_the_wall_clock` checks its own source for it.
- **Step order**, the first error being the outcome:
  1. `jwt.validate` (and `jwt.issue`'s `validate`): import `decrypt.key`, then build `decrypt`'s allow-lists and bound, then import `key` or `jwks`, then build the policy from `allowed_algs` and `policy` (the allow-list first, then the `leeway`).
  2. `jwt.issue`: import `key`, then parse `claims`, then import `encrypt.key`, then sign, then encrypt.
  3. Call the library.

  So a **JWK or JWK Set import error is the vector's result**, compared like any other: an RSA private JWK (or a JWK Set holding one, ADR 0029 §3) is `UnsupportedAlgorithm` (ADR 0021), and a set without a `keys` array is `InvalidKey`. A set member that is merely invalid is skipped at import (RFC 7517 §5), which can leave `NoMatchingKey` at validation.
- **One fault per failure vector**, as for `jws.*`; the ADR 0027 §9 precedence vectors put every fault inside `token` itself.
- **Strictness.** The schema is closed at every level: a misspelled member anywhere (`allowed_alg`, `policy.audiences`), a missing `now`, or both `key` and `jwks` fail the run. The `jwt.issue` cross-member rules above (no exact `token` with `encrypt`; `validate` required for `{ "ok": true }` unless `encrypt` is set; no `validate` on a failure vector) and the `profile`/`typ` contradiction fail it too.
- Map `policy` to the binding's validation options member by member, `typ` to its typing mode, `profile` to its access-token policy, `key`/`jwks` to its single-key and key-set forms, and `decrypt` to its nested-JWT call. Never substitute defaults of your own (ADR 0030).
- **Nested JWTs** (`decrypt`, `encrypt`) are wired in every runner now. Their vectors land with the library's nested implementation (feature 0004 T13).

## Features

A vector may need a cargo feature of polyjose, written in `features` as:

| Name in a vector | Cargo feature | Needed by |
|---|---|---|
| `"fixed-rng"` | `insecure-test-vectors` (ADR 0041 §3) | a byte-exact `jwe.encrypt` (`rng_b64u`, `protected_b64u`) |
| `"deflate"` | `deflate` (ADR 0017) | `zip` (`compress`, and the `zip` decrypt vectors), in `features` or `features_absent` |

The test RNG's cargo name may appear only in `crates/polyjose`, `scripts/check-test-vectors-off.sh` and Markdown (that script fails the build otherwise, so no build file can switch it on, ADR 0005); vector files therefore use `"fixed-rng"`. A runner whose build does not enable every listed feature:

- still validates the vector against the schema, and fails it if invalid;
- does not run it, and reports it **SKIPPED with the missing feature names** (the Rust runner prints the cargo name: ``<file>: SKIPPED (needs feature `insecure-test-vectors`)``);
- never counts it as passing.

The bindings never enable `insecure-test-vectors` (ADR 0005), so `fixed-rng` vectors are Rust-only; every RFC output they reproduce also has a `jwe.decrypt` vector that every platform runs.

`features_absent` is the mirror form (ADR 0056): the features a vector must run **without**. A runner whose build enables one of them does the same three things, and reports the vector SKIPPED with `!` before that name (the Rust runner: ``<file>: SKIPPED (needs feature `deflate` off)``). It exists for the binding configuration's decisions, which hold only without a feature: `zip: DEF` and `compress: true` are `UnsupportedAlgorithm` while the bindings build without `deflate` (ADR 0030 §4). In the binding configuration those vectors run everywhere, the `rust-core` reference included. A name may not be listed in both `features` and `features_absent`, and the list may not be empty; a runner fails such a vector.

## Binding readiness

Every vector under `jws-*/`, `third_party/**/jws/`, `jwe/` and `keys/`, and every `jws.*`, `jwe.*` or `keys.*` vector anywhere, must be readable by every binding's own JSON parser unchanged. The Rust runner's `jws_and_keys_vectors_are_binding_ready` and `jwe_vectors_are_binding_ready` tests check it:

- every number is a plain integer (no fraction, no exponent) of magnitude at most 2^32 − 1 (`count` in the schema is a `u32`, as in ADR 0030), so no binding needs a 64-bit-only type or reads a double;
- octets are base64url strings (`*_b64u`), never `*_hex` or raw bytes, and every one a runner decodes is canonical;
- in a `keys.*` vector, every base64url member (`x`, `y`, `d`, `n`, `e`, `k`) of a `jwk` object is canonical.

Every vector under `jwt/`, and every `jwt.*` vector anywhere, must be readable the same way; `jwt_vectors_are_binding_ready` checks it. It uses only strings, booleans, `null`, objects, arrays and numbers of magnitude at most 2^53 − 1 (9007199254740991, the NumericDate range, ADR 0027 §2), which every binding holds exactly, JavaScript's doubles included:

- an integer is written plainly (`1300819380`, `-100`; never `1300819380.0` or `1.3e9`), so a binding reads `now` and every count as an integer;
- a non-integral value (a fractional NumericDate, RFC 7519 §2, in expected `claims`) is a plain decimal (`1300819380.5`), no exponent;
- values outside that range, which the library must reject (`exp: 2^53`, `1e400`), are tested **inside the base64url payload of `token`**, never in the vector JSON;
- the `*_b64u` and `*_hex` rules above apply too.

## Rules for every runner

Each platform's runner (Rust: `crates/polyjose/tests/conformance.rs`) must:

- load every `*.json` file under `vectors/`, recursively (a glob of `conformance/vectors/**`, never a list of directories), `third_party/` included, so a new directory such as `jws-limits/` is picked up without a runner change;
- parse vector files with an input limit of at least 4 MiB, or with the platform's native JSON parser. Vector files are trusted test data, and a vector of a JWS just over the library's 1 MiB default `max_input_len` (ADR 0026 §7) is itself over 1 MiB. The library under test keeps its own defaults;
- **fail** on a file that is not schema-valid, including a misspelled or unknown member anywhere: every object the schema defines is closed;
- **fail** on a vector whose `operation` it does not implement, whether `schema.json` reserves it or not. The only vectors not run are those whose `features` the build lacks or whose `features_absent` it has, reported SKIPPED by name ([Features](#features));
- **fail** when it finds no vector files, so a wrong path can't pass vacuously;
- run every vector and report every failure, not only the first, each naming the file and its `source`;
- write one results file, `target/conformance/<runner>.json`, with an entry for every vector file ([Binding runners](#binding-runners), ADR 0034 §2), and the [vector-set digest](#the-vector-set-digest) of the files it read (ADR 0060).

The Rust runner also checks `schema.json` against its own tables (`schema_and_runner_agree`), so the schema and the runner can't drift apart.

## Binding runners

Every runner (the Rust reference run, the Rust surface run and each binding's) runs every vector file, follows the [rules for every runner](#rules-for-every-runner) and writes **one results file**. `scripts/conformance-parity.sh` then compares each results file with the Rust reference run, so a runner can't pass by running fewer vectors, by skipping one for another reason, or by getting `"ok": false` with another error code (ADR 0034).

### Status per platform

Which operation families each platform's runner runs today. A cell that isn't "runs" is reported as SKIPPED with that reason in the test report, never as passing (pipeline rule 9).

| Platform | Runner | `b64url.*`, `jwk.thumbprint`, `jwks.select`, `jws.*` | `keys.*` | `jwt.*` |
|---|---|---|---|---|
| Rust | `crates/polyjose/tests/conformance.rs` | runs | runs | runs |
| Rust surface | `bindings/surface/tests/conformance.rs` (`polyjose-surface`, ADR 0030) | runs | runs | runs |
| WASM | the shared JS runner (`bindings/js/conformance/`) over `@polyjose/wasm` (0006): `wasm-node`, `wasm-chrome` (wasm-bindgen-test) and `wasm-pkg-node`, `wasm-pkg-chrome`, `wasm-pkg-workerd` (the packed tarball) | runs | runs | runs |
| Node | the shared JS runner (`bindings/js/conformance/`) over `@polyjose/node` (0007): `node` | runs | runs | runs |
| Kotlin (JVM) | `platforms/android/shared-test/kotlin` (`dev.polyjose.conformance`), hosted by `polyjose-jvm`'s `ConformanceTest` | runs | runs | runs |
| Kotlin (Android) | the same runner, hosted by `:polyjose`'s `ConformanceInstrumentedTest` on the emulator (`platforms/android/scripts/run-instrumented.sh`) | runs | runs | runs |
| Swift (iOS) | `platforms/swift/Tests/PolyjoseTests/ConformanceRunner.swift` (0009): `swift-macos` on the macOS host, `swift-ios-sim` on the iOS 27.2 Simulator | runs | runs | runs |

`jwks.select`, and `jwk.thumbprint`'s optional `hash`, run through the surface (`rust-surface`, 0013 T14) and in every binding runner above (the shared JS runner, the Kotlin runner and the Swift runner implement both).

When a binding's runner lands it implements every family it binds, and the never-skip rule applies to it from then on. Each binding's feature updates its row. ADR 0034's parity check then compares its results with the Rust reference run.

### Runner names and results files

Every runner writes `target/conformance/<runner>.json` at the **repository root** (not under `CARGO_TARGET_DIR`), in the format of [`schema/results.schema.json`](schema/results.schema.json). The names are those of ADR 0034 §2, exactly; the schema's `runner` enum is the list the parity check uses.

| Runner | What runs | Feature |
|---|---|---|
| `rust-core` | `crates/polyjose/tests/conformance.rs` (`conformance_vectors`), built with the default features: **the reference run** (ADR 0034 §4) | 0013 T02 |
| `rust-surface` | `bindings/surface/tests/conformance.rs`, the same files through `polyjose-surface` only (ADR 0030) | 0013 T11 |
| `wasm-node`, `wasm-chrome` | the wasm-bindgen-test runs of the WASM adapter (`wasm-pack test --node`, `--headless --chrome`) | 0006 |
| `wasm-pkg-node`, `wasm-pkg-chrome`, `wasm-pkg-workerd` | the packed `@polyjose/wasm` tarball through the shared JS facade and its runner (`bindings/js/conformance/`) | 0006 |
| `node` | `@polyjose/node` through the shared JS facade and its runner | 0007 |
| `jvm` | the generated Kotlin API on the host JVM through JNA (`./gradlew :polyjose-jvm:test`), over `conformance/vectors/` read from the checkout | 0008 T02 |
| `android-emulator` | the same Kotlin runner on the Android emulator (AVD `polyjose-api36`, arm64-v8a), over the vectors bundled as test-APK assets (`platforms/android/scripts/run-instrumented.sh`). Host-optional: with no SDK, AVD or booted emulator, `platforms/android/test.sh` waives it with `SKIPPED-RUNNER (android-emulator: host:<token>)` | 0008 T03 |
| `swift-macos`, `swift-ios-sim` | the Swift API on the macOS host (`swift test`, `platforms/swift/test.sh`) and on a disposable iPhone simulator on the iOS 27.2 runtime (`xcodebuild test`, `platforms/swift/scripts/test-simulators.sh`). `swift-tvos-sim` stays a name in the schema but is not run: the Swift tests run on macOS and the iOS Simulator only (ADR 0046 §2, §4), so parity lists it as `SKIPPED (no results: swift-tvos-sim)` | 0009 |

- **Off-host runs** (a browser page, workerd, the emulator, a simulator) hand their results to the host-side driver, which writes the file on the host. On the iOS Simulator, the Swift conformance test prints the document as one line starting with `POLYJOSE-CONFORMANCE-RESULTS `. It also writes a copy to the host path that the driver passes as `TEST_RUNNER_POLYJOSE_CONFORMANCE_OUT`. `platforms/swift/scripts/test-simulators.sh` extracts the line and requires it to equal that copy byte for byte. It also requires the line's `vectors_digest` to equal the [shell reference](#the-vector-set-digest) over the checkout, and only then writes `swift-ios-sim.json`.
- **CI matrix runs** append their target to the file name: `node-x86_64-unknown-linux-musl.json`, `jvm-linux-x86-64.json`. The file's `runner` member stays the bare name (`node`), and the parity check compares the file like `<runner>`.
- **Rust builds with features** (`cargo test -p polyjose --all-features`, as `scripts/test-all.sh rust` runs) write `rust-core-<features>.json`, the enabled feature names joined by `-` (for example `rust-core-deflate-fixed-rng.json`). They aren't the reference, and the parity check ignores them. Only the default-features build writes `rust-core.json`.
- **`rust-surface`** never enables `fixed-rng`: the surface has no reproducible encryption (ADR 0005), so those vectors are always skipped with `feature:fixed-rng`, as in every binding. It enables `deflate` exactly when the core under it has it, which it finds out through the surface (a `compress` encryption succeeds, or is `UnsupportedAlgorithm`). Only the binding configuration, no `deflate`, writes `rust-surface.json`. A build in which Cargo turns the core's `deflate` on (`cargo test --workspace --all-features`) still runs and checks every vector but writes no results file, since its skip set is not the bindings' (ADR 0034 §3).
- **Test doubles** (a runner tested against a fake backend) never write to `target/conformance/`.

### The results file

```json
{ "runner": "node", "polyjose": "0.1.0",
  "vectors_digest": "9a06f1efdd269176088cb0e6bfc6a7e4d4f74aa3d1b1b8fc6c879fdbb82ac7d1",
  "features": [], "error_codes": ["InvalidBase64", "…"],
  "results": [
    { "id": "jws-rfc7515/a1-hs256-compact-verify.json#0", "source": "RFC 7515 App. A.1", "op": "jws.verify",
      "status": "pass", "actual": { "ok": true } },
    { "id": "jwe/zip/bound-exact-decrypts.json#0", "op": "jwe.decrypt", "status": "skipped", "reason": "feature:deflate" } ] }
```

| Member | Rule |
|---|---|
| `runner` | The runner name above, without any file-name suffix. |
| `polyjose` | The binding's `version()` (ADR 0030 §4); for the Rust runners, the crate version. It must equal the reference's. |
| `vectors_digest` | The [vector-set digest](#the-vector-set-digest) of the files the runner read: 64 lowercase hex characters (ADR 0060 §1). Required. It must equal the reference's. |
| `features` | The vector feature names (see [Features](#features)) the build enables. `[]` for every binding and for the reference. |
| `error_codes` | The binding's `error_codes()`, in its order; for the Rust runners, `Error::CODES`. It must equal the reference's list, in the same order (ADR 0034 §8). |
| `results` | **One entry per `*.json` file** under `vectors/`, including a file that doesn't parse. Ids are unique; order is free. |
| `results[].id` | The file's path under `conformance/vectors/`, with `/` separators on every platform, then `#0`: every file holds one vector (ADR 0034 §1, ADR 0045 §4). Derived, never written by hand. |
| `results[].source` | Optional: the vector's `source`. Not compared. |
| `results[].op` | The vector's `operation`, as written. Required unless the file doesn't parse or names none. |
| `results[].status` | `pass`: the vector ran and met its expectation (exact outputs, shape and round-trip checks included). `skipped`: only under [the skip rule](#the-skip-rule). `fail`: anything else. |
| `results[].actual` | The outcome of the operation's calls in the [mapping](#operation-mapping): `{ "ok": true }` when every call returned, or `{ "ok": false, "error": <code> }` with the first call's error code. It's the library's outcome, recorded before any comparison, so a vector whose expectation is wrong still records what happened. Required for `pass`; on a `fail`, present when the operation completed, its runner checks included; never on a skip. The output comparison after the operation decides `pass` or `fail` but never changes `actual`. A runner check *inside* the operation (a shape or round-trip check of `verify_with`, `decrypt_with` or a `jwt.issue` round trip, or an input the runner can't decode) that fails makes the vector a `fail` **without** `actual`, as the Rust reference does. |
| `results[].reason` | `skipped`: `feature:` and the feature names of [the skip rule](#the-skip-rule). `fail`: a message saying why (the file, the `source`, the problem). |

### The vector-set digest

`vectors_digest` binds a results file to the exact vector files the runner executed, so a copied, templated or stale results file, or an Android or iOS bundle whose copy of the vectors has drifted from the checkout, fails parity even when its ids and outcomes match (ADR 0060). Every runner computes it itself, while it reads the vectors:

1. **One line per vector file read.** These are the `*.json` files under `vectors/` (recursively), exactly the files that get a results entry. `README.md`, `NOTICE.md`, the `.jwk` key files and `generate.mjs` aren't vectors and aren't hashed. A file the runner could not read, or a symbolic link, is a `fail` and gets **no line**.
2. **The line** is `<id>` TAB `<hash>` LF, encoded as UTF-8. `<id>` is exactly the results entry's `id` (`jws/b.json#0`). `<hash>` is the lowercase hex SHA-256 of the file's **raw bytes as parsed**, with no line-ending, BOM or encoding change, and not taken from a second read, a manifest or a digest computed at build time. A runner with bundled vectors (Android assets, an iOS bundle, `include_bytes!`) hashes the bundled bytes it parsed.
3. **Sort the encoded lines by their bytes** (unsigned, lexicographic; a shorter prefix first). Don't sort platform strings or paths by component: JS and Kotlin `String` order is UTF-16, Swift's `String <` is neither, and Rust's `Path` order puts `jws/b.json` before `jws-x/c.json`, while byte order puts `-` (0x2D) before `/` (0x2F).
4. **`vectors_digest`** is the lowercase hex SHA-256 of the concatenated sorted lines.

An empty corpus is invalid: a runner that read no vector file fails its run and writes no results file, and parity refuses the SHA-256 of the empty input, `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`, in any file.

Each runner uses **its platform's own SHA-256, never polyjose's API under test** (ADR 0060 §5):

| Runner(s) | SHA-256 | Where |
|---|---|---|
| `rust-core`, `rust-surface`, `wasm-node`, `wasm-chrome` | the `sha2` crate, called directly as a test oracle (a dev-dependency where the crate lacks it, ADR 0016 §5) | `crates/polyjose/tests/conformance.rs`, `bindings/surface/tests/conformance.rs`; 0006 for `wasm-*` |
| `node`, `wasm-pkg-node` | `node:crypto` `createHash("sha256")`. `node-main.ts` reads each file once as bytes, hashes them, and only then decodes them as UTF-8 for the runner | `bindings/js/conformance/node-main.ts` |
| `wasm-pkg-chrome`, `wasm-pkg-workerd` | `crypto.subtle.digest("SHA-256", bytes)`: the driver fetches each file as bytes and calls `vectorsDigest(files, subtleSha256)` from `bindings/js/conformance/runner.ts` | 0006 |
| `jvm`, `android-emulator` | `java.security.MessageDigest.getInstance("SHA-256")` | 0008 |
| `swift-macos`, `swift-ios-sim` | CryptoKit `SHA256`, over the bytes bundled in the test bundle (`Bundle.module`), hashed before parsing; `swift-tvos-sim` too if that run is ever brought back (ADR 0046) | `platforms/swift/Tests/PolyjoseTests/VectorCorpus.swift` |

**Every new runner (features 0006 to 0009) computes the digest from its first commit and unit-tests the worked example below.** A runner that can't compute it can't write a valid results file, so it fails parity; it is never skipped.

**Worked example** (ADR 0060 §4). A directory standing in for `vectors/` holds `a.json` = `7b 7d` (`{}`), `jws/b.json` = `7b 7d 0a` (`{}` LF), `jws-x/c.json` = `ef bb bf 7b 7d` (a UTF-8 BOM, then `{}`) and `README.md` = `notes` (not a vector). The sorted lines (`→` is the TAB) are:

```
a.json#0→44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a
jws-x/c.json#0→aa25e978046d680ef8740d837e6de5bc1e2a2dc6089dbda1012544b538d53f65
jws/b.json#0→ca3d163bab055381827226140568f3bef7eaac187cebd76878e0b63e9e442356
```

and `vectors_digest` is `9a06f1efdd269176088cb0e6bfc6a7e4d4f74aa3d1b1b8fc6c879fdbb82ac7d1`. The tests `vectors_digest_follows_the_adr_0060_worked_example` (both Rust runners) and `bindings/js/test/vectors-digest.test.ts` check it.

**Shell reference**, an oracle independent of every runner (it assumes no newline or backslash in a file name, which the corpus never has; on Linux use `sha256sum` for `shasum -a 256`). When two digests differ, compare these per-file lines on both sides to find the file.

```sh
cd conformance/vectors &&
find . -type f -name '*.json' | sed 's|^\./||' |
  while IFS= read -r p; do printf '%s#0\t%s\n' "$p" "$(shasum -a 256 "$p" | cut -d' ' -f1)"; done |
  LC_ALL=C sort | shasum -a 256 | cut -d' ' -f1
```

### The skip rule

A vector is skipped **only** when its `features` lists a feature the runner's build doesn't enable (ADR 0034 §3), or its `features_absent` lists one the build enables (ADR 0056). `reason` is `feature:` followed by the missing `features` names in the vector's order, then each enabled `features_absent` name as `!<name>` in its order, comma-separated: `feature:fixed-rng`, `feature:deflate,fixed-rng`, `feature:!deflate`, `feature:fixed-rng,!deflate`. The vector is still validated against `schema.json` first, and a schema-invalid one is a `fail`.

The binding configuration for 0.1.0 is the core's default features: never `fixed-rng` (ADR 0005), and no `deflate` (ADR 0030 §4). So every binding skips exactly the vectors the `rust-core` reference skips, with the same reasons. An unknown operation, an operation the runner hasn't mapped, an unreadable or unparseable file, an exception in the harness, and a host-side error that isn't a polyjose error (implementer note 8) are each a **`fail`**, never a skip.

### The parity check

`scripts/conformance-parity.sh [dir]` (default `target/conformance/`) needs `node` and nothing else. It validates every results file against `schema/results.schema.json` (so a file without a well-formed `vectors_digest` fails, the reference included), checks that each file's `runner` matches its file name, that no id appears twice and that its `vectors_digest` is not the SHA-256 of the empty input, then compares every file with `rust-core.json`. It checks for:

- the same `polyjose` version, printing both on a mismatch, so equal results from another build or release don't pass;
- the same `vectors_digest`, printing `FAIL: <file>: vectors_digest differs: rust-core <hex> | <runner> <hex>`, so results from another vector corpus don't pass even when every id, status and outcome agrees (ADR 0060 §6);
- the same set of ids;
- the same `status` per id, and the same `reason` for a skip;
- the same `actual` (`ok`, and the error code) per executed id;
- the same `error_codes` list;
- no `fail` entry, in any file, the reference included.

All of these are checked together, so a file can fail on several at once. The digest binds a file to a corpus and the version to a release; neither proves that a runner executed what it reports, so each runner's own expected-versus-actual check stays (ADR 0060 §6).

Each difference is printed as a `FAIL:` line with the id and both outcomes, and the exit status is 1. A missing, malformed or feature-built `rust-core.json` also exits 1. A runner without a file is printed as `SKIPPED (no results: <runner>)`, never as passing, and doesn't fail the check. Usage and tool errors (no `node`) exit 2. The script's own tests are in `scripts/tests/conformance-parity/`. `scripts/test-all.sh` runs them with the other negative tests, and 0013 T04 wires the check itself in after the platform suites.

### Operation mapping

How each vector `operation` maps to the ADR 0030 operations. Names are the surface's (`snake_case`); hosts call the `camelCase` form (`jws_verify_compact` → `jwsVerifyCompact`, `protected_b64u` → `protectedB64u`, `allowed_algs` → `allowedAlgs`). Record fields not listed are left unset, so the core default applies. A runner never writes a default of its own (ADR 0030 §3).

- **Arguments.** JSON-valued arguments (a JWK, a JWK Set, a header, a JSON JWS or JWE, claims) are passed as **JSON text**: the vector's own text for that member, or an order-preserving re-serialization of it (see implementer note 4 for claims). `*_b64u` members are decoded by the runner to bytes, and a non-canonical value fails the vector (it's never an outcome). Strings and integers are passed as given.
- **Outputs.** Byte results are written back as canonical base64url (RFC 4648 §5, no padding) with any correct encoder. JSON results are parsed and compared as JSON values, as each operation's section says.
- **Calls.** The runner makes exactly the calls in the table, in that order, and none of its own before them (no `jwk_parse` to pre-check a key). The per-family step orders above happen inside each surface call, and the `rust-surface` run's parity with `rust-core` proves they match. `actual` is the outcome of these calls; the round-trip calls in the last column are checks, so they never set `actual`.

| Vector `operation` | ADR 0030 call(s), with the vector members they take | Outputs and checks |
|---|---|---|
| `b64url.encode` | `base64url_encode(bytes)`, where `bytes` is `bytes_hex` decoded by the runner's own hex code | `b64u` = the result |
| `b64url.decode` | `base64url_decode(b64u)` | `bytes_hex` = the result as lowercase hex |
| `jwk.thumbprint` | `jwk_thumbprint(jwk, hash)`, then `jwk_thumbprint_uri(jwk, hash)`. The surface's `hash` is optional and takes the names of ADR 0054 §8.2, which the core parses (`ThumbprintHash::from_name`), so the vector's `hash` is passed exactly as given, with no runner mapping, and an absent `hash` is passed as absent (the core default, SHA-256; ADR 0054 §9). A name the core rejects is the vector's outcome. | `thumbprint`, `thumbprint_uri` |
| `jwks.select` | `jwks_select(jwks, JwkSelector { kid, alg, key_use })`: `jwks` as JSON text, and each selector member that is present, as given; an absent one stays unset. The surface imports the set (`JwkSet::from_json`), builds the core selector (`kid`, then `alg` by `KeyAlg::from`, then `key_use` by `KeyUse::from`) and selects (ADR 0054 §4, §9), so the runner maps, normalizes or rejects nothing. Hosts name the member `keyUse`. | `jwk` = the returned key (a secret-bearing string) parsed as JSON and compared as a JSON value |
| `jws.sign`, `serialization` `"compact"` | `jws_sign_compact(payload, signers[0].key, JwsSignOptions { protected_b64u: signers[0].protected_b64u, detached })`. The header always goes as `protected_b64u`, never as `protected_header`. | `jws` (a string, compared exactly), or the `verify_with` round trip |
| `jws.sign`, `"flattened"` | `jws_sign_flattened(payload, JwsSigner { key, protected_b64u, unprotected_header: header }, detached)`, from `signers[0]`. A signer may have only `header` (note 11). | `jws`: the returned JSON text parsed and compared as a JSON value; or `verify_with` |
| `jws.sign`, `"general"` | `jws_sign_general(payload, [JwsSigner, …], detached)`: one `JwsSigner` per `signers` entry, in order, built as for flattened | as flattened |
| `jws.sign` round trip (`verify_with`) | check: the output's shape (three compact parts; `signature` without `signatures`; one `signatures` entry per signer), then `jws_verify_compact` or `jws_verify_json` with `verify_with.key` and `JwsVerifyOptions { allowed_algs: verify_with.allowed_algs, detached_payload }`, where `detached_payload` is set only when `detached` is `true`, to the signed payload's **decoded octets** (`payload_b64u` decoded, not its base64url text) | the verified payload equals `payload_b64u`; any failure here is a `fail` |
| `jws.verify` | a string `jws`: `jws_verify_compact(jws, key, options)`; an object: `jws_verify_json(<its JSON text>, key, options)`, with `JwsVerifyOptions { allowed_algs, detached_payload: detached_payload_b64u, max_input_len, max_signatures }` | `payload_b64u` = `JwsVerified.payload`, `alg`, `signature_index` |
| `keys.import_pem` | `jwk_from_pem(pem)` | `jwk` = the result as an object; an `oct` result fails the vector |
| `keys.export_pem` | `jwk_to_pem(jwk, format)`; `format` is passed as given (`pkcs8`, `sec1`, `spki`, `pkcs1`) | `pem` (exact text) |
| `keys.import_der` | `jwk_from_der(der, format)`, where `der` is `der_b64u` decoded | `jwk`, as `keys.import_pem` |
| `keys.export_der` | `jwk_to_der(jwk, format)` | `der_b64u` = the result |
| `keys.generate_for` | `jwk_generate_for_alg(alg)`, `alg` passed as given | `shape`, after the checks of [`keys.generate_for`](#keysgenerate_for). The import-back check is `jwk_parse(<the generated JWK>)`, compared with it as a JSON value. Then the `use_with` round trip, when the vector has one (note 14) |
| `keys.generate_oct`, `_ec`, `_okp` | `jwk_generate_oct(len_bytes)`, `jwk_generate_ec(crv)`, `jwk_generate_okp(crv)` | `shape` (no `alg`), after the same checks; then the `use_with` round trip (note 14) |
| `jwe.encrypt`, `"compact"` | `jwe_encrypt_compact(plaintext, options)` | `jwe` (a string), or the `decrypt_with` round trip |
| `jwe.encrypt`, `"flattened"` or `"general"` | `jwe_encrypt_json(plaintext, options, serialization)` | `jwe`: the JSON text parsed and compared as a JSON value; or `decrypt_with` |
| `jwe.encrypt` options | `JweEncryptOptions { enc, recipients, protected_header: protected, shared_unprotected_header: unprotected, aad: aad_b64u, compress }`, with one `JweRecipient { alg, key, header, apu: apu_b64u, apv: apv_b64u, p2c, p2s_len }` per `recipients` entry, in order. `rng_b64u` and `protected_b64u` occur only in `fixed-rng` vectors, which every binding skips, so they have no mapping. | |
| `jwe.encrypt` round trip (`decrypt_with`) | check: the output's shape (five compact parts; `ciphertext` without `recipients`; one `recipients` entry per recipient), then `jwe_decrypt_compact` or `jwe_decrypt_json` with `decrypt_with.key` and `JweDecryptOptions { allowed_algs, allowed_enc }` from `decrypt_with` | the plaintext equals `plaintext_b64u`; any failure here is a `fail` |
| `jwe.decrypt` | a string `jwe`: `jwe_decrypt_compact(jwe, key, options)`; an object: `jwe_decrypt_json(<its JSON text>, key, options)`, with `JweDecryptOptions { allowed_algs, allowed_enc, understood_crit, max_input_len, max_recipients, max_pbes2_count, max_decompressed_len }` | `plaintext_b64u` = `JweDecrypted.plaintext`, `recipient` = `recipient_index` |
| `jwt.validate`, no `decrypt` | `key`: `jwt_verify(token, key, options)`; `jwks`: `jwt_verify_with_jwks(token, jwks, options)` | `claims` = `JwtVerified.claims` (a JSON value, numbers as doubles, note 1), `alg`, and `key_index` exactly when the input has `jwks` (note 2) |
| `jwt.validate`, with `decrypt` | `key`: `jwt_decrypt_nested(token, decrypt.key, JweDecryptOptions { allowed_algs: decrypt.allowed_algs, allowed_enc: decrypt.allowed_enc, max_pbes2_count: decrypt.max_pbes2_count }, key, options)`; `jwks`: `jwt_decrypt_nested_with_jwks(…, jwks, options)`. Beyond the two allow-lists, `decrypt` sets **only** `max_pbes2_count` (when present); every other `JweDecryptOptions` field stays unset, so the core default applies. | as above, from `JwtNestedVerified.inner` |
| `jwt.validate` options | `JwtVerifyOptions` from `now`, `allowed_algs` and `policy`, member by member (the table below) | |
| `jwt.issue` | `jwt_sign(claims, key, JwtSignOptions { alg, … })`, where `typ` absent sets nothing (the default `JWT`), a string sets `typ`, and `null` sets `omit_typ: true` (note 3). `access_token` and `header` are never set: an access token's `typ` comes as the string `at+jwt`. With `encrypt`: then `jwt_encrypt_nested(<the signed JWT>, JweEncryptOptions { enc: encrypt.enc, recipients: [JweRecipient { alg: encrypt.alg, key: encrypt.key }] })`. | `token` (exact), or the `{ "ok": true }` checks (note 10); with `validate`, the token also validates as for `jwt.validate` |

`policy` → `JwtVerifyOptions`, for `jwt.validate` and `jwt.issue`'s `validate`:

| Vector member | `JwtVerifyOptions` field |
|---|---|
| `now` | `now` (always present: no runner reads a clock, ADR 0028 §4) |
| `allowed_algs` | `allowed_algs` |
| `policy.issuer` | `issuers`: a string becomes a one-element list, an array is passed as given |
| `policy.audience` | `audiences` (an array only) |
| `policy.subject` | `subject` |
| `policy.leeway` | `leeway` |
| `policy.max_age` | `max_age` |
| `policy.require` | `required_claims` |
| `policy.allow_missing_exp` | `allow_missing_exp: true` when `true`; `false` or absent sets nothing (note 6) |
| `policy.ignore_audience` | `ignore_audience: true` when `true`; `false` or absent sets nothing |
| `policy.typ` | mode `default`: nothing; mode `exact`: `typ: value`; mode `any`: `any_typ: true` |
| `policy.profile` | `profile: "access_token"`. With `typ` mode `default` the vector is broken: a `fail` |
| `policy.max_key_candidates` | `max_key_candidates` |
| (none) | `max_input_len` is never set by a vector |

### Implementer notes

Points the sections above imply but that are easy to get wrong in a binding runner (from the 0004 T10 test report, and ADR 0045):

1. **Claims numbers are compared as doubles.** Normalize both sides to IEEE 754 doubles before comparing `claims`: a Kotlin `Long` or Swift `Int` from the vector's parser against the `Double` the library's claims parse to, and vice versa. Vector JSON never holds an integer beyond 2^53 − 1 ([Binding readiness](#binding-readiness)), so the conversion is exact. Larger values appear only inside token payloads, where the library rejects them.
2. **`key_index` is present exactly when the input has `jwks`, and `0` is a value.** Treat the binding's absent form (`undefined`, `null`, Kotlin `null`, Swift `nil`) as absent, and test for presence, never truthiness: JavaScript's `if (keyIndex)` drops index `0`.
3. **`typ: null` is not an absent `typ`** in `jwt.issue`. `null` omits the header parameter (`omit_typ: true`), while an absent member keeps the default `JWT` (nothing set). The runner's JSON model must keep the two apart. `JSON.parse` does; Swift `Codable` decodes both as `nil` unless the runner checks `contains`, and a Kotlin `JsonObject` needs `containsKey` plus a `JsonNull` check.
4. **Claims member order matters for exact tokens.** The library serializes the registered claims first, then the others in the order given (ADR 0027 §1). So `claims` goes to `jwt_sign` as **ordered JSON text**: the exact slice of the vector file, or the output of an order-preserving parser. A JavaScript object moves integer-like keys (`"1"`) to the front, and a Swift dictionary has no order, so neither may produce that text. The current vectors have no integer-like claim name. A runner that can't keep the order must fail such a vector, not reorder it.
5. **`now` and every count are JSON integers.** Read them as integers and pass them as integers. JSON Schema's `integer` also admits `1300819439.0`, but the vectors never use that form ([Binding readiness](#binding-readiness)). A runner treats a fraction or exponent there as a broken vector (`fail`), as the Rust runner does, and never writes one.
6. **`policy.audience` is an array only; `policy.issuer` is a string or an array.** A boolean member set to `false` (`allow_missing_exp`, `ignore_audience`) means "keep the default". Leave the option unset. Never call an opt-out, or set a field the core reads as configured, because of a `false`.
7. **The policy is built before the token is parsed.** The Rust runner builds the policy, checking the allow-list and then `leeway` (over 600 is `InvalidClaim`), before the library looks at the token, and the surface's `jwt_verify*` and `jwt_decrypt_nested*` calls must do the same (the `rust-surface` parity run checks it). A binding must not validate its options lazily after reading the token. A vector with a bad `leeway` and a bad token would then report the other error. The one-fault rule keeps today's vectors from depending on this, but only by convention.
8. **The outcome's `error` is the core code.** Read it from the binding's error: JS `PolyjoseError.code`, Kotlin `PolyjoseException.code()`, Swift `PolyjoseError.code()` (ADR 0030 §5), never from a class name or message. Any other thrown error is not an outcome, and the vector is a `fail`. That covers a JS `TypeError`, a napi `InvalidArg` and a Kotlin `IllegalArgumentException`.
9. **JWK Set import is lenient, as in the core.** A member that is merely invalid is skipped (RFC 7517 §5), which can leave `NoMatchingKey` at validation. So the runner passes the vector's `jwks` text to the surface unchanged, and never parses, filters or pre-validates the set itself. A set without a `keys` array is `InvalidKey`, and a set holding an RSA private JWK is `UnsupportedAlgorithm` (ADR 0021, ADR 0029 §3).
10. **`jwt.issue` `{ "ok": true }` is runner logic.** The runner checks that the token has three compact parts (five with `encrypt`), then validates it with `validate` through the `jwt.validate` mapping. The validated `alg` must be the issued one, and the claims must equal the issued `claims` as a JSON value. Any failure there is a `fail`, and the result then has **no** `actual` (as for every failed runner check inside an operation, see `results[].actual`); a passing vector's `actual` is `{ "ok": true }`.
11. **A `jws.sign` signer may have only an unprotected header** (RFC 7515 §7.2.1, ADR 0045 §1): `header` and no `protected_b64u`, in the flattened and general serializations. It maps to a `JwsSigner` with `unprotected_header` only, and the surface signs it over `"." || payload`. Compact signers always have `protected_b64u`.
12. **The RFC 7520 §4.7 vectors are never skipped.** `third_party/rfc7520/jws/4-7-unprotected-only-hs256-{flattened,general}-{sign,verify}.json` need no feature, so every binding runs them (ADR 0045 §1), like every other vector without `features`.
13. **`features_absent` vectors run in every binding** (ADR 0056). A binding builds without `deflate`, so `binding-surface/jwe-decrypt-zip-def-without-deflate.json` and `jwe-encrypt-compress-without-deflate.json` run and must give `UnsupportedAlgorithm`, as `rust-core` does. Compute the skip from both lists, missing names first, and never treat `features_absent` as `features`: `feature:deflate` where the reference has `feature:!deflate` is a parity failure.
14. **`use_with` is runner logic, with surface calls only.** Without `enc`: `jws_sign_compact(b"polyjose", <the key>, JwsSignOptions { protected_header: {"alg": alg} })`, then `jws_verify_compact(<token>, <public form>, JwsVerifyOptions { allowed_algs: [alg] })`. With `enc`: `jwe_encrypt_compact(b"polyjose", JweEncryptOptions { enc, recipients: [JweRecipient { alg, key: <public form> }] })`, then `jwe_decrypt_compact(<token>, <the key>, JweDecryptOptions { allowed_algs: [alg], allowed_enc: [enc] })`. The public form is `jwk_to_public(<the key>)`, or the key itself for `oct`. Any failure there is a `fail` without `actual`, as for `verify_with`.

## Writing vectors

- Name files after what they check, grouped by operation: `vectors/b64url/encode-rfc4648-10-foo.json`, `vectors/jwk-thumbprint/reject-oct-k-padded.json`.
- Key vectors live in `keys/`. Successes are `import-*`, `import-der-*`, `export-*`, `export-der-*` and `generate-*`; failures are `reject-*`. Their expected values never come from polyjose:
  - JWKs, PEM texts and DER are the committed key fixtures (`crates/polyjose/tests/data/keys/`: OpenSSL 4.1.0 output and the RFC golden files). The DER is each PEM fixture's body.
  - `generate-*` shapes are the RFC sizes and curves.
  - The RSA modulus-bound keys are built by the generator, which also writes their JWK.

  `source` names the RFC, OpenSSL for a generated key, or `polyjose` for a rule the description cites. `crates/polyjose/tests/data/keys/regen/make-keys-vectors.py` writes them all (`python3 -I`); edit the script, not the files. **Every binding runner (WASM, Node, Kotlin and Swift, 0006–0009) runs `keys.*` (see [Binding runners](#binding-runners)), and the never-skip rule above applies to each.**
- JWE vectors live under `jwe/`, one directory per task and kind: `jwe/compact/` (RFC 7516 Appendix A, RFC 7520 §5.6 and §5.8, round trips), `jwe/negative-structure/` (the error contract, one vector per rule; `source` "polyjose" or the RFC whose vector is refused), and the per-family and JSON directories of the later JWE tasks. RFC 7520 values are generated from the vendored ietf-jose cookbook (`crates/polyjose/tests/third_party/ietf-jose-cookbook/`), not transcribed.
- JWS vectors are grouped by origin: `jws-rfc7515/` (RFC 7515 Appendix A and F; `source` "RFC 7515 App. A.x" or "RFC 7515 App. F"), `jws-rfc7797/`, `jws-rfc8037/`, `jws-oracle/` (generated independently of polyjose; `source` names the tool and its versions), `jws-negative/` (`source` names the RFC section, CVE or ADR enforced), `jws-limits/` (the default ADR 0026 §7 limits, at and just over each), and `third_party/rfc7520/jws/` (the RFC 7520 §4 cookbook).
- Check every expected value against the RFC text yourself. If the RFC doesn't print the value, derive it independently of polyjose (for example with Python's `hashlib` over the hand-built input) and say so in `description`.
- **Deterministic algorithms** (HMAC, EdDSA) also have `sign` vectors with an exact expected output. **Randomized ones** (ECDSA, JWE) are checked by round trip (`verify_with`) plus a `verify`/`decrypt` vector of the RFC's published output. RS\*/PS\* are verify-only (ADR 0021): only `verify` vectors, and `sign` vectors that expect `UnsupportedAlgorithm`.
- **Negative vectors are mandatory:** tampered signatures, `alg: none`, alg/key mismatch, wrong `crit`, expired JWTs, invalid curve points, non-canonical encodings.
- Imported upstream suites that every platform runs (the RFC 7520 cookbook) live in `vectors/third_party/`, converted to this format, with their licenses alongside them (non-JSON files are ignored).
- JWK Set selection vectors live in `jwks-select/`, one per file (ADR 0045), named by outcome (see [`jwks.select`](#jwksselect)). `source` cites the ADR 0054 rule and the RFC section, and `description` states the rule that decides the outcome. That outcome is written by hand from the ADR 0054 text in `tools/jwk-oracle/specs/select.json`. It is never computed by polyjose, and the generator never decides one. Keys are the committed fixtures: RFC 7517 App. A, `tools/jwt-oracle/keys.json`, `crates/polyjose/tests/data/jwe/rsa-bound/rsa1024.jwk.json`, RFC 8037 A.6's X25519 key and the `jws-oracle` secp256k1 key. Edit the spec and rerun the generator; don't edit the files.
- JWT vectors live under `jwt/`, one vector per file like every other (ADR 0045), in one directory per origin: `jwt/rfc7519/` (the RFC 7519 §3.1 and §6.1 examples and the RFC 7515 A.2 token that is RFC 7519 A.2's inner JWT; `source` the RFC section), and the directories of feature 0004 T11–T13 (oracle positives, negatives, nested). Tokens that aren't RFC-published come from `tools/jwt-oracle` (`node:crypto`), never from polyjose; a spec given to it as a single entry writes a single vector, which is the form a vector file must have. An expected token or value an RFC doesn't print is derived independently and the `description` says how (for example `jwt/rfc7519/3-1-hs256-issue-exact.json`, an HMAC computed with Python's `hmac`).
- **`binding-surface/`** pins the core's defaults and security decisions that a binding could otherwise re-state or bypass (ADR 0034 §6), so the first vector to fail when a binding substitutes a default of its own is one of these. Each `source` names the ADR it pins. Apart from the two `features_absent` vectors below, they need no feature, so every platform runs them:
  - allow-lists (ADR 0007): `jws-verify-allowed-algs-{empty,none-only}`, `jwe-decrypt-allowed-algs-{empty,none-only}`, `jwe-decrypt-allowed-enc-empty`, all `AlgorithmNotAllowed`;
  - the PBES2 bound (ADR 0023): `pbes2-p2c-10000-default-decrypts`, `pbes2-p2c-10001-default-fails` (`DecryptionFailed`), `pbes2-p2c-10001-bound-20000-decrypts`; the per-token budget (ADR 0050 §2): `pbes2-two-recipients-over-default-budget` (`DecryptionFailed`) and `pbes2-two-recipients-budget-raised`;
  - JWS limits (ADR 0026 §7): `jws-verify-17-signatures-default` and `jws-verify-max-input-len-small`, both `InvalidFormat`;
  - RSA public-key only (ADR 0021) and no RSA-OAEP (ADR 0022): `jws-sign-rsa-private-jwk`, `jws-sign-rs256-public-key`, `jwe-decrypt-rsa-oaep-256` and `jwe-encrypt-rsa-oaep`, all `UnsupportedAlgorithm`;
  - JWK Set selection (ADR 0029): `jwt-jwks-kidless-second-key` (`key_index` 1) and `jwt-jwks-no-candidate` (`NoMatchingKey`);
  - no DEFLATE in the binding configuration (ADR 0030 §4): `jwe-decrypt-zip-def-without-deflate` and `jwe-encrypt-compress-without-deflate`, both `UnsupportedAlgorithm`. They have `features_absent: ["deflate"]` (ADR 0056), so the only skips among these files are in builds with `deflate` (`feature:!deflate`);
  - one vector per generator (ADR 0030 §4, ADR 0034 §6), by shape and a `use_with` round trip: `generate-oct-32-hs256`, `generate-ec-p256-es256`, `generate-okp-ed25519-eddsa`, `generate-okp-x25519-ecdh-es`; the `oct` length bound, `generate-oct-15-invalid-key` (`InvalidKey`); and `generate-for-alg-es256` and `generate-for-alg-a128kw`, which add the round trip to `jwk_generate_for_alg`.

  Pins that existing vectors already make, which every platform runs too: a `dir` JWE with an unprotected `alg` is `InvalidHeader` (ADR 0050 §1: `jwe/negative-cross-mode/dir-alg-shared-enc-protected.json`, `dir-no-protected-header.json`); an unprotected-only JSON signer (ADR 0045 §1: `third_party/rfc7520/jws/4-7-unprotected-only-hs256-*.json`); an access token whose `client_id` is a number is `InvalidClaim` (ADR 0052: `jwt/negative/identity-access-token-client-id-not-string-number.json`); `jwk_generate_for_alg` per algorithm, by shape (`keys/generate-*.json`, `keys/reject-generate-*.json`, including `ECDH-ES` → `InvalidKey`).

  The SHA-1 thumbprint pin (ADR 0022, ADR 0054 §8.2) is made by feature 0015's `jwk-thumbprint/hash-reject-sha-1.json` and `hash-reject-upper-sha-1.json` (`UnsupportedAlgorithm` from the core's `ThumbprintHash::from_name`, through the optional `hash` of 0013 T14), with `hash-reject-invalid-key-p256-off-curve.json` for the ADR 0057 §2 order (the import error first). They need no feature, so every platform runs them; `binding-surface/` has no copy.

  `binding-surface/generate.mjs <repo-root> [<out-dir>]` writes them all: the RFC inputs come from the committed vectors it names, and the PBES2 tokens are built with node:crypto from SHA-256-derived bytes and opened with it before writing. Edit the script, not the files.
- **Wycheproof is not here.** It lives in `crates/polyjose/tests/third_party/wycheproof/`, in its upstream format, because it is a Rust-layer suite (ADR 0008 layer 1): it exercises the primitives through polyjose's JOSE layer, and the bindings add nothing to that.

## Tools

The scripts that generated or check vectors live in [`tools/`](tools/). They read only data (the vendored ietf-jose cookbook and Wycheproof files, the RFC text, committed key files) and use only Node's built-ins (node:crypto, which is OpenSSL) and Python's standard library: no npm or pip packages, and none of them calls polyjose. Paths below are relative to this directory (`conformance/`). The index of the JWE vectors, with the generator of each directory, is [`vectors/jwe/README.md`](vectors/jwe/README.md).

- **`tools/jwe/reproduce.sh <rfc-dir>`** re-runs every JWE generator below into a temporary directory and compares each file it writes with the committed vector, byte for byte; a historical generator is reported as such. `<rfc-dir>` holds `rfc7516.txt` and `rfc7517.txt` from `https://www.rfc-editor.org/rfc/` (the script checks their SHA-256). The Node generators write the Node and OpenSSL versions into `source` or `description`, so they reproduce byte for byte with the versions named in the committed files (Node.js 24.21.0, OpenSSL 3.5.8); another version changes only that text.
- **`vectors/binding-surface/generate.mjs <repo-root> [<out-dir>]`**, the one generator kept beside its vectors, writes the 27 files of `binding-surface/` (0013 T11, T15, ADR 0034 §6; see [Writing vectors](#writing-vectors)) and reproduces them byte for byte with the Node version named in their descriptions.
- **`tools/jwk-oracle/thumbprints.mjs <out-dir>`** writes the 25 `jwk-thumbprint/` files named `sha384-*`, `sha512-*` and `hash-*` (feature 0015 T03, ADR 0054 §8): SHA-384 and SHA-512 thumbprints of six RFC keys, the absent-hash default, the accepted aliases and the rejected names. It hand-builds the RFC 7638 §3.3 hash input and hashes it with node:crypto, after checking that it reproduces RFC 7638 §3.1, RFC 8037 A.3 and RFC 9278 §6. A re-run with Node.js 24.21.0 / OpenSSL 3.5.8 reproduces the files byte for byte. Its [README](tools/jwk-oracle/README.md) lists the keys and the panva/jose 6.2.15 cross-check.
- **`tools/jwk-oracle/select.mjs <specs/select.json> <out-dir>`** writes the 64 `jwks-select/` files (feature 0015 T04, ADR 0054 §1–§4), one per entry of [`tools/jwk-oracle/specs/select.json`](tools/jwk-oracle/specs/select.json). It resolves key references into the committed fixtures and checks them (for example that RFC 7517 A.2's EC `d` gives A.1's point and its RSA `p · q` gives `n`). For each positive it checks that the expected `jwk` is one of the input members. It computes no outcome, so a rerun reproduces every file byte for byte on any Node 24. Its [README](tools/jwk-oracle/README.md) has the spec format and the panva/jose 6.2.15 cross-check.
- **`tools/jwt-oracle/gen.mjs <spec.json> <out.json>`** builds `jwt.validate` and `jwt.issue` vectors from a spec: compact and flattened JWSs over raw payload octets (so malformed claims sit behind valid signatures) and nested JWEs, with `node:crypto` only. Its [README](tools/jwt-oracle/README.md) has the spec format and the fixed test keys.
- **`tools/rsa-oaep-oracle.mjs [vector-dir]`** checks every exact RSA-OAEP-256 `jwe.encrypt` vector in `vectors/jwe/rsa-oaep-256/` against its test-only private key (`keys/*.private.jwk`) with Node's built-in RSA, independently of polyjose, which has no RSA private-key code (ADR 0021).
- **`tools/jwe/t09-extract-rfc-inputs.py <rfc7516.txt> <cookbook jwe dir> <out.json>`**: *historical.* Extracts the RFC 7516 App. A.1 and A.2 and RFC 7520 §5.1 and §5.2 compact JWEs and RSA public keys used by four `negative-structure/` vectors. The script that wrote `compact/` and `negative-structure/` (0003 T09) was not preserved, so those 60 files have no generator; `reproduce.sh` checks that the four extracted inputs match their vectors.
- **`tools/jwe/t10-gcmkw.mjs <cookbook 5_7 json> <out-dir>`** writes the 24 0003 T10 files of `gcmkw/`: RFC 7520 §5.7 decrypt and exact encrypt from the cookbook, and A\*GCMKW tokens and negatives built with node:crypto from SHA-256-derived bytes.
- **`tools/jwe/t11-rsa-oaep-256.mjs <repo-root>`** writes the six `rsa-oaep-256/*-reproduced.json` exact encrypt vectors into `<repo-root>/conformance/vectors/jwe/rsa-oaep-256/`, from `rsa-oaep-oracle.mjs`'s own EME-OAEP encoding and Node's raw RSA with the test keys in `keys/`. The other nine files of that directory (0003 T11 negatives) have no preserved generator: *historical*.
- **`tools/jwe/t12-pbes2.py <cookbook 5_3 json> tools/jwe/t12-rfc7517c.json <out-dir>`** writes 24 of the 27 files of `pbes2/` from RFC 7520 §5.3 (cookbook) and RFC 7517 App. C, plus the encrypt limits of ADR 0050 §2 (`p2c` above 1,000,000, `p2s` above 256 octets). **`tools/jwe/t12-rfc7517c-extract.py <rfc7517.txt>`** prints `t12-rfc7517c.json`, the App. C values, cross-checking C.1–C.9 against each other and C.4 against Python's `hashlib.pbkdf2_hmac`.
- **`tools/jwe/f07-pbes2-budget.mjs <out-dir>`** writes the other 3 files of `pbes2/` (0003 F07, ADR 0050 §2): one general JWE with 16 kid-less PBES2-HS256+A128KW recipients of `p2c` 1000 (15 decoys, then the decrypting password), DecryptionFailed under the default 10,000 per-token budget and with 15,999, decrypting with 16,000. Built with node:crypto from SHA-256-derived bytes; it checks that only the 16th recipient unwraps under the password and that the token opens before writing.
- **`tools/jwe/t13-ecdh-es.js <cookbook jwe dir> <out-dir>`** writes the 39 files of `ecdh-es/`: RFC 7520 §5.4 and §5.5 from the cookbook, and X25519, P-256 (RFC 7518 App. C) and P-521 known answers and `epk` negatives computed with node:crypto. It reads the test keys `t13-p521-key.json` and `t13-p384-key.json` (their `d` is in the committed vectors).
- **`tools/jwe/t14-json.py <repo-root> <rfc7516.txt>`** writes the 0003 T14 files of `json/` (28) and `negative-json/` (45) under `<repo-root>/conformance/vectors/jwe/`, from the cookbook (RFC 7520 §5.6, §5.8, §5.10–§5.12) and the RFC 7516 text (App. A.3–A.5).
- **`tools/jwe/t15-zip.py <repo-root> tools/jwe/t15-zip-tokens.txt`** writes the 11 0003 T15 files of `zip/` under `<repo-root>/conformance/vectors/jwe/zip/`, from RFC 7520 §5.9 (cookbook) and the recorded tokens. **`tools/jwe/t15-zip-tokens.rs`** printed those tokens: *historical.* It was a scratch binary against polyjose (feature `deflate`) and the aes-gcm crate, not part of the workspace; its `bound64` and `empty` tokens were encrypted on the OS CSPRNG, so a rerun gives other IVs. Its forged tokens (fixed key and IV, hand-built DEFLATE streams) and the key reproduce exactly.
- **`tools/jwe/f06-cross-mode.mjs <out-dir>`** writes the 20 files of `negative-cross-mode/` (0003 F06, ADR 0050 §1): A\*GCMKW key wraps relabelled as `dir`, the reverse relabel, direct modes with an unprotected `alg` or `enc` on `dir`, P-256 and X25519, and positive controls, built with node:crypto from SHA-256-derived bytes, plus the security audit's forged token verbatim. It opens every forgery and checks every ECDH agreement from both sides before writing.
- **`tools/jwe/t18-cross-family.mjs <repo-root> [<out-root>]`** writes `rfc7520-multi/` (6, RFC 7520 §5.13), `negative-crypto/` (38), the RFC 7520 §5.7 flattened pair in `json/` (erratum 4802), the §5.9 JSON pair in `zip/` and the five per-recipient `iv`/`tag` files in `gcmkw/` (0003 T18), from the cookbook, the vendored Wycheproof ECDH webcrypto files (invalid P-384 and P-521 points by `tcId`) and tokens built with node:crypto from SHA-256-derived bytes. It cross-checks the cookbook values it uses (key unwraps, content tags) before writing.
