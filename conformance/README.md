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
| `jws.sign`, `jws.verify`, `jwe.encrypt`, `jwe.decrypt`, `jwt.validate` | reserved | reserved | |

A reserved operation's input and output members are defined by the feature that implements it, which adds them to `schema.json` and to every runner. Until then no runner implements it, so a vector that uses it fails.

**Bytes under test are written in lowercase hex** (`bytes_hex`: two digits per octet, `""` for none), never in base64url, so the base64url codec is never checked against itself.

## Rules for every runner

Each platform's runner (Rust: `crates/polyjose/tests/conformance.rs`) must:

- load every `*.json` file under `vectors/`, recursively, `third_party/` included;
- **fail** on a file that is not schema-valid;
- **fail** on a vector whose `operation` it does not implement, whether `schema.json` reserves it or not. Nothing is skipped;
- **fail** when it finds no vector files, so a wrong path can't pass vacuously;
- run every vector and report every failure, not only the first, each naming the file and its `source`.

The Rust runner also checks `schema.json` against its own tables (`schema_and_runner_agree`), so the schema and the runner can't drift apart.

## Writing vectors

- Name files after what they check, grouped by operation: `vectors/b64url/encode-rfc4648-10-foo.json`, `vectors/jwk-thumbprint/reject-oct-k-padded.json`.
- Check every expected value against the RFC text yourself. If the RFC doesn't print the value, derive it independently of polyjose (for example with Python's `hashlib` over the hand-built input) and say so in `description`.
- **Deterministic algorithms** (HMAC, RS256, EdDSA) also have `sign` vectors with an exact expected output. **Randomized ones** (ECDSA, PS*, JWE) are checked by round-trip plus a `verify`/`decrypt` vector of the RFC's published output.
- **Negative vectors are mandatory:** tampered signatures, `alg: none`, alg/key mismatch, wrong `crit`, expired JWTs, invalid curve points, non-canonical encodings.
- Imported upstream suites (RFC 7520 cookbook, Wycheproof) live in `vectors/third_party/`, converted to this format, with their licenses alongside them (non-JSON files are ignored).
