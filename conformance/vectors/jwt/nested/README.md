# Nested JWT vectors (feature 0004 T13)

One vector per file (ADR 0045, id `<path>#0`). These are sign-then-encrypt JWTs: a compact JWE around a compact JWS (RFC 7519 §5.2, §11.2), validated with separate JWE and JWS allow-lists and keys (RFC 8725 §3.3), under ADR 0027 §7 and the §9 order.

The tokens come from `conformance/tools/jwt-oracle` (node:crypto, Node v24.21.0, OpenSSL 3.5.8), never from polyjose. The spec is [`specs/nested.json`](../../../tools/jwt-oracle/specs/nested.json), and its `comment` member gives the two regeneration commands:

1. generate the whole spec;
2. split it into these files by each entry's `file`.

Every JWE and every ES256 signature is randomized, so a re-run rewrites every token. Regenerate only on purpose. The RFC's own nested examples are in [`../rfc7520-nested/`](../rfc7520-nested/README.md).

| Rule | Files | Expect |
|---|---|---|
| Decrypt-then-verify (ADR 0027 §7) | `es256-dir-a256gcm`, `es256-a128kw-a128gcm`, `es256-ecdh-es-a128kw-p256` | ok, exact inner claims |
| Outer `cty` compared as a media type (RFC 7515 §4.1.10) | `outer-cty-lowercase` | ok |
| Replicated outer `iss` (RFC 7519 §5.3) | `outer-iss-replicated-equal` / `outer-iss-replicated-differs` | ok / `InvalidClaim` |
| Inner explicit typing (RFC 8725 §3.11, RFC 9068) | `inner-at-jwt-access-token` | ok |
| Inner key from a JWK Set (ADR 0029) | `inner-jwks-key-index` | ok, `key_index` 1 |
| `jwt.issue` with `encrypt` | `issue-es256-ecdh-es-a128kw` (the runner validates the token) | ok |
| | `issue-es256-rsa-oaep-256-round-trip` (decrypted with the RFC 7515 A.2 RSA private key, ADR 0067) | ok |
| Inner signature invalid | `inner-signed-by-key-outside-jwks`, `inner-signature-bit-flipped` | `InvalidSignature` |
| Inner token expired | `inner-expired` | `TokenExpired` |
| Outer JWE tampered | `outer-tag-tampered`, `outer-ciphertext-tampered` | `DecryptionFailed` |
| Outer `cty` absent (§9 N1) | `outer-cty-absent-encrypt-only`, `outer-cty-absent-around-jws` | `InvalidHeader` |
| Depth 1 | `inner-is-jwe` | `InvalidFormat` |
| Inner `alg: none` | `inner-alg-none` | `AlgorithmNotAllowed` |
| Outer `enc` / `alg` outside the allow-list | `outer-enc-not-allowed`, `outer-alg-not-allowed` | `AlgorithmNotAllowed` |
| Precedence: outer tampered **and** inner signature invalid | `precedence-outer-tampered-inner-signature-invalid` | `DecryptionFailed` |
| JSON serialization (ADR 0027 §6, ADR 0050 §3) | `flattened-cty-only-in-shared-unprotected`, `flattened-cty-protected` | `InvalidFormat` |
