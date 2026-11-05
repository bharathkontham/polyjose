# Conformance vectors

These are shared test vectors. **Every platform's test suite runs all of them**: Rust, WASM, Node, Kotlin/Android and Swift. That's how polyjose guarantees identical behaviour everywhere.

Each file in `vectors/` is JSON:

```json
{
  "source": "RFC 7520 §4.1",
  "description": "RSA v1.5 signature (RS256), compact",
  "operation": "jws.verify",              // jws.sign | jws.verify | jwe.encrypt | jwe.decrypt | jwk.thumbprint | jwt.validate | b64url.*
  "input": { "token": "...", "key": { /* JWK */ }, "allowed_algs": ["RS256"] },
  "expect": { "ok": true, "payload_b64u": "..." }   // or { "ok": false, "error": "InvalidSignature" }
}
```

Rules:
- **Deterministic algorithms** (HMAC, RS256, EdDSA) also have `sign` vectors with an exact expected output. **Randomized ones** (ECDSA, PS*, JWE) are checked by round-trip plus a `verify`/`decrypt` vector of the RFC's published output.
- **Negative vectors are mandatory:** tampered signatures, `alg: none`, alg/key mismatch, wrong `crit`, expired JWTs, invalid curve points.
- Error names are the stable cross-platform error codes in `crates/polyjose/src/error.rs`.
- Imported upstream suites (RFC 7520 cookbook, Wycheproof) keep their licenses alongside them in `vectors/third_party/`.
