# Test-only RSA private keys (RSA-OAEP-256 oracle)

**These keys are public test data. Never use them for anything else.**

`rsa-2048.private.jwk`, `rsa-3072.private.jwk` and `rsa-4096.private.jwk` were generated with
Node v24.21.0's built-in `crypto.generateKeyPairSync('rsa', { modulusLength, publicExponent:
65537 })` (OpenSSL 3.5.8) and exported as JWKs (RFC 7518 §6.3). They are outside Rust on purpose:

- polyjose performs no RSA private-key operation and has no RSA private-key code (ADR 0021), so no
  Rust code reads these files. An RSA private JWK given to polyjose fails at import with
  `UnsupportedAlgorithm`.
- `conformance/tools/rsa-oaep-oracle.mjs` reads them, matched to a vector by the modulus `n`, to
  check every RSA-OAEP-256 vector in the parent directory with Node's own RSA-OAEP decryption
  (`crypto.privateDecrypt`, `oaepHash: 'sha256'`).
- The vectors themselves carry only the public half (`kty`, `n`, `e`) as the recipient key.

The files end in `.jwk`, not `.json`, so the conformance runners (which load every `*.json` under
`vectors/`) never treat them as vectors.
