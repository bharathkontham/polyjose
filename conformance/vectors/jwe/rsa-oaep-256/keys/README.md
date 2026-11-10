# Test-only RSA private keys (RSA-OAEP-256 oracle)

**These keys are public test data. Never use them for anything else.**

`rsa-2048.private.jwk`, `rsa-3072.private.jwk` and `rsa-4096.private.jwk` were generated with
Node v24.21.0's built-in `crypto.generateKeyPairSync('rsa', { modulusLength, publicExponent:
65537 })` (OpenSSL 3.5.8) and exported as JWKs (RFC 7518 §6.3).

- `conformance/tools/rsa-oaep-oracle.mjs` reads them, matched to a vector by the modulus `n`, to
  check every exact RSA-OAEP-256 encrypt vector in the parent directory with Node's own RSA-OAEP
  decryption (`crypto.privateDecrypt`, `oaepHash: 'sha256'`). Those vectors carry only the public
  half (`kty`, `n`, `e`) as the recipient key.
- Since ADR 0067, polyjose decrypts RSA-OAEP-256. The `decrypt-<bits>-<enc>.json` vectors, the
  tampered and round-trip vectors, and `binding-surface/jwe-decrypt-rsa-oaep-256.json` carry a
  copy of these JWKs, unchanged, as the decryption key. No runner reads the `.jwk` files.

The files end in `.jwk`, not `.json`, so the conformance runners (which load every `*.json` under
`vectors/`) never treat them as vectors.
