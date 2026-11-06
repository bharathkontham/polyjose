# Security policy

polyjose is a cryptographic library, so we treat security reports as top priority.

- **Report privately** through GitHub Security Advisories ("Report a vulnerability" on the repo's Security tab). Don't open public issues for vulnerabilities.
- We acknowledge reports within 72 hours and aim to publish a fix and an advisory within 30 days.
- **In scope:** signature or MAC bypass, algorithm confusion, key or plaintext disclosure, timing side channels in polyjose's own code, panics on untrusted input, and binding-level memory issues.
- **Known upstream issue (RSA):** RSA comes from the RustCrypto `rsa` crate, the only pure-Rust implementation. [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071) (the Marvin timing side channel) affects every `rsa` release so far, including the 0.10 release candidates, and has no patched version. The leak is in operations that use the private key. So, until RustSec marks the advisory resolved for a stable `rsa` release, polyjose limits RSA to public-key operations, which handle no secret:
  - verifying `RS256`, `RS384`, `RS512`, `PS256`, `PS384` and `PS512` signatures;
  - encrypting to `RSA-OAEP-256` recipients;
  - importing RSA public keys.

  polyjose does not sign or decrypt with RSA or generate RSA keys, and importing an RSA private JWK fails with `UnsupportedAlgorithm`. `RSA1_5` is not implemented in either direction (RFC 8725 discourages it), and no feature flag turns it on. `RSA-OAEP` is not implemented either, because it uses SHA-1, and polyjose contains no SHA-1; use `RSA-OAEP-256` or ECDH-ES instead. `cargo deny` checks the advisory on every change: it may be ignored only for this public-key-only use, together with a check that rejects any RSA private-key call in polyjose's code.
