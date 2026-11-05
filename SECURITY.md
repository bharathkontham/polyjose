# Security policy

polyjose is a cryptographic library, so we treat security reports as top priority.

- **Report privately** through GitHub Security Advisories ("Report a vulnerability" on the repo's Security tab). Don't open public issues for vulnerabilities.
- We acknowledge reports within 72 hours and aim to publish a fix and an advisory within 30 days.
- **In scope:** signature or MAC bypass, algorithm confusion, key or plaintext disclosure, timing side channels in polyjose's own code, panics on untrusted input, and binding-level memory issues.
- **Known upstream issue: RSA.** The RustCrypto `rsa` crate is affected by RUSTSEC-2023-0071 (the Marvin timing side channel), and no patched release exists yet. The leak concerns operations that use an RSA **private** key, so polyjose 0.1.0 supports RSA **public-key operations only**: verifying RS256/384/512 and PS256/384/512 signatures, and encrypting to RSA-OAEP-256 recipients. RSA signing, RSA decryption, RSA key generation and RSA private keys in any format are rejected with `UnsupportedAlgorithm`, and a build-time guard keeps RSA private-key code out of the library. `RSA1_5` is not supported. They will be enabled only once a fixed `rsa` release is available.
- **No SHA-1.** polyjose does not implement `RSA-OAEP` (SHA-1); use `RSA-OAEP-256` or ECDH-ES.
