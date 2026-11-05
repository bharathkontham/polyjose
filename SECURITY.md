# Security policy

polyjose is a cryptographic library, so we treat security reports as top priority.

- **Report privately** through GitHub Security Advisories ("Report a vulnerability" on the repo's Security tab). Don't open public issues for vulnerabilities.
- We acknowledge reports within 72 hours and aim to publish a fix and an advisory within 30 days.
- **In scope:** signature or MAC bypass, algorithm confusion, key or plaintext disclosure, timing side channels in polyjose's own code, panics on untrusted input, and binding-level memory issues.
- **Known upstream issue:** RSA private-key operations depend on the RustCrypto `rsa` crate. `rsa` 0.9 is affected by RUSTSEC-2023-0071 (Marvin timing side channel). polyjose builds on the constant-time `rsa` 0.10 line, never ships on 0.9 (enforced by `cargo deny`), keeps RSA1_5 behind an off-by-default feature, and won't release 1.0 until `rsa` 0.10 is stable.
