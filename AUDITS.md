# Audits

This is polyjose's audit register. It records which of the cryptographic primitive crates
polyjose builds on have a published, independent third-party audit, and how that audit relates to
the version polyjose uses.

## polyjose itself

**polyjose itself has not been independently audited.** No third party has reviewed its JOSE
layer: its JSON, base64url and DER/PEM code, the Concat KDF, its key handling, or the way it
composes the primitives below. polyjose plans to seek a funded independent audit before 1.0.

polyjose's maintainers run internal security reviews during development. These are internal
reviews, not audits, and polyjose does not present them as audits.

## Primitive crates

One row per primitive crate: every crate that `crates/polyjose` depends on directly, plus the
arithmetic crates beneath the curves and RSA (`curve25519-dalek`, `crypto-bigint`). The version is
the one `Cargo.lock` resolves. "None known" means that no published independent audit of the crate
was found. An audit of an earlier release line does not cover the version polyjose uses; the
notes say where that applies. Every other crate in the tree is listed in [CREDITS.md](CREDITS.md).

| Crate | Version | Third-party audit | Notes |
|---|---|---|---|
| `aes` | 0.9.4 | None known | |
| `aes-gcm` | 0.11.1 | [NCC Group, 2020](https://www.nccgroup.com/research/public-report-rustcrypto-aesgcm-and-chacha20pluspoly1305-implementation-review/) (for MobileCoin) | No significant findings. The review covered the 0.8 line; polyjose uses a later line. |
| `aes-kw` | 0.3.1 | None known | |
| `cbc` | 0.2.1 | None known | |
| `crypto-bigint` | 0.7.11 | [NCC Group, 2023](https://www.nccgroup.com/media/bq2gfxb3/_ncc_group_entropycryptography_e008526_report_2023-08-25_v10.pdf) (for Entropy) | Reviewed with `k256`. The review covered the 0.5 line (commits fde0661 and ad08a7e); polyjose uses a later line, which has diverged significantly since. |
| `curve25519-dalek` | 5.0.0 | [Quarkslab, 2019](https://blog.quarkslab.com/security-audit-of-dalek-libraries.html) (for Tari) | Minor issues only. A Scalar timing fix ([RUSTSEC-2024-0344](https://rustsec.org/advisories/RUSTSEC-2024-0344.html)) came later; polyjose uses a later line. |
| `ed25519-dalek` | 3.0.0 | None known | Quarkslab's 2019 dalek review covered this crate only marginally. [RUSTSEC-2022-0093](https://rustsec.org/advisories/RUSTSEC-2022-0093.html) (1.x line) was fixed after it. |
| `getrandom` | 0.4.3 | None known | |
| `hmac` | 0.13.0 | None known | |
| `k256` | 0.14.0 | [NCC Group, 2023](https://www.nccgroup.com/media/bq2gfxb3/_ncc_group_entropycryptography_e008526_report_2023-08-25_v10.pdf) (for Entropy) | Two high-severity findings, both fixed. The review covered the 0.13 line (commits 0f27814 and 5c829a4); polyjose uses a later line. |
| `p256` | 0.14.0 | None known | |
| `p384` | 0.14.0 | None known | |
| `p521` | 0.14.0 | None known | |
| `pbkdf2` | 0.13.0 | None known | |
| `rsa` | 0.10.0 | [Include Security, 2019](https://public.opentech.fund/documents/1907_OTF_DeltaChat_RPGP_RustRSA_GB_Report_v1.pdf) | One minor finding. The review predates [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html) (the Marvin timing attack on private-key operations), which 0.10.0 is the first release to patch; the 0.10 rewrite has no published audit. Upstream checks its constant-time code with BINSEC; polyjose adds a dudect-style timing test of its RSA signing and RSA-OAEP-256 decryption. No Marvin-toolkit run. |
| `sha2` | 0.11.1 | None known | |
| `subtle` | 2.6.1 | [Quarkslab, 2019](https://blog.quarkslab.com/security-audit-of-dalek-libraries.html) (for Tari) | Part of the dalek review, which found no trivial time leak in the source or its compiled assembly at the time. polyjose uses a later release. |
| `x25519-dalek` | 3.0.0 | None known | Quarkslab's 2019 dalek review covered this crate only marginally. |
| `zeroize` | 1.9.1 | None known | |

## How polyjose closes the gaps

- It runs the RFC test vectors, and Wycheproof where it applies, against the exact versions above,
  through its own JOSE layer.
- `cargo deny` checks the dependency tree against the RustSec advisory database.
- Crypto crates are pinned to exact versions (`=x.y.z`). An upgrade re-runs the full test suite and
  updates this file.
