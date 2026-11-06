//! JSON Web Encryption (RFC 7516).
//!
//! # Serializations
//!
//! - **Compact** (RFC 7516 §3.1, §7.1): [`Encryptor::encrypt_compact`] and
//!   [`decrypt_compact`]. One recipient, a protected header only.
//! - **JSON** (RFC 7516 §7.2): [`Encryptor::encrypt_json`] with
//!   [`JsonForm::General`] (any number of recipients) or
//!   [`JsonForm::Flattened`] (one), and [`decrypt_json`] (either form).
//!   Shared and per-recipient unprotected headers and the JWE AAD.
//!
//! # Algorithms (ADR 0006, ADR 0021, ADR 0022)
//!
//! | `alg` | encrypt | decrypt |
//! |---|---|---|
//! | `dir`, `A128KW`/`A192KW`/`A256KW`, `A128GCMKW`/`A192GCMKW`/`A256GCMKW` | yes | yes |
//! | `ECDH-ES`, `ECDH-ES+A128KW`/`+A192KW`/`+A256KW` on P-256/384/521 and X25519 | yes | yes |
//! | `PBES2-HS256+A128KW`, `PBES2-HS384+A192KW`, `PBES2-HS512+A256KW` | yes | yes |
//! | `RSA-OAEP-256` | yes, to a public key | [`Error::UnsupportedAlgorithm`] |
//! | `RSA-OAEP` (SHA-1), `RSA1_5` | [`Error::UnsupportedAlgorithm`] | [`Error::UnsupportedAlgorithm`] |
//!
//! Every `enc`: A128CBC-HS256, A192CBC-HS384, A256CBC-HS512 (RFC 7518
//! §5.2), A128GCM, A192GCM, A256GCM (§5.3). `zip: DEF` (RFC 7516 §4.1.3)
//! only with the off-by-default `deflate` feature (ADR 0017).
//!
//! # Misuse resistance (RFC 8725, ADR 0007)
//!
//! - **Allow-lists.** Every decrypt takes a [`DecryptPolicy`], built from
//!   non-empty lists of the `alg` and `enc` values the caller accepts. The
//!   header alone is never trusted (RFC 8725 §3.1).
//! - **Key binding.** The key must be of the family the `alg` needs, and
//!   its JWK `alg`, `use` and `key_ops` must allow the operation
//!   (RFC 7517 §4.2–§4.4).
//! - **One decryption error.** Every failure after key management starts
//!   is [`Error::DecryptionFailed`], with no detail (RFC 7516 §11.4–§11.5).
//! - **Bounded work.** [`DecryptPolicy`] bounds the input size, the
//!   recipient count, the PBES2 iteration count (ADR 0023) and the
//!   decompressed size (ADR 0017).
//!
//! # Errors (plan.md error contract; ADR 0026's order, applied to JWE)
//!
//! | step (RFC 7516 §5.2) | failure | error |
//! |---|---|---|
//! | limits | input over `max_input_len`; more than `max_recipients` | [`Error::InvalidFormat`] |
//! | 1 | not 5 compact parts; a JSON shape RFC 7516 §7.2 forbids | [`Error::InvalidFormat`] |
//! | 1, 3 | JSON syntax, I-JSON, depth, size; duplicate members (ADR 0041 §1); a protected header that is valid JSON but not an object, as for JWS (ADR 0026 §2 step 4) | [`Error::InvalidJson`] |
//! | 2 | a part or member that is not strict base64url | [`Error::InvalidBase64`] |
//! | 3–4 | header parts not disjoint, `alg`/`enc` missing, `zip` outside the protected header, a registered parameter of the wrong type | [`Error::InvalidHeader`] |
//! | 5 | `crit` names something not understood | [`Error::UnknownCritical`] |
//! | support | `alg`, `enc` or `zip` not implemented (checked over every recipient first) | [`Error::UnsupportedAlgorithm`] |
//! | allow-list | `alg` or `enc` not in the policy | [`Error::AlgorithmNotAllowed`] |
//! | key | the key cannot serve the `alg` | [`Error::KeyAlgorithmMismatch`] |
//! | 6–17 | anything once key management starts | [`Error::DecryptionFailed`] |
//!
//! Encryption fails with [`Error::InvalidKey`] for a key of the wrong size
//! and [`Error::InvalidFormat`] for a request the serialization cannot
//! carry (RFC 7516 §7.1) or a `dir`/ECDH-ES message with more than one
//! recipient.
//!
//! [`Encryptor::encrypt_compact`]: crate::jwe::Encryptor::encrypt_compact
//! [`Encryptor::encrypt_json`]: crate::jwe::Encryptor::encrypt_json
//! [`decrypt_compact`]: crate::jwe::decrypt_compact
//! [`decrypt_json`]: crate::jwe::decrypt_json
//! [`DecryptPolicy`]: crate::jwe::DecryptPolicy
//! [`JsonForm::General`]: crate::jwe::JsonForm::General
//! [`JsonForm::Flattened`]: crate::jwe::JsonForm::Flattened
//! [`Error::UnsupportedAlgorithm`]: crate::Error::UnsupportedAlgorithm
//! [`Error::InvalidFormat`]: crate::Error::InvalidFormat
//! [`Error::InvalidJson`]: crate::Error::InvalidJson
//! [`Error::InvalidBase64`]: crate::Error::InvalidBase64
//! [`Error::InvalidHeader`]: crate::Error::InvalidHeader
//! [`Error::UnknownCritical`]: crate::Error::UnknownCritical
//! [`Error::AlgorithmNotAllowed`]: crate::Error::AlgorithmNotAllowed
//! [`Error::KeyAlgorithmMismatch`]: crate::Error::KeyAlgorithmMismatch
//! [`Error::DecryptionFailed`]: crate::Error::DecryptionFailed
//! [`Error::InvalidKey`]: crate::Error::InvalidKey

mod api;

pub use api::{
    DecryptPolicy, Decrypted, Encryptor, JsonForm, Recipient, Serialization, decrypt_compact,
    decrypt_json,
};

// The internal modules of the JWE pipeline (RFC 7516 §5).
mod aes_gcm_kw;
mod aes_kw;
mod compact;
mod concat_kdf;
mod content;
mod core;
mod dir;
mod ecdh_es;
mod ecdh_nist;
mod ecdh_x25519;
mod enc_cbc_hmac;
mod enc_gcm;
mod json;
mod key;
mod keymgmt;
mod pbes2;
mod random;
mod rsa_oaep;
mod zip;
