//! PKCS#8 private keys: OneAsymmetricKey / PrivateKeyInfo (RFC 5958 §2,
//! RFC 5208 §5), versions v1(0) and v2(1) with the `[0]` attributes and the
//! `[1]` publicKey, read into and written from `Pkcs8Parts`.
//! EncryptedPrivateKeyInfo (RFC 5958 §3) is rejected as unsupported
//! (ADR 0018 §4).
//!
//! Filled in by task T02 of the keys feature.
