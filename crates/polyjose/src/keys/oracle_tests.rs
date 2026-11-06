//! Differential tests of the owned DER and PEM codecs against the RustCrypto
//! formats crates (`der`, `spki`, `pkcs8`, `sec1`, `pkcs1`, `pem-rfc7468`),
//! which are dev-dependencies only (ADR 0016 §5, ADR 0018 §1), and
//! canonicality properties: whatever is accepted re-encodes byte for byte
//! (X.690 §10, RFC 7468 §3).
//!
//! Filled in by task T09 of the keys feature.
