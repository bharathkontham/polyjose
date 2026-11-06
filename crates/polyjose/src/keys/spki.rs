//! SubjectPublicKeyInfo (RFC 5280 §4.1.2.7) with its AlgorithmIdentifier
//! (RFC 5280 §4.1.1.2), read into and written from `SpkiParts`. The
//! AlgorithmIdentifier is classified against the byte templates in `oid.rs`,
//! in the order of ADR 0018 §4.
//!
//! Filled in by task T02 of the keys feature.
