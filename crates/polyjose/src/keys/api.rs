//! The public PEM/DER entry points on `Jwk` (ADR 0018 §3): `from_pem`, where
//! the label selects the structure (RFC 7468 §2), `from_der` with an explicit
//! `KeyFormat`, and `to_pem`/`to_der`. `oct` keys never cross PEM/DER, so
//! text can never become an HMAC secret (RFC 8725 §2.1).
//!
//! Filled in by task T08 of the keys feature.
