//! Key generation from the OS CSPRNG (ADR 0005, ADR 0018 §5):
//!
//! - `oct`: the RFC 7518 key sizes per `alg`/`enc` (§3.2, §4.4, §4.7,
//!   §5.2.3–§5.2.5, §5.3);
//! - EC P-256/P-384/P-521/secp256k1: a private scalar d in [1, n − 1]
//!   (SEC 1 v2 §3.2.1) by rejection sampling;
//! - Ed25519: 32 random octets (RFC 8032 §5.1.5);
//! - X25519: 32 random octets (RFC 7748 §5, §6.1).
//!
//! No RSA key generation (ADR 0021).
//!
//! Filled in by task T04 of the keys feature.
