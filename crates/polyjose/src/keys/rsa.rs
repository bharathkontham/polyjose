//! RSA public keys (RFC 7518 §6.3.1) to and from SPKI with rsaEncryption and
//! NULL parameters (RFC 3279 §2.3.1, RFC 8017 App. A.1). Every RSA private
//! key encoding (RFC 8017 App. A.1.2 RSAPrivateKey, in PKCS#8 or PKCS#1) is
//! rejected as unsupported (ADR 0021). This module never uses the rsa crate.
//!
//! Filled in by task T07 of the keys feature.
