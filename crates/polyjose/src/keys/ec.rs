//! EC keys on P-256, P-384, P-521 and secp256k1 (RFC 7518 §6.2, RFC 8812
//! §3.1) to and from SPKI (RFC 5480 §2.1.1 namedCurve, §2.2 uncompressed or
//! compressed points) and PKCS#8, whose privateKey holds an RFC 5915
//! ECPrivateKey (RFC 5915 §1; without `[0]`, per erratum 5008).
//!
//! Filled in by task T06 of the keys feature.
