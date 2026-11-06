//! Key generation and PEM/DER key import and export.
//!
//! - **Generation** of `oct`, EC (P-256, P-384, P-521, secp256k1) and OKP
//!   (Ed25519, X25519) keys from the OS CSPRNG (ADR 0005). There is no RSA
//!   key generation (ADR 0021).
//! - **Import and export** of PKCS#8 (RFC 5958 §2), SubjectPublicKeyInfo
//!   (RFC 5280 §4.1.2.7) and SEC1 ECPrivateKey (RFC 5915 §3) for EC keys,
//!   PKCS#8 and SPKI for OKP keys (RFC 8410), and SPKI and PKCS#1
//!   RSAPublicKey (RFC 8017 App. A.1.1) for RSA **public** keys, as DER or
//!   as RFC 7468 PEM.
//!
//! The DER and PEM codecs are polyjose's own and strict (ADR 0018, ADR 0020):
//! BER, explanatory text around a PEM block, encrypted PKCS#8 and RSA private
//! keys are rejected. Every key is returned only after the typed-JWK
//! validation of [`Jwk::from_object`](crate::jwk::Jwk::from_object): points
//! on their curve, scalars in range, RSA moduli of at least 2048 bits.
//!
//! The key type always comes from a structural parse of the DER, never from
//! the PEM label alone, and `oct` keys never cross PEM/DER in either
//! direction (RFC 8725 §2.1, ADR 0018 §3).
//!
//! The module exports [`generate`](crate::keys::generate()),
//! [`generate_for`](crate::keys::generate_for),
//! [`JoseAlg`](crate::keys::JoseAlg), [`KeyFormat`](crate::keys::KeyFormat)
//! and [`KeySpec`](crate::keys::KeySpec); import and export are methods on
//! [`Jwk`](crate::jwk::Jwk). A glob import brings in all five:
//!
//! ```
//! use polyjose::jwa::SigningAlg;
//! use polyjose::jwk::Jwk;
//! use polyjose::keys::*;
//!
//! let _: fn(KeySpec) -> polyjose::Result<Jwk> = generate;
//! let key = generate_for(JoseAlg::from(SigningAlg::ES256))?;
//! let der = key.to_der(KeyFormat::Pkcs8)?;
//! // DER has no `alg`: the imported key is the same key, unbound.
//! let imported = Jwk::from_der(&der, KeyFormat::Pkcs8)?;
//! assert!(imported.alg().is_none());
//! # Ok::<(), polyjose::Error>(())
//! ```

mod api;
mod der;
mod ec;
pub(crate) mod generate;
mod jwk_build;
mod oid;
mod okp;
#[cfg(test)]
mod oracle_tests;
mod pem;
mod pkcs1;
mod pkcs8;
mod rsa;
mod sec1;
mod spki;
mod types;

pub use self::types::{JoseAlg, KeyFormat, KeySpec};

/// The public generation API (`generate`, `generate_for`) is defined in
/// `generate.rs` and re-exported here, so that module alone owns it.
pub use self::generate::{generate, generate_for};
