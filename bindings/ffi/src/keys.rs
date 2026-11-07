//! The key exports (ADR 0030 §4, "JWK"): `jwk_generate_oct`, `jwk_generate_ec`,
//! `jwk_generate_okp`, `jwk_generate_for_alg`, `jwk_from_pem`, `jwk_from_der`, `jwk_to_pem` and
//! `jwk_to_der` (RFC 7518 §6, RFC 8037, RFC 7468, RFC 5958, RFC 5915, RFC 5280; ADR 0018).
//!
//! Each export is a type conversion and one call into `polyjose_surface::keys` (ADR 0030 §1,
//! "the adapter test"). Key generation draws from the OS CSPRNG inside the core (ADR 0005); RSA
//! generation and RSA private import fail with `UnsupportedAlgorithm` (ADR 0021).
//!
//! **Secrets (ADR 0030 §7).**
//! - **Inputs.** A JWK or PEM `String` argument is moved into a [`Zeroizing`] owner in the first
//!   statement, and is UniFFI's only Rust-heap copy of it (0009 research §8). A DER `Vec<u8>`
//!   argument is moved into a [`Zeroizing`] owner the same way; UniFFI 0.32.2 lifted it by
//!   copying it out of a `RustBuffer` that it then freed unwiped: 1 copy per `Vec<u8>` argument
//!   (ADR 0030 §7.1, §7.3; restated in ADR 0058).
//! - **Outputs.** Generated keys, imported keys, and the PEM or DER of a private key come from
//!   the surface as `SecretString`/`SecretBytes`. The adapter copies each once into the value
//!   UniFFI lowers, and the surface's buffer is wiped when it drops at the end of the statement
//!   (ADR 0030 §7.2). The unwiped Rust-heap copies UniFFI 0.32.2 then leaves are measured in
//!   ADR 0058 (which supersedes ADR 0030 §7.3 for outputs); the adapter cannot reach them
//!   without `unsafe`:
//!   - a `String` result (every export here but `jwk_to_der`) becomes the host's `RustBuffer` as
//!     is, and leaves exactly **1** copy, that buffer, freed unwiped by the host;
//!   - the `Vec<u8>` result of `jwk_to_der` leaves **at least 2** full copies: the adapter's
//!     vector, which UniFFI writes into a growing buffer and then drops, and the final buffer the
//!     host frees. Each move of the growing buffer adds a full or partial copy, depending on the
//!     size and the platform allocator (2 to 3 full copies of `d` measured on macOS, ADR 0058).
//!
//!   Callers should wipe the `ByteArray`/`Data` they receive (ADR 0030 §7.4); the opaque key
//!   handles planned for 0.2.0 remove these copies for keys (ADR 0058, ADR 0030 option C2).

use zeroize::Zeroizing;

use crate::PolyjoseError;

/// A new random `oct` key of `len_bytes` octets, 16 to 512 (ADR 0030 §4; RFC 7518 §6.4).
///
/// # Errors
///
/// `InvalidKey` for a length outside 16..=512 (ADR 0030 §5); `RandomnessUnavailable` if the
/// OS CSPRNG fails (ADR 0005).
#[uniffi::export]
pub fn jwk_generate_oct(len_bytes: u32) -> Result<String, PolyjoseError> {
    Ok(polyjose_surface::keys::jwk_generate_oct(len_bytes)?
        .as_str()
        .to_owned())
}

/// A new random EC private key on `crv`: `P-256`, `P-384`, `P-521` or `secp256k1` (ADR 0030
/// §4; RFC 7518 §6.2, RFC 8812 §3.1).
///
/// # Errors
///
/// `UnsupportedAlgorithm` for any other curve name (ADR 0030 §5); `RandomnessUnavailable`.
#[uniffi::export]
pub fn jwk_generate_ec(crv: String) -> Result<String, PolyjoseError> {
    Ok(polyjose_surface::keys::jwk_generate_ec(&crv)?
        .as_str()
        .to_owned())
}

/// A new random OKP private key on `crv`: `Ed25519` or `X25519` (ADR 0030 §4; RFC 8037 §2).
///
/// # Errors
///
/// `UnsupportedAlgorithm` for any other curve name, Ed448 and X448 included (ADR 0006);
/// `RandomnessUnavailable`.
#[uniffi::export]
pub fn jwk_generate_okp(crv: String) -> Result<String, PolyjoseError> {
    Ok(polyjose_surface::keys::jwk_generate_okp(&crv)?
        .as_str()
        .to_owned())
}

/// A new random key for the JWS `alg` or JWE `alg`/`enc` name `alg`, with `alg` set (ADR 0030
/// §4; RFC 7517 §4.4, RFC 7518 §3–§5; the 0005 `generate_for` table).
///
/// # Errors
///
/// `UnsupportedAlgorithm` for RSA (ADR 0021), `PBES2-*`, `dir`, `none` (RFC 8725 §3.1) and
/// unknown names;
/// `InvalidKey` where the core needs a curve the name does not fix (ECDH-ES);
/// `RandomnessUnavailable`.
#[uniffi::export]
pub fn jwk_generate_for_alg(alg: String) -> Result<String, PolyjoseError> {
    Ok(polyjose_surface::keys::jwk_generate_for_alg(&alg)?
        .as_str()
        .to_owned())
}

/// The JWK of the PEM-encoded key `pem` (ADR 0030 §4; RFC 7468 §10, §13; ADR 0018): PKCS#8
/// (RFC 5958 §2), SEC1 (RFC 5915 §3), SPKI (RFC 5280 §4.1.2.7) or PKCS#1 public (RFC 8017
/// Appendix A.1.1).
///
/// # Errors
///
/// `InvalidKey` for malformed PEM or DER; `UnsupportedAlgorithm` for encrypted PKCS#8, a
/// certificate, an RSA private key (ADR 0021) or an unsupported key type.
#[uniffi::export]
pub fn jwk_from_pem(pem: String) -> Result<String, PolyjoseError> {
    let pem = Zeroizing::new(pem);
    Ok(polyjose_surface::keys::jwk_from_pem(&pem)?
        .as_str()
        .to_owned())
}

/// The JWK of the DER-encoded key `der` in `format`: `pkcs8`, `sec1`, `spki` or `pkcs1`
/// (ADR 0030 §4; RFC 5958 §2, RFC 5915 §3, RFC 5280 §4.1.2.7, RFC 8017 Appendix A.1.1; ADR 0018
/// §3, no format sniffing).
///
/// # Errors
///
/// `UnsupportedAlgorithm` for an unknown format name (ADR 0030 §5), RSA private keys
/// (ADR 0021) and unsupported key types; `InvalidKey` for DER that is not the named structure.
#[uniffi::export]
pub fn jwk_from_der(der: Vec<u8>, format: String) -> Result<String, PolyjoseError> {
    let der = Zeroizing::new(der);
    Ok(polyjose_surface::keys::jwk_from_der(&der, &format)?
        .as_str()
        .to_owned())
}

/// `jwk` as PEM in `format`, laid out as OpenSSL writes it (ADR 0030 §4; RFC 7468 §10, §13;
/// ADR 0018 §3). `spki` of a private key exports its public half (RFC 5280 §4.1.2.7).
///
/// # Errors
///
/// `UnsupportedAlgorithm` for an unknown format name (ADR 0030 §5), an RSA private JWK
/// (ADR 0021) or a format the key type has none of (ADR 0018 §3 format matrix; an `oct` key in
/// any format, RFC 8725 §2.1); `InvalidKey` for a public key in `pkcs8` or `sec1`; the core's
/// JWK parse errors.
#[uniffi::export]
pub fn jwk_to_pem(jwk: String, format: String) -> Result<String, PolyjoseError> {
    let jwk = Zeroizing::new(jwk);
    Ok(polyjose_surface::keys::jwk_to_pem(&jwk, &format)?
        .as_str()
        .to_owned())
}

/// `jwk` as DER in `format` (ADR 0030 §4; RFC 5958 §2, RFC 5915 §3, RFC 5280 §4.1.2.7; ADR 0018
/// §3).
///
/// # Errors
///
/// Those of [`jwk_to_pem`].
#[uniffi::export]
pub fn jwk_to_der(jwk: String, format: String) -> Result<Vec<u8>, PolyjoseError> {
    let jwk = Zeroizing::new(jwk);
    Ok(polyjose_surface::keys::jwk_to_der(&jwk, &format)?
        .as_bytes()
        .to_vec())
}
