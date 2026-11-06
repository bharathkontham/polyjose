//! ECDH-ES, ECDH-ES+A128KW, ECDH-ES+A192KW and ECDH-ES+A256KW (RFC 7518
//! §4.6) on P-256/384/521 (`ecdh_nist`) and X25519 (`ecdh_x25519`, RFC 8037
//! §3.2), with the Concat KDF (`concat_kdf`, §4.6.2). The `epk` is
//! validated before any agreement (RFC 8725 §3.4).
//!
//! # Key derivation (RFC 7518 §4.6.2)
//!
//! | `alg` | Mode (RFC 7516 §2) | AlgorithmID | keydatalen |
//! |---|---|---|---|
//! | `ECDH-ES` | Direct Key Agreement | the `enc` value | the `enc` key length |
//! | `ECDH-ES+A128KW` | Key Agreement with Key Wrapping | the `alg` value | 128 |
//! | `ECDH-ES+A192KW` | Key Agreement with Key Wrapping | the `alg` value | 192 |
//! | `ECDH-ES+A256KW` | Key Agreement with Key Wrapping | the `alg` value | 256 |
//!
//! PartyUInfo and PartyVInfo are the base64url-decoded `apu` and `apv`
//! (RFC 7518 §4.6.1.2–§4.6.1.3), empty when absent. Z is the full-length
//! x-coordinate for the NIST curves and the 32-octet X25519 output.
//!
//! # `epk` validation on decrypt (RFC 8725 §3.4, ADR 0041 §4)
//!
//! In this order, every failure is [`Error::DecryptionFailed`] and none
//! runs a scalar multiplication:
//!
//! 1. direct ECDH-ES needs an empty JWE Encrypted Key (RFC 7516 §5.2
//!    step 10);
//! 2. `apu` and `apv`, when present, must be strict base64url (RFC 7518
//!    §4.6.1.2–§4.6.1.3);
//! 3. `epk` must be present (RFC 7518 §4.6.1.1: "MUST be present");
//! 4. it must hold no private key member (RFC 7518 §4.6.1.1: "MUST contain
//!    only public key parameters");
//! 5. it must import as a JWK ([`Jwk::from_object`]: exact coordinate
//!    lengths, EC points on their curve and not the identity; ADR 0041 §4,
//!    SP 800-56A r3 §5.6.2.3.4 partial public-key validation);
//! 6. its `kty` and `crv` must be those of the recipient's key (RFC 7518
//!    §4.6: the agreement is on the recipient's curve; this stops the
//!    invalid-curve attacks of research.md §4.2).
//!
//! Only then does the agreement run. For X25519 the one remaining check is
//! the all-zero shared secret (RFC 7748 §6.1, `ecdh_x25519::agree`); X25519
//! public keys with a torsion component stay allowed (ADR 0043 §2).

use p256::elliptic_curve::sec1::{FromSec1Point, ModulusSize, ToSec1Point};
use p256::elliptic_curve::{AffinePoint, CurveArithmetic, FieldBytesSize, PublicKey, SecretKey};
use zeroize::Zeroizing;

use super::api::DecryptPolicy;
use super::content::{Cek, cek_len};
use super::key::RecipientKey;
use super::keymgmt::{KeyOutput, RecipientOptions};
use super::random::RandomSource;
use super::{aes_kw, concat_kdf, ecdh_nist, ecdh_x25519};
use crate::header::Header;
use crate::json::{Object, Value};
use crate::jwa::{ContentEncAlg, KeyMgmtAlg};
use crate::jwk::{EcCurve, EcKey, Jwk, KeyMaterial, OkpCurve};
use crate::util::{b64url_decode, b64url_encode};
use crate::{Error, Result};

/// Detail for `apu` equal to `apv` on encrypt.
const APU_EQUALS_APV: &str = "apu and apv must be distinct (RFC 7518 §4.6.2)";

/// Detail for a caller of `encrypt_key` that breaks the `KeyOutput`
/// contract (a random CEK for direct ECDH-ES, or none for +A*KW).
const CEK_CONTRACT: &str = "ECDH-ES takes a random CEK exactly for the +A*KW variants";

/// The JWK members that hold private key material: `d` of `EC` (RFC 7518
/// §6.2.2.1) and `OKP` (RFC 8037 §2), the other RSA private members
/// (RFC 7518 §6.3.2) and the `oct` key value `k` (RFC 7518 §6.4.1). An
/// `epk` "MUST contain only public key parameters" (RFC 7518 §4.6.1.1).
const PRIVATE_MEMBERS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/// The Concat KDF inputs that `alg` fixes (RFC 7518 §4.6.2, see the
/// module table).
struct Derivation<'a> {
    /// AlgorithmID: the `enc` value (direct) or the `alg` value (+A*KW).
    alg_id: &'a str,
    /// keydatalen, in bits.
    keydatalen_bits: u32,
    /// Whether the derived key wraps a random CEK (RFC 7518 §4.6:
    /// "Key Agreement with Key Wrapping") rather than being the CEK.
    wraps: bool,
}

/// The [`Derivation`] for `alg` and `enc` (RFC 7518 §4.6.2).
///
/// # Errors
///
/// [`Error::UnsupportedAlgorithm`] for an `alg` that is not ECDH-ES, or an
/// unknown `enc` with direct ECDH-ES.
fn derivation<'a>(alg: &'a KeyMgmtAlg, enc: &'a ContentEncAlg) -> Result<Derivation<'a>> {
    let wrap = |bits| {
        Ok(Derivation {
            alg_id: alg.as_str(),
            keydatalen_bits: bits,
            wraps: true,
        })
    };
    match alg {
        // "For "ECDH-ES", this is length of the key used by the "enc"
        // algorithm."
        KeyMgmtAlg::EcdhEs => {
            let bits = cek_len(enc)?
                .checked_mul(8)
                .and_then(|bits| u32::try_from(bits).ok())
                .ok_or(Error::UnsupportedAlgorithm)?;
            Ok(Derivation {
                alg_id: enc.as_str(),
                keydatalen_bits: bits,
                wraps: false,
            })
        }
        // "For "ECDH-ES+A128KW", "ECDH-ES+A192KW", and "ECDH-ES+A256KW",
        // this is 128, 192, and 256, respectively."
        KeyMgmtAlg::EcdhEsA128KW => wrap(128),
        KeyMgmtAlg::EcdhEsA192KW => wrap(192),
        KeyMgmtAlg::EcdhEsA256KW => wrap(256),
        _ => Err(Error::UnsupportedAlgorithm),
    }
}

/// Key management on encrypt (RFC 7516 §5.1 steps 3–7) for ECDH-ES and
/// ECDH-ES+A*KW:
///
/// 1. `apu` and `apv` "MUST be distinct, when used" (RFC 7518 §4.6.2),
///    checked before anything is drawn;
/// 2. a fresh ephemeral key pair on the recipient's curve (RFC 7518
///    §4.6.1: one per key agreement), drawn from `rng`: the NIST scalar
///    through the crate's EC sampler (`ecdh_nist::generate`), 32 bytes for
///    X25519 (`ecdh_x25519::generate`);
/// 3. Z with the recipient's public key, then the Concat KDF (§4.6.2);
/// 4. direct ECDH-ES: the derived key is the CEK and the JWE Encrypted Key
///    is empty (RFC 7516 §5.1 steps 5–6); +A*KW: the derived key wraps the
///    random `cek` with AES Key Wrap (RFC 7518 §4.6, §4.4).
///
/// The header parameters are `epk` (only the public members `kty`, `crv`,
/// `x` and, for EC, `y`: RFC 7518 §4.6.1.1, §6.2.1; RFC 8037 §2) and `apu`
/// and `apv` as given, base64url-encoded (§4.6.1.2–§4.6.1.3).
///
/// # Errors
///
/// - [`Error::InvalidFormat`] for `apu` equal to `apv` (RFC 7518 §4.6.2);
/// - [`Error::RandomnessUnavailable`] if `rng` fails;
/// - [`Error::InvalidKey`] for an X25519 recipient key that gives an
///   all-zero shared secret (RFC 7748 §6.1), or a `cek` that does not
///   match the mode;
/// - [`Error::KeyAlgorithmMismatch`] for a key that is not an ECDH-ES
///   public key, and [`Error::UnsupportedAlgorithm`] for an `alg` that is
///   not ECDH-ES (`RecipientKey::from_jwk` and the dispatcher rule both
///   out first).
pub(super) fn encrypt_key(
    alg: &KeyMgmtAlg,
    key: &RecipientKey,
    enc: &ContentEncAlg,
    cek: Option<&Cek>,
    options: &RecipientOptions,
    rng: &mut dyn RandomSource,
) -> Result<KeyOutput> {
    let derivation = derivation(alg, enc)?;
    if let (Some(apu), Some(apv)) = (&options.apu, &options.apv)
        && apu == apv
    {
        return Err(Error::InvalidFormat(APU_EQUALS_APV));
    }
    if derivation.wraps != cek.is_some() {
        return Err(Error::InvalidKey(CEK_CONTRACT));
    }
    let (epk, z) = match key {
        RecipientKey::P256Public(public) => nist_encrypt(EcCurve::P256, public, rng)?,
        RecipientKey::P384Public(public) => nist_encrypt(EcCurve::P384, public, rng)?,
        RecipientKey::P521Public(public) => nist_encrypt(EcCurve::P521, public, rng)?,
        RecipientKey::X25519Public(public) => {
            let (secret, ephemeral) = ecdh_x25519::generate(rng)?;
            let z = ecdh_x25519::agree(&secret, public)?;
            let mut epk = Object::new();
            epk.insert("kty", "OKP");
            epk.insert("crv", OkpCurve::X25519.as_str());
            epk.insert("x", b64url_encode(ephemeral.as_bytes()));
            (epk, Zeroizing::new(z.to_vec()))
        }
        _ => return Err(Error::KeyAlgorithmMismatch),
    };
    let apu = options.apu.as_deref().unwrap_or_default();
    let apv = options.apv.as_deref().unwrap_or_default();
    let derived = concat_kdf::derive(&z, derivation.alg_id, apu, apv, derivation.keydatalen_bits)?;

    let mut header_params = Object::new();
    header_params.insert("epk", Value::from(epk));
    if let Some(apu) = &options.apu {
        header_params.insert("apu", b64url_encode(apu));
    }
    if let Some(apv) = &options.apv {
        header_params.insert("apv", b64url_encode(apv));
    }
    match cek {
        // RFC 7518 §4.6: "the agreed-upon key is used to wrap the CEK".
        Some(cek) => Ok(KeyOutput {
            encrypted_key: aes_kw::wrap(&derived, cek.as_bytes())?,
            header_params,
            cek: None,
        }),
        // RFC 7518 §4.6: "the output of the Concat KDF MUST be a key of
        // the same length as that used by the "enc" algorithm", used as
        // the CEK; RFC 7516 §5.1 step 6: the Encrypted Key is empty.
        None => Ok(KeyOutput {
            encrypted_key: Vec::new(),
            header_params,
            cek: Some(Cek::new(derived)),
        }),
    }
}

/// A fresh ephemeral key on the NIST curve `crv` (RFC 7518 §4.6.1), its
/// `epk` (RFC 7518 §6.2.1: `kty`, `crv`, and `x`, `y` at the full
/// coordinate length) and Z with `recipient`.
fn nist_encrypt<C>(
    crv: EcCurve,
    recipient: &PublicKey<C>,
    rng: &mut dyn RandomSource,
) -> Result<(Object, Zeroizing<Vec<u8>>)>
where
    C: CurveArithmetic,
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
    FieldBytesSize<C>: ModulusSize,
{
    let (secret, public) = ecdh_nist::generate::<C>(rng)?;
    let z = ecdh_nist::agree(&secret, recipient)?;
    let point = public.to_sec1_point(false);
    // d ≠ 0 and G has order n, so Q = d·G is never the identity, the only
    // point without coordinates.
    let (Some(x), Some(y)) = (point.x(), point.y()) else {
        return Err(Error::InvalidKey("EC public key is the identity"));
    };
    let mut epk = Object::new();
    epk.insert("kty", "EC");
    epk.insert("crv", crv.as_str());
    epk.insert("x", b64url_encode(x));
    epk.insert("y", b64url_encode(y));
    Ok((epk, z))
}

/// Key management on decrypt (RFC 7516 §5.2 steps 6–12) for ECDH-ES and
/// ECDH-ES+A*KW: the CEK, which must have the length `enc` requires (§5.2
/// step 9).
///
/// The `epk` is validated as the module documentation lists, before any
/// agreement; then Z, the Concat KDF (RFC 7518 §4.6.2) and, for +A*KW,
/// AES Key Wrap unwrap (RFC 3394 §2.2.2–§2.2.3).
///
/// # Errors
///
/// [`Error::DecryptionFailed`], whatever the cause: a missing or invalid
/// `epk` (wrong `kty`/`crv`, private members, off-curve, identity, wrong
/// length, all-zero X25519 secret), malformed `apu`/`apv`, a non-empty
/// encrypted key for direct ECDH-ES (RFC 7516 §5.2 step 10), a failed
/// unwrap or a CEK of the wrong length. No cause can be told from another
/// (RFC 7516 §11.4–§11.5).
pub(super) fn decrypt_key(
    alg: &KeyMgmtAlg,
    key: &RecipientKey,
    enc: &ContentEncAlg,
    header: &Header,
    encrypted_key: &[u8],
    _policy: &DecryptPolicy,
) -> Result<Cek> {
    unwrap_cek(alg, key, enc, header, encrypted_key).map_err(|_| Error::DecryptionFailed)
}

/// [`decrypt_key`] with the detailed error, which is never shown.
fn unwrap_cek(
    alg: &KeyMgmtAlg,
    key: &RecipientKey,
    enc: &ContentEncAlg,
    header: &Header,
    encrypted_key: &[u8],
) -> Result<Cek> {
    let derivation = derivation(alg, enc)?;
    let cek_len = cek_len(enc)?;
    // RFC 7516 §5.2 step 10: with Direct Key Agreement, "verify that the
    // JWE Encrypted Key value is an empty octet sequence".
    if !derivation.wraps && !encrypted_key.is_empty() {
        return Err(Error::DecryptionFailed);
    }
    // RFC 7518 §4.6.1.2–§4.6.1.3: base64url, decoded before use.
    let apu = party_info(header.apu.as_deref())?;
    let apv = party_info(header.apv.as_deref())?;
    let epk = header.epk.as_ref().ok_or(Error::DecryptionFailed)?;
    let z = agree_with_epk(key, epk)?;
    let derived = concat_kdf::derive(
        &z,
        derivation.alg_id,
        &apu,
        &apv,
        derivation.keydatalen_bits,
    )?;
    let cek = if derivation.wraps {
        aes_kw::unwrap(&derived, encrypted_key)?
    } else {
        derived
    };
    // RFC 7516 §5.2 step 9 (via RFC 7518 §4.6 for direct, where it holds by
    // construction): the CEK has the length `enc` requires.
    if cek.len() != cek_len {
        return Err(Error::DecryptionFailed);
    }
    Ok(Cek::new(cek))
}

/// The decoded `apu` or `apv` (RFC 7518 §4.6.1.2–§4.6.1.3), empty when
/// absent (§4.6.2: a zero-length Datalen).
fn party_info(value: Option<&str>) -> Result<Vec<u8>> {
    value.map_or_else(|| Ok(Vec::new()), b64url_decode)
}

/// Validates the `epk` object against the recipient's private `key` (the
/// steps of the module documentation) and, only if it passes, computes Z.
///
/// Shared by [`decrypt_key`] and the Wycheproof tests of `ecdh_nist`, so
/// those run the exact decrypt path.
///
/// # Errors
///
/// [`Error::DecryptionFailed`] for an `epk` that fails a check, or a `key`
/// that is not an ECDH-ES private key; the agreement's error otherwise
/// (an all-zero X25519 secret).
pub(super) fn agree_with_epk(key: &RecipientKey, epk: &Object) -> Result<Zeroizing<Vec<u8>>> {
    agree_with_imported_epk(key, epk, Jwk::from_object)
}

/// [`agree_with_epk`] with the JWK import step passed in as `import`.
///
/// Production always passes [`Jwk::from_object`]; the seam lets the unit
/// tests observe whether, and when, import is reached (ADR 0050), without
/// any global or thread-local state.
fn agree_with_imported_epk(
    key: &RecipientKey,
    epk: &Object,
    import: impl FnOnce(&Object) -> Result<Jwk>,
) -> Result<Zeroizing<Vec<u8>>> {
    // RFC 7518 §4.6.1.1: "It MUST contain only public key parameters".
    // Checked on the raw object, before import, which would otherwise run
    // the ADR 0043 §3 d·G consistency check: a scalar multiplication on
    // attacker input.
    if PRIVATE_MEMBERS.iter().any(|name| epk.contains(name)) {
        return Err(Error::DecryptionFailed);
    }
    // ADR 0041 §4: the JWK import checks (lengths, on-curve, identity).
    let epk = import(epk).map_err(|_| Error::DecryptionFailed)?;
    // RFC 7518 §4.6, RFC 8725 §3.4: the ephemeral key must be on the
    // recipient's curve.
    match (key, epk.material()) {
        (RecipientKey::P256Secret(secret), KeyMaterial::Ec(e)) if e.crv() == EcCurve::P256 => {
            nist_decrypt(secret, e)
        }
        (RecipientKey::P384Secret(secret), KeyMaterial::Ec(e)) if e.crv() == EcCurve::P384 => {
            nist_decrypt(secret, e)
        }
        (RecipientKey::P521Secret(secret), KeyMaterial::Ec(e)) if e.crv() == EcCurve::P521 => {
            nist_decrypt(secret, e)
        }
        (RecipientKey::X25519Secret(secret), KeyMaterial::Okp(o))
            if o.crv() == OkpCurve::X25519 =>
        {
            let x = <[u8; 32]>::try_from(o.x()).map_err(|_| Error::DecryptionFailed)?;
            // RFC 7748 §6.1: the all-zero Z is rejected by `agree`.
            let z = ecdh_x25519::agree(secret, &x25519_dalek::PublicKey::from(x))?;
            Ok(Zeroizing::new(z.to_vec()))
        }
        _ => Err(Error::DecryptionFailed),
    }
}

/// Z of the recipient's `secret` and the imported `epk` on the same NIST
/// curve. The point is the uncompressed SEC 1 encoding `0x04 ‖ x ‖ y`
/// (SEC 1 v2 §2.3.3) of the full-length coordinates import checked, and
/// the curve crate decodes it with its own on-curve check once more.
fn nist_decrypt<C>(secret: &SecretKey<C>, epk: &EcKey) -> Result<Zeroizing<Vec<u8>>>
where
    C: CurveArithmetic,
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
    FieldBytesSize<C>: ModulusSize,
{
    let point = [&[0x04][..], epk.x(), epk.y()].concat();
    let public = PublicKey::<C>::from_sec1_bytes(&point).map_err(|_| Error::DecryptionFailed)?;
    ecdh_nist::agree(secret, &public)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwe::content::generate_cek;
    use crate::jwe::key::Direction;
    use crate::jwe::random::OsRandom;
    use crate::keys::generate::{generate_ec, generate_okp};
    use crate::rng::CryptoRngAdapter;
    use crate::rng::insecure_test_vectors::FixedRng;
    use crate::test_counters::ecdh_agreements;

    use ContentEncAlg as E;
    use KeyMgmtAlg as A;

    const ALGS: [KeyMgmtAlg; 4] = [A::EcdhEs, A::EcdhEsA128KW, A::EcdhEsA192KW, A::EcdhEsA256KW];

    fn b64(text: &str) -> Vec<u8> {
        b64url_decode(text).unwrap_or_else(|e| panic!("{text}: {e}"))
    }

    fn hex(text: &str) -> Vec<u8> {
        assert!(text.len().is_multiple_of(2), "{text}");
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap_or_else(|e| panic!("{e}")))
            .collect()
    }

    fn jwk(json: &str) -> Jwk {
        Jwk::from_json(json.as_bytes()).unwrap_or_else(|e| panic!("{json}: {e}"))
    }

    fn object(json: &str) -> Object {
        crate::json::parse(json.as_bytes())
            .ok()
            .and_then(Value::into_object)
            .unwrap_or_else(|| panic!("{json}"))
    }

    fn header(json: &str) -> Header {
        Header::from_json(json.as_bytes()).unwrap_or_else(|e| panic!("{json}: {e}"))
    }

    fn bind(
        key: &Jwk,
        alg: &KeyMgmtAlg,
        enc: &ContentEncAlg,
        direction: Direction,
    ) -> RecipientKey {
        RecipientKey::from_jwk(key, alg, enc, direction).unwrap_or_else(|e| panic!("{alg}: {e}"))
    }

    fn policy() -> DecryptPolicy {
        DecryptPolicy::new(&ALGS, ContentEncAlg::KNOWN).unwrap_or_else(|e| panic!("{e}"))
    }

    fn options(apu: Option<&[u8]>, apv: Option<&[u8]>) -> RecipientOptions {
        RecipientOptions {
            apu: apu.map(<[u8]>::to_vec),
            apv: apv.map(<[u8]>::to_vec),
            ..RecipientOptions::default()
        }
    }

    fn decrypt(
        alg: &KeyMgmtAlg,
        key: &RecipientKey,
        enc: &ContentEncAlg,
        header: &Header,
        encrypted_key: &[u8],
    ) -> Result<Vec<u8>> {
        decrypt_key(alg, key, enc, header, encrypted_key, &policy())
            .map(|cek| cek.as_bytes().to_vec())
    }

    /// RFC 7518 Appendix C: Alice (the producer, ephemeral key) and Bob
    /// (the recipient), P-256, ECDH-ES with A128GCM, apu "Alice", apv "Bob".
    mod app_c {
        pub(super) const ALICE_D: &str = "0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo";
        pub(super) const ALICE_EPK: &str = r#"{"kty":"EC","crv":"P-256","x":"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0","y":"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps"}"#;
        pub(super) const BOB: &str = r#"{"kty":"EC","crv":"P-256","x":"weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ","y":"e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck","d":"VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"}"#;
        /// The Appendix C JOSE Header.
        pub(super) const HEADER: &str = r#"{"alg":"ECDH-ES","enc":"A128GCM","apu":"QWxpY2U","apv":"Qm9i","epk":{"kty":"EC","crv":"P-256","x":"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0","y":"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps"}}"#;
        /// The derived key.
        pub(super) const DERIVED: &str = "VqqN6vgjbSBcIijNcacQGg";
        /// Z (RFC 7518 Appendix C, as JSON array there).
        pub(super) const Z: [u8; 32] = [
            158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132, 38, 156, 251, 49,
            110, 163, 218, 128, 106, 72, 246, 218, 167, 121, 140, 254, 144, 196,
        ];
    }

    /// RFC 7520 §5.4.1 (Figure 107): the P-384 recipient key.
    const P384_KEY: &str = r#"{"kty":"EC","kid":"peregrin.took@tuckborough.example","use":"enc","crv":"P-384","x":"YU4rRUzdmVqmRtWOs2OpDE_T5fsNIodcG8G5FWPrTPMyxpzsSOGaQLpe2FpxBmu2","y":"A8-yxCHxkfBz3hKZfI1jUYMjUhsEveZ9THuwFjH2sCNdtksRJU7D5-SkgaFL1ETP","d":"iTx2pk7wW-GqJkHcEkFQb2EFyYcO7RugmaW3mRrQVAOUiPommT0IdnYK2xDlZh-j"}"#;
    /// RFC 7520 §5.4.3 (Figure 108): the P-384 ephemeral public key of §5.4.
    const P384_EPK: &str = r#"{"kty":"EC","crv":"P-384","x":"uBo4kHPw6kbjx5l0xowrd_oYzBmaz-GKFZu4xAFFkbYiWgutEK6iuEDsQ6wNdNg3","y":"sp3p5SGhZVC2faXumI-e9JU2Mo8KpoYrFDr5yPNVtW4PgEwZOyQTA-JdaY8tb7E0"}"#;
    /// RFC 7748 §6.1: Bob's X25519 key (RFC 8037 A.6 uses its public key).
    const X25519_BOB: &str = r#"{"kty":"OKP","crv":"X25519","x":"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08","d":"XasIfmJKikt54X-Lg4AO5m87sSkmGLb9HC-LJ_-I4Os"}"#;

    /// A generated private key on every ECDH-ES curve, with Appendix C's
    /// Bob for P-256.
    fn recipients() -> Vec<Jwk> {
        let mut os = CryptoRngAdapter::os();
        let gen_ec = |crv, rng: &mut CryptoRngAdapter<'_>| {
            generate_ec(crv, rng).unwrap_or_else(|e| panic!("{e}"))
        };
        vec![
            jwk(app_c::BOB),
            gen_ec(EcCurve::P384, &mut os),
            gen_ec(EcCurve::P521, &mut os),
            generate_okp(OkpCurve::X25519, &mut os).unwrap_or_else(|e| panic!("{e}")),
        ]
    }

    #[test]
    fn rfc7518_appendix_c_end_to_end() {
        // Encrypt: Alice's ephemeral d is the one draw; with Bob's public
        // key, apu "Alice" and apv "Bob", the CEK is the printed derived key
        // and the header carries Alice's epk and the encoded apu/apv.
        let bob = jwk(app_c::BOB);
        let encrypt_key_bob = bind(&bob, &A::EcdhEs, &E::A128GCM, Direction::Encrypt);
        let mut rng = FixedRng::new(b64(app_c::ALICE_D));
        let options = options(Some(b"Alice"), Some(b"Bob"));
        let out = encrypt_key(
            &A::EcdhEs,
            &encrypt_key_bob,
            &E::A128GCM,
            None,
            &options,
            &mut rng,
        )
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(rng.remaining(), 0);
        assert!(out.encrypted_key.is_empty());
        let cek = out.cek.as_ref().map(|c| c.as_bytes().to_vec());
        assert_eq!(cek, Some(b64(app_c::DERIVED)));
        assert_eq!(
            out.header_params.get("epk"),
            Some(&Value::from(object(app_c::ALICE_EPK)))
        );
        assert_eq!(out.header_params.get("apu"), Some(&Value::from("QWxpY2U")));
        assert_eq!(out.header_params.get("apv"), Some(&Value::from("Qm9i")));
        let names: Vec<&str> = out.header_params.iter().map(|(n, _)| n).collect();
        assert_eq!(names, ["epk", "apu", "apv"]);

        // Decrypt: Bob's private key and the printed header give the same key.
        let bob_secret = bind(&bob, &A::EcdhEs, &E::A128GCM, Direction::Decrypt);
        let (cek, ticks) = ecdh_agreements::count(|| {
            decrypt(
                &A::EcdhEs,
                &bob_secret,
                &E::A128GCM,
                &header(app_c::HEADER),
                &[],
            )
        });
        assert_eq!(cek, Ok(b64(app_c::DERIVED)));
        assert_eq!(ticks, 1);
    }

    #[test]
    fn independently_computed_concat_kdf_outputs_are_reproduced() {
        // T04 tester values, recomputed with Python hashlib (independent of
        // `sha2`) from the RFC 7518 Appendix C Z: direct ECDH-ES derives the
        // whole `enc` key (RFC 7518 §4.6.2 keydatalen), here 512 and 384
        // bits, which take two SHA-256 blocks.
        let bob = bind(
            &jwk(app_c::BOB),
            &A::EcdhEs,
            &E::A128GCM,
            Direction::Decrypt,
        );
        let hs512 =
            r#"{"alg":"ECDH-ES","enc":"A256CBC-HS512","apu":"QWxpY2U","apv":"Qm9i","epk":EPK}"#
                .replace("EPK", app_c::ALICE_EPK);
        let cek = decrypt(&A::EcdhEs, &bob, &E::A256CbcHs512, &header(&hs512), &[]);
        assert_eq!(
            cek,
            Ok(hex(
                "3986aa79f6396420e580e5d3890f623fee5d4522307929eb99ee3425a001ecc1\
                 75b1754e3fb644ce825034b562523e9a8806bca8d76afa861e9b79515803225d"
            ))
        );
        let hs384 =
            r#"{"alg":"ECDH-ES","enc":"A192CBC-HS384","epk":EPK}"#.replace("EPK", app_c::ALICE_EPK);
        let cek = decrypt(&A::EcdhEs, &bob, &E::A192CbcHs384, &header(&hs384), &[]);
        assert_eq!(
            cek,
            Ok(hex(
                "f7166ec8eafc577e0404b84bd248f333feb0b9ad0dba869bbd0af407c3d85355\
                 72fac2b38b1d05ac372d4fca4eb8b41a"
            ))
        );
    }

    #[test]
    fn key_wrapping_uses_the_alg_as_algorithm_id_and_its_key_length() {
        // RFC 7518 §4.6.2: for +A*KW, AlgorithmID is the `alg` value and
        // keydatalen is 128/192/256; the derived key wraps the CEK
        // (RFC 3394). Alice's ephemeral key, so Z is Appendix C's.
        let bob = jwk(app_c::BOB);
        let cek = Cek::from_slice(&[0x5Au8; 32]);
        for (alg, bits) in [
            (A::EcdhEsA128KW, 128),
            (A::EcdhEsA192KW, 192),
            (A::EcdhEsA256KW, 256),
        ] {
            let public = bind(&bob, &alg, &E::A256GCM, Direction::Encrypt);
            let mut rng = FixedRng::new(b64(app_c::ALICE_D));
            let options = options(Some(b"Alice"), Some(b"Bob"));
            let out = encrypt_key(&alg, &public, &E::A256GCM, Some(&cek), &options, &mut rng)
                .unwrap_or_else(|e| panic!("{alg}: {e}"));
            assert!(out.cek.is_none(), "{alg}");
            assert_eq!(out.encrypted_key.len(), 40, "{alg}");
            let kek = concat_kdf::derive(&app_c::Z, alg.as_str(), b"Alice", b"Bob", bits)
                .unwrap_or_else(|e| panic!("{e}"));
            assert_eq!(kek.len() * 8, bits as usize);
            let unwrapped = aes_kw::unwrap(&kek, &out.encrypted_key).map(|k| k.to_vec());
            assert_eq!(unwrapped, Ok(cek.as_bytes().to_vec()), "{alg}");
            // The `enc` value as AlgorithmID would give another key.
            let wrong = concat_kdf::derive(&app_c::Z, E::A256GCM.as_str(), b"Alice", b"Bob", bits)
                .unwrap_or_else(|e| panic!("{e}"));
            assert!(aes_kw::unwrap(&wrong, &out.encrypted_key).is_err(), "{alg}");

            let secret = bind(&bob, &alg, &E::A256GCM, Direction::Decrypt);
            let header = Header::from_object(out.header_params).unwrap_or_else(|e| panic!("{e}"));
            let got = decrypt(&alg, &secret, &E::A256GCM, &header, &out.encrypted_key);
            assert_eq!(got, Ok(cek.as_bytes().to_vec()), "{alg}");
        }
    }

    #[test]
    fn apu_equal_to_apv_is_invalid_format_before_any_draw() {
        // RFC 7518 §4.6.2: "The "apu" and "apv" values MUST be distinct,
        // when used."
        let bob = jwk(app_c::BOB);
        for alg in &ALGS {
            let public = bind(&bob, alg, &E::A128GCM, Direction::Encrypt);
            let cek = generate_cek(&E::A128GCM, &mut OsRandom).unwrap_or_else(|e| panic!("{e}"));
            let cek = (*alg != A::EcdhEs).then_some(&cek);
            for same in [&b"same"[..], b""] {
                let mut rng = FixedRng::new(b64(app_c::ALICE_D));
                let result = encrypt_key(
                    alg,
                    &public,
                    &E::A128GCM,
                    cek,
                    &options(Some(same), Some(same)),
                    &mut rng,
                );
                assert!(matches!(result, Err(Error::InvalidFormat(_))), "{alg}");
                assert_eq!(rng.remaining(), 32, "{alg}: nothing drawn");
            }
            // Distinct, or only one of them, is fine.
            for (apu, apv) in [
                (Some(&b"a"[..]), Some(&b"b"[..])),
                (Some(b"a"), None),
                (None, Some(b"a")),
                (None, None),
            ] {
                let mut rng = FixedRng::new(b64(app_c::ALICE_D));
                let out = encrypt_key(alg, &public, &E::A128GCM, cek, &options(apu, apv), &mut rng)
                    .unwrap_or_else(|e| panic!("{alg}: {e}"));
                assert_eq!(out.header_params.contains("apu"), apu.is_some());
                assert_eq!(out.header_params.contains("apv"), apv.is_some());
            }
        }
    }

    #[test]
    fn apu_and_apv_are_base64url_decoded_into_the_kdf() {
        // RFC 7518 §4.6.1.2–§4.6.1.3: the KDF takes the decoded octets, so
        // a different apu derives a different key, and a value that is not
        // strict base64url fails.
        let bob = bind(
            &jwk(app_c::BOB),
            &A::EcdhEs,
            &E::A128GCM,
            Direction::Decrypt,
        );
        let other = app_c::HEADER.replace("QWxpY2U", "QWxpY2E"); // "Alica"
        let cek = decrypt(&A::EcdhEs, &bob, &E::A128GCM, &header(&other), &[]);
        assert!(cek.is_ok_and(|cek| cek != b64(app_c::DERIVED)));
        for bad in ["QWxpY2U=", "QWxp Y2U", "QWxpY2V"] {
            let bad = app_c::HEADER.replace("QWxpY2U", bad);
            let (result, ticks) = ecdh_agreements::count(|| {
                decrypt(&A::EcdhEs, &bob, &E::A128GCM, &header(&bad), &[])
            });
            assert_eq!(result, Err(Error::DecryptionFailed), "{bad}");
            assert_eq!(ticks, 0, "{bad}");
        }
    }

    #[test]
    fn every_curve_and_alg_round_trips() {
        // RFC 7518 §4.6 on P-256, P-384, P-521 (§6.2) and X25519 (RFC 8037
        // §3.2), direct and with key wrapping, for a GCM and a CBC-HMAC enc.
        for key in recipients() {
            for alg in &ALGS {
                for enc in [E::A128GCM, E::A256CbcHs512] {
                    let public = bind(&key, alg, &enc, Direction::Encrypt);
                    let secret = bind(&key, alg, &enc, Direction::Decrypt);
                    let random =
                        generate_cek(&enc, &mut OsRandom).unwrap_or_else(|e| panic!("{e}"));
                    let given = (*alg != A::EcdhEs).then_some(&random);
                    let out = encrypt_key(
                        alg,
                        &public,
                        &enc,
                        given,
                        &options(Some(b"u"), None),
                        &mut OsRandom,
                    )
                    .unwrap_or_else(|e| panic!("{alg}: {e}"));
                    let expected = out.cek.as_ref().or(given).map(|c| c.as_bytes().to_vec());
                    let header =
                        Header::from_object(out.header_params).unwrap_or_else(|e| panic!("{e}"));
                    let got = decrypt(alg, &secret, &enc, &header, &out.encrypted_key);
                    assert_eq!(got.ok(), expected, "{alg} {enc}");
                }
            }
        }
    }

    #[test]
    fn every_agreement_uses_a_fresh_ephemeral_key() {
        // RFC 7518 §4.6.1: "A new ephemeral public key value MUST be
        // generated for each key agreement operation."
        for key in recipients() {
            let public = bind(&key, &A::EcdhEs, &E::A128GCM, Direction::Encrypt);
            let run = || {
                encrypt_key(
                    &A::EcdhEs,
                    &public,
                    &E::A128GCM,
                    None,
                    &RecipientOptions::default(),
                    &mut OsRandom,
                )
                .unwrap_or_else(|e| panic!("{e}"))
            };
            let (a, b) = (run(), run());
            assert_ne!(a.header_params.get("epk"), b.header_params.get("epk"));
            assert_ne!(
                a.cek.map(|c| c.as_bytes().to_vec()),
                b.cek.map(|c| c.as_bytes().to_vec())
            );
        }
    }

    #[test]
    fn epk_has_only_public_members_at_full_length() {
        // RFC 7518 §4.6.1.1 ("MUST contain only public key parameters"),
        // §6.2.1 (full-length x and y), RFC 8037 §2 (32-octet x).
        for (key, members, len) in recipients()
            .iter()
            .zip([
                (&["kty", "crv", "x", "y"][..], 32),
                (&["kty", "crv", "x", "y"][..], 48),
                (&["kty", "crv", "x", "y"][..], 66),
                (&["kty", "crv", "x"][..], 32),
            ])
            .map(|(k, (m, l))| (k, m, l))
        {
            let public = bind(key, &A::EcdhEs, &E::A128GCM, Direction::Encrypt);
            let out = encrypt_key(
                &A::EcdhEs,
                &public,
                &E::A128GCM,
                None,
                &RecipientOptions::default(),
                &mut OsRandom,
            )
            .unwrap_or_else(|e| panic!("{e}"));
            let epk = out
                .header_params
                .get("epk")
                .and_then(Value::as_object)
                .unwrap_or_else(|| panic!("epk"));
            let names: Vec<&str> = epk.iter().map(|(n, _)| n).collect();
            assert_eq!(names, members);
            for coordinate in &members[2..] {
                let value = epk
                    .get(coordinate)
                    .and_then(Value::as_str)
                    .unwrap_or_else(|| panic!("{coordinate}"));
                assert_eq!(b64(value).len(), len);
            }
            let imported = Jwk::from_object(epk).unwrap_or_else(|e| panic!("{e}"));
            assert!(imported.is_public());
        }
    }

    /// A P-256 point on y² = x³ − 3x + b′ with b′ ≠ b: the P-256 generator's
    /// x with y + 1, so the point lies on another curve over the same
    /// field (the invalid-curve attack, CVE-2017-16007, research.md §4.2).
    const INVALID_CURVE_EPK: &str = r#"{"kty":"EC","crv":"P-256","x":"axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY","y":"T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfY"}"#;
    /// A low-order point of the quadratic twist of P-256 (Sanso 2017; the x
    /// of Wycheproof `ecdh_secp256r1_ecpoint` tcId 350, "public key is a low
    /// order point on twist"), written as (x, y) with −y² = x³ − 3x + b.
    /// x³ − 3x + b is a non-residue mod p, so no y puts it on P-256.
    const TWIST_EPK: &str = r#"{"kty":"EC","crv":"P-256","x":"793jsyhyqe_887lMv3Oqezn5aD7OkSG5hSFn9OPaYJs","y":"6rahtGMUwhn3AU4EFtzM7Ice2VkxZ8AgMIZQw-EQ6Uo"}"#;
    /// The secp256k1 generator (SEC 2 §2.4.1): on its own curve, not P-256.
    const SECP256K1_EPK: &str = r#"{"kty":"EC","crv":"secp256k1","x":"eb5mfvncu6xVoGKVzocLBwKb_NstzijZWfKBWxb4F5g","y":"SDradyajxGVdpPv8DhEIqP0XtEimhVQZnEfQj_sQ1Lg"}"#;

    /// The Appendix C header with `epk` replaced (or removed for `None`).
    fn app_c_header_with(epk: Option<&str>) -> Header {
        match epk {
            Some(epk) => header(&format!(
                r#"{{"alg":"ECDH-ES","enc":"A128GCM","epk":{epk}}}"#
            )),
            None => header(r#"{"alg":"ECDH-ES","enc":"A128GCM"}"#),
        }
    }

    #[test]
    fn invalid_nist_epk_fails_before_any_agreement() {
        // RFC 8725 §3.4, RFC 7518 §4.6.1.1, ADR 0041 §4: each invalid epk is
        // DecryptionFailed, and `ecdh_nist::agree` never runs.
        let bob = bind(
            &jwk(app_c::BOB),
            &A::EcdhEs,
            &E::A128GCM,
            Direction::Decrypt,
        );
        let alice = object(app_c::ALICE_EPK);
        let with = |name: &str, value: &str| {
            let mut epk = alice.clone();
            epk.insert(name, value);
            Value::from(epk).to_json()
        };
        let cases: Vec<(&str, Option<String>)> = vec![
            ("missing", None),
            ("private d", Some(with("d", app_c::ALICE_D))),
            ("private k", Some(with("k", "AAAA"))),
            ("kty OKP", Some(r#"{"kty":"OKP","crv":"X25519","x":"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08"}"#.to_owned())),
            ("kty oct", Some(r#"{"kty":"oct"}"#.to_owned())),
            ("crv P-384", Some(P384_EPK.to_owned())),
            ("crv secp256k1", Some(SECP256K1_EPK.to_owned())),
            ("crv label only", Some(with("crv", "P-384"))),
            ("x 31 octets", Some(with("x", "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SQ"))),
            ("y 33 octets", Some(with("y", "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFppsA"))),
            ("y missing", Some(r#"{"kty":"EC","crv":"P-256","x":"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0"}"#.to_owned())),
            ("off-curve", Some(with("y", "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFppo"))),
            // The identity has no affine coordinates; (0, 0) is how an
            // attacker would spell it (b ≠ 0, so it is off the curve).
            ("identity (0, 0)", Some(format!(r#"{{"kty":"EC","crv":"P-256","x":"{zero}","y":"{zero}"}}"#, zero = "A".repeat(43)))),
            ("invalid curve", Some(INVALID_CURVE_EPK.to_owned())),
            ("twist point", Some(TWIST_EPK.to_owned())),
            ("x not base64url", Some(with("x", "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0="))),
        ];
        for (what, epk) in &cases {
            let header = app_c_header_with(epk.as_deref());
            let (result, ticks) =
                ecdh_agreements::count(|| decrypt(&A::EcdhEs, &bob, &E::A128GCM, &header, &[]));
            assert_eq!(result, Err(Error::DecryptionFailed), "{what}");
            assert_eq!(ticks, 0, "{what}: the agreement ran");
            // The same for the key-wrapping variant.
            let kw = bind(
                &jwk(app_c::BOB),
                &A::EcdhEsA128KW,
                &E::A128GCM,
                Direction::Decrypt,
            );
            let (result, ticks) = ecdh_agreements::count(|| {
                decrypt(&A::EcdhEsA128KW, &kw, &E::A128GCM, &header, &[0xA6; 24])
            });
            assert_eq!(result, Err(Error::DecryptionFailed), "{what} (KW)");
            assert_eq!(ticks, 0, "{what} (KW): the agreement ran");
        }
        // The valid epk with a non-empty encrypted key under direct ECDH-ES
        // (RFC 7516 §5.2 step 10) fails before the agreement too.
        let header = app_c_header_with(Some(app_c::ALICE_EPK));
        let (result, ticks) =
            ecdh_agreements::count(|| decrypt(&A::EcdhEs, &bob, &E::A128GCM, &header, &[0]));
        assert_eq!((result, ticks), (Err(Error::DecryptionFailed), 0));
        // And the valid epk itself reaches exactly one agreement.
        let (result, ticks) =
            ecdh_agreements::count(|| decrypt(&A::EcdhEs, &bob, &E::A128GCM, &header, &[]));
        assert!(result.is_ok());
        assert_eq!(ticks, 1);
    }

    #[test]
    fn an_epk_on_the_wrong_curve_fails_for_every_recipient_curve() {
        // RFC 7518 §4.6: the agreement is on the recipient's curve; a P-256
        // epk is refused by P-384, P-521 and X25519 keys, and an X25519 epk
        // by every NIST key, with no agreement.
        let x25519_epk =
            r#"{"kty":"OKP","crv":"X25519","x":"hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo"}"#;
        for key in recipients().iter().skip(1) {
            let secret = bind(key, &A::EcdhEs, &E::A128GCM, Direction::Decrypt);
            let epk = if matches!(secret, RecipientKey::X25519Secret(_)) {
                app_c::ALICE_EPK
            } else {
                x25519_epk
            };
            for epk in [epk, app_c::ALICE_EPK] {
                if matches!(secret, RecipientKey::X25519Secret(_)) == (epk == x25519_epk) {
                    continue;
                }
                let header = app_c_header_with(Some(epk));
                let (result, ticks) = ecdh_agreements::count(|| {
                    decrypt(&A::EcdhEs, &secret, &E::A128GCM, &header, &[])
                });
                assert_eq!((result, ticks), (Err(Error::DecryptionFailed), 0), "{epk}");
            }
        }
    }

    #[test]
    fn low_order_x25519_epk_fails_after_its_one_agreement() {
        // RFC 7748 §6.1, ADR 0043 §2: a low-order u gives the all-zero Z,
        // which `ecdh_x25519::agree` rejects after computing it (so the
        // counter is 1, not 0); the error is DecryptionFailed.
        let bob = jwk(X25519_BOB);
        for alg in &ALGS {
            let secret = bind(&bob, alg, &E::A128GCM, Direction::Decrypt);
            let ek: &[u8] = if *alg == A::EcdhEs { &[] } else { &[0xA6; 24] };
            for u in [
                // Wycheproof x25519 LowOrderPublic points: 0, 1, and the
                // point of order 8.
                "0000000000000000000000000000000000000000000000000000000000000000",
                "0100000000000000000000000000000000000000000000000000000000000000",
                "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
            ] {
                let epk = format!(
                    r#"{{"kty":"OKP","crv":"X25519","x":"{}"}}"#,
                    b64url_encode(&hex(u))
                );
                let header = app_c_header_with(Some(&epk));
                let (result, ticks) =
                    ecdh_agreements::count(|| decrypt(alg, &secret, &E::A128GCM, &header, ek));
                assert_eq!(result, Err(Error::DecryptionFailed), "{alg} {u}");
                assert_eq!(ticks, 1, "{alg} {u}");
            }
            // A private member or a wrong length fails before the agreement.
            for epk in [
                r#"{"kty":"OKP","crv":"X25519","x":"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08","d":"XasIfmJKikt54X-Lg4AO5m87sSkmGLb9HC-LJ_-I4Os"}"#,
                r#"{"kty":"OKP","crv":"X25519","x":"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK0"}"#,
                r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#,
            ] {
                let header = app_c_header_with(Some(epk));
                let (result, ticks) =
                    ecdh_agreements::count(|| decrypt(alg, &secret, &E::A128GCM, &header, ek));
                assert_eq!(
                    (result, ticks),
                    (Err(Error::DecryptionFailed), 0),
                    "{alg} {epk}"
                );
            }
        }
    }

    #[test]
    fn x25519_encrypt_to_a_low_order_recipient_key_is_invalid_key() {
        // RFC 7748 §6.1: the all-zero Z is refused on encrypt too; the
        // caller's key is unusable (plan.md error contract).
        let low = jwk(
            r#"{"kty":"OKP","crv":"X25519","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
        );
        let public = bind(&low, &A::EcdhEs, &E::A128GCM, Direction::Encrypt);
        let result = encrypt_key(
            &A::EcdhEs,
            &public,
            &E::A128GCM,
            None,
            &RecipientOptions::default(),
            &mut OsRandom,
        );
        assert!(matches!(result, Err(Error::InvalidKey(_))));
    }

    #[test]
    fn a_wrong_key_or_a_cek_of_the_wrong_length_fails() {
        // RFC 3394 §2.2.3: another recipient's key fails the unwrap
        // integrity check; RFC 7516 §5.2 step 9: an unwrapped CEK of the
        // wrong length for `enc` fails. Both are DecryptionFailed.
        let keys = recipients();
        let bob = &keys[0];
        let other = generate_ec(EcCurve::P256, &mut CryptoRngAdapter::os())
            .unwrap_or_else(|e| panic!("{e}"));
        let alg = A::EcdhEsA128KW;
        let public = bind(bob, &alg, &E::A128GCM, Direction::Encrypt);
        let cek = generate_cek(&E::A128GCM, &mut OsRandom).unwrap_or_else(|e| panic!("{e}"));
        let out = encrypt_key(
            &alg,
            &public,
            &E::A128GCM,
            Some(&cek),
            &RecipientOptions::default(),
            &mut OsRandom,
        )
        .unwrap_or_else(|e| panic!("{e}"));
        let header = Header::from_object(out.header_params).unwrap_or_else(|e| panic!("{e}"));
        let wrong = bind(&other, &alg, &E::A128GCM, Direction::Decrypt);
        assert_eq!(
            decrypt(&alg, &wrong, &E::A128GCM, &header, &out.encrypted_key),
            Err(Error::DecryptionFailed)
        );
        let right = bind(bob, &alg, &E::A128GCM, Direction::Decrypt);
        assert_eq!(
            decrypt(&alg, &right, &E::A256GCM, &header, &out.encrypted_key),
            Err(Error::DecryptionFailed)
        );
        assert_eq!(
            decrypt(&alg, &right, &E::A128GCM, &header, &out.encrypted_key),
            Ok(cek.as_bytes().to_vec())
        );
        // A truncated wrapped key, or an empty one.
        for ek in [&out.encrypted_key[..16], &[][..]] {
            assert_eq!(
                decrypt(&alg, &right, &E::A128GCM, &header, ek),
                Err(Error::DecryptionFailed)
            );
        }
    }

    #[test]
    fn the_cek_contract_and_the_key_family_are_enforced() {
        let bob = jwk(app_c::BOB);
        let cek = generate_cek(&E::A128GCM, &mut OsRandom).unwrap_or_else(|e| panic!("{e}"));
        let none = RecipientOptions::default();
        // Direct ECDH-ES determines the CEK; +A*KW wraps the given one.
        let public = bind(&bob, &A::EcdhEs, &E::A128GCM, Direction::Encrypt);
        let result = encrypt_key(
            &A::EcdhEs,
            &public,
            &E::A128GCM,
            Some(&cek),
            &none,
            &mut OsRandom,
        );
        assert!(matches!(result, Err(Error::InvalidKey(_))));
        let result = encrypt_key(
            &A::EcdhEsA256KW,
            &public,
            &E::A128GCM,
            None,
            &none,
            &mut OsRandom,
        );
        assert!(matches!(result, Err(Error::InvalidKey(_))));
        // Not an ECDH-ES public key, or not an ECDH-ES alg.
        let symmetric = RecipientKey::Symmetric(Zeroizing::new(vec![0; 16]));
        let result = encrypt_key(
            &A::EcdhEs,
            &symmetric,
            &E::A128GCM,
            None,
            &none,
            &mut OsRandom,
        );
        assert_eq!(result.map(|_| ()), Err(Error::KeyAlgorithmMismatch));
        let secret = bind(&bob, &A::EcdhEs, &E::A128GCM, Direction::Decrypt);
        let result = encrypt_key(&A::EcdhEs, &secret, &E::A128GCM, None, &none, &mut OsRandom);
        assert_eq!(result.map(|_| ()), Err(Error::KeyAlgorithmMismatch));
        let result = encrypt_key(
            &A::A128KW,
            &public,
            &E::A128GCM,
            Some(&cek),
            &none,
            &mut OsRandom,
        );
        assert_eq!(result.map(|_| ()), Err(Error::UnsupportedAlgorithm));
        // On decrypt every such case is DecryptionFailed.
        let header = header(app_c::HEADER);
        assert_eq!(
            decrypt(&A::EcdhEs, &symmetric, &E::A128GCM, &header, &[]),
            Err(Error::DecryptionFailed)
        );
        assert_eq!(
            decrypt(&A::EcdhEs, &public, &E::A128GCM, &header, &[]),
            Err(Error::DecryptionFailed)
        );
        assert_eq!(
            decrypt(&A::A128KW, &secret, &E::A128GCM, &header, &[]),
            Err(Error::DecryptionFailed)
        );
        assert_eq!(
            decrypt(&A::EcdhEs, &secret, &E::from("A512GCM"), &header, &[]),
            Err(Error::DecryptionFailed)
        );
    }

    #[test]
    fn a_failing_rng_is_randomness_unavailable() {
        // ADR 0005: fail closed, no output.
        for key in recipients() {
            let public = bind(&key, &A::EcdhEs, &E::A128GCM, Direction::Encrypt);
            let mut rng = FixedRng::new([1u8; 31]);
            let result = encrypt_key(
                &A::EcdhEs,
                &public,
                &E::A128GCM,
                None,
                &RecipientOptions::default(),
                &mut rng,
            );
            assert_eq!(result.map(|_| ()), Err(Error::RandomnessUnavailable));
        }
    }

    #[test]
    fn rfc7520_5_4_epk_unwraps_the_printed_cek() {
        // RFC 7520 §5.4: the P-384 recipient key and the printed epk unwrap
        // the printed encrypted key (Figure 111) to the CEK (Figure 109).
        let secret = bind(
            &jwk(P384_KEY),
            &A::EcdhEsA128KW,
            &E::A128GCM,
            Direction::Decrypt,
        );
        let header = header(&format!(
            r#"{{"alg":"ECDH-ES+A128KW","enc":"A128GCM","epk":{P384_EPK}}}"#
        ));
        let cek = decrypt(
            &A::EcdhEsA128KW,
            &secret,
            &E::A128GCM,
            &header,
            &b64("0DJjBXri_kBcC46IkU5_Jk9BqaQeHdv2"),
        );
        assert_eq!(cek, Ok(b64("Nou2ueKlP70ZXDbq9UrRwg")));
    }
}
