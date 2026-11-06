//! ECDSA family: ES256, ES384, ES512 (RFC 7518 §3.4) and ES256K
//! (RFC 8812 §3.2), with fixed-length R‖S signatures.
//!
//! Implements the family contract documented in `jws/alg.rs`, on the
//! RustCrypto curve crates (`p256`, `p384`, `p521`, `k256`, ADR 0002):
//!
//! | `alg`  | curve     | hash    | R‖S octets |
//! |--------|-----------|---------|------------|
//! | ES256  | P-256     | SHA-256 | 64         |
//! | ES384  | P-384     | SHA-384 | 96         |
//! | ES512  | P-521     | SHA-512 | 132        |
//! | ES256K | secp256k1 | SHA-256 | 64         |
//!
//! - **Signature form.** The JWS Signature is R ‖ S, each a big-endian
//!   integer of exactly the curve's field size (RFC 7518 §3.4 steps 2–3,
//!   RFC 8812 §3.2), never ASN.1 DER.
//! - **S form (ADR 0026 §5).** Signing emits low-S on every curve. Verify
//!   normalizes S before checking, so a high-S signature is valid exactly
//!   when its low-S twin is. Consequence: a JWS's bytes are malleable
//!   (s ↔ n − s), so the raw token is no uniqueness or replay key
//!   (RFC 8725 §3.10 spirit); use the claims (`jti`).
//! - **Randomness (ADR 0005).** Signing is hedged RFC 6979: the nonce is
//!   derived from the key, the message hash and fresh OS randomness
//!   (`ecdsa`'s `try_sign_with_rng`, RFC 6979 §3.6), so neither a weak RNG
//!   nor a repeated message can leak the key.
//! - **Keys.** The public point is rebuilt from the JWK `x`/`y` and checked
//!   on the curve; the private `d` must be exactly the field size and in
//!   [1, n − 1]. Import already checks both (ADR 0041 §4); the family
//!   checks again where it builds the key (ADR 0007). `d` is only borrowed
//!   from its wiped-on-drop buffer, and the curve crate's `SigningKey`
//!   wipes its scalar on drop.

use crate::error::{Error, Result};
use crate::jwa::SigningAlg;
use crate::jwk::{EcCurve, EcKey, Jwk, KeyMaterial};
use crate::rng::CryptoRngAdapter;

/// Signs `signing_input` with hedged RFC 6979 ECDSA (ADR 0005), returning
/// R‖S of exactly 64/96/132/64 octets for ES256/384/512/256K
/// (RFC 7518 §3.4, RFC 8812 §3.2), with S in low form (ADR 0026 §5).
///
/// Key binding has checked that `key` is an `EC` private key on the
/// curve `alg` requires (RFC 7518 §3.4, RFC 8812 §3.3).
///
/// # Errors
///
/// - [`Error::InvalidKey`] if the private scalar is not exactly the field
///   size or not a valid scalar.
/// - [`Error::RandomnessUnavailable`] if the OS CSPRNG fails (ADR 0005).
pub(crate) fn sign(alg: &SigningAlg, key: &Jwk, signing_input: &[u8]) -> Result<Vec<u8>> {
    sign_with_rng(alg, key, signing_input, &mut CryptoRngAdapter::os())
}

/// [`sign`], with the added entropy of the hedged RFC 6979 nonce drawn
/// from `rng`. [`sign`] always passes [`CryptoRngAdapter::os`]; only tests
/// pass another source, explicitly (ADR 0041 §3).
fn sign_with_rng(
    alg: &SigningAlg,
    key: &Jwk,
    signing_input: &[u8],
    rng: &mut CryptoRngAdapter<'_>,
) -> Result<Vec<u8>> {
    let ec = bound_ec_key(alg, key)?;
    // Key binding refuses a public key for signing; this is the guard.
    let d = ec.d().ok_or(Error::KeyAlgorithmMismatch)?;
    match ec.crv() {
        EcCurve::P256 => p256_ops::sign(d, signing_input, rng),
        EcCurve::P384 => p384_ops::sign(d, signing_input, rng),
        EcCurve::P521 => p521_ops::sign(d, signing_input, rng),
        EcCurve::Secp256k1 => k256_ops::sign(d, signing_input, rng),
    }
}

/// Validates an R‖S signature over `signing_input` (RFC 7518 §3.4,
/// RFC 8812 §3.2; RFC 7515 §5.2 step 8). A high-S signature is valid
/// exactly when its low-S twin is (ADR 0026 §5).
///
/// Key binding has checked the key's family and curve as for [`sign`].
/// The key is checked before the signature (ADR 0026 §2: step 8, then 9).
///
/// # Errors
///
/// - [`Error::InvalidSignature`] if the signature is not exactly
///   64/96/132/64 octets (DER is never accepted), has r = 0 or s = 0, or
///   does not validate.
/// - [`Error::InvalidKey`] if the public point is not on the curve or is
///   the identity.
pub(crate) fn verify(
    alg: &SigningAlg,
    key: &Jwk,
    signing_input: &[u8],
    signature: &[u8],
) -> Result<()> {
    let ec = bound_ec_key(alg, key)?;
    let (x, y) = (ec.x(), ec.y());
    match ec.crv() {
        EcCurve::P256 => p256_ops::verify(x, y, signing_input, signature),
        EcCurve::P384 => p384_ops::verify(x, y, signing_input, signature),
        EcCurve::P521 => p521_ops::verify(x, y, signing_input, signature),
        EcCurve::Secp256k1 => k256_ops::verify(x, y, signing_input, signature),
    }
}

/// The `EC` key of `key`, if it is on the curve `alg` names: ES256 P-256,
/// ES384 P-384, ES512 P-521 (RFC 7518 §3.4), ES256K secp256k1
/// (RFC 8812 §3.3).
///
/// Key binding guarantees this; anything else is
/// [`Error::KeyAlgorithmMismatch`], never a signature on the wrong curve
/// or a panic (the family contract in `jws/alg.rs`).
fn bound_ec_key<'k>(alg: &SigningAlg, key: &'k Jwk) -> Result<&'k EcKey> {
    let curve = match alg {
        SigningAlg::ES256 => EcCurve::P256,
        SigningAlg::ES384 => EcCurve::P384,
        SigningAlg::ES512 => EcCurve::P521,
        SigningAlg::ES256K => EcCurve::Secp256k1,
        _ => return Err(Error::KeyAlgorithmMismatch),
    };
    match key.material() {
        KeyMaterial::Ec(ec) if ec.crv() == curve => Ok(ec),
        _ => Err(Error::KeyAlgorithmMismatch),
    }
}

/// Detail for an `x` or `y` that is not exactly the field size
/// (RFC 7518 §6.2.1.2–§6.2.1.3).
const COORDINATE_LENGTH: &str = "EC coordinate has the wrong length for crv";
/// Detail for a public point that is off the curve (SEC 1 v2 §3.2.2.1).
const POINT_INVALID: &str = "EC point is not on the curve";
/// Detail for a `d` that is not exactly the field size (RFC 7518 §6.2.2.1).
const SCALAR_LENGTH: &str = "EC private key d has the wrong length for crv";
/// Detail for a `d` outside [1, n − 1] (SEC 1 v2 §3.2.1).
const SCALAR_INVALID: &str = "EC private key d is out of range";

/// The per-curve primitives. Each curve crate exposes its ECDSA types only
/// as concrete aliases (`pXXX::ecdsa::{Signature, SigningKey,
/// VerifyingKey}`; p521 0.14 has no newtype wrapper), so one module is
/// generated per curve with identical code.
macro_rules! curve_ops {
    ($(#[$doc:meta])* $module:ident, $krate:ident) => {
        $(#[$doc])*
        pub(super) mod $module {
            use $krate::ecdsa::signature::{RandomizedSigner, Verifier};
            use $krate::ecdsa::{Signature, SigningKey, VerifyingKey};
            use $krate::{FieldBytes, Sec1Point};

            use super::{COORDINATE_LENGTH, POINT_INVALID, SCALAR_INVALID, SCALAR_LENGTH};
            use crate::error::{Error, Result};
            use crate::rng::CryptoRngAdapter;

            /// The signing key for the private scalar `d`
            /// (RFC 7518 §6.2.2.1).
            ///
            /// `d` must be exactly the field size: it is borrowed as
            /// `FieldBytes` (no copy, no zero-padding of a short value into
            /// another key, as `from_slice` would), and must be in
            /// [1, n − 1] (SEC 1 v2 §3.2.1). The `SigningKey` wipes its
            /// scalar on drop.
            ///
            /// # Errors
            ///
            /// [`Error::InvalidKey`] for a wrong length or an out-of-range
            /// scalar.
            pub(crate) fn signing_key(d: &[u8]) -> Result<SigningKey> {
                let d = <&FieldBytes>::try_from(d).map_err(|_| Error::InvalidKey(SCALAR_LENGTH))?;
                SigningKey::from_bytes(d).map_err(|_| Error::InvalidKey(SCALAR_INVALID))
            }

            /// RFC 7518 §3.4 signing: ECDSA with the curve's hash and a
            /// hedged RFC 6979 nonce (`try_sign_with_rng`, never the
            /// deterministic `Signer::sign`; ADR 0005), S normalized to low
            /// form (ADR 0026 §5), serialized as R‖S of exactly twice the
            /// field size.
            ///
            /// # Errors
            ///
            /// [`Error::InvalidKey`] from [`signing_key`];
            /// [`Error::RandomnessUnavailable`] if `rng` fails. With a valid
            /// key that is the only way `try_sign_with_rng` can fail in
            /// `ecdsa` 0.17.0 (pinned through the curve crate): it draws one
            /// field element of entropy and then signs infallibly.
            pub(crate) fn sign(
                d: &[u8],
                signing_input: &[u8],
                rng: &mut CryptoRngAdapter<'_>,
            ) -> Result<Vec<u8>> {
                let key = signing_key(d)?;
                let signature: Signature = key
                    .try_sign_with_rng(rng, signing_input)
                    .map_err(|_| Error::RandomnessUnavailable)?;
                Ok(signature.normalize_s().to_bytes().to_vec())
            }

            /// The public key at (`x`, `y`) (RFC 7518 §6.2.1.2–§6.2.1.3):
            /// the uncompressed SEC 1 point (SEC 1 v2 §2.3.3), which the
            /// curve crate checks for reduced coordinates on the curve
            /// (SEC 1 v2 §3.2.2.1). The identity has no affine form.
            ///
            /// # Errors
            ///
            /// [`Error::InvalidKey`] for a coordinate that is not exactly
            /// the field size or a point that is not on the curve.
            pub(crate) fn verifying_key(x: &[u8], y: &[u8]) -> Result<VerifyingKey> {
                let (Ok(x), Ok(y)) = (<&FieldBytes>::try_from(x), <&FieldBytes>::try_from(y))
                else {
                    return Err(Error::InvalidKey(COORDINATE_LENGTH));
                };
                let point = Sec1Point::from_affine_coordinates(x, y, false);
                VerifyingKey::from_sec1_point(&point).map_err(|_| Error::InvalidKey(POINT_INVALID))
            }

            /// RFC 7518 §3.4 validation: the key first, then R‖S of exactly
            /// twice the field size with r and s in [1, n − 1]
            /// (`Signature::from_slice`, SEC 1 v2 §4.1.4 step 1), S
            /// normalized to low form (ADR 0026 §5), then ECDSA
            /// verification with the curve's hash.
            ///
            /// # Errors
            ///
            /// [`Error::InvalidKey`] from [`verifying_key`]; otherwise
            /// [`Error::InvalidSignature`].
            pub(crate) fn verify(
                x: &[u8],
                y: &[u8],
                signing_input: &[u8],
                signature: &[u8],
            ) -> Result<()> {
                let key = verifying_key(x, y)?;
                let signature =
                    Signature::from_slice(signature).map_err(|_| Error::InvalidSignature)?;
                key.verify(signing_input, &signature.normalize_s())
                    .map_err(|_| Error::InvalidSignature)
            }
        }
    };
}

curve_ops!(
    /// ES256: P-256 with SHA-256 (RFC 7518 §3.4).
    p256_ops,
    p256
);
curve_ops!(
    /// ES384: P-384 with SHA-384 (RFC 7518 §3.4).
    p384_ops,
    p384
);
curve_ops!(
    /// ES512: P-521 with SHA-512 (RFC 7518 §3.4).
    p521_ops,
    p521
);
curve_ops!(
    /// ES256K: secp256k1 with SHA-256 (RFC 8812 §3.2).
    k256_ops,
    k256
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::b64url_decode;

    use SigningAlg as A;

    fn jwk(json: &str) -> Jwk {
        Jwk::from_json(json.as_bytes()).unwrap()
    }

    fn b64(s: &str) -> Vec<u8> {
        b64url_decode(s).unwrap()
    }

    /// An `EC` JWK of `crv` with `x`, `y` and, if given, `d`.
    fn ec_jwk(crv: &str, x: &str, y: &str, d: Option<&str>) -> Jwk {
        let d = d.map(|d| format!(r#","d":"{d}""#)).unwrap_or_default();
        jwk(&format!(
            r#"{{"kty":"EC","crv":"{crv}","x":"{x}","y":"{y}"{d}}}"#
        ))
    }

    // RFC 7515 Appendix A.3: ES256.
    const A3_X: &str = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU";
    const A3_Y: &str = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0";
    const A3_D: &str = "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI";
    const A3_INPUT: &str = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
    const A3_SIG: &str =
        "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";

    // RFC 7515 Appendix A.4: ES512.
    const A4_X: &str =
        "AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk";
    const A4_Y: &str =
        "ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2";
    const A4_D: &str =
        "AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C";
    const A4_INPUT: &str = "eyJhbGciOiJFUzUxMiJ9.UGF5bG9hZA";
    const A4_SIG: &str = "AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZqwqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8KpEHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn";

    // RFC 7520 §3.2 (the P-521 private key, with its `kid` and `use`) and
    // §4.3 (ES512, Figure 27).
    const RFC7520_KEY: &str = r#"{"kty":"EC","kid":"bilbo.baggins@hobbiton.example","use":"sig","crv":"P-521","x":"AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt","y":"AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1","d":"AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zbKipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt"}"#;
    const RFC7520_INPUT: &str = "eyJhbGciOiJFUzUxMiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhbXBsZSJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4";
    const RFC7520_SIG: &str = "AE_R_YZCChjn4791jSQCrdPZCNYqHXCTZH0-JZGYNlaAjP2kqaluUIIUnC9qvbu9Plon7KRTzoNEuT4Va2cmL1eJAQy3mtPBu_u_sDDyYjnAMDxXPn7XrT0lw-kvAD890jl8e2puQens_IEKBpHABlsbEPX6sFY8OcGDqoRuBomu9xQ2";

    fn a3_public() -> Jwk {
        ec_jwk("P-256", A3_X, A3_Y, None)
    }

    fn a4_public() -> Jwk {
        ec_jwk("P-521", A4_X, A4_Y, None)
    }

    /// (alg, public key, signing input, signature) of every RFC example.
    fn rfc_vectors() -> Vec<(SigningAlg, Jwk, &'static str, Vec<u8>)> {
        vec![
            (A::ES256, a3_public(), A3_INPUT, b64(A3_SIG)),
            (A::ES512, a4_public(), A4_INPUT, b64(A4_SIG)),
            (A::ES512, jwk(RFC7520_KEY), RFC7520_INPUT, b64(RFC7520_SIG)),
        ]
    }

    #[test]
    fn rfc7515_a3_es256_verifies() {
        let sig = b64(A3_SIG);
        assert_eq!(sig.len(), 64);
        assert_eq!(
            verify(&A::ES256, &a3_public(), A3_INPUT.as_bytes(), &sig),
            Ok(())
        );
    }

    #[test]
    fn rfc7515_a3_is_a_high_s_signature_and_its_twin_verifies_too() {
        // A.3's S starts 0xC5, above n/2: the RFC's own example only
        // verifies because S is normalized first (ADR 0026 §5). Its low-S
        // twin (n - s) is valid as well.
        let sig = p256::ecdsa::Signature::from_slice(&b64(A3_SIG)).unwrap();
        let low = sig.normalize_s();
        assert_ne!(low, sig, "A.3 is expected to be high-S");
        let low = low.to_bytes().to_vec();
        assert_eq!(
            verify(&A::ES256, &a3_public(), A3_INPUT.as_bytes(), &low),
            Ok(())
        );
    }

    #[test]
    fn rfc7515_a4_es512_verifies() {
        let sig = b64(A4_SIG);
        assert_eq!(sig.len(), 132);
        assert_eq!(
            verify(&A::ES512, &a4_public(), A4_INPUT.as_bytes(), &sig),
            Ok(())
        );
    }

    #[test]
    fn rfc7520_4_3_es512_verifies_with_the_3_2_key() {
        let sig = b64(RFC7520_SIG);
        assert_eq!(sig.len(), 132);
        let key = jwk(RFC7520_KEY);
        assert_eq!(
            verify(&A::ES512, &key, RFC7520_INPUT.as_bytes(), &sig),
            Ok(())
        );
        // The public part alone verifies the same way.
        let public = key.to_public().unwrap();
        assert_eq!(
            verify(&A::ES512, &public, RFC7520_INPUT.as_bytes(), &sig),
            Ok(())
        );
    }

    #[test]
    fn a3_any_one_bit_flip_of_the_signature_fails() {
        // RFC 7515 §5.2 step 8: every bit of R‖S matters.
        let key = a3_public();
        let sig = b64(A3_SIG);
        for bit in 0..sig.len() * 8 {
            let mut flipped = sig.clone();
            flipped[bit / 8] ^= 1 << (bit % 8);
            assert_eq!(
                verify(&A::ES256, &key, A3_INPUT.as_bytes(), &flipped),
                Err(Error::InvalidSignature),
                "bit {bit}"
            );
        }
    }

    #[test]
    fn rfc_vectors_reject_a_flipped_bit_in_signature_or_input() {
        for (alg, key, input, sig) in rfc_vectors() {
            let n = sig.len();
            // The first, last and middle bits of R and of S.
            for bit in [0, 7, n * 2, n * 4 - 1, n * 4, n * 6, n * 8 - 1] {
                let mut flipped = sig.clone();
                flipped[bit / 8] ^= 1 << (bit % 8);
                assert_eq!(
                    verify(&alg, &key, input.as_bytes(), &flipped),
                    Err(Error::InvalidSignature),
                    "{alg} signature bit {bit}"
                );
            }
            for at in [0, input.len() / 2, input.len() - 1] {
                let mut tampered = input.as_bytes().to_vec();
                tampered[at] ^= 1;
                assert_eq!(
                    verify(&alg, &key, &tampered, &sig),
                    Err(Error::InvalidSignature),
                    "{alg} input byte {at}"
                );
            }
        }
    }

    /// The ASN.1 DER `ECDSA-Sig-Value` (RFC 3279 §2.2.3) of an R‖S
    /// signature of one-byte-length form: what a non-JOSE signer emits.
    fn der(rs: &[u8]) -> Vec<u8> {
        let (r, s) = rs.split_at(rs.len() / 2);
        let int = |v: &[u8]| {
            let v: Vec<u8> = v.iter().copied().skip_while(|&b| b == 0).collect();
            let mut out = vec![0x02];
            let pad = v.first().is_some_and(|&b| b >= 0x80);
            out.push(u8::try_from(v.len() + usize::from(pad)).unwrap());
            if pad {
                out.push(0);
            }
            out.extend(v);
            out
        };
        let body = [int(r), int(s)].concat();
        [vec![0x30, u8::try_from(body.len()).unwrap()], body].concat()
    }

    #[test]
    fn verify_requires_the_exact_r_s_length_and_never_accepts_der() {
        // RFC 7518 §3.4: "If the JWS Signature value is not a 64-octet
        // sequence, the validation has failed" (132 for ES512).
        for (alg, key, input, sig) in rfc_vectors() {
            let n = sig.len();
            let mut long = sig.clone();
            long.push(0);
            let mut zero_prefixed = vec![0];
            zero_prefixed.extend(&sig);
            let wrong = [
                Vec::new(),
                sig[..n - 1].to_vec(),
                long,
                zero_prefixed,
                [sig.clone(), sig.clone()].concat(),
                sig[..n / 2].to_vec(),
            ];
            for bad in &wrong {
                assert_eq!(
                    verify(&alg, &key, input.as_bytes(), bad),
                    Err(Error::InvalidSignature),
                    "{alg}: {} octets",
                    bad.len()
                );
            }
        }
        let der = der(&b64(A3_SIG));
        assert_eq!(der.len(), 71);
        assert_eq!(
            verify(&A::ES256, &a3_public(), A3_INPUT.as_bytes(), &der),
            Err(Error::InvalidSignature)
        );
    }

    #[test]
    fn verify_rejects_zero_r_or_s() {
        // CVE-2022-21449: (r, s) = (0, 0) verified any message in some JDKs.
        // SEC 1 v2 §4.1.4 step 1: r and s must be in [1, n - 1].
        for (alg, key, input, sig) in rfc_vectors() {
            let half = sig.len() / 2;
            let zero_r = [vec![0; half], sig[half..].to_vec()].concat();
            let zero_s = [sig[..half].to_vec(), vec![0; half]].concat();
            for bad in [vec![0; sig.len()], zero_r, zero_s] {
                assert_eq!(
                    verify(&alg, &key, input.as_bytes(), &bad),
                    Err(Error::InvalidSignature),
                    "{alg}"
                );
            }
        }
    }

    #[test]
    fn verify_rejects_r_or_s_not_below_the_group_order() {
        // SEC 1 v2 §4.1.4 step 1. P-256 n (SEC 2 v2 §2.4.2).
        let n = hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
        let sig = b64(A3_SIG);
        let all_ones = vec![0xff; 32];
        for bad in [
            [n.clone(), sig[32..].to_vec()].concat(),
            [sig[..32].to_vec(), n.clone()].concat(),
            [all_ones.clone(), all_ones].concat(),
        ] {
            assert_eq!(
                verify(&A::ES256, &a3_public(), A3_INPUT.as_bytes(), &bad),
                Err(Error::InvalidSignature)
            );
        }
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn public_point_is_checked_at_use() {
        // Import already rejects these (ADR 0041 §4); the family checks
        // again where it builds the key (defence in depth, ADR 0007).
        let (x, y) = (b64(A3_X), b64(A3_Y));
        let mut y_off = y.clone();
        y_off[31] ^= 1;
        let point_error =
            |r: Result<p256::ecdsa::VerifyingKey>| r.map(|_| ()).map_err(|e| e.code());
        assert_eq!(point_error(p256_ops::verifying_key(&x, &y)), Ok(()));
        assert_eq!(
            point_error(p256_ops::verifying_key(&x, &y_off)),
            Err("InvalidKey")
        );
        // The identity has no affine form; (0, 0) is the usual attempt.
        assert_eq!(
            point_error(p256_ops::verifying_key(&[0; 32], &[0; 32])),
            Err("InvalidKey")
        );
        assert_eq!(
            point_error(p256_ops::verifying_key(&x[1..], &y)),
            Err("InvalidKey")
        );
        assert!(p384_ops::verifying_key(&[0; 48], &[0; 48]).is_err());
        assert!(p521_ops::verifying_key(&[0; 66], &[0; 66]).is_err());
        assert!(k256_ops::verifying_key(&[0; 32], &[0; 32]).is_err());
        let (x, mut y) = (b64(A4_X), b64(A4_Y));
        y[65] ^= 1;
        assert!(p521_ops::verifying_key(&x, &y).is_err());
        // An off-curve key fails as InvalidKey before the signature is
        // looked at (ADR 0026 §2: step 8 before step 9).
        assert_eq!(
            p256_ops::verify(&b64(A3_X), &y_off, A3_INPUT.as_bytes(), b"not a signature")
                .map_err(|e| e.code()),
            Err("InvalidKey")
        );
    }

    #[test]
    fn a_key_of_another_curve_or_family_is_refused_not_used() {
        // bind_key rules these out (ADR 0026 §2 step 8); the family still
        // refuses them rather than using the wrong curve or panicking.
        let sig = b64(A3_SIG);
        let input = A3_INPUT.as_bytes();
        let oct = crate::jws::alg::test_keys::oct(32, "");
        let cases = [
            (A::ES384, a3_public()),
            (A::ES256K, a3_public()),
            (A::ES256, a4_public()),
            (A::ES256, oct),
            (A::HS256, a3_public()),
        ];
        for (alg, key) in &cases {
            assert_eq!(
                verify(alg, key, input, &sig),
                Err(Error::KeyAlgorithmMismatch),
                "{alg}"
            );
        }
    }

    use crate::rng::insecure_test_vectors::FixedRng;

    const ALL: [SigningAlg; 4] = [A::ES256, A::ES384, A::ES512, A::ES256K];

    /// R‖S length per `alg` (RFC 7518 §3.4, RFC 8812 §3.2).
    fn signature_len(alg: &SigningAlg) -> usize {
        match alg {
            A::ES256 | A::ES256K => 64,
            A::ES384 => 96,
            _ => 132,
        }
    }

    /// A JWK for a private scalar `d`, with (`x`, `y`) = d·G computed by
    /// the curve crate.
    fn derived_jwk(crv: &str, d: &[u8], xy: (Vec<u8>, Vec<u8>)) -> Jwk {
        let e = crate::util::b64url_encode;
        ec_jwk(crv, &e(&xy.0), &e(&xy.1), Some(&e(d)))
    }

    /// A private key per `alg`: the RFC 7515 A.3 (P-256) and A.4 (P-521)
    /// keys, and keys derived from fixed scalars for P-384 and secp256k1,
    /// which have no published JWK.
    fn private_key(alg: &SigningAlg) -> Jwk {
        macro_rules! derived {
            ($krate:ident, $crv:literal, $d:expr) => {{
                use $krate::elliptic_curve::sec1::ToSec1Point;
                let d: &[u8] = $d;
                let public = $krate::SecretKey::from_slice(d).unwrap().public_key();
                let point = public.to_sec1_point(false);
                let xy = (point.x().unwrap().to_vec(), point.y().unwrap().to_vec());
                derived_jwk($crv, d, xy)
            }};
        }
        match alg {
            A::ES256 => ec_jwk("P-256", A3_X, A3_Y, Some(A3_D)),
            A::ES512 => ec_jwk("P-521", A4_X, A4_Y, Some(A4_D)),
            A::ES384 => derived!(p384, "P-384", &[0x38; 48]),
            _ => derived!(k256, "secp256k1", &[0x6b; 32]),
        }
    }

    /// Whether `sig` is in low-S form, and its high-S twin (r, n − s),
    /// built with the curve crate's own scalar arithmetic.
    fn low_s_and_twin(alg: &SigningAlg, sig: &[u8]) -> (bool, Vec<u8>) {
        macro_rules! twin {
            ($krate:ident) => {{
                use $krate::elliptic_curve::ff::PrimeField;
                let sig = $krate::ecdsa::Signature::from_slice(sig).unwrap();
                let (r, s) = sig.split_scalars();
                let twin =
                    $krate::ecdsa::Signature::from_scalars(r.to_repr(), (-*s).to_repr()).unwrap();
                (sig.normalize_s() == sig, twin.to_bytes().to_vec())
            }};
        }
        match alg {
            A::ES256 => twin!(p256),
            A::ES384 => twin!(p384),
            A::ES512 => twin!(p521),
            _ => twin!(k256),
        }
    }

    #[test]
    fn rfc_private_keys_sign_what_their_public_keys_verify() {
        for (alg, key) in [
            (A::ES256, private_key(&A::ES256)),
            (A::ES512, private_key(&A::ES512)),
            (A::ES512, jwk(RFC7520_KEY)),
        ] {
            let sig = sign(&alg, &key, b"RFC 7515 \xc2\xa75.1").unwrap();
            assert_eq!(sig.len(), signature_len(&alg));
            let public = key.to_public().unwrap();
            assert_eq!(verify(&alg, &public, b"RFC 7515 \xc2\xa75.1", &sig), Ok(()));
            assert_eq!(
                verify(&alg, &public, b"RFC 7515 \xc2\xa75.2", &sig),
                Err(Error::InvalidSignature)
            );
        }
    }

    #[test]
    fn two_hundred_signatures_per_curve_are_low_s_and_verify_in_both_forms() {
        // ADR 0026 §5: emit low-S on every curve (k256 does by itself,
        // P-256/384/521 are normalized), and accept the high-S twin.
        for alg in &ALL {
            let key = private_key(alg);
            let public = key.to_public().unwrap();
            let mut seen = std::collections::BTreeSet::new();
            for i in 0u32..200 {
                let input = format!("eyJhbGciOiJFUzI1NiJ9.{i}");
                let sig = sign(alg, &key, input.as_bytes()).unwrap();
                assert_eq!(sig.len(), signature_len(alg), "{alg} #{i}");
                let (low, twin) = low_s_and_twin(alg, &sig);
                assert!(low, "{alg} #{i}: high-S emitted");
                assert_ne!(twin, sig);
                assert_eq!(
                    verify(alg, &public, input.as_bytes(), &sig),
                    Ok(()),
                    "{alg} #{i}"
                );
                assert_eq!(
                    verify(alg, &public, input.as_bytes(), &twin),
                    Ok(()),
                    "{alg} #{i} twin"
                );
                assert!(seen.insert(sig), "{alg} #{i}: repeated signature");
            }
        }
    }

    #[test]
    fn signing_is_hedged_not_deterministic() {
        // ADR 0005: try_sign_with_rng mixes fresh randomness into the
        // RFC 6979 nonce, so the same message signs differently each time
        // (deterministic Signer::sign would repeat; 2^-256 odds otherwise).
        for alg in &ALL {
            let key = private_key(alg);
            let a = sign(alg, &key, b"same input").unwrap();
            let b = sign(alg, &key, b"same input").unwrap();
            assert_ne!(a, b, "{alg}");
        }
    }

    #[test]
    fn signing_draws_exactly_one_field_element_of_entropy() {
        // The added entropy is one field element (RFC 6979 §3.6's k'),
        // taken from the adapter passed in: the same bytes give the same
        // signature, other bytes another, and too few bytes fail closed.
        for alg in &ALL {
            let key = private_key(alg);
            let len = signature_len(alg) / 2;
            let sign_fixed = |bytes: Vec<u8>| {
                let mut fixed = FixedRng::new(bytes);
                let sig = sign_with_rng(
                    alg,
                    &key,
                    b"input",
                    &mut CryptoRngAdapter::fixed(&mut fixed),
                );
                (sig, fixed.remaining())
            };
            let (a, left) = sign_fixed(vec![1; len]);
            assert_eq!(left, 0, "{alg}");
            let a = a.unwrap();
            assert_eq!(sign_fixed(vec![1; len]).0.as_ref(), Ok(&a), "{alg}");
            assert_ne!(sign_fixed(vec![2; len]).0.as_ref(), Ok(&a), "{alg}");
            assert_eq!(
                sign_fixed(vec![1; len - 1]).0,
                Err(Error::RandomnessUnavailable),
                "{alg}"
            );
            let public = key.to_public().unwrap();
            assert_eq!(verify(alg, &public, b"input", &a), Ok(()));
        }
    }

    #[test]
    fn a_getrandom_failure_is_randomness_unavailable_on_every_curve() {
        // ADR 0005: fail closed, with no signature, through rng.rs's
        // fail_closed injection point.
        let injected = [
            getrandom::Error::UNSUPPORTED,
            getrandom::Error::UNEXPECTED,
            getrandom::Error::new_custom(7),
        ];
        for alg in &ALL {
            let key = private_key(alg);
            for e in injected {
                assert_eq!(
                    sign_with_rng(alg, &key, b"input", &mut CryptoRngAdapter::failing(e)),
                    Err(Error::RandomnessUnavailable),
                    "{alg} {e:?}"
                );
            }
        }
    }

    #[test]
    fn private_scalar_is_checked_at_use() {
        // RFC 7518 §6.2.2.1: d is exactly ceil(log2(n)/8) octets. A short
        // d must not be zero-padded into another key (SecretKey::from_slice
        // would pad it), so the length is checked first. Import already
        // rejects these (ADR 0041 §4); the family checks again.
        let code = |r: Result<()>| r.map_err(|e| e.code());
        let d = b64(A3_D);
        let n = hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
        assert_eq!(code(p256_ops::signing_key(&d).map(|_| ())), Ok(()));
        for bad in [
            d[1..].to_vec(),
            [vec![0], d.clone()].concat(),
            vec![0; 32],
            n,
        ] {
            assert_eq!(
                code(p256_ops::signing_key(&bad).map(|_| ())),
                Err("InvalidKey"),
                "{} octets",
                bad.len()
            );
        }
        let d = b64(A4_D);
        assert!(p521_ops::signing_key(&d).is_ok());
        assert!(p521_ops::signing_key(&d[1..]).is_err());
        assert!(p384_ops::signing_key(&[0x38; 47]).is_err());
        assert!(k256_ops::signing_key(&[0x6b; 31]).is_err());
        assert!(k256_ops::signing_key(&[0; 32]).is_err());
    }

    #[test]
    fn signing_refuses_a_key_of_another_curve_family_or_without_d() {
        // bind_key rules these out (ADR 0026 §2 step 8); the family never
        // signs with the wrong curve or panics.
        let cases = [
            (A::ES384, private_key(&A::ES256)),
            (A::ES256K, private_key(&A::ES256)),
            (A::ES256, private_key(&A::ES256).to_public().unwrap()),
            (A::ES256, crate::jws::alg::test_keys::oct(32, "")),
            (A::HS256, private_key(&A::ES256)),
        ];
        for (alg, key) in &cases {
            assert_eq!(
                sign(alg, key, b"x"),
                Err(Error::KeyAlgorithmMismatch),
                "{alg}"
            );
        }
    }
}
