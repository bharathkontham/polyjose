//! ECDH on P-256, P-384 and P-521 for ECDH-ES (RFC 7518 §4.6), on the
//! `ecdh` feature of the pinned curve crates.
//!
//! - [`generate`] makes the ephemeral key pair of one agreement through the
//!   crate's one EC sampler (`keys::generate::generate_ec_secret`).
//! - [`agree`] computes Z, the x-coordinate of the shared point.
//!
//! Neither decodes a peer key: the `epk` is validated and decoded by
//! `ecdh_es` (JWK import, then the curve check) before [`agree`] can be
//! reached, so a `PublicKey` here is always on the curve and never the
//! identity (RFC 8725 §3.4, SP 800-56A r3 §5.6.2.3.4).
//!
//! The functions are generic over the curve, so `C` is `p256::NistP256`,
//! `p384::NistP384` or `p521::NistP521`.

use p256::elliptic_curve::{CurveArithmetic, NonZeroScalar, PublicKey, SecretKey, ecdh};
use zeroize::{Zeroize, Zeroizing};

use super::random::RandomSource;
use crate::Result;
use crate::keys::generate::generate_ec_secret;

/// A fresh ephemeral key pair (RFC 7518 §4.6.1: "a new ephemeral public
/// key value MUST be generated for each key agreement operation").
///
/// The private scalar d ∈ [1, n − 1] (SEC 1 v2 §3.2.1) comes from the
/// crate's one EC sampler, `keys::generate::generate_ec_secret` (rejection
/// sampling with `NonZeroScalar`), drawing from `rng` through
/// [`RandomSource::crypto_rng`]. Each attempt consumes the field size in
/// bytes (32, 48 or 66), so a `FixedRng` vector supplies the d it wants
/// as exactly those big-endian bytes. The public key is Q = d·G.
///
/// # Errors
///
/// [`crate::Error::RandomnessUnavailable`] if `rng` fails; no key is
/// returned (ADR 0005).
pub(crate) fn generate<C: CurveArithmetic>(
    rng: &mut dyn RandomSource,
) -> Result<(SecretKey<C>, PublicKey<C>)> {
    let secret = generate_ec_secret::<C, _>(&mut rng.crypto_rng())?;
    let public = secret.public_key();
    Ok((secret, public))
}

/// The ECDH shared secret Z of `secret` and `public`: the x-coordinate of
/// the shared point d·Q, as a big-endian field element of the full field
/// length (RFC 7518 §4.6.2: Z is "the output of the key agreement";
/// SP 800-56A r3 §5.7.1.2, the ECC CDH primitive, with cofactor 1).
///
/// `public` is a `PublicKey`, so it has already passed SP 800-56A r3
/// §5.6.2.3.4 partial public-key validation (on the curve, not the
/// identity) where it was decoded (RFC 8725 §3.4): the curve crate builds
/// one only from a validated point. NIST prime curves have cofactor 1, so
/// d·Q is never the identity for d ∈ [1, n − 1].
///
/// Ticks `test_counters::ecdh_agreements` (test builds only) once per
/// agreement, so tests can prove an invalid `epk` never reaches here.
///
/// # Errors
///
/// None in practice; the `Result` keeps the signature of
/// `ecdh_x25519::agree`. JWE decrypt maps any error to `DecryptionFailed`.
pub(crate) fn agree<C: CurveArithmetic>(
    secret: &SecretKey<C>,
    public: &PublicKey<C>,
) -> Result<Zeroizing<Vec<u8>>> {
    #[cfg(test)]
    crate::test_counters::ecdh_agreements::tick();
    let mut scalar = secret.to_nonzero_scalar();
    // `SharedSecret` wipes itself on drop; the copy of Z is `Zeroizing`.
    // Borrowed, not copied, so the one copy of the scalar is wiped below.
    let borrowed: &NonZeroScalar<C> = &scalar;
    let shared = ecdh::diffie_hellman(borrowed, public.as_affine());
    // NonZeroScalar does not wipe itself on drop.
    scalar.zeroize();
    Ok(Zeroizing::new(shared.raw_secret_bytes().to_vec()))
}

#[cfg(test)]
mod tests {
    use p256::elliptic_curve::sec1::ToSec1Point;
    use p256::elliptic_curve::{FieldBytes, sec1::FromSec1Point};

    use super::*;
    use crate::Error;
    use crate::rng::insecure_test_vectors::FixedRng;
    use crate::test_counters::ecdh_agreements;
    use crate::util::b64url_decode;

    fn b64(text: &str) -> Vec<u8> {
        b64url_decode(text).unwrap_or_else(|e| panic!("{text}: {e}"))
    }

    /// The uncompressed SEC 1 point `04 ‖ x ‖ y` (SEC 1 v2 §2.3.3) of
    /// base64url JWK coordinates (RFC 7518 §6.2.1.2–§6.2.1.3).
    fn public<C>(x: &str, y: &str) -> PublicKey<C>
    where
        C: CurveArithmetic,
        C::AffinePoint: FromSec1Point<C> + ToSec1Point<C>,
        p256::elliptic_curve::FieldBytesSize<C>: p256::elliptic_curve::sec1::ModulusSize,
    {
        let point = [vec![0x04], b64(x), b64(y)].concat();
        PublicKey::<C>::from_sec1_bytes(&point).unwrap_or_else(|e| panic!("{e}"))
    }

    fn secret<C: CurveArithmetic>(d: &str) -> SecretKey<C> {
        let d = b64(d);
        let d = <&FieldBytes<C>>::try_from(d.as_slice()).unwrap_or_else(|e| panic!("{e}"));
        SecretKey::<C>::from_bytes(d).unwrap_or_else(|e| panic!("{e}"))
    }

    fn xy<C>(public: &PublicKey<C>) -> (Vec<u8>, Vec<u8>)
    where
        C: CurveArithmetic,
        C::AffinePoint: FromSec1Point<C> + ToSec1Point<C>,
        p256::elliptic_curve::FieldBytesSize<C>: p256::elliptic_curve::sec1::ModulusSize,
    {
        let point = public.to_sec1_point(false);
        let (Some(x), Some(y)) = (point.x(), point.y()) else {
            panic!("identity");
        };
        (x.to_vec(), y.to_vec())
    }

    /// RFC 7520 §5.4.3 (Figure 108): the P-384 ephemeral key of §5.4.
    mod c54 {
        pub(super) const D: &str =
            "D5H4Y_5PSKZvhfVFbcCYJOtcGZygRgfZkpsBr59Icmmhe9sW6nkZ8WfwhinUfWJg";
        pub(super) const X: &str =
            "uBo4kHPw6kbjx5l0xowrd_oYzBmaz-GKFZu4xAFFkbYiWgutEK6iuEDsQ6wNdNg3";
        pub(super) const Y: &str =
            "sp3p5SGhZVC2faXumI-e9JU2Mo8KpoYrFDr5yPNVtW4PgEwZOyQTA-JdaY8tb7E0";
    }

    /// RFC 7520 §5.5.3 (Figure 120): the P-256 ephemeral key of §5.5.
    mod c55 {
        pub(super) const D: &str = "AtH35vJsQ9SGjYfOsjUxYXQKrPH3FjZHmEtSKoSN8cM";
        pub(super) const X: &str = "mPUKT_bAWGHIhg0TpjjqVsP1rXWQu_vwVOHHtNkdYoA";
        pub(super) const Y: &str = "8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs";
    }

    /// RFC 7518 Appendix C: Alice's ephemeral and Bob's static P-256 keys,
    /// and their shared secret Z.
    mod app_c {
        pub(super) const ALICE_D: &str = "0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo";
        pub(super) const ALICE_X: &str = "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0";
        pub(super) const ALICE_Y: &str = "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps";
        pub(super) const BOB_D: &str = "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw";
        pub(super) const BOB_X: &str = "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ";
        pub(super) const BOB_Y: &str = "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck";
        pub(super) const Z: [u8; 32] = [
            158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132, 38, 156, 251, 49,
            110, 163, 218, 128, 106, 72, 246, 218, 167, 121, 140, 254, 144, 196,
        ];
    }

    type Pair<C> = (SecretKey<C>, PublicKey<C>);

    /// `generate` over a `FixedRng` holding exactly `bytes`; the key pair
    /// and the number of bytes left.
    fn generate_from<C: CurveArithmetic>(bytes: &[u8]) -> (Result<Pair<C>>, usize) {
        let mut fixed = FixedRng::new(bytes);
        let pair = generate::<C>(&mut fixed);
        (pair, fixed.remaining())
    }

    #[test]
    fn rfc7520_ephemeral_d_values_are_accepted_on_the_first_draw() {
        // RFC 7520 §5.4.3 and §5.5.3 print the ephemeral keys. The
        // generator draws field-size big-endian bytes per attempt (SEC 1 v2
        // §2.3.7) and redraws only on 0 or ≥ n, so a FixedRng holding just
        // the printed d (48 bytes for P-384, 32 for P-256) is consumed in
        // one draw, and the derived public key is the printed epk.
        let (pair, left) = generate_from::<p384::NistP384>(&b64(c54::D));
        let (secret, public) = pair.unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(left, 0);
        assert_eq!(secret.to_bytes().to_vec(), b64(c54::D));
        assert_eq!(xy(&public), (b64(c54::X), b64(c54::Y)));

        let (pair, left) = generate_from::<p256::NistP256>(&b64(c55::D));
        let (secret, public) = pair.unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(left, 0);
        assert_eq!(secret.to_bytes().to_vec(), b64(c55::D));
        assert_eq!(xy(&public), (b64(c55::X), b64(c55::Y)));
    }

    #[test]
    fn generate_rejection_samples_through_the_crate_generator() {
        // SEC 1 v2 §3.2.1: d ∈ [1, n − 1]. Zero and an all-0xFF draw
        // (above n) are redrawn; the third draw is the RFC 7520 §5.5 d.
        let mut bytes = vec![0u8; 32];
        bytes.extend([0xFFu8; 32]);
        bytes.extend(b64(c55::D));
        let (pair, left) = generate_from::<p256::NistP256>(&bytes);
        let (secret, _) = pair.unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(left, 0);
        assert_eq!(secret.to_bytes().to_vec(), b64(c55::D));
        // P-521: 66 bytes per draw (RFC 7518 §6.2.1.2: ⌈521/8⌉).
        let d521: Vec<u8> = (0..66u8).map(|i| if i == 0 { 1 } else { i }).collect();
        let (pair, left) = generate_from::<p521::NistP521>(&d521);
        let (secret, _) = pair.unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(left, 0);
        assert_eq!(secret.to_bytes().to_vec(), d521);
    }

    #[test]
    fn generate_fails_closed_when_the_rng_runs_out() {
        // ADR 0005: no key from a short source.
        let (pair, _) = generate_from::<p384::NistP384>(&[7u8; 47]);
        assert_eq!(pair.map(|_| ()), Err(Error::RandomnessUnavailable));
    }

    #[test]
    fn consecutive_os_generations_differ() {
        // RFC 7518 §4.6.1: a new ephemeral key for every agreement.
        let mut os = super::super::random::OsRandom;
        let a = generate::<p256::NistP256>(&mut os).unwrap_or_else(|e| panic!("{e}"));
        let b = generate::<p256::NistP256>(&mut os).unwrap_or_else(|e| panic!("{e}"));
        assert_ne!(a.0.to_bytes(), b.0.to_bytes());
        assert_ne!(xy(&a.1), xy(&b.1));
    }

    #[test]
    fn rfc7518_appendix_c_agreement_gives_z_both_ways() {
        // RFC 7518 Appendix C: Z from Alice's ephemeral d and Bob's public
        // key, and the same Z from Bob's d and Alice's public key (the
        // x-coordinate of the shared point, SP 800-56A §5.7.1.2).
        let alice = secret::<p256::NistP256>(app_c::ALICE_D);
        let bob = secret::<p256::NistP256>(app_c::BOB_D);
        let alice_public = public::<p256::NistP256>(app_c::ALICE_X, app_c::ALICE_Y);
        let bob_public = public::<p256::NistP256>(app_c::BOB_X, app_c::BOB_Y);
        assert_eq!(xy(&alice.public_key()), xy(&alice_public));
        let (z, ticks) = ecdh_agreements::count(|| agree(&alice, &bob_public));
        assert_eq!(z.unwrap_or_else(|e| panic!("{e}")).as_slice(), app_c::Z);
        assert_eq!(ticks, 1);
        let z = agree(&bob, &alice_public).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(z.as_slice(), app_c::Z);
    }

    #[test]
    fn z_has_the_full_field_length_on_every_curve() {
        // RFC 7518 §4.6.2 and SP 800-56A §5.7.1.2: Z is the x-coordinate
        // as a full-length field element (32, 48 and 66 octets), and both
        // parties compute the same value.
        fn check<C>(len: usize)
        where
            C: CurveArithmetic,
            C::AffinePoint: FromSec1Point<C> + ToSec1Point<C>,
            p256::elliptic_curve::FieldBytesSize<C>: p256::elliptic_curve::sec1::ModulusSize,
        {
            let mut os = super::super::random::OsRandom;
            let (a, a_pub) = generate::<C>(&mut os).unwrap_or_else(|e| panic!("{e}"));
            let (b, b_pub) = generate::<C>(&mut os).unwrap_or_else(|e| panic!("{e}"));
            let ab = agree(&a, &b_pub).unwrap_or_else(|e| panic!("{e}"));
            let ba = agree(&b, &a_pub).unwrap_or_else(|e| panic!("{e}"));
            assert_eq!(ab.len(), len);
            assert_eq!(*ab, *ba);
        }
        check::<p256::NistP256>(32);
        check::<p384::NistP384>(48);
        check::<p521::NistP521>(66);
    }

    /// Wycheproof ECDH on P-256, P-384 and P-521 through the JWE `epk`
    /// path (`ecdh_es::agree_with_epk`, the exact decrypt code): the
    /// `ecpoint` files (raw SEC 1 points) and the `webcrypto` files (JWK
    /// public keys).
    mod wycheproof_ecdh {
        use super::super::super::ecdh_es::agree_with_epk;
        use super::*;
        use crate::json::Object;
        use crate::jwa::{ContentEncAlg, KeyMgmtAlg};
        use crate::jwe::key::{Direction, RecipientKey};
        use crate::jwk::{EcCurve, Jwk};
        use crate::test_support::wycheproof::{self, Deviation, Outcome, Summary, Test};
        use crate::util::b64url_encode;

        /// The one `acceptable` case of each `ecpoint` file (tcId 2,
        /// `CompressedPublic`): polyjose rejects it, because a JWK cannot
        /// carry a compressed point.
        const ECPOINT: &[Deviation] = &[Deviation::tests(
            &[2],
            Outcome::Reject,
            "RFC 7518 §6.2.1: an EC JWK (and so an epk) has no compressed form; x and y are both required",
        )];

        /// The flags of the cases that must be rejected before any agreement
        /// (research.md §4.2, RFC 8725 §3.4).
        const NO_AGREEMENT: &[&str] = &[
            "InvalidCurveAttack",
            "WrongCurve",
            "InvalidEncoding",
            "CompressedPoint",
            "InvalidPublic",
        ];

        /// `key`'s private scalar as `RecipientKey`, from Wycheproof's
        /// big-endian integer (leading zeros stripped or added to the field
        /// length, RFC 7518 §6.2.2.1), or `None` if it is not in [1, n − 1].
        fn recipient(crv: EcCurve, private: &[u8]) -> Option<RecipientKey> {
            let len = crv.coordinate_len();
            let start = private
                .iter()
                .position(|&b| b != 0)
                .unwrap_or(private.len());
            let digits = &private[start..];
            if digits.len() > len {
                return None;
            }
            let mut d = vec![0u8; len - digits.len()];
            d.extend_from_slice(digits);
            match crv {
                EcCurve::P256 => SecretKey::<p256::NistP256>::from_slice(&d)
                    .ok()
                    .map(RecipientKey::P256Secret),
                EcCurve::P384 => SecretKey::<p384::NistP384>::from_slice(&d)
                    .ok()
                    .map(RecipientKey::P384Secret),
                EcCurve::P521 => SecretKey::<p521::NistP521>::from_slice(&d)
                    .ok()
                    .map(RecipientKey::P521Secret),
                EcCurve::Secp256k1 => None,
            }
        }

        /// The `epk` a JWE would carry for a raw SEC 1 `public` point, or
        /// `None` if JWK cannot express it: only the uncompressed form
        /// `04 ‖ x ‖ y` with full-length coordinates maps to `x` and `y`
        /// (RFC 7518 §6.2.1.2–§6.2.1.3, SEC 1 v2 §2.3.3).
        fn epk(crv: EcCurve, public: &[u8]) -> Option<Object> {
            let len = crv.coordinate_len();
            if public.len() != 1 + 2 * len || public[0] != 0x04 {
                return None;
            }
            let mut epk = Object::new();
            epk.insert("kty", "EC");
            epk.insert("crv", crv.as_str());
            epk.insert("x", b64url_encode(&public[1..=len]));
            epk.insert("y", b64url_encode(&public[1 + len..]));
            Some(epk)
        }

        /// Checks one test's result: an accepted case gives exactly the
        /// expected Z, and a case flagged as an attack never reaches the
        /// agreement.
        fn outcome(
            test: &Test,
            result: &Result<Zeroizing<Vec<u8>>>,
            shared: &[u8],
            agreements: u64,
        ) -> Outcome {
            let id = test.tc_id;
            if let Ok(z) = result {
                assert_eq!(z.as_slice(), shared, "tcId {id}: wrong shared secret");
            }
            if NO_AGREEMENT.iter().any(|flag| test.has_flag(flag)) {
                assert!(result.is_err(), "tcId {id}: attack case accepted");
                assert_eq!(agreements, 0, "tcId {id}: agreed before refusing");
            }
            Outcome::of(result)
        }

        fn ecpoint(name: &str, crv: EcCurve) -> Summary {
            let suite = wycheproof::load(name);
            wycheproof::assert_conforms(&suite, ECPOINT, |_, test| {
                let (public, private, shared) = test.agreement();
                let (result, agreements) = ecdh_agreements::count(|| {
                    let key = recipient(crv, private).ok_or(Error::InvalidKey("scalar"))?;
                    let epk = epk(crv, public).ok_or(Error::DecryptionFailed)?;
                    agree_with_epk(&key, &epk)
                });
                outcome(test, &result, shared, agreements)
            })
        }

        fn webcrypto(name: &str) -> Summary {
            let suite = wycheproof::load(name);
            wycheproof::assert_conforms(&suite, &[], |_, test| {
                let (public, private, shared) = test.jwk_agreement();
                // Our side: the private JWK, bound to ECDH-ES for decrypt
                // exactly as `decrypt_compact` binds it (RFC 7518 §4.6).
                let private = Jwk::from_json(private.as_bytes()).unwrap_or_else(|e| panic!("{e}"));
                let key = RecipientKey::from_jwk(
                    &private,
                    &KeyMgmtAlg::EcdhEs,
                    &ContentEncAlg::A128GCM,
                    Direction::Decrypt,
                )
                .unwrap_or_else(|e| panic!("tcId {}: {e}", test.tc_id));
                // The peer's public JWK, as the epk of a JWE header.
                let epk = crate::json::parse(public.as_bytes())
                    .ok()
                    .and_then(crate::json::Value::into_object)
                    .unwrap_or_else(|| panic!("tcId {}: public is not an object", test.tc_id));
                let (result, agreements) = ecdh_agreements::count(|| agree_with_epk(&key, &epk));
                outcome(test, &result, shared, agreements)
            })
        }

        fn summary(tests: usize, accepted: usize, deviations: usize) -> Summary {
            Summary {
                tests,
                accepted,
                rejected: tests - accepted,
                deviations,
            }
        }

        #[test]
        fn wycheproof_ecdh_ecpoint() {
            // Every `valid` case gives its Z; every `invalid` one (16
            // InvalidCurveAttack, the InvalidEncoding, the compressed
            // WrongCurve twist points and InvalidCompressedPublic) and the
            // `acceptable` compressed point are rejected, all of them before
            // any agreement.
            assert_eq!(
                ecpoint("ecdh_secp256r1_ecpoint", EcCurve::P256),
                summary(355, 330, 1)
            );
            assert_eq!(
                ecpoint("ecdh_secp384r1_ecpoint", EcCurve::P384),
                summary(790, 771, 1)
            );
            assert_eq!(
                ecpoint("ecdh_secp521r1_ecpoint", EcCurve::P521),
                summary(661, 632, 1)
            );
        }

        #[test]
        fn wycheproof_ecdh_webcrypto() {
            // The same agreements with JWK public keys, the closest form to
            // an `epk`: 16 InvalidCurveAttack, the WrongCurve keys (another
            // `crv`) and the InvalidPublic ones (modified point or group)
            // are rejected before any agreement.
            assert_eq!(webcrypto("ecdh_secp256r1_webcrypto"), summary(353, 330, 0));
            assert_eq!(webcrypto("ecdh_secp384r1_webcrypto"), summary(794, 771, 0));
            assert_eq!(webcrypto("ecdh_secp521r1_webcrypto"), summary(655, 632, 0));
        }
    }
}
