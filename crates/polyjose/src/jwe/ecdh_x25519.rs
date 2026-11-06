//! X25519 (RFC 7748) for ECDH-ES with OKP keys (RFC 8037 §3.2), on
//! `x25519-dalek`.
//!
//! - [`generate`] makes the ephemeral key pair of one ECDH-ES agreement
//!   (RFC 7518 §4.6) from 32 bytes of the [`RandomSource`] (RFC 7748 §6.1).
//! - [`agree`] computes the shared secret Z = X25519(secret, public)
//!   (RFC 7748 §5, §6.1) and rejects an all-zero Z.
//!
//! # Public-key handling (RFC 7748 §5, ADR 0043)
//!
//! Every 32-octet string is a valid X25519 public key. As RFC 7748 §5
//! requires, the most significant bit of the u-coordinate is masked and a
//! non-canonical value (at or above 2^255 - 19) is reduced mod p, and
//! points on the twist and points with a torsion component are accepted:
//! the clamped scalar (`decodeScalar25519`) clears the cofactor. The one
//! low-order defence is the all-zero shared-secret check of RFC 7748 §6.1,
//! done in constant time with `SharedSecret::was_contributory`; no
//! Ed25519-style mixed-order rejection applies here (ADR 0043).
//!
//! # Secrets
//!
//! `StaticSecret` and `SharedSecret` wipe themselves on drop (the
//! `zeroize` feature of the pinned `x25519-dalek`), the random bytes of
//! [`generate`] are held in a [`Zeroizing`] buffer, and Z is returned as a
//! [`Zeroizing`] array.

use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use super::random::RandomSource;
use crate::{Error, Result};

/// A fresh ephemeral key pair (RFC 7518 §4.6, RFC 8037 §3.2): exactly 32
/// bytes drawn from `rng` into `StaticSecret::from` (RFC 7748 §6.1: the
/// private key is 32 random bytes; clamping, §5 `decodeScalar25519`, is
/// done by the primitive), and its public key X25519(secret, 9).
///
/// `StaticSecret` rather than `EphemeralSecret`, because only it can be
/// built from bytes, which is how the [`RandomSource`] (and so the
/// `FixedRng` reproductions of RFC 8037 A.6) supplies the secret.
///
/// # Errors
///
/// [`Error::RandomnessUnavailable`] if `rng` fails.
pub(crate) fn generate(rng: &mut dyn RandomSource) -> Result<(StaticSecret, PublicKey)> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    rng.fill(bytes.as_mut_slice())?;
    let secret = StaticSecret::from(*bytes);
    let public = PublicKey::from(&secret);
    Ok((secret, public))
}

/// The X25519 shared secret Z of `secret` and `public` (RFC 7748 §6.1;
/// ECDH-ES uses it as the Concat KDF input Z, RFC 8037 §3.2, RFC 7518
/// §4.6.2).
///
/// An all-zero Z, which a low-order `public` produces, is rejected
/// (RFC 7748 §6.1 allows the check, RFC 8725 §3.4 asks for it). The test
/// is `SharedSecret::was_contributory`, a constant-time comparison with
/// the identity. Ticks `test_counters::ecdh_agreements` (test builds only)
/// once per agreement computed, the rejected ones included.
///
/// # Errors
///
/// [`Error::InvalidKey`] for an all-zero shared secret; JWE decrypt maps
/// it to `DecryptionFailed` (RFC 7516 §11.5).
pub(crate) fn agree(secret: &StaticSecret, public: &PublicKey) -> Result<Zeroizing<[u8; 32]>> {
    #[cfg(test)]
    crate::test_counters::ecdh_agreements::tick();
    let shared = secret.diffie_hellman(public);
    if !shared.was_contributory() {
        return Err(Error::InvalidKey("X25519 shared secret is all-zero"));
    }
    Ok(Zeroizing::new(shared.to_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::insecure_test_vectors::FixedRng;
    use crate::test_counters::ecdh_agreements;
    use crate::test_support::wycheproof::{self, Deviation, Outcome, Summary, Test};
    use crate::util::{b64url_decode, b64url_encode};

    /// 32 bytes from 64 lowercase hex digits (RFC 7748 §5.2, §6.1 print
    /// their vectors this way).
    fn hex32(text: &str) -> [u8; 32] {
        assert_eq!(text.len(), 64, "{text:?} is not 32 bytes of hex");
        let mut out = [0u8; 32];
        for (byte, pair) in out.iter_mut().zip(text.as_bytes().chunks(2)) {
            let pair = core::str::from_utf8(pair).unwrap();
            *byte = u8::from_str_radix(pair, 16).unwrap();
        }
        out
    }

    fn b64_32(text: &str) -> [u8; 32] {
        b64url_decode(text).unwrap().try_into().unwrap()
    }

    /// `agree` on raw scalar and u-coordinate bytes: the X25519 function of
    /// RFC 7748 §5 (`StaticSecret::from` keeps the bytes, and dalek clamps
    /// them in the multiplication, §5 `decodeScalar25519`).
    fn x25519(k: [u8; 32], u: [u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
        agree(&StaticSecret::from(k), &PublicKey::from(u))
    }

    // RFC 7748 §6.1, the Alice and Bob example.
    const ALICE_PRIVATE: &str = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
    const ALICE_PUBLIC: &str = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
    const BOB_PRIVATE: &str = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
    const BOB_PUBLIC: &str = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
    const SHARED_K: &str = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

    #[test]
    fn rfc7748_section_5_2_x25519_function_vectors() {
        // RFC 7748 §5.2, the two single-call test vectors.
        let vectors = [
            (
                "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
                "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
                "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
            ),
            (
                "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
                "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
                "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
            ),
        ];
        for (scalar, u, out) in vectors {
            assert_eq!(*x25519(hex32(scalar), hex32(u)).unwrap(), hex32(out));
        }
    }

    #[test]
    fn rfc7748_section_5_2_iterated_vectors() {
        // RFC 7748 §5.2: k = u = 9; then k, u = X25519(k, u), k. The
        // 1,000,000-iteration value is left out of the fast suite (ADR 0009:
        // no slow tests there); 1 and 1,000 iterations exercise the same
        // chaining.
        let mut k = [0u8; 32];
        k[0] = 9;
        let mut u = k;
        let mut step = || {
            let out = *x25519(k, u).unwrap();
            u = k;
            k = out;
            k
        };
        assert_eq!(
            step(),
            hex32("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079")
        );
        for _ in 1..999 {
            step();
        }
        assert_eq!(
            step(),
            hex32("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51")
        );
    }

    #[test]
    fn rfc7748_section_6_1_alice_and_bob() {
        // RFC 7748 §6.1: each side's public key is X25519(private, 9), and
        // both sides compute the same K.
        let mut rng = FixedRng::new([hex32(ALICE_PRIVATE), hex32(BOB_PRIVATE)].concat());
        let (alice, alice_public) = generate(&mut rng).unwrap();
        let (bob, bob_public) = generate(&mut rng).unwrap();
        assert_eq!(alice_public.to_bytes(), hex32(ALICE_PUBLIC));
        assert_eq!(bob_public.to_bytes(), hex32(BOB_PUBLIC));
        assert_eq!(*agree(&alice, &bob_public).unwrap(), hex32(SHARED_K));
        assert_eq!(*agree(&bob, &alice_public).unwrap(), hex32(SHARED_K));
    }

    #[test]
    fn rfc8037_appendix_a_6_ecdh_es_with_x25519() {
        // RFC 8037 A.6: Bob's static key is the recipient; the sender's
        // ephemeral secret is injected through the RandomSource.
        let bob_public = PublicKey::from(b64_32("3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08"));
        let mut rng = FixedRng::new(b64_32("dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo"));
        let (ephemeral, epk) = generate(&mut rng).unwrap();
        assert_eq!(
            b64url_encode(epk.as_bytes()),
            "hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo"
        );
        let z = hex32(SHARED_K);
        // Sender side: the ephemeral secret with Bob's public key.
        assert_eq!(*agree(&ephemeral, &bob_public).unwrap(), z);
        // Receiver side: Bob's private key (RFC 7748 §6.1) with the `epk`.
        let bob = StaticSecret::from(hex32(BOB_PRIVATE));
        assert_eq!(PublicKey::from(&bob), bob_public);
        assert_eq!(*agree(&bob, &epk).unwrap(), z);
    }

    #[test]
    fn generate_draws_exactly_32_bytes() {
        // RFC 7748 §6.1 / RFC 8037 §3.2: the secret is 32 random bytes; the
        // draw order (`jwe::random`) relies on exactly 32 being consumed.
        let mut rng = FixedRng::new([0x42u8; 33]);
        let (secret, public) = generate(&mut rng).unwrap();
        assert_eq!(rng.remaining(), 1);
        assert_eq!(secret.to_bytes(), [0x42u8; 32]);
        assert_eq!(public, PublicKey::from(&secret));
    }

    #[test]
    fn generate_fails_closed_without_randomness() {
        // ADR 0005: a source that cannot supply 32 bytes is an error, never
        // a weak key.
        let mut rng = FixedRng::new([0u8; 31]);
        assert!(matches!(
            generate(&mut rng),
            Err(Error::RandomnessUnavailable)
        ));
    }

    #[test]
    fn every_agreement_ticks_the_counter_once() {
        // test_counters::ecdh_agreements counts computed agreements, the
        // rejected all-zero one included (T13 asserts an invalid `epk` is
        // rejected before reaching here).
        let alice = StaticSecret::from(hex32(ALICE_PRIVATE));
        let (ok, n) = ecdh_agreements::count(|| agree(&alice, &PublicKey::from(hex32(BOB_PUBLIC))));
        assert!(ok.is_ok());
        assert_eq!(n, 1);
        let (zero, n) = ecdh_agreements::count(|| agree(&alice, &PublicKey::from([0u8; 32])));
        assert!(zero.is_err());
        assert_eq!(n, 1);
    }

    /// Why polyjose picks a side on Wycheproof's `acceptable` X25519 tests.
    /// `x25519_test.json` and `x25519_jwk_test.json` number the same cases
    /// 1..=518 identically, so one list serves both.
    const ZERO_SHARED: &str = "RFC 7748 §6.1: an all-zero shared secret (a low-order public \
        key) is rejected, as RFC 8725 §3.4 asks for ECDH-ES";
    const SPECIAL_PUBLIC: &str = "RFC 7748 §5: every 32-octet public key is accepted: the top \
        bit is masked, a non-canonical u is reduced mod p, twist and torsion points go through \
        the clamped ladder (ADR 0043)";
    const XDH: &[Deviation] = &[
        // `LowOrderPublic` / `ZeroSharedSecret`.
        Deviation::range(32, 33, Outcome::Reject, ZERO_SHARED),
        Deviation::range(63, 86, Outcome::Reject, ZERO_SHARED),
        Deviation::range(117, 118, Outcome::Reject, ZERO_SHARED),
        Deviation::tests(&[154, 165, 166], Outcome::Reject, ZERO_SHARED),
        // `Twist`, `NonCanonicalPublic`, `SpecialPublicKey` and the other
        // acceptable cases with a non-zero shared secret.
        Deviation::range(2, 31, Outcome::Accept, SPECIAL_PUBLIC),
        Deviation::range(87, 99, Outcome::Accept, SPECIAL_PUBLIC),
        Deviation::tests(
            &[
                101, 103, 106, 108, 111, 112, 114, 115, 116, 119, 121, 124, 126, 127, 129, 130,
                133, 136, 139, 140, 147, 148, 155, 159, 160, 162, 167, 169, 176, 181, 182, 183,
                186, 192, 193, 196, 197, 198, 199, 200, 201, 205, 206, 207, 210, 211, 215, 216,
                217, 221, 222, 226, 229, 231, 232, 233, 234, 237, 239, 240, 242, 243, 247, 251,
                253, 256, 257, 259, 260, 261, 262, 263, 265, 266, 271, 272, 274, 276, 279, 281,
                283, 284, 286, 287, 288, 290, 291, 293, 296, 298, 300, 302, 306, 307, 313, 314,
                315, 318, 320, 323, 326, 327, 328, 329, 333, 335, 338, 344, 346, 350, 356, 357,
                362, 364, 365, 366, 370, 373, 375, 380, 381, 382, 387, 388, 390, 392, 394, 395,
                396, 401, 405, 406, 412, 415, 416, 418, 419, 420, 421, 425, 427, 430, 431, 432,
                435, 438, 443, 445, 446, 447, 448, 450, 451, 452, 457, 458, 461, 462, 463, 464,
                466, 469, 472, 473, 477, 478, 481, 482, 484, 485, 488, 489, 492, 494, 498, 501,
                503, 505, 506, 512,
            ],
            Outcome::Accept,
            SPECIAL_PUBLIC,
        ),
    ];

    /// Whether Wycheproof marks `test` as a low-order or zero-secret case.
    fn is_low_order(test: &Test) -> bool {
        test.flags
            .iter()
            .any(|f| f == "LowOrderPublic" || f == "ZeroSharedSecret")
    }

    /// Checks one agreement against the test beyond accept/reject: an
    /// accepted case has exactly the expected Z, and a rejected one is
    /// exactly the flagged low-order cases, with the all-zero error.
    fn check_agreement(test: &Test, result: &Result<Zeroizing<[u8; 32]>>, shared: &[u8]) {
        let id = test.tc_id;
        match result {
            Ok(z) => assert_eq!(&z[..], shared, "tcId {id}: wrong shared secret"),
            Err(err) => {
                assert_eq!(*err, Error::InvalidKey("X25519 shared secret is all-zero"));
                assert_eq!(shared, [0u8; 32], "tcId {id}: rejected a non-zero secret");
            }
        }
        assert_eq!(
            result.is_err(),
            is_low_order(test),
            "tcId {id} ({:?}, flags {:?})",
            test.comment,
            test.flags
        );
    }

    /// Every case outside the flagged ones is accepted, every flagged one
    /// rejected: 518 tests, 31 of them low order, 223 other acceptable.
    const XDH_SUMMARY: Summary = Summary {
        tests: 518,
        accepted: 487,
        rejected: 31,
        deviations: 254,
    };

    #[test]
    fn wycheproof_x25519() {
        let suite = wycheproof::load("x25519");
        let summary = wycheproof::assert_conforms(&suite, XDH, |_, test| {
            let (public, private, shared) = test.agreement();
            let secret = StaticSecret::from(<[u8; 32]>::try_from(private).unwrap());
            let public = PublicKey::from(<[u8; 32]>::try_from(public).unwrap());
            let result = agree(&secret, &public);
            check_agreement(test, &result, shared);
            Outcome::of(&result)
        });
        assert_eq!(summary, XDH_SUMMARY);
    }
}
