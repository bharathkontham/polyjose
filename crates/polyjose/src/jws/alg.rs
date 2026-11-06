//! JWS algorithm families: `alg` → family dispatch, the per-family
//! contract, and the test seam.
//!
//! # The family contract
//!
//! Each family module (`hmac`, `rsa`, `ecdsa`, `eddsa`) provides exactly:
//!
//! ```text
//! pub(crate) fn sign(alg: &SigningAlg, key: &Jwk, signing_input: &[u8]) -> Result<Vec<u8>>;
//! pub(crate) fn verify(alg: &SigningAlg, key: &Jwk, signing_input: &[u8], signature: &[u8]) -> Result<()>;
//! ```
//!
//! - `signing_input` is the complete JWS Signing Input (RFC 7515 §5.1
//!   step 5, RFC 7797 §3), built by `process::signing_input`.
//! - `signature` is the decoded JWS Signature octets (RFC 7515 §5.2
//!   step 7), unchecked: a wrong length is the family's to reject.
//! - **Preconditions.** The caller has already run key binding
//!   ([`bind_key`], ADR 0026 §2 step 8), so `alg` belongs to the family,
//!   the key is of the family's `kty`/`crv`, its JWK `alg`/`use`/`key_ops`
//!   allow the operation, a sign key holds private material, an HMAC key
//!   is at least the hash size and an RSA modulus is 2048..=8192 bits.
//!   A family still matches on the key material and returns
//!   [`Error::KeyAlgorithmMismatch`] if it is not its own, rather than
//!   panicking.
//! - **What a family checks itself**, because it needs the primitive:
//!   EC points and scalars, Ed25519 small-order keys
//!   ([`Error::InvalidKey`]), and signature length and value
//!   ([`Error::InvalidSignature`]).
//! - **Errors.** `verify` returns only [`Error::InvalidSignature`] or
//!   [`Error::InvalidKey`]. `sign` returns only [`Error::InvalidKey`] or,
//!   for ECDSA, [`Error::RandomnessUnavailable`]; RSA `sign` always
//!   returns [`Error::UnsupportedAlgorithm`] (ADR 0021). No error carries
//!   key material or input (ADR 0007).
//!
//! # The test seam
//!
//! The serialization layers never call a family directly. They take a
//! [`Families`] table and call it after key binding; the public functions
//! pass [`FAMILIES`], the real dispatch. A `#[cfg(test)]` module can pass
//! its own table instead (for example [`fake::FAKE`]) to test the
//! serialization and the processing order without any real algorithm.
//! Key binding is not part of the table, so it is never substituted.

use crate::error::{Error, Result};
use crate::jwa::SigningAlg;
use crate::jwk::{Jwk, KeyAlg, KeyMaterial, KeyOp};

use super::{ecdsa, eddsa, hmac, rsa};

/// A family `sign` function (see the module docs for the contract).
pub(crate) type SignFn = fn(&SigningAlg, &Jwk, &[u8]) -> Result<Vec<u8>>;

/// A family `verify` function (see the module docs for the contract).
pub(crate) type VerifyFn = fn(&SigningAlg, &Jwk, &[u8], &[u8]) -> Result<()>;

/// The signature primitives the serialization layers call, after key
/// binding: the crate-internal test seam (see the module docs).
#[derive(Clone, Copy)]
pub(crate) struct Families {
    /// Computes a JWS Signature over a JWS Signing Input
    /// (RFC 7515 §5.1 step 5).
    pub(crate) sign: SignFn,
    /// Validates a JWS Signature against a JWS Signing Input
    /// (RFC 7515 §5.2 step 8).
    pub(crate) verify: VerifyFn,
}

/// The real dispatch: each `alg` goes to its family module.
pub(crate) const FAMILIES: Families = Families {
    sign: dispatch_sign,
    verify: dispatch_verify,
};

/// The JWS algorithm families (RFC 7518 §3.1, RFC 8037 §3.1,
/// RFC 8812 §3.2, RFC 9864 §2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Family {
    /// HS256, HS384, HS512 (RFC 7518 §3.2).
    Hmac,
    /// RS256/384/512 (RFC 7518 §3.3) and PS256/384/512 (RFC 7518 §3.5).
    Rsa,
    /// ES256, ES384, ES512 (RFC 7518 §3.4) and ES256K (RFC 8812 §3.2).
    Ecdsa,
    /// EdDSA (RFC 8037 §3.1) and Ed25519 (RFC 9864 §2.2), Ed25519 keys only.
    EdDsa,
}

/// The family of `alg`, or `None` for `none` (RFC 7518 §3.6) and unknown
/// values, which no family serves.
pub(crate) fn family(alg: &SigningAlg) -> Option<Family> {
    use SigningAlg as A;
    match alg {
        A::HS256 | A::HS384 | A::HS512 => Some(Family::Hmac),
        A::RS256 | A::RS384 | A::RS512 | A::PS256 | A::PS384 | A::PS512 => Some(Family::Rsa),
        A::ES256 | A::ES384 | A::ES512 | A::ES256K => Some(Family::Ecdsa),
        A::EdDSA | A::Ed25519 => Some(Family::EdDsa),
        A::None | A::Unknown(_) => None,
    }
}

/// The error for an `alg` no family serves: `none` is never allowed
/// (RFC 8725 §3.1, ADR 0007), an unknown value is unsupported
/// (RFC 7515 §4.1.1).
pub(crate) fn unserved(alg: &SigningAlg) -> Error {
    if *alg == SigningAlg::None {
        Error::AlgorithmNotAllowed
    } else {
        Error::UnsupportedAlgorithm
    }
}

/// The operation a key is bound for (RFC 7517 §4.3 `sign` / `verify`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Operation {
    /// Computing a JWS Signature (RFC 7515 §5.1).
    Sign,
    /// Validating a JWS Signature (RFC 7515 §5.2).
    Verify,
}

/// The smallest RSA modulus polyjose uses, in bits (RFC 7518 §3.3, §3.5).
/// Import already rejects smaller keys (ADR 0007); this is defence in
/// depth.
const RSA_MIN_BITS: usize = 2048;

/// The largest RSA modulus polyjose uses, in bits: the `rsa` crate's own
/// maximum (ADR 0026 §2 step 8).
const RSA_MAX_BITS: usize = 8192;

/// Key binding, ADR 0026 §2 step 8: checks that `key` may be used with
/// `alg` for `op`, before any cryptography runs. Signing and verifying
/// both call it, and nothing reaches a family without it.
///
/// In this order:
///
/// 1. `alg` must have a family: `none` → [`Error::AlgorithmNotAllowed`]
///    (RFC 8725 §3.2), unknown → [`Error::UnsupportedAlgorithm`]
///    (RFC 7515 §4.1.1). The verify allow-list stops both earlier.
/// 2. Signing with RS*/PS* → [`Error::UnsupportedAlgorithm`], whatever
///    the key (ADR 0021).
/// 3. → [`Error::KeyAlgorithmMismatch`] if any of these fails:
///    - the key is of the family `alg` requires, per
///      [`KeyMaterial::serves_signing_alg`], the single copy of that table
///      (RFC 7518 §3, RFC 8037 §3.1, RFC 8812 §3.3, RFC 9864 §2.2;
///      RFC 8725 §3.1);
///    - a JWK `alg`, if present, is exactly `alg` (RFC 7517 §4.4,
///      RFC 9864 §7): `EdDSA` and `Ed25519` differ;
///    - a JWK `use`, if present, is `sig`, and a JWK `key_ops`, if present,
///      contains `sign` or `verify` ([`Jwk::permits`]; RFC 7517 §4.2,
///      §4.3);
///    - a key for signing holds private material (RFC 7518 §3).
/// 4. → [`Error::InvalidKey`] for weak material: an HMAC key shorter than
///    the hash output, on sign **and** verify (RFC 7518 §3.2), or an RSA
///    modulus outside 2048..=8192 bits (RFC 7518 §3.3, §3.5). EC and
///    Ed25519 checks need the curve arithmetic and are the family's.
pub(crate) fn bind_key(alg: &SigningAlg, key: &Jwk, op: Operation) -> Result<()> {
    let family = family(alg).ok_or_else(|| unserved(alg))?;
    if op == Operation::Sign && family == Family::Rsa {
        return Err(Error::UnsupportedAlgorithm);
    }
    let jwk_alg_ok = key
        .alg()
        .is_none_or(|key_alg| matches!(key_alg, KeyAlg::Signing(a) if a == alg));
    let key_op = match op {
        Operation::Sign => KeyOp::Sign,
        Operation::Verify => KeyOp::Verify,
    };
    let bound = key.material().serves_signing_alg(alg)
        && jwk_alg_ok
        && key.permits(&key_op)
        && !(op == Operation::Sign && key.is_public());
    if !bound {
        return Err(Error::KeyAlgorithmMismatch);
    }
    check_strength(alg, key.material())
}

/// The key-strength part of [`bind_key`] that needs no primitive.
fn check_strength(alg: &SigningAlg, material: &KeyMaterial) -> Result<()> {
    match material {
        KeyMaterial::Oct(k) => {
            // RFC 7518 §3.2: "A key of the same size as the hash output
            // ... or larger MUST be used with this algorithm."
            let min = match alg {
                SigningAlg::HS384 => 48,
                SigningAlg::HS512 => 64,
                _ => 32,
            };
            if k.len() < min {
                return Err(Error::InvalidKey(
                    "HMAC key is shorter than the hash output",
                ));
            }
            Ok(())
        }
        KeyMaterial::Rsa(k) => {
            if (RSA_MIN_BITS..=RSA_MAX_BITS).contains(&k.modulus_bits()) {
                Ok(())
            } else {
                Err(Error::InvalidKey("RSA modulus must be 2048 to 8192 bits"))
            }
        }
        KeyMaterial::Ec(_) | KeyMaterial::Okp(_) => Ok(()),
    }
}

fn dispatch_sign(alg: &SigningAlg, key: &Jwk, signing_input: &[u8]) -> Result<Vec<u8>> {
    match family(alg) {
        Some(Family::Hmac) => hmac::sign(alg, key, signing_input),
        Some(Family::Rsa) => rsa::sign(alg, key, signing_input),
        Some(Family::Ecdsa) => ecdsa::sign(alg, key, signing_input),
        Some(Family::EdDsa) => eddsa::sign(alg, key, signing_input),
        None => Err(unserved(alg)),
    }
}

fn dispatch_verify(
    alg: &SigningAlg,
    key: &Jwk,
    signing_input: &[u8],
    signature: &[u8],
) -> Result<()> {
    match family(alg) {
        Some(Family::Hmac) => hmac::verify(alg, key, signing_input, signature),
        Some(Family::Rsa) => rsa::verify(alg, key, signing_input, signature),
        Some(Family::Ecdsa) => ecdsa::verify(alg, key, signing_input, signature),
        Some(Family::EdDsa) => eddsa::verify(alg, key, signing_input, signature),
        None => Err(unserved(alg)),
    }
}

/// Test-only [`Families`] tables for the serialization and processing
/// tests.
#[cfg(test)]
pub(crate) mod fake {
    use sha2::{Digest, Sha256};

    use super::Families;
    use crate::error::{Error, Result};
    use crate::jwa::SigningAlg;
    use crate::jwk::Jwk;

    /// A deterministic stand-in for every family: the "signature" is
    /// SHA-256(`alg` ‖ 0x00 ‖ signing input). It ignores the key, so it is
    /// no MAC; it only lets a test round-trip and tamper with a JWS.
    pub(crate) const FAKE: Families = Families {
        sign: fake_sign,
        verify: fake_verify,
    };

    /// A table whose `verify` always fails with
    /// [`Error::InvalidSignature`], and whose `sign` is [`FAKE`]'s.
    pub(crate) const REJECTING: Families = Families {
        sign: fake_sign,
        verify: |_, _, _, _| Err(Error::InvalidSignature),
    };

    /// The fake signature of `signing_input` under `alg`.
    pub(crate) fn fake_signature(alg: &SigningAlg, signing_input: &[u8]) -> Vec<u8> {
        let mut h = Sha256::new();
        h.update(alg.as_str().as_bytes());
        h.update([0]);
        h.update(signing_input);
        h.finalize().to_vec()
    }

    fn fake_sign(alg: &SigningAlg, _key: &Jwk, signing_input: &[u8]) -> Result<Vec<u8>> {
        Ok(fake_signature(alg, signing_input))
    }

    fn fake_verify(
        alg: &SigningAlg,
        _key: &Jwk,
        signing_input: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        if fake_signature(alg, signing_input) == signature {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }
}

#[cfg(test)]
/// Test JWK fixtures for the JWS unit tests. EC points are on their curves (RFC 7517 A.1 for
/// P-256, the curve generators for P-384 and secp256k1), so they stay
/// valid under import-time curve checks (ADR 0041 §4).
pub(crate) mod test_keys {
    use crate::jwk::Jwk;
    use crate::util::b64url_encode;

    pub(crate) const P256_X: &str = "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4";
    pub(crate) const P256_Y: &str = "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM";
    pub(crate) const P256_D: &str = "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE";
    pub(crate) const ED25519_X: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
    pub(crate) const ED25519_D: &str = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A";

    pub(crate) fn jwk(json: &str) -> Jwk {
        Jwk::from_json(json.as_bytes()).unwrap()
    }

    /// An `oct` key of `len` octets, with extra members appended.
    pub(crate) fn oct(len: usize, extra: &str) -> Jwk {
        let k = b64url_encode(&vec![0x5a; len]);
        jwk(&format!(r#"{{"kty":"oct","k":"{k}"{extra}}}"#))
    }

    /// An RSA public key with a modulus of `bits` bits (all ones, so
    /// odd and minimal) and e = 65537. Structurally valid only; key
    /// binding never does RSA arithmetic.
    pub(crate) fn rsa(bits: usize) -> Jwk {
        let mut n = vec![0xff; bits.div_ceil(8)];
        n[0] >>= (8 - bits % 8) % 8;
        let n = b64url_encode(&n);
        jwk(&format!(r#"{{"kty":"RSA","n":"{n}","e":"AQAB"}}"#))
    }

    pub(crate) fn p256(extra: &str) -> Jwk {
        jwk(&format!(
            r#"{{"kty":"EC","crv":"P-256","x":"{P256_X}","y":"{P256_Y}"{extra}}}"#
        ))
    }

    pub(crate) fn p256_private(extra: &str) -> Jwk {
        p256(&format!(r#","d":"{P256_D}"{extra}"#))
    }

    pub(crate) fn p384() -> Jwk {
        jwk(
            r#"{"kty":"EC","crv":"P-384","x":"qofKIr6LBTeOscce8yCtdG4dO2KLp5uYWfdB4IJUKjhVAvJdv1UpbDpUXjhydgq3","y":"NhfeSpYmLG9dnpi_kpLcKfj0Hb0omhR86doxE7XwuMAKYLHOHX6BnXpDHXyQ6g5f"}"#,
        )
    }

    pub(crate) fn secp256k1() -> Jwk {
        jwk(
            r#"{"kty":"EC","crv":"secp256k1","x":"eb5mfvncu6xVoGKVzocLBwKb_NstzijZWfKBWxb4F5g","y":"SDradyajxGVdpPv8DhEIqP0XtEimhVQZnEfQj_sQ1Lg"}"#,
        )
    }

    pub(crate) fn ed25519(extra: &str) -> Jwk {
        jwk(&format!(
            r#"{{"kty":"OKP","crv":"Ed25519","x":"{ED25519_X}"{extra}}}"#
        ))
    }

    pub(crate) fn ed25519_private(extra: &str) -> Jwk {
        ed25519(&format!(r#","d":"{ED25519_D}"{extra}"#))
    }

    /// RFC 7748 §6.1 Alice's X25519 public key.
    pub(crate) fn x25519() -> Jwk {
        jwk(r#"{"kty":"OKP","crv":"X25519","x":"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08"}"#)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oct() -> Jwk {
        Jwk::from_json(br#"{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}"#).unwrap()
    }

    use super::test_keys as keys;
    use Operation::{Sign, Verify};
    use SigningAlg as A;

    const MISMATCH: Result<()> = Err(Error::KeyAlgorithmMismatch);

    #[test]
    fn binding_accepts_each_family_with_its_key() {
        let cases = [
            (A::HS256, keys::oct(32, "")),
            (A::HS384, keys::oct(48, "")),
            (A::HS512, keys::oct(64, "")),
            (A::ES256, keys::p256_private("")),
            (A::EdDSA, keys::ed25519_private("")),
            (A::Ed25519, keys::ed25519_private("")),
        ];
        for (alg, key) in &cases {
            assert_eq!(bind_key(alg, key, Sign), Ok(()), "sign {alg}");
            assert_eq!(bind_key(alg, key, Verify), Ok(()), "verify {alg}");
        }
        let verify_only = [
            (A::RS256, keys::rsa(2048)),
            (A::PS512, keys::rsa(8192)),
            (A::ES256, keys::p256("")),
            (A::ES384, keys::p384()),
            (A::ES256K, keys::secp256k1()),
            (A::Ed25519, keys::ed25519("")),
        ];
        for (alg, key) in &verify_only {
            assert_eq!(bind_key(alg, key, Verify), Ok(()), "verify {alg}");
        }
    }

    #[test]
    fn binding_rejects_the_wrong_family() {
        // RFC 8725 §2.1 HS/RS confusion, ADR 0026 §2 step 8.
        assert_eq!(bind_key(&A::HS256, &keys::rsa(2048), Verify), MISMATCH);
        assert_eq!(bind_key(&A::HS256, &keys::rsa(2048), Sign), MISMATCH);
        assert_eq!(bind_key(&A::RS256, &keys::oct(64, ""), Verify), MISMATCH);
        // RFC 7518 §3.4: each ES* names one curve.
        assert_eq!(bind_key(&A::ES256, &keys::p384(), Verify), MISMATCH);
        // RFC 8812 §3.3: secp256k1 only with ES256K, and ES256K only with it.
        assert_eq!(bind_key(&A::ES256K, &keys::p256(""), Verify), MISMATCH);
        assert_eq!(bind_key(&A::ES256, &keys::secp256k1(), Verify), MISMATCH);
        // RFC 8037 §3.1-§3.2: X25519 is a key agreement key.
        assert_eq!(bind_key(&A::EdDSA, &keys::x25519(), Verify), MISMATCH);
        assert_eq!(bind_key(&A::Ed25519, &keys::x25519(), Verify), MISMATCH);
        assert_eq!(bind_key(&A::ES256, &keys::ed25519(""), Verify), MISMATCH);
    }

    #[test]
    fn binding_requires_the_jwk_alg_to_match_exactly() {
        // RFC 7517 §4.4, RFC 9864 §2.2, ADR 0026 §2 step 8: EdDSA != Ed25519.
        let eddsa = keys::ed25519_private(r#","alg":"EdDSA""#);
        assert_eq!(bind_key(&A::Ed25519, &eddsa, Verify), MISMATCH);
        assert_eq!(bind_key(&A::Ed25519, &eddsa, Sign), MISMATCH);
        assert_eq!(bind_key(&A::EdDSA, &eddsa, Verify), Ok(()));
        let ed25519 = keys::ed25519(r#","alg":"Ed25519""#);
        assert_eq!(bind_key(&A::EdDSA, &ed25519, Verify), MISMATCH);
        assert_eq!(bind_key(&A::Ed25519, &ed25519, Verify), Ok(()));
        // Same family, other hash.
        let hs256 = keys::oct(64, r#","alg":"HS256""#);
        assert_eq!(bind_key(&A::HS512, &hs256, Verify), MISMATCH);
        assert_eq!(bind_key(&A::HS256, &hs256, Verify), Ok(()));
        // A JWE algorithm, or an unknown one, on the key.
        let a128kw = keys::oct(64, r#","alg":"A128KW""#);
        assert_eq!(bind_key(&A::HS256, &a128kw, Verify), MISMATCH);
        let unknown = keys::oct(64, r#","alg":"HS1""#);
        assert_eq!(bind_key(&A::HS256, &unknown, Verify), MISMATCH);
    }

    #[test]
    fn binding_honours_use_and_key_ops() {
        // RFC 7517 §4.2: `use` must be `sig`.
        let enc = keys::oct(64, r#","use":"enc""#);
        assert_eq!(bind_key(&A::HS256, &enc, Verify), MISMATCH);
        assert_eq!(bind_key(&A::HS256, &enc, Sign), MISMATCH);
        let other = keys::p256(r#","use":"other""#);
        assert_eq!(bind_key(&A::ES256, &other, Verify), MISMATCH);
        let sig = keys::p256(r#","use":"sig""#);
        assert_eq!(bind_key(&A::ES256, &sig, Verify), Ok(()));
        // RFC 7517 §4.3: `key_ops` must contain the operation.
        let sign_only = keys::p256_private(r#","key_ops":["sign"]"#);
        assert_eq!(bind_key(&A::ES256, &sign_only, Verify), MISMATCH);
        assert_eq!(bind_key(&A::ES256, &sign_only, Sign), Ok(()));
        let verify_only = keys::oct(64, r#","key_ops":["verify"]"#);
        assert_eq!(bind_key(&A::HS256, &verify_only, Sign), MISMATCH);
        assert_eq!(bind_key(&A::HS256, &verify_only, Verify), Ok(()));
    }

    #[test]
    fn binding_refuses_a_public_key_for_signing() {
        assert_eq!(bind_key(&A::ES256, &keys::p256(""), Sign), MISMATCH);
        assert_eq!(bind_key(&A::Ed25519, &keys::ed25519(""), Sign), MISMATCH);
        // `to_public` of a private key, as a caller might pass by mistake.
        let public = keys::p256_private("").to_public().unwrap();
        assert_eq!(bind_key(&A::ES256, &public, Sign), MISMATCH);
    }

    #[test]
    fn binding_enforces_the_hmac_key_minimum_both_ways() {
        // RFC 7518 §3.2: a key at least the size of the hash output.
        for (alg, min) in [(A::HS256, 32), (A::HS384, 48), (A::HS512, 64)] {
            let short = keys::oct(min - 1, "");
            for op in [Sign, Verify] {
                assert_eq!(
                    bind_key(&alg, &short, op).map_err(|e| e.code()),
                    Err("InvalidKey"),
                    "{alg} {op:?}"
                );
                assert_eq!(bind_key(&alg, &keys::oct(min, ""), op), Ok(()));
            }
        }
    }

    #[test]
    fn binding_enforces_the_rsa_modulus_range() {
        // RFC 7518 §3.3, §3.5 and ADR 0026 §2 step 8: 2048..=8192 bits.
        // (Under 2048 bits never imports, ADR 0007.)
        let huge = keys::rsa(8200);
        assert_eq!(
            bind_key(&A::RS256, &huge, Verify).map_err(|e| e.code()),
            Err("InvalidKey")
        );
        assert_eq!(bind_key(&A::PS256, &keys::rsa(8192), Verify), Ok(()));
    }

    #[test]
    fn binding_refuses_rsa_signing_before_anything_else() {
        // ADR 0021 / ADR 0026 §2 step 8: UnsupportedAlgorithm even when the
        // key would fail the other checks.
        for alg in [A::RS256, A::RS384, A::RS512, A::PS256, A::PS384, A::PS512] {
            for key in [keys::rsa(2048), keys::oct(64, ""), keys::rsa(8200)] {
                assert_eq!(
                    bind_key(&alg, &key, Sign),
                    Err(Error::UnsupportedAlgorithm),
                    "{alg}"
                );
            }
        }
    }

    #[test]
    fn binding_refuses_none_and_unknown() {
        // RFC 8725 §3.2: never produce (or consume) `none`.
        for op in [Sign, Verify] {
            assert_eq!(
                bind_key(&A::None, &keys::oct(64, ""), op),
                Err(Error::AlgorithmNotAllowed)
            );
            assert_eq!(
                bind_key(&A::Unknown("HS1".into()), &keys::oct(64, ""), op),
                Err(Error::UnsupportedAlgorithm)
            );
        }
    }

    #[test]
    fn every_known_alg_but_none_has_a_family() {
        use Family as F;
        use SigningAlg as A;
        let expected = [
            (A::HS256, F::Hmac),
            (A::HS384, F::Hmac),
            (A::HS512, F::Hmac),
            (A::RS256, F::Rsa),
            (A::RS384, F::Rsa),
            (A::RS512, F::Rsa),
            (A::PS256, F::Rsa),
            (A::PS384, F::Rsa),
            (A::PS512, F::Rsa),
            (A::ES256, F::Ecdsa),
            (A::ES384, F::Ecdsa),
            (A::ES512, F::Ecdsa),
            (A::ES256K, F::Ecdsa),
            (A::EdDSA, F::EdDsa),
            (A::Ed25519, F::EdDsa),
        ];
        for (alg, fam) in &expected {
            assert_eq!(family(alg), Some(*fam), "{alg}");
        }
        assert_eq!(expected.len() + 1, SigningAlg::KNOWN.len());
        assert_eq!(family(&A::None), None);
        assert_eq!(family(&A::Unknown("HS1".into())), None);
    }

    #[test]
    fn dispatch_refuses_none_and_unknown() {
        let key = oct();
        let unknown = SigningAlg::Unknown("HS1".into());
        assert_eq!(
            (FAMILIES.sign)(&SigningAlg::None, &key, b"x"),
            Err(Error::AlgorithmNotAllowed)
        );
        assert_eq!(
            (FAMILIES.verify)(&SigningAlg::None, &key, b"x", b""),
            Err(Error::AlgorithmNotAllowed)
        );
        assert_eq!(
            (FAMILIES.sign)(&unknown, &key, b"x"),
            Err(Error::UnsupportedAlgorithm)
        );
        assert_eq!(
            (FAMILIES.verify)(&unknown, &key, b"x", b""),
            Err(Error::UnsupportedAlgorithm)
        );
    }

    #[test]
    fn rsa_sign_is_never_offered() {
        // ADR 0021: no RSA private-key operations in 0.1.0.
        let key = oct();
        for alg in [SigningAlg::RS256, SigningAlg::PS512] {
            assert_eq!(
                (FAMILIES.sign)(&alg, &key, b"x"),
                Err(Error::UnsupportedAlgorithm)
            );
        }
    }

    #[test]
    fn fake_families_round_trip_and_reject_tampering() {
        let key = oct();
        let alg = SigningAlg::HS256;
        let sig = (fake::FAKE.sign)(&alg, &key, b"input").unwrap();
        assert_eq!((fake::FAKE.verify)(&alg, &key, b"input", &sig), Ok(()));
        assert_eq!(
            (fake::FAKE.verify)(&alg, &key, b"inpuT", &sig),
            Err(Error::InvalidSignature)
        );
        assert_eq!(
            (fake::FAKE.verify)(&SigningAlg::HS384, &key, b"input", &sig),
            Err(Error::InvalidSignature)
        );
        assert_eq!(
            (fake::REJECTING.verify)(&alg, &key, b"input", &sig),
            Err(Error::InvalidSignature)
        );
    }
}
