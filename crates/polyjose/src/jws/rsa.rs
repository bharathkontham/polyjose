//! RSA family: RS256/384/512 (RSASSA-PKCS1-v1_5, RFC 7518 §3.3) and
//! PS256/384/512 (RSASSA-PSS, RFC 7518 §3.5), verify only (ADR 0021).
//!
//! Implements the family contract documented in `jws/alg.rs` on the
//! RustCrypto `rsa` and `sha2` crates (ADR 0002); no part of RSA is
//! written here.
//!
//! - **Public-key operations only (ADR 0021).** RUSTSEC-2023-0071 (Marvin)
//!   is a timing leak in the `rsa` crate's private-key operations, so
//!   polyjose verifies RS*/PS* signatures but never makes them: [`sign`]
//!   always fails. This file uses only `rsa::RsaPublicKey` and the typed
//!   `rsa::pkcs1v15::VerifyingKey` and `rsa::pss::VerifyingKey`;
//!   `scripts/check-deps.sh` (ADR 0021 §3) fails the build if any RSA
//!   private-key, signing or decryption type appears here or anywhere
//!   else in the core.
//! - **Key import.** [`public_key`] turns a JWK's `n` and `e` into the
//!   `rsa` crate's key with the modulus bounds of [`MODULUS_BITS`]. It is
//!   the crate's one RSA public-key import, shared with RSA-OAEP-256
//!   encryption (feature 0003).
//! - **No SHA-1.** Only SHA-256/384/512 (ADR 0022).
//! - **No secrets.** Every input is public; errors carry no key or input
//!   octets (ADR 0007).

use core::ops::RangeInclusive;

use rsa::signature::Verifier;
use rsa::{BoxedUint, pkcs1v15, pss};
use sha2::{Sha256, Sha384, Sha512};

use crate::error::{Error, Result};
use crate::jwa::SigningAlg;
use crate::jwk::{Jwk, KeyMaterial};

/// The RSA modulus sizes polyjose uses, in bits: at least 2048
/// (RFC 7518 §3.3, §3.5, §4.2: "A key of size 2048 bits or larger MUST be
/// used") and at most 8192, the `rsa` crate's own maximum
/// (ADR 0026 §2 step 8).
pub(crate) const MODULUS_BITS: RangeInclusive<usize> = 2048..=8192;

/// RSA signing is not offered in 0.1.0 (ADR 0021: RUSTSEC-2023-0071
/// affects private-key operations). This body is final.
///
/// # Errors
///
/// Always [`Error::UnsupportedAlgorithm`]. Key binding already refuses
/// RS*/PS* signing with the same error before any other key check
/// (ADR 0026 §2 step 8).
pub(crate) fn sign(alg: &SigningAlg, key: &Jwk, signing_input: &[u8]) -> Result<Vec<u8>> {
    let _ = (alg, key, signing_input);
    Err(Error::UnsupportedAlgorithm)
}

/// Validates an RS256/384/512 (RFC 7518 §3.3) or PS256/384/512
/// (RFC 7518 §3.5) signature over `signing_input` (RFC 7515 §5.2 step 8).
///
/// - **RS\***: RSASSA-PKCS1-v1_5 verification (RFC 8017 §8.2.2) with
///   SHA-256/384/512, by `rsa::pkcs1v15::VerifyingKey`. The DigestInfo
///   prefix is the DER one with NULL parameters (RFC 8017 §9.2 note 1),
///   and EM is compared whole (§8.2.2 step 4), so no BER variant, missing
///   NULL or trailing data is accepted.
/// - **PS\***: RSASSA-PSS verification (RFC 8017 §8.1.2) with
///   SHA-256/384/512, MGF1 over the same hash, and a salt exactly as long
///   as the hash output (RFC 7518 §3.5: "The size of the salt value is the
///   same size as the hash function output"), by
///   `rsa::pss::VerifyingKey::new`. A signature made with another salt
///   length fails (RFC 8017 §9.1.2 step 10).
/// - **Length.** The signature must be exactly k octets, the modulus
///   length (RFC 8017 §8.1.2 step 1, §8.2.2 step 1), so a signature whose
///   leading zero octets were stripped, or with extra ones, fails. The
///   signature representative must be below n (RFC 8017 §5.2.2).
///
/// Key binding has checked that `key` is an `RSA` public key with a
/// modulus of 2048..=8192 bits (RFC 7518 §3.3, §3.5; ADR 0026 §2 step 8);
/// [`public_key`] checks the key again. Only public-key operations run
/// (ADR 0021).
///
/// # Errors
///
/// - [`Error::InvalidSignature`] if the signature does not validate.
/// - [`Error::InvalidKey`] if [`public_key`] refuses the key.
/// - [`Error::KeyAlgorithmMismatch`] only if called against the contract
///   (`alg` not RS*/PS*, or a non-RSA key), which key binding prevents.
pub(crate) fn verify(
    alg: &SigningAlg,
    key: &Jwk,
    signing_input: &[u8],
    signature: &[u8],
) -> Result<()> {
    use SigningAlg as A;
    let KeyMaterial::Rsa(jwk_key) = key.material() else {
        return Err(Error::KeyAlgorithmMismatch);
    };
    if !matches!(
        alg,
        A::RS256 | A::RS384 | A::RS512 | A::PS256 | A::PS384 | A::PS512
    ) {
        return Err(Error::KeyAlgorithmMismatch);
    }
    let public = public_key(jwk_key.n(), jwk_key.e())?;
    let verified = match alg {
        A::RS256 => pkcs1v15::VerifyingKey::<Sha256>::new(public)
            .verify(signing_input, &pkcs1v15_signature(signature)?),
        A::RS384 => pkcs1v15::VerifyingKey::<Sha384>::new(public)
            .verify(signing_input, &pkcs1v15_signature(signature)?),
        A::RS512 => pkcs1v15::VerifyingKey::<Sha512>::new(public)
            .verify(signing_input, &pkcs1v15_signature(signature)?),
        A::PS256 => pss::VerifyingKey::<Sha256>::new(public)
            .verify(signing_input, &pss_signature(signature)?),
        A::PS384 => pss::VerifyingKey::<Sha384>::new(public)
            .verify(signing_input, &pss_signature(signature)?),
        A::PS512 => pss::VerifyingKey::<Sha512>::new(public)
            .verify(signing_input, &pss_signature(signature)?),
        _ => return Err(Error::KeyAlgorithmMismatch),
    };
    verified.map_err(|_| Error::InvalidSignature)
}

/// The signature octets for RSASSA-PKCS1-v1_5. Over 1024 octets (an 8192-bit
/// modulus) is no signature of a usable key.
fn pkcs1v15_signature(signature: &[u8]) -> Result<pkcs1v15::Signature> {
    pkcs1v15::Signature::try_from(signature).map_err(|_| Error::InvalidSignature)
}

/// The signature octets for RSASSA-PSS, as [`pkcs1v15_signature`].
fn pss_signature(signature: &[u8]) -> Result<pss::Signature> {
    pss::Signature::try_from(signature).map_err(|_| Error::InvalidSignature)
}

/// Builds the `rsa` crate's public key from the big-endian modulus `n` and
/// public exponent `e` of an RSA public JWK (RFC 7518 §6.3.1.1,
/// §6.3.1.2). This is the one RSA public-key import of the crate: JWS
/// verify uses it, and so does RSA-OAEP-256 encryption (feature 0003,
/// ADR 0022). It handles public values only (ADR 0021).
///
/// `rsa::RsaPublicKey::new_with_size_limits` with [`MODULUS_BITS`] checks:
///
/// - the modulus is 2048..=8192 bits (RFC 7518 §3.3, §3.5, §4.2;
///   ADR 0026 §2 step 8), and odd (RFC 8017 §3.1: a product of odd primes);
/// - `e` is odd and 2 < e < n (RFC 8017 §3.1);
/// - `e` is at most 2^33 − 1. RFC 8017 §3.1 allows any e < n, but the
///   `rsa` crate bounds it, as *ring* does, because a huge exponent makes
///   every verification slow (RSA DoS). JWK import (`jwk.rs`) accepts such
///   an `e`; verifying with it fails here with [`Error::InvalidKey`].
///
/// Leading zero octets are allowed (a JWK's `n` and `e` have none,
/// RFC 7518 §2). Each integer gets the precision of its own octet length,
/// as the `rsa` crate's PKCS#1 decoder does.
///
/// # Errors
///
/// [`Error::InvalidKey`] if any check fails. The detail names the rule,
/// never the values (ADR 0007).
pub(crate) fn public_key(n: &[u8], e: &[u8]) -> Result<rsa::RsaPublicKey> {
    use rsa::errors::Error as E;
    let (n, e) = (uint(n)?, uint(e)?);
    rsa::RsaPublicKey::new_with_size_limits(n, e, MODULUS_BITS).map_err(|err| {
        Error::InvalidKey(match err {
            E::ModulusTooSmall | E::ModulusTooLarge => "RSA modulus must be 2048 to 8192 bits",
            E::InvalidExponent | E::PublicExponentTooSmall => {
                "RSA exponent must be odd and greater than 1"
            }
            E::PublicExponentTooLarge => "RSA exponent is larger than 2^33 - 1",
            // Also e >= n (RFC 8017 §3.1).
            _ => "RSA modulus must be odd and greater than the exponent",
        })
    })
}

/// The big-endian unsigned integer `bytes` (OS2IP, RFC 8017 §4.2), with
/// a precision of 8 bits per octet. Empty input is no integer.
fn uint(bytes: &[u8]) -> Result<BoxedUint> {
    let bits = u32::try_from(bytes.len())
        .ok()
        .and_then(|len| len.checked_mul(8))
        .filter(|&bits| bits > 0)
        .ok_or(Error::InvalidKey("RSA key member is empty or too long"))?;
    BoxedUint::from_be_slice(bytes, bits)
        .map_err(|_| Error::InvalidKey("RSA key member is empty or too long"))
}

#[cfg(test)]
mod tests {
    use rsa::traits::PublicKeyParts;

    use super::super::alg::{Operation, bind_key};
    use super::*;
    use crate::test_support::wycheproof::{
        self, Deviation, Group, Outcome, Schema, Suite, Summary,
    };
    use crate::util::b64url_decode;
    use SigningAlg as A;

    /// e = 65537 (`AQAB`).
    const F4: &[u8] = &[0x01, 0x00, 0x01];

    /// RFC 7515 Appendix A.2.1: the RSA key's `n` (its `e` is `AQAB`).
    const RFC7515_A2_N: &str = concat!(
        "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx",
        "HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs",
        "D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH",
        "SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV",
        "MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8",
        "NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",
    );

    /// RFC 7515 Appendix A.2.1: the JWS Signing Input (RS256).
    const RFC7515_A2_INPUT: &str = concat!(
        "eyJhbGciOiJSUzI1NiJ9",
        ".",
        "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt",
        "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
    );

    /// RFC 7515 Appendix A.2.1: BASE64URL(JWS Signature).
    const RFC7515_A2_SIG: &str = concat!(
        "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7",
        "AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4",
        "BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K",
        "0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqv",
        "hJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrB",
        "p0igcN_IoypGlUPQGe77Rw",
    );

    /// RFC 7520 §3.3 (Figure 3): the RSA public key's `n` (`e` is `AQAB`).
    const RFC7520_N: &str = concat!(
        "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT",
        "-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqV",
        "wGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-",
        "oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde",
        "3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuC",
        "LqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5g",
        "HdrNP5zw",
    );

    /// RFC 7520 §4 (Figure 8): BASE64URL(JWS Payload), shared by §4.1
    /// and §4.2.
    const RFC7520_PAYLOAD: &str = concat!(
        "SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IH",
        "lvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBk",
        "b24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcm",
        "UgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4",
    );

    /// RFC 7520 §4.1.2 (Figure 10): the RS256 JWS Protected Header,
    /// base64url-encoded.
    const RFC7520_4_1_PROTECTED: &str = concat!(
        "eyJhbGciOiJSUzI1NiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZX",
        "hhbXBsZSJ9",
    );

    /// RFC 7520 §4.1.2 (Figure 12): the RS256 JWS Signature.
    const RFC7520_4_1_SIG: &str = concat!(
        "MRjdkly7_-oTPTS3AXP41iQIGKa80A0ZmTuV5MEaHoxnW2e5CZ5NlKtainoFmK",
        "ZopdHM1O2U4mwzJdQx996ivp83xuglII7PNDi84wnB-BDkoBwA78185hX-Es4J",
        "IwmDLJK3lfWRa-XtL0RnltuYv746iYTh_qHRD68BNt1uSNCrUCTJDt5aAE6x8w",
        "W1Kt9eRo4QPocSadnHXFxnt8Is9UzpERV0ePPQdLuW3IS_de3xyIrDaLGdjluP",
        "xUAhb6L2aXic1U12podGU0KLUQSE_oI-ZnmKJ3F4uOZDnd6QZWJushZ41Axf_f",
        "cIe8u9ipH84ogoree7vjbU5y18kDquDg",
    );

    /// RFC 7520 §4.2.2 (Figure 17): the PS384 JWS Protected Header,
    /// base64url-encoded.
    const RFC7520_4_2_PROTECTED: &str = concat!(
        "eyJhbGciOiJQUzM4NCIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZX",
        "hhbXBsZSJ9",
    );

    /// RFC 7520 §4.2.2 (Figure 19): the PS384 JWS Signature.
    const RFC7520_4_2_SIG: &str = concat!(
        "cu22eBqkYDKgIlTpzDXGvaFfz6WGoz7fUDcfT0kkOy42miAh2qyBzk1xEsnk2I",
        "pN6-tPid6VrklHkqsGqDqHCdP6O8TTB5dDDItllVo6_1OLPpcbUrhiUSMxbbXU",
        "vdvWXzg-UD8biiReQFlfz28zGWVsdiNAUf8ZnyPEgVFn442ZdNqiVJRmBqrYRX",
        "e8P_ijQ7p8Vdz0TTrxUeT3lm8d9shnr2lfJT8ImUjvAA2Xez2Mlp8cBE5awDzT",
        "0qI0n6uiP1aCN_2_jLAeQTlqRHtfa64QQSUmFAAjVKPbByi7xho0uTOcbH510a",
        "6GYmJUAfmWjwZ6oD4ifKo8DYM-X72Eaw",
    );

    /// A public RSA JWK with modulus `n` (base64url) and e = 65537.
    fn rsa_jwk(n: &str) -> Jwk {
        Jwk::from_json(format!(r#"{{"kty":"RSA","n":"{n}","e":"AQAB"}}"#).as_bytes()).unwrap()
    }

    /// `protected` '.' `payload` (RFC 7515 §5.1 step 5).
    fn signing_input(protected: &str, payload: &str) -> Vec<u8> {
        format!("{protected}.{payload}").into_bytes()
    }

    /// One RFC signature vector.
    struct Vector {
        /// Where it comes from.
        at: &'static str,
        alg: SigningAlg,
        key: Jwk,
        input: Vec<u8>,
        sig: Vec<u8>,
    }

    /// RFC 7515 A.2 and RFC 7520 §4.1, §4.2.
    fn rfc_vectors() -> Vec<Vector> {
        let sig = |s: &str| b64url_decode(s).unwrap();
        vec![
            Vector {
                at: "RFC 7515 A.2",
                alg: A::RS256,
                key: rsa_jwk(RFC7515_A2_N),
                input: RFC7515_A2_INPUT.as_bytes().to_vec(),
                sig: sig(RFC7515_A2_SIG),
            },
            Vector {
                at: "RFC 7520 4.1",
                alg: A::RS256,
                key: rsa_jwk(RFC7520_N),
                input: signing_input(RFC7520_4_1_PROTECTED, RFC7520_PAYLOAD),
                sig: sig(RFC7520_4_1_SIG),
            },
            Vector {
                at: "RFC 7520 4.2",
                alg: A::PS384,
                key: rsa_jwk(RFC7520_N),
                input: signing_input(RFC7520_4_2_PROTECTED, RFC7520_PAYLOAD),
                sig: sig(RFC7520_4_2_SIG),
            },
        ]
    }

    /// `bytes` with bit `bit` of octet `at` flipped.
    fn flipped(bytes: &[u8], at: usize, bit: u8) -> Vec<u8> {
        let mut out = bytes.to_vec();
        out[at] ^= 1 << bit;
        out
    }

    #[test]
    fn rfc_vectors_verify_with_the_public_key() {
        // RFC 7515 A.2.2: validate with the public key (n, e) only.
        // RFC 7520 §4.1, §4.2: the §3.3 public key.
        for Vector {
            at,
            alg,
            key,
            input,
            sig,
        } in rfc_vectors()
        {
            assert!(key.is_public(), "{at}");
            assert_eq!(verify(&alg, &key, &input, &sig), Ok(()), "{at}");
        }
    }

    #[test]
    fn rfc_vectors_with_a_flipped_bit_are_invalid() {
        // RFC 8017 §8.2.2 step 4, §8.1.2 step 3: any change to the
        // signature or the signed message makes it invalid.
        for Vector {
            at,
            alg,
            key,
            input,
            sig,
        } in rfc_vectors()
        {
            for pos in [0, sig.len() / 2, sig.len() - 1] {
                for bit in [0, 7] {
                    let bad = flipped(&sig, pos, bit);
                    assert_eq!(
                        verify(&alg, &key, &input, &bad),
                        Err(Error::InvalidSignature),
                        "{at}: signature octet {pos} bit {bit}"
                    );
                }
            }
            for pos in [0, input.len() / 2, input.len() - 1] {
                for bit in [0, 7] {
                    let bad = flipped(&input, pos, bit);
                    assert_eq!(
                        verify(&alg, &key, &bad, &sig),
                        Err(Error::InvalidSignature),
                        "{at}: signing input octet {pos} bit {bit}"
                    );
                }
            }
        }
    }

    #[test]
    fn rfc_vectors_fail_under_every_other_rsa_alg() {
        // RFC 7518 §3.3, §3.5: the alg fixes the scheme and the hash, so a
        // signature never verifies under another RS*/PS* value.
        let all = [A::RS256, A::RS384, A::RS512, A::PS256, A::PS384, A::PS512];
        for Vector {
            at,
            alg,
            key,
            input,
            sig,
        } in rfc_vectors()
        {
            for other in all.iter().filter(|other| **other != alg) {
                assert_eq!(
                    verify(other, &key, &input, &sig),
                    Err(Error::InvalidSignature),
                    "{at} under {other}"
                );
            }
        }
    }

    #[test]
    fn verify_refuses_what_key_binding_would_have_stopped() {
        // The alg.rs contract: no panic if called against it.
        let Vector {
            key: rsa_key,
            input,
            sig,
            ..
        } = rfc_vectors().remove(0);
        let oct = Jwk::from_json(br#"{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}"#).unwrap();
        assert_eq!(
            verify(&A::RS256, &oct, &input, &sig),
            Err(Error::KeyAlgorithmMismatch)
        );
        for alg in [A::HS256, A::ES256, A::EdDSA, A::None] {
            assert_eq!(
                verify(&alg, &rsa_key, &input, &sig),
                Err(Error::KeyAlgorithmMismatch),
                "{alg}"
            );
        }
    }

    #[test]
    fn verify_rejects_a_key_the_rsa_crate_refuses() {
        // JWK import accepts e up to n - 1 (RFC 8017 §3.1); `public_key`
        // refuses e > 2^33 - 1, so verify reports InvalidKey.
        let Vector { input, sig, .. } = rfc_vectors().remove(0);
        let key = Jwk::from_json(
            format!(r#"{{"kty":"RSA","n":"{RFC7515_A2_N}","e":"AgAAAAE"}}"#).as_bytes(),
        )
        .unwrap();
        assert!(matches!(
            verify(&A::RS256, &key, &input, &sig),
            Err(Error::InvalidKey(_))
        ));
    }

    /// An odd modulus of exactly `bits` bits: all ones. Structurally valid
    /// only; no signature verifies under it.
    fn modulus(bits: usize) -> Vec<u8> {
        let mut n = vec![0xff; bits.div_ceil(8)];
        n[0] >>= (8 - bits % 8) % 8;
        n
    }

    fn invalid_key(result: Result<rsa::RsaPublicKey>) -> bool {
        matches!(result, Err(Error::InvalidKey(_)))
    }

    #[test]
    fn public_key_imports_2048_to_8192_bits() {
        // RFC 7518 §3.3, §3.5; ADR 0026 §2 step 8.
        for bits in [2048, 3072, 4096, 8191, 8192] {
            let key = public_key(&modulus(bits), F4).unwrap();
            assert_eq!(key.n().bits() as usize, bits);
            assert_eq!(key.size(), bits.div_ceil(8));
        }
        // e = 3 is the smallest odd exponent above 1 (RFC 8017 §3.1).
        assert!(public_key(&modulus(2048), &[3]).is_ok());
    }

    #[test]
    fn public_key_rejects_a_modulus_outside_2048_to_8192_bits() {
        for bits in [1024, 2047, 8193, 8200] {
            assert!(invalid_key(public_key(&modulus(bits), F4)), "{bits}");
        }
    }

    #[test]
    fn public_key_rejects_a_bad_exponent() {
        let n = modulus(2048);
        // RFC 8017 §3.1: e is odd and 3 <= e <= n - 1.
        for e in [&[0x01, 0x00, 0x00][..], &[1], &[0], &[2], &[]] {
            assert!(invalid_key(public_key(&n, e)), "{e:?}");
        }
        assert!(invalid_key(public_key(&n, &n)), "e = n");
        // The rsa crate bounds e by 2^33 - 1 against RSA DoS (see
        // `public_key`'s docs).
        assert!(invalid_key(public_key(&n, &[0x02, 0x00, 0x00, 0x00, 0x01])));
        assert!(public_key(&n, &[0x01, 0xff, 0xff, 0xff, 0xff]).is_ok());
    }

    #[test]
    fn public_key_rejects_an_even_or_empty_modulus() {
        let mut even = modulus(2048);
        if let Some(last) = even.last_mut() {
            *last = 0xfe;
        }
        assert!(invalid_key(public_key(&even, F4)));
        assert!(invalid_key(public_key(&[], F4)));
    }

    /// Where polyjose's outcome differs from, or picks a side of,
    /// Wycheproof's `result` in every `rsa_signature_*` suite.
    const PKCS1V15_DEVIATIONS: &[Deviation] = &[Deviation::tests(
        &[8],
        Outcome::Reject,
        "RFC 8017 §8.2.2 step 4, §9.2 note 1: EM' carries the DigestInfo \
         with NULL hash parameters, so one without them (MissingNull) is \
         an invalid signature",
    )];

    /// The PSS suites have no `acceptable` test and polyjose follows
    /// every `result`.
    const PSS_DEVIATIONS: &[Deviation] = &[];

    /// The JWS `alg` for a Wycheproof group: RS* for the PKCS #1 v1.5
    /// suites, PS* for the PSS ones (RFC 7518 §3.1). A PSS group must use
    /// MGF1 over the message hash and a salt of the hash length, the only
    /// parameters RFC 7518 §3.5 defines.
    fn group_alg(suite: &Suite, group: &Group) -> SigningAlg {
        let sha = group.sha.as_deref().unwrap_or_default();
        let (alg, hash_len) = match (suite.schema, sha) {
            (Schema::RsassaPkcs1Verify, "SHA-256") => (A::RS256, 32),
            (Schema::RsassaPkcs1Verify, "SHA-384") => (A::RS384, 48),
            (Schema::RsassaPkcs1Verify, "SHA-512") => (A::RS512, 64),
            (Schema::RsassaPssVerify, "SHA-256") => (A::PS256, 32),
            (Schema::RsassaPssVerify, "SHA-384") => (A::PS384, 48),
            (Schema::RsassaPssVerify, "SHA-512") => (A::PS512, 64),
            other => panic!("{}: no JWS alg for {other:?}", suite.name),
        };
        if suite.schema == Schema::RsassaPssVerify {
            assert_eq!(group.mgf_sha.as_deref(), Some(sha), "{}", suite.name);
            assert_eq!(group.salt_len, Some(hash_len), "{}", suite.name);
        }
        alg
    }

    /// Runs `suite` through key binding (ADR 0026 §2 step 8) and
    /// [`verify`], with the group's `keyJwk`/`publicKeyJwk`. A rejection
    /// must be [`Error::InvalidSignature`]: every Wycheproof key is valid.
    fn run_wycheproof(suite: &Suite, deviations: &[Deviation]) -> Summary {
        wycheproof::assert_conforms(suite, deviations, |group, test| {
            let alg = group_alg(suite, group);
            let key = Jwk::from_json(group.verification_jwk().as_bytes())
                .unwrap_or_else(|e| panic!("{}: tcId {}: {e:?}", suite.name, test.tc_id));
            assert_eq!(bind_key(&alg, &key, Operation::Verify), Ok(()));
            let (msg, sig) = test.signature();
            let result = verify(&alg, &key, msg, sig);
            if let Err(err) = &result {
                assert_eq!(
                    *err,
                    Error::InvalidSignature,
                    "{}: tcId {}",
                    suite.name,
                    test.tc_id
                );
            }
            Outcome::of(&result)
        })
    }

    #[test]
    fn wycheproof_rsa_signature_suites() {
        // RFC 7518 §3.3 on every vendored rsa_signature_* file, 8192 bits
        // included.
        for name in wycheproof::names("rsa_signature_") {
            let suite = wycheproof::load(name);
            let summary = run_wycheproof(&suite, PKCS1V15_DEVIATIONS);
            println!("{name}: {summary:?}");
        }
    }

    #[test]
    fn wycheproof_rsa_pss_suites() {
        // RFC 7518 §3.5 on every vendored rsa_pss_* file.
        for name in wycheproof::names("rsa_pss_") {
            let suite = wycheproof::load(name);
            let summary = run_wycheproof(&suite, PSS_DEVIATIONS);
            println!("{name}: {summary:?}");
        }
    }
}
