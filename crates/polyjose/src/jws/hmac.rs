//! HMAC family: HS256, HS384 and HS512 (RFC 7518 §3.2).
//!
//! Implements the family contract documented in `jws/alg.rs` on the
//! RustCrypto `hmac` and `sha2` crates (ADR 0002); no part of HMAC is
//! written here.
//!
//! - **Full-length tags only.** HS256/384/512 produce a 32/48/64-octet
//!   tag, and verify accepts only a tag of exactly that length: JWS has no
//!   truncated HMAC (RFC 7518 §3.2, unlike the truncated JWE
//!   `A*CBC-HS*` tags of §5.2.2.1).
//! - **Constant time.** The tag is compared by `Mac::verify_slice`, which
//!   rejects a wrong length first (the length is public) and then compares
//!   with `subtle::ConstantTimeEq` (RFC 7518 §3.2: "in a manner that is
//!   protected against timing attacks").
//! - **Key length.** A key shorter than the hash output is
//!   [`Error::InvalidKey`] on sign and verify (RFC 7518 §3.2). Key binding
//!   (ADR 0026 §2 step 8) checks this first; the family checks it again so
//!   it never computes a MAC with a weak key, whoever calls it.
//! - **Secrets.** The key is read in place from the `oct` JWK's zeroizing
//!   buffer and never copied by this module. The keyed state, the inner
//!   and outer SHA-2 cores of `Hmac` (RFC 2104 §2), is wiped on drop by
//!   `sha2`'s `zeroize` feature. (`hmac` 0.13.0 does not wipe the
//!   key-xor-pad block it builds on the stack while keying; that is
//!   upstream code.) No error names the key.

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Sha256, Sha384, Sha512};

use crate::error::{Error, Result};
use crate::jwa::SigningAlg;
use crate::jwk::{Jwk, KeyMaterial};

/// The detail of [`Error::InvalidKey`] for a short key; the same text as
/// key binding's.
const SHORT_KEY: &str = "HMAC key is shorter than the hash output";

/// Computes the HMAC of `signing_input` with SHA-256/384/512 for
/// HS256/384/512 (RFC 7518 §3.2; RFC 7515 §5.1 step 5), returning the full
/// 32/48/64-octet tag.
///
/// Key binding (ADR 0026 §2 step 8) has checked that `key` is `oct` and at
/// least as long as the hash output (RFC 7518 §3.2).
///
/// # Errors
///
/// - [`Error::InvalidKey`] if the key is shorter than the hash output
///   (RFC 7518 §3.2).
/// - [`Error::KeyAlgorithmMismatch`] only if called against the contract,
///   with a non-`oct` key or a non-HMAC `alg`.
pub(crate) fn sign(alg: &SigningAlg, key: &Jwk, signing_input: &[u8]) -> Result<Vec<u8>> {
    let k = oct_key(key)?;
    match alg {
        SigningAlg::HS256 => tag::<Hmac<Sha256>>(k, signing_input),
        SigningAlg::HS384 => tag::<Hmac<Sha384>>(k, signing_input),
        SigningAlg::HS512 => tag::<Hmac<Sha512>>(k, signing_input),
        _ => Err(Error::KeyAlgorithmMismatch),
    }
}

/// Validates an HS256/384/512 tag over `signing_input` (RFC 7518 §3.2,
/// RFC 7515 §5.2 step 8), in constant time.
///
/// Key binding has checked the key as for [`sign`].
///
/// # Errors
///
/// - [`Error::InvalidSignature`] if the tag does not match, including a
///   tag of the wrong length (no truncated MACs, RFC 7518 §3.2).
/// - [`Error::InvalidKey`] if the key is shorter than the hash output
///   (RFC 7518 §3.2), checked before any MAC is computed.
/// - [`Error::KeyAlgorithmMismatch`] only if called against the contract,
///   as for [`sign`].
pub(crate) fn verify(
    alg: &SigningAlg,
    key: &Jwk,
    signing_input: &[u8],
    signature: &[u8],
) -> Result<()> {
    let k = oct_key(key)?;
    match alg {
        SigningAlg::HS256 => check::<Hmac<Sha256>>(k, signing_input, signature),
        SigningAlg::HS384 => check::<Hmac<Sha384>>(k, signing_input, signature),
        SigningAlg::HS512 => check::<Hmac<Sha512>>(k, signing_input, signature),
        _ => Err(Error::KeyAlgorithmMismatch),
    }
}

/// The secret `k` of an `oct` JWK (RFC 7518 §6.4.1), borrowed from its
/// zeroizing buffer.
fn oct_key(key: &Jwk) -> Result<&[u8]> {
    match key.material() {
        KeyMaterial::Oct(oct) => Ok(oct.k()),
        _ => Err(Error::KeyAlgorithmMismatch),
    }
}

/// `M` keyed with `k` and fed `signing_input`, after the RFC 7518 §3.2
/// key-length rule: the HMAC output size is the hash output size.
fn keyed<M: Mac + KeyInit>(k: &[u8], signing_input: &[u8]) -> Result<M> {
    if k.len() < M::output_size() {
        return Err(Error::InvalidKey(SHORT_KEY));
    }
    // HMAC takes a key of any length (RFC 2104 §2), so this cannot fail.
    let mut mac = <M as KeyInit>::new_from_slice(k).map_err(|_| Error::InvalidKey(SHORT_KEY))?;
    Mac::update(&mut mac, signing_input);
    Ok(mac)
}

/// The full-length tag (RFC 7518 §3.2).
fn tag<M: Mac + KeyInit>(k: &[u8], signing_input: &[u8]) -> Result<Vec<u8>> {
    Ok(keyed::<M>(k, signing_input)?
        .finalize()
        .into_bytes()
        .to_vec())
}

/// Constant-time check of a full-length tag (RFC 7518 §3.2):
/// `verify_slice` fails on any length but the output size, then compares
/// with `subtle`.
fn check<M: Mac + KeyInit>(k: &[u8], signing_input: &[u8], signature: &[u8]) -> Result<()> {
    keyed::<M>(k, signing_input)?
        .verify_slice(signature)
        .map_err(|_| Error::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{b64url_decode, b64url_encode};

    /// RFC 7515 Appendix A.1: the encoded JWS Protected Header, whose JSON
    /// contains CRLF line breaks (A.1.1).
    const A1_PROTECTED: &str = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9";
    /// RFC 7515 Appendix A.1.1: the encoded JWS Payload.
    const A1_PAYLOAD: &str = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
    /// RFC 7515 Appendix A.1.1: the HMAC key, as an `oct` JWK.
    const A1_KEY: &str = r#"{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}"#;
    /// RFC 7515 Appendix A.1.1: the encoded JWS Signature.
    const A1_SIGNATURE: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    fn jwk(json: &str) -> Jwk {
        Jwk::from_json(json.as_bytes()).unwrap()
    }

    /// An `oct` JWK holding exactly `k`.
    fn oct(k: &[u8]) -> Jwk {
        jwk(&format!(r#"{{"kty":"oct","k":"{}"}}"#, b64url_encode(k)))
    }

    /// RFC 7515 A.1.1: ASCII(BASE64URL(UTF8(JWS Protected Header)) || '.' ||
    /// BASE64URL(JWS Payload)).
    fn a1_signing_input() -> Vec<u8> {
        format!("{A1_PROTECTED}.{A1_PAYLOAD}").into_bytes()
    }

    fn a1_signature() -> Vec<u8> {
        b64url_decode(A1_SIGNATURE).unwrap()
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn rfc7515_a1_signing_input_is_the_crlf_header() {
        // RFC 7515 A.1.1: the header JSON has CRLF line breaks, so only the
        // caller's exact octets reproduce the signature.
        assert_eq!(
            b64url_decode(A1_PROTECTED).unwrap(),
            b"{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}"
        );
        let input = a1_signing_input();
        // The first octets RFC 7515 A.1.1 lists for the JWS Signing Input.
        assert_eq!(
            input[..20],
            [
                101, 121, 74, 48, 101, 88, 65, 105, 79, 105, 74, 75, 86, 49, 81, 105, 76, 65, 48,
                75
            ]
        );
    }

    #[test]
    fn rfc7515_a1_hs256_signs_to_the_published_signature() {
        let sig = sign(&SigningAlg::HS256, &jwk(A1_KEY), &a1_signing_input()).unwrap();
        assert_eq!(b64url_encode(&sig), A1_SIGNATURE);
    }

    #[test]
    fn rfc7515_a1_hs256_verifies() {
        assert_eq!(
            verify(
                &SigningAlg::HS256,
                &jwk(A1_KEY),
                &a1_signing_input(),
                &a1_signature()
            ),
            Ok(())
        );
    }

    /// RFC 4231 §4.7 (Test Case 6): a 131-octet key, longer than the block,
    /// so it is long enough for every HS* (RFC 7518 §3.2). RFC 7515 has no
    /// HS384 or HS512 example.
    const RFC4231_TC6_DATA: &[u8] = b"Test Using Larger Than Block-Size Key - Hash Key First";

    fn rfc4231_tc6() -> [(SigningAlg, Vec<u8>); 3] {
        [
            (
                SigningAlg::HS256,
                hex("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"),
            ),
            (
                SigningAlg::HS384,
                hex(concat!(
                    "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f",
                    "3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952"
                )),
            ),
            (
                SigningAlg::HS512,
                hex(concat!(
                    "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352",
                    "6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598"
                )),
            ),
        ]
    }

    #[test]
    fn rfc4231_tc6_signs_and_verifies_for_every_hs_alg() {
        let key = oct(&[0xaa; 131]);
        for (alg, tag) in rfc4231_tc6() {
            assert_eq!(sign(&alg, &key, RFC4231_TC6_DATA).unwrap(), tag, "{alg}");
            assert_eq!(verify(&alg, &key, RFC4231_TC6_DATA, &tag), Ok(()), "{alg}");
        }
    }

    #[test]
    fn a_tag_of_the_wrong_length_is_an_invalid_signature() {
        // RFC 7518 §3.2: no truncated tags, and nothing appended.
        let key = jwk(A1_KEY);
        let input = a1_signing_input();
        let sig = a1_signature();
        let mut long = sig.clone();
        long.push(0);
        for bad in [&sig[..sig.len() - 1], &long[..], &sig[..16], &[][..]] {
            assert_eq!(
                verify(&SigningAlg::HS256, &key, &input, bad),
                Err(Error::InvalidSignature),
                "{} octets",
                bad.len()
            );
        }
    }

    #[test]
    fn a_flipped_bit_anywhere_is_an_invalid_signature() {
        let key = jwk(A1_KEY);
        let input = a1_signing_input();
        for at in 0..32 {
            for bit in 0..8 {
                let mut sig = a1_signature();
                sig[at] ^= 1 << bit;
                assert_eq!(
                    verify(&SigningAlg::HS256, &key, &input, &sig),
                    Err(Error::InvalidSignature),
                    "octet {at} bit {bit}"
                );
            }
        }
    }

    #[test]
    fn a_tag_over_other_input_or_under_another_hash_is_rejected() {
        let key = jwk(A1_KEY);
        let mut input = a1_signing_input();
        let last = input.len() - 1;
        input[last] ^= 1;
        assert_eq!(
            verify(&SigningAlg::HS256, &key, &input, &a1_signature()),
            Err(Error::InvalidSignature)
        );
        // The same key and input under HS384/HS512: other hash, other length.
        let key = oct(&[0xaa; 131]);
        let [(_, hs256), (_, hs384), _] = rfc4231_tc6();
        for alg in [SigningAlg::HS384, SigningAlg::HS512] {
            assert_eq!(
                verify(&alg, &key, RFC4231_TC6_DATA, &hs256),
                Err(Error::InvalidSignature),
                "{alg}"
            );
        }
        // An HS384 tag cut to 32 octets is not an HS256 tag.
        assert_eq!(
            verify(&SigningAlg::HS256, &key, RFC4231_TC6_DATA, &hs384[..32]),
            Err(Error::InvalidSignature)
        );
    }

    #[test]
    fn tags_are_compared_only_by_verify_slice() {
        // RFC 7518 §3.2 constant-time comparison: the production code (this
        // file above its tests) compares tags only through
        // `Mac::verify_slice`, never a truncated check or `==`.
        let source = include_str!("hmac.rs");
        let production = &source[..source.find("#[cfg(test)]\nmod tests").unwrap()];
        assert!(production.contains(".verify_slice(signature)"));
        for banned in ["verify_truncated", "==", "!=", "ct_eq", ".verify("] {
            assert!(!production.contains(banned), "found {banned:?}");
        }
    }

    #[test]
    fn a_key_shorter_than_the_hash_is_an_invalid_key_on_sign_and_verify() {
        // RFC 7518 §3.2: "A key of the same size as the hash output ... or
        // larger MUST be used". Checked here too, not only in key binding.
        for (alg, min) in [
            (SigningAlg::HS256, 32),
            (SigningAlg::HS384, 48),
            (SigningAlg::HS512, 64),
        ] {
            for len in [1, min / 2, min - 1] {
                let short = oct(&vec![0x42; len]);
                assert_eq!(
                    sign(&alg, &short, b"input"),
                    Err(Error::InvalidKey(SHORT_KEY)),
                    "{alg} sign, {len} octets"
                );
                // Even with the tag that key would give, the key is refused.
                let tag = vec![0; min];
                assert_eq!(
                    verify(&alg, &short, b"input", &tag),
                    Err(Error::InvalidKey(SHORT_KEY)),
                    "{alg} verify, {len} octets"
                );
            }
            let exact = oct(&vec![0x42; min]);
            let tag = sign(&alg, &exact, b"input").unwrap();
            assert_eq!(tag.len(), min, "{alg}");
            assert_eq!(verify(&alg, &exact, b"input", &tag), Ok(()), "{alg}");
        }
    }

    #[test]
    fn no_key_bytes_reach_an_error_or_debug() {
        // ADR 0007 / RFC 7518 §3.2: the secret never appears in output.
        let secret = [0x5c_u8; 31];
        let key = oct(&secret);
        let k_b64 = b64url_encode(&secret);
        let k_hex: String = secret.iter().map(|b| format!("{b:02x}")).collect();
        let errors = [
            sign(&SigningAlg::HS256, &key, b"input").unwrap_err(),
            verify(&SigningAlg::HS256, &key, b"input", &[0; 32]).unwrap_err(),
            verify(&SigningAlg::HS256, &jwk(A1_KEY), b"input", &[0; 32]).unwrap_err(),
        ];
        let a1_k = "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ";
        for text in errors
            .iter()
            .flat_map(|e| [format!("{e}"), format!("{e:?}")])
            .chain([format!("{key:?}"), format!("{:?}", jwk(A1_KEY))])
        {
            assert!(!text.contains(&k_b64), "{text}");
            assert!(!text.contains(&k_hex), "{text}");
            assert!(!text.contains(a1_k), "{text}");
            assert!(!text.contains("5c5c"), "{text}");
        }
    }

    #[test]
    fn the_keyed_hmac_state_is_wiped_on_drop() {
        // CLAUDE.md secrets rule. hmac 0.13.0's `Hmac<D>` holds its keyed
        // state as two `D::Core` values (inner and outer, RFC 2104 §2) and
        // has no `ZeroizeOnDrop` marker of its own, so the marker is checked
        // on those cores, which sha2's `zeroize` feature wipes in `Drop`.
        use hmac::EagerHash;
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<<Sha256 as EagerHash>::Core>();
        assert_zeroize_on_drop::<<Sha384 as EagerHash>::Core>();
        assert_zeroize_on_drop::<<Sha512 as EagerHash>::Core>();
    }

    #[test]
    fn a_call_against_the_contract_is_a_mismatch_not_a_panic() {
        // alg.rs contract: key binding stops these first; the family still
        // refuses them (RFC 8725 §3.1, ADR 0026 §2 step 8).
        use crate::jws::alg::test_keys;
        let ec = test_keys::p256_private("");
        assert_eq!(
            sign(&SigningAlg::HS256, &ec, b"x"),
            Err(Error::KeyAlgorithmMismatch)
        );
        assert_eq!(
            verify(&SigningAlg::HS256, &ec, b"x", &[0; 32]),
            Err(Error::KeyAlgorithmMismatch)
        );
        let key = jwk(A1_KEY);
        for alg in [SigningAlg::RS256, SigningAlg::ES256, SigningAlg::None] {
            assert_eq!(sign(&alg, &key, b"x"), Err(Error::KeyAlgorithmMismatch));
            assert_eq!(
                verify(&alg, &key, b"x", &[0; 32]),
                Err(Error::KeyAlgorithmMismatch)
            );
        }
    }
}
