//! RSA-OAEP-256 (RFC 7518 §4.3): RSAES-OAEP with SHA-256 and MGF1 with
//! SHA-256, to and from an RSA key of at least 2048 bits (ADR 0067,
//! superseding ADR 0021's encrypt-only rule).
//!
//! - **Encryption** ([`encrypt_key`]) draws the OAEP seed from
//!   `RandomSource::crypto_rng`, the crate's one `rng::CryptoRngAdapter`.
//! - **Decryption** ([`decrypt_key`]) uses the blinded
//!   `PrivateKey::oaep_decrypt_with_rng` only, with the OS CSPRNG
//!   (ADR 0005, ADR 0067 §2, §6), and never reports a CEK decryption
//!   failure: it substitutes a random CEK and goes on, so the failure shows
//!   only as the content decryption's [`Error::DecryptionFailed`]
//!   (RFC 7516 §11.5, ADR 0067 §5).
//!
//! This file, `jws/rsa.rs` and `keys/rsa.rs` are the only ones that name the
//! `rsa` crate's private-key items (ADR 0067 §6, the guards in
//! `scripts/check-deps.sh` and `scripts/check-rsa-symbols.sh`). RSA-OAEP
//! with SHA-1 is not implemented (ADR 0022), and neither is RSA1_5
//! (ADR 0067 §3).

use rsa::traits::PaddingScheme;
use subtle::{Choice, ConditionallySelectable};
use zeroize::Zeroizing;

use super::api::DecryptPolicy;
use super::content::{Cek, cek_len};
use super::key::RecipientKey;
use super::keymgmt::{KeyOutput, RecipientOptions};
use super::random::RandomSource;
use crate::header::Header;
use crate::json::Object;
use crate::jwa::{ContentEncAlg, KeyMgmtAlg};
use crate::rng::{CryptoRngAdapter, fill_random};
use crate::{Error, Result};

/// hLen of SHA-256 in octets: the length of the OAEP seed (RFC 8017
/// §7.1.1 step 2.d). The `rsa` crate draws the seed itself; only the tests
/// count it.
#[cfg(test)]
const SEED_LEN: usize = 32;

/// The smallest RSA modulus RSA-OAEP-256 accepts, in bits (RFC 7518 §4.3:
/// "A key of size 2048 bits or larger MUST be used with these
/// algorithms").
const MIN_MODULUS_BITS: u32 = 2048;

const CEK_SIZE: &str = "CEK is missing or not the size enc requires";
const MODULUS_SIZE: &str = "RSA modulus must be at least 2048 bits";
const MEMBER_SIZE: &str = "RSA key member is empty or too long";
const KEY_INVALID: &str = "RSA public key is not valid for RSA-OAEP-256";

/// Key management on encrypt (RFC 7516 §5.1 steps 3–7) for RSA-OAEP-256:
/// the random CEK encrypted to the recipient's RSA public key with
/// RSAES-OAEP-ENCRYPT (RFC 8017 §7.1.1), SHA-256 as the hash and MGF1 with
/// SHA-256 as the mask generation function, and the empty label (RFC 7518
/// §4.3: "the default parameters specified by RFC 3447 ... except for
/// using SHA-256"). The result is the JWE Encrypted Key (RFC 7516 §5.1
/// step 4), exactly k octets, k being the modulus length (RFC 8017
/// §7.1.1 step 3.c). The algorithm defines no header parameter.
///
/// The one random value is the hLen-octet OAEP seed (RFC 8017 §7.1.1 step
/// 2.d), drawn through `rng.crypto_rng()` at this recipient's place in
/// the draw order of `jwe::random`. The key checks run first, so a
/// refused key draws nothing.
///
/// The key is imported with `rsa::PublicKey::new` (RFC 8017 §3.1: n
/// odd, e odd and 1 < e < n; at most 8192 bits). `jwk` import has already
/// bounded the modulus to 2048..=8192 bits (`jwk::RSA_MODULUS_BITS`;
/// RFC 7518 §4.3, ADR 0026 §2 step 8).
///
/// # Errors
///
/// - [`Error::UnsupportedAlgorithm`] for an `alg` other than RSA-OAEP-256
///   (RSA-OAEP, ADR 0022) or an unknown `enc`;
/// - [`Error::KeyAlgorithmMismatch`] for a key that is not an RSA public
///   key (RFC 7518 §4.3, RFC 8725 §3.1);
/// - [`Error::InvalidKey`] for a modulus under 2048 bits, a malformed
///   public key, or a CEK that is missing or not the length `enc`
///   requires (RFC 7516 §5.1 step 2);
/// - [`Error::RandomnessUnavailable`] if `rng` cannot supply the seed
///   (ADR 0005).
pub(super) fn encrypt_key(
    alg: &KeyMgmtAlg,
    key: &RecipientKey,
    enc: &ContentEncAlg,
    cek: Option<&Cek>,
    _options: &RecipientOptions,
    rng: &mut dyn RandomSource,
) -> Result<KeyOutput> {
    if *alg != KeyMgmtAlg::RsaOaep256 {
        return Err(Error::UnsupportedAlgorithm);
    }
    let RecipientKey::RsaPublic { n, e } = key else {
        return Err(Error::KeyAlgorithmMismatch);
    };
    let cek_len = cek_len(enc)?;
    let cek = cek
        .filter(|cek| cek.len() == cek_len)
        .ok_or(Error::InvalidKey(CEK_SIZE))?;
    let public = public_key(n, e)?;
    let mut seed_rng = rng.crypto_rng();
    let encrypted_key = rsa::Oaep::<sha2::Sha256>::new()
        .encrypt(&mut seed_rng, &public, cek.as_bytes())
        .map_err(|err| match err {
            rsa::errors::Error::Rng => Error::RandomnessUnavailable,
            // A CEK of at most 64 octets always fits: k − 2·hLen − 2 is at
            // least 190 for 2048 bits (RFC 8017 §7.1.1 step 1.b).
            _ => Error::InvalidKey(KEY_INVALID),
        })?;
    Ok(KeyOutput {
        encrypted_key,
        header_params: Object::new(),
        cek: None,
    })
}

/// Key management for decryption (RFC 7516 §5.2 steps 9–10) with RSA-OAEP-256:
/// the JWE Encrypted Key decrypted with RSAES-OAEP-DECRYPT (RFC 8017
/// §7.1.2), SHA-256 and MGF1-SHA-256 and the empty label (RFC 7518 §4.3),
/// through the blinded `PrivateKey::oaep_decrypt_with_rng` with the OS
/// CSPRNG (ADR 0005, ADR 0067 §2).
///
/// **No CEK decryption failure is ever reported (RFC 7516 §11.5,
/// ADR 0067 §5).** RFC 7516 §11.5: the recipient "MUST NOT distinguish
/// between format, padding, and length errors of encrypted keys", and "It
/// is strongly recommended, in the event of receiving an improperly
/// formatted key, that the recipient substitute a randomly generated CEK
/// and proceed to the next step, to mitigate timing attacks." So:
///
/// 1. a random CEK of the `enc` length is drawn first, whatever the input;
/// 2. the Encrypted Key is decrypted (it may fail: a wrong length, a value
///    of at least n, bad OAEP padding or label hash; RFC 8017 §7.1.2);
/// 3. the result is the decrypted CEK if decryption succeeded with exactly
///    the `enc` length (RFC 7516 §5.2 step 10), and otherwise the random
///    one, chosen byte by byte with `subtle`, so this layer does the same
///    work on either path.
///
/// The content decryption then fails its tag check with the random CEK
/// (RFC 7516 §5.2 step 16), which `core` reports as
/// [`Error::DecryptionFailed`], the same error by the same path as a
/// tampered tag. The `rsa` crate's OAEP decoding is constant-time up to its
/// final result; this layer adds no branch on why it failed.
///
/// The private key is built here (validated, CRT values precomputed) for
/// each candidate recipient: each costs one private-key build and one
/// blinded private-key operation, at most `max_recipients` per decrypt
/// call (`DecryptPolicy`).
///
/// # Errors
///
/// [`Error::UnsupportedAlgorithm`] for an `alg` other than RSA-OAEP-256 or
/// an unknown `enc`, [`Error::KeyAlgorithmMismatch`] for a key that is not
/// an RSA private key, [`Error::InvalidKey`] if the private key cannot be
/// built (import rules that out), and [`Error::RandomnessUnavailable`] only
/// if the OS CSPRNG cannot supply the substitute CEK of step 1 (ADR 0005). A
/// blinding RNG failure inside the RSA decryption is not reported: like
/// any other decryption failure, it leaves the random CEK in place
/// (RFC 7516 §11.5). `core` reports every error as
/// [`Error::DecryptionFailed`]. No error depends on the Encrypted Key.
pub(super) fn decrypt_key(
    alg: &KeyMgmtAlg,
    key: &RecipientKey,
    enc: &ContentEncAlg,
    _header: &Header,
    encrypted_key: &[u8],
    _policy: &DecryptPolicy,
) -> Result<Cek> {
    if *alg != KeyMgmtAlg::RsaOaep256 {
        return Err(Error::UnsupportedAlgorithm);
    }
    let RecipientKey::RsaPrivate(jwk_key) = key else {
        return Err(Error::KeyAlgorithmMismatch);
    };
    let cek_len = cek_len(enc)?;
    let private = crate::keys::rsa::private_key(jwk_key)?;
    // RFC 7516 §11.5: the substitute, drawn before the Encrypted Key is
    // looked at.
    let mut cek = Zeroizing::new(vec![0u8; cek_len]);
    fill_random(&mut cek)?;
    let decrypted = unwrap(&private, encrypted_key, &mut CryptoRngAdapter::os());
    #[cfg(test)]
    crate::test_counters::rsa_oaep_unwraps::tick();
    let decrypted: &[u8] = match &decrypted {
        Ok(plaintext) => plaintext,
        Err(_) => &[],
    };
    let valid = Choice::from(u8::from(decrypted.len() == cek_len));
    for (index, byte) in cek.iter_mut().enumerate() {
        let candidate = decrypted.get(index).copied().unwrap_or(0);
        byte.conditional_assign(&candidate, valid);
    }
    Ok(Cek::new(cek))
}

/// RSAES-OAEP-DECRYPT (RFC 8017 §7.1.2) with SHA-256, MGF1-SHA-256 and the
/// empty label (RFC 7518 §4.3), blinded with `rng` (ADR 0067 §2): the
/// decrypted octets in a buffer wiped on drop.
///
/// # Errors
///
/// [`Error::DecryptionFailed`] for any decryption error (RFC 8017 §7.1.2:
/// "decryption error", whatever the cause; RFC 7516 §11.5),
/// [`Error::RandomnessUnavailable`] if the blinding RNG fails. Either way
/// [`decrypt_key`] discards the error and keeps the random CEK.
fn unwrap(
    private: &rsa::PrivateKey,
    encrypted_key: &[u8],
    rng: &mut CryptoRngAdapter<'_>,
) -> Result<Zeroizing<Vec<u8>>> {
    private
        .oaep_decrypt_with_rng::<sha2::Sha256, _>(rng, encrypted_key)
        .map(Zeroizing::new)
        .map_err(|err| match err {
            rsa::errors::Error::Rng => Error::RandomnessUnavailable,
            _ => Error::DecryptionFailed,
        })
}

/// The `rsa` crate's public key for the big-endian modulus `n` and public
/// exponent `e` (RFC 7518 §6.3.1.1–§6.3.1.2, OS2IP of RFC 8017 §4.2),
/// refusing a modulus under [`MIN_MODULUS_BITS`] (RFC 7518 §4.3) before
/// `rsa::PublicKey::new` checks the rest (RFC 8017 §3.1). The error
/// detail names the rule, never the values (ADR 0007).
fn public_key(n: &[u8], e: &[u8]) -> Result<rsa::PublicKey> {
    let (n, e) = (uint(n)?, uint(e)?);
    if n.bit_width() < MIN_MODULUS_BITS {
        return Err(Error::InvalidKey(MODULUS_SIZE));
    }
    rsa::PublicKey::new(n, e).map_err(|_| Error::InvalidKey(KEY_INVALID))
}

/// The unsigned integer of the big-endian `bytes` (OS2IP, RFC 8017
/// §4.2), with a precision of 8 bits per octet. Empty input is no
/// integer.
fn uint(bytes: &[u8]) -> Result<rsa::BoxedUint> {
    let bits = u32::try_from(bytes.len())
        .ok()
        .and_then(|len| len.checked_mul(8))
        .filter(|&bits| bits > 0)
        .ok_or(Error::InvalidKey(MEMBER_SIZE))?;
    rsa::BoxedUint::from_be_slice(bytes, bits).map_err(|_| Error::InvalidKey(MEMBER_SIZE))
}

#[cfg(test)]
mod tests {
    use super::super::random::OsRandom;
    use super::*;
    use crate::rng::insecure_test_vectors::FixedRng;

    const F4: &[u8] = &[1, 0, 1];

    /// An odd modulus of exactly `bits` bits (all ones). It is no product
    /// of two primes, but RSAEP (RFC 8017 §5.1.1) only needs n and e.
    fn modulus(bits: usize) -> Vec<u8> {
        let mut n = vec![0xff; bits.div_ceil(8)];
        n[0] >>= (8 - bits % 8) % 8;
        n
    }

    fn key(bits: usize) -> RecipientKey {
        RecipientKey::RsaPublic {
            n: modulus(bits),
            e: F4.to_vec(),
        }
    }

    fn cek(enc: &ContentEncAlg) -> Cek {
        let len = super::super::content::cek_len(enc).unwrap();
        Cek::from_slice(&vec![0x5a; len])
    }

    fn seed() -> FixedRng {
        FixedRng::new([0x42u8; SEED_LEN])
    }

    fn run(
        key: &RecipientKey,
        enc: &ContentEncAlg,
        cek: Option<&Cek>,
        rng: &mut dyn RandomSource,
    ) -> Result<KeyOutput> {
        encrypt_key(
            &KeyMgmtAlg::RsaOaep256,
            key,
            enc,
            cek,
            &RecipientOptions::default(),
            rng,
        )
    }

    #[test]
    fn the_encrypted_key_is_k_octets_and_defines_no_header_parameter() {
        // RFC 8017 §7.1.1 step 3.c: the ciphertext C is an octet string of
        // length k, the modulus length; RFC 7518 §4.3 adds no parameter.
        for bits in [2048, 3072, 4096, 4097, 8192] {
            for enc in ContentEncAlg::KNOWN {
                let cek = cek(enc);
                let mut rng = seed();
                let out = run(&key(bits), enc, Some(&cek), &mut rng).unwrap();
                assert_eq!(out.encrypted_key.len(), bits.div_ceil(8), "{bits} {enc}");
                assert!(out.header_params.is_empty(), "{bits} {enc}");
                assert!(out.cek.is_none(), "{bits} {enc}: the random CEK is used");
            }
        }
    }

    #[test]
    fn the_oaep_seed_is_one_draw_of_hlen_octets() {
        // RFC 8017 §7.1.1 step 2.d: a random octet string seed of length
        // hLen (32 for SHA-256), drawn through `crypto_rng` from the same
        // stream as the CEK and IV (the `jwe::random` draw order).
        let enc = ContentEncAlg::A128GCM;
        let cek = cek(&enc);
        let mut rng = FixedRng::new([0x42u8; SEED_LEN + 3]);
        run(&key(2048), &enc, Some(&cek), &mut rng).unwrap();
        assert_eq!(rng.remaining(), 3);
    }

    #[test]
    fn the_same_seed_gives_the_same_encrypted_key_and_another_seed_another() {
        // RSAES-OAEP is deterministic given the seed (RFC 8017 §7.1.1), so
        // `FixedRng` vectors are byte-exact; any seed change changes C.
        let enc = ContentEncAlg::A256CbcHs512;
        let cek = cek(&enc);
        let first = run(&key(2048), &enc, Some(&cek), &mut seed()).unwrap();
        let again = run(&key(2048), &enc, Some(&cek), &mut seed()).unwrap();
        assert_eq!(first.encrypted_key, again.encrypted_key);
        let mut other = [0x42u8; SEED_LEN];
        other[SEED_LEN - 1] ^= 1;
        let other = run(&key(2048), &enc, Some(&cek), &mut FixedRng::new(other)).unwrap();
        assert_ne!(first.encrypted_key, other.encrypted_key);
    }

    #[test]
    fn the_os_source_gives_a_fresh_seed_each_time() {
        // ADR 0005: production draws the seed from the OS CSPRNG, so two
        // encryptions of one CEK differ (equal seeds: a 2^-256 event).
        let enc = ContentEncAlg::A128GCM;
        let cek = cek(&enc);
        let a = run(&key(2048), &enc, Some(&cek), &mut OsRandom).unwrap();
        let b = run(&key(2048), &enc, Some(&cek), &mut OsRandom).unwrap();
        assert_eq!(a.encrypted_key.len(), 256);
        assert_ne!(a.encrypted_key, b.encrypted_key);
    }

    #[test]
    fn a_short_source_fails_closed() {
        // ADR 0005: a source that cannot supply the whole seed is
        // RandomnessUnavailable, never a short or padded seed.
        let enc = ContentEncAlg::A128GCM;
        let cek = cek(&enc);
        let mut rng = FixedRng::new([0x42u8; SEED_LEN - 1]);
        let out = run(&key(2048), &enc, Some(&cek), &mut rng);
        assert_eq!(out.err(), Some(Error::RandomnessUnavailable));
    }

    #[test]
    fn a_modulus_under_2048_bits_is_an_invalid_key() {
        // RFC 7518 §4.3: "A key of size 2048 bits or larger MUST be used
        // with these algorithms." Import refuses such a JWK already; this
        // holds for any `RecipientKey` too, and draws nothing.
        let enc = ContentEncAlg::A128GCM;
        let cek = cek(&enc);
        for bits in [512, 1024, 2047] {
            let mut rng = seed();
            let out = run(&key(bits), &enc, Some(&cek), &mut rng);
            assert!(matches!(out, Err(Error::InvalidKey(_))), "{bits}");
            assert_eq!(rng.remaining(), SEED_LEN, "{bits}");
        }
    }

    #[test]
    fn a_malformed_public_key_is_an_invalid_key() {
        // RFC 8017 §3.1: n is odd and 1 < e < n, e odd.
        let enc = ContentEncAlg::A128GCM;
        let cek = cek(&enc);
        let mut even = modulus(2048);
        *even.last_mut().unwrap() &= 0xfe;
        let cases = [
            (even, F4.to_vec()),
            (modulus(2048), vec![2]),
            (modulus(2048), vec![1]),
            (modulus(2048), Vec::new()),
            (Vec::new(), F4.to_vec()),
        ];
        for (n, e) in cases {
            let key = RecipientKey::RsaPublic { n, e };
            let out = run(&key, &enc, Some(&cek), &mut seed());
            assert!(matches!(out, Err(Error::InvalidKey(_))), "{key:?}");
        }
    }

    #[test]
    fn a_missing_or_wrong_size_cek_is_an_invalid_key() {
        // RFC 7516 §5.1 step 2: the CEK has the length `enc` requires.
        let enc = ContentEncAlg::A128GCM;
        assert!(matches!(
            run(&key(2048), &enc, None, &mut seed()),
            Err(Error::InvalidKey(_))
        ));
        let long = Cek::from_slice(&[0x5a; 32]);
        assert!(matches!(
            run(&key(2048), &enc, Some(&long), &mut seed()),
            Err(Error::InvalidKey(_))
        ));
    }

    #[test]
    fn only_an_rsa_public_key_serves_and_only_rsa_oaep_256() {
        // RFC 8725 §3.1 and RFC 7518 §4.3: the alg names one key family;
        // RSA-OAEP (SHA-1) is not implemented (ADR 0022).
        let enc = ContentEncAlg::A128GCM;
        let cek = cek(&enc);
        let oct = RecipientKey::Symmetric(zeroize::Zeroizing::new(vec![0u8; 16]));
        assert_eq!(
            run(&oct, &enc, Some(&cek), &mut seed()).err(),
            Some(Error::KeyAlgorithmMismatch)
        );
        for alg in [KeyMgmtAlg::from("RSA-OAEP"), KeyMgmtAlg::A128KW] {
            let out = encrypt_key(
                &alg,
                &key(2048),
                &enc,
                Some(&cek),
                &RecipientOptions::default(),
                &mut seed(),
            );
            assert_eq!(out.err(), Some(Error::UnsupportedAlgorithm), "{alg}");
        }
        let unknown = ContentEncAlg::from("A128CTR");
        assert_eq!(
            run(&key(2048), &unknown, Some(&cek), &mut seed()).err(),
            Some(Error::UnsupportedAlgorithm)
        );
    }

    // ---- Decryption (ADR 0067) ----

    use crate::jwe::{Encryptor, JsonForm, Recipient, decrypt_compact, decrypt_json};
    use crate::jwk::{Jwk, KeyMaterial};
    use crate::util::{b64url_decode, b64url_encode};

    /// The RSA private key of RFC 7515 Appendix A.2.1 (2048 bits).
    fn private_jwk() -> Jwk {
        Jwk::from_json(include_bytes!(
            "../../tests/data/keys/rfc/rfc7515-a2-rsa-private.jwk.json"
        ))
        .unwrap()
    }

    fn private_key() -> RecipientKey {
        let KeyMaterial::Rsa(key) = private_jwk().material().clone() else {
            panic!("RSA");
        };
        RecipientKey::RsaPrivate(key)
    }

    fn public_key() -> RecipientKey {
        let KeyMaterial::Rsa(key) = private_jwk().material().clone() else {
            panic!("RSA");
        };
        RecipientKey::RsaPublic {
            n: key.n().to_vec(),
            e: key.e().to_vec(),
        }
    }

    fn policy() -> DecryptPolicy {
        DecryptPolicy::new(&[KeyMgmtAlg::RsaOaep256], ContentEncAlg::KNOWN).unwrap()
    }

    fn unwrap_key(key: &RecipientKey, enc: &ContentEncAlg, encrypted_key: &[u8]) -> Result<Cek> {
        decrypt_key(
            &KeyMgmtAlg::RsaOaep256,
            key,
            enc,
            &Header::new(),
            encrypted_key,
            &policy(),
        )
    }

    #[test]
    fn decrypt_key_recovers_what_encrypt_key_encrypted() {
        // RFC 8017 §7.1.2 inverts §7.1.1 (SHA-256, MGF1-SHA-256, empty
        // label; RFC 7518 §4.3), for every `enc` CEK length.
        for enc in ContentEncAlg::KNOWN {
            let cek = cek(enc);
            let out = run(&public_key(), enc, Some(&cek), &mut OsRandom).unwrap();
            let back = unwrap_key(&private_key(), enc, &out.encrypted_key).unwrap();
            assert_eq!(back.as_bytes(), cek.as_bytes(), "{enc}");
        }
    }

    #[test]
    fn a_bad_encrypted_key_yields_a_random_cek_not_an_error() {
        // RFC 7516 §11.5, ADR 0067 §5: no format, padding or length error of
        // the Encrypted Key is reported; a fresh random CEK of the `enc`
        // length takes its place.
        let enc = ContentEncAlg::A128GCM;
        let cek = cek(&enc);
        let good = run(&public_key(), &enc, Some(&cek), &mut OsRandom)
            .unwrap()
            .encrypted_key;
        let mut flipped = good.clone();
        flipped[17] ^= 0x01;
        let mut too_long = good.clone();
        too_long.push(0);
        let at_least_n = vec![0xFF; 256];
        // A CEK of the wrong length for `enc` (RFC 7516 §5.2 step 10):
        // a valid OAEP plaintext of 32 octets for A128GCM's 16.
        let long_cek = Cek::from_slice(&[0x5a; 32]);
        let wrong_length = run(
            &public_key(),
            &ContentEncAlg::A256GCM,
            Some(&long_cek),
            &mut OsRandom,
        )
        .unwrap()
        .encrypted_key;
        for (what, ek) in [
            ("empty", Vec::new()),
            ("one octet", vec![0]),
            ("a flipped bit", flipped),
            ("k + 1 octets", too_long),
            ("a value of at least n", at_least_n),
            ("zero", vec![0; 256]),
            ("a 32-octet CEK for A128GCM", wrong_length),
        ] {
            let first = unwrap_key(&private_key(), &enc, &ek).unwrap();
            let second = unwrap_key(&private_key(), &enc, &ek).unwrap();
            assert_eq!(first.len(), 16, "{what}");
            assert_ne!(first.as_bytes(), cek.as_bytes(), "{what}");
            assert_ne!(
                first.as_bytes(),
                second.as_bytes(),
                "{what}: a fresh CEK each time"
            );
        }
    }

    #[test]
    fn decrypt_key_refuses_other_algs_and_keys_before_reading_the_encrypted_key() {
        // RFC 7518 §4.3, RFC 8725 §3.1: RSA-OAEP-256 and an RSA private key
        // only; RSA-OAEP (SHA-1, ADR 0022) and RSA1_5 (ADR 0067 §3) are not
        // implemented.
        let enc = ContentEncAlg::A128GCM;
        for alg in [
            KeyMgmtAlg::from("RSA-OAEP"),
            KeyMgmtAlg::from("RSA1_5"),
            KeyMgmtAlg::A128KW,
        ] {
            let result = decrypt_key(
                &alg,
                &private_key(),
                &enc,
                &Header::new(),
                &[0; 256],
                &policy(),
            );
            assert_eq!(result.err(), Some(Error::UnsupportedAlgorithm), "{alg}");
        }
        assert_eq!(
            unwrap_key(&public_key(), &enc, &[0; 256]).err(),
            Some(Error::KeyAlgorithmMismatch)
        );
        assert_eq!(
            unwrap_key(&private_key(), &ContentEncAlg::from("A128CTR"), &[0; 256]).err(),
            Some(Error::UnsupportedAlgorithm)
        );
    }

    /// A compact RSA-OAEP-256 JWE of `plaintext` to the RFC 7515 A.2 key.
    fn compact(enc: ContentEncAlg, plaintext: &[u8]) -> String {
        Encryptor::new(enc)
            .recipient(Recipient::new(
                KeyMgmtAlg::RsaOaep256,
                &private_jwk().to_public().unwrap(),
            ))
            .encrypt_compact(plaintext)
            .unwrap()
    }

    /// `jwe` with one octet of compact part `part` changed.
    fn tampered(jwe: &str, part: usize) -> String {
        let mut parts: Vec<String> = jwe.split('.').map(str::to_owned).collect();
        let mut octets = b64url_decode(&parts[part]).unwrap();
        octets[0] ^= 0x80;
        parts[part] = b64url_encode(&octets);
        parts.join(".")
    }

    #[test]
    fn a_bad_encrypted_key_fails_like_a_bad_tag_by_the_same_path() {
        // RFC 7516 §11.5, ADR 0067 §5: a malformed Encrypted Key and a
        // tampered tag give the same error, DecryptionFailed with no
        // detail, and both run one RSA decryption and then one content
        // decryption (the counters of `test_counters`): the random CEK goes
        // on to the tag check, as a wrong tag does.
        use crate::test_counters::{content_decryptions, rsa_oaep_unwraps};
        let key = private_jwk();
        for enc in ContentEncAlg::KNOWN {
            let jwe = compact(enc.clone(), b"RFC 7516 section 11.5");
            let ok = decrypt_compact(&jwe, &key, &policy()).unwrap();
            assert_eq!(ok.plaintext(), b"RFC 7516 section 11.5");
            for part in [1, 4] {
                let bad = tampered(&jwe, part);
                let ((result, unwraps), decryptions) = content_decryptions::count(|| {
                    rsa_oaep_unwraps::count(|| decrypt_compact(&bad, &key, &policy()))
                });
                let error = result.unwrap_err();
                assert_eq!(error, Error::DecryptionFailed, "{enc} part {part}");
                assert_eq!(format!("{error:?}"), "DecryptionFailed");
                assert_eq!((unwraps, decryptions), (1, 1), "{enc} part {part}");
            }
        }
    }

    #[test]
    fn rsa_oaep_256_decrypts_compact_json_and_multi_recipient() {
        // RFC 7516 §7.1, §7.2.1, §7.2.2: every serialization, and the RSA
        // recipient among others (RFC 7516 §5.2 step 18: the first
        // candidate that decrypts wins).
        let key = private_jwk();
        let public = key.to_public().unwrap();
        let plaintext = b"Live long and prosper.";
        let jwe = compact(ContentEncAlg::A256CbcHs512, plaintext);
        assert_eq!(
            decrypt_compact(&jwe, &key, &policy()).unwrap().plaintext(),
            plaintext
        );
        let flattened = Encryptor::new(ContentEncAlg::A256GCM)
            .recipient(Recipient::new(KeyMgmtAlg::RsaOaep256, &public))
            .encrypt_json(plaintext, JsonForm::Flattened)
            .unwrap();
        assert_eq!(
            decrypt_json(&flattened, &key, &policy())
                .unwrap()
                .plaintext(),
            plaintext
        );
        let other = Jwk::from_json(br#"{"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg"}"#).unwrap();
        let general = Encryptor::new(ContentEncAlg::A128GCM)
            .recipient(Recipient::new(KeyMgmtAlg::A128KW, &other))
            .recipient(Recipient::new(KeyMgmtAlg::RsaOaep256, &public))
            .encrypt_json(plaintext, JsonForm::General)
            .unwrap();
        let both = DecryptPolicy::new(
            &[KeyMgmtAlg::RsaOaep256, KeyMgmtAlg::A128KW],
            &[ContentEncAlg::A128GCM],
        )
        .unwrap();
        let decrypted = decrypt_json(&general, &key, &both).unwrap();
        assert_eq!(
            (decrypted.plaintext(), decrypted.recipient()),
            (&plaintext[..], 1)
        );
        assert_eq!(
            decrypt_json(&general, &other, &both).unwrap().recipient(),
            0
        );
        // The public key is no candidate (RFC 7518 §4.3: decryption needs
        // the private key).
        assert_eq!(
            decrypt_compact(&jwe, &public, &policy()).err(),
            Some(Error::KeyAlgorithmMismatch)
        );
    }

    #[test]
    fn sixteen_kidless_rsa_recipients_decrypt_under_the_default_limit() {
        // Feature 0020 review (decrypt amplification): with no `kid`, every
        // RSA-OAEP-256 recipient is a candidate (RFC 7516 §4.1.6), each
        // costing one private-key build and operation, bounded by
        // `max_recipients` (default 16, ADR 0026 §7). A JWE at that bound
        // still decrypts: the first recipient succeeds after one unwrap,
        // and with a bad tag every recipient is tried once.
        use crate::test_counters::rsa_oaep_unwraps;
        assert_eq!(DecryptPolicy::DEFAULT_MAX_RECIPIENTS, 16);
        let key = private_jwk();
        let public = key.to_public().unwrap();
        let mut encryptor = Encryptor::new(ContentEncAlg::A128GCM);
        for _ in 0..16 {
            encryptor = encryptor.recipient(Recipient::new(KeyMgmtAlg::RsaOaep256, &public));
        }
        let jwe = encryptor.encrypt_json(b"16", JsonForm::General).unwrap();
        assert_eq!(jwe.matches("\"encrypted_key\"").count(), 16);
        assert!(!jwe.contains("\"kid\""));
        let counted = |jwe: &str| {
            let (result, unwraps) = rsa_oaep_unwraps::count(|| decrypt_json(jwe, &key, &policy()));
            (
                result.map(|d| (d.recipient(), d.plaintext().to_vec())),
                unwraps,
            )
        };
        assert_eq!(counted(&jwe), (Ok((0, b"16".to_vec())), 1));
        // A tampered tag fails every candidate, each tried once.
        let (start, _) = jwe.match_indices("\"tag\":\"").next().unwrap();
        let start = start + "\"tag\":\"".len();
        let end = start + jwe[start..].find('"').unwrap();
        let mut tag = b64url_decode(&jwe[start..end]).unwrap();
        tag[0] ^= 0x01;
        let bad = format!("{}{}{}", &jwe[..start], b64url_encode(&tag), &jwe[end..]);
        assert_eq!(counted(&bad), (Err(Error::DecryptionFailed), 16));
    }

    #[test]
    fn rsa_oaep_with_sha_1_stays_unsupported_even_with_the_private_key() {
        // ADR 0022: `RSA-OAEP` (SHA-1; RFC 7516 A.1, RFC 7520 §5.2) is never
        // decrypted, whatever the key and the allow-list: the header `alg`
        // of an RSA-OAEP-256 JWE renamed to RSA-OAEP is UnsupportedAlgorithm.
        let jwe = compact(ContentEncAlg::A128GCM, b"x");
        let mut parts: Vec<&str> = jwe.split('.').collect();
        let header = b64url_encode(br#"{"alg":"RSA-OAEP","enc":"A128GCM"}"#);
        parts[0] = &header;
        let renamed = parts.join(".");
        let sha1 = DecryptPolicy::new(
            &[KeyMgmtAlg::from("RSA-OAEP"), KeyMgmtAlg::RsaOaep256],
            &[ContentEncAlg::A128GCM],
        )
        .unwrap();
        assert_eq!(
            decrypt_compact(&renamed, &private_jwk(), &sha1).err(),
            Some(Error::UnsupportedAlgorithm)
        );
    }

    /// The Wycheproof RSAES-OAEP tests whose decryption result the `rsa`
    /// crate decides against Wycheproof's `result` (see
    /// [`wycheproof_rsa_oaep_sha256_mgf1sha256`]): `(suite, tcId)`.
    ///
    /// rsa 0.10.0 does not check that the first octet Y of EM is zero
    /// (RFC 8017 §7.1.2 step 3.g); its own `decrypt_ignores_first_octet`
    /// test pins that. So "First byte is 1" (`invalid`) decrypts to its
    /// message. RSA-OAEP-256 in JWE is not weakened by it: anyone holding
    /// the public key can already make a valid encryption of any CEK, and
    /// the CEK is authenticated by the content tag (RFC 7516 §5.2 step 16)
    /// and never reported on failure (RFC 7516 §11.5). polyjose has no way
    /// to add the check without the rsa crate's raw RSA API, which ADR 0067 §3
    /// keeps out; it is recorded here so an upstream change shows.
    const OAEP_FIRST_OCTET_IGNORED: &[(&str, u32)] = &[
        ("rsa_oaep_2048_sha256_mgf1sha256", 23),
        ("rsa_oaep_3072_sha256_mgf1sha256", 23),
        ("rsa_oaep_4096_sha256_mgf1sha256", 23),
    ];

    #[test]
    fn wycheproof_rsa_oaep_sha256_mgf1sha256() {
        // RFC 7518 §4.3: RSA-OAEP-256 is RSAES-OAEP (RFC 8017 §7.1.2) with
        // SHA-256, MGF1-SHA-256 and the empty label. Every group with that
        // hash pair and a usable key (2048 to 8192 bits, RFC 7518 §4.3,
        // ADR 0026 §2 step 8) is run through the blinded decryption; a
        // smaller key is refused at JWK import. A test with a non-empty
        // label is a different OAEP instance, which polyjose never decrypts
        // (it always uses the empty label), so it must fail like an
        // `invalid` one; that includes the two `acceptable` ones (tcIds 376
        // and 385 of `rsa_oaep_misc`, small-integer EMs with a label).
        use crate::test_support::wycheproof::{self, Expected};
        let (mut decrypted, mut rejected, mut labelled, mut small) = (0, 0, 0, 0);
        let mut first_octet = Vec::new();
        for name in wycheproof::names("rsa_oaep_") {
            let suite = wycheproof::load(name);
            for group in &suite.groups {
                if (group.sha.as_deref(), group.mgf_sha.as_deref())
                    != (Some("SHA-256"), Some("SHA-256"))
                {
                    continue;
                }
                let jwk = Jwk::from_json(group.private_key_jwk.as_deref().unwrap().as_bytes());
                if group.key_size.is_some_and(|bits| bits < 2048) {
                    assert!(matches!(jwk, Err(Error::InvalidKey(_))), "{name}");
                    small += 1;
                    continue;
                }
                let jwk = jwk.unwrap_or_else(|e| panic!("{name}: {e:?}"));
                let KeyMaterial::Rsa(key) = jwk.material() else {
                    panic!("RSA")
                };
                let private = crate::keys::rsa::private_key(key).unwrap();
                for test in &group.tests {
                    let (msg, ct, label) = test.oaep();
                    let got = unwrap(&private, ct, &mut CryptoRngAdapter::os());
                    if OAEP_FIRST_OCTET_IGNORED.contains(&(name, test.tc_id)) {
                        assert_eq!(test.result, Expected::Invalid, "{name} tcId {}", test.tc_id);
                        assert_eq!(
                            got.as_deref().map(|m| &m[..]),
                            Ok(msg),
                            "{name} tcId {}",
                            test.tc_id
                        );
                        first_octet.push((name, test.tc_id));
                        continue;
                    }
                    if test.result == Expected::Acceptable {
                        assert!(
                            !label.is_empty(),
                            "{name} tcId {}: decide and list it",
                            test.tc_id
                        );
                    }
                    if test.result != Expected::Invalid && label.is_empty() {
                        assert_eq!(
                            got.as_deref().map(|m| &m[..]),
                            Ok(msg),
                            "{name} tcId {}",
                            test.tc_id
                        );
                        decrypted += 1;
                    } else {
                        assert_eq!(
                            got.err(),
                            Some(Error::DecryptionFailed),
                            "{name} tcId {}",
                            test.tc_id
                        );
                        if label.is_empty() {
                            rejected += 1;
                        } else {
                            labelled += 1;
                        }
                    }
                }
            }
        }
        assert_eq!(first_octet, OAEP_FIRST_OCTET_IGNORED);
        // 42 decrypted, 54 rejected with the empty label, 40 with a label,
        // and 2 groups of keys under 2048 bits refused at import.
        assert_eq!((decrypted, rejected, labelled, small), (42, 54, 40, 2));
    }
}
