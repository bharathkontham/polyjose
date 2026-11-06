//! RSA-OAEP-256 (RFC 7518 §4.3): RSAES-OAEP with SHA-256 and MGF1 with
//! SHA-256, to an RSA public key of at least 2048 bits. **Encryption
//! only** (ADR 0021): polyjose performs no RSA private-key operation, so
//! the dispatcher in `keymgmt` answers RSA-OAEP-256 on the receiving side
//! with `UnsupportedAlgorithm` itself and never reaches this file, and an
//! RSA private JWK never imports (`jwk`). The OAEP seed comes from
//! `RandomSource::crypto_rng`, the crate's one `rng::CryptoRngAdapter`.
//!
//! This file and `jws/rsa.rs` are the only ones that name the `rsa` crate
//! (ADR 0021 §3, the guard in `scripts/check-deps.sh`). RSA-OAEP with
//! SHA-1 is not implemented (ADR 0022), and neither is RSA1_5 (ADR 0021).

use rsa::traits::PaddingScheme;

use super::content::{Cek, cek_len};
use super::key::RecipientKey;
use super::keymgmt::{KeyOutput, RecipientOptions};
use super::random::RandomSource;
use crate::json::Object;
use crate::jwa::{ContentEncAlg, KeyMgmtAlg};
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
/// The key is imported with `rsa::RsaPublicKey::new` (RFC 8017 §3.1: n
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

/// The `rsa` crate's public key for the big-endian modulus `n` and public
/// exponent `e` (RFC 7518 §6.3.1.1–§6.3.1.2, OS2IP of RFC 8017 §4.2),
/// refusing a modulus under [`MIN_MODULUS_BITS`] (RFC 7518 §4.3) before
/// `rsa::RsaPublicKey::new` checks the rest (RFC 8017 §3.1). The error
/// detail names the rule, never the values (ADR 0007).
fn public_key(n: &[u8], e: &[u8]) -> Result<rsa::RsaPublicKey> {
    let (n, e) = (uint(n)?, uint(e)?);
    if n.bits() < MIN_MODULUS_BITS {
        return Err(Error::InvalidKey(MODULUS_SIZE));
    }
    rsa::RsaPublicKey::new(n, e).map_err(|_| Error::InvalidKey(KEY_INVALID))
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
}
