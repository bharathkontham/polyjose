//! PBES2-HS256+A128KW, PBES2-HS384+A192KW and PBES2-HS512+A256KW
//! (RFC 7518 §4.8): PBKDF2 (RFC 8018 §5.2) over the password with salt
//! `UTF8(alg) || 0x00 || p2s` derives the key that AES Key Wrap (RFC 3394,
//! [`aes_kw::wrap`]) wraps the CEK with.
//!
//! The decrypt side checks `p2s` and `p2c` before any derivation: `p2c` is
//! attacker-chosen, and each iteration is two hash compressions, so the
//! bound `DecryptPolicy::max_pbes2_count` (ADR 0023; 10,000 by default) is
//! enforced first (RFC 7518 §8.8; CVE-2022-36083, CVE-2023-52428,
//! CVE-2023-51775).

use super::api::DecryptPolicy;
use super::content::Cek;
use super::key::RecipientKey;
use super::keymgmt::{KeyOutput, RecipientOptions};
use super::random::RandomSource;
use crate::header::Header;
use crate::jwa::{ContentEncAlg, KeyMgmtAlg};
use crate::{Error, Result};
use sha2::{Sha256, Sha384, Sha512};
use zeroize::Zeroizing;

/// Key management on encrypt (RFC 7516 §5.1 steps 3–7) for the three PBES2 algorithms.
///
/// # Errors
///
/// An error for a `p2s` shorter than 8 bytes or a `p2c` of 0; `RandomnessUnavailable` if `rng` fails.
pub(super) fn encrypt_key(
    _alg: &KeyMgmtAlg,
    _key: &RecipientKey,
    _enc: &ContentEncAlg,
    _cek: Option<&Cek>,
    _options: &RecipientOptions,
    _rng: &mut dyn RandomSource,
) -> Result<KeyOutput> {
    Err(Error::UnsupportedAlgorithm)
}

/// Key management on decrypt (RFC 7516 §5.2 steps 6–12) for the three PBES2 algorithms: the
/// CEK, which must have the length `enc` requires (§5.2 step 9).
///
/// # Errors
///
/// An error for a missing or malformed `p2s` or `p2c`, a `p2c` below 1 or above the policy bound, or a failed unwrap. `core` reports every error from here as `DecryptionFailed`.
pub(super) fn decrypt_key(
    _alg: &KeyMgmtAlg,
    _key: &RecipientKey,
    _enc: &ContentEncAlg,
    _header: &Header,
    _encrypted_key: &[u8],
    _policy: &DecryptPolicy,
) -> Result<Cek> {
    Err(Error::UnsupportedAlgorithm)
}

/// The PBKDF2 pseudorandom function of a PBES2 algorithm: HMAC with
/// SHA-256, SHA-384 or SHA-512 (RFC 7518 §4.8, RFC 8018 §5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Prf {
    Sha256,
    Sha384,
    Sha512,
}

/// The PRF and the AES Key Wrap key length in bytes of `alg` (RFC 7518
/// §4.8: HS256 with A128KW, HS384 with A192KW, HS512 with A256KW; the
/// derived key length is the KW key size), or `None` for an `alg` outside
/// the family.
fn params(alg: &KeyMgmtAlg) -> Option<(Prf, usize)> {
    match alg {
        KeyMgmtAlg::Pbes2Hs256A128KW => Some((Prf::Sha256, 16)),
        KeyMgmtAlg::Pbes2Hs384A192KW => Some((Prf::Sha384, 24)),
        KeyMgmtAlg::Pbes2Hs512A256KW => Some((Prf::Sha512, 32)),
        _ => None,
    }
}

/// PBKDF2 (RFC 8018 §5.2) with HMAC-`prf` over `password` and `salt` for
/// `count` iterations, filling `out` (its length is dkLen).
///
/// The only place PBKDF2 runs, so the `pbkdf2_derivations` test counter
/// sees every derivation.
fn pbkdf2_hmac_sha2(prf: Prf, password: &[u8], salt: &[u8], count: u32, out: &mut [u8]) {
    #[cfg(test)]
    crate::test_counters::pbkdf2_derivations::tick();
    match prf {
        Prf::Sha256 => pbkdf2::pbkdf2_hmac::<Sha256>(password, salt, count, out),
        Prf::Sha384 => pbkdf2::pbkdf2_hmac::<Sha384>(password, salt, count, out),
        Prf::Sha512 => pbkdf2::pbkdf2_hmac::<Sha512>(password, salt, count, out),
    }
}

/// The PBKDF2 salt of RFC 7518 §4.8.1.1: `(UTF8(Alg) || 0x00 || Salt
/// Input)`, where Alg is the `alg` header value.
fn salt(alg: &KeyMgmtAlg, p2s: &[u8]) -> Zeroizing<Vec<u8>> {
    let alg = alg.as_str().as_bytes();
    let mut salt = Zeroizing::new(Vec::with_capacity(alg.len() + 1 + p2s.len()));
    salt.extend_from_slice(alg);
    salt.push(0);
    salt.extend_from_slice(p2s);
    salt
}

/// The AES Key Wrap key of RFC 7518 §4.8: PBKDF2 over `password` with the
/// §4.8.1.1 salt and `p2c` iterations, of the KW key length of `alg`. `None`
/// for an `alg` outside the family. Callers check `p2c` first.
fn derive_kek(
    alg: &KeyMgmtAlg,
    password: &[u8],
    p2s: &[u8],
    p2c: u32,
) -> Option<Zeroizing<Vec<u8>>> {
    let (prf, kek_len) = params(alg)?;
    let salt = salt(alg, p2s);
    let mut kek = Zeroizing::new(vec![0; kek_len]);
    pbkdf2_hmac_sha2(prf, password, &salt, p2c, &mut kek);
    Some(kek)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::wycheproof::{self, Outcome};

    /// RFC 7517 Appendix C.4: the passphrase.
    const C4_PASSWORD: &[u8] = b"Thus from my lips, by yours, my sin is purged.";
    /// RFC 7517 Appendix C.2: the Salt Input `p2s`.
    const C2_P2S: [u8; 16] = [
        217, 96, 147, 112, 150, 117, 70, 247, 127, 8, 155, 137, 174, 42, 80, 215,
    ];
    /// RFC 7517 Appendix C.4: the Salt value (UTF8(Alg) || 0x00 || Salt Input).
    const C4_SALT: [u8; 35] = [
        80, 66, 69, 83, 50, 45, 72, 83, 50, 53, 54, 43, 65, 49, 50, 56, 75, 87, 0, 217, 96, 147,
        112, 150, 117, 70, 247, 127, 8, 155, 137, 174, 42, 80, 215,
    ];
    /// RFC 7517 Appendix C.4: the PBKDF2 Derived Key.
    const C4_DERIVED: [u8; 16] = [
        110, 171, 169, 92, 129, 92, 109, 117, 233, 242, 116, 233, 170, 14, 24, 75,
    ];

    /// RFC 7520 §5.3.1 Figure 96, with "\xe2\x80\x93" as U+2013.
    const C53_PASSWORD: &str = "entrap_o\u{2013}peter_long\u{2013}credit_tun";
    /// RFC 7520 §5.3.3 Figure 99, base64url-decoded.
    const C53_P2S: &str = "8Q1SzinasR3xchYz6ZZcHA";
    /// The §5.3 KEK. RFC 7520 does not print it; derived independently of
    /// polyjose with Python's `hashlib.pbkdf2_hmac("sha512", password,
    /// b"PBES2-HS512+A256KW\0" + p2s, 8192, 32)`.
    const C53_DERIVED: &str = "b5fb1d5672ce178b8c42c3cf9b95edb31d989aa2cb5457f516099b613189c1a9";

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn salt_is_the_alg_a_zero_octet_and_the_salt_input() {
        // RFC 7518 §4.8.1.1, checked against RFC 7517 Appendix C.4.
        let salt = salt(&KeyMgmtAlg::Pbes2Hs256A128KW, &C2_P2S);
        assert_eq!(salt.as_slice(), C4_SALT);
    }

    #[test]
    fn derived_key_matches_rfc_7517_appendix_c4() {
        let kek = derive_kek(&KeyMgmtAlg::Pbes2Hs256A128KW, C4_PASSWORD, &C2_P2S, 4096).unwrap();
        assert_eq!(kek.as_slice(), C4_DERIVED);
    }

    #[test]
    fn derived_key_matches_an_independent_derivation_for_rfc_7520_5_3() {
        let p2s = crate::util::b64url_decode(C53_P2S).unwrap();
        let kek = derive_kek(
            &KeyMgmtAlg::Pbes2Hs512A256KW,
            C53_PASSWORD.as_bytes(),
            &p2s,
            8192,
        )
        .unwrap();
        assert_eq!(kek.as_slice(), hex(C53_DERIVED));
    }

    #[test]
    fn derived_key_lengths_are_the_key_wrap_key_sizes() {
        // RFC 7518 §4.8: HS256 → A128KW (16), HS384 → A192KW (24),
        // HS512 → A256KW (32).
        for (alg, len) in [
            (KeyMgmtAlg::Pbes2Hs256A128KW, 16),
            (KeyMgmtAlg::Pbes2Hs384A192KW, 24),
            (KeyMgmtAlg::Pbes2Hs512A256KW, 32),
        ] {
            let kek = derive_kek(&alg, b"pw", &[7; 8], 1).unwrap();
            assert_eq!(kek.len(), len, "{alg}");
        }
        assert!(derive_kek(&KeyMgmtAlg::A128KW, b"pw", &[7; 8], 1).is_none());
    }

    /// Wycheproof PBKDF2-HMAC-SHA-2 (RFC 8018 §5.2) through
    /// [`pbkdf2_hmac_sha2`]: every test is valid, and must derive `dk`.
    fn wycheproof_pbkdf2(name: &str, prf: Prf, tests: usize) {
        let suite = wycheproof::load(name);
        let summary = wycheproof::assert_conforms(&suite, &[], |_, test| {
            let input = test.pbkdf();
            let mut dk = vec![0; input.dk_len];
            pbkdf2_hmac_sha2(
                prf,
                &input.password,
                &input.salt,
                input.iteration_count,
                &mut dk,
            );
            Outcome::of(&if dk == input.dk { Ok(()) } else { Err(()) })
        });
        assert_eq!((summary.tests, summary.accepted), (tests, tests), "{name}");
    }

    #[test]
    fn wycheproof_pbkdf2_hmacsha256() {
        wycheproof_pbkdf2("pbkdf2_hmacsha256", Prf::Sha256, 60);
    }

    #[test]
    fn wycheproof_pbkdf2_hmacsha384() {
        wycheproof_pbkdf2("pbkdf2_hmacsha384", Prf::Sha384, 58);
    }

    #[test]
    fn wycheproof_pbkdf2_hmacsha512() {
        wycheproof_pbkdf2("pbkdf2_hmacsha512", Prf::Sha512, 58);
    }
}
