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

use super::aes_kw;
use super::api::DecryptPolicy;
use super::content::{Cek, cek_len};
use super::key::RecipientKey;
use super::keymgmt::{KeyOutput, RecipientOptions};
use super::random::RandomSource;
use crate::header::Header;
use crate::jwa::{ContentEncAlg, KeyMgmtAlg};
use crate::util::b64url_decode;
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

/// Key management on decrypt (RFC 7516 §5.2 steps 6–12) for the three
/// PBES2 algorithms: the JWE Encrypted Key unwrapped (RFC 3394 §2.2.2) under
/// the key PBKDF2 derives from the password, `p2s` and `p2c` (RFC 7518
/// §4.8). The CEK must have the length `enc` requires (§5.2 step 9).
///
/// `p2s` and `p2c` are checked before PBKDF2 runs, so a hostile count
/// costs nothing (RFC 7518 §8.8, ADR 0023):
/// - `p2c` must be present, at least 1 (a "positive JSON integer", RFC 7518
///   §4.8.1.2) and at most `policy.max_pbes2_count`;
/// - `p2s` must be present, strict base64url (RFC 7515 §2), and at least 8
///   octets once decoded (RFC 7518 §4.8.1.1: "A Salt Input value containing
///   8 or more octets MUST be used").
///
/// # Errors
///
/// [`Error::DecryptionFailed`], whatever the cause, so no cause can be told
/// from another (RFC 7516 §11.4–§11.5, the plan.md error contract): an
/// `alg` outside the family, a key that is not a password, an unknown
/// `enc`, any `p2s` or `p2c` fault above, a wrapped key of the wrong size,
/// an integrity failure (a wrong password, RFC 3394 §2.2.3) or an unwrapped
/// CEK of the wrong length. The derived key and every unwrapped byte are
/// wiped before returning.
pub(super) fn decrypt_key(
    alg: &KeyMgmtAlg,
    key: &RecipientKey,
    enc: &ContentEncAlg,
    header: &Header,
    encrypted_key: &[u8],
    policy: &DecryptPolicy,
) -> Result<Cek> {
    let RecipientKey::Password(password) = key else {
        return Err(Error::DecryptionFailed);
    };
    let cek_len = cek_len(enc).map_err(|_| Error::DecryptionFailed)?;
    let p2c = header
        .p2c
        .filter(|&p2c| p2c >= 1 && p2c <= u64::from(policy.max_pbes2_count))
        .and_then(|p2c| u32::try_from(p2c).ok())
        .ok_or(Error::DecryptionFailed)?;
    let p2s = header
        .p2s
        .as_deref()
        .and_then(|p2s| b64url_decode(p2s).ok())
        .filter(|p2s| p2s.len() >= MIN_P2S_LEN)
        .ok_or(Error::DecryptionFailed)?;
    let kek = derive_kek(alg, password, &p2s, p2c).ok_or(Error::DecryptionFailed)?;
    let cek = aes_kw::unwrap(&kek, encrypted_key)?;
    if cek.len() != cek_len {
        // `cek` is `Zeroizing`: dropping it here wipes the unwrapped bytes.
        return Err(Error::DecryptionFailed);
    }
    Ok(Cek::new(cek))
}

/// The shortest Salt Input `p2s`, in octets (RFC 7518 §4.8.1.1).
const MIN_P2S_LEN: usize = 8;

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
    use crate::test_counters::pbkdf2_derivations;
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

    /// `(alg, KEK length)` of RFC 7518 §4.8.
    const FAMILY: [(KeyMgmtAlg, usize); 3] = [
        (KeyMgmtAlg::Pbes2Hs256A128KW, 16),
        (KeyMgmtAlg::Pbes2Hs384A192KW, 24),
        (KeyMgmtAlg::Pbes2Hs512A256KW, 32),
    ];

    const PASSWORD: &[u8] = b"correct horse battery staple";
    const P2S: [u8; 16] = [0x11; 16];

    fn password(pw: &[u8]) -> RecipientKey {
        RecipientKey::Password(Zeroizing::new(pw.to_vec()))
    }

    fn policy() -> DecryptPolicy {
        DecryptPolicy::new(&FAMILY.map(|(alg, _)| alg), ContentEncAlg::KNOWN).unwrap()
    }

    fn header(p2s: Option<&[u8]>, p2c: Option<u64>) -> Header {
        let mut h = Header::new();
        h.p2s = p2s.map(crate::util::b64url_encode);
        h.p2c = p2c;
        h
    }

    /// A CEK of `len` bytes, wrapped under the KEK derived from `PASSWORD`,
    /// `p2s` and `p2c`, built without `encrypt_key`.
    fn wrapped(alg: &KeyMgmtAlg, p2s: &[u8], p2c: u32, len: usize) -> (Vec<u8>, Vec<u8>) {
        let cek: Vec<u8> = (0..len).map(|i| 0xC0 ^ i as u8).collect();
        let kek = derive_kek(alg, PASSWORD, p2s, p2c).unwrap();
        (cek.clone(), aes_kw::wrap(&kek, &cek).unwrap())
    }

    /// `decrypt_key` with the number of PBKDF2 derivations it ran.
    fn decrypt_counted(
        alg: &KeyMgmtAlg,
        key: &RecipientKey,
        enc: &ContentEncAlg,
        header: &Header,
        encrypted_key: &[u8],
        policy: &DecryptPolicy,
    ) -> (Result<Cek>, u64) {
        pbkdf2_derivations::count(|| decrypt_key(alg, key, enc, header, encrypted_key, policy))
    }

    #[test]
    fn decrypt_key_unwraps_the_cek_under_the_derived_key() {
        // RFC 7518 §4.8: derive with the received p2s and p2c, then unwrap.
        for (alg, _) in &FAMILY {
            for enc in ContentEncAlg::KNOWN {
                let len = cek_len(enc).unwrap();
                let (cek, ek) = wrapped(alg, &P2S, 1000, len);
                let h = header(Some(&P2S), Some(1000));
                let (out, n) = decrypt_counted(alg, &password(PASSWORD), enc, &h, &ek, &policy());
                assert_eq!(out.map(|c| c.as_bytes().to_vec()), Ok(cek), "{alg} {enc}");
                assert_eq!(n, 1, "{alg} {enc}");
            }
        }
    }

    #[test]
    fn decrypt_key_accepts_the_bound_and_the_shortest_salt_input() {
        // ADR 0023: p2c equal to max_pbes2_count is accepted; RFC 7518
        // §4.8.1.1: 8 octets is the shortest Salt Input.
        let alg = KeyMgmtAlg::Pbes2Hs256A128KW;
        let enc = ContentEncAlg::A128GCM;
        let bound = DecryptPolicy::DEFAULT_MAX_PBES2_COUNT;
        let (cek, ek) = wrapped(&alg, &P2S[..8], bound, 16);
        let h = header(Some(&P2S[..8]), Some(u64::from(bound)));
        let (out, n) = decrypt_counted(&alg, &password(PASSWORD), &enc, &h, &ek, &policy());
        assert_eq!(out.map(|c| c.as_bytes().to_vec()), Ok(cek));
        assert_eq!(n, 1);
    }

    #[test]
    fn every_p2s_and_p2c_fault_fails_before_any_derivation() {
        // RFC 7518 §4.8.1.1–§4.8.1.2, §8.8; ADR 0023; plan.md error
        // contract: each is DecryptionFailed, and PBKDF2 never runs
        // (CVE-2022-36083, CVE-2023-52428, CVE-2023-51775).
        let bound = u64::from(DecryptPolicy::DEFAULT_MAX_PBES2_COUNT);
        let ceiling = u64::from(DecryptPolicy::MAX_PBES2_COUNT_CEILING);
        let default = policy();
        let raised = policy().max_pbes2_count(u32::MAX);
        let mut short_b64 = header(None, Some(1000));
        short_b64.p2s = Some("!!!!".into());
        let mut padded = header(None, Some(1000));
        padded.p2s = Some(format!("{}=", crate::util::b64url_encode(&P2S[..10])));
        let cases: Vec<(&str, Header, &DecryptPolicy)> = vec![
            ("missing p2s", header(None, Some(1000)), &default),
            ("missing p2c", header(Some(&P2S), None), &default),
            ("missing both", header(None, None), &default),
            ("p2c 0", header(Some(&P2S), Some(0)), &default),
            (
                "p2c bound + 1",
                header(Some(&P2S), Some(bound + 1)),
                &default,
            ),
            (
                "p2c u32::MAX",
                header(Some(&P2S), Some(u64::from(u32::MAX))),
                &default,
            ),
            (
                "p2c 2^53 - 1",
                header(Some(&P2S), Some((1 << 53) - 1)),
                &default,
            ),
            ("p2c u64::MAX", header(Some(&P2S), Some(u64::MAX)), &default),
            (
                "p2c ceiling + 1, raised",
                header(Some(&P2S), Some(ceiling + 1)),
                &raised,
            ),
            ("p2s empty", header(Some(&[]), Some(1000)), &default),
            (
                "p2s 7 octets",
                header(Some(&P2S[..7]), Some(1000)),
                &default,
            ),
            ("p2s not base64url", short_b64, &default),
            ("p2s padded", padded, &default),
        ];
        let (_, ek) = wrapped(&KeyMgmtAlg::Pbes2Hs256A128KW, &P2S, 1000, 16);
        for (what, h, policy) in &cases {
            for (alg, _) in &FAMILY {
                let (out, n) = decrypt_counted(
                    alg,
                    &password(PASSWORD),
                    &ContentEncAlg::A128GCM,
                    h,
                    &ek,
                    policy,
                );
                assert_eq!(
                    out.map(|_| ()),
                    Err(Error::DecryptionFailed),
                    "{what} {alg}"
                );
                assert_eq!(n, 0, "{what} {alg}: PBKDF2 ran");
            }
        }
    }

    #[test]
    fn a_lowered_bound_rejects_a_count_the_default_accepts() {
        let alg = KeyMgmtAlg::Pbes2Hs256A128KW;
        let (_, ek) = wrapped(&alg, &P2S, 1000, 16);
        let h = header(Some(&P2S), Some(1000));
        let low = policy().max_pbes2_count(999);
        let (out, n) = decrypt_counted(
            &alg,
            &password(PASSWORD),
            &ContentEncAlg::A128GCM,
            &h,
            &ek,
            &low,
        );
        assert_eq!((out.map(|_| ()), n), (Err(Error::DecryptionFailed), 0));
    }

    #[test]
    fn wrong_password_or_tampered_key_fails_after_one_derivation() {
        // RFC 3394 §2.2.3: the integrity check fails; RFC 7516 §11.5: the
        // same DecryptionFailed as every other cause.
        let alg = KeyMgmtAlg::Pbes2Hs512A256KW;
        let enc = ContentEncAlg::A256GCM;
        let (_, ek) = wrapped(&alg, &P2S, 1000, 32);
        let h = header(Some(&P2S), Some(1000));
        let (out, n) = decrypt_counted(&alg, &password(b"wrong"), &enc, &h, &ek, &policy());
        assert_eq!((out.map(|_| ()), n), (Err(Error::DecryptionFailed), 1));
        let mut tampered = ek.clone();
        tampered[9] ^= 1;
        let (out, n) = decrypt_counted(&alg, &password(PASSWORD), &enc, &h, &tampered, &policy());
        assert_eq!((out.map(|_| ()), n), (Err(Error::DecryptionFailed), 1));
        // A different p2s or p2c derives a different key.
        for h in [
            header(Some(&[0x12; 16]), Some(1000)),
            header(Some(&P2S), Some(1001)),
        ] {
            let (out, _) = decrypt_counted(&alg, &password(PASSWORD), &enc, &h, &ek, &policy());
            assert_eq!(out.map(|_| ()), Err(Error::DecryptionFailed));
        }
    }

    #[test]
    fn decrypt_key_refuses_other_keys_algs_and_cek_lengths() {
        let alg = KeyMgmtAlg::Pbes2Hs256A128KW;
        let h = header(Some(&P2S), Some(1000));
        let (_, ek) = wrapped(&alg, &P2S, 1000, 32);
        // RFC 7516 §5.2 step 9: the CEK must have the length enc requires.
        let (out, _) = decrypt_counted(
            &alg,
            &password(PASSWORD),
            &ContentEncAlg::A128GCM,
            &h,
            &ek,
            &policy(),
        );
        assert_eq!(out.map(|_| ()), Err(Error::DecryptionFailed));
        // RFC 8725 §3.1: a symmetric key is not a password; nothing derived.
        let symmetric = RecipientKey::Symmetric(Zeroizing::new(PASSWORD.to_vec()));
        let enc = ContentEncAlg::A128CbcHs256;
        let (out, n) = decrypt_counted(&alg, &symmetric, &enc, &h, &ek, &policy());
        assert_eq!((out.map(|_| ()), n), (Err(Error::DecryptionFailed), 0));
        // An alg outside the family.
        let (out, n) = decrypt_counted(
            &KeyMgmtAlg::A128KW,
            &password(PASSWORD),
            &enc,
            &h,
            &ek,
            &policy(),
        );
        assert_eq!((out.map(|_| ()), n), (Err(Error::DecryptionFailed), 0));
        // An empty or short encrypted key.
        for ek in [&[][..], &ek[..16]] {
            let (out, _) = decrypt_counted(&alg, &password(PASSWORD), &enc, &h, ek, &policy());
            assert_eq!(out.map(|_| ()), Err(Error::DecryptionFailed));
        }
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
