//! PBES2-HS256+A128KW, PBES2-HS384+A192KW and PBES2-HS512+A256KW
//! (RFC 7518 §4.8): PBKDF2 (RFC 8018 §5.2) over the password with salt
//! `UTF8(alg) || 0x00 || p2s` derives the key that AES Key Wrap (RFC 3394,
//! [`aes_kw::wrap`]) wraps the CEK with.
//!
//! The decrypt side checks `p2s` and `p2c` before any derivation: `p2c` is
//! attacker-chosen, and each iteration is two hash compressions, so the
//! bound `DecryptPolicy::max_pbes2_count` (ADR 0023; 10,000 by default) is
//! enforced first (RFC 7518 §8.8; CVE-2022-36083, CVE-2023-52428,
//! CVE-2023-51775). The bound is one [`Budget`] for the whole decrypt call,
//! summed over every PBES2 candidate tried (ADR 0050 §2), so a token with
//! many recipients costs no more than one.

use super::aes_kw;
use super::api::DecryptPolicy;
use super::content::{Cek, cek_len};
use super::key::RecipientKey;
use super::keymgmt::{KeyOutput, RecipientOptions};
use super::random::RandomSource;
use crate::header::Header;
use crate::json::{Number, Object, Value};
use crate::jwa::{ContentEncAlg, KeyMgmtAlg};
use crate::util::{b64url_decode, b64url_encode};
use crate::{Error, Result};
use sha2::{Sha256, Sha384, Sha512};
use zeroize::Zeroizing;

/// Key management on encrypt (RFC 7516 §5.1 steps 3–7) for the three PBES2
/// algorithms: the random CEK wrapped with AES Key Wrap (RFC 3394 §2.2.1)
/// under the key PBKDF2 derives from the password (RFC 7518 §4.8). The
/// header parameters are `p2s`, the base64url Salt Input, and `p2c`, the
/// iteration count (RFC 7518 §4.8.1.1–§4.8.1.2).
///
/// - `p2s` is `options.p2s_len` octets (16 by default, 8 to 256: RFC 7518
///   §4.8.1.1, ADR 0050 §2), drawn from `rng` (ADR 0005; plan.md RNG draw
///   order).
/// - `p2c` is `options.p2c` (10,000 by default, ADR 0023), 1000 to
///   1,000,000 ([`check_encrypt_options`]).
///
/// Every check runs before anything is drawn or derived; `core::encrypt`
/// also runs [`check_encrypt_options`] before its first draw, the CEK.
///
/// # Errors
///
/// - [`Error::UnsupportedAlgorithm`] for an `alg` outside the family or an
///   unknown `enc`;
/// - [`Error::KeyAlgorithmMismatch`] for a key that is not a password
///   (RFC 7518 §4.8, RFC 8725 §3.1);
/// - [`Error::InvalidKey`] for a `p2c` or `p2s` length out of range
///   ([`check_encrypt_options`]), or a CEK that is missing or not the length
///   `enc` requires (RFC 7516 §5.1 step 2);
/// - [`Error::RandomnessUnavailable`] if `rng` fails.
pub(super) fn encrypt_key(
    alg: &KeyMgmtAlg,
    key: &RecipientKey,
    enc: &ContentEncAlg,
    cek: Option<&Cek>,
    options: &RecipientOptions,
    rng: &mut dyn RandomSource,
) -> Result<KeyOutput> {
    if params(alg).is_none() {
        return Err(Error::UnsupportedAlgorithm);
    }
    let RecipientKey::Password(password) = key else {
        return Err(Error::KeyAlgorithmMismatch);
    };
    let cek_len = cek_len(enc)?;
    let cek = cek
        .filter(|cek| cek.len() == cek_len)
        .ok_or(Error::InvalidKey(CEK_SIZE))?;
    let (p2c, p2s_len) = encrypt_params(options)?;
    // A u32 is always an exact I-JSON integer (RFC 7493 §2.2); the error
    // arm is never taken.
    let p2c_number = Number::from_u64(u64::from(p2c)).ok_or(Error::InvalidKey(P2C_TOO_LOW))?;
    let mut p2s = vec![0; p2s_len];
    rng.fill(&mut p2s)?;
    let kek = derive_kek(alg, password, &p2s, p2c).ok_or(Error::UnsupportedAlgorithm)?;
    let encrypted_key = aes_kw::wrap(&kek, cek.as_bytes())?;
    let mut header_params = Object::new();
    header_params.insert("p2s", b64url_encode(&p2s));
    header_params.insert("p2c", Value::from(p2c_number));
    Ok(KeyOutput {
        encrypted_key,
        header_params,
        cek: None,
    })
}

/// Checks a recipient's PBES2 encrypt options when `alg` is a PBES2
/// algorithm (RFC 7518 §4.8.1), and accepts any options for another `alg`,
/// whose family ignores them. `core::encrypt` calls it before its first
/// draw, so a bad option costs no randomness and no derivation.
///
/// - `p2c` (10,000 by default, ADR 0023) is at least 1000, the minimum RFC
///   7518 §4.8.1.2 recommends, and at most the 1,000,000 decrypt ceiling
///   [`DecryptPolicy::MAX_PBES2_COUNT_CEILING`] (ADR 0050 §2): no
///   `DecryptPolicy` could decrypt more.
/// - `p2s_len` (16 by default) is at least 8 octets (RFC 7518 §4.8.1.1: "A
///   Salt Input value containing 8 or more octets MUST be used") and at most
///   256 (ADR 0050 §2), which bounds the salt PBKDF2 hashes.
///
/// # Errors
///
/// [`Error::InvalidKey`] for a value out of range.
pub(crate) fn check_encrypt_options(alg: &KeyMgmtAlg, options: &RecipientOptions) -> Result<()> {
    if params(alg).is_some() {
        encrypt_params(options)?;
    }
    Ok(())
}

/// `(p2c, p2s_len)` of `options` with the defaults applied, checked as
/// [`check_encrypt_options`] describes.
fn encrypt_params(options: &RecipientOptions) -> Result<(u32, usize)> {
    let p2c = options.p2c.unwrap_or(DEFAULT_P2C);
    if p2c < MIN_P2C {
        return Err(Error::InvalidKey(P2C_TOO_LOW));
    }
    if p2c > DecryptPolicy::MAX_PBES2_COUNT_CEILING {
        return Err(Error::InvalidKey(P2C_TOO_HIGH));
    }
    let p2s_len = options.p2s_len.unwrap_or(DEFAULT_P2S_LEN);
    if p2s_len < MIN_P2S_LEN {
        return Err(Error::InvalidKey(P2S_TOO_SHORT));
    }
    if p2s_len > MAX_P2S_LEN {
        return Err(Error::InvalidKey(P2S_TOO_LONG));
    }
    Ok((p2c, p2s_len))
}

/// The encrypt-side default `p2c` (ADR 0023): inside every mainstream
/// library's default decrypt bound, polyjose's included.
const DEFAULT_P2C: u32 = 10_000;

/// The smallest `p2c` polyjose encrypts with: the minimum RFC 7518 §4.8.1.2
/// recommends ("A minimum iteration count of 1000 is RECOMMENDED").
const MIN_P2C: u32 = 1000;

/// The encrypt-side default Salt Input length in octets (plan.md interface
/// contract), twice the RFC 7518 §4.8.1.1 minimum.
const DEFAULT_P2S_LEN: usize = 16;

/// The [`Error::InvalidKey`] detail for a `p2c` below [`MIN_P2C`].
const P2C_TOO_LOW: &str = "PBES2 p2c must be at least 1000";

/// The [`Error::InvalidKey`] detail for a `p2c` above the decrypt ceiling.
const P2C_TOO_HIGH: &str = "PBES2 p2c must be at most 1000000";

/// The longest Salt Input polyjose encrypts with, in octets (ADR 0050 §2).
const MAX_P2S_LEN: usize = 256;

/// The [`Error::InvalidKey`] detail for a `p2s` shorter than [`MIN_P2S_LEN`].
const P2S_TOO_SHORT: &str = "PBES2 p2s must be at least 8 octets";

/// The [`Error::InvalidKey`] detail for a `p2s` longer than [`MAX_P2S_LEN`].
const P2S_TOO_LONG: &str = "PBES2 p2s must be at most 256 octets";

/// The [`Error::InvalidKey`] detail for a missing CEK or one of the wrong
/// length.
const CEK_SIZE: &str = "the CEK must have the length enc requires";

/// The PBKDF2 iterations one decrypt call may still spend, over every PBES2
/// candidate it tries (ADR 0050 §2, amending ADR 0023; RFC 7518 §8.8).
///
/// `core::decrypt` makes one from `policy.max_pbes2_count` per call and
/// passes it to each candidate's key management; [`decrypt_key`] spends a
/// candidate's `p2c` from it just before PBKDF2 runs, and only then. The
/// sum of `p2c` over the derivations of one call is therefore at most
/// `max_pbes2_count`, however many recipients the JWE has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Budget {
    remaining: u32,
}

impl Budget {
    /// A budget of `policy.max_pbes2_count` iterations, for one decrypt call.
    pub(crate) fn new(policy: &DecryptPolicy) -> Self {
        Self {
            remaining: policy.max_pbes2_count,
        }
    }

    /// Spends `p2c` iterations, or refuses (leaving the budget unchanged)
    /// if fewer than `p2c` remain: `p2c` equal to what remains is accepted,
    /// as the bound is inclusive (ADR 0023).
    fn spend(&mut self, p2c: u32) -> Result<()> {
        self.remaining = self
            .remaining
            .checked_sub(p2c)
            .ok_or(Error::DecryptionFailed)?;
        Ok(())
    }
}

/// Key management on decrypt (RFC 7516 §5.2 steps 6–12) for the three
/// PBES2 algorithms: the JWE Encrypted Key unwrapped (RFC 3394 §2.2.2) under
/// the key PBKDF2 derives from the password, `p2s` and `p2c` (RFC 7518
/// §4.8). The CEK must have the length `enc` requires (§5.2 step 9).
///
/// `p2s` and `p2c` are checked before PBKDF2 runs, so a hostile count
/// costs nothing (RFC 7518 §8.8, ADR 0023, ADR 0050 §2):
/// - `p2c` must be present and at least 1 (a "positive JSON integer",
///   RFC 7518 §4.8.1.2);
/// - `p2s` must be present, strict base64url (RFC 7515 §2), and at least 8
///   octets once decoded (RFC 7518 §4.8.1.1: "A Salt Input value containing
///   8 or more octets MUST be used");
/// - then `p2c` must fit what is left of the call's `budget`, which it is
///   spent from (so it is never above `policy.max_pbes2_count`). A fault
///   above spends nothing.
///
/// # Errors
///
/// [`Error::DecryptionFailed`], whatever the cause, so no cause can be told
/// from another (RFC 7516 §11.4–§11.5, the plan.md error contract): an
/// `alg` outside the family, a key that is not a password, an unknown
/// `enc`, any `p2s` or `p2c` fault above, a `p2c` over the remaining
/// budget, a wrapped key of the wrong size, an integrity failure (a wrong
/// password, RFC 3394 §2.2.3) or an unwrapped CEK of the wrong length. The
/// derived key and every unwrapped byte are wiped before returning.
pub(super) fn decrypt_key(
    alg: &KeyMgmtAlg,
    key: &RecipientKey,
    enc: &ContentEncAlg,
    header: &Header,
    encrypted_key: &[u8],
    budget: &mut Budget,
) -> Result<Cek> {
    let RecipientKey::Password(password) = key else {
        return Err(Error::DecryptionFailed);
    };
    let cek_len = cek_len(enc).map_err(|_| Error::DecryptionFailed)?;
    if params(alg).is_none() {
        return Err(Error::DecryptionFailed);
    }
    let p2c = header
        .p2c
        .filter(|&p2c| p2c >= 1)
        .and_then(|p2c| u32::try_from(p2c).ok())
        .ok_or(Error::DecryptionFailed)?;
    let p2s = header
        .p2s
        .as_deref()
        .and_then(|p2s| b64url_decode(p2s).ok())
        .filter(|p2s| p2s.len() >= MIN_P2S_LEN)
        .ok_or(Error::DecryptionFailed)?;
    // ADR 0050 §2: the last check before PBKDF2, so only a derivation that
    // runs is charged.
    budget.spend(p2c)?;
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
    use crate::jwe::random::OsRandom;
    use crate::rng::insecure_test_vectors::FixedRng;
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
        let mut budget = Budget::new(policy);
        pbkdf2_derivations::count(|| decrypt_key(alg, key, enc, header, encrypted_key, &mut budget))
    }

    #[test]
    fn the_budget_is_spent_only_by_derivations_that_run() {
        // ADR 0050 §2: each derivation spends its p2c from the call's
        // budget, checked before PBKDF2 runs; a fault found first spends
        // nothing, and a p2c over what is left derives nothing.
        let alg = KeyMgmtAlg::Pbes2Hs256A128KW;
        let enc = ContentEncAlg::A128GCM;
        let pw = password(PASSWORD);
        let (cek, ek) = wrapped(&alg, &P2S, 4000, 16);
        let good = header(Some(&P2S), Some(4000));
        let mut budget = Budget::new(&policy());
        let run = |h: &Header, ek: &[u8], budget: &mut Budget| {
            pbkdf2_derivations::count(|| {
                decrypt_key(&alg, &pw, &enc, h, ek, budget).map(|c| c.as_bytes().to_vec())
            })
        };
        // A fault before the budget check: nothing spent.
        let (out, n) = run(&header(Some(&P2S[..7]), Some(4000)), &ek, &mut budget);
        assert_eq!((out, n), (Err(Error::DecryptionFailed), 0));
        assert_eq!(budget, Budget { remaining: 10_000 });
        // A derivation that fails afterwards (a tampered key) still spends.
        let mut tampered = ek.clone();
        tampered[9] ^= 1;
        let (out, n) = run(&good, &tampered, &mut budget);
        assert_eq!((out, n), (Err(Error::DecryptionFailed), 1));
        assert_eq!(budget, Budget { remaining: 6000 });
        let (out, n) = run(&good, &ek, &mut budget);
        assert_eq!((out, n), (Ok(cek.clone()), 1));
        assert_eq!(budget, Budget { remaining: 2000 });
        // 4000 > 2000 left: refused without deriving, nothing spent.
        let (out, n) = run(&good, &ek, &mut budget);
        assert_eq!((out, n), (Err(Error::DecryptionFailed), 0));
        assert_eq!(budget, Budget { remaining: 2000 });
        // Exactly what is left is accepted (the bound is inclusive).
        let (cek2, ek2) = wrapped(&alg, &P2S, 2000, 16);
        let (out, n) = run(&header(Some(&P2S), Some(2000)), &ek2, &mut budget);
        assert_eq!((out, n), (Ok(cek2), 1));
        assert_eq!(budget, Budget { remaining: 0 });
        let (out, n) = run(&header(Some(&P2S), Some(1)), &ek, &mut budget);
        assert_eq!((out, n), (Err(Error::DecryptionFailed), 0));
    }

    #[test]
    fn an_alg_outside_the_family_spends_nothing() {
        let mut budget = Budget::new(&policy());
        let h = header(Some(&P2S), Some(1000));
        let (out, n) = pbkdf2_derivations::count(|| {
            decrypt_key(
                &KeyMgmtAlg::A128KW,
                &password(PASSWORD),
                &ContentEncAlg::A128GCM,
                &h,
                &[0; 24],
                &mut budget,
            )
        });
        assert_eq!((out.map(|_| ()), n), (Err(Error::DecryptionFailed), 0));
        assert_eq!(budget, Budget::new(&policy()));
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

    /// RFC 7517 Appendix C.3: the CEK.
    const C3_CEK: [u8; 32] = [
        111, 27, 25, 52, 66, 29, 20, 78, 92, 176, 56, 240, 65, 208, 82, 112, 161, 131, 36, 55, 202,
        236, 185, 172, 129, 23, 153, 194, 195, 48, 253, 182,
    ];
    /// RFC 7517 Appendix C.5: the JWE Encrypted Key.
    const C5_ENCRYPTED_KEY: [u8; 40] = [
        78, 186, 151, 59, 11, 141, 81, 240, 213, 245, 83, 211, 53, 188, 134, 188, 66, 125, 36, 200,
        222, 124, 5, 103, 249, 52, 117, 184, 140, 81, 246, 158, 161, 177, 20, 33, 245, 57, 59, 4,
    ];

    fn cek_for(enc: &ContentEncAlg) -> Cek {
        let len = cek_len(enc).unwrap();
        Cek::new(Zeroizing::new((0..len).map(|i| 0xC0 ^ i as u8).collect()))
    }

    fn options(p2c: Option<u32>, p2s_len: Option<usize>) -> RecipientOptions {
        RecipientOptions {
            p2c,
            p2s_len,
            ..RecipientOptions::default()
        }
    }

    fn p2c_value(n: u64) -> Value {
        Value::from(Number::from_u64(n).unwrap())
    }

    #[test]
    fn encrypt_key_reproduces_rfc_7517_appendix_c5() {
        // RFC 7517 Appendix C.2–C.5: p2s drawn from the RNG, p2c 4096.
        let mut rng = FixedRng::new(C2_P2S.to_vec());
        let out = encrypt_key(
            &KeyMgmtAlg::Pbes2Hs256A128KW,
            &password(C4_PASSWORD),
            &ContentEncAlg::A128CbcHs256,
            Some(&Cek::from_slice(&C3_CEK)),
            &options(Some(4096), None),
            &mut rng,
        )
        .unwrap();
        assert_eq!(out.encrypted_key, C5_ENCRYPTED_KEY);
        assert_eq!(rng.remaining(), 0);
        assert!(out.cek.is_none());
        let mut expected = Object::new();
        expected.insert("p2s", "2WCTcJZ1Rvd_CJuJripQ1w");
        expected.insert("p2c", p2c_value(4096));
        assert_eq!(out.header_params, expected);
    }

    #[test]
    fn encrypt_defaults_to_16_salt_octets_and_10000_iterations() {
        // RFC 7518 §4.8.1.1 (p2s ≥ 8 octets; 16 here), ADR 0023 (p2c 10,000).
        for (alg, _) in &FAMILY {
            for enc in ContentEncAlg::KNOWN {
                let cek = cek_for(enc);
                let mut rng = FixedRng::new(P2S.to_vec());
                let (out, n) = pbkdf2_derivations::count(|| {
                    encrypt_key(
                        alg,
                        &password(PASSWORD),
                        enc,
                        Some(&cek),
                        &options(None, None),
                        &mut rng,
                    )
                });
                let out = out.unwrap();
                assert_eq!((rng.remaining(), n), (0, 1), "{alg} {enc}");
                assert_eq!(out.header_params.len(), 2);
                assert_eq!(
                    out.header_params.get("p2s"),
                    Some(&Value::from(crate::util::b64url_encode(&P2S))),
                );
                assert_eq!(out.header_params.get("p2c"), Some(&p2c_value(10_000)));
                let h = header(Some(&P2S), Some(10_000));
                let back = decrypt_key(
                    alg,
                    &password(PASSWORD),
                    enc,
                    &h,
                    &out.encrypted_key,
                    &mut Budget::new(&policy()),
                );
                assert_eq!(
                    back.map(|c| c.as_bytes().to_vec()),
                    Ok(cek.as_bytes().to_vec())
                );
            }
        }
    }

    #[test]
    fn encrypt_takes_the_callers_count_and_salt_length() {
        let alg = KeyMgmtAlg::Pbes2Hs384A192KW;
        let enc = ContentEncAlg::A192GCM;
        for (p2c, p2s_len) in [(1000, 8), (4096, 9), (20_000, 64)] {
            let mut rng = FixedRng::new(vec![0x33; p2s_len]);
            let out = encrypt_key(
                &alg,
                &password(PASSWORD),
                &enc,
                Some(&cek_for(&enc)),
                &options(Some(p2c), Some(p2s_len)),
                &mut rng,
            )
            .unwrap();
            assert_eq!(rng.remaining(), 0);
            assert_eq!(
                out.header_params.get("p2c"),
                Some(&p2c_value(u64::from(p2c)))
            );
            let p2s = out
                .header_params
                .get("p2s")
                .and_then(Value::as_str)
                .unwrap();
            assert_eq!(
                crate::util::b64url_decode(p2s).unwrap(),
                vec![0x33; p2s_len]
            );
        }
    }

    #[test]
    fn os_random_salt_inputs_differ() {
        let alg = KeyMgmtAlg::Pbes2Hs256A128KW;
        let enc = ContentEncAlg::A128GCM;
        let run = || {
            let out = encrypt_key(
                &alg,
                &password(PASSWORD),
                &enc,
                Some(&cek_for(&enc)),
                &options(Some(1000), None),
                &mut OsRandom,
            )
            .unwrap();
            (out.header_params.get("p2s").cloned(), out.encrypted_key)
        };
        let (a, b) = (run(), run());
        assert_ne!(a.0, b.0);
        assert_ne!(a.1, b.1);
    }

    #[test]
    fn encrypt_refuses_weak_parameters_before_drawing_or_deriving() {
        // RFC 7518 §4.8.1.2: "A minimum iteration count of 1000 is
        // RECOMMENDED"; §4.8.1.1: at least 8 salt input octets.
        let alg = KeyMgmtAlg::Pbes2Hs256A128KW;
        let enc = ContentEncAlg::A128GCM;
        for opts in [
            options(Some(999), None),
            options(Some(1), None),
            options(Some(0), None),
            options(None, Some(7)),
            options(None, Some(0)),
            options(Some(0), Some(0)),
        ] {
            let mut rng = FixedRng::new(vec![0; 64]);
            let (out, n) = pbkdf2_derivations::count(|| {
                encrypt_key(
                    &alg,
                    &password(PASSWORD),
                    &enc,
                    Some(&cek_for(&enc)),
                    &opts,
                    &mut rng,
                )
            });
            assert!(matches!(out, Err(Error::InvalidKey(_))), "{opts:?}");
            assert_eq!((rng.remaining(), n), (64, 0), "{opts:?}");
        }
    }

    #[test]
    fn encrypt_refuses_a_count_above_the_ceiling_or_a_salt_input_above_256_octets() {
        // ADR 0050 §2: p2c above the 1,000,000 decrypt ceiling (ADR 0023)
        // could never be decrypted, and p2s_len is capped at 256 octets;
        // both are InvalidKey before anything is drawn or derived.
        let alg = KeyMgmtAlg::Pbes2Hs256A128KW;
        let enc = ContentEncAlg::A128GCM;
        let ceiling = DecryptPolicy::MAX_PBES2_COUNT_CEILING;
        for opts in [
            options(Some(ceiling + 1), None),
            options(Some(u32::MAX), None),
            options(None, Some(257)),
            options(None, Some(usize::MAX)),
            options(Some(ceiling + 1), Some(257)),
        ] {
            let mut rng = FixedRng::new(vec![0; 512]);
            let (out, n) = pbkdf2_derivations::count(|| {
                encrypt_key(
                    &alg,
                    &password(PASSWORD),
                    &enc,
                    Some(&cek_for(&enc)),
                    &opts,
                    &mut rng,
                )
            });
            assert!(matches!(out, Err(Error::InvalidKey(_))), "{opts:?}");
            assert_eq!((rng.remaining(), n), (512, 0), "{opts:?}");
            assert!(
                matches!(
                    check_encrypt_options(&alg, &opts),
                    Err(Error::InvalidKey(_))
                ),
                "{opts:?}"
            );
        }
    }

    #[test]
    fn the_encrypt_limits_are_inclusive() {
        // The ceiling and 256 octets themselves are accepted. The count is
        // checked without deriving 1,000,000 iterations.
        let alg = KeyMgmtAlg::Pbes2Hs512A256KW;
        let ceiling = DecryptPolicy::MAX_PBES2_COUNT_CEILING;
        assert_eq!(
            check_encrypt_options(&alg, &options(Some(ceiling), Some(256))),
            Ok(())
        );
        let enc = ContentEncAlg::A256GCM;
        let mut rng = FixedRng::new(vec![0x44; 256]);
        let out = encrypt_key(
            &alg,
            &password(PASSWORD),
            &enc,
            Some(&cek_for(&enc)),
            &options(Some(1000), Some(256)),
            &mut rng,
        )
        .unwrap();
        assert_eq!(rng.remaining(), 0);
        let p2s = out
            .header_params
            .get("p2s")
            .and_then(Value::as_str)
            .unwrap();
        assert_eq!(crate::util::b64url_decode(p2s).unwrap(), vec![0x44; 256]);
    }

    #[test]
    fn encrypt_options_of_other_algs_are_not_checked_here() {
        // The other families ignore p2c and p2s_len.
        let opts = options(Some(u32::MAX), Some(usize::MAX));
        assert_eq!(check_encrypt_options(&KeyMgmtAlg::A128KW, &opts), Ok(()));
    }

    #[test]
    fn encrypt_refuses_other_keys_algs_and_ceks() {
        let alg = KeyMgmtAlg::Pbes2Hs256A128KW;
        let enc = ContentEncAlg::A128GCM;
        let opts = options(None, None);
        let mut rng = FixedRng::new(vec![0; 16]);
        let symmetric = RecipientKey::Symmetric(Zeroizing::new(vec![1; 16]));
        let cek = cek_for(&enc);
        assert_eq!(
            encrypt_key(&alg, &symmetric, &enc, Some(&cek), &opts, &mut rng).map(|_| ()),
            Err(Error::KeyAlgorithmMismatch)
        );
        assert_eq!(
            encrypt_key(
                &KeyMgmtAlg::A128KW,
                &password(PASSWORD),
                &enc,
                Some(&cek),
                &opts,
                &mut rng
            )
            .map(|_| ()),
            Err(Error::UnsupportedAlgorithm)
        );
        // RFC 7516 §5.1 step 2: the CEK has the length enc requires.
        let wrong = cek_for(&ContentEncAlg::A256GCM);
        for cek in [None, Some(&wrong)] {
            assert!(matches!(
                encrypt_key(&alg, &password(PASSWORD), &enc, cek, &opts, &mut rng),
                Err(Error::InvalidKey(_))
            ));
        }
        assert_eq!(rng.remaining(), 16, "drew before the checks");
        // An RNG failure is reported, not papered over (ADR 0005).
        let mut empty = FixedRng::new(Vec::new());
        assert_eq!(
            encrypt_key(
                &alg,
                &password(PASSWORD),
                &enc,
                Some(&cek),
                &opts,
                &mut empty
            )
            .map(|_| ()),
            Err(Error::RandomnessUnavailable)
        );
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
