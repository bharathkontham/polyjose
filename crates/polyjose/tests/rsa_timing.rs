//! A dudect-style statistical timing test of polyjose's RSA private-key
//! operations (PRD 0003 R6, ADR 0067 T4, ADR 0055 §3.6): Welch's t-test on
//! the execution times of two input classes, after Reparaz, Balasch and
//! Verbauwhede, "Dude, is my code constant time?" (DATE 2017).
//!
//! It is evidence, not a proof: it can show a timing difference, never its
//! absence. polyjose does not run the Marvin toolkit (owner, ADR 0067 T4).
//!
//! # The classes
//!
//! - **RSA-OAEP-256 decryption** (RFC 7518 §4.3), through the public
//!   `jwe::decrypt_compact`, on JWEs that both fail with
//!   `DecryptionFailed` by the same path (RFC 7516 §11.5): class 0 has a
//!   *valid* Encrypted Key and a tampered tag, class 1 a *random* Encrypted
//!   Key below the modulus (so OAEP decoding fails and a random CEK is
//!   substituted). A difference would be an oracle on the Encrypted Key,
//!   which RFC 7516 §11.5 forbids. The random key is kept below n because
//!   a ciphertext representative of at least n is refused before any
//!   private-key arithmetic (RFC 8017 §5.1.2 step 1): that check depends on
//!   public values only (the ciphertext and n) and so reveals nothing, but
//!   it is fast enough to dominate the statistic (|t| ≈ 60 with
//!   unrestricted random keys).
//! - **RS256 and PS256 signing** (RFC 7518 §3.3, §3.5), through
//!   `jws::sign_compact`: class 0 signs one fixed payload, class 1 a fresh
//!   random payload each time (dudect's fixed-versus-random).
//!
//! Classes are interleaved at random (bits from the OS CSPRNG) so drift in
//! the machine's state spreads over both. The t statistic is computed on
//! the whole sample and on samples cropped at increasing percentiles, as
//! dudect does, and the largest |t| is reported. dudect reads |t| > 10 as
//! "definitely not constant time"; 4.5 is the usual threshold for a
//! suspicion. This test fails at 10 and prints a warning above 4.5.
//!
//! # Running it
//!
//! Not part of the fast suite (`#[ignore]`) and never in the Criterion
//! benches (ADR 0036): it measures time, so it runs alone, in release
//! mode, on an otherwise idle machine:
//!
//! ```text
//! cargo test -p polyjose --release --test rsa_timing -- --ignored --nocapture --test-threads=1
//! ```
//!
//! `POLYJOSE_DUDECT_SAMPLES` sets the number of measurements per test
//! (default 20000, both classes together).
//!
//! # Reuse on wasm32 (feature 0020 T02)
//!
//! [`welch`] and [`run`] need no `std::time`: the clock is a parameter
//! (`FnMut() -> u64`, any monotonic unit), so a wasm32 runner can pass
//! `performance.now()` and reuse the classes and the statistics unchanged.
//! Only [`native_clock`] and the `#[test]` wrappers are native.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a panic is a failed assertion

use polyjose::Error;
use polyjose::header::Header;
use polyjose::jwa::{ContentEncAlg, KeyMgmtAlg, SigningAlg};
use polyjose::jwe::{DecryptPolicy, Encryptor, Recipient, decrypt_compact};
use polyjose::jwk::Jwk;
use polyjose::jws::{ProtectedHeader, SignOptions, sign_compact};

/// Welch's t-test on streaming samples, with dudect's percentile crops.
pub mod welch {
    /// Running mean and variance of one class (Welford's algorithm).
    #[derive(Clone, Copy, Default)]
    pub struct Moments {
        n: f64,
        mean: f64,
        m2: f64,
    }

    impl Moments {
        /// Adds one sample.
        pub fn push(&mut self, x: f64) {
            self.n += 1.0;
            let delta = x - self.mean;
            self.mean += delta / self.n;
            self.m2 += delta * (x - self.mean);
        }

        /// The number of samples.
        pub fn count(&self) -> f64 {
            self.n
        }

        fn variance(&self) -> f64 {
            if self.n < 2.0 {
                0.0
            } else {
                self.m2 / (self.n - 1.0)
            }
        }
    }

    /// Welch's t between two classes: (mean0 − mean1) / sqrt(var0/n0 +
    /// var1/n1). Zero when either class has fewer than two samples.
    pub fn t(a: &Moments, b: &Moments) -> f64 {
        if a.n < 2.0 || b.n < 2.0 {
            return 0.0;
        }
        let se = (a.variance() / a.n + b.variance() / b.n).sqrt();
        if se == 0.0 {
            0.0
        } else {
            (a.mean - b.mean) / se
        }
    }

    /// The crop thresholds dudect uses: the 1 − 0.5^(10·(i+1)/100)
    /// percentiles of the pooled samples, for i in 0..100, plus no crop.
    pub fn thresholds(samples: &[(u8, u64)]) -> Vec<u64> {
        let mut sorted: Vec<u64> = samples.iter().map(|&(_, t)| t).collect();
        sorted.sort_unstable();
        let mut out = vec![u64::MAX];
        for i in 0..100 {
            let p = 1.0 - 0.5f64.powf(10.0 * f64::from(i + 1) / 100.0);
            let index = ((sorted.len() as f64) * p) as usize;
            out.push(sorted[index.min(sorted.len() - 1)]);
        }
        out
    }

    /// The largest |t| over the crops, and the sample counts of the uncropped
    /// classes.
    pub fn max_abs_t(samples: &[(u8, u64)]) -> (f64, f64, f64) {
        let mut worst: f64 = 0.0;
        let mut counts = (0.0, 0.0);
        for (index, limit) in thresholds(samples).into_iter().enumerate() {
            let mut classes = [Moments::default(); 2];
            for &(class, time) in samples {
                if time <= limit {
                    classes[usize::from(class)].push(time as f64);
                }
            }
            if index == 0 {
                counts = (classes[0].count(), classes[1].count());
            }
            worst = worst.max(t(&classes[0], &classes[1]).abs());
        }
        (worst, counts.0, counts.1)
    }

    #[test]
    fn welch_t_separates_shifted_classes_and_not_equal_ones() {
        // A deterministic check of the statistic itself (no timing).
        let mut same = Vec::new();
        let mut shifted = Vec::new();
        for i in 0..2000u64 {
            let noise = (i * 7919) % 101;
            same.push(((i % 2) as u8, 1000 + noise));
            shifted.push(((i % 2) as u8, 1000 + noise + 40 * (i % 2)));
        }
        assert!(max_abs_t(&same).0 < 4.5);
        assert!(max_abs_t(&shifted).0 > 10.0);
    }
}

/// Measures `samples` runs of `op(class)`, the class drawn at random for
/// each run, with `clock` read before and after. `prepare(class)` runs
/// outside the timed region (dudect prepares inputs first).
pub fn run<T>(
    samples: usize,
    mut clock: impl FnMut() -> u64,
    mut random_bit: impl FnMut() -> u8,
    mut prepare: impl FnMut(u8) -> T,
    mut op: impl FnMut(&T),
) -> Vec<(u8, u64)> {
    let mut out = Vec::with_capacity(samples);
    // Warm up both classes (caches, branch predictors, allocations).
    for class in [0, 1, 0, 1] {
        let input = prepare(class);
        op(&input);
    }
    for _ in 0..samples {
        let class = random_bit() & 1;
        let input = prepare(class);
        let start = clock();
        op(&input);
        let end = clock();
        out.push((class, end.saturating_sub(start)));
    }
    out
}

/// The native clock: nanoseconds since a fixed instant.
fn native_clock() -> impl FnMut() -> u64 {
    let origin = std::time::Instant::now();
    move || u64::try_from(origin.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

/// One bit from the OS CSPRNG (ADR 0005), buffered 64 at a time.
fn os_bits() -> impl FnMut() -> u8 {
    let mut word = 0u64;
    let mut left = 0;
    move || {
        if left == 0 {
            let mut bytes = [0u8; 8];
            getrandom::fill(&mut bytes).unwrap();
            word = u64::from_le_bytes(bytes);
            left = 64;
        }
        let bit = (word & 1) as u8;
        word >>= 1;
        left -= 1;
        bit
    }
}

fn os_bytes(len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    getrandom::fill(&mut out).unwrap();
    out
}

fn samples() -> usize {
    std::env::var("POLYJOSE_DUDECT_SAMPLES")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(20_000)
}

/// RFC 7515 Appendix A.2.1's 2048-bit RSA private key.
fn rsa_key() -> Jwk {
    Jwk::from_json(include_bytes!(
        "data/keys/rfc/rfc7515-a2-rsa-private.jwk.json"
    ))
    .unwrap()
}

/// Prints and checks one measurement set.
fn report(what: &str, samples: &[(u8, u64)]) {
    let (t, n0, n1) = welch::max_abs_t(samples);
    let verdict = if t > 10.0 {
        "LEAK (|t| > 10)"
    } else if t > 4.5 {
        "suspicious (4.5 < |t| <= 10): re-run on an idle machine"
    } else {
        "no leak detected (|t| <= 4.5)"
    };
    println!("dudect {what}: max |t| = {t:.2} over {n0} + {n1} samples: {verdict}");
    assert!(t <= 10.0, "{what}: max |t| = {t:.2}");
}

fn b64url(bytes: &[u8]) -> String {
    // RFC 7515 §2 base64url without padding (test-local, no dependency).
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for i in 0..=chunk.len() {
            out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
        }
    }
    out
}

/// The OAEP classes: a valid JWE with a tampered tag, or the same JWE with
/// a random Encrypted Key. Both are `DecryptionFailed` (RFC 7516 §11.5).
fn oaep_inputs(key: &Jwk) -> impl FnMut(u8) -> String + use<> {
    let public = key.to_public().unwrap();
    let jwe = Encryptor::new(ContentEncAlg::A128GCM)
        .recipient(Recipient::new(KeyMgmtAlg::RsaOaep256, &public))
        .encrypt_compact(b"dudect: RSA-OAEP-256 Encrypted Key timing")
        .unwrap();
    let parts: Vec<String> = jwe.split('.').map(str::to_owned).collect();
    // Flip one tag character to another valid one (the tag is 16 octets:
    // the last character carries 2 padding bits, so change the first).
    let mut tag = parts[4].clone();
    let first = if tag.starts_with('A') { "B" } else { "A" };
    tag.replace_range(0..1, first);
    move |class| {
        let encrypted_key = if class == 0 {
            parts[1].clone()
        } else {
            // Below n: the A.2 modulus starts with 0xa1 (RFC 7515 A.2.1).
            let mut random = os_bytes(256);
            random[0] &= 0x7f;
            b64url(&random)
        };
        [
            parts[0].as_str(),
            &encrypted_key,
            &parts[2],
            &parts[3],
            &tag,
        ]
        .join(".")
    }
}

#[test]
#[ignore = "statistical timing test: run alone in release mode (see the module docs)"]
fn dudect_rsa_oaep_256_valid_and_invalid_encrypted_keys() {
    let key = rsa_key();
    let policy = DecryptPolicy::new(&[KeyMgmtAlg::RsaOaep256], &[ContentEncAlg::A128GCM]).unwrap();
    let mut prepare = oaep_inputs(&key);
    // Both classes fail the same way before anything is measured.
    for class in [0, 1] {
        let jwe = prepare(class);
        assert_eq!(
            decrypt_compact(&jwe, &key, &policy).err(),
            Some(Error::DecryptionFailed)
        );
    }
    let measured = run(samples(), native_clock(), os_bits(), prepare, |jwe| {
        let result = decrypt_compact(jwe, &key, &policy);
        std::hint::black_box(result.is_err());
    });
    report("RSA-OAEP-256 valid vs random Encrypted Key", &measured);
}

fn signing(alg: SigningAlg) {
    let key = rsa_key();
    let header = Header::from_json(format!(r#"{{"alg":"{alg}"}}"#).as_bytes()).unwrap();
    let protected = ProtectedHeader::new(header).unwrap();
    let opts = SignOptions::new();
    let fixed = vec![0x5a; 64];
    let prepare = |class: u8| {
        if class == 0 {
            fixed.clone()
        } else {
            os_bytes(64)
        }
    };
    let measured = run(samples(), native_clock(), os_bits(), prepare, |payload| {
        let jws = sign_compact(&protected, payload, &key, &opts);
        std::hint::black_box(jws.is_ok());
    });
    report(&format!("{alg} fixed vs random payload"), &measured);
}

#[test]
#[ignore = "statistical timing test: run alone in release mode (see the module docs)"]
fn dudect_rs256_signing_fixed_and_random_messages() {
    signing(SigningAlg::RS256);
}

#[test]
#[ignore = "statistical timing test: run alone in release mode (see the module docs)"]
fn dudect_ps256_signing_fixed_and_random_messages() {
    signing(SigningAlg::PS256);
}
