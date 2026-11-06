//! The single source of randomness in polyjose: the OS CSPRNG (ADR 0005).
//!
//! JOSE is only as strong as its random values. Keys need enough entropy
//! (RFC 7515 §10.1); JWE also draws Content Encryption Keys and IVs from it
//! (RFC 7516 §11.1, RFC 7518 §8.9), AES-CBC needs a random 128-bit IV
//! (RFC 7518 §5.2.2.1), an AES-GCM IV must never repeat under one key
//! (RFC 7518 §8.4), ECDH-ES needs a fresh ephemeral key per operation
//! (RFC 7518 §4.6) and PBES2 a fresh random salt per encryption
//! (RFC 7518 §4.8.1.1).
//!
//! Every random byte comes from [`fill_random`], which calls the OS CSPRNG
//! through `getrandom` 0.4 and fails closed: there is no fallback source, no
//! retry loop of our own and no switchable source in production code. On
//! `wasm32-unknown-unknown` the backend is `crypto.getRandomValues`, which
//! the WASM binding selects with getrandom's `wasm_js` crate feature (see
//! `bindings/wasm/Cargo.toml`).
//!
//! The only other byte source is `insecure_test_vectors::FixedRng`, compiled
//! for polyjose's own tests and behind the off-by-default
//! `insecure-test-vectors` feature, which no binding may enable
//! (`scripts/check-test-vectors-off.sh`).

use core::fmt;
use core::marker::PhantomData;

use p256::elliptic_curve::rand_core::{TryCryptoRng, TryRng};
use zeroize::Zeroize;

use crate::{Error, Result};

/// Fills `dest` with bytes from the operating-system CSPRNG (ADR 0005).
///
/// Use it for every key, CEK, IV, salt and ephemeral key (RFC 7515 §10.1,
/// RFC 7516 §11.1, RFC 7518 §8.9).
///
/// # Errors
///
/// [`Error::RandomnessUnavailable`] if the OS source fails. The call is
/// made once; getrandom itself only retries interrupted system calls. On
/// failure `dest` is zeroed, so no partial output survives, and the error
/// carries no backend or OS detail.
///
/// There is no process-wide or thread-local switch to another source: this
/// body always calls `getrandom::fill` and has no `cfg`, so it is the same
/// with or without the `insecure-test-vectors` feature. A
/// `insecure_test_vectors::FixedRng` is used only where a caller passes one
/// explicitly (ADR 0005).
pub(crate) fn fill_random(dest: &mut [u8]) -> Result<()> {
    let outcome = getrandom::fill(dest);
    fail_closed(dest, outcome)
}

/// Maps the outcome of a `getrandom` call to polyjose's result, failing
/// closed.
///
/// Any `getrandom::Error` becomes a detail-free
/// [`Error::RandomnessUnavailable`] (ADR 0005, ADR 0007) and `dest` is
/// zeroed. It is a separate pure function so tests can inject every
/// `getrandom::Error` without a switchable source in production code.
fn fail_closed(dest: &mut [u8], outcome: core::result::Result<(), getrandom::Error>) -> Result<()> {
    match outcome {
        Ok(()) => Ok(()),
        Err(_) => {
            dest.zeroize();
            Err(Error::RandomnessUnavailable)
        }
    }
}

/// The crate's one rand_core 0.10 RNG, for the primitive crates that take
/// an RNG parameter (ADR 0005).
///
/// It implements `rand_core::TryRng` (with `Error =`
/// [`Error`]) and the `rand_core::TryCryptoRng` marker,
/// reached through `p256::elliptic_curve::rand_core`, so polyjose has no
/// direct `rand_core` dependency. These are the only `TryRng` and
/// `TryCryptoRng` impls in the crate. It draws from:
///
/// - **the OS CSPRNG** ([`CryptoRngAdapter::os`]): every byte of every
///   call comes straight from [`fill_random`], with nothing buffered,
///   seeded or cached. This is the only source in a build without the
///   `insecure-test-vectors` feature, where the adapter is zero-sized
///   (checked at compile time) like getrandom's own `SysRng`;
/// - **an explicitly passed `FixedRng`** (`CryptoRngAdapter::fixed`), only
///   in polyjose's own tests or with the `insecure-test-vectors` feature
///   (ADR 0041 §3), to reproduce published vectors. That constructor and
///   its source variant do not exist otherwise, so no production path can
///   select it, and nothing global can switch an `os()` adapter to it.
///
/// Callers that need randomness take `&mut CryptoRngAdapter` (or
/// `&mut impl TryCryptoRng`) as a parameter; public APIs create
/// [`CryptoRngAdapter::os`] themselves. Uses: the added entropy of hedged
/// RFC 6979 ECDSA signing (`ecdsa`'s `try_sign_with_rng`; RFC 7518 §3.4,
/// RFC 8812 §3.2), which ADR 0005 requires so that a weak RNG cannot leak
/// the key, and later JWE and key generation.
///
/// A failure is [`Error::RandomnessUnavailable`] and leaves no partial
/// output (the OS path through [`fill_random`], a `FixedRng` by running
/// out). The adapter provides bytes only; it is not a key generator. It is
/// deliberately not `Clone` or `Copy` (rand_core's advice for
/// cryptographic RNGs), and its `Debug` names the source only.
pub(crate) struct CryptoRngAdapter<'a>(Source<'a>);

/// Where a [`CryptoRngAdapter`] draws its bytes from.
enum Source<'a> {
    /// The OS CSPRNG through [`fill_random`]. The marker only carries the
    /// lifetime, which a build without the test sources leaves unused.
    Os(PhantomData<&'a mut ()>),
    /// A deterministic `FixedRng` the caller passed explicitly (ADR 0041 §3).
    #[cfg(any(test, feature = "insecure-test-vectors"))]
    Fixed(&'a mut insecure_test_vectors::FixedRng),
    /// Test-only: an OS source that fails with this `getrandom::Error`,
    /// fed through [`fail_closed`], the mapping [`fill_random`] itself uses.
    /// It reaches a caller's `RandomnessUnavailable` path (ADR 0005).
    #[cfg(test)]
    Failing(getrandom::Error),
}

// Without the test sources the adapter is a zero-sized handle on the OS
// CSPRNG: there is no state to seed, share or switch (ADR 0005).
#[cfg(not(any(test, feature = "insecure-test-vectors")))]
const _: () = assert!(core::mem::size_of::<CryptoRngAdapter<'static>>() == 0);

impl CryptoRngAdapter<'_> {
    /// An adapter over the OS CSPRNG ([`fill_random`], ADR 0005).
    pub(crate) fn os() -> Self {
        CryptoRngAdapter(Source::Os(PhantomData))
    }

    /// Fills `dest` from the source; on failure `dest` is zeroed.
    fn fill(&mut self, dest: &mut [u8]) -> Result<()> {
        match &mut self.0 {
            Source::Os(_) => fill_random(dest),
            #[cfg(any(test, feature = "insecure-test-vectors"))]
            Source::Fixed(rng) => rng.fill(dest),
            #[cfg(test)]
            Source::Failing(injected) => fail_closed(dest, Err(*injected)),
        }
    }
}

#[cfg(any(test, feature = "insecure-test-vectors"))]
impl<'a> CryptoRngAdapter<'a> {
    /// An adapter over `rng`, a deterministic source a test passes
    /// explicitly to reproduce published vectors (ADR 0005, ADR 0041 §3).
    /// It exists only in polyjose's own tests and with the
    /// `insecure-test-vectors` feature.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "used by the RFC 7520 JWE vector tests of feature 0003"
        )
    )]
    pub(crate) fn fixed(rng: &'a mut insecure_test_vectors::FixedRng) -> Self {
        CryptoRngAdapter(Source::Fixed(rng))
    }
}

#[cfg(test)]
impl CryptoRngAdapter<'_> {
    /// Test-only: an adapter whose OS source fails with `injected`, through
    /// the [`fail_closed`] injection point.
    pub(crate) fn failing(injected: getrandom::Error) -> Self {
        CryptoRngAdapter(Source::Failing(injected))
    }
}

impl fmt::Debug for CryptoRngAdapter<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The source kind only: never a FixedRng's bytes (test keys).
        let source = match self.0 {
            Source::Os(_) => "Os",
            #[cfg(any(test, feature = "insecure-test-vectors"))]
            Source::Fixed(_) => "Fixed",
            #[cfg(test)]
            Source::Failing(_) => "Failing",
        };
        f.debug_tuple("CryptoRngAdapter").field(&source).finish()
    }
}

impl TryRng for CryptoRngAdapter<'_> {
    type Error = Error;

    /// Four bytes, little-endian (rand_core's convention for words built
    /// from bytes).
    fn try_next_u32(&mut self) -> Result<u32> {
        let mut bytes = [0u8; 4];
        self.fill(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    /// Eight bytes, little-endian.
    fn try_next_u64(&mut self) -> Result<u64> {
        let mut bytes = [0u8; 8];
        self.fill(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<()> {
        self.fill(dst)
    }
}

/// The OS CSPRNG is cryptographically secure (ADR 0005). A `FixedRng`
/// source is not, which is why it exists only in tests and behind the
/// `insecure-test-vectors` feature.
impl TryCryptoRng for CryptoRngAdapter<'_> {}

/// Deterministic byte source for reproducing published test vectors.
///
/// **Never use this in production.** Its output is fixed by the caller and
/// is not random. It exists only so tests can reproduce outputs that depend
/// on "random" values, such as the CEKs and IVs of the RFC 7520 JWE
/// examples. Outside polyjose's own unit tests it exists only with the
/// off-by-default `insecure-test-vectors` cargo feature (ADR 0005), and
/// `scripts/check-test-vectors-off.sh` fails if any binding enables it.
///
/// A `FixedRng` is a plain value that is reachable only as an explicit
/// parameter a test passes in. It can never be installed as polyjose's random
/// source: there is no global or thread-local RNG switch, and
/// polyjose's OS source (`fill_random`) has no code path to it, even with
/// the feature on.
///
/// ```
/// use polyjose::insecure_test_vectors::FixedRng;
///
/// let mut rng = FixedRng::new([0x01, 0x02, 0x03]);
/// let mut iv = [0u8; 2];
/// rng.fill(&mut iv)?;
/// assert_eq!(iv, [0x01, 0x02]);
/// assert!(rng.fill(&mut [0u8; 2]).is_err()); // only one byte is left
/// # Ok::<(), polyjose::Error>(())
/// ```
#[cfg(any(test, feature = "insecure-test-vectors"))]
pub mod insecure_test_vectors {
    use zeroize::{Zeroize, Zeroizing};

    use crate::{Error, Result};

    /// Replays a fixed byte sequence, in order and exactly once.
    ///
    /// It never wraps around or pads: a repeated IV would break AES-GCM
    /// (RFC 7518 §8.4), so running out is an error, just like a failing OS
    /// source. The bytes are zeroized on drop, since they become test keys.
    pub struct FixedRng {
        bytes: Zeroizing<Vec<u8>>,
        pos: usize,
    }

    impl FixedRng {
        /// Creates a source that hands out `bytes` in order, exactly once.
        pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
            Self {
                bytes: Zeroizing::new(bytes.into()),
                pos: 0,
            }
        }

        /// Fills `dest` with the next `dest.len()` bytes.
        ///
        /// # Errors
        ///
        /// [`Error::RandomnessUnavailable`] if fewer than `dest.len()` bytes
        /// are left. Nothing is consumed and `dest` is zeroed, matching the
        /// fail-closed behaviour of the OS source.
        pub fn fill(&mut self, dest: &mut [u8]) -> Result<()> {
            let next = self
                .pos
                .checked_add(dest.len())
                .and_then(|end| self.bytes.get(self.pos..end).map(|src| (src, end)));
            match next {
                Some((src, end)) => {
                    dest.copy_from_slice(src);
                    self.pos = end;
                    Ok(())
                }
                None => {
                    dest.zeroize();
                    Err(Error::RandomnessUnavailable)
                }
            }
        }

        /// The number of bytes not yet handed out.
        pub fn remaining(&self) -> usize {
            self.bytes.len().saturating_sub(self.pos)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn replays_bytes_in_order_across_calls() {
            let mut rng = FixedRng::new([1u8, 2, 3, 4, 5]);
            let (mut a, mut b) = ([0u8; 2], [0u8; 3]);
            assert_eq!(rng.fill(&mut a), Ok(()));
            assert_eq!(rng.fill(&mut b), Ok(()));
            assert_eq!((a, b), ([1, 2], [3, 4, 5]));
            assert_eq!(rng.remaining(), 0);
        }

        #[test]
        fn empty_request_consumes_nothing() {
            let mut rng = FixedRng::new([7u8]);
            assert_eq!(rng.fill(&mut []), Ok(()));
            assert_eq!(rng.remaining(), 1);
        }

        #[test]
        fn exhaustion_fails_closed_without_wrapping() {
            // Never repeat or pad: a reused AES-GCM IV breaks JWE
            // (RFC 7518 §8.4). Asking for more than is left is an error, the
            // output is zeroed and nothing is consumed.
            let mut rng = FixedRng::new([1u8, 2, 3]);
            let mut buf = [0xA5u8; 4];
            assert_eq!(rng.fill(&mut buf), Err(Error::RandomnessUnavailable));
            assert_eq!(buf, [0u8; 4]);
            assert_eq!(rng.remaining(), 3);
            let mut rest = [0u8; 3];
            assert_eq!(rng.fill(&mut rest), Ok(()));
            assert_eq!(rest, [1, 2, 3]);
            assert_eq!(rng.fill(&mut [0u8; 1]), Err(Error::RandomnessUnavailable));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fills_with_os_randomness() {
        // 256 bits: an all-zero or repeated output is a 2^-256 event, not flakiness.
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        assert_eq!(fill_random(&mut a), Ok(()));
        assert_eq!(fill_random(&mut b), Ok(()));
        assert_ne!(a, [0u8; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn fill_random_never_consults_a_fixed_rng() {
        // A FixedRng in scope is just a value: fill_random still reads the OS
        // source and leaves the fixed bytes untouched (ADR 0005).
        let rng = insecure_test_vectors::FixedRng::new([0u8; 32]);
        let mut buf = [0u8; 32];
        assert_eq!(fill_random(&mut buf), Ok(()));
        assert_ne!(buf, [0u8; 32]);
        assert_eq!(rng.remaining(), 32);
    }

    #[test]
    fn fill_random_has_one_unconditional_source() {
        // The body is the same with or without `insecure-test-vectors`: no
        // `cfg`, no reference to the fixed source, only `getrandom::fill`.
        let src = include_str!("rng.rs");
        let start = src.find("pub(crate) fn fill_random(");
        assert!(start.is_some(), "fill_random not found");
        let body = &src[start.unwrap_or_default()..];
        let end = body.find("\n}\n");
        assert!(end.is_some(), "end of fill_random not found");
        let body = &body[..end.unwrap_or_default()];
        assert!(body.contains("getrandom::fill(dest)"), "{body}");
        for banned in ["cfg", "FixedRng", "insecure", "static", "thread"] {
            assert!(!body.contains(banned), "fill_random mentions {banned}");
        }
    }

    #[test]
    fn no_global_or_thread_local_state_can_switch_the_rng() {
        // A global RNG switch needs process-wide or thread-local state:
        // `static` items or `thread_local!`. polyjose's library code has
        // none, so FixedRng can only be passed explicitly. The banned tokens
        // are split so this test does not match itself.
        //
        // One file is exempt: `src/test_counters.rs`, the thread-local
        // operation counters that let tests bound the work of untrusted-input
        // paths without wall-clock timing. It is skipped only after this test
        // proves it never reaches a non-test build: the file opens with
        // `#![cfg(test)]`, and the crate declares it exactly once, as
        // `mod test_counters;` in `lib.rs` directly under `#[cfg(test)]`.
        let banned = [
            ["thread", "_local!"].concat(),
            ["Once", "Lock"].concat(),
            ["Once", "Cell"].concat(),
            ["Lazy", "Lock"].concat(),
            ["Lazy", "Cell"].concat(),
            ["Atomic", "Ptr"].concat(),
        ];
        let is_static_item = |line: &str| {
            let item = ["pub(crate) ", "pub(super) ", "pub "]
                .iter()
                .find_map(|vis| line.strip_prefix(vis))
                .unwrap_or(line);
            item.starts_with(&["static", " "].concat())
        };
        let src = std::path::PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/src"));
        let exempt = src.join(["test", "_counters.rs"].concat());
        let exempt_mod = ["test", "_counters"].concat();
        // Any `mod test_counters`, whatever its visibility, attributes or
        // spacing: the word `mod` followed by the module's name.
        let declares_exempt = |line: &str| {
            let words: Vec<&str> = line
                .split(|c: char| !(c.is_alphanumeric() || c == '_'))
                .filter(|w| !w.is_empty())
                .collect();
            words
                .windows(2)
                .any(|w| w[0] == "mod" && w[1] == exempt_mod)
        };
        // (file, declaration line, the line directly above it), trimmed.
        let mut declarations = Vec::new();
        let mut exempt_text = None;
        let mut dirs = vec![src.clone()];
        let mut scanned = 0;
        while let Some(dir) = dirs.pop() {
            let entries = std::fs::read_dir(&dir);
            assert!(entries.is_ok(), "cannot read {}", dir.display());
            for entry in entries.into_iter().flatten() {
                assert!(entry.is_ok(), "cannot list {}", dir.display());
                let Ok(path) = entry.map(|e| e.path()) else {
                    continue;
                };
                if path.is_dir() {
                    dirs.push(path);
                    continue;
                }
                if path.extension().is_none_or(|ext| ext != "rs") {
                    continue;
                }
                let text = std::fs::read_to_string(&path);
                assert!(text.is_ok(), "cannot read {}", path.display());
                let text = text.unwrap_or_default();
                scanned += 1;
                let mut previous = "";
                for (n, line) in text.lines().enumerate() {
                    let line = line.trim();
                    if !line.starts_with("//") && declares_exempt(line) {
                        declarations.push((path.clone(), line.to_owned(), previous.to_owned()));
                    }
                    previous = line;
                    if path == exempt || line.starts_with("//") {
                        continue;
                    }
                    let hit = banned.iter().any(|b| line.contains(b.as_str()));
                    assert!(
                        !hit && !is_static_item(line),
                        "{}:{}: global or thread-local state: {line}",
                        path.display(),
                        n + 1
                    );
                }
                if path == exempt {
                    exempt_text = Some(text);
                }
            }
        }
        // Guard against a vacuous pass if the layout changes.
        assert!(scanned >= 10, "scanned only {scanned} source files");

        // The exemption holds only while the exempt file is test-only.
        if let Some(text) = exempt_text {
            let first_code = text
                .lines()
                .map(str::trim)
                .find(|l| !l.is_empty() && !l.starts_with("//"));
            assert_eq!(
                first_code,
                Some("#![cfg(test)]"),
                "{} must open with #![cfg(test)]",
                exempt.display()
            );
            let expected = [(
                src.join("lib.rs"),
                ["mod ", &exempt_mod, ";"].concat(),
                "#[cfg(test)]".to_owned(),
            )];
            assert_eq!(
                declarations, expected,
                "{exempt_mod} must be declared exactly once, as `mod {exempt_mod};` \
                 in lib.rs directly under #[cfg(test)]"
            );
        }
    }

    #[test]
    fn empty_buffer_is_ok() {
        assert_eq!(fill_random(&mut []), Ok(()));
    }

    #[test]
    fn fills_every_chunk_of_a_large_buffer() {
        // Larger than the 65,536-byte `crypto.getRandomValues` limit that
        // getrandom chunks around on WASM; every 32-byte window must be filled.
        let mut buf = vec![0u8; 65_536 + 4_096];
        assert_eq!(fill_random(&mut buf), Ok(()));
        assert!(buf.chunks(32).all(|c| c.iter().any(|&b| b != 0)));
    }

    /// Every `getrandom::Error` a test can construct. OS errors (`errno`)
    /// can't be built outside getrandom; they take the same `Err(_)` arm.
    fn injected_errors() -> [getrandom::Error; 5] {
        [
            getrandom::Error::UNSUPPORTED,
            getrandom::Error::ERRNO_NOT_POSITIVE,
            getrandom::Error::UNEXPECTED,
            getrandom::Error::new_custom(0),
            getrandom::Error::new_custom(u16::MAX),
        ]
    }

    #[test]
    fn success_passes_through_untouched() {
        let mut buf = [0xA5u8; 16];
        assert_eq!(fail_closed(&mut buf, Ok(())), Ok(()));
        assert_eq!(buf, [0xA5u8; 16]);
    }

    #[test]
    fn failure_leaves_no_partial_output() {
        // A backend may fail after writing part of `dest` (getrandom chunks
        // large requests); none of it may survive as if it were usable.
        for injected in injected_errors() {
            let mut buf = [0xA5u8; 16];
            assert!(fail_closed(&mut buf, Err(injected)).is_err());
            assert_eq!(buf, [0u8; 16], "{injected:?}");
        }
    }

    #[test]
    fn every_getrandom_error_maps_to_randomness_unavailable() {
        for injected in injected_errors() {
            let e = fail_closed(&mut [0u8; 4], Err(injected)).err();
            assert_eq!(e, Some(Error::RandomnessUnavailable), "{injected:?}");
        }
    }

    #[test]
    fn mapped_error_carries_no_backend_detail() {
        // getrandom's own message names the backend or OS error; ours must
        // not, and must not expose it as a cause either (ADR 0007).
        for injected in injected_errors() {
            let Err(e) = fail_closed(&mut [0u8; 4], Err(injected)) else {
                unreachable!("an injected error must fail");
            };
            assert_eq!(e.code(), "RandomnessUnavailable");
            assert_eq!(format!("{e:?}"), "RandomnessUnavailable");
            assert_eq!(e.to_string(), "randomness unavailable");
            assert!(!e.to_string().contains(&injected.to_string()));
            assert!(std::error::Error::source(&e).is_none());
        }
    }

    /// Compiles only for a `TryCryptoRng`: the bound `ecdsa`'s
    /// `try_sign_with_rng` and elliptic-curve's `Generate` place on an RNG.
    fn require_try_crypto_rng<R: TryCryptoRng<Error = Error>>(_: &R) {}

    #[test]
    fn every_adapter_source_is_a_try_crypto_rng() {
        let mut fixed = insecure_test_vectors::FixedRng::new([0u8; 1]);
        require_try_crypto_rng(&CryptoRngAdapter::os());
        require_try_crypto_rng(&CryptoRngAdapter::fixed(&mut fixed));
        require_try_crypto_rng(&CryptoRngAdapter::failing(getrandom::Error::UNSUPPORTED));
    }

    #[test]
    fn os_adapter_fills_bytes_from_the_os() {
        // 256 bits each: equal or all-zero outputs are 2^-256 events.
        let mut rng = CryptoRngAdapter::os();
        let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
        assert_eq!(rng.try_fill_bytes(&mut a), Ok(()));
        assert_eq!(rng.try_fill_bytes(&mut b), Ok(()));
        assert_ne!(a, [0u8; 32]);
        assert_ne!(a, b);
        assert_eq!(rng.try_fill_bytes(&mut []), Ok(()));
    }

    #[test]
    fn os_adapter_draws_words_from_the_os() {
        // Two 64-bit draws collide with probability 2^-64; four 32-bit draws
        // are all equal with probability 2^-96.
        let mut rng = CryptoRngAdapter::os();
        let (a, b) = (rng.try_next_u64(), rng.try_next_u64());
        assert!(a.is_ok() && b.is_ok());
        assert_ne!(a, b);
        let words: Vec<_> = (0..4).map(|_| rng.try_next_u32()).collect();
        assert!(words.iter().all(Result::is_ok));
        assert!(words.windows(2).any(|w| w[0] != w[1]), "{words:?}");
    }

    #[test]
    fn os_adapters_are_independent_of_a_fixed_rng_in_scope() {
        // An explicitly passed FixedRng feeds only its own adapter: an
        // os() adapter made alongside still reads the OS (ADR 0041 §3).
        let mut fixed = insecure_test_vectors::FixedRng::new([0u8; 32]);
        let _fixed_adapter = CryptoRngAdapter::fixed(&mut fixed);
        let mut buf = [0u8; 32];
        assert_eq!(CryptoRngAdapter::os().try_fill_bytes(&mut buf), Ok(()));
        assert_ne!(buf, [0u8; 32]);
    }

    #[test]
    fn fixed_adapter_replays_the_bytes_little_endian() {
        // rand_core builds words from bytes little-endian; pinning it keeps
        // vector reproduction stable.
        let bytes: Vec<u8> = (1..=16).collect();
        let mut fixed = insecure_test_vectors::FixedRng::new(bytes);
        {
            let mut rng = CryptoRngAdapter::fixed(&mut fixed);
            assert_eq!(rng.try_next_u32(), Ok(0x0403_0201));
            assert_eq!(rng.try_next_u64(), Ok(0x0c0b_0a09_0807_0605));
            let mut rest = [0u8; 4];
            assert_eq!(rng.try_fill_bytes(&mut rest), Ok(()));
            assert_eq!(rest, [13, 14, 15, 16]);
        }
        assert_eq!(fixed.remaining(), 0);
    }

    #[test]
    fn fixed_adapter_fails_closed_when_exhausted() {
        // Never wraps or pads (RFC 7518 §8.4 IV reuse); same error as the OS.
        let mut fixed = insecure_test_vectors::FixedRng::new([1u8, 2, 3]);
        let mut rng = CryptoRngAdapter::fixed(&mut fixed);
        assert_eq!(rng.try_next_u32(), Err(Error::RandomnessUnavailable));
        let mut buf = [0xA5u8; 4];
        assert_eq!(
            rng.try_fill_bytes(&mut buf),
            Err(Error::RandomnessUnavailable)
        );
        assert_eq!(buf, [0u8; 4]);
    }

    #[test]
    fn adapter_debug_names_the_source_only() {
        let mut fixed = insecure_test_vectors::FixedRng::new([0x5Au8; 8]);
        assert_eq!(
            format!("{:?}", CryptoRngAdapter::os()),
            r#"CryptoRngAdapter("Os")"#
        );
        let debug = format!("{:?}", CryptoRngAdapter::fixed(&mut fixed));
        assert_eq!(debug, r#"CryptoRngAdapter("Fixed")"#);
    }

    #[test]
    fn injected_getrandom_failure_surfaces_from_the_adapter() {
        // The adapter's failure path, through the fail_closed injection
        // point: every getrandom error is RandomnessUnavailable, with no
        // partial output left behind (ADR 0005, ADR 0007).
        for injected in injected_errors() {
            let mut rng = CryptoRngAdapter::failing(injected);
            let mut buf = [0xA5u8; 32];
            assert_eq!(
                rng.try_fill_bytes(&mut buf),
                Err(Error::RandomnessUnavailable),
                "{injected:?}"
            );
            assert_eq!(buf, [0u8; 32]);
            assert_eq!(rng.try_next_u32(), Err(Error::RandomnessUnavailable));
            assert_eq!(rng.try_next_u64(), Err(Error::RandomnessUnavailable));
        }
    }
}
