//! The public JWE API (RFC 7516): the decrypt policy, the decrypt result,
//! the encryptor and its recipients.
//!
//! The bodies here only delegate to `core`, `compact` and `json` (which
//! call `zip`), so the tasks that fill those in never edit this file.

use core::fmt;

use zeroize::Zeroizing;

use super::keymgmt::RecipientOptions;
use super::random::OsRandom;
use super::{compact, core as pipeline, json};
use crate::header::Header;
#[cfg(feature = "insecure-test-vectors")]
use crate::insecure_test_vectors::FixedRng;
use crate::jwa::{ContentEncAlg, KeyMgmtAlg};
use crate::jwk::Jwk;
use crate::{Error, Result};

/// What [`decrypt_compact`] and
/// [`decrypt_json`] accept (RFC 8725 §3.1,
/// ADR 0007).
///
/// A JWE is decrypted only if its `alg` and `enc` are both in the policy's
/// allow-lists: the header alone is never trusted. The limits bound the work
/// an attacker-chosen JWE can cause before it fails.
///
/// ```
/// use polyjose::jwa::{ContentEncAlg, KeyMgmtAlg};
/// use polyjose::jwe::DecryptPolicy;
///
/// let policy = DecryptPolicy::new(&[KeyMgmtAlg::A256KW], &[ContentEncAlg::A256GCM])?
///     .max_recipients(4);
/// # Ok::<(), polyjose::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct DecryptPolicy {
    // core.rs, keymgmt.rs and the families read these fields directly.
    pub(super) allowed_algs: Vec<KeyMgmtAlg>,
    pub(super) allowed_enc: Vec<ContentEncAlg>,
    pub(super) max_pbes2_count: u32,
    pub(super) max_decompressed_len: usize,
    pub(super) understood_crit: Vec<String>,
    pub(super) max_input_len: usize,
    pub(super) max_recipients: usize,
}

impl DecryptPolicy {
    /// The default [`max_pbes2_count`](DecryptPolicy::max_pbes2_count):
    /// 10,000 PBKDF2 iterations (ADR 0023).
    pub const DEFAULT_MAX_PBES2_COUNT: u32 = 10_000;

    /// The hard ceiling of [`max_pbes2_count`](DecryptPolicy::max_pbes2_count):
    /// 1,000,000 iterations (ADR 0023, ADR 0007).
    pub const MAX_PBES2_COUNT_CEILING: u32 = 1_000_000;

    /// The default
    /// [`max_decompressed_len`](DecryptPolicy::max_decompressed_len):
    /// 250,000 bytes (ADR 0017).
    pub const DEFAULT_MAX_DECOMPRESSED_LEN: usize = 250_000;

    /// The default [`max_input_len`](DecryptPolicy::max_input_len): 1 MiB,
    /// as for JWS (ADR 0026 §7).
    pub const DEFAULT_MAX_INPUT_LEN: usize = 1024 * 1024;

    /// The default [`max_recipients`](DecryptPolicy::max_recipients): 16,
    /// as the JWS signature limit (ADR 0026 §7).
    pub const DEFAULT_MAX_RECIPIENTS: usize = 16;

    /// A policy allowing exactly the key management algorithms
    /// `allowed_algs` and the content encryption algorithms `allowed_enc`,
    /// with the default limits and no understood `crit` extensions.
    ///
    /// An algorithm polyjose does not implement may be listed but never
    /// decrypts: a JWE using it fails with
    /// [`Error::UnsupportedAlgorithm`] before the allow-list is consulted
    /// (the support check comes first; RFC 7516 §5.2, ADR 0007). That
    /// includes `RSA-OAEP-256`, which polyjose only encrypts to (ADR 0021).
    ///
    /// # Errors
    ///
    /// [`Error::AlgorithmNotAllowed`] if either list is empty (RFC 8725
    /// §3.1, ADR 0007).
    pub fn new(allowed_algs: &[KeyMgmtAlg], allowed_enc: &[ContentEncAlg]) -> Result<Self> {
        if allowed_algs.is_empty() || allowed_enc.is_empty() {
            return Err(Error::AlgorithmNotAllowed);
        }
        Ok(Self {
            allowed_algs: allowed_algs.to_vec(),
            allowed_enc: allowed_enc.to_vec(),
            max_pbes2_count: Self::DEFAULT_MAX_PBES2_COUNT,
            max_decompressed_len: Self::DEFAULT_MAX_DECOMPRESSED_LEN,
            understood_crit: Vec::new(),
            max_input_len: Self::DEFAULT_MAX_INPUT_LEN,
            max_recipients: Self::DEFAULT_MAX_RECIPIENTS,
        })
    }

    /// The PBES2 iteration budget (RFC 7518 §4.8.1.2 `p2c`) **per token,
    /// summed over all PBES2 candidates tried** in one decrypt call
    /// (ADR 0050 §2, amending ADR 0023).
    ///
    /// Each PBES2 recipient that is a candidate for the key spends its `p2c`
    /// from the budget just before its PBKDF2 derivation runs. A candidate
    /// whose `p2c` exceeds what is left fails, without any PBKDF2 work, and
    /// the next candidate is tried; if none decrypts, the result is
    /// [`Error::DecryptionFailed`], as for any other cause. So a JWE with 16
    /// PBES2 recipients of `p2c` 1,000 and no `kid` runs at most 10
    /// derivations under the default, and its 16th recipient decrypts only
    /// with a budget of 16,000 or more. A `kid` on the key and the
    /// recipients narrows the candidates (RFC 7516 §4.1.6).
    ///
    /// The default is [`DEFAULT_MAX_PBES2_COUNT`](Self::DEFAULT_MAX_PBES2_COUNT)
    /// (10,000). A value above
    /// [`MAX_PBES2_COUNT_CEILING`](Self::MAX_PBES2_COUNT_CEILING) (1,000,000)
    /// is clamped to it: the ceiling bounds the CPU one token can cost
    /// (ADR 0023). Prefer high-entropy secrets over high iteration counts.
    ///
    /// ECDH-ES has the same up-to-[`max_recipients`](Self::max_recipients)
    /// multiplier: each candidate ECDH-ES recipient costs one scalar
    /// multiplication. That is cheap next to PBKDF2, so it is bounded only
    /// by the recipient count, not budgeted (ADR 0050 §2).
    #[must_use]
    pub fn max_pbes2_count(mut self, n: u32) -> Self {
        self.max_pbes2_count = n.min(Self::MAX_PBES2_COUNT_CEILING);
        self
    }

    /// The largest plaintext a `zip: DEF` JWE may inflate to, in bytes
    /// (RFC 7516 §4.1.3, ADR 0017). Inflation stops, with
    /// [`Error::DecryptionFailed`], as soon as the output would exceed it.
    /// `0` rejects every compressed JWE. The default is
    /// [`DEFAULT_MAX_DECOMPRESSED_LEN`](Self::DEFAULT_MAX_DECOMPRESSED_LEN)
    /// (250,000). Only used with the `deflate` feature; without it `zip` is
    /// always [`Error::UnsupportedAlgorithm`].
    ///
    /// The value is also the size of the output buffer inflation allocates
    /// up front, before decoding (less only when the compressed input is too
    /// short to expand that far, RFC 1951 §3.2.5). Raising it raises the
    /// memory one authenticated JWE can claim by the same amount.
    #[must_use]
    pub fn max_decompressed_len(mut self, n: usize) -> Self {
        self.max_decompressed_len = n;
        self
    }

    /// The `crit` extension names the caller understands and processes
    /// (RFC 7516 §4.1.13). A JWE whose `crit` names anything else fails with
    /// [`Error::UnknownCritical`]. The default is none. Replaces any earlier
    /// list.
    #[must_use]
    pub fn understood_crit(mut self, names: &[&str]) -> Self {
        self.understood_crit = names.iter().map(|&name| name.to_owned()).collect();
        self
    }

    /// The largest input accepted, in bytes; a longer one fails with
    /// [`Error::InvalidFormat`] before any parsing (ADR 0026 §7). The
    /// default is [`DEFAULT_MAX_INPUT_LEN`](Self::DEFAULT_MAX_INPUT_LEN)
    /// (1 MiB).
    #[must_use]
    pub fn max_input_len(mut self, n: usize) -> Self {
        self.max_input_len = n;
        self
    }

    /// The most recipients a JSON JWE may have (RFC 7516 §7.2.1); more fail
    /// with [`Error::InvalidFormat`] (ADR 0026 §7). The default is
    /// [`DEFAULT_MAX_RECIPIENTS`](Self::DEFAULT_MAX_RECIPIENTS) (16).
    #[must_use]
    pub fn max_recipients(mut self, n: usize) -> Self {
        self.max_recipients = n;
        self
    }
}

/// A successfully decrypted JWE (RFC 7516 §5.2).
///
/// The plaintext is wiped on drop and `Debug` never prints it. The header
/// parts are returned as received, together with their union, the JOSE
/// Header that was used (RFC 7516 §5.2 step 4).
pub struct Decrypted {
    // core.rs builds this value.
    pub(super) plaintext: Zeroizing<Vec<u8>>,
    pub(super) protected_header: Option<Header>,
    pub(super) shared_header: Option<Header>,
    pub(super) recipient_header: Option<Header>,
    pub(super) header: Header,
    /// Wiped on drop: the AAD can carry application secrets (ADR 0050 §4,
    /// ADR 0030 §7.2).
    pub(super) aad: Option<Zeroizing<Vec<u8>>>,
    pub(super) recipient: usize,
}

impl Decrypted {
    /// The plaintext (RFC 7516 §5.2 step 16), decompressed if the JWE used
    /// `zip` (§5.2 step 17).
    pub fn plaintext(&self) -> &[u8] {
        &self.plaintext
    }

    /// The plaintext, in a buffer that is wiped on drop.
    pub fn into_plaintext(self) -> Zeroizing<Vec<u8>> {
        self.plaintext
    }

    /// The JWE Protected Header (RFC 7516 §2), if the JWE has one.
    pub fn protected_header(&self) -> Option<&Header> {
        self.protected_header.as_ref()
    }

    /// The JWE Shared Unprotected Header (RFC 7516 §7.2.1 `unprotected`),
    /// JSON only.
    pub fn shared_header(&self) -> Option<&Header> {
        self.shared_header.as_ref()
    }

    /// The JWE Per-Recipient Unprotected Header (RFC 7516 §7.2.1 `header`)
    /// of the recipient that decrypted, JSON only.
    pub fn recipient_header(&self) -> Option<&Header> {
        self.recipient_header.as_ref()
    }

    /// The JOSE Header used: the union of the three parts above (RFC 7516
    /// §5.2 step 4).
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// The JWE AAD (RFC 7516 §7.2.1 `aad`), decoded, JSON only. It is
    /// held in a buffer wiped on drop, as it can carry application secrets
    /// (ADR 0050 §4, ADR 0030 §7.2), and `Debug` never prints it.
    pub fn aad(&self) -> Option<&[u8]> {
        self.aad.as_deref().map(Vec::as_slice)
    }

    /// The index of the recipient that decrypted, in the order of the JWE's
    /// `recipients` (RFC 7516 §7.2.1); 0 for compact and flattened JWEs.
    pub fn recipient(&self) -> usize {
        self.recipient
    }
}

impl fmt::Debug for Decrypted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Decrypted")
            .field("plaintext", &"<redacted>")
            .field("protected_header", &self.protected_header)
            .field("shared_header", &self.shared_header)
            .field("recipient_header", &self.recipient_header)
            .field("header", &self.header)
            .field("aad", &self.aad.as_ref().map(|_| "<redacted>"))
            .field("recipient", &self.recipient)
            .finish()
    }
}

/// The two JWE JSON Serialization syntaxes (RFC 7516 §7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonForm {
    /// General (RFC 7516 §7.2.1): a `recipients` array, any number of
    /// recipients.
    General,
    /// Flattened (RFC 7516 §7.2.2): one recipient, at the top level.
    Flattened,
}

/// A JWE serialization (RFC 7516 §3, §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Serialization {
    /// The JWE Compact Serialization (RFC 7516 §7.1).
    Compact,
    /// The JWE JSON Serialization (RFC 7516 §7.2), in either form.
    Json(JsonForm),
}

/// One recipient of an [`Encryptor`]: its key management algorithm, its
/// key and its options (RFC 7516 §5.1 steps 1–8).
///
/// The key is a public key (RSA, EC, OKP) or a symmetric key (`oct`: the
/// key for `dir`, A*KW and A*GCMKW, the password for PBES2). It is checked
/// against `alg` when encrypting (RFC 8725 §3.1, ADR 0007).
#[derive(Debug, Clone)]
pub struct Recipient {
    // core.rs reads these fields directly.
    pub(super) alg: KeyMgmtAlg,
    pub(super) key: Jwk,
    pub(super) header: Option<Header>,
    pub(super) options: RecipientOptions,
}

impl Recipient {
    /// A recipient that `alg` encrypts to with `key`.
    pub fn new(alg: KeyMgmtAlg, key: &Jwk) -> Self {
        Self {
            alg,
            key: key.clone(),
            header: None,
            options: RecipientOptions::default(),
        }
    }

    /// This recipient's Per-Recipient Unprotected Header (RFC 7516 §7.2.1
    /// `header`), JSON only. Replaces any earlier one.
    #[must_use]
    pub fn header(mut self, header: Header) -> Self {
        self.header = Some(header);
        self
    }

    /// ECDH-ES Agreement PartyUInfo, raw bytes; sent base64url-encoded as
    /// `apu` (RFC 7518 §4.6.1.2). It must differ from `apv`.
    #[must_use]
    pub fn apu(mut self, apu: impl Into<Vec<u8>>) -> Self {
        self.options.apu = Some(apu.into());
        self
    }

    /// ECDH-ES Agreement PartyVInfo, raw bytes; sent base64url-encoded as
    /// `apv` (RFC 7518 §4.6.1.3). It must differ from `apu`.
    #[must_use]
    pub fn apv(mut self, apv: impl Into<Vec<u8>>) -> Self {
        self.options.apv = Some(apv.into());
        self
    }

    /// The PBES2 iteration count `p2c` (RFC 7518 §4.8.1.2). The default is
    /// 10,000 (ADR 0023), inside every mainstream library's decrypt bound.
    #[must_use]
    pub fn p2c(mut self, p2c: u32) -> Self {
        self.options.p2c = Some(p2c);
        self
    }

    /// The length of the random PBES2 salt input `p2s`, in bytes, at least
    /// 8 (RFC 7518 §4.8.1.1). The default is 16.
    #[must_use]
    pub fn p2s_len(mut self, len: usize) -> Self {
        self.options.p2s_len = Some(len);
        self
    }
}

/// Builds and encrypts JWEs (RFC 7516 §5.1).
///
/// `enc` always goes in the JWE Protected Header. For compact and flattened
/// output, each recipient's `alg` and key management parameters do too; for
/// general JSON they go in the recipient's `header` (as RFC 7520 §5.13),
/// except for `dir` and ECDH-ES, which are protected in every form (ADR
/// 0050 §1: a direct mode's `alg` and `enc` must be protected to decrypt).
/// Every random value comes from the OS CSPRNG (ADR 0005).
///
/// ```no_run
/// use polyjose::jwa::{ContentEncAlg, KeyMgmtAlg};
/// use polyjose::jwe::{Encryptor, Recipient};
/// use polyjose::jwk::Jwk;
///
/// let key = Jwk::from_json(br#"{"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg"}"#)?;
/// let jwe = Encryptor::new(ContentEncAlg::A128GCM)
///     .recipient(Recipient::new(KeyMgmtAlg::A128KW, &key))
///     .encrypt_compact(b"hello")?;
/// # Ok::<(), polyjose::Error>(())
/// ```
#[derive(Clone)]
pub struct Encryptor {
    // core.rs reads these fields directly.
    pub(super) enc: ContentEncAlg,
    pub(super) protected: Option<Header>,
    pub(super) shared: Option<Header>,
    pub(super) aad: Option<Vec<u8>>,
    /// Set only with the `deflate` feature (RFC 7516 §4.1.3).
    pub(super) compress: bool,
    pub(super) recipients: Vec<Recipient>,
}

impl Encryptor {
    /// An encryptor for content encryption algorithm `enc` (RFC 7516
    /// §4.1.2), with no recipients yet.
    pub fn new(enc: ContentEncAlg) -> Self {
        Self {
            enc,
            protected: None,
            shared: None,
            aad: None,
            compress: false,
            recipients: Vec::new(),
        }
    }

    /// Extra parameters for the JWE Protected Header (RFC 7516 §4), such
    /// as `typ`, `cty` or `kid`. `alg`, `enc`, `zip` and the key management
    /// parameters are set by polyjose and must not be given here.
    #[must_use]
    pub fn protected_header(mut self, header: Header) -> Self {
        self.protected = Some(header);
        self
    }

    /// The JWE Shared Unprotected Header (RFC 7516 §7.2.1 `unprotected`),
    /// JSON only.
    #[must_use]
    pub fn shared_unprotected_header(mut self, header: Header) -> Self {
        self.shared = Some(header);
        self
    }

    /// The JWE AAD (RFC 7516 §7.2.1 `aad`), integrity protected but not
    /// encrypted, JSON only.
    #[must_use]
    pub fn aad(mut self, aad: impl Into<Vec<u8>>) -> Self {
        self.aad = Some(aad.into());
        self
    }

    /// Compresses the plaintext with `zip: DEF` before encrypting it
    /// (RFC 7516 §4.1.3). Compression can reveal information about the
    /// plaintext (RFC 8725 §3.6); use it only for data an attacker cannot
    /// influence.
    #[cfg(feature = "deflate")]
    #[must_use]
    pub fn compress(mut self) -> Self {
        self.compress = true;
        self
    }

    /// Adds a recipient (RFC 7516 §5.1 step 8).
    #[must_use]
    pub fn recipient(mut self, recipient: Recipient) -> Self {
        self.recipients.push(recipient);
        self
    }

    /// Encrypts `plaintext` in the JWE Compact Serialization (RFC 7516
    /// §7.1).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidFormat`] unless there is exactly one recipient and
    /// no shared unprotected header, per-recipient header or AAD (RFC 7516
    /// §7.1); otherwise the header, key and algorithm errors of
    /// [`crate::jwe`].
    pub fn encrypt_compact(&self, plaintext: &[u8]) -> Result<String> {
        let parts =
            pipeline::encrypt(self, plaintext, Serialization::Compact, &mut OsRandom, None)?;
        compact::serialize(&parts)
    }

    /// Encrypts `plaintext` in the JWE JSON Serialization (RFC 7516 §7.2),
    /// general or flattened.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidFormat`] for no recipients, or a flattened JWE with
    /// more than one (RFC 7516 §7.2.2); otherwise the header, key and
    /// algorithm errors of [`crate::jwe`].
    pub fn encrypt_json(&self, plaintext: &[u8], form: JsonForm) -> Result<String> {
        let form_ = Serialization::Json(form);
        let parts = pipeline::encrypt(self, plaintext, form_, &mut OsRandom, None)?;
        json::serialize(&parts, form)
    }

    /// **Insecure: reproduces published test vectors only.** Encrypts like
    /// [`encrypt_compact`](Self::encrypt_compact) or
    /// [`encrypt_json`](Self::encrypt_json), drawing every random value from
    /// `rng` in the documented order, so an RFC 7516 Appendix A or RFC 7520
    /// §5 output can be reproduced byte for byte (ADR 0005, ADR 0041 §3).
    ///
    /// `protected_b64`, if given, is the RFC's exact encoded protected
    /// header. It is used verbatim for the AAD and the output, but only if
    /// it decodes to a header JSON-equal to the one polyjose builds (member
    /// order aside), so a test cannot make polyjose emit a header it would
    /// not produce.
    ///
    /// # Errors
    ///
    /// As the method for `form`; [`Error::RandomnessUnavailable`] when
    /// `rng` runs out; [`Error::InvalidFormat`] when `protected_b64` does
    /// not match the built header.
    #[cfg(feature = "insecure-test-vectors")]
    pub fn encrypt_reproducible(
        &self,
        plaintext: &[u8],
        form: Serialization,
        rng: &mut FixedRng,
        protected_b64: Option<&str>,
    ) -> Result<String> {
        let parts = pipeline::encrypt(self, plaintext, form, rng, protected_b64)?;
        match form {
            Serialization::Compact => compact::serialize(&parts),
            Serialization::Json(json_form) => json::serialize(&parts, json_form),
        }
    }
}

/// Written by hand so the JWE AAD (RFC 7516 §7.2.1 `aad`) is never
/// printed: it can carry application secrets, so only whether it is set and
/// its length are shown (ADR 0050 §4; secrets are never in `Debug`, ADR
/// 0030 §7.5). Recipients are counted, not listed; the headers are shown
/// only as set or not set. For example:
///
/// ```text
/// Encryptor { enc: A128GCM, recipients: 1, protected_header: false,
///     shared_header: false, aad: Some(<redacted, len=13>), compress: false }
/// ```
impl fmt::Debug for Encryptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        /// The AAD's length, in place of its bytes.
        struct RedactedLen(usize);
        impl fmt::Debug for RedactedLen {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "<redacted, len={}>", self.0)
            }
        }
        f.debug_struct("Encryptor")
            .field("enc", &self.enc)
            .field("recipients", &self.recipients.len())
            .field("protected_header", &self.protected.is_some())
            .field("shared_header", &self.shared.is_some())
            .field("aad", &self.aad.as_ref().map(|aad| RedactedLen(aad.len())))
            .field("compress", &self.compress)
            .finish()
    }
}

/// Decrypts a JWE in the Compact Serialization (RFC 7516 §5.2, §7.1) with
/// `key`, if `policy` allows its `alg` and `enc`.
///
/// # Errors
///
/// The error contract of [`crate::jwe`]: [`Error::InvalidFormat`],
/// [`Error::InvalidBase64`], [`Error::InvalidJson`],
/// [`Error::InvalidHeader`] and [`Error::UnknownCritical`] for malformed
/// input; [`Error::UnsupportedAlgorithm`], [`Error::AlgorithmNotAllowed`]
/// and [`Error::KeyAlgorithmMismatch`] before any cryptography; and a
/// detail-free [`Error::DecryptionFailed`] for everything after.
pub fn decrypt_compact(token: &str, key: &Jwk, policy: &DecryptPolicy) -> Result<Decrypted> {
    let parts = compact::parse(token, policy)?;
    pipeline::decrypt(parts, key, policy)
}

/// Decrypts a JWE in the JSON Serialization (RFC 7516 §5.2, §7.2),
/// general or flattened, with `key`, if `policy` allows its `alg` and
/// `enc`. With several recipients, each one `key` can serve is tried in
/// order and the first that decrypts wins ([`Decrypted::recipient`]).
///
/// # Errors
///
/// As [`decrypt_compact`].
pub fn decrypt_json(jwe: &str, key: &Jwk, policy: &DecryptPolicy) -> Result<Decrypted> {
    let parts = json::parse(jwe, policy)?;
    pipeline::decrypt(parts, key, policy)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> DecryptPolicy {
        DecryptPolicy::new(&[KeyMgmtAlg::A128KW], &[ContentEncAlg::A128GCM])
            .unwrap_or_else(|e| panic!("{e}"))
    }

    #[test]
    fn empty_allow_lists_are_rejected() {
        let alg = [KeyMgmtAlg::A128KW];
        let enc = [ContentEncAlg::A128GCM];
        let not_allowed = Err(Error::AlgorithmNotAllowed);
        assert_eq!(DecryptPolicy::new(&[], &enc).map(|_| ()), not_allowed);
        assert_eq!(DecryptPolicy::new(&alg, &[]).map(|_| ()), not_allowed);
        assert_eq!(DecryptPolicy::new(&[], &[]).map(|_| ()), not_allowed);
        assert!(DecryptPolicy::new(&alg, &enc).is_ok());
    }

    #[test]
    fn defaults_follow_adr_0023_0017_and_0026() {
        let p = policy();
        assert_eq!(p.allowed_algs, [KeyMgmtAlg::A128KW]);
        assert_eq!(p.allowed_enc, [ContentEncAlg::A128GCM]);
        assert_eq!(p.max_pbes2_count, 10_000);
        assert_eq!(p.max_decompressed_len, 250_000);
        assert_eq!(p.max_input_len, 1 << 20);
        assert_eq!(p.max_recipients, 16);
        assert!(p.understood_crit.is_empty());
    }

    #[test]
    fn max_pbes2_count_clamps_at_the_ceiling() {
        assert_eq!(policy().max_pbes2_count(1_000).max_pbes2_count, 1_000);
        assert_eq!(policy().max_pbes2_count(0).max_pbes2_count, 0);
        let ceiling = DecryptPolicy::MAX_PBES2_COUNT_CEILING;
        assert_eq!(ceiling, 1_000_000);
        assert_eq!(policy().max_pbes2_count(ceiling).max_pbes2_count, ceiling);
        assert_eq!(
            policy().max_pbes2_count(ceiling + 1).max_pbes2_count,
            ceiling
        );
        assert_eq!(policy().max_pbes2_count(u32::MAX).max_pbes2_count, ceiling);
    }

    #[test]
    fn builders_set_their_limit() {
        let p = policy()
            .max_decompressed_len(0)
            .max_input_len(10)
            .max_recipients(1)
            .understood_crit(&["exp"])
            .understood_crit(&["a", "b"]);
        assert_eq!(p.max_decompressed_len, 0);
        assert_eq!(p.max_input_len, 10);
        assert_eq!(p.max_recipients, 1);
        assert_eq!(p.understood_crit, ["a", "b"]);
    }

    #[test]
    fn unimplemented_algorithms_may_be_listed() {
        // They fail later with UnsupportedAlgorithm (support before allow-list).
        let algs = [KeyMgmtAlg::from("RSA1_5"), KeyMgmtAlg::RsaOaep256];
        let p = DecryptPolicy::new(&algs, &[ContentEncAlg::from("A128CTR")]);
        assert!(p.is_ok());
    }

    fn oct_key() -> Jwk {
        Jwk::from_json(br#"{"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg"}"#)
            .unwrap_or_else(|e| panic!("{e}"))
    }

    #[test]
    fn builders_record_what_they_are_given() {
        let r = Recipient::new(KeyMgmtAlg::EcdhEs, &oct_key())
            .apu(b"Alice".to_vec())
            .apv(*b"Bob")
            .p2c(4096)
            .p2s_len(8)
            .header(Header::new());
        assert_eq!(r.alg, KeyMgmtAlg::EcdhEs);
        assert_eq!(r.options.apu.as_deref(), Some(&b"Alice"[..]));
        assert_eq!(r.options.apv.as_deref(), Some(&b"Bob"[..]));
        assert_eq!((r.options.p2c, r.options.p2s_len), (Some(4096), Some(8)));
        assert!(r.header.is_some());
        let e = Encryptor::new(ContentEncAlg::A128GCM)
            .protected_header(Header::new())
            .shared_unprotected_header(Header::new())
            .aad(*b"aad")
            .recipient(r.clone())
            .recipient(r);
        assert_eq!(e.enc, ContentEncAlg::A128GCM);
        assert!(e.protected.is_some() && e.shared.is_some());
        assert_eq!(e.aad.as_deref(), Some(&b"aad"[..]));
        assert_eq!(e.recipients.len(), 2);
        assert!(!e.compress);
        #[cfg(feature = "deflate")]
        assert!(e.compress().compress);
    }

    #[test]
    fn decrypted_redacts_plaintext_and_aad() {
        let d = Decrypted {
            plaintext: Zeroizing::new(b"MARKERsecret".to_vec()),
            protected_header: None,
            shared_header: None,
            recipient_header: None,
            header: Header::new(),
            aad: Some(Zeroizing::new(b"MARKERaad".to_vec())),
            recipient: 2,
        };
        // ADR 0050 §4: the AAD is held in a buffer wiped on drop.
        let _: &Option<Zeroizing<Vec<u8>>> = &d.aad;
        let debug = format!("{d:?}");
        assert!(!debug.contains("MARKER"), "{debug}");
        assert!(debug.contains("<redacted>"), "{debug}");
        assert_eq!(
            (d.plaintext(), d.aad(), d.recipient()),
            (&b"MARKERsecret"[..], Some(&b"MARKERaad"[..]), 2)
        );
        assert!(d.protected_header().is_none() && d.shared_header().is_none());
        assert!(d.recipient_header().is_none() && d.header().alg.is_none());
        assert_eq!(d.into_plaintext().as_slice(), b"MARKERsecret");
    }

    #[test]
    fn compact_round_trips_through_the_public_entry_points() {
        let key = oct_key();
        let policy = policy();
        let e = Encryptor::new(ContentEncAlg::A128GCM)
            .recipient(Recipient::new(KeyMgmtAlg::A128KW, &key));
        let token = e.encrypt_compact(b"x").unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(token.split('.').count(), 5);
        let d = decrypt_compact(&token, &key, &policy).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!((d.plaintext(), d.recipient()), (&b"x"[..], 0));
        assert!(d.shared_header().is_none() && d.recipient_header().is_none());
        assert!(d.aad().is_none());
        assert_eq!(d.protected_header(), Some(d.header()));
        assert!(decrypt_compact("a.b.c.d.e", &key, &policy).is_err());
    }
}
