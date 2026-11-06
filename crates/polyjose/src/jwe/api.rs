//! The public JWE API (RFC 7516): the decrypt policy, the decrypt result,
//! the encryptor and its recipients.
//!
//! The bodies here only delegate to `core`, `compact` and `json`, so the
//! tasks that fill those in never edit this file.

use crate::jwa::{ContentEncAlg, KeyMgmtAlg};
use crate::{Error, Result};

/// What [`decrypt_compact`](crate::jwe::decrypt_compact) and
/// [`decrypt_json`](crate::jwe::decrypt_json) accept (RFC 8725 §3.1,
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
    // The allow-lists are read by the pipeline (T09), which may not edit
    // this file; remove the attributes once it lands.
    #[allow(dead_code, reason = "read by jwe/core.rs (0003 T09)")]
    pub(super) allowed_algs: Vec<KeyMgmtAlg>,
    #[allow(dead_code, reason = "read by jwe/core.rs (0003 T09)")]
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

    /// The largest PBES2 iteration count `p2c` accepted (RFC 7518 §4.8.1.2).
    /// A JWE over the bound fails with [`Error::DecryptionFailed`] before
    /// any PBKDF2 work (ADR 0023).
    ///
    /// The default is [`DEFAULT_MAX_PBES2_COUNT`](Self::DEFAULT_MAX_PBES2_COUNT)
    /// (10,000). A value above
    /// [`MAX_PBES2_COUNT_CEILING`](Self::MAX_PBES2_COUNT_CEILING) (1,000,000)
    /// is clamped to it: the ceiling bounds the CPU one token can cost
    /// (ADR 0023). Prefer high-entropy secrets over high iteration counts.
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
}
