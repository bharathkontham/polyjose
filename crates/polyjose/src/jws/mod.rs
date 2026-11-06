//! JSON Web Signature (RFC 7515), with the unencoded payload option
//! (RFC 7797).
//!
//! # Serializations
//!
//! - **Compact** (RFC 7515 §3.1, §7.1): [`sign_compact`] and
//!   [`verify_compact`]. One signature, a protected header only.
//! - **JSON** (RFC 7515 §7.2): [`sign_flattened`] (one signature),
//!   [`sign_general`] (one or more) and [`verify_json`] (either form).
//!   Each signature may have a protected header, an unprotected header, or
//!   both.
//!
//! Detached content (RFC 7515 Appendix F) is chosen with
//! [`SignOptions::detached`] and [`VerifyOptions::detached_payload`].
//!
//! # Misuse resistance (RFC 8725, ADR 0007)
//!
//! - **Allow-list.** Every verify takes a [`VerifyOptions`], which can only
//!   be built from a non-empty list of known algorithms without `none`
//!   (RFC 8725 §3.1). A header `alg` outside the list fails before any
//!   cryptography runs.
//! - **Key binding.** The key must be of the family the `alg` requires,
//!   and its JWK `alg`, `use` and `key_ops`, when present, must allow the
//!   operation (RFC 7517 §4.2–§4.4, RFC 8725 §3.1). An `oct` key never
//!   verifies RS256, so the RS256→HS256 confusion (RFC 8725 §2.1) cannot
//!   happen.
//! - **No RSA signing** in 0.1.0 (ADR 0021): RS*/PS* verify only.
//! - **`crit`.** Only `b64` (RFC 7797) is understood; any other critical
//!   extension makes the JWS invalid (RFC 7515 §4.1.11).
//! - **Embedded keys are data.** A header's `jwk`, `jku`, `x5u`, `x5c` or
//!   `kid` never selects or replaces the caller's key (CVE-2018-0114,
//!   ADR 0026 §2). They are returned in [`Verified`] for the caller to use
//!   as it sees fit.
//!
//! # Processing order and errors (ADR 0048, clarifying ADR 0026 §2)
//!
//! A JWS that is wrong in several ways fails with the error of the first
//! failing step, identically on every platform. The steps are ADR 0048's
//! six, with ADR 0049 §3 placing the unprotected header's type checks at
//! step 3:
//!
//! | step | check | error |
//! |---|---|---|
//! | 1 | shape and limits: [`VerifyOptions::max_input_len`] and [`VerifyOptions::max_signatures`] (ADR 0026 §7); the number of parts (RFC 7515 §7.1) or the JSON serialization members (RFC 7515 §7.2), with JSON syntax and duplicate members | [`Error::InvalidFormat`]; [`Error::InvalidJson`] |
//! | 2 | base64url of each signature (RFC 7515 §5.2 step 7) | [`Error::InvalidBase64`] |
//! | 3 | protected-header decoding: base64url (RFC 7515 §5.2 step 2), then one I-JSON object (step 3; a duplicate member is [`Error::InvalidJson`], ADR 0041 §1), then the type of each registered parameter and the syntax of `crit`, a non-empty array of strings naming no registered parameter (RFC 7515 §4.1.11). A JSON serialization's unprotected `header` gets the same type and `crit`-syntax checks here (ADR 0049 §3) | [`Error::InvalidBase64`]; [`Error::InvalidJson`]; [`Error::InvalidHeader`] |
//! | 4 | base64url of the payload (RFC 7515 §5.2 step 6), skipped when `b64` is `false` (RFC 7797 §3) or the payload is detached | [`Error::InvalidBase64`] |
//! | 5 | whole-header structure: `crit` lists an absent parameter, `alg` missing, protected and unprotected headers share a name, `crit` or `b64` in the unprotected header, `b64` not listed in `crit`, signatures disagree on `b64` (RFC 7515 §4.1.1, §4.1.11, §5.2 step 4; RFC 7797 §3, §6) | [`Error::InvalidHeader`] |
//! | 6a | `crit` lists only understood names (`b64`) | [`Error::UnknownCritical`] |
//! | 6b | `alg` is a known JWS algorithm (RFC 7515 §4.1.1) | [`Error::UnsupportedAlgorithm`] |
//! | 6c | `alg` is in the caller's allow-list; `none` never is (RFC 8725 §3.1) | [`Error::AlgorithmNotAllowed`] |
//! | 6d | key binding: family, JWK `alg`/`use`/`key_ops`; key strength | [`Error::KeyAlgorithmMismatch`]; [`Error::InvalidKey`] |
//! | 6e | the signature or MAC (RFC 7515 §5.2 step 8) | [`Error::InvalidSignature`] |
//!
//! Step 6 is the rest of ADR 0026 §2, unchanged: 6a–6e are its steps 5–9,
//! which is the numbering comments such as "ADR 0026 §2 step 8" (key
//! binding) use. The payload waits for step 4 because the protected
//! header's `b64` decides whether it is base64url at all (RFC 7797 §3).
//! Steps 2 and 3 both report [`Error::InvalidBase64`] for bad base64url,
//! so which of the two runs first cannot be observed.
//!
//! With several signatures, [`verify_json`] runs steps 1–5 over all of
//! them first, each step over every signature before the next, then
//! step 6 per signature until one verifies (ADR 0026 §3).
//!
//! Signing applies the same header rules (steps 5 and 6a–6d, with `none`
//! refused at 6c and RS*/PS* refused with [`Error::UnsupportedAlgorithm`]
//! before the rest of 6d), then the serialization's payload rules
//! ([`Error::InvalidFormat`], RFC 7797 §5.2–§5.3), then computes the
//! signature.
//!
//! # Example
//!
//! ```no_run
//! use polyjose::header::Header;
//! use polyjose::jwa::SigningAlg;
//! use polyjose::jwk::Jwk;
//! use polyjose::jws::{self, ProtectedHeader, SignOptions, VerifyOptions};
//!
//! // RFC 7515 Appendix A.1's HMAC key.
//! let key = Jwk::from_json(br#"{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}"#)?;
//!
//! let mut header = Header::new();
//! header.alg = Some("HS256".into());
//! let protected = ProtectedHeader::new(header)?;
//! let token = jws::sign_compact(&protected, b"hello", &key, &SignOptions::new())?;
//!
//! let allowed = [SigningAlg::HS256];
//! let verified = jws::verify_compact(&token, &key, &VerifyOptions::new(&allowed)?)?;
//! assert_eq!(*verified.payload, b"hello");
//! assert_eq!(verified.alg, SigningAlg::HS256);
//! # Ok::<(), polyjose::Error>(())
//! ```
//!
//! [`Error::AlgorithmNotAllowed`]: crate::error::Error::AlgorithmNotAllowed
//! [`Error::InvalidFormat`]: crate::error::Error::InvalidFormat
//! [`Error::InvalidHeader`]: crate::error::Error::InvalidHeader
//! [`Error::InvalidJson`]: crate::error::Error::InvalidJson
//! [`Error::InvalidKey`]: crate::error::Error::InvalidKey
//! [`Error::InvalidSignature`]: crate::error::Error::InvalidSignature
//! [`Error::KeyAlgorithmMismatch`]: crate::error::Error::KeyAlgorithmMismatch
//! [`Error::UnknownCritical`]: crate::error::Error::UnknownCritical
//! [`Error::UnsupportedAlgorithm`]: crate::error::Error::UnsupportedAlgorithm
//! [`SignOptions::detached`]: crate::jws::SignOptions::detached
//! [`Verified`]: crate::jws::Verified
//! [`VerifyOptions`]: crate::jws::VerifyOptions
//! [`VerifyOptions::detached_payload`]: crate::jws::VerifyOptions::detached_payload
//! [`VerifyOptions::max_input_len`]: crate::jws::VerifyOptions::max_input_len
//! [`VerifyOptions::max_signatures`]: crate::jws::VerifyOptions::max_signatures
//! [`sign_compact`]: crate::jws::sign_compact
//! [`sign_flattened`]: crate::jws::sign_flattened
//! [`sign_general`]: crate::jws::sign_general
//! [`verify_compact`]: crate::jws::verify_compact
//! [`verify_json`]: crate::jws::verify_json

use core::fmt;

use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::header::Header;
use crate::jwa::SigningAlg;
use crate::jwk::Jwk;
use crate::util::{b64url_decode, b64url_encode};

// Internal layout (feature 0002). Shared rules live in `alg` (family
// dispatch, key binding, the test seam) and `process` (header rules,
// signing input, error ranking). Each other file is owned by one task and
// replaced as a whole: `compact` (T04), `json` (T05), `hmac` (T06), `rsa`
// (T07), `ecdsa` (T08), `eddsa` (T09).
mod alg;
mod compact;
mod ecdsa;
mod eddsa;
mod hmac;
mod json;
mod process;
mod rsa;
#[cfg(test)]
mod wycheproof_jose;

pub use compact::{sign_compact, verify_compact};
pub use json::{sign_flattened, sign_general, verify_json};

/// A JWS Protected Header together with its exact base64url encoding,
/// `BASE64URL(UTF8(JWS Protected Header))` (RFC 7515 §2, §5.1 step 3).
///
/// The signature covers the encoded octets, not a re-serialization
/// (RFC 7515 §5.1–§5.2), so the encoding is kept as it was made or
/// received:
///
/// - [`ProtectedHeader::new`] serializes a [`Header`] with polyjose's
///   deterministic JSON writer.
/// - [`ProtectedHeader::from_encoded`] keeps the caller's octets, for
///   example RFC 7515 Appendix A.1's header with its CRLF line breaks.
///
/// ```
/// use polyjose::jws::ProtectedHeader;
/// use polyjose::jwa::SigningAlg;
///
/// // RFC 7515 Appendix A.1: {"typ":"JWT",\r\n "alg":"HS256"}
/// let encoded = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9";
/// let protected = ProtectedHeader::from_encoded(encoded)?;
/// assert_eq!(protected.encoded(), encoded);
/// assert_eq!(protected.header().signing_alg()?, SigningAlg::HS256);
/// # Ok::<(), polyjose::Error>(())
/// ```
///
/// `Debug` prints the parsed header (whose `Debug` redacts JSON-object
/// members such as `jwk`) and the encoding's length, never the encoding
/// itself, which could carry the same members unredacted.
#[derive(Clone, PartialEq)]
pub struct ProtectedHeader {
    header: Header,
    encoded: String,
}

impl ProtectedHeader {
    /// Serializes `header` as compact JSON and base64url-encodes it
    /// (RFC 7515 §5.1 steps 3–4; RFC 7515 §2 for the encoding).
    ///
    /// The JOSE Header rules (`alg` present, `crit`, `b64`, …) are checked
    /// when signing, against the complete JOSE Header (RFC 7515 §5.2
    /// step 4), not here.
    ///
    /// # Errors
    ///
    /// As [`Header::to_json`]: [`Error::InvalidHeader`] for a `p2c` that
    /// JSON cannot carry.
    pub fn new(header: Header) -> Result<Self> {
        let json = Zeroizing::new(header.to_json()?);
        let encoded = b64url_encode(json.as_bytes());
        Ok(Self { header, encoded })
    }

    /// Decodes and parses an encoded JWS Protected Header, keeping
    /// `encoded` verbatim for the signing input (RFC 7515 §5.2 steps 2–3).
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidBase64`] if `encoded` is not strict unpadded
    ///   base64url (RFC 7515 §2, §5.2 step 2).
    /// - [`Error::InvalidJson`] if the octets are not a UTF-8, completely
    ///   valid I-JSON object (RFC 7515 §5.2 step 3), including a member
    ///   name that occurs twice (ADR 0041 §1).
    /// - [`Error::InvalidHeader`] if a registered parameter has the wrong
    ///   type or `crit` is malformed (see [`Header::from_json`]).
    pub fn from_encoded(encoded: &str) -> Result<Self> {
        let json = Zeroizing::new(b64url_decode(encoded)?);
        let header = Header::from_json(&json)?;
        Ok(Self {
            header,
            encoded: encoded.to_owned(),
        })
    }

    /// The parsed JWS Protected Header (RFC 7515 §4).
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// The exact base64url encoding the signing input uses
    /// (RFC 7515 §5.1 step 3).
    pub fn encoded(&self) -> &str {
        &self.encoded
    }

    /// The parsed header, dropping the encoding.
    pub fn into_header(self) -> Header {
        self.header
    }
}

impl fmt::Debug for ProtectedHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProtectedHeader")
            .field("header", &self.header)
            .field("encoded_len", &self.encoded.len())
            .finish()
    }
}

/// Options for every sign function.
///
/// ```
/// use polyjose::jws::SignOptions;
///
/// let attached = SignOptions::new();
/// assert!(!attached.detached);
/// assert!(SignOptions::new().detached(true).detached);
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct SignOptions {
    /// Leave the payload out of the output (RFC 7515 Appendix F): compact
    /// output is `header..signature`, and JSON output has no `payload`
    /// member. The signature still covers the payload. Default: `false`.
    pub detached: bool,
}

impl SignOptions {
    /// The defaults: the payload is attached.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets [`detached`](SignOptions::detached) (RFC 7515 Appendix F).
    pub fn detached(mut self, detached: bool) -> Self {
        self.detached = detached;
        self
    }
}

/// One signature to compute in the JWS JSON Serialization
/// (RFC 7515 §7.2.1): its key and its JWS Protected and Unprotected Headers.
///
/// The JOSE Header of the signature is the union of the two headers, which
/// must not share a name (RFC 7515 §5.2 step 4, §7.2.1). `alg` may be in
/// either; `crit` and `b64` must be in the protected header
/// (RFC 7515 §4.1.11, RFC 7797 §3). With no protected header the signing
/// input starts with an empty string (RFC 7515 §5.1, RFC 7520 §4.7).
///
/// ```
/// use polyjose::header::Header;
/// use polyjose::jwk::Jwk;
/// use polyjose::jws::{ProtectedHeader, Signer};
///
/// let key = Jwk::from_json(br#"{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}"#)?;
/// let mut protected = Header::new();
/// protected.alg = Some("HS256".into());
/// let mut unprotected = Header::new();
/// unprotected.kid = Some("k1".into());
///
/// let signer = Signer::new(&key)
///     .protected(ProtectedHeader::new(protected)?)
///     .unprotected(unprotected);
/// assert!(signer.protected.is_some() && signer.unprotected.is_some());
/// # Ok::<(), polyjose::Error>(())
/// ```
///
/// `Debug` prints the key through [`Jwk`]'s redacting `Debug`, so private
/// key material never appears.
#[derive(Clone)]
#[non_exhaustive]
pub struct Signer<'a> {
    /// The JWS Protected Header, if any (RFC 7515 §7.2.1 `protected`).
    pub protected: Option<ProtectedHeader>,
    /// The JWS Unprotected Header, if any (RFC 7515 §7.2.1 `header`).
    pub unprotected: Option<Header>,
    /// The signing key. It must hold private material (RFC 7518 §3), and
    /// pass key binding for the header `alg` (ADR 0026 §2 step 8).
    pub key: &'a Jwk,
}

impl<'a> Signer<'a> {
    /// A signer with `key` and no headers yet.
    pub fn new(key: &'a Jwk) -> Self {
        Self {
            protected: None,
            unprotected: None,
            key,
        }
    }

    /// Sets the JWS Protected Header (RFC 7515 §7.2.1 `protected`).
    pub fn protected(mut self, protected: ProtectedHeader) -> Self {
        self.protected = Some(protected);
        self
    }

    /// Sets the JWS Unprotected Header (RFC 7515 §7.2.1 `header`).
    pub fn unprotected(mut self, unprotected: Header) -> Self {
        self.unprotected = Some(unprotected);
        self
    }
}

impl fmt::Debug for Signer<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Signer")
            .field("protected", &self.protected)
            .field("unprotected", &self.unprotected)
            .field("key", self.key)
            .finish()
    }
}

/// Options for every verify function: the algorithm allow-list, detached
/// content and input limits.
///
/// The allow-list is mandatory: a JWS whose `alg` is not in it fails with
/// [`Error::AlgorithmNotAllowed`] before any cryptography runs
/// (RFC 8725 §3.1, ADR 0007).
///
/// ```
/// use polyjose::Error;
/// use polyjose::jwa::SigningAlg;
/// use polyjose::jws::VerifyOptions;
///
/// let allowed = [SigningAlg::ES256, SigningAlg::Ed25519];
/// let opts = VerifyOptions::new(&allowed)?.max_signatures(4);
/// assert_eq!(opts.allowed_algs(), &allowed);
///
/// // `none` can never be allowed (RFC 8725 §3.1).
/// let err = VerifyOptions::new(&[SigningAlg::None]).unwrap_err();
/// assert_eq!(err, Error::AlgorithmNotAllowed);
/// # Ok::<(), polyjose::Error>(())
/// ```
///
/// `Debug` prints the detached payload's length, never its bytes.
#[derive(Clone, Copy)]
pub struct VerifyOptions<'a> {
    // compact.rs and json.rs read these fields directly.
    allowed_algs: &'a [SigningAlg],
    detached_payload: Option<&'a [u8]>,
    max_input_len: usize,
    max_signatures: usize,
}

impl<'a> VerifyOptions<'a> {
    /// The default [`max_input_len`](VerifyOptions::max_input_len): 1 MiB
    /// (ADR 0026 §7), the default input limit of [`crate::json::Limits`].
    pub const DEFAULT_MAX_INPUT_LEN: usize = 1024 * 1024;

    /// The default [`max_signatures`](VerifyOptions::max_signatures): 16
    /// (ADR 0026 §7).
    pub const DEFAULT_MAX_SIGNATURES: usize = 16;

    /// Options allowing exactly the algorithms in `allowed_algs`, with the
    /// payload attached and the default limits.
    ///
    /// # Errors
    ///
    /// [`Error::AlgorithmNotAllowed`] if `allowed_algs` is empty, or holds
    /// `none` (RFC 7518 §3.6, RFC 8725 §3.1) or an
    /// [`Unknown`](SigningAlg::Unknown) value, which no key can serve
    /// (ADR 0026 §2 step 7).
    pub fn new(allowed_algs: &'a [SigningAlg]) -> Result<Self> {
        let usable = |alg: &SigningAlg| alg.is_known() && *alg != SigningAlg::None;
        if allowed_algs.is_empty() || !allowed_algs.iter().all(usable) {
            return Err(Error::AlgorithmNotAllowed);
        }
        Ok(Self {
            allowed_algs,
            detached_payload: None,
            max_input_len: Self::DEFAULT_MAX_INPUT_LEN,
            max_signatures: Self::DEFAULT_MAX_SIGNATURES,
        })
    }

    /// Verifies against `payload`, supplied separately (RFC 7515
    /// Appendix F). The JWS must then not carry a payload: a non-empty
    /// compact payload part, or a JSON `payload` member, fails with
    /// [`Error::InvalidFormat`] (ADR 0026 §1).
    pub fn detached_payload(mut self, payload: &'a [u8]) -> Self {
        self.detached_payload = Some(payload);
        self
    }

    /// The largest serialized JWS accepted, in bytes, not counting a
    /// detached payload; longer input fails with [`Error::InvalidFormat`]
    /// before it is parsed (ADR 0026 §7). Default
    /// [`DEFAULT_MAX_INPUT_LEN`](VerifyOptions::DEFAULT_MAX_INPUT_LEN).
    pub fn max_input_len(mut self, max_input_len: usize) -> Self {
        self.max_input_len = max_input_len;
        self
    }

    /// The most signatures a general JSON JWS may have; more fail with
    /// [`Error::InvalidFormat`] (ADR 0026 §7). Default
    /// [`DEFAULT_MAX_SIGNATURES`](VerifyOptions::DEFAULT_MAX_SIGNATURES).
    pub fn max_signatures(mut self, max_signatures: usize) -> Self {
        self.max_signatures = max_signatures;
        self
    }

    /// The allowed algorithms, as given to [`VerifyOptions::new`].
    pub fn allowed_algs(&self) -> &'a [SigningAlg] {
        self.allowed_algs
    }
}

impl fmt::Debug for VerifyOptions<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifyOptions")
            .field("allowed_algs", &self.allowed_algs)
            .field(
                "detached_payload_len",
                &self.detached_payload.map(<[u8]>::len),
            )
            .field("max_input_len", &self.max_input_len)
            .field("max_signatures", &self.max_signatures)
            .finish()
    }
}

/// A successfully verified JWS (RFC 7515 §5.2).
///
/// For a JSON JWS with several signatures, this describes the first one
/// that verified with the given key (ADR 0026 §3), in array order.
///
/// Header parameters such as `jwk`, `jku`, `x5c` and `kid` are returned as
/// data only; they played no part in choosing the key (ADR 0026 §2).
///
/// Only [`protected`](Self::protected) is integrity-protected: the
/// signature covers it, and does not cover
/// [`unprotected`](Self::unprotected) (RFC 7515 §5.1 step 5, §7.2.1).
/// Anyone can change or add an unprotected header without the JWS failing
/// to verify, so read `typ`, `cty`, `kid` and `crit` from `protected`
/// only, and never trust them from `unprotected` (ADR 0049 §2).
///
/// `Debug` prints the payload's length, never its bytes, and the headers
/// through [`Header`]'s redacting `Debug`.
#[derive(Clone, PartialEq)]
#[non_exhaustive]
pub struct Verified {
    /// The `alg` of the signature that verified (RFC 7515 §4.1.1).
    pub alg: SigningAlg,
    /// That signature's JWS Protected Header, if it had one (always, for
    /// compact).
    pub protected: Option<Header>,
    /// That signature's JWS Unprotected Header, if it had one (JSON only,
    /// RFC 7515 §7.2.1).
    ///
    /// **Not integrity-protected** (ADR 0049 §2): the signature does not
    /// cover it (RFC 7515 §5.1 step 5), so an attacker can set any value
    /// here and the JWS still verifies. It is returned because RFC 7515
    /// makes it part of the JOSE Header, but callers must not trust it for
    /// `typ`, `cty`, `kid` or `crit`; read those from
    /// [`protected`](Self::protected). (Verification already rejects
    /// `crit` and `b64` here, RFC 7515 §4.1.11, RFC 7797 §3.)
    pub unprotected: Option<Header>,
    /// The JWS Payload (RFC 7515 §2): base64url-decoded, or the raw octets
    /// when `b64` is `false` (RFC 7797 §3), or a copy of the detached
    /// payload (RFC 7515 Appendix F).
    ///
    /// A payload may be secret, so it is wiped when dropped
    /// (ADR 0049 §4, amending ADR 0030 §7). Read it through `Deref`:
    /// `&*verified.payload` is a `&Vec<u8>`, `&verified.payload[..]` a
    /// `&[u8]`. Copying it out (`to_vec`, `mem::take`) leaves the copy
    /// unprotected.
    ///
    /// ```
    /// # use polyjose::header::Header;
    /// # use polyjose::jwa::SigningAlg;
    /// # use polyjose::jwk::Jwk;
    /// # use polyjose::jws::{self, ProtectedHeader, SignOptions, VerifyOptions};
    /// use zeroize::Zeroizing;
    ///
    /// # let key = Jwk::from_json(br#"{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}"#)?;
    /// # let mut header = Header::new();
    /// # header.alg = Some("HS256".into());
    /// # let token = jws::sign_compact(&ProtectedHeader::new(header)?, b"secret", &key, &SignOptions::new())?;
    /// let verified = jws::verify_compact(&token, &key, &VerifyOptions::new(&[SigningAlg::HS256])?)?;
    /// let payload: &Zeroizing<Vec<u8>> = &verified.payload;
    /// assert_eq!(&payload[..], b"secret");
    /// # Ok::<(), polyjose::Error>(())
    /// ```
    pub payload: Zeroizing<Vec<u8>>,
    /// The index of the signature that verified: `0` for compact and
    /// flattened, the position in `signatures` for general JSON
    /// (ADR 0026 §3).
    pub signature_index: usize,
}

impl fmt::Debug for Verified {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Verified")
            .field("alg", &self.alg)
            .field("protected", &self.protected)
            .field("unprotected", &self.unprotected)
            .field("payload_len", &self.payload.len())
            .field("signature_index", &self.signature_index)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::Value;

    /// RFC 7515 Appendix A.1's encoded protected header, with CRLF.
    const A1_PROTECTED: &str = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9";

    /// Valid base64url of 32 octets, standing in for secret key material
    /// or payload bytes; a leak would contain `MARKER`.
    const SECRET: &str = "MARKERsecretMARKERsecretMARKERsecretMARKERs";
    const MARKER: &str = "MARKERsecret";

    fn assert_no_marker<T: fmt::Debug>(value: &T) {
        for debug in [format!("{value:?}"), format!("{value:#?}")] {
            assert!(!debug.contains(MARKER), "Debug leaks: {debug}");
        }
    }

    fn hs256_header() -> Header {
        let mut h = Header::new();
        h.alg = Some("HS256".into());
        h
    }

    #[test]
    fn protected_header_new_encodes_deterministic_json() {
        let p = ProtectedHeader::new(hs256_header()).unwrap();
        // {"alg":"HS256"}, RFC 7797 §4.1's header.
        assert_eq!(p.encoded(), "eyJhbGciOiJIUzI1NiJ9");
        assert_eq!(p.header(), &hs256_header());
    }

    #[test]
    fn protected_header_from_encoded_keeps_the_octets() {
        // RFC 7515 A.1: re-serializing would drop the CRLF and spaces and
        // change the signing input.
        let p = ProtectedHeader::from_encoded(A1_PROTECTED).unwrap();
        assert_eq!(p.encoded(), A1_PROTECTED);
        assert_eq!(p.header().typ.as_deref(), Some("JWT"));
        assert_eq!(p.header().signing_alg(), Ok(SigningAlg::HS256));
        assert_ne!(
            ProtectedHeader::new(p.header().clone()).unwrap().encoded(),
            A1_PROTECTED
        );
        assert_eq!(p.into_header().alg.as_deref(), Some("HS256"));
    }

    #[test]
    fn protected_header_from_encoded_errors() {
        // RFC 7515 §5.2 step 2: strict base64url.
        assert_eq!(
            ProtectedHeader::from_encoded("eyJhbGciOiJIUzI1NiJ9="),
            Err(Error::InvalidBase64)
        );
        // Step 3: a JSON object. "WzFd" is `[1]`.
        assert_eq!(
            ProtectedHeader::from_encoded("WzFd")
                .map(drop)
                .unwrap_err()
                .code(),
            "InvalidJson"
        );
        // ADR 0041 §1: a duplicate member is InvalidJson, not InvalidHeader.
        let dup = b64url_encode(br#"{"alg":"HS256","alg":"none"}"#);
        assert_eq!(
            ProtectedHeader::from_encoded(&dup)
                .map(drop)
                .unwrap_err()
                .code(),
            "InvalidJson"
        );
        // A registered parameter of the wrong type.
        let typed = b64url_encode(br#"{"alg":1}"#);
        assert_eq!(
            ProtectedHeader::from_encoded(&typed)
                .map(drop)
                .unwrap_err()
                .code(),
            "InvalidHeader"
        );
    }

    #[test]
    fn protected_header_debug_hides_the_encoding() {
        let mut h = hs256_header();
        let mut jwk = crate::json::Object::new();
        jwk.insert("kty", "oct");
        jwk.insert("k", SECRET);
        h.jwk = Some(jwk);
        let p = ProtectedHeader::new(h).unwrap();
        assert_no_marker(&p);
        assert!(!format!("{p:?}").contains(p.encoded()));
    }

    #[test]
    fn sign_options_default_to_attached() {
        assert_eq!(SignOptions::new(), SignOptions { detached: false });
        assert!(SignOptions::new().detached(true).detached);
        assert!(!SignOptions::new().detached(true).detached(false).detached);
    }

    #[test]
    fn verify_options_reject_empty_none_and_unknown() {
        // ADR 0026 §2 step 7, RFC 8725 §3.1.
        let cases: [&[SigningAlg]; 5] = [
            &[],
            &[SigningAlg::None],
            &[SigningAlg::HS256, SigningAlg::None],
            &[SigningAlg::Unknown("HS1".into())],
            // Non-canonical: a known name built as Unknown fails closed.
            &[SigningAlg::Unknown("HS256".into())],
        ];
        for allowed in cases {
            assert_eq!(
                VerifyOptions::new(allowed).map(drop),
                Err(Error::AlgorithmNotAllowed),
                "{allowed:?}"
            );
        }
    }

    #[test]
    fn verify_options_defaults_and_builders() {
        let allowed = [SigningAlg::HS256, SigningAlg::EdDSA];
        let o = VerifyOptions::new(&allowed).unwrap();
        assert_eq!(o.allowed_algs(), &allowed);
        assert_eq!(o.detached_payload, None);
        assert_eq!(o.max_input_len, 1024 * 1024);
        assert_eq!(o.max_signatures, 16);
        let o = o
            .detached_payload(b"abc")
            .max_input_len(10)
            .max_signatures(2);
        assert_eq!(o.detached_payload, Some(&b"abc"[..]));
        assert_eq!((o.max_input_len, o.max_signatures), (10, 2));
        // Every known algorithm except `none` may be allowed.
        let all: Vec<SigningAlg> = SigningAlg::KNOWN
            .iter()
            .filter(|a| **a != SigningAlg::None)
            .cloned()
            .collect();
        assert!(VerifyOptions::new(&all).is_ok());
    }

    #[test]
    fn verify_options_debug_hides_the_detached_payload() {
        let allowed = [SigningAlg::HS256];
        let o = VerifyOptions::new(&allowed)
            .unwrap()
            .detached_payload(SECRET.as_bytes());
        assert_no_marker(&o);
        assert!(format!("{o:?}").contains("detached_payload_len: Some(43)"));
    }

    #[test]
    fn signer_debug_redacts_key_material() {
        let oct = Jwk::from_json(format!(r#"{{"kty":"oct","k":"{SECRET}"}}"#).as_bytes()).unwrap();
        // A P-256 key whose `d` is the marker; (x, y) = d·G, derived
        // independently in Python (SEC 1 §2.2.1 arithmetic), since import
        // checks the pair (ADR 0043 §3).
        let ec = Jwk::from_json(
            format!(
                r#"{{"kty":"EC","crv":"P-256","x":"Qm0_Y3iAhrDndVQ247skVXv2bFfwnTvlLUyup22HGDM","y":"MXHhtkN4vHVS87SCP6IfVsIXSeUWHsOjnuQIgzhWL6Q","d":"{SECRET}"}}"#
            )
            .as_bytes(),
        )
        .unwrap();
        // An Ed25519 key whose seed `d` is the marker; `x` derived
        // independently in Python (RFC 8032 §5.1.5).
        let okp = Jwk::from_json(
            format!(
                r#"{{"kty":"OKP","crv":"Ed25519","x":"TrgjJgt_upZmFJb7d22T8iGZ_57PzgtlGh4Tq4b-tkc","d":"{SECRET}"}}"#
            )
            .as_bytes(),
        )
        .unwrap();
        for key in [&oct, &ec, &okp] {
            let mut unprotected = Header::new();
            unprotected
                .insert_other("x-secret", Value::from(SECRET))
                .unwrap();
            let signer = Signer::new(key)
                .protected(ProtectedHeader::new(hs256_header()).unwrap())
                .unprotected(unprotected);
            assert_no_marker(&signer);
            assert!(format!("{signer:?}").contains("<redacted>"));
        }
    }

    #[test]
    fn verified_payload_is_wiped_on_drop() {
        // ADR 0049 §4 (amending ADR 0030 §7): the payload may be secret, so
        // the public field is a `Zeroizing` buffer. Fails to compile if the
        // type changes.
        fn is_zeroizing(_: &Zeroizing<Vec<u8>>) {}
        let key = Jwk::from_json(format!(r#"{{"kty":"oct","k":"{SECRET}"}}"#).as_bytes()).unwrap();
        let protected = ProtectedHeader::new(hs256_header()).unwrap();
        let jws = compact::sign_compact(&protected, b"secret", &key, &SignOptions::new()).unwrap();
        let allowed = [SigningAlg::HS256];
        let opts = VerifyOptions::new(&allowed).unwrap();
        for verified in [
            compact::verify_compact(&jws, &key, &opts).unwrap(),
            compact::verify_compact(
                &jws.replace(".c2VjcmV0.", ".."),
                &key,
                &opts.detached_payload(b"secret"),
            )
            .unwrap(),
        ] {
            is_zeroizing(&verified.payload);
            assert_eq!(*verified.payload, b"secret");
        }
    }

    #[test]
    fn verified_debug_hides_the_payload() {
        let mut protected = hs256_header();
        protected
            .insert_other("x-secret", Value::from(SECRET))
            .unwrap();
        let v = Verified {
            alg: SigningAlg::HS256,
            protected: Some(protected),
            unprotected: None,
            payload: Zeroizing::new(SECRET.as_bytes().to_vec()),
            signature_index: 0,
        };
        assert_no_marker(&v);
        assert!(format!("{v:?}").contains("payload_len: 43"));
    }
}
