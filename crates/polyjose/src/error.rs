//! The polyjose error type and its stable, cross-platform error codes.
//!
//! # Stability contract
//!
//! - **Stable:** the code strings returned by [`Error::code`] and listed in
//!   [`Error::CODES`]. Every binding (Node, WASM, Kotlin, Swift) surfaces
//!   them unchanged, and the shared conformance vectors name them in
//!   `"expect": { "ok": false, "error": "<code>" }`. A released code is never
//!   renamed or removed; new codes may be added.
//! - **Not stable:** the `Display` text and the `&'static str` details. They
//!   are for humans and may be reworded in any release. Don't match on them.
//!
//! # No secrets, no input (ADR 0007)
//!
//! An error never contains key material or bytes of the input being
//! processed: a detail can only be a string literal from polyjose itself,
//! and no error wraps another error as its `source()`. polyjose parses JSON
//! and base64url itself (ADR 0016), so no dependency's error message, which
//! might quote input, ever reaches an `Error`. JWE decryption has a single,
//! detail-free failure, [`Error::DecryptionFailed`] (RFC 7516 §11.5).
//!
//! # Adding a variant
//!
//! Give it a doc comment citing its RFC section, add its code to
//! [`Error::code`] and [`Error::CODES`] (same order as the declaration), and
//! add it to `one_of_each` in this module's tests. The compiler flags the
//! first and the last; the tests check the list.

/// Errors returned by polyjose.
///
/// Each variant has a stable [`code`](Error::code). The code is the contract
/// shared by every binding and every conformance vector (ADR 0007), so it
/// never changes once released. New variants may be added (the enum is
/// `#[non_exhaustive]`).
///
/// No variant carries key material or bytes from the input being processed.
/// Any detail is a `&'static str` written into polyjose itself, so `Debug`
/// and `Display` never echo untrusted input or secrets (ADR 0007).
///
/// ```
/// use polyjose::Error;
///
/// let err = Error::InvalidClaim("aud");
/// assert_eq!(err.code(), "InvalidClaim");
/// assert!(Error::CODES.contains(&err.code()));
///
/// // Match on the code (or the variant), never on the message text.
/// assert_eq!(Error::DecryptionFailed.code(), "DecryptionFailed");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Input is not valid unpadded base64url (RFC 7515 §2, RFC 4648 §5).
    ///
    /// Raised when decoding any base64url-encoded JOSE component
    /// (RFC 7515 §5.2 steps 2, 6 and 7; RFC 7516 §5.2) or JWK member.
    InvalidBase64,

    /// Input is not a valid JSON object of the expected shape.
    ///
    /// A JOSE Header must be a completely valid JSON object (RFC 7515 §5.2
    /// step 3, RFC 7516 §5.2 step 3), and so must a JWT Claims Set
    /// (RFC 7519 §7.2 step 10) and a JWK (RFC 7517 §4). That includes a
    /// member name occurring twice in one object, a JOSE Header included
    /// (RFC 7515 §5.2 step 4, RFC 7516 §5.2 step 4; ADR 0041 §1). The
    /// detail names the failure category only, never the offending input.
    InvalidJson(&'static str),

    /// The JOSE Header is structurally invalid.
    ///
    /// For example: a required parameter such as `alg` is missing
    /// (RFC 7515 §4.1.1, RFC 7516 §4.1.1–§4.1.2), a registered parameter
    /// has the wrong type, the protected and unprotected headers share a
    /// name (RFC 7515 §5.2 step 4, §7.2.1; RFC 7516 §5.2 step 4), `crit`
    /// is malformed or not in the protected header (RFC 7515 §4.1.11,
    /// RFC 7516 §4.1.13), or `b64` breaks the RFC 7797 §3/§6 rules.
    ///
    /// A member name that occurs twice **inside one** header object is not
    /// this error: the JSON layer rejects it first, as
    /// [`Error::InvalidJson`] (ADR 0041 §1, amending ADR 0026 §2 step 4).
    InvalidHeader(&'static str),

    /// The `alg` or `enc` value does not name an algorithm polyjose
    /// implements.
    ///
    /// The JWS is invalid if `alg` is not a supported algorithm
    /// (RFC 7515 §4.1.1); the same holds for JWE `alg` and `enc`
    /// (RFC 7516 §4.1.1–§4.1.2). The rejected value is not echoed.
    ///
    /// Also a well-formed key or key encoding that polyjose does not
    /// support, e.g. encrypted PKCS#8 (RFC 5958 §3) or RSA private keys
    /// (ADR 0018, ADR 0021).
    UnsupportedAlgorithm,

    /// The algorithm is supported but not in the caller's allow-list.
    ///
    /// Libraries must let the caller specify the accepted algorithms and
    /// must not use any other (RFC 8725 §3.1, §2.1; ADR 0007). `none` is
    /// never allowed.
    AlgorithmNotAllowed,

    /// The key is malformed or too weak for any use.
    ///
    /// For example: missing or malformed JWK members (RFC 7517 §4,
    /// RFC 7518 §6), an RSA modulus under 2048 bits (RFC 7518 §3.3, §3.5,
    /// §4.2), an HMAC key shorter than the hash output (RFC 7518 §3.2), or
    /// an EC point that is not on its curve (RFC 8725 §3.4), and malformed
    /// or non-canonical DER/PEM key encodings (ADR 0018). The detail never
    /// contains key material.
    InvalidKey(&'static str),

    /// The key is valid but not for this algorithm or operation.
    ///
    /// Each key must be used with exactly one algorithm (RFC 8725 §3.1),
    /// which blocks the RS256→HS256 confusion attack (RFC 8725 §2.1). Also
    /// raised when the JWK `alg`, `use` or `key_ops` members forbid the
    /// operation (RFC 7517 §4.2–§4.4).
    KeyAlgorithmMismatch,

    /// A JWS signature or MAC did not validate (RFC 7515 §5.2 step 8).
    InvalidSignature,

    /// JWE decryption failed.
    ///
    /// Every decryption failure maps to this one variant, whatever the
    /// internal cause, and it deliberately carries no detail. The recipient
    /// must not distinguish format, padding and length errors
    /// (RFC 7516 §11.5), so no padding or key-unwrap oracle is exposed
    /// (RFC 7516 §5.2, ADR 0007).
    DecryptionFailed,

    /// `crit` lists an extension polyjose does not understand.
    ///
    /// Recipients must reject the JWS/JWE in that case (RFC 7515 §4.1.11,
    /// RFC 7516 §4.1.13). The unknown name is not echoed.
    UnknownCritical,

    /// The JWT `exp` time has passed, allowing for the configured clock
    /// skew (RFC 7519 §4.1.4).
    TokenExpired,

    /// The JWT `nbf` time has not been reached yet, allowing for the
    /// configured clock skew (RFC 7519 §4.1.5).
    TokenNotYetValid,

    /// A JWT claim is missing, malformed or failed validation.
    ///
    /// The detail names the claim (for example `"aud"`), never its value.
    /// Covers RFC 7519 §4.1 and §7.2 and the RFC 8725 §3.8–§3.9 issuer and
    /// audience checks.
    InvalidClaim(&'static str),

    /// The operating-system CSPRNG could not supply random bytes.
    ///
    /// Keys, IVs and CEKs require a cryptographically secure source
    /// (RFC 7515 §10.1, RFC 8725 §3.5); polyjose never falls back to a
    /// weaker one (ADR 0005).
    RandomnessUnavailable,

    /// The serialization does not have the shape its RFC requires, or the
    /// input exceeds a configured limit (ADR 0026 §1, §7).
    ///
    /// For JWS: a compact JWS without exactly three dot-separated parts
    /// (RFC 7515 §7.1, §5.2 step 1); a JSON JWS that is not an object of
    /// the RFC 7515 §7.2.1/§7.2.2 shape (for example a missing or
    /// non-string `signature`, an empty `signatures` array, `signatures`
    /// mixed with top-level signature members, or an empty-string
    /// `protected`); a payload that is present or absent against the
    /// detached-content mode (RFC 7515 Appendix F); a `b64: false` payload
    /// that the serialization cannot carry (RFC 7797 §5.2, §5.3); or an
    /// input over the size or signature-count limits. JWE reuses it for its
    /// own serialization shapes.
    ///
    /// JSON syntax errors stay [`Error::InvalidJson`] and base64url errors
    /// stay [`Error::InvalidBase64`]. The detail names the rule, never the
    /// input.
    InvalidFormat(&'static str),
}

impl Error {
    /// Every stable error code, in declaration order.
    ///
    /// Bindings and the conformance harness use this to check that an
    /// expected `error` value names a real code.
    pub const CODES: &'static [&'static str] = &[
        "InvalidBase64",
        "InvalidJson",
        "InvalidHeader",
        "UnsupportedAlgorithm",
        "AlgorithmNotAllowed",
        "InvalidKey",
        "KeyAlgorithmMismatch",
        "InvalidSignature",
        "DecryptionFailed",
        "UnknownCritical",
        "TokenExpired",
        "TokenNotYetValid",
        "InvalidClaim",
        "RandomnessUnavailable",
        "InvalidFormat",
    ];

    /// The stable, cross-platform code for this error (ADR 0007).
    ///
    /// Match on this, not on the `Display` text: the code never changes,
    /// while the message may be reworded.
    pub fn code(&self) -> &'static str {
        match self {
            Error::InvalidBase64 => "InvalidBase64",
            Error::InvalidJson(_) => "InvalidJson",
            Error::InvalidHeader(_) => "InvalidHeader",
            Error::UnsupportedAlgorithm => "UnsupportedAlgorithm",
            Error::AlgorithmNotAllowed => "AlgorithmNotAllowed",
            Error::InvalidKey(_) => "InvalidKey",
            Error::KeyAlgorithmMismatch => "KeyAlgorithmMismatch",
            Error::InvalidSignature => "InvalidSignature",
            Error::DecryptionFailed => "DecryptionFailed",
            Error::UnknownCritical => "UnknownCritical",
            Error::TokenExpired => "TokenExpired",
            Error::TokenNotYetValid => "TokenNotYetValid",
            Error::InvalidClaim(_) => "InvalidClaim",
            Error::RandomnessUnavailable => "RandomnessUnavailable",
            Error::InvalidFormat(_) => "InvalidFormat",
        }
    }
}

/// Human-readable text: a fixed phrase per variant, followed by the
/// `&'static str` detail for the variants that carry one.
///
/// The text holds nothing but string literals from polyjose, so it never
/// contains input or key material (ADR 0007). It is not stable: match on
/// [`Error::code`] instead.
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::InvalidBase64 => f.write_str("invalid base64url"),
            Error::InvalidJson(detail) => write!(f, "invalid JSON: {detail}"),
            Error::InvalidHeader(detail) => write!(f, "invalid header: {detail}"),
            Error::UnsupportedAlgorithm => f.write_str("unsupported algorithm"),
            Error::AlgorithmNotAllowed => f.write_str("algorithm not allowed"),
            Error::InvalidKey(detail) => write!(f, "invalid key: {detail}"),
            Error::KeyAlgorithmMismatch => f.write_str("key does not match the algorithm"),
            Error::InvalidSignature => f.write_str("signature verification failed"),
            Error::DecryptionFailed => f.write_str("decryption failed"),
            Error::UnknownCritical => f.write_str("unknown critical header parameter"),
            Error::TokenExpired => f.write_str("token expired"),
            Error::TokenNotYetValid => f.write_str("token not yet valid"),
            Error::InvalidClaim(detail) => write!(f, "invalid claim: {detail}"),
            Error::RandomnessUnavailable => f.write_str("randomness unavailable"),
            Error::InvalidFormat(detail) => write!(f, "invalid format: {detail}"),
        }
    }
}

/// No variant has a [`source`](std::error::Error::source): an error never
/// wraps a dependency's error, whose message could quote input (ADR 0007).
/// In particular [`Error::DecryptionFailed`] exposes no cause, so callers
/// cannot tell decryption failures apart (RFC 7516 §11.5).
impl std::error::Error for Error {}

/// Result alias using [`Error`].
pub type Result<T> = core::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    /// One value of every variant, in declaration order.
    ///
    /// Keep in sync with [`variant_index`]: adding a variant breaks that
    /// exhaustive match at compile time, which is the reminder to add it here.
    fn one_of_each() -> Vec<Error> {
        vec![
            Error::InvalidBase64,
            Error::InvalidJson("syntax error"),
            Error::InvalidHeader("missing \"alg\""),
            Error::UnsupportedAlgorithm,
            Error::AlgorithmNotAllowed,
            Error::InvalidKey("RSA modulus is under 2048 bits"),
            Error::KeyAlgorithmMismatch,
            Error::InvalidSignature,
            Error::DecryptionFailed,
            Error::UnknownCritical,
            Error::TokenExpired,
            Error::TokenNotYetValid,
            Error::InvalidClaim("aud"),
            Error::RandomnessUnavailable,
            Error::InvalidFormat("compact JWS must have three parts"),
        ]
    }

    /// Compile-time exhaustiveness guard for [`one_of_each`].
    fn variant_index(e: &Error) -> usize {
        match e {
            Error::InvalidBase64 => 0,
            Error::InvalidJson(_) => 1,
            Error::InvalidHeader(_) => 2,
            Error::UnsupportedAlgorithm => 3,
            Error::AlgorithmNotAllowed => 4,
            Error::InvalidKey(_) => 5,
            Error::KeyAlgorithmMismatch => 6,
            Error::InvalidSignature => 7,
            Error::DecryptionFailed => 8,
            Error::UnknownCritical => 9,
            Error::TokenExpired => 10,
            Error::TokenNotYetValid => 11,
            Error::InvalidClaim(_) => 12,
            Error::RandomnessUnavailable => 13,
            Error::InvalidFormat(_) => 14,
        }
    }

    #[test]
    fn codes_are_the_stable_names() {
        // These strings are the cross-binding contract (ADR 0007). Changing one
        // is a breaking change for every binding and conformance vector.
        let expected = [
            "InvalidBase64",
            "InvalidJson",
            "InvalidHeader",
            "UnsupportedAlgorithm",
            "AlgorithmNotAllowed",
            "InvalidKey",
            "KeyAlgorithmMismatch",
            "InvalidSignature",
            "DecryptionFailed",
            "UnknownCritical",
            "TokenExpired",
            "TokenNotYetValid",
            "InvalidClaim",
            "RandomnessUnavailable",
            "InvalidFormat",
        ];
        let actual: Vec<&str> = one_of_each().iter().map(Error::code).collect();
        assert_eq!(actual, expected);
    }

    #[test]
    fn one_of_each_covers_every_variant_once() {
        let indices: Vec<usize> = one_of_each().iter().map(variant_index).collect();
        let expected: Vec<usize> = (0..Error::CODES.len()).collect();
        assert_eq!(indices, expected);
    }

    #[test]
    fn codes_list_matches_variants() {
        let from_variants: Vec<&str> = one_of_each().iter().map(Error::code).collect();
        assert_eq!(Error::CODES, from_variants.as_slice());
    }

    #[test]
    fn codes_are_unique_identifiers() {
        let mut seen = std::collections::BTreeSet::new();
        for code in Error::CODES {
            assert!(seen.insert(*code), "duplicate code {code}");
            assert!(
                !code.is_empty() && code.bytes().all(|b| b.is_ascii_alphanumeric()),
                "code {code} must be a non-empty ASCII identifier"
            );
        }
    }

    #[test]
    fn display_text_of_every_variant() {
        // Not part of the stability contract (codes are), but pinned so a
        // change to the formatting code cannot alter messages by accident.
        let expected = [
            "invalid base64url",
            "invalid JSON: syntax error",
            "invalid header: missing \"alg\"",
            "unsupported algorithm",
            "algorithm not allowed",
            "invalid key: RSA modulus is under 2048 bits",
            "key does not match the algorithm",
            "signature verification failed",
            "decryption failed",
            "unknown critical header parameter",
            "token expired",
            "token not yet valid",
            "invalid claim: aud",
            "randomness unavailable",
            "invalid format: compact JWS must have three parts",
        ];
        let actual: Vec<String> = one_of_each().iter().map(Error::to_string).collect();
        assert_eq!(actual, expected);
    }

    /// A distinctive value standing in for untrusted input or key material.
    const MARKER: &str = "pj-SECRET-marker-7f3a";

    /// Asserts that neither `Debug` nor `Display` of `e` contains `MARKER`.
    fn assert_no_marker(e: &Error) {
        let debug = format!("{e:?}");
        let display = e.to_string();
        assert!(!debug.contains(MARKER), "Debug leaks input: {debug}");
        assert!(!display.contains(MARKER), "Display leaks input: {display}");
    }

    #[test]
    fn no_variant_renders_input_or_has_a_cause() {
        // Details are &'static str, so a variant cannot hold runtime input;
        // this guards the rendering and the (absent) cause chain.
        for e in one_of_each() {
            assert_no_marker(&e);
            assert!(!e.to_string().is_empty(), "{} has no message", e.code());
            assert!(
                std::error::Error::source(&e).is_none(),
                "{} exposes a cause",
                e.code()
            );
        }
    }

    #[test]
    fn decryption_failed_has_no_detail() {
        // RFC 7516 §11.5, ADR 0007: one uniform failure, no oracle.
        let e = Error::DecryptionFailed;
        assert_eq!(format!("{e:?}"), "DecryptionFailed");
        assert_eq!(e.to_string(), "decryption failed");
        assert!(std::error::Error::source(&e).is_none());
    }

    /// Malformed JSON texts containing `MARKER`, each with the
    /// [`Error::InvalidJson`] detail that [`crate::json::parse`] must return.
    ///
    /// The marker sits next to the fault, where a parser that quotes the
    /// offending input (as `serde_json` does) would echo it.
    fn marked_malformed_json() -> Vec<(Vec<u8>, &'static str)> {
        let mut invalid_utf8 = format!("\"{MARKER}").into_bytes();
        invalid_utf8.extend_from_slice(&[0xff, 0xfe, b'"']);
        vec![
            (
                format!("{{\"{MARKER}\" {MARKER}}}").into_bytes(),
                "unexpected character",
            ),
            (
                format!("{{\"{MARKER}\":").into_bytes(),
                "unexpected end of input",
            ),
            (
                format!("\"{MARKER}\" {MARKER}").into_bytes(),
                "trailing content after the value",
            ),
            (format!("\"{MARKER}\\q\"").into_bytes(), "invalid escape"),
            (
                format!("\"{MARKER}\\ud800\"").into_bytes(),
                "lone surrogate escape",
            ),
            (
                format!("\"{MARKER}\n\"").into_bytes(),
                "unescaped control character in string",
            ),
            (
                format!("{{\"{MARKER}\":1,\"{MARKER}\":2}}").into_bytes(),
                "duplicate member name",
            ),
            (
                format!("{{\"{MARKER}\":1e400}}").into_bytes(),
                "number out of range",
            ),
            (invalid_utf8, "invalid UTF-8"),
        ]
    }

    #[test]
    fn json_errors_are_invalid_json_without_input() {
        for (input, detail) in marked_malformed_json() {
            // The probe is meaningful only if the marker is in the input.
            assert!(
                input.windows(MARKER.len()).any(|w| w == MARKER.as_bytes()),
                "probe for {detail:?} lacks the marker"
            );
            let e = crate::json::parse(&input).err();
            assert_eq!(e, Some(Error::InvalidJson(detail)));
            if let Some(e) = e {
                assert_eq!(e.code(), "InvalidJson");
                assert_no_marker(&e);
                assert!(std::error::Error::source(&e).is_none());
            }
        }
    }
}
