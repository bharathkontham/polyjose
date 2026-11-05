//! The polyjose error type and its stable, cross-platform error codes.

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
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Input is not valid unpadded base64url (RFC 7515 §2, RFC 4648 §5).
    ///
    /// Raised when decoding any base64url-encoded JOSE component
    /// (RFC 7515 §5.2 steps 2, 6 and 7; RFC 7516 §5.2) or JWK member.
    #[error("invalid base64url")]
    InvalidBase64,

    /// Input is not a valid JSON object of the expected shape.
    ///
    /// A JOSE Header must be a completely valid JSON object (RFC 7515 §5.2
    /// step 3, RFC 7516 §5.2 step 3), and so must a JWT Claims Set
    /// (RFC 7519 §7.2 step 10) and a JWK (RFC 7517 §4). The detail names
    /// the failure category only, never the offending input.
    #[error("invalid JSON: {0}")]
    InvalidJson(&'static str),

    /// The JOSE Header is structurally invalid.
    ///
    /// For example: a required parameter such as `alg` is missing
    /// (RFC 7515 §4.1.1, RFC 7516 §4.1.1–§4.1.2), a parameter has the wrong
    /// type, a Header Parameter name is duplicated (RFC 7515 §5.2 step 4,
    /// RFC 7516 §5.2 step 4), or `crit` itself is malformed
    /// (RFC 7515 §4.1.11, RFC 7516 §4.1.13).
    #[error("invalid header: {0}")]
    InvalidHeader(&'static str),

    /// The `alg` or `enc` value does not name an algorithm polyjose
    /// implements.
    ///
    /// The JWS is invalid if `alg` is not a supported algorithm
    /// (RFC 7515 §4.1.1); the same holds for JWE `alg` and `enc`
    /// (RFC 7516 §4.1.1–§4.1.2). The rejected value is not echoed.
    #[error("unsupported algorithm")]
    UnsupportedAlgorithm,

    /// The algorithm is supported but not in the caller's allow-list.
    ///
    /// Libraries must let the caller specify the accepted algorithms and
    /// must not use any other (RFC 8725 §3.1, §2.1; ADR 0007). `none` is
    /// never allowed.
    #[error("algorithm not allowed")]
    AlgorithmNotAllowed,

    /// The key is malformed or too weak for any use.
    ///
    /// For example: missing or malformed JWK members (RFC 7517 §4,
    /// RFC 7518 §6), an RSA modulus under 2048 bits (RFC 7518 §3.3, §3.5,
    /// §4.2), an HMAC key shorter than the hash output (RFC 7518 §3.2), or
    /// an EC point that is not on its curve (RFC 8725 §3.4). The detail
    /// never contains key material.
    #[error("invalid key: {0}")]
    InvalidKey(&'static str),

    /// The key is valid but not for this algorithm or operation.
    ///
    /// Each key must be used with exactly one algorithm (RFC 8725 §3.1),
    /// which blocks the RS256→HS256 confusion attack (RFC 8725 §2.1). Also
    /// raised when the JWK `alg`, `use` or `key_ops` members forbid the
    /// operation (RFC 7517 §4.2–§4.4).
    #[error("key does not match the algorithm")]
    KeyAlgorithmMismatch,

    /// A JWS signature or MAC did not validate (RFC 7515 §5.2 step 8).
    #[error("signature verification failed")]
    InvalidSignature,

    /// JWE decryption failed.
    ///
    /// Every decryption failure maps to this one variant, whatever the
    /// internal cause, and it deliberately carries no detail. The recipient
    /// must not distinguish format, padding and length errors
    /// (RFC 7516 §11.5), so no padding or key-unwrap oracle is exposed
    /// (RFC 7516 §5.2, ADR 0007).
    #[error("decryption failed")]
    DecryptionFailed,

    /// `crit` lists an extension polyjose does not understand.
    ///
    /// Recipients must reject the JWS/JWE in that case (RFC 7515 §4.1.11,
    /// RFC 7516 §4.1.13). The unknown name is not echoed.
    #[error("unknown critical header parameter")]
    UnknownCritical,

    /// The JWT `exp` time has passed, allowing for the configured clock
    /// skew (RFC 7519 §4.1.4).
    #[error("token expired")]
    TokenExpired,

    /// The JWT `nbf` time has not been reached yet, allowing for the
    /// configured clock skew (RFC 7519 §4.1.5).
    #[error("token not yet valid")]
    TokenNotYetValid,

    /// A JWT claim is missing, malformed or failed validation.
    ///
    /// The detail names the claim (for example `"aud"`), never its value.
    /// Covers RFC 7519 §4.1 and §7.2 and the RFC 8725 §3.8–§3.9 issuer and
    /// audience checks.
    #[error("invalid claim: {0}")]
    InvalidClaim(&'static str),

    /// The operating-system CSPRNG could not supply random bytes.
    ///
    /// Keys, IVs and CEKs require a cryptographically secure source
    /// (RFC 7515 §10.1, RFC 8725 §3.5); polyjose never falls back to a
    /// weaker one (ADR 0005).
    #[error("randomness unavailable")]
    RandomnessUnavailable,
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
        }
    }
}

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

    /// serde_json errors built from input containing `MARKER`, one per
    /// `serde_json::error::Category`, with the detail we expect for each.
    fn json_errors_from_marked_input() -> Vec<(serde_json::Error, &'static str)> {
        #[derive(Debug, serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        #[allow(dead_code)]
        struct Strict {
            a: u8,
        }
        struct FailingReader;
        impl std::io::Read for FailingReader {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other(MARKER))
            }
        }
        let data_value = format!("\"{MARKER}\"");
        let unknown_field = format!("{{\"{MARKER}\":1}}");
        let syntax = format!("{{\"{MARKER}\" {MARKER}}}");
        let eof = format!("{{\"{MARKER}\":");
        let errs = [
            (serde_json::from_str::<u32>(&data_value).err(), JSON_DATA),
            (serde_json::from_str::<Strict>(&unknown_field).err(), JSON_DATA),
            (serde_json::from_str::<serde_json::Value>(&syntax).err(), JSON_SYNTAX),
            (serde_json::from_str::<serde_json::Value>(&eof).err(), JSON_EOF),
            (serde_json::from_reader::<_, serde_json::Value>(FailingReader).err(), JSON_IO),
        ];
        errs.into_iter()
            .map(|(e, detail)| (e.unwrap_or_else(|| unreachable!("input must fail")), detail))
            .collect()
    }

    #[test]
    fn serde_json_errors_map_to_invalid_json_without_input() {
        let mut echoed = 0;
        for (json_err, detail) in json_errors_from_marked_input() {
            if json_err.to_string().contains(MARKER) {
                echoed += 1;
            }
            let e = Error::from(json_err);
            assert_eq!(e, Error::InvalidJson(detail));
            assert_eq!(e.code(), "InvalidJson");
            assert_no_marker(&e);
        }
        // Proves the test is meaningful: serde_json itself does echo input.
        assert!(echoed >= 3, "expected serde_json to echo the marker");
    }
}
