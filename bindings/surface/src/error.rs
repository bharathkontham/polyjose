//! The surface error: one stable core code plus the core message (ADR 0030 §5).

use core::fmt;

/// The error every surface operation returns (ADR 0030 §5, option E1).
///
/// It carries exactly two things, both taken from a core [`polyjose::Error`]:
///
/// - [`code`](Self::code): the stable string of [`polyjose::Error::code`], one of
///   [`error_codes`](crate::util::error_codes). This is the cross-platform contract: every
///   binding surfaces it unchanged (JS `err.code`, the Kotlin and Swift `code()` accessor), and
///   the conformance vectors name it (ADR 0008, ADR 0034).
/// - [`message`](Self::message): the core's `Display` text, for humans. It is not stable; match
///   on the code.
///
/// The only constructor is `From<polyjose::Error>`, and the fields are private with no setter,
/// so no binding can invent a code or put input into a message (ADR 0030 §5). The core already
/// guarantees that neither the code nor the message holds key material or input bytes
/// (ADR 0007): its details are `&'static str` literals of polyjose itself.
///
/// ```
/// use polyjose_surface::error::SurfaceError;
///
/// let err = SurfaceError::from(polyjose::Error::InvalidClaim("aud"));
/// assert_eq!(err.code(), "InvalidClaim");
/// assert_eq!(err.message(), "invalid claim: aud");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurfaceError {
    code: &'static str,
    message: String,
}

impl SurfaceError {
    /// The stable error code, equal to [`polyjose::Error::code`] of the core error this was
    /// built from (ADR 0030 §5).
    pub fn code(&self) -> &'static str {
        self.code
    }

    /// The core's human-readable message ([`polyjose::Error`]'s `Display`). Not stable: match
    /// on [`code`](Self::code) instead (ADR 0030 §5).
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// The one way to build a [`SurfaceError`]: `code = e.code()`, `message = e.to_string()`
/// (ADR 0030 §5).
impl From<polyjose::Error> for SurfaceError {
    fn from(e: polyjose::Error) -> Self {
        Self {
            code: e.code(),
            message: e.to_string(),
        }
    }
}

/// Prints the message only, as the core error does.
impl fmt::Display for SurfaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

/// No cause: like the core error, a surface error never wraps another error whose message
/// could quote input (ADR 0007).
impl std::error::Error for SurfaceError {}

/// The result of every surface operation (ADR 0030 §4).
pub type SurfaceResult<T> = Result<T, SurfaceError>;

#[cfg(test)]
mod tests {
    use super::*;
    use polyjose::Error;

    /// One value of every core variant, in `Error::CODES` order. `Error` is `#[non_exhaustive]`,
    /// so this list cannot be checked exhaustively from here; `every_code_maps_through_unchanged`
    /// compares it with `Error::CODES`, which fails as soon as the core adds a code.
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
            Error::NoMatchingKey,
            Error::MultipleMatchingKeys,
        ]
    }

    /// A distinctive value standing in for untrusted input or key material (the core's marker
    /// style, `polyjose::error` tests).
    const MARKER: &str = "pj-SECRET-marker-7f3a";

    fn assert_no_marker(e: &SurfaceError) {
        for rendered in [
            format!("{e:?}"),
            format!("{e:#?}"),
            e.to_string(),
            e.message().to_owned(),
            e.code().to_owned(),
        ] {
            assert!(
                !rendered.contains(MARKER),
                "surface error leaks input: {rendered}"
            );
        }
    }

    #[test]
    fn every_code_maps_through_unchanged() {
        let codes: Vec<&str> = one_of_each()
            .into_iter()
            .map(|e| SurfaceError::from(e).code())
            .collect();
        assert_eq!(codes, Error::CODES);
    }

    #[test]
    fn message_is_the_core_display_text() {
        for e in one_of_each() {
            let expected = e.to_string();
            let surface = SurfaceError::from(e);
            assert_eq!(surface.message(), expected);
            assert_eq!(surface.to_string(), expected);
        }
    }

    #[test]
    fn no_variant_renders_a_marker_or_has_a_cause() {
        for e in one_of_each() {
            let surface = SurfaceError::from(e);
            assert_no_marker(&surface);
            assert!(std::error::Error::source(&surface).is_none());
        }
    }

    #[test]
    fn a_failing_core_call_on_marked_input_does_not_leak_the_marker() {
        // A private EC JWK whose members hold the marker (21 base64url characters, a length no
        // base64url text has, so the key fails), a JSON text whose syntax error sits next to the
        // marker, where a quoting parser would echo it, and marked bad base64url.
        let marked_jwk =
            format!(r#"{{"kty":"EC","crv":"P-256","x":"{MARKER}","y":"{MARKER}","d":"{MARKER}"}}"#);
        let marked_json = format!("{{\"{MARKER}\" {MARKER}}}");
        let failures = [
            polyjose::jwk::Jwk::from_json(marked_jwk.as_bytes()).unwrap_err(),
            polyjose::jwk::Jwk::from_json(marked_json.as_bytes()).unwrap_err(),
            polyjose::util::b64url_decode(&format!("{MARKER}=")).unwrap_err(),
        ];
        for e in failures {
            assert_no_marker(&SurfaceError::from(e));
        }
    }
}
