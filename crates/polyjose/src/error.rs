/// Errors returned by polyjose. Stable error codes come in T02.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Input is not valid unpadded base64url (RFC 7515 §2).
    #[error("invalid base64url")]
    Base64,
    /// Input is not valid JSON.
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// The algorithm is not supported by polyjose.
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
    /// The key is malformed or unsuitable for the operation.
    #[error("invalid key: {0}")]
    InvalidKey(String),
    /// A JWS signature or MAC did not verify.
    #[error("signature verification failed")]
    InvalidSignature,
    /// JWE decryption failed. The cause is deliberately not reported (no oracle).
    #[error("decryption failed")]
    DecryptionFailed,
    /// The token is malformed or failed validation.
    #[error("invalid token: {0}")]
    InvalidToken(String),
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
}
