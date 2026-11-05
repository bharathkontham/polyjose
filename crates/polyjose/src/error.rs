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
