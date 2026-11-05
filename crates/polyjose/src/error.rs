#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid base64url")]
    Base64,
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("invalid key: {0}")]
    InvalidKey(String),
    #[error("signature verification failed")]
    InvalidSignature,
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("invalid token: {0}")]
    InvalidToken(String),
}

pub type Result<T> = core::result::Result<T, Error>;
