//! RFC 7517 JSON Web Key. TODO: kty EC/RSA/oct/OKP, JWK Set, RFC 7638 thumbprint.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
/// A JSON Web Key (RFC 7517 §4).
pub struct Jwk {
    /// Key type (RFC 7517 §4.1).
    pub kty: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Key ID (RFC 7517 §4.5).
    pub kid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Intended algorithm (RFC 7517 §4.4).
    pub alg: Option<String>,
    #[serde(flatten)]
    /// Key-type-specific and other parameters.
    pub params: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// A JWK Set (RFC 7517 §5).
pub struct JwkSet {
    /// The keys in the set (RFC 7517 §5.1).
    pub keys: Vec<Jwk>,
}
