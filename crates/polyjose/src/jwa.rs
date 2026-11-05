//! RFC 7518 algorithm identifiers.
use serde::{Deserialize, Serialize};

/// JWS `alg` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SigningAlg {
    /// HMAC using SHA-256 (RFC 7518 §3.2).
    HS256,
    /// HMAC using SHA-384 (RFC 7518 §3.2).
    HS384,
    /// HMAC using SHA-512 (RFC 7518 §3.2).
    HS512,
    /// RSASSA-PKCS1-v1_5 using SHA-256 (RFC 7518 §3.3).
    RS256,
    /// RSASSA-PKCS1-v1_5 using SHA-384 (RFC 7518 §3.3).
    RS384,
    /// RSASSA-PKCS1-v1_5 using SHA-512 (RFC 7518 §3.3).
    RS512,
    /// RSASSA-PSS using SHA-256 and MGF1 with SHA-256 (RFC 7518 §3.5).
    PS256,
    /// RSASSA-PSS using SHA-384 and MGF1 with SHA-384 (RFC 7518 §3.5).
    PS384,
    /// RSASSA-PSS using SHA-512 and MGF1 with SHA-512 (RFC 7518 §3.5).
    PS512,
    /// ECDSA using P-256 and SHA-256 (RFC 7518 §3.4).
    ES256,
    /// ECDSA using P-384 and SHA-384 (RFC 7518 §3.4).
    ES384,
    /// ECDSA using P-521 and SHA-512 (RFC 7518 §3.4).
    ES512,
    /// EdDSA signature algorithms (RFC 8037 §3.1).
    EdDSA,
}

/// JWE `alg` (key management) values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyMgmtAlg {
    /// `RSA-OAEP`: RSAES OAEP using default parameters (RFC 7518 §4.3).
    #[serde(rename = "RSA-OAEP")]
    RsaOaep,
    /// `RSA-OAEP-256`: RSAES OAEP using SHA-256 and MGF1 with SHA-256 (RFC 7518 §4.3).
    #[serde(rename = "RSA-OAEP-256")]
    RsaOaep256,
    /// AES Key Wrap with a 128-bit key (RFC 7518 §4.4).
    A128KW,
    /// AES Key Wrap with a 192-bit key (RFC 7518 §4.4).
    A192KW,
    /// AES Key Wrap with a 256-bit key (RFC 7518 §4.4).
    A256KW,
    /// `dir`: direct use of a shared symmetric key as the CEK (RFC 7518 §4.5).
    #[serde(rename = "dir")]
    Dir,
    /// `ECDH-ES`: ECDH Ephemeral Static direct key agreement (RFC 7518 §4.6).
    #[serde(rename = "ECDH-ES")]
    EcdhEs,
    /// `ECDH-ES+A128KW`: ECDH-ES with A128KW (RFC 7518 §4.6).
    #[serde(rename = "ECDH-ES+A128KW")]
    EcdhEsA128KW,
    /// `ECDH-ES+A256KW`: ECDH-ES with A256KW (RFC 7518 §4.6).
    #[serde(rename = "ECDH-ES+A256KW")]
    EcdhEsA256KW,
    /// Key wrapping with AES-GCM using a 128-bit key (RFC 7518 §4.7).
    A128GCMKW,
    /// Key wrapping with AES-GCM using a 256-bit key (RFC 7518 §4.7).
    A256GCMKW,
    /// `PBES2-HS256+A128KW`: PBES2 with HMAC SHA-256 and A128KW (RFC 7518 §4.8).
    #[serde(rename = "PBES2-HS256+A128KW")]
    Pbes2Hs256A128KW,
}

/// JWE `enc` (content encryption) values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContentEncAlg {
    /// `A128CBC-HS256`: AES-128-CBC with HMAC SHA-256 (RFC 7518 §5.2.3).
    #[serde(rename = "A128CBC-HS256")]
    A128CbcHs256,
    /// `A192CBC-HS384`: AES-192-CBC with HMAC SHA-384 (RFC 7518 §5.2.4).
    #[serde(rename = "A192CBC-HS384")]
    A192CbcHs384,
    /// `A256CBC-HS512`: AES-256-CBC with HMAC SHA-512 (RFC 7518 §5.2.5).
    #[serde(rename = "A256CBC-HS512")]
    A256CbcHs512,
    /// AES-GCM using a 128-bit key (RFC 7518 §5.3).
    A128GCM,
    /// AES-GCM using a 192-bit key (RFC 7518 §5.3).
    A192GCM,
    /// AES-GCM using a 256-bit key (RFC 7518 §5.3).
    A256GCM,
}
