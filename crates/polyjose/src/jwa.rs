//! RFC 7518 algorithm identifiers.
use serde::{Deserialize, Serialize};

/// JWS `alg` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SigningAlg {
    HS256, HS384, HS512,
    RS256, RS384, RS512,
    PS256, PS384, PS512,
    ES256, ES384, ES512,
    EdDSA,
}

/// JWE `alg` (key management) values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyMgmtAlg {
    #[serde(rename = "RSA-OAEP")] RsaOaep,
    #[serde(rename = "RSA-OAEP-256")] RsaOaep256,
    A128KW, A192KW, A256KW,
    #[serde(rename = "dir")] Dir,
    #[serde(rename = "ECDH-ES")] EcdhEs,
    #[serde(rename = "ECDH-ES+A128KW")] EcdhEsA128KW,
    #[serde(rename = "ECDH-ES+A256KW")] EcdhEsA256KW,
    A128GCMKW, A256GCMKW,
    #[serde(rename = "PBES2-HS256+A128KW")] Pbes2Hs256A128KW,
}

/// JWE `enc` (content encryption) values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContentEncAlg {
    #[serde(rename = "A128CBC-HS256")] A128CbcHs256,
    #[serde(rename = "A192CBC-HS384")] A192CbcHs384,
    #[serde(rename = "A256CBC-HS512")] A256CbcHs512,
    A128GCM, A192GCM, A256GCM,
}
