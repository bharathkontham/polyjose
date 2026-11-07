//! UniFFI mirrors of every surface record (ADR 0030 §3, §4), with `From` conversions and no
//! other logic (ADR 0030 §1, "the adapter test").
//!
//! - **Names** are the surface's; Kotlin and Swift see the fields in `camelCase`
//!   (`allowedAlgs`, `keyUse`) and `Vec<u8>` as `ByteArray`/`Data` (ADR 0030 §2).
//! - **Defaults** (`#[uniffi(default = …)]`, Kotlin default arguments and Swift initialiser
//!   defaults) exist only for `Option` fields (`None`, the core default) and booleans (`false`).
//!   `allowed_algs` and `allowed_enc` have none, so omitting them does not compile in Kotlin or
//!   Swift (ADR 0030 §3, ADR 0007, RFC 8725 §3.1). No adapter writes a default value of its own:
//!   `None` reaches the surface, which calls no core setter (ADR 0030 §3).
//! - **Secrets** (ADR 0030 §7): a secret `String` input (`JwsSigner::key`, `JweRecipient::key`)
//!   is moved into a [`SecretString`], keeping UniFFI's single Rust-heap allocation and wiping it
//!   on drop; secret byte inputs (`detached_payload`, `aad`) move into a [`SecretBytes`]. Secret
//!   outputs (`payload`, `plaintext`, `aad`) are copied once from the surface's borrowed,
//!   zeroizing buffer, which is wiped when the surface record drops. UniFFI 0.32.2 then writes
//!   the record into a buffer that grows as it is written and drops the record, and the host
//!   frees the final `RustBuffer`, all unwiped. So each secret output leaves **at least 2** full
//!   Rust-heap copies (the adapter's vector and the host-freed buffer), plus a full or partial
//!   copy for each move of the growing buffer, depending on the size and the platform allocator.
//!   These are the measured residual of ADR 0058, which supersedes ADR 0030 §7.3 for outputs;
//!   the adapter cannot reach them without `unsafe` (counts in the `jws` and `jwe` module docs).
//! - **Not logged:** none of these records implements `Debug`. The generated Kotlin data classes
//!   and Swift structs of [`JwsSigner`] and [`JweRecipient`] print their key in
//!   `toString`/`description`; never log them (ADR 0030 §3, §7).

use polyjose_surface::records as surface;
use polyjose_surface::{SecretBytes, SecretString};

// ------------------------------------------------------------------------------------------------
// JWK
// ------------------------------------------------------------------------------------------------

/// Which member of a JWK Set `jwks_select` picks; each `None` member places no constraint
/// (RFC 7517 §4.2, §4.4, §4.5, §5).
#[derive(uniffi::Record)]
pub struct JwkSelector {
    /// The JWK `kid` to match exactly (RFC 7517 §4.5).
    #[uniffi(default = None)]
    pub kid: Option<String>,
    /// The algorithm the key must serve, as registered (RFC 7517 §4.4, RFC 7518 §3.1, §4.1).
    #[uniffi(default = None)]
    pub alg: Option<String>,
    /// The JWK `use` to match, `sig` or `enc` (RFC 7517 §4.2).
    #[uniffi(default = None)]
    pub key_use: Option<String>,
}

impl From<JwkSelector> for surface::JwkSelector {
    fn from(v: JwkSelector) -> Self {
        Self {
            kid: v.kid,
            alg: v.alg,
            key_use: v.key_use,
        }
    }
}

// ------------------------------------------------------------------------------------------------
// JWS
// ------------------------------------------------------------------------------------------------

/// Options of `jws_sign_compact` (RFC 7515 §5.1, §7.1). Exactly one of `protected_header` and
/// `protected_b64u`; both or neither fail with `InvalidHeader` (ADR 0030 §4).
#[derive(uniffi::Record)]
pub struct JwsSignOptions {
    /// The JWS Protected Header as JSON text (RFC 7515 §5.1 step 3).
    #[uniffi(default = None)]
    pub protected_header: Option<String>,
    /// The JWS Protected Header already base64url-encoded, signed over as given (RFC 7515 §5.1
    /// step 3, Appendix A.1).
    #[uniffi(default = None)]
    pub protected_b64u: Option<String>,
    /// Leave the payload out of the output (RFC 7515 Appendix F).
    #[uniffi(default = false)]
    pub detached: bool,
}

impl From<JwsSignOptions> for surface::JwsSignOptions {
    fn from(v: JwsSignOptions) -> Self {
        Self {
            protected_header: v.protected_header,
            protected_b64u: v.protected_b64u,
            detached: v.detached,
        }
    }
}

/// One signature of a JWS JSON Serialization (RFC 7515 §7.2.1). Holds a key: its generated
/// `toString`/`description` prints it, so never log it (ADR 0030 §3).
#[derive(uniffi::Record)]
pub struct JwsSigner {
    /// The signing key, a private JWK as JSON text (RFC 7517 §4). Secret (ADR 0030 §7).
    pub key: String,
    /// The JWS Protected Header as JSON text (RFC 7515 §7.2.1 `protected`).
    #[uniffi(default = None)]
    pub protected_header: Option<String>,
    /// The JWS Protected Header already base64url-encoded (RFC 7515 §5.1 step 3).
    #[uniffi(default = None)]
    pub protected_b64u: Option<String>,
    /// The JWS Unprotected Header as JSON text, not signed (RFC 7515 §7.2.1 `header`).
    #[uniffi(default = None)]
    pub unprotected_header: Option<String>,
}

impl From<JwsSigner> for surface::JwsSigner {
    fn from(v: JwsSigner) -> Self {
        Self {
            key: SecretString::from(v.key),
            protected_header: v.protected_header,
            protected_b64u: v.protected_b64u,
            unprotected_header: v.unprotected_header,
        }
    }
}

/// Options of `jws_verify_compact` and `jws_verify_json` (RFC 7515 §5.2; ADR 0026).
#[derive(uniffi::Record)]
pub struct JwsVerifyOptions {
    /// The algorithms the caller accepts (RFC 8725 §3.1, ADR 0007). Required, no default.
    pub allowed_algs: Vec<String>,
    /// The payload, when it travels separately (RFC 7515 Appendix F). Secret (ADR 0049 §4).
    #[uniffi(default = None)]
    pub detached_payload: Option<Vec<u8>>,
    /// The largest serialized JWS accepted, in bytes (ADR 0026 §7). `None`: the core default.
    #[uniffi(default = None)]
    pub max_input_len: Option<u32>,
    /// The most signatures a general JSON JWS may have (ADR 0026 §7). `None`: the core default.
    #[uniffi(default = None)]
    pub max_signatures: Option<u32>,
}

impl From<JwsVerifyOptions> for surface::JwsVerifyOptions {
    fn from(v: JwsVerifyOptions) -> Self {
        Self {
            allowed_algs: v.allowed_algs,
            detached_payload: v.detached_payload.map(SecretBytes::from),
            max_input_len: v.max_input_len,
            max_signatures: v.max_signatures,
        }
    }
}

/// A verified JWS (RFC 7515 §5.2).
#[derive(uniffi::Record)]
pub struct JwsVerified {
    /// The `alg` of the signature that verified (RFC 7515 §4.1.1).
    pub alg: String,
    /// The JWS Payload (RFC 7515 §2). Treated as secret (ADR 0049 §4).
    pub payload: Vec<u8>,
    /// That signature's JWS Protected Header, the only integrity-protected one (RFC 7515 §5.1
    /// step 5).
    #[uniffi(default = None)]
    pub protected_header: Option<String>,
    /// That signature's JWS Unprotected Header (RFC 7515 §7.2.1). **Not integrity-protected**
    /// (ADR 0049 §2): never trust `typ`, `cty`, `kid` or `crit` from it.
    #[uniffi(default = None)]
    pub unprotected_header: Option<String>,
    /// The index of the signature that verified (ADR 0026 §3).
    pub signature_index: u32,
}

impl From<surface::JwsVerified> for JwsVerified {
    fn from(v: surface::JwsVerified) -> Self {
        Self {
            alg: v.alg,
            payload: v.payload.as_bytes().to_vec(),
            protected_header: v.protected_header,
            unprotected_header: v.unprotected_header,
            signature_index: v.signature_index,
        }
    }
}

// ------------------------------------------------------------------------------------------------
// JWE
// ------------------------------------------------------------------------------------------------

/// Options of `jwe_encrypt_compact`, `jwe_encrypt_json` and `jwt_encrypt_nested` (RFC 7516
/// §5.1, §7).
#[derive(uniffi::Record)]
pub struct JweEncryptOptions {
    /// The content encryption algorithm, as registered (RFC 7516 §4.1.2, RFC 7518 §5.1).
    pub enc: String,
    /// The recipients, in output order (RFC 7516 §7.2.1).
    pub recipients: Vec<JweRecipient>,
    /// The JWE Protected Header's extra members as JSON text (RFC 7516 §2).
    #[uniffi(default = None)]
    pub protected_header: Option<String>,
    /// The JWE Shared Unprotected Header as JSON text (RFC 7516 §7.2.1 `unprotected`).
    #[uniffi(default = None)]
    pub shared_unprotected_header: Option<String>,
    /// The JWE AAD (RFC 7516 §7.2.1 `aad`), JSON only. Secret (ADR 0030 §7).
    #[uniffi(default = None)]
    pub aad: Option<Vec<u8>>,
    /// Compress with `zip: DEF` (RFC 7516 §4.1.3); `true` fails with `UnsupportedAlgorithm` in the
    /// bindings, built without the core's `deflate` feature (ADR 0030 §4, ADR 0034 §3).
    #[uniffi(default = false)]
    pub compress: bool,
}

impl From<JweEncryptOptions> for surface::JweEncryptOptions {
    fn from(v: JweEncryptOptions) -> Self {
        Self {
            enc: v.enc,
            recipients: v.recipients.into_iter().map(Into::into).collect(),
            protected_header: v.protected_header,
            shared_unprotected_header: v.shared_unprotected_header,
            aad: v.aad.map(SecretBytes::from),
            compress: v.compress,
        }
    }
}

/// One recipient of a JWE (RFC 7516 §7.2.1, RFC 7518 §4). Holds a key: its generated
/// `toString`/`description` prints it, so never log it (ADR 0030 §3).
#[derive(uniffi::Record)]
pub struct JweRecipient {
    /// The key management algorithm, as registered (RFC 7516 §4.1.1, RFC 7518 §4.1).
    pub alg: String,
    /// The recipient's key as JWK JSON text, or the PBES2 password as an `oct` JWK (RFC 7518 §4).
    /// Secret (ADR 0030 §7).
    pub key: String,
    /// The JWE Per-Recipient Unprotected Header as JSON text (RFC 7516 §7.2.1 `header`).
    #[uniffi(default = None)]
    pub header: Option<String>,
    /// Agreement PartyUInfo for ECDH-ES (RFC 7518 §4.6.1.2).
    #[uniffi(default = None)]
    pub apu: Option<Vec<u8>>,
    /// Agreement PartyVInfo for ECDH-ES (RFC 7518 §4.6.1.3).
    #[uniffi(default = None)]
    pub apv: Option<Vec<u8>>,
    /// The PBES2 iteration count (RFC 7518 §4.8.1.2). `None`: the core default (ADR 0023).
    #[uniffi(default = None)]
    pub p2c: Option<u32>,
    /// The PBES2 salt input length in octets (RFC 7518 §4.8.1.1). `None`: the core default.
    #[uniffi(default = None)]
    pub p2s_len: Option<u32>,
}

impl From<JweRecipient> for surface::JweRecipient {
    fn from(v: JweRecipient) -> Self {
        Self {
            alg: v.alg,
            key: SecretString::from(v.key),
            header: v.header,
            apu: v.apu,
            apv: v.apv,
            p2c: v.p2c,
            p2s_len: v.p2s_len,
        }
    }
}

/// Options of `jwe_decrypt_compact`, `jwe_decrypt_json` and the nested JWT decrypt operations
/// (RFC 7516 §5.2; ADR 0023, ADR 0050).
#[derive(uniffi::Record)]
pub struct JweDecryptOptions {
    /// The key management algorithms the caller accepts (RFC 8725 §3.1, ADR 0007). Required, no
    /// default.
    pub allowed_algs: Vec<String>,
    /// The content encryption algorithms the caller accepts (RFC 8725 §3.1, ADR 0007). Required,
    /// no default.
    pub allowed_enc: Vec<String>,
    /// The PBES2 budget, summed over the PBES2 recipients tried (ADR 0023, ADR 0050 §2). `None`:
    /// the core default.
    #[uniffi(default = None)]
    pub max_pbes2_count: Option<u32>,
    /// The largest decompressed plaintext for `zip: DEF` (ADR 0017). `None`: the core default.
    #[uniffi(default = None)]
    pub max_decompressed_len: Option<u32>,
    /// The largest serialized JWE accepted, in bytes. `None`: the core default.
    #[uniffi(default = None)]
    pub max_input_len: Option<u32>,
    /// The most recipients a general JSON JWE may have. `None`: the core default.
    #[uniffi(default = None)]
    pub max_recipients: Option<u32>,
    /// Extension header names the caller processes itself (RFC 7516 §4.1.13). `None`: none.
    #[uniffi(default = None)]
    pub understood_crit: Option<Vec<String>>,
}

impl From<JweDecryptOptions> for surface::JweDecryptOptions {
    fn from(v: JweDecryptOptions) -> Self {
        Self {
            allowed_algs: v.allowed_algs,
            allowed_enc: v.allowed_enc,
            max_pbes2_count: v.max_pbes2_count,
            max_decompressed_len: v.max_decompressed_len,
            max_input_len: v.max_input_len,
            max_recipients: v.max_recipients,
            understood_crit: v.understood_crit,
        }
    }
}

/// A decrypted JWE (RFC 7516 §5.2). Only `protected_header` is integrity-protected (RFC 7516
/// §5.1 steps 14–15, ADR 0050 §3).
#[derive(uniffi::Record)]
pub struct JweDecrypted {
    /// The plaintext (RFC 7516 §5.2 step 16). Secret (ADR 0030 §7).
    pub plaintext: Vec<u8>,
    /// The JOSE Header used, the union of every header part (RFC 7516 §5.2 step 4). Not
    /// integrity-protected as a whole (ADR 0050 §3).
    pub header: String,
    /// The JWE Protected Header (RFC 7516 §2), integrity-protected.
    #[uniffi(default = None)]
    pub protected_header: Option<String>,
    /// The JWE Shared Unprotected Header (RFC 7516 §7.2.1). Not integrity-protected.
    #[uniffi(default = None)]
    pub shared_unprotected_header: Option<String>,
    /// The decrypting recipient's Per-Recipient Unprotected Header (RFC 7516 §7.2.1). Not
    /// integrity-protected.
    #[uniffi(default = None)]
    pub recipient_header: Option<String>,
    /// The JWE AAD (RFC 7516 §7.2.1 `aad`), decoded. Secret (ADR 0050 §4).
    #[uniffi(default = None)]
    pub aad: Option<Vec<u8>>,
    /// The index of the recipient that decrypted (RFC 7516 §7.2.1).
    pub recipient_index: u32,
}

impl From<surface::JweDecrypted> for JweDecrypted {
    fn from(v: surface::JweDecrypted) -> Self {
        Self {
            plaintext: v.plaintext.as_bytes().to_vec(),
            header: v.header,
            protected_header: v.protected_header,
            shared_unprotected_header: v.shared_unprotected_header,
            recipient_header: v.recipient_header,
            aad: v.aad.as_ref().map(|aad| aad.as_bytes().to_vec()),
            recipient_index: v.recipient_index,
        }
    }
}

// ------------------------------------------------------------------------------------------------
// JWT
// ------------------------------------------------------------------------------------------------

/// Options of `jwt_sign` (RFC 7519 §7.1, RFC 9068 §2.1). `typ` together with `omit_typ` or
/// `access_token` fails with `InvalidHeader` (ADR 0030 §4).
#[derive(uniffi::Record)]
pub struct JwtSignOptions {
    /// The JWS algorithm, as registered (RFC 7515 §4.1.1, RFC 7518 §3.1).
    pub alg: String,
    /// The JOSE `typ` (RFC 7519 §5.1). `None`: the core default, `JWT`.
    #[uniffi(default = None)]
    pub typ: Option<String>,
    /// Write no `typ` at all.
    #[uniffi(default = false)]
    pub omit_typ: bool,
    /// Issue an RFC 9068 access token, `typ: at+jwt` (RFC 9068 §2.1).
    #[uniffi(default = false)]
    pub access_token: bool,
    /// Extra JWS Protected Header members as a JSON object (RFC 7515 §4).
    #[uniffi(default = None)]
    pub header: Option<String>,
}

impl From<JwtSignOptions> for surface::JwtSignOptions {
    fn from(v: JwtSignOptions) -> Self {
        Self {
            alg: v.alg,
            typ: v.typ,
            omit_typ: v.omit_typ,
            access_token: v.access_token,
            header: v.header,
        }
    }
}

/// Options of `jwt_verify`, `jwt_verify_with_jwks` and the nested JWT decrypt operations
/// (RFC 7519 §7.2, RFC 8725 §3; ADR 0027, ADR 0028, ADR 0029). Each `None`/`false` leaves the
/// core default (ADR 0030 §4).
#[derive(uniffi::Record)]
pub struct JwtVerifyOptions {
    /// The JWS algorithms the caller accepts (RFC 8725 §3.1, ADR 0007). Required, no default.
    pub allowed_algs: Vec<String>,
    /// The time to validate against, whole seconds since the epoch (ADR 0028). `None`: the
    /// system clock (ADR 0030 §4, "The clock").
    #[uniffi(default = None)]
    pub now: Option<i64>,
    /// The accepted issuers, compared exactly (RFC 7519 §4.1.1, RFC 8725 §3.8).
    #[uniffi(default = None)]
    pub issuers: Option<Vec<String>>,
    /// The accepted audiences (RFC 7519 §4.1.3, RFC 8725 §3.9).
    #[uniffi(default = None)]
    pub audiences: Option<Vec<String>>,
    /// The required subject (RFC 7519 §4.1.2).
    #[uniffi(default = None)]
    pub subject: Option<String>,
    /// The clock skew allowed, in seconds (RFC 7519 §4.1.4–§4.1.6, ADR 0027 §3). `None`: the
    /// core default.
    #[uniffi(default = None)]
    pub leeway: Option<u32>,
    /// The oldest `iat` accepted, in seconds before `now` (ADR 0027 §3).
    #[uniffi(default = None)]
    pub max_age: Option<u32>,
    /// Claims that must be present (ADR 0027 §4).
    #[uniffi(default = None)]
    pub required_claims: Option<Vec<String>>,
    /// Accept a token without `exp` (ADR 0027 §3).
    #[uniffi(default = false)]
    pub allow_missing_exp: bool,
    /// Skip the audience check (ADR 0027 §4).
    #[uniffi(default = false)]
    pub ignore_audience: bool,
    /// The exact JOSE `typ` required (RFC 8725 §3.11).
    #[uniffi(default = None)]
    pub typ: Option<String>,
    /// Accept any `typ`.
    #[uniffi(default = false)]
    pub any_typ: bool,
    /// A validation profile: `access_token` is RFC 9068 §4.
    #[uniffi(default = None)]
    pub profile: Option<String>,
    /// The most JWK Set members tried (ADR 0029 §4). `None`: the core default.
    #[uniffi(default = None)]
    pub max_key_candidates: Option<u32>,
    /// The largest token accepted, in bytes (ADR 0026 §7). `None`: the core default.
    #[uniffi(default = None)]
    pub max_input_len: Option<u32>,
}

impl From<JwtVerifyOptions> for surface::JwtVerifyOptions {
    fn from(v: JwtVerifyOptions) -> Self {
        Self {
            allowed_algs: v.allowed_algs,
            now: v.now,
            issuers: v.issuers,
            audiences: v.audiences,
            subject: v.subject,
            leeway: v.leeway,
            max_age: v.max_age,
            required_claims: v.required_claims,
            allow_missing_exp: v.allow_missing_exp,
            ignore_audience: v.ignore_audience,
            typ: v.typ,
            any_typ: v.any_typ,
            profile: v.profile,
            max_key_candidates: v.max_key_candidates,
            max_input_len: v.max_input_len,
        }
    }
}

/// A verified, validated signed JWT (RFC 7519 §7.2).
#[derive(uniffi::Record)]
pub struct JwtVerified {
    /// The JWT Claims Set as the core serializes it, registered claims first (ADR 0027 §1).
    pub claims: String,
    /// The JWS Protected Header, as the core serializes it (RFC 7519 §5).
    pub header: String,
    /// The `alg` that verified (RFC 7515 §4.1.1).
    pub alg: String,
    /// The JWK Set index of the key that verified; `None` for a single key (ADR 0029 §4).
    #[uniffi(default = None)]
    pub key_index: Option<u32>,
    /// The `kid` of the key that verified, if it has one (RFC 7517 §4.5).
    #[uniffi(default = None)]
    pub kid: Option<String>,
}

impl From<surface::JwtVerified> for JwtVerified {
    fn from(v: surface::JwtVerified) -> Self {
        Self {
            claims: v.claims,
            header: v.header,
            alg: v.alg,
            key_index: v.key_index,
            kid: v.kid,
        }
    }
}

/// A verified nested JWT, sign-then-encrypt (RFC 7519 §5.2, §11.2; ADR 0027 §7).
#[derive(uniffi::Record)]
pub struct JwtNestedVerified {
    /// The inner signed JWT.
    pub inner: JwtVerified,
    /// The outer JWE's JOSE Header (RFC 7516 §5.2 step 4); `cty` is `JWT` (RFC 7519 §5.2).
    pub outer_header: String,
    /// The index of the JWE recipient that decrypted (RFC 7516 §7.2.1).
    pub recipient_index: u32,
}

impl From<surface::JwtNestedVerified> for JwtNestedVerified {
    fn from(v: surface::JwtNestedVerified) -> Self {
        Self {
            inner: v.inner.into(),
            outer_header: v.outer_header,
            recipient_index: v.recipient_index,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use polyjose_surface::{SecretBytes, SecretString};

    fn s(v: &str) -> String {
        v.to_owned()
    }

    fn list(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_owned()).collect()
    }

    #[test]
    fn jwk_selector_maps_every_field() {
        let out = surface::JwkSelector::from(JwkSelector {
            kid: Some(s("k1")),
            alg: Some(s("ES256")),
            key_use: Some(s("sig")),
        });
        assert_eq!(
            out,
            surface::JwkSelector {
                kid: Some(s("k1")),
                alg: Some(s("ES256")),
                key_use: Some(s("sig")),
            }
        );
    }

    #[test]
    fn jws_sign_options_map_every_field() {
        let out = surface::JwsSignOptions::from(JwsSignOptions {
            protected_header: Some(s(r#"{"alg":"HS256"}"#)),
            protected_b64u: Some(s("eyJhbGciOiJIUzI1NiJ9")),
            detached: true,
        });
        assert_eq!(out.protected_header.as_deref(), Some(r#"{"alg":"HS256"}"#));
        assert_eq!(out.protected_b64u.as_deref(), Some("eyJhbGciOiJIUzI1NiJ9"));
        assert!(out.detached);
    }

    #[test]
    fn jws_signer_moves_the_key_into_a_secret_owner() {
        let key = s(r#"{"kty":"oct","k":"c2VjcmV0"}"#);
        let ptr = key.as_ptr();
        let out = surface::JwsSigner::from(JwsSigner {
            key,
            protected_header: Some(s("p")),
            protected_b64u: Some(s("b")),
            unprotected_header: Some(s("u")),
        });
        // Moved, not copied: the only Rust-heap copy is now wiped on drop (ADR 0030 §7.1).
        assert_eq!(out.key.as_str().as_ptr(), ptr);
        assert_eq!(out.key.as_str(), r#"{"kty":"oct","k":"c2VjcmV0"}"#);
        assert_eq!(out.protected_header.as_deref(), Some("p"));
        assert_eq!(out.protected_b64u.as_deref(), Some("b"));
        assert_eq!(out.unprotected_header.as_deref(), Some("u"));
    }

    #[test]
    fn jws_verify_options_map_every_field() {
        let out = surface::JwsVerifyOptions::from(JwsVerifyOptions {
            allowed_algs: list(&["ES256", "EdDSA"]),
            detached_payload: Some(vec![1, 2, 3]),
            max_input_len: Some(10),
            max_signatures: Some(2),
        });
        assert_eq!(out.allowed_algs, list(&["ES256", "EdDSA"]));
        assert_eq!(
            out.detached_payload.as_ref().map(SecretBytes::as_bytes),
            Some(&[1u8, 2, 3][..])
        );
        assert_eq!(out.max_input_len, Some(10));
        assert_eq!(out.max_signatures, Some(2));
    }

    #[test]
    fn jws_verified_maps_every_field() {
        let out = JwsVerified::from(surface::JwsVerified {
            alg: s("ES256"),
            payload: SecretBytes::from(vec![4, 5]),
            protected_header: Some(s(r#"{"alg":"ES256"}"#)),
            unprotected_header: Some(s(r#"{"kid":"a"}"#)),
            signature_index: 3,
        });
        assert_eq!(out.alg, "ES256");
        assert_eq!(out.payload, [4, 5]);
        assert_eq!(out.protected_header.as_deref(), Some(r#"{"alg":"ES256"}"#));
        assert_eq!(out.unprotected_header.as_deref(), Some(r#"{"kid":"a"}"#));
        assert_eq!(out.signature_index, 3);
    }

    #[test]
    fn jwe_encrypt_options_and_recipients_map_every_field() {
        let out = surface::JweEncryptOptions::from(JweEncryptOptions {
            enc: s("A256GCM"),
            recipients: vec![
                JweRecipient {
                    alg: s("ECDH-ES+A128KW"),
                    key: s("jwk-1"),
                    header: Some(s(r#"{"kid":"r1"}"#)),
                    apu: Some(vec![1]),
                    apv: Some(vec![2]),
                    p2c: Some(4096),
                    p2s_len: Some(16),
                },
                JweRecipient {
                    alg: s("dir"),
                    key: s("jwk-2"),
                    header: None,
                    apu: None,
                    apv: None,
                    p2c: None,
                    p2s_len: None,
                },
            ],
            protected_header: Some(s(r#"{"cty":"x"}"#)),
            shared_unprotected_header: Some(s(r#"{"jku":"y"}"#)),
            aad: Some(vec![9, 9]),
            compress: true,
        });
        assert_eq!(out.enc, "A256GCM");
        assert_eq!(out.protected_header.as_deref(), Some(r#"{"cty":"x"}"#));
        assert_eq!(
            out.shared_unprotected_header.as_deref(),
            Some(r#"{"jku":"y"}"#)
        );
        assert_eq!(
            out.aad.as_ref().map(SecretBytes::as_bytes),
            Some(&[9u8, 9][..])
        );
        assert!(out.compress);
        assert_eq!(out.recipients.len(), 2);
        let r = &out.recipients[0];
        assert_eq!(r.alg, "ECDH-ES+A128KW");
        assert_eq!(r.key.as_str(), "jwk-1");
        assert_eq!(r.header.as_deref(), Some(r#"{"kid":"r1"}"#));
        assert_eq!(r.apu.as_deref(), Some(&[1u8][..]));
        assert_eq!(r.apv.as_deref(), Some(&[2u8][..]));
        assert_eq!(r.p2c, Some(4096));
        assert_eq!(r.p2s_len, Some(16));
        let r = &out.recipients[1];
        assert_eq!((r.alg.as_str(), r.key.as_str()), ("dir", "jwk-2"));
        assert_eq!((r.header.is_none(), r.apu.is_none()), (true, true));
        assert_eq!((r.apv.is_none(), r.p2c, r.p2s_len), (true, None, None));
    }

    #[test]
    fn jwe_decrypt_options_map_every_field() {
        let out = surface::JweDecryptOptions::from(JweDecryptOptions {
            allowed_algs: list(&["A128KW"]),
            allowed_enc: list(&["A128GCM"]),
            max_pbes2_count: Some(1000),
            max_decompressed_len: Some(2000),
            max_input_len: Some(3000),
            max_recipients: Some(4),
            understood_crit: Some(list(&["exp"])),
        });
        assert_eq!(
            out,
            surface::JweDecryptOptions {
                allowed_algs: list(&["A128KW"]),
                allowed_enc: list(&["A128GCM"]),
                max_pbes2_count: Some(1000),
                max_decompressed_len: Some(2000),
                max_input_len: Some(3000),
                max_recipients: Some(4),
                understood_crit: Some(list(&["exp"])),
            }
        );
    }

    #[test]
    fn jwe_decrypted_maps_every_field() {
        let out = JweDecrypted::from(surface::JweDecrypted {
            plaintext: SecretBytes::from(vec![7, 8]),
            header: s("h"),
            protected_header: Some(s("p")),
            shared_unprotected_header: Some(s("s")),
            recipient_header: Some(s("r")),
            aad: Some(SecretBytes::from(vec![6])),
            recipient_index: 1,
        });
        assert_eq!(out.plaintext, [7, 8]);
        assert_eq!(out.header, "h");
        assert_eq!(out.protected_header.as_deref(), Some("p"));
        assert_eq!(out.shared_unprotected_header.as_deref(), Some("s"));
        assert_eq!(out.recipient_header.as_deref(), Some("r"));
        assert_eq!(out.aad.as_deref(), Some(&[6u8][..]));
        assert_eq!(out.recipient_index, 1);
    }

    #[test]
    fn jwt_sign_options_map_every_field() {
        let out = surface::JwtSignOptions::from(JwtSignOptions {
            alg: s("EdDSA"),
            typ: Some(s("JWT")),
            omit_typ: true,
            access_token: true,
            header: Some(s(r#"{"kid":"k"}"#)),
        });
        assert_eq!(
            out,
            surface::JwtSignOptions {
                alg: s("EdDSA"),
                typ: Some(s("JWT")),
                omit_typ: true,
                access_token: true,
                header: Some(s(r#"{"kid":"k"}"#)),
            }
        );
    }

    #[test]
    fn jwt_verify_options_map_every_field() {
        let out = surface::JwtVerifyOptions::from(JwtVerifyOptions {
            allowed_algs: list(&["ES256"]),
            now: Some(1_700_000_000),
            issuers: Some(list(&["iss"])),
            audiences: Some(list(&["aud"])),
            subject: Some(s("sub")),
            leeway: Some(30),
            max_age: Some(600),
            required_claims: Some(list(&["jti"])),
            allow_missing_exp: true,
            ignore_audience: true,
            typ: Some(s("at+jwt")),
            any_typ: true,
            profile: Some(s("access_token")),
            max_key_candidates: Some(3),
            max_input_len: Some(4096),
        });
        assert_eq!(
            out,
            surface::JwtVerifyOptions {
                allowed_algs: list(&["ES256"]),
                now: Some(1_700_000_000),
                issuers: Some(list(&["iss"])),
                audiences: Some(list(&["aud"])),
                subject: Some(s("sub")),
                leeway: Some(30),
                max_age: Some(600),
                required_claims: Some(list(&["jti"])),
                allow_missing_exp: true,
                ignore_audience: true,
                typ: Some(s("at+jwt")),
                any_typ: true,
                profile: Some(s("access_token")),
                max_key_candidates: Some(3),
                max_input_len: Some(4096),
            }
        );
    }

    #[test]
    fn jwt_verified_and_nested_map_every_field() {
        let inner = surface::JwtVerified {
            claims: s(r#"{"sub":"a"}"#),
            header: s(r#"{"alg":"ES256"}"#),
            alg: s("ES256"),
            key_index: Some(2),
            kid: Some(s("k2")),
        };
        let out = JwtNestedVerified::from(surface::JwtNestedVerified {
            inner: inner.clone(),
            outer_header: s(r#"{"cty":"JWT"}"#),
            recipient_index: 5,
        });
        assert_eq!(out.outer_header, r#"{"cty":"JWT"}"#);
        assert_eq!(out.recipient_index, 5);
        let single = JwtVerified::from(inner);
        for v in [&out.inner, &single] {
            assert_eq!(v.claims, r#"{"sub":"a"}"#);
            assert_eq!(v.header, r#"{"alg":"ES256"}"#);
            assert_eq!(v.alg, "ES256");
            assert_eq!(v.key_index, Some(2));
            assert_eq!(v.kid.as_deref(), Some("k2"));
        }
    }

    #[test]
    fn secret_string_input_is_a_move() {
        let key = s("secret");
        let ptr = key.as_ptr();
        let r = surface::JweRecipient::from(JweRecipient {
            alg: s("dir"),
            key,
            header: None,
            apu: None,
            apv: None,
            p2c: None,
            p2s_len: None,
        });
        let _: &SecretString = &r.key;
        assert_eq!(r.key.as_str().as_ptr(), ptr);
    }
}
