//! Every record and result of the binding API (ADR 0030 §3, §4), plus the crate-private
//! conversion helpers the operations use to hand them to the core.
//!
//! # Rules every record follows (ADR 0030 §3)
//!
//! - **Every tunable is optional, and `None` means the core default.** No surface code writes a
//!   default: the helpers below call a core setter only for `Some`, and a `false` flag calls
//!   nothing, so the PBES2 bound (ADR 0023, ADR 0050 §2), the JWS and JWE input limits
//!   (ADR 0026 §7), the DEFLATE cap (ADR 0017) and the JWT leeway and candidate bound
//!   (ADR 0027 §3, ADR 0029 §4) live in the core only.
//! - **Allow-lists are required:** `allowed_algs` (and `allowed_enc` for JWE) are plain
//!   `Vec<String>` fields with no default and appear in each record's `new` (ADR 0007,
//!   RFC 8725 §3.1). An empty list reaches the core, which rejects it with `AlgorithmNotAllowed`.
//! - **Identifiers are strings exactly as registered** (`ES256`, `A256GCM`, `ECDH-ES+A128KW`;
//!   ADR 0030 option D1). The core decides what an unknown one means.
//! - **JSON values are JSON text** (`String`): headers, claims and JWKs are parsed and written by
//!   the core's own I-JSON code (ADR 0016, ADR 0030 §2), never by the surface.
//! - **Secret-bearing fields** (keys, payloads, plaintext, `aad`; ADR 0030 §7) are
//!   [`SecretString`]/[`SecretBytes`], and every record with one implements `Debug` by hand with
//!   `<redacted>`. JSON-valued fields print as their length only, like the core's redacting
//!   `Debug` of a [`polyjose::header::Header`]'s JSON members.
//! - **Not `#[non_exhaustive]`, on purpose.** Adapters (WASM, Node, UniFFI) re-declare each record
//!   with their framework's derive and convert with a struct literal, so adding a field later
//!   fails to compile in every adapter until it maps the field (ADR 0030 §1, "the adapter test").
//!
//! Field names are the core option names, which are also the conformance vector member names
//! (ADR 0030 option D'); hosts see them in `camelCase` (ADR 0030 §2).

use core::fmt;

use crate::secret::{SecretBytes, SecretString};

// ------------------------------------------------------------------------------------------------
// JWK
// ------------------------------------------------------------------------------------------------

/// Which member of a JWK Set [`jwks_select`](crate::jwk::jwks_select) picks (ADR 0030 §4, JWK;
/// RFC 7517 §4.2, §4.4, §4.5, §5).
///
/// Each `None` member places no constraint on the selection.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JwkSelector {
    /// The JWK `kid` to match exactly (RFC 7517 §4.5).
    pub kid: Option<String>,
    /// The algorithm the key must serve, as registered (RFC 7517 §4.4, RFC 7518 §3.1, §4.1).
    pub alg: Option<String>,
    /// The JWK `use` to match, `sig` or `enc` (RFC 7517 §4.2). Named `key_use` because `use` is
    /// a Rust keyword; every host keeps the same name (ADR 0030 §4).
    pub key_use: Option<String>,
}

// ------------------------------------------------------------------------------------------------
// JWS
// ------------------------------------------------------------------------------------------------

/// Options of [`jws_sign_compact`](crate::jws::jws_sign_compact) (ADR 0030 §4, JWS; RFC 7515
/// §5.1, §7.1).
///
/// Exactly one of `protected_header` and `protected_b64u` must be set; both or neither fail with
/// `InvalidHeader` (ADR 0030 §4), because the compact serialization needs a JWS Protected Header
/// (RFC 7515 §7.1, ADR 0045 §1).
#[derive(Clone, Default, PartialEq, Eq)]
pub struct JwsSignOptions {
    /// The JWS Protected Header as JSON text, serialized by the core (RFC 7515 §5.1 step 3).
    pub protected_header: Option<String>,
    /// The JWS Protected Header already encoded, `BASE64URL(UTF8(JWS Protected Header))`, signed
    /// over exactly as given (RFC 7515 §5.1 step 3, Appendix A.1's CRLF octets).
    pub protected_b64u: Option<String>,
    /// Leave the payload out of the output (RFC 7515 Appendix F). Default `false`.
    pub detached: bool,
}

/// Prints the header forms' lengths only.
impl fmt::Debug for JwsSignOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JwsSignOptions")
            .field("protected_header_len", &json_len(&self.protected_header))
            .field("protected_b64u_len", &json_len(&self.protected_b64u))
            .field("detached", &self.detached)
            .finish()
    }
}

/// One signature of a JWS JSON Serialization, for
/// [`jws_sign_flattened`](crate::jws::jws_sign_flattened) and
/// [`jws_sign_general`](crate::jws::jws_sign_general) (ADR 0030 §4, JWS; RFC 7515 §7.2.1).
///
/// At most one of `protected_header` and `protected_b64u` may be set (both fail with
/// `InvalidHeader`). **A signer may carry only `unprotected_header`** in the flattened and
/// general JSON serializations (RFC 7515 §7.2.1, ADR 0045 §1, amending ADR 0030): its signing
/// input is then `"." || payload` (RFC 7515 §5.1). Every signer still needs an `alg` in one of
/// its headers, and a member may not appear in both (RFC 7515 §4, §7.2.1).
///
/// The record holds a key, so a generated Kotlin data class or Swift struct mirroring it prints
/// the key in `toString`/`description`: never log it (ADR 0030 §3, residual risk §7). Here,
/// `Debug` redacts it.
pub struct JwsSigner {
    /// The signing key, a private JWK as JSON text (RFC 7517 §4).
    pub key: SecretString,
    /// The JWS Protected Header as JSON text (RFC 7515 §7.2.1 `protected`).
    pub protected_header: Option<String>,
    /// The JWS Protected Header already base64url-encoded, used verbatim (RFC 7515 §5.1 step 3).
    pub protected_b64u: Option<String>,
    /// The JWS Unprotected Header as JSON text (RFC 7515 §7.2.1 `header`). Not covered by the
    /// signature (RFC 7515 §5.1 step 5).
    pub unprotected_header: Option<String>,
}

impl JwsSigner {
    /// A signer with `key` and no header yet.
    pub fn new(key: SecretString) -> Self {
        Self {
            key,
            protected_header: None,
            protected_b64u: None,
            unprotected_header: None,
        }
    }
}

/// Redacts the key and prints the headers' lengths only (ADR 0030 §7.5).
impl fmt::Debug for JwsSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JwsSigner")
            .field("key", &self.key)
            .field("protected_header_len", &json_len(&self.protected_header))
            .field("protected_b64u_len", &json_len(&self.protected_b64u))
            .field(
                "unprotected_header_len",
                &json_len(&self.unprotected_header),
            )
            .finish()
    }
}

/// Options of [`jws_verify_compact`](crate::jws::jws_verify_compact) and
/// [`jws_verify_json`](crate::jws::jws_verify_json) (ADR 0030 §4, JWS; RFC 7515 §5.2;
/// ADR 0026).
pub struct JwsVerifyOptions {
    /// The algorithms the caller accepts, as registered (RFC 8725 §3.1, ADR 0007). Required: an
    /// empty list, or one holding only `none`, fails with `AlgorithmNotAllowed` in the core.
    pub allowed_algs: Vec<String>,
    /// The payload, when it travels separately (RFC 7515 Appendix F). Treated as secret
    /// (ADR 0030 §7, ADR 0049 §4).
    pub detached_payload: Option<SecretBytes>,
    /// The largest serialized JWS accepted, in bytes (ADR 0026 §7). `None`: the core default.
    pub max_input_len: Option<u32>,
    /// The most signatures a general JSON JWS may have (ADR 0026 §7). `None`: the core default.
    pub max_signatures: Option<u32>,
}

impl JwsVerifyOptions {
    /// Options accepting exactly `allowed_algs`, every other member left to the core.
    pub fn new(allowed_algs: Vec<String>) -> Self {
        Self {
            allowed_algs,
            detached_payload: None,
            max_input_len: None,
            max_signatures: None,
        }
    }
}

/// Redacts the detached payload (ADR 0030 §7.5).
impl fmt::Debug for JwsVerifyOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JwsVerifyOptions")
            .field("allowed_algs", &self.allowed_algs)
            .field("detached_payload", &self.detached_payload)
            .field("max_input_len", &self.max_input_len)
            .field("max_signatures", &self.max_signatures)
            .finish()
    }
}

/// A verified JWS (ADR 0030 §4, JWS; RFC 7515 §5.2): the result of
/// [`jws_verify_compact`](crate::jws::jws_verify_compact) and
/// [`jws_verify_json`](crate::jws::jws_verify_json).
///
/// For a general JSON JWS, it describes the first signature that verified with the given key,
/// in array order (ADR 0026 §3).
pub struct JwsVerified {
    /// The `alg` of the signature that verified (RFC 7515 §4.1.1).
    pub alg: String,
    /// The JWS Payload (RFC 7515 §2), wiped on drop: payloads are treated as secret
    /// (ADR 0049 §4, ADR 0030 §7).
    pub payload: SecretBytes,
    /// That signature's JWS Protected Header, as the core serializes it (always present for
    /// compact). The only integrity-protected header (RFC 7515 §5.1 step 5).
    pub protected_header: Option<String>,
    /// That signature's JWS Unprotected Header (JSON serializations only, RFC 7515 §7.2.1).
    ///
    /// **Not integrity-protected** (ADR 0049 §2): the signature does not cover it (RFC 7515
    /// §5.1 step 5), so anyone can change it and the JWS still verifies. Never trust `typ`,
    /// `cty`, `kid` or `crit` from it; read them from
    /// [`protected_header`](Self::protected_header).
    pub unprotected_header: Option<String>,
    /// The index of the signature that verified: `0` for compact and flattened, its position in
    /// `signatures` for general JSON (ADR 0026 §3).
    pub signature_index: u32,
}

/// Redacts the payload and prints the headers' lengths only (ADR 0030 §7.5).
impl fmt::Debug for JwsVerified {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JwsVerified")
            .field("alg", &self.alg)
            .field("payload", &self.payload)
            .field("protected_header_len", &json_len(&self.protected_header))
            .field(
                "unprotected_header_len",
                &json_len(&self.unprotected_header),
            )
            .field("signature_index", &self.signature_index)
            .finish()
    }
}

// ------------------------------------------------------------------------------------------------
// JWE
// ------------------------------------------------------------------------------------------------

/// Options of [`jwe_encrypt_compact`](crate::jwe::jwe_encrypt_compact),
/// [`jwe_encrypt_json`](crate::jwe::jwe_encrypt_json) and
/// [`jwt_encrypt_nested`](crate::jwt::jwt_encrypt_nested) (ADR 0030 §4, JWE; RFC 7516 §5.1,
/// §7).
///
/// Compact output takes exactly one recipient, and no `aad` or unprotected header (RFC 7516
/// §7.1); the core rejects anything else with `InvalidFormat`.
pub struct JweEncryptOptions {
    /// The content encryption algorithm, as registered (RFC 7516 §4.1.2, RFC 7518 §5.1).
    pub enc: String,
    /// The recipients, in output order (RFC 7516 §7.2.1).
    pub recipients: Vec<JweRecipient>,
    /// The JWE Protected Header as JSON text (RFC 7516 §2), extra members only: the core places
    /// `alg` and `enc` itself.
    pub protected_header: Option<String>,
    /// The JWE Shared Unprotected Header as JSON text (RFC 7516 §7.2.1 `unprotected`).
    pub shared_unprotected_header: Option<String>,
    /// The JWE AAD (RFC 7516 §7.2.1 `aad`), JSON only. Treated as secret (ADR 0050 §4,
    /// ADR 0030 §7).
    pub aad: Option<SecretBytes>,
    /// Compress with `zip: DEF` before encrypting (RFC 7516 §4.1.3). Default `false`. The
    /// bindings build without the core's `deflate` feature, so `true` fails with
    /// `UnsupportedAlgorithm` (ADR 0030 §4, ADR 0034 §3).
    pub compress: bool,
}

impl JweEncryptOptions {
    /// Options encrypting with `enc` to `recipients`, every other member left to the core.
    pub fn new(enc: String, recipients: Vec<JweRecipient>) -> Self {
        Self {
            enc,
            recipients,
            protected_header: None,
            shared_unprotected_header: None,
            aad: None,
            compress: false,
        }
    }
}

/// Redacts the recipients' keys and the AAD, and prints the headers' lengths only
/// (ADR 0030 §7.5).
impl fmt::Debug for JweEncryptOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JweEncryptOptions")
            .field("enc", &self.enc)
            .field("recipients", &self.recipients)
            .field("protected_header_len", &json_len(&self.protected_header))
            .field(
                "shared_unprotected_header_len",
                &json_len(&self.shared_unprotected_header),
            )
            .field("aad", &self.aad)
            .field("compress", &self.compress)
            .finish()
    }
}

/// One recipient of a JWE (ADR 0030 §4, JWE; RFC 7516 §7.2.1; RFC 7518 §4).
///
/// The record holds a key, so a generated Kotlin data class or Swift struct mirroring it prints
/// the key in `toString`/`description`: never log it (ADR 0030 §3, residual risk §7). Here,
/// `Debug` redacts it.
pub struct JweRecipient {
    /// The key management algorithm, as registered (RFC 7516 §4.1.1, RFC 7518 §4.1).
    pub alg: String,
    /// The recipient's key as JWK JSON text: a public key for ECDH-ES and RSA-OAEP-256, the
    /// shared `oct` key for `dir`, A*KW and A*GCMKW, the password as an `oct` key for PBES2
    /// (RFC 7518 §4).
    pub key: SecretString,
    /// The JWE Per-Recipient Unprotected Header as JSON text (RFC 7516 §7.2.1 `header`).
    pub header: Option<String>,
    /// Agreement PartyUInfo for ECDH-ES (RFC 7518 §4.6.1.2).
    pub apu: Option<Vec<u8>>,
    /// Agreement PartyVInfo for ECDH-ES (RFC 7518 §4.6.1.3).
    pub apv: Option<Vec<u8>>,
    /// The PBES2 iteration count (RFC 7518 §4.8.1.2). `None`: the core default (ADR 0023).
    pub p2c: Option<u32>,
    /// The PBES2 salt input length in octets (RFC 7518 §4.8.1.1). `None`: the core default.
    pub p2s_len: Option<u32>,
}

impl JweRecipient {
    /// A recipient using `alg` with `key`, every other member left to the core.
    pub fn new(alg: String, key: SecretString) -> Self {
        Self {
            alg,
            key,
            header: None,
            apu: None,
            apv: None,
            p2c: None,
            p2s_len: None,
        }
    }
}

/// Redacts the key and prints the header's length only (ADR 0030 §7.5).
impl fmt::Debug for JweRecipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JweRecipient")
            .field("alg", &self.alg)
            .field("key", &self.key)
            .field("header_len", &json_len(&self.header))
            .field("apu_len", &self.apu.as_ref().map(Vec::len))
            .field("apv_len", &self.apv.as_ref().map(Vec::len))
            .field("p2c", &self.p2c)
            .field("p2s_len", &self.p2s_len)
            .finish()
    }
}

/// Options of [`jwe_decrypt_compact`](crate::jwe::jwe_decrypt_compact),
/// [`jwe_decrypt_json`](crate::jwe::jwe_decrypt_json) and the nested JWT decrypt operations
/// (ADR 0030 §4, JWE; RFC 7516 §5.2; ADR 0023, ADR 0050).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JweDecryptOptions {
    /// The key management algorithms the caller accepts (RFC 8725 §3.1, ADR 0007). Required: an
    /// empty list fails with `AlgorithmNotAllowed` in the core.
    pub allowed_algs: Vec<String>,
    /// The content encryption algorithms the caller accepts (RFC 8725 §3.1, ADR 0007).
    /// Required: an empty list fails with `AlgorithmNotAllowed` in the core.
    pub allowed_enc: Vec<String>,
    /// The PBES2 budget: the most `p2c` summed over every PBES2 recipient tried in one call
    /// (ADR 0023, ADR 0050 §2). `None`: the core default.
    pub max_pbes2_count: Option<u32>,
    /// The largest decompressed plaintext for `zip: DEF` (ADR 0017). `None`: the core default.
    pub max_decompressed_len: Option<u32>,
    /// The largest serialized JWE accepted, in bytes. `None`: the core default.
    pub max_input_len: Option<u32>,
    /// The most recipients a general JSON JWE may have. `None`: the core default.
    pub max_recipients: Option<u32>,
    /// Extension header names the caller processes itself, accepted in `crit` (RFC 7516
    /// §4.1.13). `None`: none.
    pub understood_crit: Option<Vec<String>>,
}

impl JweDecryptOptions {
    /// Options accepting exactly `allowed_algs` and `allowed_enc`, every other member left to
    /// the core.
    pub fn new(allowed_algs: Vec<String>, allowed_enc: Vec<String>) -> Self {
        Self {
            allowed_algs,
            allowed_enc,
            max_pbes2_count: None,
            max_decompressed_len: None,
            max_input_len: None,
            max_recipients: None,
            understood_crit: None,
        }
    }
}

/// A decrypted JWE (ADR 0030 §4, JWE; RFC 7516 §5.2): the result of
/// [`jwe_decrypt_compact`](crate::jwe::jwe_decrypt_compact) and
/// [`jwe_decrypt_json`](crate::jwe::jwe_decrypt_json).
///
/// **Only [`protected_header`](Self::protected_header) is integrity-protected** (RFC 7516 §5.1
/// steps 14–15). Do not base security decisions (key selection, content typing, trust) on
/// `kid`, `cty`, `jku` or any other member taken from [`header`](Self::header),
/// [`shared_unprotected_header`](Self::shared_unprotected_header) or
/// [`recipient_header`](Self::recipient_header) (ADR 0050 §3).
pub struct JweDecrypted {
    /// The plaintext (RFC 7516 §5.2 step 16), wiped on drop (ADR 0030 §7).
    pub plaintext: SecretBytes,
    /// The JOSE Header used: the union of the protected, shared unprotected and per-recipient
    /// unprotected headers (RFC 7516 §5.2 step 4), as the core serializes it.
    ///
    /// **Not integrity-protected as a whole** (ADR 0050 §3): any member may come from an
    /// unprotected part, which anyone can change in transit.
    pub header: String,
    /// The JWE Protected Header (RFC 7516 §2), if the JWE has one. Integrity-protected: it is
    /// part of the AAD (RFC 7516 §5.1 step 14).
    pub protected_header: Option<String>,
    /// The JWE Shared Unprotected Header (RFC 7516 §7.2.1 `unprotected`), JSON only.
    ///
    /// **Not integrity-protected** (RFC 7516 §7.2.1, ADR 0050 §3).
    pub shared_unprotected_header: Option<String>,
    /// The Per-Recipient Unprotected Header of the recipient that decrypted (RFC 7516 §7.2.1
    /// `header`), JSON only.
    ///
    /// **Not integrity-protected** (RFC 7516 §7.2.1, ADR 0050 §3).
    pub recipient_header: Option<String>,
    /// The JWE AAD (RFC 7516 §7.2.1 `aad`), decoded, JSON only. Wiped on drop: it can carry
    /// application secrets (ADR 0050 §4, ADR 0030 §7).
    pub aad: Option<SecretBytes>,
    /// The index of the recipient that decrypted in `recipients` (RFC 7516 §7.2.1); `0` for
    /// compact and flattened.
    pub recipient_index: u32,
}

/// Redacts the plaintext and the AAD, and prints the headers' lengths only (ADR 0030 §7.5).
impl fmt::Debug for JweDecrypted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JweDecrypted")
            .field("plaintext", &self.plaintext)
            .field("header_len", &self.header.len())
            .field("protected_header_len", &json_len(&self.protected_header))
            .field(
                "shared_unprotected_header_len",
                &json_len(&self.shared_unprotected_header),
            )
            .field("recipient_header_len", &json_len(&self.recipient_header))
            .field("aad", &self.aad)
            .field("recipient_index", &self.recipient_index)
            .finish()
    }
}

// ------------------------------------------------------------------------------------------------
// JWT
// ------------------------------------------------------------------------------------------------

/// Options of [`jwt_sign`](crate::jwt::jwt_sign) (ADR 0030 §4, JWT; RFC 7519 §7.1, RFC 9068
/// §2.1).
///
/// `typ` together with `omit_typ` or `access_token` fails with `InvalidHeader` (ADR 0030 §4).
#[derive(Clone, PartialEq, Eq)]
pub struct JwtSignOptions {
    /// The JWS algorithm, as registered (RFC 7515 §4.1.1, RFC 7518 §3.1).
    pub alg: String,
    /// The JOSE `typ` (RFC 7519 §5.1). `None`: the core default, `JWT`.
    pub typ: Option<String>,
    /// Write no `typ` at all (the core's `IssueOptions::no_typ`). Default `false`.
    pub omit_typ: bool,
    /// Issue an RFC 9068 access token, `typ: at+jwt` (RFC 9068 §2.1; the core's
    /// `IssueOptions::access_token`). Default `false`.
    pub access_token: bool,
    /// Extra JWS Protected Header members as a JSON object, each set through the core's
    /// `IssueOptions::header_param` (RFC 7515 §4).
    pub header: Option<String>,
}

impl JwtSignOptions {
    /// Options signing with `alg`, every other member left to the core.
    pub fn new(alg: String) -> Self {
        Self {
            alg,
            typ: None,
            omit_typ: false,
            access_token: false,
            header: None,
        }
    }
}

/// Prints the extra header's length only.
impl fmt::Debug for JwtSignOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JwtSignOptions")
            .field("alg", &self.alg)
            .field("typ", &self.typ)
            .field("omit_typ", &self.omit_typ)
            .field("access_token", &self.access_token)
            .field("header_len", &json_len(&self.header))
            .finish()
    }
}

/// Options of [`jwt_verify`](crate::jwt::jwt_verify), [`jwt_verify_with_jwks`] and the nested
/// JWT decrypt operations (ADR 0030 §4, JWT; RFC 7519 §7.2, RFC 8725 §3; ADR 0027, ADR 0028,
/// ADR 0029).
///
/// Each member maps to exactly one core `jwt::Policy` call, and `None`/`false` calls nothing, so
/// every default (the leeway, `exp` required, an unconfigured `aud` rejected, the `typ` mode, the
/// key candidate bound) stays in the core (ADR 0030 §4). The members mirror the `jwt.validate`
/// vector `policy` members (0004 T10).
///
/// [`jwt_verify_with_jwks`]: crate::jwt::jwt_verify_with_jwks
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JwtVerifyOptions {
    /// The JWS algorithms the caller accepts (RFC 8725 §3.1, ADR 0007). Required: an empty list
    /// fails with `AlgorithmNotAllowed` in the core.
    pub allowed_algs: Vec<String>,
    /// The time to validate against, whole seconds since the epoch (ADR 0028). `None`: the
    /// platform's wall clock, read as ADR 0030 §4 "The clock" says.
    pub now: Option<i64>,
    /// The accepted issuers, compared exactly (RFC 7519 §4.1.1, RFC 8725 §3.8).
    pub issuers: Option<Vec<String>>,
    /// The accepted audiences (RFC 7519 §4.1.3, RFC 8725 §3.9).
    pub audiences: Option<Vec<String>>,
    /// The required subject (RFC 7519 §4.1.2).
    pub subject: Option<String>,
    /// The clock skew allowed for `exp`, `nbf` and `iat`, in seconds (RFC 7519 §4.1.4–§4.1.6,
    /// ADR 0027 §3). `None`: the core default; the core caps it.
    pub leeway: Option<u32>,
    /// The oldest `iat` accepted, in seconds before `now` (ADR 0027 §3).
    pub max_age: Option<u32>,
    /// Claims that must be present, checked in this order (ADR 0027 §4, §9 step J4).
    pub required_claims: Option<Vec<String>>,
    /// Accept a token without `exp` (ADR 0027 §3). Default `false`: `exp` is required.
    pub allow_missing_exp: bool,
    /// Skip the audience check (ADR 0027 §4). Default `false`.
    pub ignore_audience: bool,
    /// The exact JOSE `typ` required (RFC 8725 §3.11; the core's `Policy::expect_typ`).
    pub typ: Option<String>,
    /// Accept any `typ` (the core's `Policy::any_typ`). Default `false`. Together with `typ`:
    /// `InvalidHeader`.
    pub any_typ: bool,
    /// A validation profile: `access_token` is RFC 9068 §4 (the core's `Policy::access_token`,
    /// with ADR 0052's string `client_id`); any other string fails with `UnsupportedAlgorithm`.
    pub profile: Option<String>,
    /// The most JWK Set members tried (ADR 0029 §4). `None`: the core default.
    pub max_key_candidates: Option<u32>,
    /// The largest token accepted, in bytes (ADR 0026 §7). `None`: the core default.
    pub max_input_len: Option<u32>,
}

impl JwtVerifyOptions {
    /// Options accepting exactly `allowed_algs`, every other member left to the core.
    pub fn new(allowed_algs: Vec<String>) -> Self {
        Self {
            allowed_algs,
            now: None,
            issuers: None,
            audiences: None,
            subject: None,
            leeway: None,
            max_age: None,
            required_claims: None,
            allow_missing_exp: false,
            ignore_audience: false,
            typ: None,
            any_typ: false,
            profile: None,
            max_key_candidates: None,
            max_input_len: None,
        }
    }
}

/// A verified, validated signed JWT (ADR 0030 §4, JWT; RFC 7519 §7.2).
#[derive(Clone, PartialEq, Eq)]
pub struct JwtVerified {
    /// The JWT Claims Set as the core serializes it, registered claims first (ADR 0027 §1), so
    /// NumericDates keep their exact JSON form.
    pub claims: String,
    /// The JWS Protected Header, as the core serializes it (RFC 7519 §5).
    pub header: String,
    /// The `alg` that verified (RFC 7515 §4.1.1).
    pub alg: String,
    /// The index in the JWK Set of the key that verified, for
    /// [`jwt_verify_with_jwks`](crate::jwt::jwt_verify_with_jwks); `None` for a single key
    /// (ADR 0029 §4).
    pub key_index: Option<u32>,
    /// The `kid` of the key that verified, if it has one (RFC 7517 §4.5).
    pub kid: Option<String>,
}

/// Prints the claims' and header's lengths only: claims may carry personal data, which the
/// core's own `Debug` redacts too (ADR 0049 §4).
impl fmt::Debug for JwtVerified {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JwtVerified")
            .field("claims_len", &self.claims.len())
            .field("header_len", &self.header.len())
            .field("alg", &self.alg)
            .field("key_index", &self.key_index)
            .field("kid", &self.kid)
            .finish()
    }
}

/// A verified nested JWT, sign-then-encrypt (ADR 0030 §4, JWT; RFC 7519 §5.2, §11.2;
/// ADR 0027 §7).
#[derive(Clone, PartialEq, Eq)]
pub struct JwtNestedVerified {
    /// The inner signed JWT.
    pub inner: JwtVerified,
    /// The outer JWE's JOSE Header, as the core serializes it (RFC 7516 §5.2 step 4); `cty` is
    /// `JWT` (RFC 7519 §5.2).
    pub outer_header: String,
    /// The index of the JWE recipient that decrypted; `0` for compact (RFC 7516 §7.2.1).
    pub recipient_index: u32,
}

/// Prints the outer header's length only, and the inner JWT through its redacting `Debug`.
impl fmt::Debug for JwtNestedVerified {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JwtNestedVerified")
            .field("inner", &self.inner)
            .field("outer_header_len", &self.outer_header.len())
            .field("recipient_index", &self.recipient_index)
            .finish()
    }
}

/// The length of an optional JSON text, which `Debug` prints in its place.
fn json_len(value: &Option<String>) -> Option<usize> {
    value.as_ref().map(String::len)
}

// ------------------------------------------------------------------------------------------------
// Conversion helpers for the operations (T06–T09)
// ------------------------------------------------------------------------------------------------

// Sizes and counts are u32 in the surface (ADR 0030 §2) and usize in the core; the conversion is
// lossless on every target polyjose builds for.
const _: () = assert!(usize::BITS >= u32::BITS);

/// Calls the core setter `set` on `builder` only when `value` is `Some`; `None` returns the
/// builder untouched, so the core default stands (ADR 0030 §3). Every optional tunable reaches
/// the core through this or [`try_apply`].
#[allow(
    dead_code,
    reason = "used by the operations of feature 0013 T06-T09, which fill jwk/keys/jws/jwe/jwt.rs"
)]
pub(crate) fn apply<B, T>(builder: B, value: Option<T>, set: impl FnOnce(B, T) -> B) -> B {
    match value {
        Some(value) => set(builder, value),
        None => builder,
    }
}

/// [`apply`] for a fallible core setter (for example `Policy::leeway`, which rejects a value
/// above the core's cap).
#[allow(
    dead_code,
    reason = "used by the operations of feature 0013 T06-T09, which fill jwk/keys/jws/jwe/jwt.rs"
)]
pub(crate) fn try_apply<B, T>(
    builder: B,
    value: Option<T>,
    set: impl FnOnce(B, T) -> polyjose::Result<B>,
) -> polyjose::Result<B> {
    match value {
        Some(value) => set(builder, value),
        None => Ok(builder),
    }
}

/// Calls the core switch `set` only when `flag` is `true`; `false` calls nothing (ADR 0030 §4:
/// "`None`/`false` calls nothing").
#[allow(
    dead_code,
    reason = "used by the operations of feature 0013 T06-T09, which fill jwk/keys/jws/jwe/jwt.rs"
)]
pub(crate) fn apply_flag<B>(builder: B, flag: bool, set: impl FnOnce(B) -> B) -> B {
    if flag { set(builder) } else { builder }
}

/// A surface size or count (ADR 0030 §2) as the core's `usize`, losslessly.
#[allow(
    dead_code,
    reason = "used by the operations of feature 0013 T06-T09, which fill jwk/keys/jws/jwe/jwt.rs"
)]
pub(crate) fn to_usize(n: u32) -> usize {
    n as usize
}

/// Algorithm identifiers as the core's algorithm type (`SigningAlg`, `KeyMgmtAlg` or
/// `ContentEncAlg`), in order. A name the core does not know becomes its `Unknown` value, which
/// the core's allow-list check rejects (RFC 8725 §3.1, ADR 0026 §2 step 7): the surface never
/// filters or rejects a name itself.
#[allow(
    dead_code,
    reason = "used by the operations of feature 0013 T06-T09, which fill jwk/keys/jws/jwe/jwt.rs"
)]
pub(crate) fn algs<A: for<'s> From<&'s str>>(names: &[String]) -> Vec<A> {
    names.iter().map(|name| A::from(name.as_str())).collect()
}

/// A list of owned strings as the `&[&str]` the core builders take.
#[allow(
    dead_code,
    reason = "used by the operations of feature 0013 T06-T09, which fill jwk/keys/jws/jwe/jwt.rs"
)]
pub(crate) fn strs(values: &[String]) -> Vec<&str> {
    values.iter().map(String::as_str).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use polyjose::jwa::{ContentEncAlg, KeyMgmtAlg, SigningAlg};
    use polyjose::jwe::{DecryptPolicy, Encryptor, Recipient};
    use polyjose::jwk::Jwk;
    use polyjose::jws::VerifyOptions;
    use polyjose::jwt::{FixedClock, IssueOptions, Policy};

    const MARKER: &str = "pj-SECRET-marker-7f3a";
    /// RFC 7515 Appendix A.1's HMAC key.
    const OCT: &str = r#"{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}"#;

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    // --- None and false pass through untouched (ADR 0030 §3) --------------------------------

    #[test]
    fn jws_verify_options_with_every_tunable_none_leave_the_core_defaults() {
        let opts = JwsVerifyOptions::new(names(&["HS256", "ES256"]));
        assert!(opts.detached_payload.is_none());
        let allowed: Vec<SigningAlg> = algs(&opts.allowed_algs);
        let default = VerifyOptions::new(&allowed).unwrap();

        let mut built = VerifyOptions::new(&allowed).unwrap();
        built = apply(
            built,
            opts.max_input_len.map(to_usize),
            VerifyOptions::max_input_len,
        );
        built = apply(
            built,
            opts.max_signatures.map(to_usize),
            VerifyOptions::max_signatures,
        );
        built = apply(
            built,
            opts.detached_payload.as_ref().map(SecretBytes::as_bytes),
            VerifyOptions::detached_payload,
        );
        assert_eq!(format!("{built:?}"), format!("{default:?}"));
    }

    #[test]
    fn jwe_decrypt_options_with_every_tunable_none_leave_the_core_defaults() {
        let opts = JweDecryptOptions::new(names(&["A128KW", "dir"]), names(&["A256GCM"]));
        let alg: Vec<KeyMgmtAlg> = algs(&opts.allowed_algs);
        let enc: Vec<ContentEncAlg> = algs(&opts.allowed_enc);
        let default = DecryptPolicy::new(&alg, &enc).unwrap();

        let mut built = DecryptPolicy::new(&alg, &enc).unwrap();
        built = apply(built, opts.max_pbes2_count, DecryptPolicy::max_pbes2_count);
        built = apply(
            built,
            opts.max_decompressed_len.map(to_usize),
            DecryptPolicy::max_decompressed_len,
        );
        built = apply(
            built,
            opts.max_input_len.map(to_usize),
            DecryptPolicy::max_input_len,
        );
        built = apply(
            built,
            opts.max_recipients.map(to_usize),
            DecryptPolicy::max_recipients,
        );
        built = apply(built, opts.understood_crit.as_deref(), |p, crit| {
            p.understood_crit(&strs(crit))
        });
        assert_eq!(format!("{built:?}"), format!("{default:?}"));
    }

    #[test]
    fn jwe_encrypt_options_and_recipient_with_every_tunable_none_leave_the_core_defaults() {
        let key = Jwk::from_json(br#"{"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg"}"#).unwrap();
        let recipient = JweRecipient::new("A128KW".to_owned(), SecretString::from(OCT.to_owned()));
        let opts = JweEncryptOptions::new("A128GCM".to_owned(), vec![recipient]);
        let r = &opts.recipients[0];
        assert!(
            opts.protected_header.is_none()
                && opts.shared_unprotected_header.is_none()
                && r.header.is_none()
        );

        let default_recipient = Recipient::new(KeyMgmtAlg::from(r.alg.as_str()), &key);
        let mut built_recipient = Recipient::new(KeyMgmtAlg::from(r.alg.as_str()), &key);
        built_recipient = apply(built_recipient, r.apu.clone(), Recipient::apu);
        built_recipient = apply(built_recipient, r.apv.clone(), Recipient::apv);
        built_recipient = apply(built_recipient, r.p2c, Recipient::p2c);
        built_recipient = apply(built_recipient, r.p2s_len.map(to_usize), Recipient::p2s_len);
        assert_eq!(
            format!("{built_recipient:?}"),
            format!("{default_recipient:?}")
        );

        let enc = ContentEncAlg::from(opts.enc.as_str());
        let default = Encryptor::new(enc.clone());
        let mut built = Encryptor::new(enc);
        built = apply(
            built,
            opts.aad.as_ref().map(|aad| aad.as_bytes().to_vec()),
            Encryptor::aad,
        );
        built = apply_flag(built, opts.compress, Encryptor::compress);
        assert_eq!(format!("{built:?}"), format!("{default:?}"));
    }

    #[test]
    fn jws_sign_options_with_every_tunable_none_have_no_header_and_attach_the_payload() {
        let opts = JwsSignOptions::default();
        assert_eq!(opts.protected_header, None);
        assert_eq!(opts.protected_b64u, None);
        assert!(!opts.detached);

        let signer = JwsSigner::new(SecretString::from(OCT.to_owned()));
        assert!(
            signer.protected_header.is_none()
                && signer.protected_b64u.is_none()
                && signer.unprotected_header.is_none()
        );
    }

    #[test]
    fn jwt_sign_options_with_every_tunable_none_leave_the_core_defaults() {
        let opts = JwtSignOptions::new("HS256".to_owned());
        assert!(opts.header.is_none());
        let alg = SigningAlg::from(opts.alg.as_str());
        let default = IssueOptions::new(alg.clone());

        let mut built = IssueOptions::new(alg);
        built = apply(built, opts.typ.as_deref(), IssueOptions::typ);
        built = apply_flag(built, opts.omit_typ, IssueOptions::no_typ);
        built = apply_flag(built, opts.access_token, IssueOptions::access_token);
        assert_eq!(format!("{built:?}"), format!("{default:?}"));
    }

    #[test]
    fn jwt_verify_options_with_every_tunable_none_leave_the_core_defaults() {
        let opts = JwtVerifyOptions::new(names(&["HS256"]));
        assert_eq!(opts.now, None);
        assert_eq!(opts.profile, None);
        let clock = FixedClock(0);
        let allowed: Vec<SigningAlg> = algs(&opts.allowed_algs);
        let default = Policy::new(&clock, &allowed).unwrap();

        let mut p = Policy::new(&clock, &allowed).unwrap();
        p = apply(p, opts.issuers.as_deref(), |p, v| p.issuers(&strs(v)));
        p = apply(p, opts.audiences.as_deref(), |p, v| p.audiences(&strs(v)));
        p = apply(p, opts.subject.as_deref(), Policy::subject);
        p = try_apply(p, opts.leeway, Policy::leeway).unwrap();
        p = apply(p, opts.max_age, Policy::max_age);
        p = apply(p, opts.required_claims.as_deref(), |p, names| {
            names.iter().fold(p, |p, name| p.require(name))
        });
        p = apply_flag(p, opts.allow_missing_exp, Policy::allow_missing_exp);
        p = apply_flag(p, opts.ignore_audience, Policy::ignore_audience);
        p = apply(p, opts.typ.as_deref(), Policy::expect_typ);
        p = apply_flag(p, opts.any_typ, Policy::any_typ);
        p = apply(
            p,
            opts.max_key_candidates.map(to_usize),
            Policy::max_key_candidates,
        );
        p = apply(p, opts.max_input_len.map(to_usize), Policy::max_input_len);
        assert_eq!(format!("{p:?}"), format!("{default:?}"));
    }

    // --- The helpers ------------------------------------------------------------------------

    #[test]
    fn apply_calls_the_setter_only_for_some() {
        let calls = core::cell::Cell::new(0);
        let set = |b: u32, v: u32| {
            calls.set(calls.get() + 1);
            b + v
        };
        assert_eq!(apply(1, None, set), 1);
        assert_eq!(calls.get(), 0);
        assert_eq!(apply(1, Some(2), set), 3);
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn try_apply_calls_the_setter_only_for_some_and_keeps_its_error() {
        let fail = |_: u32, _: u32| -> polyjose::Result<u32> {
            Err(polyjose::Error::InvalidClaim("leeway"))
        };
        assert_eq!(try_apply(1, None, fail), Ok(1));
        assert_eq!(
            try_apply(1, Some(601), fail),
            Err(polyjose::Error::InvalidClaim("leeway"))
        );
    }

    #[test]
    fn apply_flag_calls_the_switch_only_for_true() {
        assert_eq!(apply_flag(1, false, |b| b + 1), 1);
        assert_eq!(apply_flag(1, true, |b| b + 1), 2);
    }

    #[test]
    fn to_usize_is_lossless() {
        assert_eq!(to_usize(0), 0);
        assert_eq!(to_usize(u32::MAX), 4_294_967_295);
    }

    #[test]
    fn algs_maps_in_order_and_leaves_unknown_names_to_the_core() {
        let parsed: Vec<SigningAlg> = algs(&names(&["ES256", "none", "NOPE"]));
        assert_eq!(parsed[0], SigningAlg::ES256);
        assert_eq!(parsed[1], SigningAlg::None);
        assert!(!parsed[2].is_known());
        // The core, not the surface, rejects what the caller should not allow (RFC 8725 §3.1).
        let err = VerifyOptions::new(&parsed).unwrap_err();
        assert_eq!(err.code(), "AlgorithmNotAllowed");
        let empty: Vec<SigningAlg> = algs(&[]);
        assert_eq!(
            VerifyOptions::new(&empty).unwrap_err().code(),
            "AlgorithmNotAllowed"
        );
    }

    // --- Debug never prints a secret (ADR 0030 §7.5) ----------------------------------------

    fn assert_no_marker<T: fmt::Debug>(value: &T) {
        for rendered in [format!("{value:?}"), format!("{value:#?}")] {
            assert!(!rendered.contains(MARKER), "Debug leaks: {rendered}");
        }
    }

    fn secret_string() -> SecretString {
        SecretString::from(format!(r#"{{"kty":"oct","k":"{MARKER}"}}"#))
    }

    fn secret_bytes() -> SecretBytes {
        SecretBytes::from(MARKER.as_bytes().to_vec())
    }

    fn json() -> Option<String> {
        Some(format!(r#"{{"kid":"{MARKER}"}}"#))
    }

    #[test]
    fn no_record_debug_prints_a_secret_or_a_json_value() {
        assert_no_marker(&JwsSignOptions {
            protected_header: json(),
            protected_b64u: json(),
            detached: false,
        });

        let mut signer = JwsSigner::new(secret_string());
        signer.protected_header = json();
        signer.protected_b64u = json();
        signer.unprotected_header = json();
        assert_no_marker(&signer);

        let mut verify = JwsVerifyOptions::new(names(&["HS256"]));
        verify.detached_payload = Some(secret_bytes());
        assert_no_marker(&verify);

        assert_no_marker(&JwsVerified {
            alg: "HS256".to_owned(),
            payload: secret_bytes(),
            protected_header: json(),
            unprotected_header: json(),
            signature_index: 0,
        });

        let mut recipient = JweRecipient::new("A128KW".to_owned(), secret_string());
        recipient.header = json();
        let mut encrypt = JweEncryptOptions::new("A128GCM".to_owned(), vec![recipient]);
        encrypt.protected_header = json();
        encrypt.shared_unprotected_header = json();
        encrypt.aad = Some(secret_bytes());
        assert_no_marker(&encrypt);

        assert_no_marker(&JweDecrypted {
            plaintext: secret_bytes(),
            header: json().unwrap_or_default(),
            protected_header: json(),
            shared_unprotected_header: json(),
            recipient_header: json(),
            aad: Some(secret_bytes()),
            recipient_index: 0,
        });

        let mut jwt_sign = JwtSignOptions::new("HS256".to_owned());
        jwt_sign.header = json();
        assert_no_marker(&jwt_sign);

        let inner = JwtVerified {
            claims: format!(r#"{{"sub":"{MARKER}"}}"#),
            header: json().unwrap_or_default(),
            alg: "HS256".to_owned(),
            key_index: None,
            kid: None,
        };
        assert_no_marker(&inner);
        assert_no_marker(&JwtNestedVerified {
            inner,
            outer_header: json().unwrap_or_default(),
            recipient_index: 0,
        });
    }
}
