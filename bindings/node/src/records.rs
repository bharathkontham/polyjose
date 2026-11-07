//! napi-rs mirrors of every surface record (ADR 0030 §3, §4), with `From` conversions and no other
//! logic (ADR 0030 §1, "the adapter test").
//!
//! - **Names.** JS sees `camelCase` fields (`allowedAlgs`, `keyUse`, `maxPbes2Count`), exactly as
//!   `bindings/js/BACKEND.md` lists them. napi-rs splits names at digits (`protectedB64U`), so
//!   the fields holding a digit carry an explicit `js_name`.
//! - **Inputs** (`object_to_js = false`) are read on the JS thread and converted at once, in the
//!   `#[napi]` function, into the surface record that the task owns. Two ways:
//!   - the records that hold bytes, or that follow a byte argument (`JwsSignOptions`,
//!     `JwsSigner`, `JwsVerifyOptions`, `JweRecipient`, `JweEncryptOptions`), are declared here
//!     for their TypeScript type only (`object_from_js = false`): the function takes them as a
//!     plain [`Object`], whose conversion runs no JS, and reads them field by field with
//!     [`Object::get`] (their `read` functions). Every reading of a property can run a JS getter,
//!     which could detach and free a byte argument napi has already captured as a view, so the
//!     function copies its byte argument first, and each reader copies each byte field as soon
//!     as napi hands it over, before the next property is read (review-security.md L1). Absent
//!     and `null` fields behave as napi-derive's conversion does;
//!   - the other records (`JwkSelector`, `JweDecryptOptions`, `JwtSignOptions`,
//!     `JwtVerifyOptions`) hold no bytes and follow no byte argument; napi-derive converts them.
//!
//!   In both:
//!   - a secret key `String` (`JwsSigner::key`, `JweRecipient::key`) is *moved* into a
//!     [`SecretString`] as it is read, so napi's single Rust-heap copy is the zeroizing one
//!     (ADR 0030 §7.1). It is read last, and `JweEncryptOptions::recipients`, which holds those
//!     keys, is read last too, so no other field of its record is read after a key exists; it is
//!     also declared last, so `binding.d.ts` lists it last (review-code.md N1);
//!   - borrowed JS bytes (`detachedPayload`, `aad`, `apu`, `apv`) are copied out of the
//!     `Uint8ArraySlice` while the call still runs, the secret ones (`detachedPayload`, `aad`)
//!     into a [`SecretBytes`], so `compute` never reads JS memory (0007 research §4);
//!   - an absent optional field is `None` and reaches the surface as `None`, which calls no core
//!     setter (ADR 0030 §3). An absent boolean flag (`detached`, `compress`, `omitTyp`, …) is the
//!     flag not set, `false`, which likewise calls no core setter: the surface's own reading of
//!     ADR 0030 §3, and the same as UniFFI's `default = false` (`bindings/ffi`).
//! - **Outputs** (`object_from_js = false`) are built on the JS thread in `resolve`
//!   (`ToJs`); secret bytes (`payload`, `plaintext`, `aad`) are copied into new JS memory from
//!   the surface's borrowed, zeroizing buffer, which is wiped when the surface record drops
//!   (ADR 0030 §7.2). Optional fields that are `None` are left out of the JS object.
//! - **String outputs** (headers, `alg`, `kid`, JWT claims) are `JsString`s, `string` in JS. Each
//!   surface string is first moved into a `Zeroizing` owner, all of them before the first
//!   conversion, and V8 copies it from the borrow; so every Rust copy is wiped, also when a later
//!   conversion fails (review-code.md SF-6). JWT claims stay outside ADR 0030 §7's secret
//!   classification (ADR 0058, owner decision 2); wiping the adapter's own copy changes no API.
//! - **Not logged:** none of these records implements `Debug` (ADR 0030 §7.5).

use napi::bindgen_prelude::{Array, FromNapiValue, Object, Uint8ArraySlice};
use napi::{Env, JsString};
use napi_derive::napi;
use polyjose_surface::records as surface;
use polyjose_surface::{SecretBytes, SecretString};
use zeroize::Zeroizing;

use crate::task::ToJs;

/// A required field of a record read by hand, with napi-derive's error when it is absent
/// (`Missing field`, `InvalidArg`).
fn required<T: FromNapiValue>(obj: &Object<'_>, field: &str) -> napi::Result<T> {
    obj.get::<T>(field)?
        .ok_or_else(|| napi::missing_field_error(field))
}

/// An optional byte field, copied out of JS memory in the same statement that reads it: no JS
/// can run between napi capturing the view and this copy (review-security.md L1).
fn copied_bytes(obj: &Object<'_>, field: &str) -> napi::Result<Option<Vec<u8>>> {
    Ok(obj
        .get::<Uint8ArraySlice<'_>>(field)?
        .map(|view| view.to_vec()))
}

/// The objects of a JS array, read in order, with napi's `Vec<T>` conversion error for a missing
/// element.
fn objects<'env>(array: &Array<'env>) -> napi::Result<Vec<Object<'env>>> {
    (0..array.len())
        .map(|i| {
            array.get::<Object<'env>>(i)?.ok_or_else(|| {
                napi::Error::new(
                    napi::Status::InvalidArg,
                    "Found inconsistent data type in Array<T> when converting to Rust Vec<T>",
                )
            })
        })
        .collect()
}

/// A JS string copied from the borrow of a zeroizing owner (ADR 0030 §7.2, review-code.md SF-6).
fn js_string<'env>(env: &'env Env, value: &Zeroizing<String>) -> napi::Result<JsString<'env>> {
    env.create_string(value.as_str())
}

/// [`js_string`] of an optional string; `None` stays `None` (left out of the JS object).
fn js_string_opt<'env>(
    env: &'env Env,
    value: Option<&Zeroizing<String>>,
) -> napi::Result<Option<JsString<'env>>> {
    value.map(|value| js_string(env, value)).transpose()
}

// ------------------------------------------------------------------------------------------------
// JWK
// ------------------------------------------------------------------------------------------------

/// Which member of a JWK Set `jwksSelect` picks; an absent member places no constraint
/// (RFC 7517 §4.2, §4.4, §4.5, §5).
#[napi(object, object_to_js = false)]
pub struct JwkSelector {
    /// The JWK `kid` to match exactly (RFC 7517 §4.5).
    pub kid: Option<String>,
    /// The algorithm the key must serve, as registered (RFC 7517 §4.4).
    pub alg: Option<String>,
    /// The JWK `use` to match, `sig` or `enc` (RFC 7517 §4.2). JS: `keyUse`.
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

/// Options of `jwsSignCompact` (RFC 7515 §5.1, §7.1). Exactly one of `protectedHeader` and
/// `protectedB64u`; both or neither reject with `InvalidHeader` (ADR 0030 §4).
#[napi(object, object_to_js = false, object_from_js = false)]
pub struct JwsSignOptions {
    /// The JWS Protected Header as JSON text (RFC 7515 §5.1 step 3).
    pub protected_header: Option<String>,
    /// The JWS Protected Header already base64url-encoded, signed over as given (RFC 7515 §5.1
    /// step 3, Appendix A.1).
    #[napi(js_name = "protectedB64u")]
    pub protected_b64u: Option<String>,
    /// Leave the payload out of the output (RFC 7515 Appendix F). Absent: not detached.
    pub detached: Option<bool>,
}

impl JwsSignOptions {
    /// Reads a JS `JwsSignOptions` into the surface record, field by field (see the module docs).
    pub(crate) fn read(obj: &Object<'_>) -> napi::Result<surface::JwsSignOptions> {
        Ok(surface::JwsSignOptions {
            protected_header: obj.get("protectedHeader")?,
            protected_b64u: obj.get("protectedB64u")?,
            detached: obj.get::<bool>("detached")?.unwrap_or_default(),
        })
    }
}

/// One signature of a JWS JSON Serialization (RFC 7515 §7.2.1): the key and its headers, with
/// the `JwsSignOptions` header rule (ADR 0030 §4). The key is secret (ADR 0030 §7).
#[napi(object, object_to_js = false, object_from_js = false)]
pub struct JwsSigner {
    /// The JWS Protected Header as JSON text (RFC 7515 §7.2.1).
    pub protected_header: Option<String>,
    /// The JWS Protected Header already base64url-encoded (RFC 7515 §7.2.1).
    #[napi(js_name = "protectedB64u")]
    pub protected_b64u: Option<String>,
    /// The JWS Unprotected Header as JSON text (RFC 7515 §7.2.1).
    pub unprotected_header: Option<String>,
    /// The signing JWK as JSON text (RFC 7517 §4). Declared last: see the module docs.
    pub key: String,
}

impl JwsSigner {
    /// Reads a JS `JwsSigner` into the surface record, field by field, the key last and straight
    /// into its zeroizing owner (see the module docs).
    pub(crate) fn read(obj: &Object<'_>) -> napi::Result<surface::JwsSigner> {
        Ok(surface::JwsSigner {
            protected_header: obj.get("protectedHeader")?,
            protected_b64u: obj.get("protectedB64u")?,
            unprotected_header: obj.get("unprotectedHeader")?,
            key: SecretString::from(required::<String>(obj, "key")?),
        })
    }

    /// Reads a JS `JwsSigner[]` in order.
    pub(crate) fn read_all(array: &Array<'_>) -> napi::Result<Vec<surface::JwsSigner>> {
        objects(array)?.iter().map(Self::read).collect()
    }
}

/// Options of `jwsVerifyCompact`/`jwsVerifyJson` (RFC 7515 §5.2, RFC 8725 §3.1). `allowedAlgs`
/// is required (ADR 0007); the limits default in the core (ADR 0026 §7).
#[napi(object, object_to_js = false, object_from_js = false)]
pub struct JwsVerifyOptions<'a> {
    /// The algorithms the caller accepts (RFC 8725 §3.1). Empty rejects with
    /// `AlgorithmNotAllowed`.
    pub allowed_algs: Vec<String>,
    /// The payload of a detached JWS (RFC 7515 Appendix F). Secret (ADR 0030 §7).
    pub detached_payload: Option<Uint8ArraySlice<'a>>,
    /// The longest input accepted, in octets (ADR 0026 §7).
    pub max_input_len: Option<u32>,
    /// The most signatures a JSON Serialization may carry (ADR 0026 §7).
    pub max_signatures: Option<u32>,
}

impl JwsVerifyOptions<'_> {
    /// Reads a JS `JwsVerifyOptions` into the surface record: the secret `detachedPayload` first,
    /// copied at once into its zeroizing owner, then the other fields (see the module docs).
    pub(crate) fn read(obj: &Object<'_>) -> napi::Result<surface::JwsVerifyOptions> {
        let detached_payload = copied_bytes(obj, "detachedPayload")?.map(SecretBytes::from);
        Ok(surface::JwsVerifyOptions {
            detached_payload,
            allowed_algs: required(obj, "allowedAlgs")?,
            max_input_len: obj.get("maxInputLen")?,
            max_signatures: obj.get("maxSignatures")?,
        })
    }
}

/// A verified JWS (RFC 7515 §5.2): the result of `jwsVerifyCompact`/`jwsVerifyJson`.
#[napi(object, object_from_js = false)]
pub struct JwsVerified<'env> {
    /// The algorithm that verified (RFC 7515 §4.1.1).
    pub alg: JsString<'env>,
    /// The payload octets, copied from the surface's zeroizing buffer (ADR 0049 §4).
    pub payload: Uint8ArraySlice<'env>,
    /// The JWS Protected Header as JSON text, when present (RFC 7515 §4).
    pub protected_header: Option<JsString<'env>>,
    /// The JWS Unprotected Header as JSON text, when present; not integrity-protected
    /// (RFC 7515 §7.2.1, ADR 0049 §2).
    pub unprotected_header: Option<JsString<'env>>,
    /// The index of the signature that verified (RFC 7515 §7.2.1).
    pub signature_index: u32,
}

impl<'env> ToJs<'env> for surface::JwsVerified {
    type Js = JwsVerified<'env>;

    fn to_js(self, env: &'env Env) -> napi::Result<JwsVerified<'env>> {
        let alg = Zeroizing::new(self.alg);
        let protected_header = self.protected_header.map(Zeroizing::new);
        let unprotected_header = self.unprotected_header.map(Zeroizing::new);
        Ok(JwsVerified {
            payload: Uint8ArraySlice::copy_from(env, self.payload.as_bytes())?,
            alg: js_string(env, &alg)?,
            protected_header: js_string_opt(env, protected_header.as_ref())?,
            unprotected_header: js_string_opt(env, unprotected_header.as_ref())?,
            signature_index: self.signature_index,
        })
    }
}

// ------------------------------------------------------------------------------------------------
// JWE
// ------------------------------------------------------------------------------------------------

/// One recipient of a JWE (RFC 7516 §7.2.1, RFC 7518 §4). The key is secret (ADR 0030 §7).
#[napi(object, object_to_js = false, object_from_js = false)]
pub struct JweRecipient<'a> {
    /// The key management algorithm, as registered (RFC 7518 §4.1).
    pub alg: String,
    /// The per-recipient JWE Unprotected Header as JSON text (RFC 7516 §7.2.1).
    pub header: Option<String>,
    /// The ECDH-ES `apu` (RFC 7518 §4.6.1.2).
    pub apu: Option<Uint8ArraySlice<'a>>,
    /// The ECDH-ES `apv` (RFC 7518 §4.6.1.3).
    pub apv: Option<Uint8ArraySlice<'a>>,
    /// The PBES2 iteration count (RFC 7518 §4.8.1.2).
    #[napi(js_name = "p2c")]
    pub p2c: Option<u32>,
    /// The PBES2 salt input length, in octets (RFC 7518 §4.8.1.1).
    #[napi(js_name = "p2sLen")]
    pub p2s_len: Option<u32>,
    /// The recipient JWK as JSON text (RFC 7517 §4). Declared last: see the module docs.
    pub key: String,
}

impl JweRecipient<'_> {
    /// Reads a JS `JweRecipient` into the surface record: `apu` and `apv` first, each copied at
    /// once, then the other fields, the key last and straight into its zeroizing owner (see the
    /// module docs).
    pub(crate) fn read(obj: &Object<'_>) -> napi::Result<surface::JweRecipient> {
        let apu = copied_bytes(obj, "apu")?;
        let apv = copied_bytes(obj, "apv")?;
        Ok(surface::JweRecipient {
            apu,
            apv,
            alg: required(obj, "alg")?,
            header: obj.get("header")?,
            p2c: obj.get("p2c")?,
            p2s_len: obj.get("p2sLen")?,
            key: SecretString::from(required::<String>(obj, "key")?),
        })
    }
}

/// Options of `jweEncryptCompact`/`jweEncryptJson`/`jwtEncryptNested` (RFC 7516 §5.1).
#[napi(object, object_to_js = false, object_from_js = false)]
pub struct JweEncryptOptions<'a> {
    /// The content encryption algorithm, as registered (RFC 7518 §5.1).
    pub enc: String,
    /// The JWE Protected Header as JSON text (RFC 7516 §7.2.1).
    pub protected_header: Option<String>,
    /// The JWE Shared Unprotected Header as JSON text (RFC 7516 §7.2.1).
    pub shared_unprotected_header: Option<String>,
    /// The JWE AAD (RFC 7516 §5.1 step 14). Secret (ADR 0050 §4).
    pub aad: Option<Uint8ArraySlice<'a>>,
    /// Compress with DEFLATE before encryption (RFC 7516 §4.1.3). Absent: no compression.
    pub compress: Option<bool>,
    /// The recipients (exactly one for the compact form, RFC 7516 §7.1). They hold the secret
    /// keys, so they are declared last: see the module docs.
    pub recipients: Vec<JweRecipient<'a>>,
}

impl JweEncryptOptions<'_> {
    /// Reads a JS `JweEncryptOptions` into the surface record: the secret `aad` first, copied at
    /// once into its zeroizing owner, then the other fields, and the recipients (which hold the
    /// keys) last, each through [`JweRecipient::read`] (see the module docs).
    pub(crate) fn read(obj: &Object<'_>) -> napi::Result<surface::JweEncryptOptions> {
        let aad = copied_bytes(obj, "aad")?.map(SecretBytes::from);
        Ok(surface::JweEncryptOptions {
            aad,
            enc: required(obj, "enc")?,
            protected_header: obj.get("protectedHeader")?,
            shared_unprotected_header: obj.get("sharedUnprotectedHeader")?,
            compress: obj.get::<bool>("compress")?.unwrap_or_default(),
            recipients: objects(&required::<Array<'_>>(obj, "recipients")?)?
                .iter()
                .map(JweRecipient::read)
                .collect::<napi::Result<_>>()?,
        })
    }
}

/// Options of `jweDecryptCompact`/`jweDecryptJson` and the outer layer of nested JWT decryption
/// (RFC 7516 §5.2, RFC 8725 §3.1). `allowedAlgs` and `allowedEnc` are required (ADR 0007); the
/// limits default in the core (ADR 0023, ADR 0050 §2).
#[napi(object, object_to_js = false)]
pub struct JweDecryptOptions {
    /// The key management algorithms the caller accepts (RFC 8725 §3.1).
    pub allowed_algs: Vec<String>,
    /// The content encryption algorithms the caller accepts (RFC 8725 §3.1).
    pub allowed_enc: Vec<String>,
    /// The PBES2 iteration budget per token (ADR 0050 §2).
    #[napi(js_name = "maxPbes2Count")]
    pub max_pbes2_count: Option<u32>,
    /// The largest decompressed plaintext, in octets (ADR 0017).
    pub max_decompressed_len: Option<u32>,
    /// The longest input accepted, in octets.
    pub max_input_len: Option<u32>,
    /// The most recipients a JSON Serialization may carry.
    pub max_recipients: Option<u32>,
    /// Extra `crit` names the caller understands (RFC 7516 §4.1.13, RFC 7515 §4.1.11).
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

/// A decrypted JWE (RFC 7516 §5.2): the result of `jweDecryptCompact`/`jweDecryptJson`.
#[napi(object, object_from_js = false)]
pub struct JweDecrypted<'env> {
    /// The plaintext, copied from the surface's zeroizing buffer (ADR 0030 §7).
    pub plaintext: Uint8ArraySlice<'env>,
    /// The JOSE Header used (the union of the header members, RFC 7516 §5.2 step 4), as JSON
    /// text. Only its protected members are integrity-protected (ADR 0050 §3).
    pub header: JsString<'env>,
    /// The JWE Protected Header as JSON text, when present (RFC 7516 §7.2.1).
    pub protected_header: Option<JsString<'env>>,
    /// The JWE Shared Unprotected Header as JSON text, when present (RFC 7516 §7.2.1).
    pub shared_unprotected_header: Option<JsString<'env>>,
    /// The recipient's JWE Per-Recipient Unprotected Header as JSON text, when present
    /// (RFC 7516 §7.2.1).
    pub recipient_header: Option<JsString<'env>>,
    /// The JWE AAD, when present, copied from the surface's zeroizing buffer (ADR 0050 §4).
    pub aad: Option<Uint8ArraySlice<'env>>,
    /// The index of the recipient that decrypted (RFC 7516 §7.2.1).
    pub recipient_index: u32,
}

impl<'env> ToJs<'env> for surface::JweDecrypted {
    type Js = JweDecrypted<'env>;

    fn to_js(self, env: &'env Env) -> napi::Result<JweDecrypted<'env>> {
        let header = Zeroizing::new(self.header);
        let protected_header = self.protected_header.map(Zeroizing::new);
        let shared_unprotected_header = self.shared_unprotected_header.map(Zeroizing::new);
        let recipient_header = self.recipient_header.map(Zeroizing::new);
        Ok(JweDecrypted {
            plaintext: Uint8ArraySlice::copy_from(env, self.plaintext.as_bytes())?,
            aad: self
                .aad
                .map(|aad| Uint8ArraySlice::copy_from(env, aad.as_bytes()))
                .transpose()?,
            header: js_string(env, &header)?,
            protected_header: js_string_opt(env, protected_header.as_ref())?,
            shared_unprotected_header: js_string_opt(env, shared_unprotected_header.as_ref())?,
            recipient_header: js_string_opt(env, recipient_header.as_ref())?,
            recipient_index: self.recipient_index,
        })
    }
}

// ------------------------------------------------------------------------------------------------
// JWT
// ------------------------------------------------------------------------------------------------

/// Options of `jwtSign` (RFC 7519 §7.1, RFC 9068 §2.1). `typ` together with `omitTyp` or
/// `accessToken` rejects with `InvalidHeader` (ADR 0030 §4).
#[napi(object, object_to_js = false)]
pub struct JwtSignOptions {
    /// The signing algorithm, as registered (RFC 7518 §3.1).
    pub alg: String,
    /// The `typ` header; absent: the core default `JWT` (RFC 7519 §5.1).
    pub typ: Option<String>,
    /// Write no `typ` header. Absent: not set.
    pub omit_typ: Option<bool>,
    /// Issue an RFC 9068 access token (`typ: at+jwt`, RFC 9068 §2.1). Absent: not set.
    pub access_token: Option<bool>,
    /// Extra JWS Protected Header members as a JSON object text (RFC 7515 §4).
    pub header: Option<String>,
}

impl From<JwtSignOptions> for surface::JwtSignOptions {
    fn from(v: JwtSignOptions) -> Self {
        Self {
            alg: v.alg,
            typ: v.typ,
            omit_typ: v.omit_typ.unwrap_or_default(),
            access_token: v.access_token.unwrap_or_default(),
            header: v.header,
        }
    }
}

/// Options of the JWT verify operations (RFC 7519 §7.2, RFC 8725 §3, RFC 9068 §4). Each field
/// maps to one core `Policy` method, and an absent one calls nothing (ADR 0030 §4, ADR 0027).
/// The facade always passes `now` (ADR 0028 §4); an absent one reaches the surface as `None`.
#[napi(object, object_to_js = false)]
pub struct JwtVerifyOptions {
    /// The algorithms the caller accepts (RFC 8725 §3.1).
    pub allowed_algs: Vec<String>,
    /// The verification time, whole seconds since the epoch (RFC 7519 §2, ADR 0028).
    pub now: Option<i64>,
    /// The accepted `iss` values (RFC 7519 §4.1.1).
    pub issuers: Option<Vec<String>>,
    /// The accepted `aud` values (RFC 7519 §4.1.3).
    pub audiences: Option<Vec<String>>,
    /// The required `sub` (RFC 7519 §4.1.2).
    pub subject: Option<String>,
    /// Clock skew allowance in seconds (RFC 7519 §4.1.4, §4.1.5).
    pub leeway: Option<u32>,
    /// The oldest `iat` accepted, in seconds (RFC 7519 §4.1.6).
    pub max_age: Option<u32>,
    /// Claims that must be present (RFC 7519 §4).
    pub required_claims: Option<Vec<String>>,
    /// Accept a token without `exp` (RFC 7519 §4.1.4). Absent: not set.
    pub allow_missing_exp: Option<bool>,
    /// Do not check `aud` (RFC 7519 §4.1.3). Absent: not set.
    pub ignore_audience: Option<bool>,
    /// The expected `typ` header (RFC 8725 §3.11).
    pub typ: Option<String>,
    /// Accept any `typ` (RFC 8725 §3.11). Absent: not set.
    pub any_typ: Option<bool>,
    /// A validation profile, `access_token` (RFC 9068 §4).
    pub profile: Option<String>,
    /// The most JWK Set members tried (ADR 0029).
    pub max_key_candidates: Option<u32>,
    /// The longest token accepted, in octets.
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
            allow_missing_exp: v.allow_missing_exp.unwrap_or_default(),
            ignore_audience: v.ignore_audience.unwrap_or_default(),
            typ: v.typ,
            any_typ: v.any_typ.unwrap_or_default(),
            profile: v.profile,
            max_key_candidates: v.max_key_candidates,
            max_input_len: v.max_input_len,
        }
    }
}

/// A verified JWT (RFC 7519 §7.2): the result of `jwtVerify`/`jwtVerifyWithJwks`.
#[napi(object, object_from_js = false)]
pub struct JwtVerified<'env> {
    /// The claims as the core's JSON serialization (ADR 0027 §1). Plain in the API (ADR 0058,
    /// owner decision 2); the adapter's copy is wiped all the same (see the module docs).
    pub claims: JsString<'env>,
    /// The JOSE Header as JSON text (RFC 7519 §5).
    pub header: JsString<'env>,
    /// The algorithm that verified (RFC 7515 §4.1.1).
    pub alg: JsString<'env>,
    /// The index of the JWK Set member that verified, for a set (ADR 0029).
    pub key_index: Option<u32>,
    /// The `kid` of the key that verified, when it has one (RFC 7517 §4.5).
    pub kid: Option<JsString<'env>>,
}

impl<'env> ToJs<'env> for surface::JwtVerified {
    type Js = JwtVerified<'env>;

    fn to_js(self, env: &'env Env) -> napi::Result<JwtVerified<'env>> {
        let claims = Zeroizing::new(self.claims);
        let header = Zeroizing::new(self.header);
        let alg = Zeroizing::new(self.alg);
        let kid = self.kid.map(Zeroizing::new);
        Ok(JwtVerified {
            claims: js_string(env, &claims)?,
            header: js_string(env, &header)?,
            alg: js_string(env, &alg)?,
            key_index: self.key_index,
            kid: js_string_opt(env, kid.as_ref())?,
        })
    }
}

/// A verified nested JWT (RFC 7519 §5.2, §7.2 step 8): the result of `jwtDecryptNested` and
/// `jwtDecryptNestedWithJwks`.
#[napi(object, object_from_js = false)]
pub struct JwtNestedVerified<'env> {
    /// The inner, signed JWT.
    pub inner: JwtVerified<'env>,
    /// The outer JWE's JOSE Header as JSON text (RFC 7516 §5.2).
    pub outer_header: JsString<'env>,
    /// The index of the JWE recipient that decrypted (RFC 7516 §7.2.1).
    pub recipient_index: u32,
}

impl<'env> ToJs<'env> for surface::JwtNestedVerified {
    type Js = JwtNestedVerified<'env>;

    fn to_js(self, env: &'env Env) -> napi::Result<JwtNestedVerified<'env>> {
        // Moved into its owner before the inner record converts, so it is wiped if that fails.
        let outer_header = Zeroizing::new(self.outer_header);
        Ok(JwtNestedVerified {
            inner: self.inner.to_js(env)?,
            outer_header: js_string(env, &outer_header)?,
            recipient_index: self.recipient_index,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_options_reach_the_surface_as_none_and_false() {
        // The records read by hand (JwsSignOptions, JwsSigner, JwsVerifyOptions, JweRecipient,
        // JweEncryptOptions) need a JS object; test/backend.test.ts covers their fields.
        let decrypt = surface::JweDecryptOptions::from(JweDecryptOptions {
            allowed_algs: vec!["dir".into()],
            allowed_enc: vec!["A128GCM".into()],
            max_pbes2_count: None,
            max_decompressed_len: None,
            max_input_len: None,
            max_recipients: None,
            understood_crit: None,
        });
        assert_eq!(
            decrypt,
            surface::JweDecryptOptions::new(vec!["dir".into()], vec!["A128GCM".into()])
        );

        let jwt_sign = surface::JwtSignOptions::from(JwtSignOptions {
            alg: "HS256".into(),
            typ: None,
            omit_typ: None,
            access_token: None,
            header: None,
        });
        assert_eq!(jwt_sign, surface::JwtSignOptions::new("HS256".into()));

        let verify = surface::JwtVerifyOptions::from(JwtVerifyOptions {
            allowed_algs: vec!["HS256".into()],
            now: None,
            issuers: None,
            audiences: None,
            subject: None,
            leeway: None,
            max_age: None,
            required_claims: None,
            allow_missing_exp: None,
            ignore_audience: None,
            typ: None,
            any_typ: None,
            profile: None,
            max_key_candidates: None,
            max_input_len: None,
        });
        assert_eq!(verify, surface::JwtVerifyOptions::new(vec!["HS256".into()]));
    }

    #[test]
    fn every_field_passes_through_unchanged() {
        let verify = surface::JwtVerifyOptions::from(JwtVerifyOptions {
            allowed_algs: vec!["ES256".into()],
            now: Some(1_700_000_000),
            issuers: Some(vec!["iss".into()]),
            audiences: Some(vec!["aud".into()]),
            subject: Some("sub".into()),
            leeway: Some(5),
            max_age: Some(60),
            required_claims: Some(vec!["jti".into()]),
            allow_missing_exp: Some(true),
            ignore_audience: Some(true),
            typ: Some("JWT".into()),
            any_typ: Some(true),
            profile: Some("access_token".into()),
            max_key_candidates: Some(2),
            max_input_len: Some(4096),
        });
        assert_eq!(
            verify,
            surface::JwtVerifyOptions {
                allowed_algs: vec!["ES256".into()],
                now: Some(1_700_000_000),
                issuers: Some(vec!["iss".into()]),
                audiences: Some(vec!["aud".into()]),
                subject: Some("sub".into()),
                leeway: Some(5),
                max_age: Some(60),
                required_claims: Some(vec!["jti".into()]),
                allow_missing_exp: true,
                ignore_audience: true,
                typ: Some("JWT".into()),
                any_typ: true,
                profile: Some("access_token".into()),
                max_key_candidates: Some(2),
                max_input_len: Some(4096),
            }
        );

        let selector = surface::JwkSelector::from(JwkSelector {
            kid: Some("k1".into()),
            alg: Some("ES256".into()),
            key_use: Some("sig".into()),
        });
        assert_eq!(selector.key_use.as_deref(), Some("sig"));
        assert_eq!(selector.kid.as_deref(), Some("k1"));
    }
}
