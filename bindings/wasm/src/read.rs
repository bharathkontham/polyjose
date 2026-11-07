//! Plain JS objects to surface records, read with `js_sys::Reflect` (ADR 0031 §3, "Records";
//! 0006 research §4).
//!
//! wasm-bindgen has no record derive without serde (banned: ADR 0016, ADR 0030 §1), and its typed
//! parameters coerce silently (`-1` becomes `4294967295` for a `u32`, a string passed as a list is
//! split into characters; research §4). So every record argument arrives as a `JsValue` and is
//! read here, member by member, with type checks only:
//!
//! - **No logic beyond type checks** (ADR 0030 §1, "the adapter test"). Each reader fills the
//!   surface record with a struct literal, so a field added to the surface fails to compile here
//!   until it is mapped. Unknown members are ignored: the facade passes only fields it validated.
//! - **Absent means `undefined`** (BACKEND.md: the facade leaves absent optional fields out). An
//!   absent optional member is `None`, the core default, and an absent flag is `false`: no default
//!   value is written here (ADR 0030 §3). A missing required member (an allow-list, a key) and any
//!   member of the wrong type, `null` included, is a JS `TypeError`, not a `PolyjoseError`
//!   (ADR 0031 §3). The message names the member, never its value (ADR 0030 §5).
//! - **Integers** are JS numbers that are integral and in range: `0..=2^32-1` for the `u32` sizes
//!   and counts, and a safe integer (`|n| <= 2^53-1`) for JWT `now` (ADR 0030 §2, ADR 0028).
//!   The facade already checked them (BACKEND.md); this is the type check of the conversion.
//! - **Secrets** (ADR 0030 §7.1): a key is read with `JsValue::as_string`, which hands Rust the
//!   only wasm-memory copy (the glue's `passStringToWasm0`, as for a by-value `String` parameter,
//!   research §3), and moved straight into a [`SecretString`]; secret bytes (`detachedPayload`,
//!   `aad`) are copied once out of the `Uint8Array` into a new `Vec<u8>` of exact capacity that
//!   moves straight into a [`SecretBytes`]. A reader that fails half-way drops what it has read,
//!   wiping it. So a record leaves no copy on the Rust heap (regression-tested in
//!   `tests/memory.rs`, a reader that fails after the key included); the wasm shadow stack is not
//!   scrubbed; JWT claims follow ADR 0058. A non-ASCII key string shares the glue's `realloc` edge
//!   (`lib.rs`, "Secrets", review N7).

use js_sys::{Array, Reflect, Uint8Array};
use polyjose_surface::records::{
    JweDecryptOptions, JweEncryptOptions, JweRecipient, JwkSelector, JwsSignOptions, JwsSigner,
    JwsVerifyOptions, JwtSignOptions, JwtVerifyOptions,
};
use polyjose_surface::{SecretBytes, SecretString};
use wasm_bindgen::{JsCast, JsValue};

use crate::error::type_error;

/// A reader's result: the value, or the JS error to throw.
type Read<T> = Result<T, JsValue>;

/// The largest integer a JS number holds exactly, `Number.MAX_SAFE_INTEGER` (ECMA-262, 2^53 - 1).
const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;

/// A record argument: one plain object, as the facade builds it (BACKEND.md, "Records").
struct Record<'a> {
    obj: &'a JsValue,
    name: &'static str,
}

impl<'a> Record<'a> {
    /// `value` must be a non-null, non-array object.
    fn new(value: &'a JsValue, name: &'static str) -> Read<Self> {
        if value.is_object() && !Array::is_array(value) {
            Ok(Self { obj: value, name })
        } else {
            Err(type_error(&format!("`{name}` must be an object")))
        }
    }

    /// The JS `TypeError` for member `key`, expected to be `expected`.
    fn wrong(&self, key: &str, expected: &str) -> JsValue {
        type_error(&format!("`{}.{key}` must be {expected}", self.name))
    }

    /// The member `key`, `None` when it is absent (`undefined`). A throwing getter's exception
    /// propagates unchanged.
    fn get(&self, key: &str) -> Read<Option<JsValue>> {
        let value = Reflect::get(self.obj, &JsValue::from_str(key))?;
        Ok((!value.is_undefined()).then_some(value))
    }

    /// A required member.
    fn need(&self, key: &str, expected: &str) -> Read<JsValue> {
        self.get(key)?.ok_or_else(|| self.wrong(key, expected))
    }

    fn opt_string(&self, key: &str) -> Read<Option<String>> {
        self.get(key)?
            .map(|v| v.as_string().ok_or_else(|| self.wrong(key, "a string")))
            .transpose()
    }

    fn string(&self, key: &str) -> Read<String> {
        self.need(key, "a string")?
            .as_string()
            .ok_or_else(|| self.wrong(key, "a string"))
    }

    /// A secret string (a JWK), owned by a [`SecretString`] from the moment it exists in Rust.
    fn secret_string(&self, key: &str) -> Read<SecretString> {
        self.string(key).map(SecretString::from)
    }

    fn opt_bytes(&self, key: &str) -> Read<Option<Vec<u8>>> {
        self.get(key)?
            .map(|v| {
                v.dyn_ref::<Uint8Array>()
                    .map(Uint8Array::to_vec)
                    .ok_or_else(|| self.wrong(key, "a Uint8Array"))
            })
            .transpose()
    }

    /// Secret octets, owned by a [`SecretBytes`] from the moment they exist in Rust.
    fn opt_secret_bytes(&self, key: &str) -> Read<Option<SecretBytes>> {
        Ok(self.opt_bytes(key)?.map(SecretBytes::from))
    }

    /// A `u32` size or count (ADR 0030 §2).
    fn opt_u32(&self, key: &str) -> Read<Option<u32>> {
        self.get(key)?
            .map(|v| match v.as_f64() {
                Some(n) if n.fract() == 0.0 && (0.0..=f64::from(u32::MAX)).contains(&n) => {
                    Ok(n as u32)
                }
                _ => Err(self.wrong(key, "an integer in 0..=4294967295")),
            })
            .transpose()
    }

    /// Whole seconds since the epoch, a safe integer (ADR 0028, ADR 0030 §2).
    fn opt_safe_i64(&self, key: &str) -> Read<Option<i64>> {
        self.get(key)?
            .map(|v| match v.as_f64() {
                Some(n) if n.fract() == 0.0 && n.abs() <= MAX_SAFE_INTEGER => Ok(n as i64),
                _ => Err(self.wrong(key, "a safe integer")),
            })
            .transpose()
    }

    /// A flag: absent is `false`, the record's own meaning of an absent flag (ADR 0030 §4).
    fn flag(&self, key: &str) -> Read<bool> {
        self.get(key)?
            .map(|v| v.as_bool().ok_or_else(|| self.wrong(key, "a boolean")))
            .transpose()
            .map(Option::unwrap_or_default)
    }

    fn opt_strings(&self, key: &str) -> Read<Option<Vec<String>>> {
        self.get(key)?
            .map(|v| {
                let wrong = || self.wrong(key, "an array of strings");
                v.dyn_ref::<Array>()
                    .ok_or_else(wrong)?
                    .iter()
                    .map(|item| item.as_string().ok_or_else(wrong))
                    .collect()
            })
            .transpose()
    }

    fn strings(&self, key: &str) -> Read<Vec<String>> {
        self.opt_strings(key)?
            .ok_or_else(|| self.wrong(key, "an array of strings"))
    }

    /// A required array of records, each read with `read`.
    fn records<T>(&self, key: &str, read: fn(&JsValue) -> Read<T>) -> Read<Vec<T>> {
        self.need(key, "an array")?
            .dyn_ref::<Array>()
            .ok_or_else(|| self.wrong(key, "an array"))?
            .iter()
            .map(|item| read(&item))
            .collect()
    }
}

/// `{ kid?, alg?, keyUse? }` (RFC 7517 §4.2, §4.4, §4.5; ADR 0030 §4).
pub(crate) fn jwk_selector(value: &JsValue) -> Read<JwkSelector> {
    let r = Record::new(value, "JwkSelector")?;
    Ok(JwkSelector {
        kid: r.opt_string("kid")?,
        alg: r.opt_string("alg")?,
        key_use: r.opt_string("keyUse")?,
    })
}

/// `{ protectedHeader?, protectedB64u?, detached? }` (RFC 7515 §5.1, §7.1, Appendix F).
pub(crate) fn jws_sign_options(value: &JsValue) -> Read<JwsSignOptions> {
    let r = Record::new(value, "JwsSignOptions")?;
    Ok(JwsSignOptions {
        protected_header: r.opt_string("protectedHeader")?,
        protected_b64u: r.opt_string("protectedB64u")?,
        detached: r.flag("detached")?,
    })
}

/// `{ key, protectedHeader?, protectedB64u?, unprotectedHeader? }` (RFC 7515 §7.2.1). The key
/// is secret (ADR 0030 §7).
pub(crate) fn jws_signer(value: &JsValue) -> Read<JwsSigner> {
    let r = Record::new(value, "JwsSigner")?;
    Ok(JwsSigner {
        key: r.secret_string("key")?,
        protected_header: r.opt_string("protectedHeader")?,
        protected_b64u: r.opt_string("protectedB64u")?,
        unprotected_header: r.opt_string("unprotectedHeader")?,
    })
}

/// An array of [`jws_signer`] records (RFC 7515 §7.2.1 `signatures`).
pub(crate) fn jws_signers(value: &JsValue) -> Read<Vec<JwsSigner>> {
    value
        .dyn_ref::<Array>()
        .ok_or_else(|| type_error("`signers` must be an array"))?
        .iter()
        .map(|item| jws_signer(&item))
        .collect()
}

/// `{ allowedAlgs, detachedPayload?, maxInputLen?, maxSignatures? }` (RFC 7515 §5.2,
/// RFC 8725 §3.1, ADR 0026 §7). The detached payload is secret (ADR 0049 §4).
pub(crate) fn jws_verify_options(value: &JsValue) -> Read<JwsVerifyOptions> {
    let r = Record::new(value, "JwsVerifyOptions")?;
    Ok(JwsVerifyOptions {
        allowed_algs: r.strings("allowedAlgs")?,
        detached_payload: r.opt_secret_bytes("detachedPayload")?,
        max_input_len: r.opt_u32("maxInputLen")?,
        max_signatures: r.opt_u32("maxSignatures")?,
    })
}

/// `{ alg, key, header?, apu?, apv?, p2c?, p2sLen? }` (RFC 7516 §7.2.1, RFC 7518 §4.6.1.2,
/// §4.6.1.3, §4.8.1.1, §4.8.1.2). The key is secret (ADR 0030 §7).
pub(crate) fn jwe_recipient(value: &JsValue) -> Read<JweRecipient> {
    let r = Record::new(value, "JweRecipient")?;
    Ok(JweRecipient {
        alg: r.string("alg")?,
        key: r.secret_string("key")?,
        header: r.opt_string("header")?,
        apu: r.opt_bytes("apu")?,
        apv: r.opt_bytes("apv")?,
        p2c: r.opt_u32("p2c")?,
        p2s_len: r.opt_u32("p2sLen")?,
    })
}

/// `{ enc, recipients, protectedHeader?, sharedUnprotectedHeader?, aad?, compress? }`
/// (RFC 7516 §5.1, §7.2.1). The `aad` is secret (ADR 0050 §4).
pub(crate) fn jwe_encrypt_options(value: &JsValue) -> Read<JweEncryptOptions> {
    let r = Record::new(value, "JweEncryptOptions")?;
    Ok(JweEncryptOptions {
        enc: r.string("enc")?,
        recipients: r.records("recipients", jwe_recipient)?,
        protected_header: r.opt_string("protectedHeader")?,
        shared_unprotected_header: r.opt_string("sharedUnprotectedHeader")?,
        aad: r.opt_secret_bytes("aad")?,
        compress: r.flag("compress")?,
    })
}

/// `{ allowedAlgs, allowedEnc, maxPbes2Count?, maxDecompressedLen?, maxInputLen?,
/// maxRecipients?, understoodCrit? }` (RFC 7516 §5.2, RFC 7515 §4.1.11, RFC 8725 §3.1,
/// ADR 0023).
pub(crate) fn jwe_decrypt_options(value: &JsValue) -> Read<JweDecryptOptions> {
    let r = Record::new(value, "JweDecryptOptions")?;
    Ok(JweDecryptOptions {
        allowed_algs: r.strings("allowedAlgs")?,
        allowed_enc: r.strings("allowedEnc")?,
        max_pbes2_count: r.opt_u32("maxPbes2Count")?,
        max_decompressed_len: r.opt_u32("maxDecompressedLen")?,
        max_input_len: r.opt_u32("maxInputLen")?,
        max_recipients: r.opt_u32("maxRecipients")?,
        understood_crit: r.opt_strings("understoodCrit")?,
    })
}

/// `{ alg, typ?, omitTyp?, accessToken?, header? }` (RFC 7519 §5.1, RFC 9068 §2.1).
pub(crate) fn jwt_sign_options(value: &JsValue) -> Read<JwtSignOptions> {
    let r = Record::new(value, "JwtSignOptions")?;
    Ok(JwtSignOptions {
        alg: r.string("alg")?,
        typ: r.opt_string("typ")?,
        omit_typ: r.flag("omitTyp")?,
        access_token: r.flag("accessToken")?,
        header: r.opt_string("header")?,
    })
}

/// `{ allowedAlgs, now, issuers?, audiences?, subject?, leeway?, maxAge?, requiredClaims?,
/// allowMissingExp?, ignoreAudience?, typ?, anyTyp?, profile?, maxKeyCandidates?,
/// maxInputLen? }` (RFC 7519 §4.1, §7.2; RFC 8725 §3.1; RFC 9068 §4; ADR 0027).
///
/// `now` is passed through as given: the facade always supplies it (ADR 0030 §4, BACKEND.md),
/// and this adapter never reads a clock. Absent, it stays `None`, which the surface answers with
/// `InvalidClaim("clock")` on `wasm32-unknown-unknown` (ADR 0028 §1).
pub(crate) fn jwt_verify_options(value: &JsValue) -> Read<JwtVerifyOptions> {
    let r = Record::new(value, "JwtVerifyOptions")?;
    Ok(JwtVerifyOptions {
        allowed_algs: r.strings("allowedAlgs")?,
        now: r.opt_safe_i64("now")?,
        issuers: r.opt_strings("issuers")?,
        audiences: r.opt_strings("audiences")?,
        subject: r.opt_string("subject")?,
        leeway: r.opt_u32("leeway")?,
        max_age: r.opt_u32("maxAge")?,
        required_claims: r.opt_strings("requiredClaims")?,
        allow_missing_exp: r.flag("allowMissingExp")?,
        ignore_audience: r.flag("ignoreAudience")?,
        typ: r.opt_string("typ")?,
        any_typ: r.flag("anyTyp")?,
        profile: r.opt_string("profile")?,
        max_key_candidates: r.opt_u32("maxKeyCandidates")?,
        max_input_len: r.opt_u32("maxInputLen")?,
    })
}
