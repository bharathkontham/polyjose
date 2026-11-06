//! The JOSE Header: registered Header Parameters (RFC 7515 §4.1,
//! RFC 7516 §4.1, RFC 7518 §4.6.1/§4.7.1/§4.8.1, RFC 7797 §3) plus any
//! Public or Private Header Parameters (RFC 7515 §4.2–§4.3).
//!
//! [`Header::from_json`][from_json] reads a header from untrusted bytes
//! through polyjose's own JSON parser ([`crate::json`], ADR 0016).
//!
//! # What parsing checks
//!
//! - The input is a UTF-8 encoded, completely valid I-JSON object
//!   (RFC 7515 §5.2 step 3, RFC 7516 §5.2 step 3, RFC 7493), else
//!   [`Error::InvalidJson`].
//! - No member name occurs twice, in the header or in any nested object,
//!   compared after unescaping (RFC 7515 §4 and §5.2 step 4, RFC 7516 §4
//!   and §5.2 step 4). The JSON parser rejects duplicates with
//!   [`Error::InvalidJson`] rather than keeping the last value, which would
//!   let two implementations read different values from one header
//!   (RFC 7515 §10.12). Nested objects are included: `jwk` and `epk` are
//!   JWKs, whose parsers may reject duplicates too (RFC 7517 §4).
//! - Each registered parameter has its registered JSON type, else
//!   [`Error::InvalidHeader`].
//! - `crit`, if present, is a non-empty list of distinct names, none of
//!   them defined by JWS, JWE or JWA (RFC 7515 §4.1.11, RFC 7516 §4.1.13),
//!   else [`Error::InvalidHeader`].
//!
//! # What parsing does not check
//!
//! - That the names in `crit` are present and understood: that depends on
//!   the complete JOSE Header and on the recipient. Call
//!   [`Header::validate_crit_understood`][crit] once the header is complete.
//! - That `alg` (or `enc`) is present: in the JSON serializations a
//!   parameter may live in another header object (RFC 7515 §7.2.1,
//!   RFC 7516 §7.2.1). Use [`Header::signing_alg`][signing_alg],
//!   [`Header::key_mgmt_alg`][key_mgmt_alg] and
//!   [`Header::content_enc_alg`][content_enc_alg] on the complete JOSE
//!   Header.
//! - base64url members (`apu`, `apv`, `iv`, `tag`, `p2s`, `x5t`, …) are
//!   kept as their encoded strings; decoding belongs to the algorithm that
//!   uses them.
//! - `jwk` and `epk` are kept as raw JSON objects; they become typed keys
//!   (and are validated) where they are used. They are never used to
//!   select the verification key (ADR 0026 §2).
//!
//! [from_json]: crate::header::Header::from_json
//! [crit]: crate::header::Header::validate_crit_understood
//! [signing_alg]: crate::header::Header::signing_alg
//! [key_mgmt_alg]: crate::header::Header::key_mgmt_alg
//! [content_enc_alg]: crate::header::Header::content_enc_alg

use std::collections::BTreeSet;

use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::json::{self, Number, Object, Value};
use crate::jwa::{ContentEncAlg, KeyMgmtAlg, SigningAlg};

/// Detail for input that is valid JSON but not a JSON object.
const NOT_AN_OBJECT: &str = "expected a JSON object";

/// A JOSE Header (RFC 7515 §4, RFC 7516 §4).
///
/// Registered parameters are typed fields; every other member is kept,
/// unchanged and in order, in [`Header::other_params`]. Parsing then
/// serializing a header yields an equal JSON object. The registered
/// parameters come first in a fixed order, so the bytes may differ from
/// the input; signatures cover the original encoded bytes, never a
/// re-serialization (RFC 7515 §5.1–§5.2).
///
/// ```
/// use polyjose::header::Header;
/// use polyjose::json::Value;
/// use polyjose::jwa::SigningAlg;
///
/// let h = Header::from_json(br#"{"alg":"HS256","typ":"JWT","x-tenant":"a"}"#)?;
/// assert_eq!(h.signing_alg()?, SigningAlg::HS256);
/// assert_eq!(h.typ.as_deref(), Some("JWT"));
/// assert_eq!(h.other_params().get("x-tenant").and_then(Value::as_str), Some("a"));
/// assert_eq!(h.to_json()?, r#"{"alg":"HS256","typ":"JWT","x-tenant":"a"}"#);
/// # Ok::<(), polyjose::Error>(())
/// ```
///
/// # Debug
///
/// `Debug` never prints key material, following the same split as a
/// [`Jwk`](crate::jwk::Jwk)'s `Debug`:
///
/// - `jwk`, `epk` and [`other_params`](Header::other_params) are JSON
///   objects and print through [`Object`]'s redacting `Debug`: member names
///   and structure show, every string prints as `"<redacted>"`. A `jwk` or
///   `epk` should be a public key (RFC 7515 §4.1.3, RFC 7516 §4.1.5,
///   RFC 7518 §4.6.1.1), but a sender may wrongly include a private member
///   such as `d` or `k` (RFC 7517 §4, RFC 7518 §6), and a Private Header
///   Parameter (RFC 7515 §4.3) can hold anything.
/// - The typed registered parameters (`alg`, `kid`, `typ`, `p2s`, `iv`,
///   `x5c`, …) print in full. None is secret: every header parameter
///   travels in the clear: base64url-encoded or as plain JSON, integrity
///   protected at most, never encrypted (RFC 7515 §3.1 and §7.2.1,
///   RFC 7516 §2 and §3.1), and they are what a reader needs to
///   diagnose a failure. They may be attacker-chosen; `Debug` escapes
///   control characters, so they cannot forge log lines.
#[derive(Debug, Clone, Default, PartialEq)]
#[non_exhaustive]
pub struct Header {
    /// `alg`: the JWS signature/MAC algorithm (RFC 7515 §4.1.1) or the JWE
    /// key management algorithm (RFC 7516 §4.1.1).
    ///
    /// Kept as the raw string because the two families share this member;
    /// read it with [`Header::signing_alg`] or [`Header::key_mgmt_alg`].
    pub alg: Option<String>,
    /// `enc`: the JWE content encryption algorithm (RFC 7516 §4.1.2).
    pub enc: Option<ContentEncAlg>,
    /// `zip`: the JWE compression algorithm (RFC 7516 §4.1.3).
    pub zip: Option<String>,
    /// `jku`: JWK Set URL (RFC 7515 §4.1.2, RFC 7516 §4.1.4).
    pub jku: Option<String>,
    /// `jwk`: the public key, as a raw JSON object (RFC 7515 §4.1.3,
    /// RFC 7516 §4.1.5).
    pub jwk: Option<Object>,
    /// `kid`: Key ID (RFC 7515 §4.1.4, RFC 7516 §4.1.6).
    pub kid: Option<String>,
    /// `x5u`: X.509 URL (RFC 7515 §4.1.5, RFC 7516 §4.1.7).
    pub x5u: Option<String>,
    /// `x5c`: X.509 certificate chain, base64 (not base64url) DER values
    /// (RFC 7515 §4.1.6, RFC 7516 §4.1.8).
    pub x5c: Option<Vec<String>>,
    /// `x5t`: base64url SHA-1 certificate thumbprint (RFC 7515 §4.1.7,
    /// RFC 7516 §4.1.9). Carried, never computed or checked (ADR 0022).
    pub x5t: Option<String>,
    /// `x5t#S256`: base64url SHA-256 certificate thumbprint
    /// (RFC 7515 §4.1.8, RFC 7516 §4.1.10).
    pub x5t_s256: Option<String>,
    /// `typ`: media type of the complete JWS/JWE (RFC 7515 §4.1.9,
    /// RFC 7516 §4.1.11).
    pub typ: Option<String>,
    /// `cty`: media type of the secured content (RFC 7515 §4.1.10,
    /// RFC 7516 §4.1.12).
    pub cty: Option<String>,
    /// `crit`: extension parameters that must be understood
    /// (RFC 7515 §4.1.11, RFC 7516 §4.1.13).
    pub crit: Option<Vec<String>>,
    /// `epk`: ECDH-ES ephemeral public key, as a raw JSON object
    /// (RFC 7518 §4.6.1.1).
    pub epk: Option<Object>,
    /// `apu`: base64url Agreement PartyUInfo (RFC 7518 §4.6.1.2).
    pub apu: Option<String>,
    /// `apv`: base64url Agreement PartyVInfo (RFC 7518 §4.6.1.3).
    pub apv: Option<String>,
    /// `iv`: base64url AES-GCM key wrap IV (RFC 7518 §4.7.1.1).
    pub iv: Option<String>,
    /// `tag`: base64url AES-GCM key wrap authentication tag
    /// (RFC 7518 §4.7.1.2).
    pub tag: Option<String>,
    /// `p2s`: base64url PBES2 salt input (RFC 7518 §4.8.1.1).
    pub p2s: Option<String>,
    /// `p2c`: PBES2 iteration count, a positive integer (RFC 7518 §4.8.1.2).
    ///
    /// JSON has one number type (RFC 8259 §6), so `1000` and `1000.0` are
    /// the same integer. Values above 2^53 − 1 are not exact in I-JSON
    /// (RFC 7493 §2.2) and are rejected. Only the type is checked here; the
    /// JWE layer enforces the upper bound (ADR 0007, ADR 0023).
    pub p2c: Option<u64>,
    /// `b64`: whether the JWS payload is base64url-encoded (RFC 7797 §3).
    pub b64: Option<bool>,
    /// All other (Public or Private, RFC 7515 §4.2–§4.3) parameters, in
    /// order.
    ///
    /// Private so that it can never hold a name that is also a field above,
    /// which would serialize as a duplicate member.
    other: Object,
}

/// Every parameter name modelled as a [`Header`] field, in serialization
/// order.
const FIELD_NAMES: &[&str] = &[
    "alg", "enc", "zip", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256", "typ", "cty",
    "crit", "epk", "apu", "apv", "iv", "tag", "p2s", "p2c", "b64",
];

impl Header {
    /// An empty header.
    pub fn new() -> Self {
        Self::default()
    }

    /// Parses a JOSE Header from its UTF-8 JSON bytes (for example the
    /// base64url-decoded JWS Protected Header, RFC 7515 §5.2 step 3).
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidJson`] if the bytes are not a UTF-8 encoded,
    ///   completely valid I-JSON object (RFC 7515 §5.2 step 3), including
    ///   when a member name occurs twice in any object, at any depth
    ///   (RFC 7515 §4, §5.2 step 4; RFC 7516 §4, §5.2 step 4), or the
    ///   [`json::Limits`] are exceeded.
    /// - [`Error::InvalidHeader`] if a registered parameter has the wrong
    ///   type or `crit` is malformed (RFC 7515 §4.1.11, RFC 7516 §4.1.13).
    ///
    /// No error contains any part of the input.
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let object = json::parse(bytes)?
            .into_object()
            .ok_or(Error::InvalidJson(NOT_AN_OBJECT))?;
        Self::from_object(object)
    }

    /// Builds a header from an already-parsed JSON object (whose names the
    /// parser has made unique), checking the type of every registered
    /// parameter and the shape of `crit`.
    ///
    /// Linear in the number of members, whatever their names.
    pub(crate) fn from_object(object: Object) -> Result<Self> {
        let mut h = Self::default();
        let mut other = Vec::new();
        for (name, value) in object {
            match name.as_str() {
                "alg" => h.alg = Some(string(value, "alg must be a string")?),
                "enc" => h.enc = Some(string(value, "enc must be a string")?.into()),
                "zip" => h.zip = Some(string(value, "zip must be a string")?),
                "jku" => h.jku = Some(string(value, "jku must be a string")?),
                "jwk" => h.jwk = Some(object_member(value, "jwk must be a JSON object")?),
                "kid" => h.kid = Some(string(value, "kid must be a string")?),
                "x5u" => h.x5u = Some(string(value, "x5u must be a string")?),
                "x5c" => h.x5c = Some(strings(value, "x5c must be an array of strings")?),
                "x5t" => h.x5t = Some(string(value, "x5t must be a string")?),
                "x5t#S256" => h.x5t_s256 = Some(string(value, "x5t#S256 must be a string")?),
                "typ" => h.typ = Some(string(value, "typ must be a string")?),
                "cty" => h.cty = Some(string(value, "cty must be a string")?),
                "crit" => h.crit = Some(strings(value, "crit must be an array of strings")?),
                "epk" => h.epk = Some(object_member(value, "epk must be a JSON object")?),
                "apu" => h.apu = Some(string(value, "apu must be a string")?),
                "apv" => h.apv = Some(string(value, "apv must be a string")?),
                "iv" => h.iv = Some(string(value, "iv must be a string")?),
                "tag" => h.tag = Some(string(value, "tag must be a string")?),
                "p2s" => h.p2s = Some(string(value, "p2s must be a string")?),
                "p2c" => h.p2c = Some(positive_int(&value, P2C_NOT_POSITIVE)?),
                "b64" => h.b64 = Some(boolean(&value, "b64 must be a boolean")?),
                _ => other.push((name, value)),
            }
        }
        // The names left over were unique in `object` and are not field
        // names, so they are unique among themselves.
        h.other = Object::from_unique_members(other);
        if let Some(crit) = &h.crit {
            check_crit_shape(crit)?;
        }
        Ok(h)
    }

    /// The header as a JSON object: the typed fields in a fixed order
    /// (alg, enc, zip, jku, jwk, kid, x5u, x5c, x5t, x5t#S256, typ, cty,
    /// crit, epk, apu, apv, iv, tag, p2s, p2c, b64), then
    /// [`other_params`](Self::other_params) in their order. Every name
    /// occurs once (RFC 7515 §4).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidHeader`] if `p2c` is set to zero or to more than
    /// 2^53 − 1, which JSON cannot carry as an exact positive integer
    /// (RFC 7518 §4.8.1.2, RFC 7493 §2.2).
    pub fn to_object(&self) -> Result<Object> {
        let mut members: Vec<(Zeroizing<String>, Value)> =
            Vec::with_capacity(FIELD_NAMES.len() + self.other.len());
        let mut push = |name: &str, value: Value| {
            members.push((Zeroizing::new(name.to_owned()), value));
        };
        let str_value = |s: &String| Value::from(s.as_str());
        let strs_value = |v: &Vec<String>| Value::from(v.iter().map(str_value).collect::<Vec<_>>());
        if let Some(v) = &self.alg {
            push("alg", str_value(v));
        }
        if let Some(v) = &self.enc {
            push("enc", Value::from(v.as_str()));
        }
        if let Some(v) = &self.zip {
            push("zip", str_value(v));
        }
        if let Some(v) = &self.jku {
            push("jku", str_value(v));
        }
        if let Some(v) = &self.jwk {
            push("jwk", Value::from(v.clone()));
        }
        if let Some(v) = &self.kid {
            push("kid", str_value(v));
        }
        if let Some(v) = &self.x5u {
            push("x5u", str_value(v));
        }
        if let Some(v) = &self.x5c {
            push("x5c", strs_value(v));
        }
        if let Some(v) = &self.x5t {
            push("x5t", str_value(v));
        }
        if let Some(v) = &self.x5t_s256 {
            push("x5t#S256", str_value(v));
        }
        if let Some(v) = &self.typ {
            push("typ", str_value(v));
        }
        if let Some(v) = &self.cty {
            push("cty", str_value(v));
        }
        if let Some(v) = &self.crit {
            push("crit", strs_value(v));
        }
        if let Some(v) = &self.epk {
            push("epk", Value::from(v.clone()));
        }
        if let Some(v) = &self.apu {
            push("apu", str_value(v));
        }
        if let Some(v) = &self.apv {
            push("apv", str_value(v));
        }
        if let Some(v) = &self.iv {
            push("iv", str_value(v));
        }
        if let Some(v) = &self.tag {
            push("tag", str_value(v));
        }
        if let Some(v) = &self.p2s {
            push("p2s", str_value(v));
        }
        if let Some(v) = self.p2c {
            let n = Number::from_u64(v)
                .filter(|_| v > 0)
                .ok_or(Error::InvalidHeader(P2C_NOT_POSITIVE))?;
            push("p2c", Value::from(n));
        }
        if let Some(v) = self.b64 {
            push("b64", Value::from(v));
        }
        for (name, value) in &self.other {
            push(name, value.clone());
        }
        // Field names are distinct, and `other` never holds one of them.
        Ok(Object::from_unique_members(members))
    }

    /// Serializes the header as compact JSON (see
    /// [`to_object`](Self::to_object) for the member order).
    ///
    /// # Errors
    ///
    /// As for [`to_object`](Self::to_object).
    pub fn to_json(&self) -> Result<String> {
        Ok(self.to_object()?.to_json())
    }

    /// The JWS `alg` (RFC 7515 §4.1.1).
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidHeader`] if `alg` is absent: it MUST be present
    ///   (RFC 7515 §4.1.1).
    /// - [`Error::UnsupportedAlgorithm`] if it is not a known JWS algorithm
    ///   (RFC 7515 §4.1.1: the JWS is then invalid). The value is not echoed.
    ///
    /// A known value, including `none`, still has to pass the caller's
    /// allow-list (RFC 8725 §3.1, ADR 0026 §2 step 7).
    pub fn signing_alg(&self) -> Result<SigningAlg> {
        let alg = SigningAlg::from(self.alg.as_deref().ok_or(MISSING_ALG)?);
        alg.ensure_known()?;
        Ok(alg)
    }

    /// The JWE `alg` (RFC 7516 §4.1.1).
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidHeader`] if `alg` is absent (RFC 7516 §4.1.1).
    /// - [`Error::UnsupportedAlgorithm`] if it is not a JWE key management
    ///   algorithm polyjose implements (RFC 7516 §4.1.1), including
    ///   `RSA-OAEP` (ADR 0022) and `RSA1_5` (ADR 0021).
    pub fn key_mgmt_alg(&self) -> Result<KeyMgmtAlg> {
        let alg = KeyMgmtAlg::from(self.alg.as_deref().ok_or(MISSING_ALG)?);
        alg.ensure_known()?;
        Ok(alg)
    }

    /// The JWE `enc` (RFC 7516 §4.1.2).
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidHeader`] if `enc` is absent (RFC 7516 §4.1.2).
    /// - [`Error::UnsupportedAlgorithm`] if it is not a known content
    ///   encryption algorithm (RFC 7516 §4.1.2).
    pub fn content_enc_alg(&self) -> Result<ContentEncAlg> {
        let enc = self
            .enc
            .as_ref()
            .ok_or(Error::InvalidHeader("missing enc"))?;
        enc.ensure_known()?;
        Ok(enc.clone())
    }

    /// Checks the `crit` rules that do not depend on what the recipient
    /// understands (RFC 7515 §4.1.11, RFC 7516 §4.1.13). An absent `crit`
    /// is valid.
    ///
    /// Call it on the complete JOSE Header: in the JSON serializations that
    /// is the union of the protected and unprotected headers (RFC 7515
    /// §5.2 step 4), since the listed names may occur in any of them. That
    /// `crit` itself occurs only in the protected header is checked by the
    /// JWS/JWE serialization layer, which knows where each member came from
    /// (ADR 0026 §2 step 4).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidHeader`] if `crit`:
    /// - is the empty list,
    /// - lists a name defined by JWS, JWE or JWA (`alg`, `enc`, `kid`, …),
    /// - lists a name twice, or
    /// - lists a name that does not occur in this header.
    pub fn validate_crit(&self) -> Result<()> {
        let Some(crit) = &self.crit else {
            return Ok(());
        };
        check_crit_shape(crit)?;
        // One pass over the other parameters, so a long `crit` list stays
        // O(n log n) rather than O(n * m).
        let other: BTreeSet<&str> = self.other.iter().map(|(name, _)| name).collect();
        let present = |name: &str| {
            if FIELD_NAMES.contains(&name) {
                self.contains(name)
            } else {
                other.contains(name)
            }
        };
        if crit.iter().all(|name| present(name)) {
            Ok(())
        } else {
            Err(Error::InvalidHeader("crit lists an absent parameter"))
        }
    }

    /// [`validate_crit`](Self::validate_crit), then requires every listed
    /// extension to be in `understood` (RFC 7515 §4.1.11, RFC 7516
    /// §4.1.13: otherwise the JWS/JWE is invalid).
    ///
    /// polyjose's JWS layer passes `&["b64"]` (RFC 7797; ADR 0007,
    /// ADR 0026 §2 step 5) and its JWE layer passes `&[]`.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidHeader`] as for [`validate_crit`](Self::validate_crit).
    /// - [`Error::UnknownCritical`] if a listed name is not in `understood`.
    ///   The name is not echoed.
    pub fn validate_crit_understood(&self, understood: &[&str]) -> Result<()> {
        self.validate_crit()?;
        let all_understood = self
            .crit
            .iter()
            .flatten()
            .all(|name| understood.contains(&name.as_str()));
        if all_understood {
            Ok(())
        } else {
            Err(Error::UnknownCritical)
        }
    }

    /// The Public and Private Header Parameters (RFC 7515 §4.2–§4.3): every
    /// member that is not one of the typed fields, in order.
    pub fn other_params(&self) -> &Object {
        &self.other
    }

    /// Sets a Public or Private Header Parameter (RFC 7515 §4.2–§4.3),
    /// returning the previous value. A new name is appended.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidHeader`] if `name` is one of the typed fields (set the
    /// field instead), so a header can never hold the same name twice
    /// (RFC 7515 §4).
    pub fn insert_other(
        &mut self,
        name: impl Into<String>,
        value: impl Into<Value>,
    ) -> Result<Option<Value>> {
        let name = Zeroizing::new(name.into());
        if FIELD_NAMES.contains(&name.as_str()) {
            return Err(Error::InvalidHeader("parameter has a typed field"));
        }
        Ok(self.other.insert(name.as_str(), value))
    }

    /// Removes a Public or Private Header Parameter, returning its value.
    pub fn remove_other(&mut self, name: &str) -> Option<Value> {
        self.other.remove(name)
    }

    /// Whether a parameter named `name` is present, typed field or not.
    pub fn contains(&self, name: &str) -> bool {
        match name {
            "alg" => self.alg.is_some(),
            "enc" => self.enc.is_some(),
            "zip" => self.zip.is_some(),
            "jku" => self.jku.is_some(),
            "jwk" => self.jwk.is_some(),
            "kid" => self.kid.is_some(),
            "x5u" => self.x5u.is_some(),
            "x5c" => self.x5c.is_some(),
            "x5t" => self.x5t.is_some(),
            "x5t#S256" => self.x5t_s256.is_some(),
            "typ" => self.typ.is_some(),
            "cty" => self.cty.is_some(),
            "crit" => self.crit.is_some(),
            "epk" => self.epk.is_some(),
            "apu" => self.apu.is_some(),
            "apv" => self.apv.is_some(),
            "iv" => self.iv.is_some(),
            "tag" => self.tag.is_some(),
            "p2s" => self.p2s.is_some(),
            "p2c" => self.p2c.is_some(),
            "b64" => self.b64.is_some(),
            _ => self.other.contains(name),
        }
    }
}

const MISSING_ALG: Error = Error::InvalidHeader("missing alg");
const P2C_NOT_POSITIVE: &str = "p2c must be a positive integer";

/// Header Parameter names defined by JWS (RFC 7515 §4.1), JWE
/// (RFC 7516 §4.1) and JWA (RFC 7518 §4.6.1, §4.7.1, §4.8.1). `crit` must
/// not list them (RFC 7515 §4.1.11, RFC 7516 §4.1.13).
///
/// The JWS and JWE sets are merged because this header model serves both:
/// a JWS whose `crit` lists a JWE-only name (`enc`, …) is rejected here,
/// where it would otherwise fail anyway as an extension polyjose doesn't
/// understand. `b64` (RFC 7797) is an extension and is not in this list.
const SPEC_DEFINED_NAMES: &[&str] = &[
    "alg", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256", "typ", "cty", "crit", "enc",
    "zip", "epk", "apu", "apv", "iv", "tag", "p2s", "p2c",
];

/// The `crit` rules that hold for any single header object
/// (RFC 7515 §4.1.11, RFC 7516 §4.1.13): non-empty, no JWS/JWE/JWA names,
/// no repeats. O(n log n) in the list length.
fn check_crit_shape(crit: &[String]) -> Result<()> {
    if crit.is_empty() {
        return Err(Error::InvalidHeader("crit must not be empty"));
    }
    let mut seen = BTreeSet::new();
    for name in crit {
        if SPEC_DEFINED_NAMES.contains(&name.as_str()) {
            return Err(Error::InvalidHeader(
                "crit lists a parameter defined by JWS, JWE or JWA",
            ));
        }
        if !seen.insert(name.as_str()) {
            return Err(Error::InvalidHeader("crit lists a name twice"));
        }
    }
    Ok(())
}

/// A JSON string, moved out of its wiped-on-drop buffer without a copy.
fn string(value: Value, detail: &'static str) -> Result<String> {
    match value {
        Value::String(mut s) => Ok(core::mem::take(&mut *s)),
        _ => Err(Error::InvalidHeader(detail)),
    }
}

fn object_member(value: Value, detail: &'static str) -> Result<Object> {
    value.into_object().ok_or(Error::InvalidHeader(detail))
}

fn strings(value: Value, detail: &'static str) -> Result<Vec<String>> {
    match value {
        Value::Array(items) => items.into_iter().map(|v| string(v, detail)).collect(),
        _ => Err(Error::InvalidHeader(detail)),
    }
}

fn boolean(value: &Value, detail: &'static str) -> Result<bool> {
    value.as_bool().ok_or(Error::InvalidHeader(detail))
}

/// A positive JSON integer (RFC 7518 §4.8.1.2), exact under I-JSON
/// (RFC 7493 §2.2): `1000` and `1000.0` qualify, `1.5`, `0`, `-1` and
/// `9007199254740992` (2^53) do not.
fn positive_int(value: &Value, detail: &'static str) -> Result<u64> {
    match value.as_u64() {
        Some(n) if n > 0 => Ok(n),
        _ => Err(Error::InvalidHeader(detail)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64ct::{Base64UrlUnpadded, Encoding};

    fn b64(s: &str) -> Vec<u8> {
        Base64UrlUnpadded::decode_vec(s).unwrap()
    }

    /// Parse, re-serialize and compare as JSON values (member order is
    /// ignored by `Value` equality).
    fn assert_round_trip(bytes: &[u8]) -> Header {
        let h = Header::from_json(bytes).unwrap();
        let original = json::parse(bytes).unwrap();
        let again = json::parse(h.to_json().unwrap().as_bytes()).unwrap();
        assert_eq!(again, original);
        assert_eq!(
            Header::from_json(h.to_json().unwrap().as_bytes()).unwrap(),
            h
        );
        h
    }

    fn assert_invalid_header(input: &[u8]) {
        let err = Header::from_json(input).err();
        assert!(
            matches!(err, Some(Error::InvalidHeader(_))),
            "{:?}: {err:?}",
            String::from_utf8_lossy(input)
        );
    }

    /// `Debug` of a header never prints the strings of `jwk`, `epk` or a
    /// Private Header Parameter (RFC 7515 §4.3), which may hold private key
    /// members (RFC 7517 §4, RFC 7518 §6.2.2.1, §6.4.1), but does print the
    /// registered parameters, which travel in the clear (RFC 7515 §4,
    /// RFC 7516 §4).
    #[test]
    fn debug_redacts_jwk_epk_and_private_parameter_strings() {
        const SECRET: &str = "MARKERsecretMARKERsecretMARKERsecretMARKERs";
        let jwk = format!(r#"{{"kty":"EC","crv":"P-256","x":"AA","y":"AA","d":"{SECRET}"}}"#);
        let epk = format!(r#"{{"kty":"OKP","crv":"X25519","x":"AA","d":"{SECRET}"}}"#);
        let oct = format!(r#"{{"kty":"oct","k":"{SECRET}"}}"#);
        let input = format!(
            r#"{{"alg":"ECDH-ES","enc":"A128GCM","kid":"k1","p2s":"c2FsdA","jwk":{jwk},"epk":{epk},"x-key":{oct},"x-secret":"{SECRET}","x-n":7}}"#
        );
        let h = Header::from_json(input.as_bytes()).unwrap();
        for debug in [format!("{h:?}"), format!("{h:#?}")] {
            assert!(!debug.contains("MARKER"), "{debug}");
            assert!(debug.contains("\"<redacted>\""), "{debug}");
            assert!(debug.contains("\"d\""), "names print: {debug}");
        }
        let debug = format!("{h:?}");
        assert!(debug.contains(r#"alg: Some("ECDH-ES")"#), "{debug}");
        assert!(debug.contains(r#"kid: Some("k1")"#), "{debug}");
        assert!(debug.contains(r#"p2s: Some("c2FsdA")"#), "{debug}");
        assert!(
            debug.contains(r#""x-secret": String("<redacted>")"#),
            "{debug}"
        );
    }

    #[test]
    fn rfc7515_a1_header_parses() {
        // RFC 7515 Appendix A.1.1: {"typ":"JWT",\r\n "alg":"HS256"}
        let bytes = b64("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9");
        let h = assert_round_trip(&bytes);
        assert_eq!(h.typ.as_deref(), Some("JWT"));
        assert_eq!(h.signing_alg().unwrap(), SigningAlg::HS256);
    }

    #[test]
    fn rfc7516_a1_header_parses() {
        // RFC 7516 Appendix A.1.1: {"alg":"RSA-OAEP","enc":"A256GCM"}
        let bytes = b64("eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ");
        let h = assert_round_trip(&bytes);
        assert_eq!(h.alg.as_deref(), Some("RSA-OAEP"));
        assert_eq!(h.content_enc_alg().unwrap(), ContentEncAlg::A256GCM);
        // RSA-OAEP (SHA-1) is not shipped (ADR 0022): it round-trips, but
        // fails as soon as it is used.
        assert_eq!(h.key_mgmt_alg(), Err(Error::UnsupportedAlgorithm));
        assert_eq!(h.to_json().unwrap().as_bytes(), bytes.as_slice());
    }

    #[test]
    fn rsa1_5_header_round_trips_and_is_unsupported() {
        // RSA1_5 is not shipped in either direction (ADR 0021).
        let bytes = br#"{"alg":"RSA1_5","enc":"A128CBC-HS256"}"#;
        let h = assert_round_trip(bytes);
        assert_eq!(h.to_json().unwrap().as_bytes(), bytes);
        assert_eq!(h.key_mgmt_alg(), Err(Error::UnsupportedAlgorithm));
        assert_eq!(h.signing_alg(), Err(Error::UnsupportedAlgorithm));
    }

    #[test]
    fn rfc7520_pbes2_header_parses() {
        // RFC 7520 §5.3.4, Figures 101/102.
        let bytes = b64(concat!(
            "eyJhbGciOiJQQkVTMi1IUzUxMitBMjU2S1ciLCJwMnMiOiI4UTFTemluYXNSM3",
            "hjaFl6NlpaY0hBIiwicDJjIjo4MTkyLCJjdHkiOiJqd2stc2V0K2pzb24iLCJl",
            "bmMiOiJBMTI4Q0JDLUhTMjU2In0"
        ));
        let h = assert_round_trip(&bytes);
        assert_eq!(h.key_mgmt_alg().unwrap(), KeyMgmtAlg::Pbes2Hs512A256KW);
        assert_eq!(h.p2s.as_deref(), Some("8Q1SzinasR3xchYz6ZZcHA"));
        assert_eq!(h.p2c, Some(8192));
        assert_eq!(h.cty.as_deref(), Some("jwk-set+json"));
        assert_eq!(h.enc, Some(ContentEncAlg::A128CbcHs256));
    }

    #[test]
    fn rfc7520_ecdh_es_header_parses() {
        // RFC 7520 §5.4.4, Figures 113/114.
        let bytes = b64(concat!(
            "eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImtpZCI6InBlcmVncmluLnRvb2tAdH",
            "Vja2Jvcm91Z2guZXhhbXBsZSIsImVwayI6eyJrdHkiOiJFQyIsImNydiI6IlAt",
            "Mzg0IiwieCI6InVCbzRrSFB3Nmtiang1bDB4b3dyZF9vWXpCbWF6LUdLRlp1NH",
            "hBRkZrYllpV2d1dEVLNml1RURzUTZ3TmROZzMiLCJ5Ijoic3AzcDVTR2haVkMy",
            "ZmFYdW1JLWU5SlUyTW84S3BvWXJGRHI1eVBOVnRXNFBnRXdaT3lRVEEtSmRhWT",
            "h0YjdFMCJ9LCJlbmMiOiJBMTI4R0NNIn0"
        ));
        let h = assert_round_trip(&bytes);
        assert_eq!(h.key_mgmt_alg().unwrap(), KeyMgmtAlg::EcdhEsA128KW);
        assert_eq!(h.kid.as_deref(), Some("peregrin.took@tuckborough.example"));
        let epk = h.epk.as_ref().unwrap();
        assert_eq!(epk.get("kty").and_then(Value::as_str), Some("EC"));
        assert_eq!(epk.get("crv").and_then(Value::as_str), Some("P-384"));
        assert_eq!(h.enc, Some(ContentEncAlg::A128GCM));
        // The member order of the cookbook header is alg, kid, epk, enc;
        // ours puts enc second. Equal as JSON, different as bytes.
        assert_ne!(h.to_json().unwrap().as_bytes(), bytes.as_slice());
    }

    #[test]
    fn rfc7797_b64_header_parses_and_serializes_exactly() {
        // RFC 7797 §4.2: {"alg":"HS256","b64":false,"crit":["b64"]}
        let bytes = b64("eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19");
        let h = assert_round_trip(&bytes);
        assert_eq!(h.b64, Some(false));
        assert_eq!(h.crit.as_deref(), Some(&["b64".to_owned()][..]));
        assert_eq!(
            h.to_json().unwrap(),
            r#"{"alg":"HS256","crit":["b64"],"b64":false}"#
        );
    }

    #[test]
    fn every_known_algorithm_name_serializes_exactly() {
        for alg in SigningAlg::KNOWN {
            let input = format!(r#"{{"alg":"{alg}"}}"#);
            let h = Header::from_json(input.as_bytes()).unwrap();
            assert_eq!(h.signing_alg().as_ref(), Ok(alg));
            assert_eq!(h.to_json().unwrap(), input);
        }
        for alg in KeyMgmtAlg::KNOWN {
            let input = format!(r#"{{"alg":"{alg}"}}"#);
            let h = Header::from_json(input.as_bytes()).unwrap();
            assert_eq!(h.key_mgmt_alg().as_ref(), Ok(alg));
            assert_eq!(h.to_json().unwrap(), input);
        }
        for enc in ContentEncAlg::KNOWN {
            let input = format!(r#"{{"enc":"{enc}"}}"#);
            let h = Header::from_json(input.as_bytes()).unwrap();
            assert_eq!(h.content_enc_alg().as_ref(), Ok(enc));
            assert_eq!(h.to_json().unwrap(), input);
        }
    }

    const ALL_PARAMS: &str = r#"{
        "alg": "ECDH-ES+A256KW", "enc": "A256GCM", "zip": "DEF",
        "jku": "https://example.com/jwks", "jwk": {"kty": "OKP", "crv": "X25519", "x": "AA"},
        "kid": "k1", "x5u": "https://example.com/c", "x5c": ["MIIB", "MIIC"],
        "x5t": "dGh1bWI", "x5t#S256": "dGh1bWIy", "typ": "JOSE", "cty": "JWT",
        "crit": ["exp"], "exp": 1363284000,
        "epk": {"kty": "EC", "crv": "P-256", "x": "AA", "y": "AA"},
        "apu": "QWxpY2U", "apv": "Qm9i", "iv": "aXY", "tag": "dGFn",
        "p2s": "c2FsdA", "p2c": 1000, "b64": true,
        "x-private": {"nested": [1, 2.5, null, false, "s"]}
    }"#;

    #[test]
    fn every_registered_parameter_round_trips() {
        let h = assert_round_trip(ALL_PARAMS.as_bytes());
        assert_eq!(h.x5t_s256.as_deref(), Some("dGh1bWIy"));
        assert_eq!(h.x5c.as_ref().map(Vec::len), Some(2));
        assert_eq!(h.other_params().len(), 2);
        assert_eq!(
            h.other_params().get("exp").and_then(Value::as_i64),
            Some(1363284000)
        );
    }

    #[test]
    fn serialization_order_is_fields_then_other_params_in_order() {
        let h = Header::from_json(br#"{"z":1,"kid":"k","a":2,"alg":"HS256"}"#).unwrap();
        assert_eq!(
            h.to_json().unwrap(),
            r#"{"alg":"HS256","kid":"k","z":1,"a":2}"#
        );
        let names: Vec<&str> = h.other_params().iter().map(|(n, _)| n).collect();
        assert_eq!(names, ["z", "a"]);
    }

    #[test]
    fn unknown_alg_and_enc_round_trip_and_fail_when_used() {
        let bytes = br#"{"alg":"Ed448","enc":"A128CBC"}"#;
        let h = assert_round_trip(bytes);
        assert_eq!(h.to_json().unwrap().as_bytes(), bytes);
        assert_eq!(h.alg.as_deref(), Some("Ed448"));
        assert_eq!(h.enc, Some(ContentEncAlg::Unknown("A128CBC".into())));
        assert_eq!(h.signing_alg(), Err(Error::UnsupportedAlgorithm));
        assert_eq!(h.key_mgmt_alg(), Err(Error::UnsupportedAlgorithm));
        assert_eq!(h.content_enc_alg(), Err(Error::UnsupportedAlgorithm));
    }

    #[test]
    fn alg_of_the_other_family_is_unsupported() {
        let jwe = Header::from_json(br#"{"alg":"A128KW"}"#).unwrap();
        assert_eq!(jwe.signing_alg(), Err(Error::UnsupportedAlgorithm));
        let jws = Header::from_json(br#"{"alg":"HS256"}"#).unwrap();
        assert_eq!(jws.key_mgmt_alg(), Err(Error::UnsupportedAlgorithm));
    }

    #[test]
    fn none_is_parsed_as_a_known_alg() {
        // RFC 7518 §3.6: parsed for diagnostics; the allow-list rejects it.
        let h = Header::from_json(br#"{"alg":"none"}"#).unwrap();
        assert_eq!(h.signing_alg(), Ok(SigningAlg::None));
    }

    #[test]
    fn missing_alg_and_enc_are_invalid_header() {
        let h = Header::from_json(b"{}").unwrap();
        assert_eq!(h.signing_alg(), Err(Error::InvalidHeader("missing alg")));
        assert_eq!(h.key_mgmt_alg(), Err(Error::InvalidHeader("missing alg")));
        assert_eq!(
            h.content_enc_alg(),
            Err(Error::InvalidHeader("missing enc"))
        );
    }

    #[test]
    fn registered_parameter_with_wrong_type_is_invalid_header() {
        let cases: &[&str] = &[
            r#"{"alg":256}"#,
            r#"{"alg":null}"#,
            r#"{"enc":["A128GCM"]}"#,
            r#"{"zip":true}"#,
            r#"{"jku":1}"#,
            r#"{"kid":{"a":1}}"#,
            r#"{"x5u":[]}"#,
            r#"{"jwk":"eyJ9"}"#,
            r#"{"epk":[]}"#,
            r#"{"x5c":"MIIB"}"#,
            r#"{"x5c":["MIIB",1]}"#,
            r#"{"x5t":false}"#,
            r#"{"x5t#S256":true}"#,
            r#"{"typ":0}"#,
            r#"{"cty":{}}"#,
            r#"{"crit":"b64"}"#,
            r#"{"crit":[1]}"#,
            r#"{"apu":1}"#,
            r#"{"apv":null}"#,
            r#"{"iv":[]}"#,
            r#"{"tag":null}"#,
            r#"{"p2s":1}"#,
            r#"{"b64":"false"}"#,
            r#"{"b64":0}"#,
            r#"{"p2c":"8192"}"#,
            r#"{"p2c":0}"#,
            r#"{"p2c":-1}"#,
            r#"{"p2c":1.5}"#,
            r#"{"p2c":9007199254740992}"#,
            r#"{"p2c":18446744073709551616}"#,
        ];
        for input in cases {
            assert_invalid_header(input.as_bytes());
        }
    }

    #[test]
    fn integral_p2c_written_as_a_float_is_the_same_integer() {
        // RFC 8259 §6 has one number type; 1000.0 is the integer 1000.
        let h = Header::from_json(br#"{"p2c":1000.0}"#).unwrap();
        assert_eq!(h.p2c, Some(1000));
        assert_eq!(h.to_json().unwrap(), r#"{"p2c":1000}"#);
        let h = Header::from_json(br#"{"p2c":9007199254740991}"#).unwrap();
        assert_eq!(h.p2c, Some(9_007_199_254_740_991));
    }

    #[test]
    fn unrepresentable_p2c_is_not_serialized() {
        for p2c in [0, 9_007_199_254_740_992, u64::MAX] {
            let mut h = Header::new();
            h.p2c = Some(p2c);
            assert_eq!(
                h.to_json(),
                Err(Error::InvalidHeader(P2C_NOT_POSITIVE)),
                "{p2c}"
            );
        }
    }

    #[test]
    fn non_object_and_malformed_json_are_invalid_json() {
        let cases: &[&[u8]] = &[
            b"",
            b"[]",
            b"\"alg\"",
            b"null",
            b"42",
            b"{",
            b"{\"alg\":\"HS256\"",
            b"{\"alg\":\"HS256\"} trailing",
            b"{\"alg\":\"HS256\"}{}",
            b"{'alg':'HS256'}",
            b"{\"alg\":\"HS256\",}",
            b"\xEF\xBB\xBF{\"alg\":\"HS256\"}",
            b"{\"alg\":\"\xff\"}",
            b"{\"alg\":\"\\ud800\"}",
            b"{\"p2c\":1e400}",
        ];
        for input in cases {
            let err = Header::from_json(input).err();
            assert!(
                matches!(err, Some(Error::InvalidJson(_))),
                "{input:?}: {err:?}"
            );
        }
    }

    #[test]
    fn errors_never_contain_input() {
        let marker = "pj-SECRET-marker-hdr";
        let cases = [
            format!(r#"{{"alg":{marker}}}"#),
            format!(r#"{{"kid":["{marker}"]}}"#),
            format!(r#"["{marker}"]"#),
            format!(r#"{{"{marker}":1"#),
            format!(r#"{{"{marker}":1,"{marker}":2}}"#),
            format!(r#"{{"crit":["{marker}","{marker}"],"{marker}":1}}"#),
        ];
        for input in cases {
            let err = Header::from_json(input.as_bytes()).err().unwrap();
            assert!(!format!("{err:?}").contains(marker), "{err:?}");
            assert!(!err.to_string().contains(marker), "{err}");
        }
    }

    #[test]
    fn insert_other_refuses_typed_field_names() {
        let mut h = Header::new();
        for name in FIELD_NAMES {
            assert_eq!(
                h.insert_other(*name, "x"),
                Err(Error::InvalidHeader("parameter has a typed field")),
                "{name}"
            );
        }
        assert_eq!(h.insert_other("exp", Value::from(true)), Ok(None));
        assert_eq!(
            h.insert_other("exp", Value::from(false)),
            Ok(Some(Value::from(true)))
        );
        assert!(h.contains("exp"));
        assert_eq!(h.remove_other("exp"), Some(Value::from(false)));
        assert!(!h.contains("exp"));
    }

    #[test]
    fn contains_covers_every_typed_field() {
        let h = Header::from_json(ALL_PARAMS.as_bytes()).unwrap();
        for name in FIELD_NAMES {
            assert!(h.contains(name), "{name}");
            assert!(!Header::new().contains(name), "{name}");
        }
        assert!(h.contains("x-private"));
        assert!(!h.contains("x-absent"));
    }

    #[test]
    fn programmatic_header_serializes_each_name_once() {
        let mut h = Header::new();
        h.alg = Some("HS256".into());
        h.jwk = Some(Object::new());
        h.b64 = Some(true);
        h.insert_other("kid2", "x").unwrap();
        assert_eq!(
            h.to_json().unwrap(),
            r#"{"alg":"HS256","jwk":{},"b64":true,"kid2":"x"}"#
        );
    }

    /// The input must be rejected as `InvalidJson`, while serde_json (a
    /// dev-only oracle that keeps the last duplicate) accepts it: so the
    /// duplicate is the only reason.
    fn assert_duplicate_rejected(input: &[u8]) {
        assert!(
            serde_json::from_slice::<serde_json::Value>(input).is_ok(),
            "test input must be otherwise valid: {:?}",
            String::from_utf8_lossy(input)
        );
        let err = Header::from_json(input).err();
        assert!(
            matches!(err, Some(Error::InvalidJson(_))),
            "{:?}: {err:?}",
            String::from_utf8_lossy(input)
        );
    }

    #[test]
    fn duplicate_registered_name_is_rejected() {
        // RFC 7515 §4 / §5.2 step 4: keeping the last value would read
        // this header as `none`.
        assert_duplicate_rejected(br#"{"alg":"HS256","alg":"none"}"#);
    }

    #[test]
    fn duplicate_with_identical_value_is_rejected() {
        assert_duplicate_rejected(br#"{"alg":"HS256","kid":"a","alg":"HS256"}"#);
    }

    #[test]
    fn duplicate_private_name_is_rejected() {
        assert_duplicate_rejected(br#"{"alg":"HS256","exp":1,"exp":2}"#);
    }

    #[test]
    fn duplicate_spelled_with_escapes_is_rejected() {
        // Names compare after JSON unescaping (RFC 8259 §7, §8.3).
        assert_duplicate_rejected(br#"{"alg":"HS256","\u0061lg":"none"}"#);
        assert_duplicate_rejected(br#"{"b64":true,"\u0062\u0036\u0034":false}"#);
        assert_duplicate_rejected(br#"{"x\/y":1,"x/y":2}"#);
    }

    #[test]
    fn duplicate_in_crit_bearing_header_is_rejected() {
        assert_duplicate_rejected(br#"{"alg":"HS256","b64":false,"crit":["b64"],"b64":true}"#);
    }

    #[test]
    fn duplicate_in_nested_objects_is_rejected() {
        assert_duplicate_rejected(br#"{"jwk":{"kty":"oct","kty":"RSA"}}"#);
        assert_duplicate_rejected(br#"{"epk":{"kty":"EC","crv":"P-256","crv":"P-384"}}"#);
        assert_duplicate_rejected(br#"{"x-priv":{"a":1,"a":1}}"#);
        assert_duplicate_rejected(br#"{"x-priv":[{"a":{"b":1,"b":2}}]}"#);
    }

    #[test]
    fn names_differing_only_in_case_are_distinct() {
        let h = Header::from_json(br#"{"alg":"HS256","Alg":"none","ALG":"x"}"#).unwrap();
        assert_eq!(h.signing_alg(), Ok(SigningAlg::HS256));
        assert_eq!(h.other_params().len(), 2);
    }

    #[test]
    fn deep_nesting_is_an_error_not_a_crash() {
        let deep = format!("{{\"x\":{}{}}}", "[".repeat(100_000), "]".repeat(100_000));
        assert!(matches!(
            Header::from_json(deep.as_bytes()),
            Err(Error::InvalidJson(_))
        ));
        let deep = format!("{}{}", "{\"a\":".repeat(10_000), "}".repeat(10_000));
        assert!(matches!(
            Header::from_json(deep.as_bytes()),
            Err(Error::InvalidJson(_))
        ));
    }

    /// Names defined by JWS, JWE and JWA for headers (IANA registry rows
    /// from RFC 7515 §4.1, RFC 7516 §4.1 and RFC 7518 §4.6.1/§4.7.1/§4.8.1).
    const SPEC_NAMES: &[&str] = &[
        "alg", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256", "typ", "cty", "crit", "enc",
        "zip", "epk", "apu", "apv", "iv", "tag", "p2s", "p2c",
    ];

    #[test]
    fn rfc7515_crit_example_is_valid_but_not_understood() {
        // RFC 7515 §4.1.11 example.
        let h = Header::from_json(br#"{"alg":"ES256","crit":["exp"],"exp":1363284000}"#).unwrap();
        assert_eq!(h.validate_crit(), Ok(()));
        assert_eq!(
            h.validate_crit_understood(&["b64"]),
            Err(Error::UnknownCritical)
        );
        assert_eq!(h.validate_crit_understood(&["exp"]), Ok(()));
    }

    #[test]
    fn rfc7797_b64_crit_is_understood_by_jws() {
        let h = Header::from_json(br#"{"alg":"HS256","b64":false,"crit":["b64"]}"#).unwrap();
        assert_eq!(h.validate_crit_understood(&["b64"]), Ok(()));
        // A JWE recipient understands no extensions.
        assert_eq!(h.validate_crit_understood(&[]), Err(Error::UnknownCritical));
    }

    #[test]
    fn absent_crit_is_valid() {
        let h = Header::from_json(br#"{"alg":"HS256"}"#).unwrap();
        assert_eq!(h.validate_crit(), Ok(()));
        assert_eq!(h.validate_crit_understood(&[]), Ok(()));
    }

    #[test]
    fn empty_crit_is_rejected() {
        // RFC 7515 §4.1.11: producers MUST NOT use the empty list.
        assert_eq!(
            Header::from_json(br#"{"alg":"HS256","crit":[]}"#),
            Err(Error::InvalidHeader("crit must not be empty"))
        );
    }

    #[test]
    fn crit_listing_a_spec_defined_name_is_rejected() {
        // RFC 7515 §4.1.11, RFC 7516 §4.1.13. Each name is present, so only
        // the "defined by this specification" rule can reject it.
        for name in SPEC_NAMES {
            let mut obj = Object::new();
            obj.insert("alg", "HS256");
            obj.insert("crit", Value::from(vec![Value::from(*name)]));
            if !obj.contains(name) {
                obj.insert(*name, "v");
            }
            assert_invalid_header(obj.to_json().as_bytes());
        }
    }

    #[test]
    fn crit_listing_a_name_twice_is_rejected() {
        // RFC 7515 §4.1.11: producers MUST NOT include duplicate names.
        assert_eq!(
            Header::from_json(br#"{"alg":"HS256","b64":false,"crit":["b64","b64"]}"#),
            Err(Error::InvalidHeader("crit lists a name twice"))
        );
    }

    #[test]
    fn crit_listing_an_absent_name_is_rejected() {
        // RFC 7515 §4.1.11: listed names must occur in the JOSE Header.
        let h = Header::from_json(br#"{"alg":"HS256","crit":["exp"]}"#).unwrap();
        let absent = Err(Error::InvalidHeader("crit lists an absent parameter"));
        assert_eq!(h.validate_crit(), absent);
        // Structural errors win over "not understood".
        assert_eq!(h.validate_crit_understood(&["exp"]), absent);
        let h = Header::from_json(br#"{"alg":"HS256","crit":["b64"]}"#).unwrap();
        assert_eq!(h.validate_crit_understood(&["b64"]), absent);
    }

    #[test]
    fn crit_set_programmatically_is_checked_too() {
        let mut h = Header::new();
        h.alg = Some("HS256".into());
        h.crit = Some(vec![]);
        assert_eq!(
            h.validate_crit(),
            Err(Error::InvalidHeader("crit must not be empty"))
        );
        h.crit = Some(vec!["kid".into()]);
        h.kid = Some("k".into());
        assert!(matches!(h.validate_crit(), Err(Error::InvalidHeader(_))));
        // Understanding a spec-defined name doesn't make it listable.
        assert!(matches!(
            h.validate_crit_understood(&["kid"]),
            Err(Error::InvalidHeader(_))
        ));
    }

    #[test]
    fn unknown_critical_name_is_not_echoed() {
        let marker = "pj-SECRET-marker-crit";
        let input = format!(r#"{{"alg":"HS256","crit":["{marker}"],"{marker}":1}}"#);
        let h = Header::from_json(input.as_bytes()).unwrap();
        let err = h.validate_crit_understood(&["b64"]).err().unwrap();
        assert_eq!(err, Error::UnknownCritical);
        assert!(!format!("{err:?}").contains(marker));
        assert!(!err.to_string().contains(marker));
    }

    #[test]
    fn crit_may_list_non_jose_registered_names() {
        // iss/sub/aud are registered by RFC 7519 §10.4.1, not by JWS/JWE/JWA.
        let h = Header::from_json(br#"{"alg":"HS256","crit":["iss","aud"],"iss":"a","aud":"b"}"#)
            .unwrap();
        assert_eq!(h.validate_crit(), Ok(()));
        assert_eq!(h.validate_crit_understood(&["iss", "aud"]), Ok(()));
    }

    #[test]
    fn long_crit_list_within_the_json_limits_is_checked() {
        // 5,000 listed names plus 5,000 members stays under the parser's
        // 10,000-entry limit; the crit checks are set-based, not quadratic.
        let names: Vec<String> = (0..5_000).map(|i| format!("x{i}")).collect();
        let mut obj = Object::new();
        obj.insert(
            "crit",
            Value::from(
                names
                    .iter()
                    .map(|n| Value::from(n.as_str()))
                    .collect::<Vec<_>>(),
            ),
        );
        for n in &names {
            obj.insert(n.as_str(), true);
        }
        let h = Header::from_json(obj.to_json().as_bytes()).unwrap();
        assert_eq!(h.validate_crit(), Ok(()));
        assert_eq!(h.validate_crit_understood(&[]), Err(Error::UnknownCritical));
    }

    mod robustness {
        //! Parser robustness (ADR 0008 layer 2): no input makes header
        //! parsing panic, every failure is a stable code, and whatever
        //! parses re-serializes to an equal object.
        use super::*;
        use proptest::prelude::*;

        /// Names that steer generation into the typed fields, `crit`
        /// targets and private parameters.
        const NAMES: &[&str] = &[
            "alg", "enc", "zip", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256", "typ",
            "cty", "crit", "epk", "apu", "apv", "iv", "tag", "p2s", "p2c", "b64", "exp", "iss",
            "x", "\u{0}", "é", "",
        ];

        fn name() -> impl Strategy<Value = String> {
            prop_oneof![
                4 => proptest::sample::select(NAMES).prop_map(str::to_owned),
                1 => "\\PC{0,6}",
            ]
        }

        fn leaf() -> impl Strategy<Value = Value> {
            prop_oneof![
                Just(Value::Null),
                any::<bool>().prop_map(Value::from),
                (-json::MAX_SAFE_INTEGER..=json::MAX_SAFE_INTEGER)
                    .prop_filter_map("exact", |i| Number::from_i64(i).map(Value::from)),
                (-3i64..10_001).prop_filter_map("exact", |i| Number::from_i64(i).map(Value::from)),
                any::<f64>().prop_filter_map("finite", |f| Number::from_f64(f).map(Value::from)),
                proptest::sample::select(NAMES).prop_map(Value::from),
                proptest::sample::select(&["HS256", "none", "RSA-OAEP", "A128GCM", "dir"][..])
                    .prop_map(Value::from),
                "\\PC{0,8}".prop_map(Value::from),
            ]
        }

        fn value() -> impl Strategy<Value = Value> {
            leaf().prop_recursive(3, 32, 5, |inner| {
                prop_oneof![
                    prop::collection::vec(inner.clone(), 0..5).prop_map(Value::from),
                    prop::collection::vec((name(), inner), 0..5).prop_map(|members| {
                        let mut o = Object::new();
                        for (n, v) in members {
                            o.insert(n, v);
                        }
                        Value::from(o)
                    }),
                ]
            })
        }

        fn header_object() -> impl Strategy<Value = Object> {
            prop::collection::vec((name(), value()), 0..10).prop_map(|members| {
                let mut o = Object::new();
                for (n, v) in members {
                    o.insert(n, v);
                }
                o
            })
        }

        /// Exercises every accessor; none may panic.
        fn use_everything(h: &Header) {
            let _ = h.signing_alg();
            let _ = h.key_mgmt_alg();
            let _ = h.content_enc_alg();
            let _ = h.validate_crit();
            let _ = h.validate_crit_understood(&["b64"]);
            for name in NAMES {
                let _ = h.contains(name);
            }
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(512))]

            #[test]
            fn arbitrary_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
                match Header::from_json(&bytes) {
                    Ok(h) => use_everything(&h),
                    Err(e) => prop_assert!(
                        matches!(e, Error::InvalidJson(_) | Error::InvalidHeader(_)),
                        "{e:?}"
                    ),
                }
            }

            #[test]
            fn mutated_headers_never_panic(
                edits in prop::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..8)
            ) {
                let mut bytes = ALL_PARAMS.as_bytes().to_vec();
                for (at, byte) in edits {
                    let i = at.index(bytes.len());
                    bytes[i] = byte;
                }
                match Header::from_json(&bytes) {
                    Ok(h) => use_everything(&h),
                    Err(e) => prop_assert!(
                        matches!(e, Error::InvalidJson(_) | Error::InvalidHeader(_)),
                        "{e:?}"
                    ),
                }
            }

            #[test]
            fn arbitrary_objects_parse_or_fail_as_invalid_header(obj in header_object()) {
                let text = obj.to_json();
                match Header::from_json(text.as_bytes()) {
                    Ok(h) => {
                        use_everything(&h);
                        let again = h.to_json().unwrap();
                        prop_assert_eq!(
                            json::parse(again.as_bytes()).unwrap(),
                            json::parse(text.as_bytes()).unwrap()
                        );
                        prop_assert_eq!(Header::from_json(again.as_bytes()).unwrap(), h);
                    }
                    // A valid JSON object can only fail the header rules.
                    Err(e) => prop_assert!(matches!(e, Error::InvalidHeader(_)), "{e:?}"),
                }
            }
        }
    }
}
