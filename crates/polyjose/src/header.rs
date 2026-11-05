//! The JOSE Header: registered Header Parameters (RFC 7515 §4.1,
//! RFC 7516 §4.1, RFC 7518 §4.6.1/§4.7.1/§4.8.1, RFC 7797 §3) plus any
//! Public or Private Header Parameters (RFC 7515 §4.2–§4.3).
//!
//! [`Header::from_json`][from_json] is the only way to read a header from
//! untrusted bytes. `Header` deliberately does not implement `Deserialize`, so it
//! can't be built by a parser that skips the checks below.
//!
//! # What parsing checks
//!
//! - The input is a UTF-8 encoded, completely valid JSON object
//!   (RFC 7515 §5.2 step 3, RFC 7516 §5.2 step 3), else
//!   [`Error::InvalidJson`].
//! - No member name occurs twice, in the header or in any nested object
//!   (RFC 7515 §4 and §5.2 step 4, RFC 7516 §4 and §5.2 step 4), else
//!   [`Error::InvalidHeader`]. Duplicates are rejected, not resolved to the
//!   last value (RFC 7515 §10.12).
//! - Each registered parameter has its registered JSON type, else
//!   [`Error::InvalidHeader`].
//!
//! # What parsing does not check
//!
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
//!   (and are validated) where they are used.
//!
//! [from_json]: crate::header::Header::from_json
//! [signing_alg]: crate::header::Header::signing_alg
//! [key_mgmt_alg]: crate::header::Header::key_mgmt_alg
//! [content_enc_alg]: crate::header::Header::content_enc_alg

use std::collections::BTreeMap;

use serde::Serialize;
use serde::ser::{SerializeMap, Serializer};
use serde_json::{Map, Value};

use crate::error::{Error, Result};
use crate::jwa::{ContentEncAlg, KeyMgmtAlg, SigningAlg};

/// Detail for input that is valid JSON but not a JSON object.
const NOT_AN_OBJECT: &str = "expected a JSON object";

/// A JOSE Header (RFC 7515 §4, RFC 7516 §4).
///
/// Registered parameters are typed fields; every other member is kept,
/// unchanged, in [`Header::other_params`]. Parsing then serializing a header
/// yields an equal JSON object (member order is not preserved, and need not
/// be: signatures cover the original encoded bytes, RFC 7515 §5.1).
///
/// ```
/// use polyjose::header::Header;
/// use polyjose::jwa::SigningAlg;
///
/// let h = Header::from_json(br#"{"alg":"HS256","typ":"JWT","x-tenant":"a"}"#)?;
/// assert_eq!(h.signing_alg()?, SigningAlg::HS256);
/// assert_eq!(h.typ.as_deref(), Some("JWT"));
/// assert_eq!(h.other_params()["x-tenant"], "a");
/// # Ok::<(), polyjose::Error>(())
/// ```
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
    pub jwk: Option<Map<String, Value>>,
    /// `kid`: Key ID (RFC 7515 §4.1.4, RFC 7516 §4.1.6).
    pub kid: Option<String>,
    /// `x5u`: X.509 URL (RFC 7515 §4.1.5, RFC 7516 §4.1.7).
    pub x5u: Option<String>,
    /// `x5c`: X.509 certificate chain, base64 (not base64url) DER values
    /// (RFC 7515 §4.1.6, RFC 7516 §4.1.8).
    pub x5c: Option<Vec<String>>,
    /// `x5t`: base64url SHA-1 certificate thumbprint (RFC 7515 §4.1.7,
    /// RFC 7516 §4.1.9).
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
    pub epk: Option<Map<String, Value>>,
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
    /// Only the type is checked here; the JWE layer enforces the upper bound
    /// (ADR 0007).
    pub p2c: Option<u64>,
    /// `b64`: whether the JWS payload is base64url-encoded (RFC 7797 §3).
    pub b64: Option<bool>,
    /// All other (Public or Private, RFC 7515 §4.2–§4.3) parameters.
    ///
    /// Private so that it can never hold a name that is also a field above,
    /// which would serialize as a duplicate member.
    other: BTreeMap<String, Value>,
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
    ///   completely valid JSON object (RFC 7515 §5.2 step 3).
    /// - [`Error::InvalidHeader`] if a member name occurs twice in any
    ///   object, at any depth (RFC 7515 §4, §5.2 step 4; RFC 7516 §4,
    ///   §5.2 step 4), or a registered parameter has the wrong type.
    ///
    /// No error contains any part of the input.
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        match strict_json::parse_object(bytes) {
            Ok(map) => Self::from_map(map),
            Err(strict_json::StrictJsonError::DuplicateName) => {
                Err(Error::InvalidHeader("duplicate member name"))
            }
            Err(strict_json::StrictJsonError::NotAnObject) => {
                Err(Error::InvalidJson(NOT_AN_OBJECT))
            }
            Err(strict_json::StrictJsonError::Json(e)) => Err(e.into()),
        }
    }

    /// Builds a header from an already-parsed JSON object, checking the type
    /// of every registered parameter.
    pub(crate) fn from_map(map: Map<String, Value>) -> Result<Self> {
        let mut h = Self::default();
        for (name, value) in map {
            match name.as_str() {
                "alg" => h.alg = Some(string(value, "alg must be a string")?),
                "enc" => h.enc = Some(string(value, "enc must be a string")?.into()),
                "zip" => h.zip = Some(string(value, "zip must be a string")?),
                "jku" => h.jku = Some(string(value, "jku must be a string")?),
                "jwk" => h.jwk = Some(object(value, "jwk must be a JSON object")?),
                "kid" => h.kid = Some(string(value, "kid must be a string")?),
                "x5u" => h.x5u = Some(string(value, "x5u must be a string")?),
                "x5c" => h.x5c = Some(strings(value, "x5c must be an array of strings")?),
                "x5t" => h.x5t = Some(string(value, "x5t must be a string")?),
                "x5t#S256" => h.x5t_s256 = Some(string(value, "x5t#S256 must be a string")?),
                "typ" => h.typ = Some(string(value, "typ must be a string")?),
                "cty" => h.cty = Some(string(value, "cty must be a string")?),
                "crit" => h.crit = Some(strings(value, "crit must be an array of strings")?),
                "epk" => h.epk = Some(object(value, "epk must be a JSON object")?),
                "apu" => h.apu = Some(string(value, "apu must be a string")?),
                "apv" => h.apv = Some(string(value, "apv must be a string")?),
                "iv" => h.iv = Some(string(value, "iv must be a string")?),
                "tag" => h.tag = Some(string(value, "tag must be a string")?),
                "p2s" => h.p2s = Some(string(value, "p2s must be a string")?),
                "p2c" => h.p2c = Some(positive_int(value, "p2c must be a positive integer")?),
                "b64" => h.b64 = Some(boolean(value, "b64 must be a boolean")?),
                _ => {
                    h.other.insert(name, value);
                }
            }
        }
        Ok(h)
    }

    /// Serializes the header as compact JSON.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidJson`] only if serialization fails, which a `Header`
    /// built through this API cannot cause.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
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
    /// allow-list (RFC 8725 §3.1).
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
    /// - [`Error::UnsupportedAlgorithm`] if it is not a known JWE key
    ///   management algorithm (RFC 7516 §4.1.1).
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

    /// The Public and Private Header Parameters (RFC 7515 §4.2–§4.3): every
    /// member that is not one of the typed fields, keyed by name.
    pub fn other_params(&self) -> &BTreeMap<String, Value> {
        &self.other
    }

    /// Sets a Public or Private Header Parameter (RFC 7515 §4.2–§4.3),
    /// returning the previous value.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidHeader`] if `name` is one of the typed fields (set the
    /// field instead), so a header can never hold the same name twice
    /// (RFC 7515 §4).
    pub fn insert_other(&mut self, name: impl Into<String>, value: Value) -> Result<Option<Value>> {
        let name = name.into();
        if FIELD_NAMES.contains(&name.as_str()) {
            return Err(Error::InvalidHeader("parameter has a typed field"));
        }
        Ok(self.other.insert(name, value))
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
            _ => self.other.contains_key(name),
        }
    }
}

const MISSING_ALG: Error = Error::InvalidHeader("missing alg");

fn string(value: Value, detail: &'static str) -> Result<String> {
    match value {
        Value::String(s) => Ok(s),
        _ => Err(Error::InvalidHeader(detail)),
    }
}

fn object(value: Value, detail: &'static str) -> Result<Map<String, Value>> {
    match value {
        Value::Object(m) => Ok(m),
        _ => Err(Error::InvalidHeader(detail)),
    }
}

fn strings(value: Value, detail: &'static str) -> Result<Vec<String>> {
    match value {
        Value::Array(items) => items.into_iter().map(|v| string(v, detail)).collect(),
        _ => Err(Error::InvalidHeader(detail)),
    }
}

fn boolean(value: Value, detail: &'static str) -> Result<bool> {
    match value {
        Value::Bool(b) => Ok(b),
        _ => Err(Error::InvalidHeader(detail)),
    }
}

/// A positive JSON integer (RFC 7518 §4.8.1.2). Floats such as `1.0` are not
/// integers here.
fn positive_int(value: Value, detail: &'static str) -> Result<u64> {
    match value.as_u64() {
        Some(n) if n > 0 => Ok(n),
        _ => Err(Error::InvalidHeader(detail)),
    }
}

impl Serialize for Header {
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        macro_rules! field {
            ($name:literal, $field:expr) => {
                if let Some(v) = &$field {
                    map.serialize_entry($name, v)?;
                }
            };
        }
        field!("alg", self.alg);
        field!("enc", self.enc);
        field!("zip", self.zip);
        field!("jku", self.jku);
        field!("jwk", self.jwk);
        field!("kid", self.kid);
        field!("x5u", self.x5u);
        field!("x5c", self.x5c);
        field!("x5t", self.x5t);
        field!("x5t#S256", self.x5t_s256);
        field!("typ", self.typ);
        field!("cty", self.cty);
        field!("crit", self.crit);
        field!("epk", self.epk);
        field!("apu", self.apu);
        field!("apv", self.apv);
        field!("iv", self.iv);
        field!("tag", self.tag);
        field!("p2s", self.p2s);
        field!("p2c", self.p2c);
        field!("b64", self.b64);
        for (name, value) in &self.other {
            map.serialize_entry(name, value)?;
        }
        map.end()
    }
}

/// JSON parsing that rejects duplicate member names.
///
/// RFC 7515 §4 and RFC 7516 §4 let a parser either reject duplicate Header
/// Parameter names or keep the lexically last one; polyjose rejects them,
/// because a parser that silently picks one value is a source of the
/// "ambiguous and potentially exploitable situations" of RFC 7515 §10.12
/// (two implementations reading different `alg` values from one header).
/// `serde_json` on its own keeps the last value, hence this parser.
///
/// Duplicates are rejected in nested objects too: `jwk` and `epk` are JWKs,
/// whose parsers may also reject duplicates (RFC 7517 §4), and applying the
/// same rule to Private Header Parameter values keeps the behaviour uniform
/// and free of parser differentials. Names compare after JSON unescaping
/// (RFC 8259 §7), so `"\u0061lg"` duplicates `"alg"`.
///
/// Nesting depth is bounded by `serde_json`'s recursion limit (128), which
/// fails with an error rather than exhausting the stack.
///
/// `pub(crate)` so that the JWS/JWE JSON serializations, JWT claims
/// (RFC 7519 §4) and JWKs can apply the same rule.
pub(crate) mod strict_json {
    use core::cell::Cell;
    use core::fmt;

    use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
    use serde_json::{Map, Number, Value};

    /// Why [`parse_object`] failed.
    #[derive(Debug)]
    pub(crate) enum StrictJsonError {
        /// A member name occurred twice in one object.
        DuplicateName,
        /// Valid JSON, but the top level is not an object.
        NotAnObject,
        /// Not valid JSON (syntax, encoding, trailing data, depth).
        Json(serde_json::Error),
    }

    /// Parses `bytes` as one complete JSON object (no trailing data) and
    /// rejects duplicate member names at every depth.
    pub(crate) fn parse_object(bytes: &[u8]) -> Result<Map<String, Value>, StrictJsonError> {
        let duplicate = Cell::new(false);
        let mut de = serde_json::Deserializer::from_slice(bytes);
        let parsed = StrictValue {
            duplicate: &duplicate,
        }
        .deserialize(&mut de);
        let parsed = parsed.and_then(|value| de.end().map(|()| value));
        match parsed {
            Ok(Value::Object(map)) => Ok(map),
            Ok(_) => Err(StrictJsonError::NotAnObject),
            Err(_) if duplicate.get() => Err(StrictJsonError::DuplicateName),
            Err(e) => Err(StrictJsonError::Json(e)),
        }
    }

    /// Builds a [`Value`], flagging the first duplicate name it meets.
    #[derive(Clone, Copy)]
    struct StrictValue<'a> {
        duplicate: &'a Cell<bool>,
    }

    impl<'de> DeserializeSeed<'de> for StrictValue<'_> {
        type Value = Value;

        fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
            deserializer.deserialize_any(self)
        }
    }

    impl<'de> Visitor<'de> for StrictValue<'_> {
        type Value = Value;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a JSON value")
        }

        fn visit_bool<E: de::Error>(self, v: bool) -> Result<Value, E> {
            Ok(Value::Bool(v))
        }

        fn visit_i64<E: de::Error>(self, v: i64) -> Result<Value, E> {
            Ok(Value::Number(v.into()))
        }

        fn visit_u64<E: de::Error>(self, v: u64) -> Result<Value, E> {
            Ok(Value::Number(v.into()))
        }

        fn visit_f64<E: de::Error>(self, v: f64) -> Result<Value, E> {
            Number::from_f64(v)
                .map(Value::Number)
                .ok_or_else(|| E::custom("non-finite number"))
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Value, E> {
            Ok(Value::String(v.to_owned()))
        }

        fn visit_string<E: de::Error>(self, v: String) -> Result<Value, E> {
            Ok(Value::String(v))
        }

        fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
            Ok(Value::Null)
        }

        fn visit_none<E: de::Error>(self) -> Result<Value, E> {
            Ok(Value::Null)
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
            let mut items = Vec::new();
            while let Some(item) = seq.next_element_seed(self)? {
                items.push(item);
            }
            Ok(Value::Array(items))
        }

        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
            let mut members = Map::new();
            while let Some(name) = map.next_key::<String>()? {
                if members.contains_key(&name) {
                    self.duplicate.set(true);
                    return Err(de::Error::custom("duplicate member name"));
                }
                let value = map.next_value_seed(self)?;
                members.insert(name, value);
            }
            Ok(Value::Object(members))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64ct::{Base64UrlUnpadded, Encoding};
    use serde_json::json;

    fn b64(s: &str) -> Vec<u8> {
        Base64UrlUnpadded::decode_vec(s).unwrap()
    }

    /// Parse, re-serialize and compare as JSON values (order-insensitive).
    fn assert_round_trip(bytes: &[u8]) -> Header {
        let h = Header::from_json(bytes).unwrap();
        let original: Value = serde_json::from_slice(bytes).unwrap();
        let again: Value = serde_json::from_slice(&h.to_json().unwrap()).unwrap();
        assert_eq!(again, original);
        h
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
        assert_eq!(h.key_mgmt_alg().unwrap(), KeyMgmtAlg::RsaOaep);
        assert_eq!(h.content_enc_alg().unwrap(), ContentEncAlg::A256GCM);
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
        assert_eq!(epk["kty"], "EC");
        assert_eq!(epk["crv"], "P-384");
        assert_eq!(h.enc, Some(ContentEncAlg::A128GCM));
    }

    #[test]
    fn rfc7797_b64_header_parses() {
        // RFC 7797 §4.2: {"alg":"HS256","b64":false,"crit":["b64"]}
        let bytes = b64("eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19");
        let h = assert_round_trip(&bytes);
        assert_eq!(h.b64, Some(false));
        assert_eq!(h.crit.as_deref(), Some(&["b64".to_owned()][..]));
    }

    #[test]
    fn every_registered_parameter_round_trips() {
        let input = json!({
            "alg": "ECDH-ES+A256KW", "enc": "A256GCM", "zip": "DEF",
            "jku": "https://example.com/jwks", "jwk": {"kty": "OKP", "crv": "X25519", "x": "AA"},
            "kid": "k1", "x5u": "https://example.com/c", "x5c": ["MIIB", "MIIC"],
            "x5t": "dGh1bWI", "x5t#S256": "dGh1bWIy", "typ": "JOSE", "cty": "JWT",
            "crit": ["exp"], "exp": 1363284000,
            "epk": {"kty": "EC", "crv": "P-256", "x": "AA", "y": "AA"},
            "apu": "QWxpY2U", "apv": "Qm9i", "iv": "aXY", "tag": "dGFn",
            "p2s": "c2FsdA", "p2c": 1000, "b64": true,
            "x-private": {"nested": [1, 2.5, null, false, "s"]}
        });
        let bytes = serde_json::to_vec(&input).unwrap();
        let h = assert_round_trip(&bytes);
        assert_eq!(h.x5t_s256.as_deref(), Some("dGh1bWIy"));
        assert_eq!(h.x5c.as_ref().map(Vec::len), Some(2));
        assert_eq!(h.other_params().len(), 2);
        assert_eq!(h.other_params()["exp"], 1363284000);
    }

    #[test]
    fn unknown_alg_and_enc_round_trip_and_fail_when_used() {
        let bytes = br#"{"alg":"Ed448","enc":"A128CBC"}"#;
        let h = assert_round_trip(bytes);
        assert_eq!(h.alg.as_deref(), Some("Ed448"));
        assert_eq!(h.enc, Some(ContentEncAlg::Unknown("A128CBC".into())));
        assert_eq!(h.signing_alg(), Err(Error::UnsupportedAlgorithm));
        assert_eq!(h.key_mgmt_alg(), Err(Error::UnsupportedAlgorithm));
        assert_eq!(h.content_enc_alg(), Err(Error::UnsupportedAlgorithm));
    }

    #[test]
    fn alg_of_the_other_family_is_unsupported() {
        let jwe = Header::from_json(br#"{"alg":"RSA-OAEP"}"#).unwrap();
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
            r#"{"kid":{"a":1}}"#,
            r#"{"jwk":"eyJ9"}"#,
            r#"{"epk":[]}"#,
            r#"{"x5c":"MIIB"}"#,
            r#"{"x5c":["MIIB",1]}"#,
            r#"{"x5t#S256":true}"#,
            r#"{"crit":"b64"}"#,
            r#"{"crit":[1]}"#,
            r#"{"b64":"false"}"#,
            r#"{"b64":0}"#,
            r#"{"p2c":"8192"}"#,
            r#"{"p2c":0}"#,
            r#"{"p2c":-1}"#,
            r#"{"p2c":1.5}"#,
            r#"{"p2c":1000.0}"#,
            r#"{"p2c":18446744073709551616}"#,
            r#"{"tag":null}"#,
        ];
        for input in cases {
            let err = Header::from_json(input.as_bytes()).err();
            assert!(
                matches!(err, Some(Error::InvalidHeader(_))),
                "{input}: {err:?}"
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
                h.insert_other(*name, json!("x")),
                Err(Error::InvalidHeader("parameter has a typed field")),
                "{name}"
            );
        }
        assert_eq!(h.insert_other("exp", json!(1)), Ok(None));
        assert_eq!(h.insert_other("exp", json!(2)), Ok(Some(json!(1))));
        assert!(h.contains("exp"));
        assert_eq!(h.remove_other("exp"), Some(json!(2)));
        assert!(!h.contains("exp"));
    }

    #[test]
    fn contains_covers_every_typed_field() {
        let mut all = serde_json::Map::new();
        for name in FIELD_NAMES {
            let v = match *name {
                "jwk" | "epk" => json!({}),
                "x5c" => json!(["a"]),
                "crit" => json!(["x"]),
                "p2c" => json!(1),
                "b64" => json!(true),
                _ => json!("v"),
            };
            all.insert((*name).to_owned(), v);
        }
        all.insert("x".to_owned(), json!(1));
        let h = Header::from_json(&serde_json::to_vec(&all).unwrap()).unwrap();
        assert!(h.other_params().len() == 1);
        for name in FIELD_NAMES {
            assert!(h.contains(name), "{name}");
            assert!(!Header::new().contains(name), "{name}");
        }
    }

    #[test]
    fn serialization_emits_each_name_once() {
        let mut h = Header::new();
        h.alg = Some("HS256".into());
        h.insert_other("kid2", json!("x")).unwrap();
        let s = String::from_utf8(h.to_json().unwrap()).unwrap();
        assert_eq!(s, r#"{"alg":"HS256","kid2":"x"}"#);
    }

    const DUPLICATE: Error = Error::InvalidHeader("duplicate member name");

    #[test]
    fn duplicate_registered_name_is_rejected() {
        // RFC 7515 §4 / §5.2 step 4: serde_json alone would keep the last
        // value and accept this header as `none`.
        let input = br#"{"alg":"HS256","alg":"none"}"#;
        assert!(serde_json::from_slice::<Value>(input).is_ok());
        assert_eq!(Header::from_json(input), Err(DUPLICATE));
    }

    #[test]
    fn duplicate_with_identical_value_is_rejected() {
        let input = br#"{"alg":"HS256","kid":"a","alg":"HS256"}"#;
        assert_eq!(Header::from_json(input), Err(DUPLICATE));
    }

    #[test]
    fn duplicate_private_name_is_rejected() {
        let input = br#"{"alg":"HS256","exp":1,"exp":2}"#;
        assert_eq!(Header::from_json(input), Err(DUPLICATE));
    }

    #[test]
    fn duplicate_spelled_with_escapes_is_rejected() {
        // Names compare after JSON unescaping (RFC 8259 §7): "alg" is "alg".
        for input in [
            br#"{"alg":"HS256","alg":"none"}"#.as_slice(),
            br#"{"b64":true,"b64":false}"#.as_slice(),
            br#"{"x\/y":1,"x/y":2}"#.as_slice(),
        ] {
            assert_eq!(Header::from_json(input), Err(DUPLICATE));
        }
    }

    #[test]
    fn duplicate_in_crit_bearing_header_is_rejected() {
        let input = br#"{"alg":"HS256","b64":false,"crit":["b64"],"b64":true}"#;
        assert_eq!(Header::from_json(input), Err(DUPLICATE));
    }

    #[test]
    fn duplicate_in_nested_objects_is_rejected() {
        // jwk/epk are JWKs (RFC 7517 §4: reject or take the last; we reject),
        // and private objects get the same treatment for consistency.
        for input in [
            br#"{"jwk":{"kty":"oct","kty":"RSA"}}"#.as_slice(),
            br#"{"epk":{"kty":"EC","crv":"P-256","crv":"P-384"}}"#.as_slice(),
            br#"{"x-priv":{"a":1,"a":1}}"#.as_slice(),
            br#"{"x-priv":[{"a":{"b":1,"b":2}}]}"#.as_slice(),
        ] {
            assert_eq!(Header::from_json(input), Err(DUPLICATE), "{input:?}");
        }
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
}
