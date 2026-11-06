//! The JWT Claims Set (RFC 7519 §4): typed registered claims, every other
//! claim kept as a [`Value`] (ADR 0027 §1).

use crate::error::{Error, Result};
use crate::json::{Object, Value};

use super::NumericDate;

/// The seven registered claim names of RFC 7519 §4.1, in the order they
/// are serialized and checked for presence (ADR 0027 §1, §9 J4).
pub(crate) const REGISTERED_CLAIMS: [&str; 7] = ["iss", "sub", "aud", "exp", "nbf", "iat", "jti"];

/// The `aud` claim (RFC 7519 §4.1.3), in the form it was received, so it
/// re-serializes unchanged.
///
/// "In the general case, the "aud" value is an array of case-sensitive
/// strings", and with one audience it "MAY be a single case-sensitive
/// string" (RFC 7519 §4.1.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Audience {
    /// A single string.
    One(String),
    /// An array of strings, in order. It may be empty, which matches no
    /// audience (ADR 0027 §4).
    Many(Vec<String>),
}

impl Audience {
    /// The audience values, whatever the form: one for
    /// [`One`](Audience::One), the array for [`Many`](Audience::Many).
    ///
    /// ```
    /// use polyjose::jwt::Audience;
    ///
    /// assert_eq!(Audience::One("api".into()).values(), ["api"]);
    /// assert!(Audience::Many(vec![]).values().is_empty());
    /// ```
    pub fn values(&self) -> &[String] {
        match self {
            Audience::One(aud) => core::slice::from_ref(aud),
            Audience::Many(auds) => auds,
        }
    }
}

/// A JWT Claims Set (RFC 7519 §4).
///
/// The registered claims of RFC 7519 §4.1 are typed fields; every other
/// claim, public or private (RFC 7519 §4.2–§4.3), is kept as a
/// [`Value`] in insertion order and reached with [`get`](Claims::get) and
/// [`insert`](Claims::insert). Validation ignores claims it does not
/// understand (RFC 7519 §4).
///
/// ```
/// use polyjose::json::Value;
/// use polyjose::jwt::{Audience, Claims, NumericDate};
///
/// let mut claims = Claims::new();
/// claims.iss = Some("joe".into());
/// claims.aud = Some(Audience::One("https://api.example".into()));
/// claims.exp = NumericDate::from_secs(1300819380);
/// claims.insert("http://example.com/is_root", Value::Bool(true))?;
/// assert_eq!(
///     claims.get("http://example.com/is_root"),
///     Some(&Value::Bool(true))
/// );
///
/// // Registered claims live in their typed fields.
/// assert!(claims.insert("exp", Value::Null).is_err());
/// # Ok::<(), polyjose::Error>(())
/// ```
///
/// `Debug` prints the claim values; other claims print through [`Value`]'s
/// `Debug`, which redacts strings.
#[derive(Debug, Clone, PartialEq, Default)]
#[non_exhaustive]
pub struct Claims {
    /// `iss`, the issuer: a case-sensitive StringOrURI (RFC 7519 §4.1.1).
    pub iss: Option<String>,
    /// `sub`, the subject: a case-sensitive StringOrURI (RFC 7519 §4.1.2).
    pub sub: Option<String>,
    /// `aud`, the audience (RFC 7519 §4.1.3).
    pub aud: Option<Audience>,
    /// `exp`, the expiration time (RFC 7519 §4.1.4).
    pub exp: Option<NumericDate>,
    /// `nbf`, the not-before time (RFC 7519 §4.1.5).
    pub nbf: Option<NumericDate>,
    /// `iat`, the issued-at time (RFC 7519 §4.1.6).
    pub iat: Option<NumericDate>,
    /// `jti`, the JWT ID: a case-sensitive string (RFC 7519 §4.1.7).
    pub jti: Option<String>,
    /// Every other claim (RFC 7519 §4.2–§4.3), in insertion order. Never
    /// holds a registered name, so serializing cannot duplicate one.
    other: Object,
}

impl Claims {
    /// An empty Claims Set: no registered and no other claims.
    pub fn new() -> Self {
        Self::default()
    }

    /// Parses a JWT Claims Set from the JWS payload octets (RFC 7519 §7.2
    /// step 10), directly, without a second base64url decoding (reported
    /// erratum 8225; ADR 0027 §1).
    ///
    /// **Not implemented yet** (feature 0004 T03): returns
    /// [`Error::UnsupportedAlgorithm`].
    ///
    /// # Errors
    ///
    /// [`Error::InvalidJson`] if the octets are not UTF-8, not one JSON
    /// object, or repeat a member name (RFC 7519 §4, §7.2 step 10);
    /// [`Error::InvalidClaim`]`(name)` if a registered claim has the wrong
    /// type, `null` included (ADR 0027 §1–§2).
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let _ = bytes;
        Err(Error::UnsupportedAlgorithm)
    }

    /// Serializes the Claims Set as compact JSON (RFC 7519 §7.1 step 1):
    /// the registered claims in the order `iss, sub, aud, exp, nbf, iat,
    /// jti`, then the other claims in insertion order (ADR 0027 §1).
    ///
    /// **Not implemented yet** (feature 0004 T03): returns an empty
    /// string.
    pub fn to_json(&self) -> String {
        String::new()
    }

    /// The claim `name` if it is not a registered claim (RFC 7519
    /// §4.2–§4.3). A registered name returns `None`: read its typed field.
    pub fn get(&self, name: &str) -> Option<&Value> {
        if registered(name).is_some() {
            return None;
        }
        self.other.get(name)
    }

    /// Sets the public or private claim `name` (RFC 7519 §4.2–§4.3),
    /// returning its previous value. A new name is appended.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidClaim`]`(name)` if `name` is a registered claim
    /// (RFC 7519 §4.1): set its typed field instead, so a Claims Set can
    /// never hold the same name twice (RFC 7519 §4).
    pub fn insert(
        &mut self,
        name: impl Into<String>,
        value: impl Into<Value>,
    ) -> Result<Option<Value>> {
        let name = name.into();
        if let Some(registered) = registered(&name) {
            return Err(Error::InvalidClaim(registered));
        }
        Ok(self.other.insert(name, value))
    }

    /// Every claim that is not a registered one (RFC 7519 §4.2–§4.3), in
    /// insertion order.
    pub fn other_claims(&self) -> &Object {
        &self.other
    }
}

/// The registered claim name equal to `name`, as a `'static` string for
/// error details.
fn registered(name: &str) -> Option<&'static str> {
    REGISTERED_CLAIMS.into_iter().find(|claim| *claim == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registered_names_are_refused_by_insert_and_hidden_from_get() {
        let mut claims = Claims::new();
        for name in REGISTERED_CLAIMS {
            assert_eq!(
                claims.insert(name, Value::Null),
                Err(Error::InvalidClaim(name))
            );
            assert_eq!(claims.get(name), None);
        }
        claims.exp = NumericDate::from_secs(1);
        assert_eq!(claims.get("exp"), None);
        assert!(claims.other_claims().is_empty());
    }

    #[test]
    fn other_claims_keep_insertion_order_and_replace_in_place() {
        let mut claims = Claims::new();
        assert_eq!(claims.insert("b", Value::from("1")), Ok(None));
        assert_eq!(claims.insert("a", Value::Bool(true)), Ok(None));
        assert_eq!(claims.insert("b", Value::Null), Ok(Some(Value::from("1"))));
        let names: Vec<&str> = claims.other_claims().iter().map(|(n, _)| n).collect();
        assert_eq!(names, ["b", "a"]);
        assert_eq!(claims.get("b"), Some(&Value::Null));
        assert_eq!(claims.get("missing"), None);
        // Close to a registered name is not one.
        assert_eq!(claims.insert("EXP", Value::Null), Ok(None));
    }

    #[test]
    fn audience_values() {
        assert_eq!(Audience::One("a".into()).values(), ["a"]);
        assert_eq!(
            Audience::Many(vec!["a".into(), "b".into()]).values(),
            ["a", "b"]
        );
        assert!(Audience::Many(Vec::new()).values().is_empty());
    }

    #[test]
    fn new_is_empty() {
        let claims = Claims::new();
        assert_eq!(claims, Claims::default());
        assert!(claims.iss.is_none() && claims.exp.is_none() && claims.aud.is_none());
    }

    /// The payload segment of the RFC 7519 §3.1 example JWT.
    const RFC7519_3_1_PAYLOAD_B64: &str = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";

    /// The RFC 7519 §3.1 JWT Claims Set octets, CRLF and leading spaces
    /// included.
    const RFC7519_3_1_CLAIMS: &[u8] =
        b"{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";

    fn claims(json: &str) -> Result<Claims> {
        Claims::from_json(json.as_bytes())
    }

    fn is_invalid_json<T>(result: &Result<T>) -> bool {
        matches!(result, Err(Error::InvalidJson(_)))
    }

    #[test]
    fn rfc7519_section_3_1_claims_parse() {
        let octets = crate::util::b64url_decode(RFC7519_3_1_PAYLOAD_B64).unwrap();
        assert_eq!(octets, RFC7519_3_1_CLAIMS);

        let c = Claims::from_json(RFC7519_3_1_CLAIMS).unwrap();
        assert_eq!(c.iss.as_deref(), Some("joe"));
        assert_eq!(c.exp.and_then(|d| d.as_secs()), Some(1_300_819_380));
        assert_eq!(
            c.get("http://example.com/is_root"),
            Some(&Value::Bool(true))
        );
        assert!(c.sub.is_none() && c.aud.is_none() && c.jti.is_none());
        assert!(c.nbf.is_none() && c.iat.is_none());
        assert_eq!(c.other_claims().len(), 1);
    }

    #[test]
    fn iss_sub_jti_must_be_strings() {
        // RFC 7519 §4.1.1, §4.1.2, §4.1.7; ADR 0027 §1: `null` included.
        for (json, name) in [
            (r#"{"iss":1}"#, "iss"),
            (r#"{"sub":null}"#, "sub"),
            (r#"{"jti":[]}"#, "jti"),
            (r#"{"iss":true}"#, "iss"),
            (r#"{"sub":{}}"#, "sub"),
            (r#"{"jti":1.5}"#, "jti"),
            (r#"{"iss":["joe"]}"#, "iss"),
        ] {
            assert_eq!(claims(json), Err(Error::InvalidClaim(name)), "{json}");
        }
        let c = claims(r#"{"jti":"j","sub":"s","iss":"i"}"#).unwrap();
        assert_eq!(c.iss.as_deref(), Some("i"));
        assert_eq!(c.sub.as_deref(), Some("s"));
        assert_eq!(c.jti.as_deref(), Some("j"));
        // An empty string is a string (RFC 7519 §2 StringOrURI).
        assert_eq!(claims(r#"{"iss":""}"#).unwrap().iss.as_deref(), Some(""));
        // Escapes are unescaped; values are not normalized (RFC 7519 §7.3).
        let c = claims(r#"{"sub":"Joe"}"#).unwrap();
        assert_eq!(c.sub.as_deref(), Some("Joe"));
    }

    #[test]
    fn aud_is_a_string_or_an_array_of_strings_in_its_received_form() {
        // RFC 7519 §4.1.3; ADR 0027 §1, §4.
        let aud = |json: &str| claims(json).map(|c| c.aud);
        assert_eq!(aud(r#"{"aud":"a"}"#), Ok(Some(Audience::One("a".into()))));
        assert_eq!(
            aud(r#"{"aud":["b","a"]}"#),
            Ok(Some(Audience::Many(vec!["b".into(), "a".into()])))
        );
        assert_eq!(
            aud(r#"{"aud":["a"]}"#),
            Ok(Some(Audience::Many(vec!["a".into()])))
        );
        assert_eq!(aud(r#"{"aud":[]}"#), Ok(Some(Audience::Many(Vec::new()))));
        for json in [
            r#"{"aud":["a",1]}"#,
            r#"{"aud":{}}"#,
            r#"{"aud":null}"#,
            r#"{"aud":1}"#,
            r#"{"aud":true}"#,
            r#"{"aud":[null]}"#,
            r#"{"aud":[["a"]]}"#,
            r#"{"aud":["a",{"b":"c"}]}"#,
        ] {
            assert_eq!(aud(json), Err(Error::InvalidClaim("aud")), "{json}");
        }
    }

    #[test]
    fn exp_nbf_iat_are_numeric_dates() {
        // RFC 7519 §2, §4.1.4–§4.1.6; ADR 0027 §2 through NumericDate::from_json.
        for name in ["exp", "nbf", "iat"] {
            let date = |value: &str| {
                claims(&format!(r#"{{"{name}":{value}}}"#)).map(|c| match name {
                    "exp" => c.exp,
                    "nbf" => c.nbf,
                    _ => c.iat,
                })
            };
            for bad in [
                r#""1300819380""#,
                "9007199254740992",
                "-9007199254740992",
                "null",
                "true",
                "[]",
                "{}",
            ] {
                assert_eq!(date(bad), Err(Error::InvalidClaim(name)), "{name}: {bad}");
            }
            for (good, secs) in [
                ("1300819380.25", 1_300_819_380.25),
                ("-5", -5.0),
                ("0", 0.0),
                ("9007199254740991", 9_007_199_254_740_991.0),
                ("1e3", 1000.0),
            ] {
                let got = date(good).unwrap().map(|d| d.as_f64());
                assert_eq!(got, Some(secs), "{name}: {good}");
            }
        }
    }

    #[test]
    fn registered_claim_errors_follow_the_registered_order() {
        // Deterministic whatever the member order: the order of
        // REGISTERED_CLAIMS (ADR 0027 §9 J3–J4).
        assert_eq!(
            claims(r#"{"jti":1,"exp":"x","sub":1}"#),
            Err(Error::InvalidClaim("sub"))
        );
        assert_eq!(
            claims(r#"{"jti":1,"iat":"x","aud":[1]}"#),
            Err(Error::InvalidClaim("aud"))
        );
        assert_eq!(
            claims(r#"{"jti":1,"iat":"x"}"#),
            Err(Error::InvalidClaim("iat"))
        );
    }

    #[test]
    fn json_level_problems_are_invalid_json() {
        // RFC 7519 §4 (duplicates rejected), §7.2 step 10; ADR 0027 §1.
        let inputs: [&[u8]; 17] = [
            br#"{"exp":1,"exp":2}"#,
            br#"{"exp":1,"exp":2}"#,
            br#"{"iss":"a","iss":"a"}"#,
            br#"{"x":1,"x":2}"#,
            br#"{"x":{"a":1,"a":2}}"#,
            b"{\"iss\":\"\xff\"}",
            b"\xef\xbb\xbf{}",
            b"[]",
            br#"[{"iss":"joe"}]"#,
            br#""joe""#,
            b"1300819380",
            b"null",
            b"true",
            br#"{"iss":"joe"}x"#,
            b"{} {}",
            b"",
            b"{",
        ];
        for input in inputs {
            assert!(
                is_invalid_json(&Claims::from_json(input)),
                "{:?}",
                String::from_utf8_lossy(input)
            );
        }
        // JSON problems are found before claim types.
        assert!(is_invalid_json(&claims(r#"{"iss":1,"iss":2}"#)));
    }

    #[test]
    fn other_claims_are_kept_as_values_in_order() {
        // RFC 7519 §4.2–§4.3; ADR 0027 §1.
        let c = claims(
            r#"{"z":{"nested":[1,{"deep":"v"}]},"iss":"joe","a":[true,null],"m":"s","n":-1.5}"#,
        )
        .unwrap();
        let names: Vec<&str> = c.other_claims().iter().map(|(n, _)| n).collect();
        assert_eq!(names, ["z", "a", "m", "n"]);
        assert_eq!(c.iss.as_deref(), Some("joe"));
        let deep = c
            .get("z")
            .and_then(|z| z.get("nested"))
            .and_then(Value::as_array)
            .and_then(|items| items.get(1))
            .and_then(|o| o.get("deep"))
            .and_then(Value::as_str);
        assert_eq!(deep, Some("v"));
        assert_eq!(
            c.get("a"),
            Some(&Value::Array(vec![Value::Bool(true), Value::Null]))
        );
        assert_eq!(c.get("m").and_then(Value::as_str), Some("s"));
        assert_eq!(c.get("n").and_then(Value::as_f64), Some(-1.5));
        // Registered names stay in the typed fields.
        for name in REGISTERED_CLAIMS {
            assert_eq!(c.get(name), None);
        }
        // Names that only resemble registered ones are other claims.
        let c = claims(r#"{"EXP":"x","iss ":1}"#).unwrap();
        assert!(c.exp.is_none() && c.iss.is_none());
        assert_eq!(c.get("EXP").and_then(Value::as_str), Some("x"));
        assert_eq!(c.get("iss ").and_then(Value::as_i64), Some(1));
        // The empty object is an empty Claims Set.
        assert_eq!(claims("{}"), Ok(Claims::new()));
        assert_eq!(claims(" \r\n{ }\t"), Ok(Claims::new()));
    }
}
