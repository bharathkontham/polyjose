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
}
