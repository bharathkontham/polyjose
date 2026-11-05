//! The owned JSON value tree (RFC 8259 §3).

use super::Number;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// A JSON value (RFC 8259 §3): `null`, `true`/`false`, a number, a string,
/// an array or an object.
///
/// Strings are Rust `String`s, so they are always valid Unicode scalar
/// values: the parser rejects invalid UTF-8 and lone surrogate escapes
/// (RFC 7493 §2.1).
///
/// Equality is structural, except that object member order is ignored
/// (an object is unordered, RFC 8259 §4) and numbers compare as doubles
/// (see [`Number`]).
///
/// # Secrets
///
/// A value may hold key material: a private JWK's `d`, `k`, `p`, `q`,
/// `dp`, `dq` and `qi` members (RFC 7517 §4, RFC 7518 §6) are strings. Every
/// string a `Value` owns, member names included, is a [`Zeroizing<String>`],
/// so its bytes are wiped when it is dropped, replaced or removed
/// (workspace secrets rule). The parser sizes each string's buffer before
/// filling it, so no reallocation leaves a stale copy, and partial results
/// are wiped on every error path. [`Zeroize`] wipes a value in place.
///
/// Not covered: the caller's input bytes, copies the caller makes (for
/// example with `as_str().to_owned()`), and [`to_json`](Value::to_json)
/// output, which the caller must wipe (see there). `Debug` prints strings as
/// `Zeroizing { .. }`.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// `null` (RFC 8259 §3).
    Null,
    /// `true` or `false` (RFC 8259 §3).
    Bool(bool),
    /// A finite number (RFC 8259 §6, RFC 7493 §2.2).
    Number(Number),
    /// A string (RFC 8259 §7), wiped on drop.
    String(Zeroizing<String>),
    /// An array (RFC 8259 §5).
    Array(Vec<Value>),
    /// An object (RFC 8259 §4) with unique member names.
    Object(Object),
}

impl Value {
    /// Whether this is `null`.
    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }

    /// The boolean, if this is `true` or `false`.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// The number, if this is a number.
    pub fn as_number(&self) -> Option<Number> {
        match self {
            Value::Number(n) => Some(*n),
            _ => None,
        }
    }

    /// The exact integer, if this is a number that is exactly an integer
    /// within ±(2^53 − 1) (RFC 7493 §2.2; see [`Number::as_i64`]).
    pub fn as_i64(&self) -> Option<i64> {
        self.as_number().and_then(|n| n.as_i64())
    }

    /// Like [`as_i64`](Value::as_i64), for non-negative integers only.
    pub fn as_u64(&self) -> Option<u64> {
        self.as_number().and_then(|n| n.as_u64())
    }

    /// The double, if this is a number.
    pub fn as_f64(&self) -> Option<f64> {
        self.as_number().map(|n| n.as_f64())
    }

    /// The string, if this is a string.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// The elements, if this is an array.
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    /// The object, if this is an object.
    pub fn as_object(&self) -> Option<&Object> {
        match self {
            Value::Object(o) => Some(o),
            _ => None,
        }
    }

    /// The object by value, if this is an object.
    pub fn into_object(self) -> Option<Object> {
        match self {
            Value::Object(o) => Some(o),
            _ => None,
        }
    }

    /// The member called `name`, if this is an object that has one.
    ///
    /// ```
    /// use polyjose::json::{Object, Value};
    ///
    /// let mut header = Object::new();
    /// header.insert("alg", "ES256");
    /// let v = Value::from(header);
    /// assert_eq!(v.get("alg").and_then(Value::as_str), Some("ES256"));
    /// assert!(v.get("kid").is_none());
    /// ```
    pub fn get(&self, name: &str) -> Option<&Value> {
        self.as_object().and_then(|o| o.get(name))
    }
}

impl Zeroize for Value {
    /// Wipes every string in the value (names and values, at every level)
    /// and leaves [`Value::Null`]. Recursion follows the nesting, which the
    /// parser caps at [`Limits::MAX_DEPTH_CEILING`](super::Limits::MAX_DEPTH_CEILING).
    fn zeroize(&mut self) {
        match self {
            Value::String(s) => s.zeroize(),
            Value::Array(items) => items.zeroize(),
            Value::Object(o) => o.zeroize(),
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
        *self = Value::Null;
    }
}

/// Every string a `Value` owns is a [`Zeroizing<String>`].
impl ZeroizeOnDrop for Value {}

impl From<bool> for Value {
    fn from(b: bool) -> Value {
        Value::Bool(b)
    }
}

impl From<Number> for Value {
    fn from(n: Number) -> Value {
        Value::Number(n)
    }
}

impl From<&str> for Value {
    fn from(s: &str) -> Value {
        Value::String(Zeroizing::new(s.to_owned()))
    }
}

impl From<String> for Value {
    fn from(s: String) -> Value {
        Value::String(Zeroizing::new(s))
    }
}

impl From<Vec<Value>> for Value {
    fn from(a: Vec<Value>) -> Value {
        Value::Array(a)
    }
}

impl From<Object> for Value {
    fn from(o: Object) -> Value {
        Value::Object(o)
    }
}

/// A JSON object (RFC 8259 §4): members in their original order, with
/// unique names.
///
/// Names are unique by construction: the parser rejects duplicates
/// (RFC 7515 §5.2, RFC 7516 §5.2, RFC 7493 §2.3) and
/// [`insert`](Object::insert) replaces. Members stay in parse or insertion
/// order, so the serializer reproduces it. Lookups are linear, which suits
/// the small objects JOSE uses.
///
/// Equality ignores member order (RFC 8259 §4: an object is unordered).
#[derive(Debug, Clone, Default)]
pub struct Object {
    members: Vec<(Zeroizing<String>, Value)>,
}

impl Object {
    /// An empty object.
    pub fn new() -> Object {
        Object::default()
    }

    /// Wraps members whose names the caller has already checked are unique.
    pub(crate) fn from_unique_members(members: Vec<(Zeroizing<String>, Value)>) -> Object {
        Object { members }
    }

    /// The number of members.
    pub fn len(&self) -> usize {
        self.members.len()
    }

    /// Whether the object has no members.
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// The value of the member called `name`.
    ///
    /// Names are compared as unescaped strings, code point by code point
    /// (RFC 8259 §8.3).
    pub fn get(&self, name: &str) -> Option<&Value> {
        self.members
            .iter()
            .find_map(|(n, v)| (n.as_str() == name).then_some(v))
    }

    /// Whether a member called `name` exists.
    pub fn contains(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    /// Sets member `name` to `value`.
    ///
    /// A new name is appended. An existing name keeps its position and its
    /// old value is returned, so names stay unique. The returned value, like
    /// any `Value`, wipes its strings when dropped, and so does the unused
    /// copy of `name`.
    ///
    /// ```
    /// use polyjose::json::{Object, Value};
    ///
    /// let mut o = Object::new();
    /// assert_eq!(o.insert("typ", "JWT"), None);
    /// assert_eq!(o.insert("typ", "at+jwt"), Some(Value::from("JWT")));
    /// assert_eq!(o.len(), 1);
    /// ```
    pub fn insert(&mut self, name: impl Into<String>, value: impl Into<Value>) -> Option<Value> {
        let name = Zeroizing::new(name.into());
        let value = value.into();
        match self
            .members
            .iter_mut()
            .find(|(n, _)| n.as_str() == name.as_str())
        {
            Some((_, slot)) => Some(core::mem::replace(slot, value)),
            None => {
                self.members.push((name, value));
                None
            }
        }
    }

    /// Removes member `name`, returning its value. Later members keep
    /// their relative order. The removed name is wiped; the returned value
    /// wipes its strings when dropped.
    pub fn remove(&mut self, name: &str) -> Option<Value> {
        let index = self.members.iter().position(|(n, _)| n.as_str() == name)?;
        Some(self.members.remove(index).1)
    }

    /// Reorders the members by name, in Unicode code point order.
    ///
    /// This is the order RFC 7638 §3.3 requires for JWK Thumbprint input.
    /// Rust compares `str` by UTF-8 bytes, and UTF-8 byte order is code
    /// point order.
    pub fn sort_members(&mut self) {
        self.members
            .sort_unstable_by(|(a, _), (b, _)| a.as_str().cmp(b.as_str()));
    }

    /// The members as `(name, value)` pairs, in order.
    pub fn iter(&self) -> Iter<'_> {
        Iter(self.members.iter())
    }
}

impl Zeroize for Object {
    /// Wipes every member name and value, then removes all members.
    fn zeroize(&mut self) {
        for (name, value) in &mut self.members {
            name.zeroize();
            value.zeroize();
        }
        self.members.clear();
    }
}

/// Member names are [`Zeroizing<String>`]s and values are [`Value`]s.
impl ZeroizeOnDrop for Object {}

impl PartialEq for Object {
    /// Order-insensitive: same names, and equal values for each name.
    fn eq(&self, other: &Object) -> bool {
        self.len() == other.len()
            && self
                .members
                .iter()
                .all(|(name, value)| other.get(name) == Some(value))
    }
}

/// Iterator over an [`Object`]'s members, in order.
#[derive(Debug, Clone)]
pub struct Iter<'a>(core::slice::Iter<'a, (Zeroizing<String>, Value)>);

impl<'a> Iterator for Iter<'a> {
    type Item = (&'a str, &'a Value);

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|(n, v)| (n.as_str(), v))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }
}

impl ExactSizeIterator for Iter<'_> {}

impl<'a> IntoIterator for &'a Object {
    type Item = (&'a str, &'a Value);
    type IntoIter = Iter<'a>;

    fn into_iter(self) -> Iter<'a> {
        self.iter()
    }
}

/// Owning iterator over an [`Object`]'s members, in order. Names stay
/// [`Zeroizing`], and members not taken are wiped when it is dropped.
#[derive(Debug)]
pub struct IntoIter(std::vec::IntoIter<(Zeroizing<String>, Value)>);

impl Iterator for IntoIter {
    type Item = (Zeroizing<String>, Value);

    fn next(&mut self) -> Option<(Zeroizing<String>, Value)> {
        self.0.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }
}

impl ExactSizeIterator for IntoIter {}

impl IntoIterator for Object {
    type Item = (Zeroizing<String>, Value);
    type IntoIter = IntoIter;

    fn into_iter(self) -> IntoIter {
        IntoIter(self.members.into_iter())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::ZeroizeOnDrop;

    fn int(i: i64) -> Value {
        Number::from_i64(i).map_or(Value::Null, Value::Number)
    }

    fn sample() -> Object {
        let mut o = Object::new();
        o.insert("kty", "EC");
        o.insert("n", int(3));
        o.insert("ok", true);
        o.insert("list", vec![Value::Null, Value::from("x")]);
        o
    }

    #[test]
    fn accessors_match_only_their_own_variant() {
        let o = sample();
        assert_eq!(o.get("kty").and_then(Value::as_str), Some("EC"));
        assert_eq!(o.get("n").and_then(Value::as_i64), Some(3));
        assert_eq!(o.get("n").and_then(Value::as_u64), Some(3));
        assert_eq!(o.get("n").and_then(Value::as_f64), Some(3.0));
        assert_eq!(o.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            o.get("list").and_then(Value::as_array).map(<[_]>::len),
            Some(2)
        );
        assert!(
            o.get("list")
                .and_then(Value::as_array)
                .is_some_and(|a| a[0].is_null())
        );

        let s = Value::from("1");
        assert_eq!(s.as_i64(), None);
        assert_eq!(s.as_bool(), None);
        assert_eq!(s.as_array(), None);
        assert!(s.as_object().is_none());
        assert!(s.get("kty").is_none());
        assert!(!s.is_null());
        assert_eq!(Value::Bool(true).as_str(), None);
        assert_eq!(Value::Null.as_number(), None);
    }

    #[test]
    fn get_and_into_object_on_values() {
        let v = Value::from(sample());
        assert_eq!(v.get("kty").and_then(Value::as_str), Some("EC"));
        assert!(v.get("missing").is_none());
        assert_eq!(v.into_object().map(|o| o.len()), Some(4));
        assert!(Value::Null.into_object().is_none());
    }

    #[test]
    fn insert_keeps_names_unique_and_position_stable() {
        let mut o = sample();
        assert_eq!(o.insert("n", int(4)), Some(int(3)));
        let names: Vec<&str> = o.iter().map(|(n, _)| n).collect();
        assert_eq!(names, ["kty", "n", "ok", "list"]);
        assert_eq!(o.get("n"), Some(&int(4)));
        assert!(o.contains("ok"));
        assert!(!o.contains("OK"));
    }

    #[test]
    fn remove_takes_one_member_and_keeps_the_rest_in_order() {
        let mut o = sample();
        assert_eq!(o.remove("n"), Some(int(3)));
        assert_eq!(o.remove("n"), None);
        let names: Vec<&str> = o.iter().map(|(n, _)| n).collect();
        assert_eq!(names, ["kty", "ok", "list"]);
    }

    #[test]
    fn sort_members_uses_code_point_order() {
        let mut o = Object::new();
        for name in [
            "y",
            "\u{e9}",
            "crv",
            "x",
            "kty",
            "Z",
            "\u{1F600}",
            "\u{ffff}",
        ] {
            o.insert(name, Value::Null);
        }
        o.sort_members();
        let names: Vec<&str> = o.iter().map(|(n, _)| n).collect();
        assert_eq!(
            names,
            [
                "Z",
                "crv",
                "kty",
                "x",
                "y",
                "\u{e9}",
                "\u{ffff}",
                "\u{1F600}"
            ]
        );
    }

    #[test]
    fn object_equality_ignores_member_order() {
        let mut a = Object::new();
        a.insert("a", int(1));
        a.insert("b", int(2));
        let mut b = Object::new();
        b.insert("b", int(2));
        b.insert("a", int(1));
        assert_eq!(a, b);
        b.insert("a", int(9));
        assert_ne!(a, b);
        b.insert("a", int(1));
        b.insert("c", int(3));
        assert_ne!(a, b);
        assert!(Object::new().is_empty());
    }

    #[test]
    fn iterators_yield_members_in_order() {
        let o = sample();
        assert_eq!(o.iter().len(), 4);
        let borrowed: Vec<String> = (&o).into_iter().map(|(n, _)| n.to_owned()).collect();
        let owned: Vec<String> = o.into_iter().map(|(n, _)| n.as_str().to_owned()).collect();
        assert_eq!(borrowed, owned);
        assert_eq!(owned, ["kty", "n", "ok", "list"]);
    }

    #[test]
    fn from_conversions_pick_the_matching_variant() {
        assert_eq!(Value::from(false), Value::Bool(false));
        assert_eq!(
            Value::from("s"),
            Value::String(Zeroizing::new("s".to_owned()))
        );
        assert_eq!(
            Value::from(String::from("s")),
            Value::String(Zeroizing::new("s".to_owned()))
        );
        assert_eq!(Value::from(Vec::new()), Value::Array(Vec::new()));
        assert_eq!(Value::from(Object::new()), Value::Object(Object::new()));
        assert_eq!(
            Number::from_f64(0.5)
                .map(Value::from)
                .and_then(|v| v.as_f64()),
            Some(0.5)
        );
    }

    fn assert_zeroize_on_drop<T: Zeroize + ZeroizeOnDrop>() {}

    #[test]
    fn values_and_objects_zeroize_their_strings_on_drop() {
        // JWK private members (RFC 7517 §4, RFC 7518 §6) pass through these
        // types, so every string they own is wiped when dropped.
        assert_zeroize_on_drop::<Value>();
        assert_zeroize_on_drop::<Object>();
        let Value::String(payload) = Value::from("secret") else {
            unreachable!("From<&str> builds a string")
        };
        let _: &Zeroizing<String> = &payload;
        let names: Vec<Zeroizing<String>> = sample().into_iter().map(|(n, _)| n).collect();
        assert_eq!(names.len(), 4);
    }

    #[test]
    fn zeroize_wipes_a_value_in_place() {
        let mut v = Value::from(vec![Value::from("d"), Value::from(sample())]);
        v.zeroize();
        assert!(v.is_null());
        let mut o = sample();
        o.zeroize();
        assert!(o.is_empty());
        let mut s = Value::from(String::from("k"));
        s.zeroize();
        assert!(s.is_null());
    }

    #[test]
    fn replaced_and_removed_members_come_back_zeroizing() {
        let mut o = sample();
        let old = o.insert("kty", "oct");
        assert!(matches!(old, Some(Value::String(_))));
        let removed = o.remove("kty");
        assert_eq!(removed.as_ref().and_then(Value::as_str), Some("oct"));
    }
}
