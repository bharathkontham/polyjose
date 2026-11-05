//! polyjose's own JSON: RFC 8259 with the I-JSON constraints of RFC 7493.
//!
//! JOSE Headers, JWT Claims Sets and JWKs are JSON objects, and they arrive
//! from untrusted parties. polyjose parses them with this module instead of
//! a general-purpose JSON crate (ADR 0016), because JOSE needs rules those
//! crates do not enforce, most importantly rejecting duplicate member names
//! (RFC 7515 §5.2 step 4, RFC 7516 §5.2 step 4).
//!
//! ```
//! use polyjose::json::{parse, Object, Value};
//!
//! let header = parse(br#"{"alg":"ES256","kid":"k1"}"#)?;
//! assert_eq!(header.get("alg").and_then(Value::as_str), Some("ES256"));
//!
//! // Duplicate names are rejected, even when spelled differently.
//! assert!(parse(br#"{"alg":"ES256","\u0061lg":"none"}"#).is_err());
//!
//! // Building and serializing is deterministic.
//! let mut o = Object::new();
//! o.insert("typ", "JWT");
//! o.insert("alg", "HS256");
//! assert_eq!(o.to_json(), r#"{"typ":"JWT","alg":"HS256"}"#);
//! # Ok::<(), polyjose::Error>(())
//! ```
//!
//! # What the parser accepts
//!
//! [`parse`](crate::json::parse) (and
//! [`parse_with_limits`](crate::json::parse_with_limits)) accepts exactly one
//! RFC 8259 JSON text, of any type, with these restrictions. Every failure is
//! [`InvalidJson`](crate::Error::InvalidJson) with a fixed detail
//! that never contains input bytes (ADR 0007), and no input can make it
//! panic or recurse without bound.
//!
//! - **UTF-8 only** (RFC 8259 §8.1, RFC 7493 §2.1). Invalid UTF-8 anywhere,
//!   including overlong forms and encoded surrogates, is rejected, as are
//!   UTF-16 and UTF-32 texts.
//! - **No byte order mark.** RFC 8259 §8.1 lets parsers ignore a leading
//!   U+FEFF; polyjose rejects it so that a signed header has one encoding.
//! - **Strict grammar** (RFC 8259 §2–§7): only the four whitespace
//!   characters, lowercase literals, no leading zeros, `+`, bare `.`,
//!   `NaN` or `Infinity`, no trailing commas, no comments, no unescaped
//!   control characters in strings, only the escapes RFC 8259 §7 lists,
//!   and nothing after the value.
//! - **No lone surrogates** (RFC 7493 §2.1). A `\uD800`–`\uDBFF` escape
//!   must be followed by a `\uDC00`–`\uDFFF` escape, so strings are always
//!   valid Rust `String`s. Noncharacters such as U+FFFE are Unicode scalar
//!   values and are accepted: RFC 7493 §2.1 addresses them to senders.
//! - **No duplicate member names** (RFC 7515 §5.2, RFC 7516 §5.2,
//!   RFC 7493 §2.3), at any nesting level, compared after unescaping and
//!   code point by code point (RFC 8259 §8.3).
//! - **Finite numbers only** (RFC 8259 §6, RFC 7493 §2.2): a number that
//!   rounds to an infinity, like `1e400`, is rejected. See
//!   [`Number`](crate::json::Number) for how exact integers are kept.
//! - **[`Limits`](crate::json::Limits)**: nesting depth 32, 1 MiB of input
//!   and 10 000 entries per object or array by default (RFC 8259 §9).
//!
//! JSONTestSuite (`tests/third_party/JSONTestSuite`) is run in full: every
//! `y_` case is accepted except the two with duplicate names, every `n_`
//! case is rejected, and every `i_` case has a documented result.
//!
//! # Serializing
//!
//! [`Value::to_json`](crate::json::Value::to_json) and
//! [`Object::to_json`](crate::json::Object::to_json) write compact JSON with
//! minimal escaping and one canonical number form, in member order. The
//! output is a deterministic function of the value, which RFC 7638
//! thumbprints rely on (with
//! [`Object::sort_members`](crate::json::Object::sort_members)).
//!
//! # Secrets
//!
//! Private JWK members are strings in a [`Value`](crate::json::Value), so
//! every string the parser builds or a `Value` owns is wiped on drop: it is
//! a `zeroize::Zeroizing<String>`, its buffer is sized up front so it never
//! reallocates, and partial results are wiped on error paths. The
//! serializer allocates its output once at the exact size, but the
//! returned `String` is the caller's to wipe. See the `Value` docs for what
//! is not covered.
//!
//! # Fuzzing
//!
//! [`parse`](crate::json::parse) takes raw bytes and has no other inputs, so
//! a `cargo fuzz` target can call it directly.

mod number;
mod parse;
mod value;
mod write;

pub use number::{MAX_SAFE_INTEGER, Number};
pub use parse::{Limits, parse, parse_with_limits};
pub use value::{IntoIter, Iter, Object, Value};
