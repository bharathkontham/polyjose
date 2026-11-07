//! JWK Set (RFC 7517 §5) and key selection: [`JwkSet::select`] and
//! [`JwkSet::matching`] (ADR 0054), and verification key selection
//! (ADR 0029 §2), all on one candidate rule (ADR 0054 §2, §6).
//!
//! The public contract is documented on [`JwkSet`] and [`JwkSelector`].
//! The alg → key family tables selection uses are
//! [`KeyMaterial::serves_signing_alg`] and
//! [`KeyMaterial::serves_key_mgmt_alg`] (ADR 0026 §2 step 8), the single
//! copies JWS and JWE key binding also use, and the JWE `key_ops` of an
//! `alg` come from the JWE key model (`jwe/key.rs`), not a copy.
//!
//! [`KeyMaterial::serves_signing_alg`]: super::KeyMaterial::serves_signing_alg
//! [`KeyMaterial::serves_key_mgmt_alg`]: super::KeyMaterial::serves_key_mgmt_alg

use core::fmt;

use zeroize::ZeroizeOnDrop;

use super::{
    Jwk, KeyAlg, KeyMaterial, KeyOp, KeyUse, MemberNames, is_rsa_private_key,
    is_unsupported_key_kind, member,
};
use crate::error::{Error, Result};
use crate::json::{self, Object, Value};
use crate::jwa::{KeyMgmtAlg, SigningAlg};
use crate::jwe::key_ops_either_direction;

/// Detail for a JWK Set document that is valid JSON but not an object.
const NOT_AN_OBJECT: &str = "a JWK Set must be a JSON object";
/// Detail for a JWK Set without a `keys` array (RFC 7517 §5).
const NO_KEYS_ARRAY: &str = "a JWK Set must have a keys member that is an array";

/// A JWK Set (RFC 7517 §5): the usable keys of a `{"keys":[...]}`
/// document, in document order, plus its other top-level members.
///
/// Build one with [`JwkSet::from_json`] (untrusted bytes) or
/// [`JwkSet::from_object`] (an already-parsed object). Pick one key with
/// [`JwkSet::select`], every key a [`JwkSelector`] matches with
/// [`JwkSet::matching`] (ADR 0054), and the keys that may verify a JWS
/// with [`JwkSet::verification_candidates`] (ADR 0029 §2). All three
/// apply the one rule documented on [`JwkSelector`].
///
/// # What import keeps
///
/// | `keys` entry | outcome |
/// |---|---|
/// | a valid, supported JWK | kept, in document order |
/// | unsupported `kty`, or `EC`/`OKP` `crv` (`XYZ`, `Ed448`, `P-192`, ...) | skipped (RFC 7517 §5, ADR 0029 §3) |
/// | otherwise invalid (not an object, missing or mistyped members, wrong lengths, bad base64url, an RSA modulus under 2048 or over 8192 bits (`RSA_MODULUS_BITS`: RFC 7518 §3.3, ADR 0026 §2 step 8), an EC point off its curve, an EC `d` out of range, an invalid or small-order Ed25519 key, ...) | skipped (RFC 7517 §5, ADR 0041 §2) |
/// | an `alg` of `RSA1_5` or `RSA-OAEP`, or one the key's family cannot serve (`oct` with `RS256`, `EC` `P-256` with `ES384`, ...) | skipped (RFC 7517 §4.4, §5; ADRs 0021, 0022) |
/// | an RSA private key | the whole set fails, [`Error::UnsupportedAlgorithm`] (ADR 0021) |
///
/// Skipping invalid entries, rather than failing the set, follows the
/// RFC 7517 §5 "SHOULD ignore" for members "missing required members, or
/// for which values are out of the supported ranges" (a 0001-T07 lead
/// decision; ADR 0029 §3 left the choice to T07). Skipping can only remove
/// verification candidates, never add one, and [`JwkSet::skipped`] counts
/// what was left out. An entry's validation is that of
/// [`Jwk::from_object`].
///
/// Document-level problems always fail: JSON errors, including a duplicate
/// member name anywhere in the document, are [`Error::InvalidJson`], and a
/// missing or non-array `keys` is [`Error::InvalidKey`].
///
/// # Indexes
///
/// A `key_index` (ADR 0029 §4) is an index into [`JwkSet::keys`], which
/// leaves skipped entries out, so it is deterministic for a given document
/// and polyjose version. A later version that supports more key types may
/// keep entries this one skips: identify keys across versions by `kid`.
///
/// # Secrets
///
/// `oct` keys, and `EC`/`OKP` keys with `d`, are secret. Every key is a
/// [`Jwk`], wiped on drop, and `Debug` prints each key's redacted `Debug`
/// and only the *names* of the other top-level members.
///
/// ```
/// use polyjose::Error;
/// use polyjose::jwk::JwkSet;
///
/// // RFC 7517 §5: a key type polyjose does not know is ignored.
/// let set = JwkSet::from_json(br#"{"keys":[
///     {"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","kid":"ed"},
///     {"kty":"XYZ","kid":"unknown"}
/// ]}"#)?;
/// assert_eq!((set.len(), set.skipped()), (1, 1));
/// assert_eq!(set.keys()[0].kid(), Some("ed"));
///
/// // ADR 0021: an RSA private key fails the whole set.
/// let leaked = br#"{"keys":[{"kty":"RSA","n":"AQAB","e":"AQAB","d":"AQAB"}]}"#;
/// assert_eq!(JwkSet::from_json(leaked).unwrap_err(), Error::UnsupportedAlgorithm);
/// # Ok::<(), polyjose::Error>(())
/// ```
#[derive(Clone)]
pub struct JwkSet {
    /// The members that imported as a [`Jwk`], in document order.
    keys: Vec<Jwk>,
    /// How many `keys` entries were skipped (RFC 7517 §5).
    skipped: usize,
    /// Top-level members other than `keys`, in input order (RFC 7517 §5:
    /// "Additional members can be present"). Never contains `keys`.
    other: Object,
}

impl JwkSet {
    /// Parses a JWK Set from its UTF-8 JSON bytes.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidJson`] if the bytes are not one I-JSON object:
    ///   a syntax error, a member name that occurs twice anywhere in the
    ///   document (in the set or in any member, RFC 7517 §4, §5), or the
    ///   default [`json::Limits`] exceeded.
    /// - Every error of [`JwkSet::from_object`].
    ///
    /// No error contains any part of the input.
    pub fn from_json(bytes: &[u8]) -> Result<JwkSet> {
        let object = json::parse(bytes)?
            .into_object()
            .ok_or(Error::InvalidJson(NOT_AN_OBJECT))?;
        JwkSet::from_object(&object)
    }

    /// Builds a JWK Set from a JSON object.
    ///
    /// Each entry of `keys` is imported with [`Jwk::from_object`]:
    ///
    /// - It is **kept** (in order) if it imports.
    /// - It is **skipped** if its `kty`, or `EC`/`OKP` `crv`, is not
    ///   supported (RFC 7517 §5: "Implementations SHOULD ignore JWKs within
    ///   a JWK Set that use "kty" (key type) values that are not understood
    ///   by them"; ADR 0029 §3), or if it is otherwise invalid: not an
    ///   object, missing required members, wrong lengths, non-canonical
    ///   base64url, an RSA modulus under 2048 bits, an off-curve EC point,
    ///   an out-of-range EC `d`, an invalid Ed25519 key (ADR 0041 §2, §4),
    ///   and so on (RFC 7517 §5:
    ///   "SHOULD ignore JWKs ... that are missing required members, or for
    ///   which values are out of the supported ranges"), or if its `alg` is
    ///   rejected (`RSA1_5`, `RSA-OAEP`, or a family mismatch, RFC 7517
    ///   §4.4). Skipping can only remove verification candidates, never add
    ///   one.
    /// - It **fails the whole set** with [`Error::UnsupportedAlgorithm`]
    ///   if it is an RSA private key (any RFC 7518 §6.3.2 member), whatever
    ///   else it holds (ADR 0021, ADR 0029 §3): a verification set never
    ///   needs RSA private material, and skipping it would hide a leaked
    ///   key.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidKey`] if `keys` is missing or not an array
    ///   (RFC 7517 §5: the object "MUST have a "keys" member"; a malformed
    ///   key set is a key problem, ADR 0018 Q3).
    /// - [`Error::UnsupportedAlgorithm`] if a member is an RSA private key.
    ///
    /// No error contains any part of the input or of a key.
    pub fn from_object(object: &Object) -> Result<JwkSet> {
        let members = object
            .get("keys")
            .and_then(Value::as_array)
            .ok_or(Error::InvalidKey(NO_KEYS_ARRAY))?;
        let mut keys = Vec::with_capacity(members.len());
        let mut skipped = 0;
        for member in members {
            match import_member(member)? {
                Some(jwk) => keys.push(jwk),
                None => skipped += 1,
            }
        }
        // RFC 7517 §5: "Additional members can be present"; they are kept.
        // They are a subset of `object`'s members, whose names are unique,
        // so they are wrapped as they are: inserting them one by one would
        // re-check every name, O(n²) on untrusted input.
        let other = Object::from_unique_members(
            object
                .iter()
                .filter(|(name, _)| *name != "keys")
                .map(|(name, value)| member(name, value.clone()))
                .collect(),
        );
        Ok(JwkSet {
            keys,
            skipped,
            other,
        })
    }

    /// The keys, in document order with skipped entries left out. An
    /// index into this slice is the `key_index` of ADR 0029 §4.
    pub fn keys(&self) -> &[Jwk] {
        &self.keys
    }

    /// The number of keys.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the set has no keys (also when every entry was skipped).
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// How many `keys` entries were skipped as unsupported or invalid
    /// (RFC 7517 §5), for diagnostics. Which entries, and why, is not
    /// reported.
    pub fn skipped(&self) -> usize {
        self.skipped
    }

    /// Top-level members other than `keys`, in input order (RFC 7517 §5).
    pub fn other_params(&self) -> &Object {
        &self.other
    }

    /// The keys that may verify a JWS whose protected header has `alg` and,
    /// if present, `kid`: the candidate filter of ADR 0029 §2. Each item is
    /// `(key_index, key)`, in set order, where `key_index` indexes
    /// [`JwkSet::keys`].
    ///
    /// This is [`JwkSet::matching`] with the selector
    /// `{ alg, key_op: verify, kid }` (ADR 0054 §6), on the same rule, so
    /// it allows no key `matching` would not. For that selector the rule
    /// reads: a key is a candidate iff all of these hold:
    ///
    /// 1. **Family:** its `kty`/`crv` serves `alg` (the ADR 0026 §2 step 8
    ///    table, e.g. `HS*` → `oct`, `ES256` → `EC` `P-256`, `EdDSA` and
    ///    `Ed25519` → `OKP` `Ed25519`). `none` and unknown algorithms
    ///    select nothing (RFC 8725 §3.1).
    /// 2. **JWK `alg`:** absent, or exactly `alg` (RFC 7517 §4.4,
    ///    RFC 8725 §3.1). `EdDSA` and `Ed25519` differ (RFC 9864 §2.2).
    /// 3. **`use`:** absent or `sig` (RFC 7517 §4.2).
    /// 4. **`key_ops`:** absent or contains `verify` (RFC 7517 §4.3).
    /// 5. **`kid`:** if `kid` is `Some`, the key has an identical `kid`
    ///    (exact, case-sensitive string equality; RFC 7515 §4.1.4,
    ///    RFC 7517 §4.5). If it is `None`, keys with and without a `kid`
    ///    all qualify, so a set rotated without `kid`s still verifies.
    ///
    /// Pass the header values only after the `alg` has passed the
    /// caller's allow-list (ADR 0026 §2 steps 1-7, ADR 0029 §1). The `kid`
    /// is only compared for equality, never used as a path, URL or query
    /// (RFC 8725 §3.10). Selection checks no key strength (HMAC key
    /// length, RSA ceiling): that is key binding at verify time
    /// (ADR 0026 §2 step 8). Bounding the number of candidates tried is
    /// the caller's job (ADR 0029 §4).
    ///
    /// ```
    /// use polyjose::jwa::SigningAlg;
    /// use polyjose::jwk::JwkSet;
    ///
    /// let set = JwkSet::from_json(br#"{"keys":[
    ///     {"kty":"oct","k":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","kid":"old"},
    ///     {"kty":"oct","k":"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8","kid":"new","use":"sig"},
    ///     {"kty":"oct","k":"QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8","use":"enc"},
    ///     {"kty":"XYZ","kid":"from the future"}
    /// ]}"#)?;
    /// assert_eq!(set.len(), 3);
    /// assert_eq!(set.skipped(), 1);
    ///
    /// let by_kid: Vec<usize> = set
    ///     .verification_candidates(&SigningAlg::HS256, Some("new"))
    ///     .map(|(index, _)| index)
    ///     .collect();
    /// assert_eq!(by_kid, [1]);
    ///
    /// // Without a kid, every compatible key: the `enc` key is not one.
    /// let all: Vec<usize> = set
    ///     .verification_candidates(&SigningAlg::HS256, None)
    ///     .map(|(index, _)| index)
    ///     .collect();
    /// assert_eq!(all, [0, 1]);
    /// # Ok::<(), polyjose::Error>(())
    /// ```
    pub fn verification_candidates<'a>(
        &'a self,
        alg: &'a SigningAlg,
        kid: Option<&'a str>,
    ) -> impl Iterator<Item = (usize, &'a Jwk)> + 'a {
        // ADR 0054 §6: the one candidate rule with
        // `{ alg: Signing(alg), key_op: verify, kid }`.
        let criteria = Criteria::new(
            Some(SelectorAlg::Signing(alg)),
            None,
            Some(KeyOp::Verify),
            kid,
        );
        self.filter_keys(move |key| criteria.matches(key))
    }

    /// The one key `selector` matches, as `(key_index, key)`, where
    /// `key_index` indexes [`JwkSet::keys`] (ADR 0054 §4, ADR 0029 §4).
    ///
    /// A member matches by the rule documented on [`JwkSelector`]
    /// (ADR 0054 §2), the same rule [`JwkSet::matching`] and
    /// [`JwkSet::verification_candidates`] apply.
    ///
    /// ```
    /// use polyjose::Error;
    /// use polyjose::jwk::{JwkSelector, JwkSet, KeyAlg};
    ///
    /// // RFC 7517 Appendix A.1 (the RSA modulus shortened here to `n`).
    /// # let n = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";
    /// let set = JwkSet::from_json(format!(r#"{{"keys":[
    ///     {{"kty":"EC","crv":"P-256","use":"enc","kid":"1",
    ///      "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
    ///      "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}},
    ///     {{"kty":"RSA","n":"{n}","e":"AQAB","alg":"RS256","kid":"2011-04-29"}}
    /// ]}}"#).as_bytes())?;
    ///
    /// let rs256 = JwkSelector::new().alg(KeyAlg::from("RS256"))?;
    /// let (index, key) = set.select(&rs256)?;
    /// assert_eq!((index, key.kid()), (1, Some("2011-04-29")));
    ///
    /// // The P-256 key is `use: enc`, so it serves ECDH-ES, not ES256.
    /// let es256 = JwkSelector::new().alg(KeyAlg::from("ES256"))?;
    /// assert_eq!(set.select(&es256).unwrap_err(), Error::NoMatchingKey);
    /// let ecdh = JwkSelector::new().alg(KeyAlg::from("ECDH-ES"))?;
    /// assert_eq!(set.select(&ecdh)?.0, 0);
    ///
    /// // No criterion and two keys: ambiguous, never a guess.
    /// assert_eq!(set.select(&JwkSelector::new()).unwrap_err(), Error::MultipleMatchingKeys);
    /// # Ok::<(), polyjose::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// - [`Error::NoMatchingKey`] if no member matches, including when the
    ///   set is empty or every entry was skipped on import.
    /// - [`Error::MultipleMatchingKeys`] if two or more members match. The
    ///   scan stops at the second match. RFC 7517 §5.1 gives the order of
    ///   a set no meaning, so polyjose does not guess: narrow the selector
    ///   (a `kid`, RFC 7517 §4.5), or try each of [`JwkSet::matching`].
    ///
    /// Neither error says which members were looked at.
    ///
    /// # Security (ADR 0054 §7, RFC 8725)
    ///
    /// - **Selection never authorizes an algorithm.** It identifies a key.
    ///   The caller's allow-list still decides: every polyjose verify and
    ///   decrypt takes one, and its key binding re-checks the family, JWK
    ///   `alg`, `use` and `key_ops` (RFC 8725 §3.1, ADR 0026 §2 step 8).
    /// - **A selector with an `alg` never crosses key families**: a secret
    ///   `oct` key is never selected for an asymmetric `alg`, nor an
    ///   asymmetric key for `HS*`, A\*KW, `dir` or PBES2, and a key whose
    ///   own `alg` is another algorithm is never selected (RFC 8725 §3.1),
    ///   except, for `dir`, a member whose `alg` is a content encryption
    ///   algorithm; the JWE key binding checks the exact `enc` at use
    ///   (ADR 0054 §2.2; RFC 7518 §4.5).
    /// - **A selector without an `alg`** (a `kid` alone, say) may return a
    ///   key of any family. Pass it only to operations that take an
    ///   allow-list.
    /// - **A `kid` is only compared for equality**, exact and
    ///   case-sensitive, never used as a path, URL or query (RFC 8725
    ///   §3.10). A `kid` from an untrusted header is safe to select by.
    /// - **The outcome reveals the set's structure** when the selector
    ///   comes from an untrusted token (ADR 0054 §4):
    ///   [`Error::NoMatchingKey`] says no member matches its `kid` (or
    ///   `alg`), and [`Error::MultipleMatchingKeys`] says two or more do,
    ///   so a prober learns which `kid`s exist and which repeat. That is
    ///   nothing new for a public JWK Set, but it is for a set of secret
    ///   `oct` keys. A server should map both, with the verify and
    ///   decrypt codes, to one opaque client error, such as
    ///   `invalid_token` (RFC 6750 §3.1); see
    ///   [the error module](crate::error#codes-are-for-logs-not-for-clients).
    /// - **The result is the member as imported**, and may hold private
    ///   members (`EC`/`OKP` `d`, `oct` `k`): it is the caller's key. Call
    ///   [`Jwk::to_public`] before publishing it. RSA private members never
    ///   import (ADR 0021).
    ///
    /// ```
    /// use polyjose::Error;
    /// use polyjose::jwa::SigningAlg;
    /// use polyjose::jwk::{JwkSelector, JwkSet, KeyAlg};
    /// use polyjose::jws::{VerifyOptions, verify_compact};
    ///
    /// // RFC 7517 Appendix A.3, and the RFC 7515 A.1 JWS its HMAC key signs.
    /// let set = JwkSet::from_json(br#"{"keys":[
    ///     {"kty":"oct","alg":"A128KW","k":"GawgguFyGrWKav7AX4VKUg"},
    ///     {"kty":"oct","kid":"HMAC key used in JWS spec Appendix A.1 example",
    ///      "k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}
    /// ]}"#)?;
    /// let jws = concat!(
    ///     "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9",
    ///     ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
    ///     ".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
    /// );
    ///
    /// let (_, key) = set.select(&JwkSelector::new().alg(KeyAlg::from("HS256"))?)?;
    /// // Selected for HS256, the key still verifies only if HS256 is allowed.
    /// let hs384_only = [SigningAlg::HS384];
    /// let refused = verify_compact(jws, key, &VerifyOptions::new(&hs384_only)?);
    /// assert_eq!(refused.unwrap_err(), Error::AlgorithmNotAllowed);
    /// let hs256 = [SigningAlg::HS256];
    /// assert!(verify_compact(jws, key, &VerifyOptions::new(&hs256)?).is_ok());
    ///
    /// // An `oct` key is never selected for an asymmetric `alg` (RFC 8725 §3.1).
    /// let es256 = JwkSelector::new().alg(KeyAlg::from("ES256"))?;
    /// assert_eq!(set.select(&es256).unwrap_err(), Error::NoMatchingKey);
    ///
    /// // The selected key is secret: it has no public form to publish.
    /// assert!(!key.is_public() && key.to_public().is_none());
    /// # Ok::<(), polyjose::Error>(())
    /// ```
    pub fn select(&self, selector: &JwkSelector) -> Result<(usize, &Jwk)> {
        let criteria = Criteria::of(selector);
        exactly_one(self.filter_keys(|key| criteria.matches(key)))
    }

    /// Every member `selector` matches, in set order, as
    /// `(key_index, key)`, where `key_index` indexes [`JwkSet::keys`]
    /// (ADR 0054 §4).
    ///
    /// The rule is that of [`JwkSet::select`], documented on
    /// [`JwkSelector`] (ADR 0054 §2). This never fails and has no bound:
    /// selection computes no cryptography, so bounding how many keys a
    /// caller then tries is the caller's choice (ADR 0029 §4's
    /// `max_key_candidates` is a verification policy).
    ///
    /// ```
    /// use polyjose::jwk::{JwkSelector, JwkSet};
    ///
    /// let set = JwkSet::from_json(br#"{"keys":[
    ///     {"kty":"oct","k":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","kid":"k"},
    ///     {"kty":"XYZ","kid":"k"},
    ///     {"kty":"OKP","crv":"X25519","x":"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08","kid":"k"}
    /// ]}"#)?;
    /// // A `kid` alone matches keys of any family, in set order; indices
    /// // leave the skipped `XYZ` entry out.
    /// let selector = JwkSelector::new().kid("k");
    /// let found: Vec<usize> = set.matching(&selector).map(|(index, _)| index).collect();
    /// assert_eq!(found, [0, 1]);
    /// # Ok::<(), polyjose::Error>(())
    /// ```
    ///
    /// # Security (ADR 0054 §7, RFC 8725)
    ///
    /// As for [`JwkSet::select`]: matching never authorizes an algorithm
    /// (the caller's allow-list decides); a selector with an `alg` never
    /// crosses key families, while one without may match any family; a
    /// `kid` is only compared for equality (RFC 8725 §3.1, §3.10); and
    /// each key is the member as imported, possibly with private members
    /// (`EC`/`OKP` `d`, `oct` `k`), the caller's to protect.
    pub fn matching<'a>(
        &'a self,
        selector: &'a JwkSelector,
    ) -> impl Iterator<Item = (usize, &'a Jwk)> + 'a {
        let criteria = Criteria::of(selector);
        self.filter_keys(move |key| criteria.matches(key))
    }

    /// The members `keep` accepts, in set order, as `(key_index, key)`:
    /// the one scan behind [`JwkSet::matching`], [`JwkSet::select`] and
    /// [`JwkSet::verification_candidates`].
    ///
    /// The iterator lives as long as both `self` and `keep`, while its
    /// items borrow only `self`, so [`JwkSet::select`] can return a key
    /// that outlives its selector.
    fn filter_keys(
        &self,
        mut keep: impl FnMut(&Jwk) -> bool,
    ) -> impl Iterator<Item = (usize, &Jwk)> {
        self.keys
            .iter()
            .enumerate()
            .filter(move |(_, key)| keep(key))
    }
}

/// The only item of `found`, reading at most two (ADR 0054 §4): none is
/// [`Error::NoMatchingKey`], a second is [`Error::MultipleMatchingKeys`].
fn exactly_one<'a>(mut found: impl Iterator<Item = (usize, &'a Jwk)>) -> Result<(usize, &'a Jwk)> {
    let first = found.next().ok_or(Error::NoMatchingKey)?;
    match found.next() {
        None => Ok(first),
        Some(_) => Err(Error::MultipleMatchingKeys),
    }
}

/// A selector `alg`, borrowed (ADR 0054 §1.1).
#[derive(Clone, Copy, Debug)]
enum SelectorAlg<'a> {
    /// A JWS algorithm (RFC 7518 §3.1).
    Signing(&'a SigningAlg),
    /// A JWE key management algorithm (RFC 7518 §4.1).
    KeyMgmt(&'a KeyMgmtAlg),
    /// Anything [`JwkSelector::alg`] refuses. A selector cannot hold one,
    /// but if it did, no member would serve it: selection fails closed.
    Unservable,
}

impl SelectorAlg<'_> {
    /// ADR 0054 §2 item 1: the member's `kty`/`crv` serves the `alg`, by
    /// the core's only family tables (ADR 0026 §2 step 8).
    fn served_by(self, material: &KeyMaterial) -> bool {
        match self {
            SelectorAlg::Signing(alg) => material.serves_signing_alg(alg),
            SelectorAlg::KeyMgmt(alg) => material.serves_key_mgmt_alg(alg),
            SelectorAlg::Unservable => false,
        }
    }

    /// ADR 0054 §2 item 2: a member `alg` that is present allows this
    /// `alg` only if it is exactly this `alg` (RFC 7517 §4.4, RFC 8725
    /// §3.1; `EdDSA` ≠ `Ed25519`, RFC 9864 §2.2). The one exception: for
    /// `dir`, a member `alg` naming a content encryption algorithm, since
    /// a `dir` key is the CEK of that `enc` (RFC 7518 §4.5, RFC 7520
    /// §5.6.1); JWE key binding checks the exact `enc` at use.
    fn named_by(self, key_alg: &KeyAlg) -> bool {
        match (self, key_alg) {
            (SelectorAlg::Signing(alg), KeyAlg::Signing(key_alg)) => alg == key_alg,
            (SelectorAlg::KeyMgmt(KeyMgmtAlg::Dir), KeyAlg::ContentEnc(_)) => true,
            (SelectorAlg::KeyMgmt(alg), KeyAlg::KeyMgmt(key_alg)) => alg == key_alg,
            _ => false,
        }
    }

    /// ADR 0054 §2 item 3: the use the `alg` implies, `sig` for JWS and
    /// `enc` for JWE key management (RFC 7517 §4.2).
    fn key_use(self) -> Option<KeyUse> {
        match self {
            SelectorAlg::Signing(_) => Some(KeyUse::Sig),
            SelectorAlg::KeyMgmt(_) => Some(KeyUse::Enc),
            SelectorAlg::Unservable => None,
        }
    }

    /// ADR 0054 §2 item 4: whether `key_ops` holds an operation this `alg`
    /// performs in either direction (RFC 7517 §4.3): `sign` or `verify`
    /// for JWS, and for JWE the `jwe/key.rs` `key_op` rows (`wrapKey` or
    /// `unwrapKey`, `encrypt` or `decrypt`, `deriveKey`).
    fn performed_by_any(self, key_ops: &[KeyOp]) -> bool {
        match self {
            SelectorAlg::Signing(_) => key_ops
                .iter()
                .any(|op| matches!(op, KeyOp::Sign | KeyOp::Verify)),
            SelectorAlg::KeyMgmt(alg) => key_ops_either_direction(alg)
                .iter()
                .flatten()
                .any(|op| key_ops.contains(op)),
            SelectorAlg::Unservable => false,
        }
    }
}

/// The effective use U of a selector (ADR 0054 §2 item 3).
#[derive(Clone, Debug)]
enum Purpose {
    /// No part implies a use, so `use` is not checked.
    Unchecked,
    /// Every part that implies a use implies this one.
    Use(KeyUse),
    /// Two parts disagree (`alg: ES256` with `key_use: enc`): the selector
    /// matches nothing.
    Conflict,
}

impl Purpose {
    /// U from `key_use`, then the use of `key_op` (`KeyOp::key_use`), then
    /// the use `alg` implies; parts given together must agree.
    fn of(key_use: Option<&KeyUse>, key_op: Option<&KeyOp>, alg: Option<SelectorAlg<'_>>) -> Self {
        let parts = [
            key_use.cloned(),
            key_op.and_then(KeyOp::key_use),
            alg.and_then(SelectorAlg::key_use),
        ];
        let mut purpose = Purpose::Unchecked;
        for part in parts.into_iter().flatten() {
            purpose = match purpose {
                Purpose::Unchecked => Purpose::Use(part),
                Purpose::Use(u) if u == part => Purpose::Use(u),
                Purpose::Use(_) | Purpose::Conflict => return Purpose::Conflict,
            };
        }
        purpose
    }
}

/// A selector, borrowed, with its effective use worked out once: the one
/// candidate rule of ADR 0054 §2. [`JwkSet::verification_candidates`]
/// builds one directly, so it allocates nothing.
#[derive(Clone, Debug)]
struct Criteria<'a> {
    alg: Option<SelectorAlg<'a>>,
    key_op: Option<KeyOp>,
    kid: Option<&'a str>,
    purpose: Purpose,
}

impl<'a> Criteria<'a> {
    fn new(
        alg: Option<SelectorAlg<'a>>,
        key_use: Option<&KeyUse>,
        key_op: Option<KeyOp>,
        kid: Option<&'a str>,
    ) -> Self {
        let purpose = Purpose::of(key_use, key_op.as_ref(), alg);
        Criteria {
            alg,
            key_op,
            kid,
            purpose,
        }
    }

    fn of(selector: &'a JwkSelector) -> Self {
        let alg = selector.alg.as_ref().map(|alg| match alg {
            KeyAlg::Signing(alg) => SelectorAlg::Signing(alg),
            KeyAlg::KeyMgmt(alg) => SelectorAlg::KeyMgmt(alg),
            KeyAlg::ContentEnc(_) | KeyAlg::Unknown(_) => SelectorAlg::Unservable,
        });
        Criteria::new(
            alg,
            selector.key_use.as_ref(),
            selector.key_op.clone(),
            selector.kid.as_deref(),
        )
    }

    /// ADR 0054 §2: all five checks, in order; an absent selector part
    /// skips its check.
    fn matches(&self, key: &Jwk) -> bool {
        // 1. Family.
        self.alg.is_none_or(|alg| alg.served_by(key.material()))
            // 2. JWK `alg`: absent or exactly the selector's.
            && self
                .alg
                .is_none_or(|alg| key.alg().is_none_or(|key_alg| alg.named_by(key_alg)))
            // 3. Purpose: the member's `use` absent or U (RFC 7517 §4.2).
            && match &self.purpose {
                Purpose::Unchecked => true,
                Purpose::Use(u) => key.key_use().is_none_or(|key_use| key_use == u),
                Purpose::Conflict => false,
            }
            // 4. `key_ops` (RFC 7517 §4.3).
            && self.key_ops_allow(key)
            // 5. `kid`: exact, case-sensitive equality only (RFC 7517 §4.5,
            //    RFC 8725 §3.10).
            && self.kid.is_none_or(|kid| key.kid() == Some(kid))
    }

    /// ADR 0054 §2 item 4: a member's `key_ops`, if present, must contain
    /// the `key_op` ([`Jwk::permits`]); otherwise an operation of the
    /// `alg` in either direction; otherwise a registered operation of U.
    fn key_ops_allow(&self, key: &Jwk) -> bool {
        if let Some(op) = &self.key_op {
            return key.permits(op);
        }
        let Some(key_ops) = key.key_ops() else {
            return true;
        };
        if let Some(alg) = self.alg {
            return alg.performed_by_any(key_ops);
        }
        match &self.purpose {
            Purpose::Use(u) => key_ops.iter().any(|op| op.key_use().as_ref() == Some(u)),
            Purpose::Unchecked | Purpose::Conflict => true,
        }
    }
}

/// Criteria for picking keys from a [`JwkSet`] (ADR 0054 §1): an optional
/// `kid`, `alg`, `use` and `key_ops` operation.
///
/// Build one with [`JwkSelector::new`], which selects every member, and
/// the setters, each of which narrows it. Every criterion is validated
/// when it is set, before any set is read (ADR 0054 §1.1, §4), so a
/// selector that exists is one polyjose can apply. Apply it with
/// [`JwkSet::select`] (one key) or [`JwkSet::matching`] (every key).
///
/// # The rule (ADR 0054 §2)
///
/// A member matches iff all five checks hold, in this order. A criterion
/// that is not set skips its check.
///
/// 1. **Family.** With an `alg`, the member's `kty`/`crv` serves it, by
///    the core's only family tables (ADR 0026 §2 step 8): `HS*` → `oct`,
///    `ES256` → `EC` `P-256`, A\*KW, `dir` and PBES2 → `oct`,
///    `RSA-OAEP-256` → `RSA`, ECDH-ES → `EC` `P-256`/`P-384`/`P-521` or
///    `OKP` `X25519` (RFC 7518 §3.1, §4.1; RFC 8037 §3).
/// 2. **JWK `alg`.** With an `alg`, the member's `alg` is absent or
///    exactly it (RFC 7517 §4.4, RFC 8725 §3.1): `EdDSA` ≠ `Ed25519`. For
///    `dir` only, a member `alg` naming a content encryption algorithm
///    also matches (RFC 7518 §4.5; the exact `enc` is checked at use).
/// 3. **Purpose.** The effective use is the `key_use`, else the use of
///    the `key_op` (`sign`/`verify` → `sig`, the others → `enc`), else the
///    use the `alg` implies (JWS → `sig`, JWE → `enc`). Parts that
///    disagree (`alg: ES256` with `key_use: enc`) match nothing. With an
///    effective use, the member's `use` is absent or that use
///    (RFC 7517 §4.2).
/// 4. **`key_ops`.** The member's `key_ops`, if present, contains the
///    `key_op` ([`Jwk::permits`]); without a `key_op`, an operation the
///    `alg` performs in either direction (`sign`/`verify`;
///    `wrapKey`/`unwrapKey`; `encrypt`/`decrypt` for `dir`; `deriveKey`
///    for ECDH-ES); with neither, a registered operation of the effective
///    use (RFC 7517 §4.3).
/// 5. **`kid`.** The member has exactly this `kid`, case-sensitive
///    (RFC 7517 §4.5). A member without a `kid` never matches.
///
/// Selection checks no key strength (HMAC length, AES key size), and not
/// whether an operation needs the private half: the operation's key
/// binding decides that at use (ADR 0054 §2, "Not part of selection").
///
/// ```
/// use polyjose::Error;
/// use polyjose::jwk::{JwkSelector, KeyAlg, KeyUse};
///
/// let selector = JwkSelector::new()
///     .kid("2011-04-29")
///     .alg(KeyAlg::from("ES256"))?
///     .key_use(KeyUse::Sig)?;
/// assert_ne!(selector, JwkSelector::new());
///
/// // RFC 8725 §3.1: `none` never selects a key, and neither does a
/// // content encryption algorithm (ADR 0054 §1.1).
/// assert_eq!(JwkSelector::new().alg(KeyAlg::from("none")), Err(Error::UnsupportedAlgorithm));
/// assert_eq!(JwkSelector::new().alg(KeyAlg::from("A256GCM")), Err(Error::UnsupportedAlgorithm));
/// # Ok::<(), polyjose::Error>(())
/// ```
///
/// # Security
///
/// A selector identifies keys; it never authorizes an algorithm. Pass a
/// selected key only to operations that take an allow-list, as every
/// polyjose verify and decrypt does (ADR 0054 §7, RFC 8725 §3.1). A `kid`
/// is only ever compared for equality (RFC 8725 §3.10). No criterion is
/// secret, so `Debug` prints them all.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct JwkSelector {
    /// The `kid` a member must carry, exactly (RFC 7517 §4.5).
    kid: Option<String>,
    /// A JWS or JWE key management algorithm polyjose implements
    /// (RFC 7517 §4.4; ADR 0054 §1.1).
    alg: Option<KeyAlg>,
    /// `sig` or `enc` (RFC 7517 §4.2).
    key_use: Option<KeyUse>,
    /// A registered operation (RFC 7517 §4.3).
    key_op: Option<KeyOp>,
}

impl JwkSelector {
    /// The empty selector, which every member matches (ADR 0054 §1.3).
    pub fn new() -> JwkSelector {
        JwkSelector::default()
    }

    /// Selects members whose `kid` equals `kid` exactly: case-sensitive
    /// string equality, no normalization (RFC 7517 §4.5, ADR 0054 §1.2). A
    /// member without a `kid` does not match. The value is never used as a
    /// path, URL or query (RFC 8725 §3.10). A later call replaces it.
    pub fn kid(mut self, kid: &str) -> JwkSelector {
        self.kid = Some(kid.to_owned());
        self
    }

    /// Selects members that may serve `alg` (ADR 0054 §2: family, JWK
    /// `alg`, `use` and `key_ops`). A later call replaces it.
    ///
    /// # Errors
    ///
    /// [`Error::UnsupportedAlgorithm`] unless `alg` is a JWS algorithm
    /// polyjose implements other than `none` ([`SigningAlg::KNOWN`],
    /// RFC 7518 §3.1, RFC 8725 §3.1), or a JWE key management algorithm it
    /// implements ([`KeyMgmtAlg::KNOWN`], RFC 7518 §4.1) (ADR 0054 §1.1).
    /// So `none`, `RSA1_5` (ADR 0021), `RSA-OAEP` (ADR 0022), unregistered
    /// names and content encryption names (`A256GCM`, RFC 7518 §5.1) are
    /// refused; select a `dir` key with `dir`. The value is not echoed.
    ///
    /// [`SigningAlg::KNOWN`]: crate::jwa::SigningAlg::KNOWN
    /// [`KeyMgmtAlg::KNOWN`]: crate::jwa::KeyMgmtAlg::KNOWN
    pub fn alg(mut self, alg: KeyAlg) -> Result<JwkSelector> {
        let implemented = match &alg {
            KeyAlg::Signing(a) => a.is_known() && *a != SigningAlg::None,
            KeyAlg::KeyMgmt(a) => a.is_known(),
            KeyAlg::ContentEnc(_) | KeyAlg::Unknown(_) => false,
        };
        if !implemented {
            return Err(Error::UnsupportedAlgorithm);
        }
        self.alg = Some(alg);
        Ok(self)
    }

    /// Selects members whose `use` is absent or `key_use` (RFC 7517 §4.2,
    /// ADR 0054 §2.3). A later call replaces it.
    ///
    /// # Errors
    ///
    /// [`Error::UnsupportedAlgorithm`] unless `key_use` is `sig` or `enc`
    /// (ADR 0054 §1.1, ADR 0030 §5). The value is not echoed.
    pub fn key_use(mut self, key_use: KeyUse) -> Result<JwkSelector> {
        if !matches!(key_use, KeyUse::Sig | KeyUse::Enc) {
            return Err(Error::UnsupportedAlgorithm);
        }
        self.key_use = Some(key_use);
        Ok(self)
    }

    /// Selects members whose `key_ops`, if present, contain `key_op`, and
    /// whose `use`, if present, is the use of `key_op` (RFC 7517 §4.2,
    /// §4.3; ADR 0054 §2.3, §2.4). A later call replaces it.
    ///
    /// # Errors
    ///
    /// [`Error::UnsupportedAlgorithm`] unless `key_op` is one of the eight
    /// operations RFC 7517 §4.3 registers (ADR 0054 §1.1). The value is
    /// not echoed.
    pub fn key_op(mut self, key_op: KeyOp) -> Result<JwkSelector> {
        if matches!(key_op, KeyOp::Unknown(_)) {
            return Err(Error::UnsupportedAlgorithm);
        }
        self.key_op = Some(key_op);
        Ok(self)
    }
}

/// Imports one `keys` entry: `Ok(Some)` to keep it, `Ok(None)` to skip it,
/// `Err` to fail the set (see [`JwkSet::from_object`]).
fn import_member(member: &Value) -> Result<Option<Jwk>> {
    let Some(object) = member.as_object() else {
        return Ok(None);
    };
    if is_unsupported_key_kind(object) {
        return Ok(None);
    }
    // ADR 0021, ADR 0029 §3: an RSA private key fails the set, checked
    // before anything else in the entry so no other defect can hide it.
    if is_rsa_private_key(object) {
        return Err(Error::UnsupportedAlgorithm);
    }
    // Every other failure is skipped (RFC 7517 §5 "SHOULD ignore"),
    // including a JWK `alg` that is not supported (`RSA1_5`, `RSA-OAEP`)
    // or that the key cannot serve (RFC 7517 §4.4): such a key could never
    // be used, so leaving it out removes no usable candidate.
    Ok(Jwk::from_object(object).ok())
}

/// Prints each key's own `Debug` (private members redacted), the skipped
/// count and only the *names* of the other members, whose values could be
/// secret.
impl fmt::Debug for JwkSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JwkSet")
            .field("keys", &self.keys)
            .field("skipped", &self.skipped)
            .field("other_names", &MemberNames(&self.other))
            .finish()
    }
}

/// Every key, and every string of the other members, is wiped on drop.
impl ZeroizeOnDrop for JwkSet {}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a panic is a failed assertion

    use crate::Error;
    use crate::json;
    use crate::jwa::{KeyMgmtAlg, SigningAlg};
    use crate::jwk::{Jwk, JwkSet, KeyAlg, KeyMaterial, KeyType};

    /// RFC 7517 Appendix A.1, the P-256 public key.
    const EC_P256: &str = r#"{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}"#;
    /// RFC 7517 Appendix A.1, the 2048-bit RSA public key.
    const RSA_2048: &str = r#"{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB"}"#;
    /// RFC 7517 Appendix A.3, the HMAC key.
    const OCT: &str = r#"{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}"#;
    /// RFC 8037 Appendix A.2, the Ed25519 public key.
    const ED25519: &str =
        r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;
    /// RFC 8037 Appendix A.6, the X25519 public key (a key agreement key).
    const X25519: &str =
        r#"{"kty":"OKP","crv":"X25519","x":"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08"}"#;

    /// The generator G of `crv` as an EC public key (SEC 2 values): a real
    /// point, since import checks that it is on the curve (ADR 0041 §4).
    /// `len` is the coordinate length the caller expects.
    fn ec(crv: &str, len: usize) -> Jwk {
        let (x, y) = match crv {
            "P-384" => (
                "qofKIr6LBTeOscce8yCtdG4dO2KLp5uYWfdB4IJUKjhVAvJdv1UpbDpUXjhydgq3",
                "NhfeSpYmLG9dnpi_kpLcKfj0Hb0omhR86doxE7XwuMAKYLHOHX6BnXpDHXyQ6g5f",
            ),
            "P-521" => (
                "AMaFjga3BATpzZ4-y2YjlbRCnGSBOQU_tSH4KK9ga009uqFLXnfv51ko_h3BJ6L_qN4zSLPBhWpCm_l-fjHC5b1m",
                "ARg5KWp4mjvABFyKX7QsfRvZmPVESVebRGgXr70XJz5mLJfucple9CZAxVC5AT-tB2E1PHCGonLCQIi-lHaf0WZQ",
            ),
            "secp256k1" => (
                "eb5mfvncu6xVoGKVzocLBwKb_NstzijZWfKBWxb4F5g",
                "SDradyajxGVdpPv8DhEIqP0XtEimhVQZnEfQj_sQ1Lg",
            ),
            other => panic!("no EC fixture for {other}"),
        };
        let json = format!(r#"{{"kty":"EC","crv":"{crv}","x":"{x}","y":"{y}"}}"#);
        let key = Jwk::from_json(json.as_bytes()).unwrap();
        let KeyMaterial::Ec(ec) = key.material() else {
            unreachable!()
        };
        assert_eq!(ec.x().len(), len, "{crv}");
        key
    }

    fn jwk(json: &str) -> Jwk {
        Jwk::from_json(json.as_bytes()).unwrap()
    }

    /// DoS regression (0001 security review, F01): a JWK Set with 10 000
    /// top-level members whose one key also has 10 000 members (the most
    /// the default `json::Limits` allow per object) imports without
    /// quadratic work. The bound is `c · n · ⌈log2 n⌉` with `c = 4` over all
    /// `n` members; quadratic code needs about 90 times that.
    #[test]
    fn import_with_10_000_members_per_object_is_n_log_n() {
        const PER_OBJECT: usize = 10_000;
        // RFC 7517 Appendix A.3, the HMAC key value.
        const OCT_K: &str = "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow";
        let mut key = format!(r#"{{"kty":"oct","k":"{OCT_K}""#);
        for i in 0..PER_OBJECT - 2 {
            key.push_str(&format!(r#","u{i}":{i}"#));
        }
        key.push('}');
        let mut set = format!(r#"{{"keys":[{key}]"#);
        for i in 0..PER_OBJECT - 1 {
            set.push_str(&format!(r#","s{i}":{i}"#));
        }
        set.push('}');

        let (set, count) =
            json::Object::count_name_comparisons(|| JwkSet::from_json(set.as_bytes()));
        let set = set.expect("the set imports");
        assert_eq!((set.len(), set.skipped()), (1, 0));
        assert_eq!(set.keys()[0].other_params().len(), PER_OBJECT - 2);
        assert_eq!(set.other_params().len(), PER_OBJECT - 1);

        let n = (2 * PER_OBJECT) as u64;
        let bound = 4 * n * u64::from(u64::BITS - n.leading_zeros());
        assert!(count <= bound, "{count} comparisons");
    }

    /// ADR 0026 §2 step 8: the whole alg → key family table, every row
    /// against every key kind.
    #[test]
    fn family_table_matches_adr_0026_step_8() {
        let keys = [
            ("oct", jwk(OCT)),
            ("RSA", jwk(RSA_2048)),
            ("P-256", jwk(EC_P256)),
            ("P-384", ec("P-384", 48)),
            ("P-521", ec("P-521", 66)),
            ("secp256k1", ec("secp256k1", 32)),
            ("Ed25519", jwk(ED25519)),
            ("X25519", jwk(X25519)),
        ];
        let table: &[(SigningAlg, &str)] = &[
            (SigningAlg::HS256, "oct"),
            (SigningAlg::HS384, "oct"),
            (SigningAlg::HS512, "oct"),
            (SigningAlg::RS256, "RSA"),
            (SigningAlg::RS384, "RSA"),
            (SigningAlg::RS512, "RSA"),
            (SigningAlg::PS256, "RSA"),
            (SigningAlg::PS384, "RSA"),
            (SigningAlg::PS512, "RSA"),
            (SigningAlg::ES256, "P-256"),
            (SigningAlg::ES384, "P-384"),
            (SigningAlg::ES512, "P-521"),
            (SigningAlg::ES256K, "secp256k1"),
            (SigningAlg::EdDSA, "Ed25519"),
            (SigningAlg::Ed25519, "Ed25519"),
        ];
        // The table covers every known algorithm except `none`.
        assert_eq!(table.len() + 1, SigningAlg::KNOWN.len());
        for (alg, family) in table {
            for (kind, key) in &keys {
                assert_eq!(
                    key.material().serves_signing_alg(alg),
                    kind == family,
                    "{alg} with a {kind} key"
                );
            }
        }
        // `none` and unknown algorithms are served by no key (RFC 8725 §3.1).
        for alg in [
            SigningAlg::None,
            SigningAlg::from("Ed448"),
            SigningAlg::from("hs256"),
        ] {
            for (kind, key) in &keys {
                assert!(
                    !key.material().serves_signing_alg(&alg),
                    "{alg} with {kind}"
                );
            }
        }
    }

    /// RFC 7517 Appendix A.1 (line breaks inside values removed).
    const A1: &str = r#"{"keys":
      [
        {"kty":"EC",
         "crv":"P-256",
         "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
         "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
         "use":"enc",
         "kid":"1"},
        {"kty":"RSA",
         "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
         "e":"AQAB",
         "alg":"RS256",
         "kid":"2011-04-29"}
      ]
    }"#;

    /// RFC 7517 Appendix A.2, which holds an RSA private key (line breaks
    /// inside values removed).
    const A2: &str = r#"{"keys":
      [
        {"kty":"EC",
         "crv":"P-256",
         "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
         "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
         "d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",
         "use":"enc",
         "kid":"1"},
        {"kty":"RSA",
         "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
         "e":"AQAB",
         "d":"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q",
         "p":"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs",
         "q":"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk",
         "dp":"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0",
         "dq":"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk",
         "qi":"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU",
         "alg":"RS256",
         "kid":"2011-04-29"}
      ]
    }"#;

    /// RFC 7517 Appendix A.3, symmetric keys.
    const A3: &str = r#"{"keys":
      [
        {"kty":"oct",
         "alg":"A128KW",
         "k":"GawgguFyGrWKav7AX4VKUg"},
        {"kty":"oct",
         "k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
         "kid":"HMAC key used in JWS spec Appendix A.1 example"}
      ]
    }"#;

    /// A set whose `keys` are the given member texts, in order.
    fn set_of(members: &[&str]) -> String {
        format!(r#"{{"keys":[{}]}}"#, members.join(","))
    }

    fn parse(json: &str) -> Result<JwkSet, Error> {
        JwkSet::from_json(json.as_bytes())
    }

    fn kids(set: &JwkSet) -> Vec<Option<&str>> {
        set.keys().iter().map(Jwk::kid).collect()
    }

    #[test]
    fn rfc7517_a1_public_keys_parse_in_order() {
        let set = parse(A1).unwrap();
        assert_eq!(set.len(), 2);
        assert!(!set.is_empty());
        assert_eq!(set.skipped(), 0);
        assert_eq!(kids(&set), [Some("1"), Some("2011-04-29")]);
        assert_eq!(set.keys()[0].key_type(), KeyType::Ec);
        assert_eq!(set.keys()[1].key_type(), KeyType::Rsa);
        assert!(set.other_params().is_empty());
    }

    #[test]
    fn rfc7517_a3_symmetric_keys_parse_in_order() {
        let set = parse(A3).unwrap();
        assert_eq!(set.len(), 2);
        assert_eq!(set.skipped(), 0);
        assert!(set.keys().iter().all(|k| k.key_type() == KeyType::Oct));
        assert_eq!(
            set.keys()[0].alg(),
            Some(&KeyAlg::KeyMgmt(KeyMgmtAlg::A128KW))
        );
        assert_eq!(
            kids(&set),
            [None, Some("HMAC key used in JWS spec Appendix A.1 example")]
        );
    }

    /// ADR 0021 and ADR 0029 §3: an RSA private member fails the whole set,
    /// so a publisher that leaked its private key is not silently used.
    #[test]
    fn rfc7517_a2_rsa_private_key_fails_the_whole_set() {
        assert_eq!(parse(A2).unwrap_err(), Error::UnsupportedAlgorithm);
    }

    /// RFC 7517 §5 / ADR 0029 §3: members of a key type or curve polyjose
    /// does not support are skipped, not fatal.
    #[test]
    fn unsupported_key_kinds_are_skipped() {
        let unsupported = [
            r#"{"kty":"XYZ","kid":"made-up"}"#,
            r#"{"kty":"OKP","crv":"Ed448","x":"AAAA","kid":"ed448"}"#,
            r#"{"kty":"OKP","crv":"X448","x":"AAAA"}"#,
            r#"{"kty":"EC","crv":"P-192","x":"AAAA","y":"AAAA"}"#,
            r#"{"kty":"EC","crv":"Ed25519","x":"AAAA"}"#,
            r#"{"kty":"ec","crv":"P-256"}"#,
        ];
        for member in unsupported {
            let json = set_of(&[ED25519, member, EC_P256]);
            let set = parse(&json).unwrap_or_else(|e| panic!("{member}: {e:?}"));
            assert_eq!(set.len(), 2, "{member}");
            assert_eq!(set.skipped(), 1, "{member}");
            assert_eq!(set.keys()[0].key_type(), KeyType::Okp);
            assert_eq!(set.keys()[1].key_type(), KeyType::Ec);
        }
    }

    /// LEAD DECISION (RFC 7517 §5: implementations "SHOULD ignore JWKs
    /// within a JWK Set that ... are missing required members, or for which
    /// values are out of the supported ranges"): every other invalid member
    /// is skipped too.
    #[test]
    fn invalid_members_are_skipped() {
        let invalid = [
            // Not a JSON object (RFC 7517 §5: an array of JWK values).
            r#""a string""#,
            "42",
            "null",
            "true",
            "[]",
            "{}",
            // kty missing or not a string (RFC 7517 §4.1).
            r#"{"crv":"P-256"}"#,
            r#"{"kty":7}"#,
            // Missing required members (RFC 7518 §6).
            r#"{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4"}"#,
            r#"{"kty":"EC","x":"AAAA"}"#,
            r#"{"kty":"oct"}"#,
            r#"{"kty":"RSA","e":"AQAB"}"#,
            // Wrong lengths, and an empty oct key.
            r#"{"kty":"OKP","crv":"Ed25519","x":"AAAA"}"#,
            r#"{"kty":"oct","k":""}"#,
            // An RSA modulus under 2048 bits (RFC 7518 §3.3).
            r#"{"kty":"RSA","n":"AQAB","e":"AQAB"}"#,
            // Not canonical base64url (RFC 7515 §2).
            r#"{"kty":"oct","k":"AA=="}"#,
            r#"{"kty":"oct","k":"!!!!"}"#,
            // Wrongly typed common members, duplicate key_ops, and use/key_ops
            // inconsistency (RFC 7517 §4.2-§4.5).
            r#"{"kty":"oct","k":"AAEC","kid":1}"#,
            r#"{"kty":"oct","k":"AAEC","use":["sig"]}"#,
            r#"{"kty":"oct","k":"AAEC","key_ops":["sign","sign"]}"#,
            r#"{"kty":"oct","k":"AAEC","use":"sig","key_ops":["encrypt"]}"#,
        ];
        for member in invalid {
            let json = set_of(&[OCT, member, RSA_2048]);
            let set = parse(&json).unwrap_or_else(|e| panic!("{member}: {e:?}"));
            assert_eq!(set.skipped(), 1, "{member}");
            assert_eq!(
                set.keys().iter().map(Jwk::key_type).collect::<Vec<_>>(),
                [KeyType::Oct, KeyType::Rsa],
                "{member}"
            );
        }
    }

    /// ADR 0021: any RSA private member (RFC 7518 §6.3.2), whatever else
    /// the member holds and wherever it sits, fails the whole set.
    #[test]
    fn any_rsa_private_member_fails_the_whole_set() {
        let private = [
            r#"{"kty":"RSA","d":"AQAB"}"#,
            r#"{"kty":"RSA","n":"AQAB","e":"AQAB","p":"AQAB"}"#,
            r#"{"kty":"RSA","oth":[]}"#,
            r#"{"kty":"RSA","qi":7,"kid":"broken"}"#,
        ];
        for member in private {
            for members in [
                [member, OCT, EC_P256],
                [OCT, member, EC_P256],
                [r#"{"kty":"XYZ"}"#, r#"{"kty":"oct"}"#, member],
            ] {
                assert_eq!(
                    parse(&set_of(&members)).unwrap_err(),
                    Error::UnsupportedAlgorithm,
                    "{members:?}"
                );
            }
        }
    }

    /// Document-level problems fail the whole set: JSON syntax, duplicate
    /// member names at any level (RFC 7517 §4, §5; RFC 7493 §2.3), the
    /// parser limits, and a document that is not an object.
    #[test]
    fn json_level_errors_fail_the_whole_set() {
        let deep = format!(
            r#"{{"keys":[{{"kty":"XYZ","x":{}1{}}}]}}"#,
            "[".repeat(40),
            "]".repeat(40)
        );
        let documents = [
            String::new(),
            "{".to_owned(),
            r#"{"keys":[]"#.to_owned(),
            r#"{"keys":[],}"#.to_owned(),
            r#"{"keys":[],"keys":[]}"#.to_owned(),
            set_of(&[r#"{"kty":"oct","k":"AAEC","kty":"oct"}"#]),
            set_of(&[r#"{"kty":"XYZ","a":{"b":1,"b":2}}"#]),
            r#"{"keys":[],"x":{"y":1,"y":1}}"#.to_owned(),
            deep,
            "[]".to_owned(),
            r#""keys""#.to_owned(),
            "null".to_owned(),
        ];
        for json in &documents {
            assert!(
                matches!(parse(json), Err(Error::InvalidJson(_))),
                "{json}: {:?}",
                parse(json)
            );
        }
        let invalid_utf8 = b"{\"keys\":[],\"x\":\"\xff\"}";
        assert!(matches!(
            JwkSet::from_json(invalid_utf8),
            Err(Error::InvalidJson(_))
        ));
    }

    /// RFC 7517 §5: "The JSON object MUST have a "keys" member, with a
    /// value that is an array of JWKs." Without one it is a malformed key
    /// set: `InvalidKey` (ADR 0018 Q3).
    #[test]
    fn missing_or_non_array_keys_is_invalid_key() {
        for json in [
            "{}",
            r#"{"Keys":[]}"#,
            r#"{"keys":null}"#,
            r#"{"keys":{}}"#,
            r#"{"keys":"[]"}"#,
            r#"{"keys":1}"#,
            &format!(r#"{{"keys":{OCT}}}"#),
        ] {
            assert!(
                matches!(parse(json), Err(Error::InvalidKey(_))),
                "{json}: {:?}",
                parse(json)
            );
        }
    }

    #[test]
    fn an_empty_or_all_skipped_set_is_empty() {
        let set = parse(r#"{"keys":[]}"#).unwrap();
        assert!(set.is_empty());
        assert_eq!((set.len(), set.skipped()), (0, 0));
        let set = parse(&set_of(&[r#"{"kty":"XYZ"}"#, "{}"])).unwrap();
        assert!(set.is_empty());
        assert_eq!(set.skipped(), 2);
    }

    /// RFC 7517 §5: "Additional members can be present in the JWK Set";
    /// they are kept, in order.
    #[test]
    fn other_top_level_members_are_preserved_in_order() {
        let set = parse(r#"{"z":1,"keys":[],"a":{"b":[true]},"m":"s"}"#).unwrap();
        let names: Vec<&str> = set.other_params().iter().map(|(n, _)| n).collect();
        assert_eq!(names, ["z", "a", "m"]);
        assert_eq!(
            set.other_params().get("m").and_then(json::Value::as_str),
            Some("s")
        );
    }

    #[test]
    fn from_object_matches_from_json() {
        let object = json::parse(A1.as_bytes()).unwrap().into_object().unwrap();
        let from_object = JwkSet::from_object(&object).unwrap();
        let from_json = parse(A1).unwrap();
        assert_eq!(kids(&from_object), kids(&from_json));
        let object = json::parse(A2.as_bytes()).unwrap().into_object().unwrap();
        assert_eq!(
            JwkSet::from_object(&object).unwrap_err(),
            Error::UnsupportedAlgorithm
        );
    }

    /// Debug shows each key's redacted Debug and only the names of the
    /// other members, never secret values.
    #[test]
    fn debug_never_shows_secrets() {
        let secret_k = "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow";
        let ec_d = "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE";
        let ec_private = format!(
            r#"{{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","d":"{ec_d}"}}"#
        );
        let json = format!(r#"{{"keys":[{OCT},{ec_private}],"secret_value_member":"hunter2"}}"#);
        let set = parse(&json).unwrap();
        let debug = format!("{set:?}");
        assert!(!debug.contains(secret_k), "{debug}");
        assert!(!debug.contains(ec_d), "{debug}");
        assert!(!debug.contains("hunter2"), "{debug}");
        assert!(debug.contains("secret_value_member"), "{debug}");
        assert!(debug.contains("<redacted>"), "{debug}");
        assert!(debug.contains("skipped"), "{debug}");
    }

    /// `member` with extra common members spliced in after its opening
    /// brace, e.g. `with(OCT, r#""kid":"a""#)`.
    fn with(member: &str, extra: &str) -> String {
        match &member[1..] {
            "}" => format!("{{{extra}}}"),
            rest => format!("{{{extra},{rest}"),
        }
    }

    /// The indices `verification_candidates` returns.
    fn candidates(set: &JwkSet, alg: &SigningAlg, kid: Option<&str>) -> Vec<usize> {
        let found: Vec<(usize, &Jwk)> = set.verification_candidates(alg, kid).collect();
        for (index, key) in &found {
            assert!(core::ptr::eq(*key, &set.keys()[*index]));
        }
        found.into_iter().map(|(index, _)| index).collect()
    }

    fn set_from(members: &[String]) -> JwkSet {
        let members: Vec<&str> = members.iter().map(String::as_str).collect();
        parse(&set_of(&members)).unwrap()
    }

    #[test]
    fn rfc7517_a1_selection() {
        let set = parse(A1).unwrap();
        assert_eq!(
            candidates(&set, &SigningAlg::RS256, Some("2011-04-29")),
            [1]
        );
        assert_eq!(candidates(&set, &SigningAlg::RS256, None), [1]);
        // The JWK `alg` is RS256 (RFC 7517 §4.4).
        assert!(candidates(&set, &SigningAlg::PS256, None).is_empty());
        // The EC key is `use` `enc` (RFC 7517 §4.2).
        assert!(candidates(&set, &SigningAlg::ES256, Some("1")).is_empty());
        assert!(candidates(&set, &SigningAlg::ES256, None).is_empty());
    }

    /// RFC 7515 §4.1.4, RFC 7517 §4.5: a header `kid` selects the members
    /// with an identical `kid` (exact, case-sensitive).
    #[test]
    fn header_kid_selects_by_exact_kid() {
        let set = set_from(&[
            with(OCT, r#""kid":"a""#),
            with(OCT, r#""kid":"b""#),
            OCT.to_owned(),
            with(OCT, r#""kid":"A""#),
            with(OCT, r#""kid":"a""#),
        ]);
        let hs = SigningAlg::HS256;
        assert_eq!(candidates(&set, &hs, Some("a")), [0, 4]);
        assert_eq!(candidates(&set, &hs, Some("A")), [3]);
        assert_eq!(candidates(&set, &hs, Some("b")), [1]);
        // No member carries this kid, and a kid-less member never matches
        // a header kid.
        for kid in ["c", "", "a ", " a", "\u{0430}"] {
            assert!(candidates(&set, &hs, Some(kid)).is_empty(), "{kid:?}");
        }
    }

    /// ADR 0029 §2 item 5 and the T07 criterion: without a header `kid`,
    /// every compatible member is a candidate, with or without a `kid`.
    #[test]
    fn without_header_kid_all_compatible_keys_are_candidates() {
        let set = set_from(&[
            OCT.to_owned(),
            EC_P256.to_owned(),
            with(OCT, r#""use":"sig""#),
            with(OCT, r#""kid":"k1""#),
            OCT.to_owned(),
            with(OCT, r#""use":"enc""#),
        ]);
        assert_eq!(candidates(&set, &SigningAlg::HS256, None), [0, 2, 3, 4]);
        assert_eq!(candidates(&set, &SigningAlg::HS512, None), [0, 2, 3, 4]);
        assert_eq!(candidates(&set, &SigningAlg::ES256, None), [1]);
    }

    /// RFC 7517 §4.4, RFC 8725 §3.1: a JWK `alg` must equal the header
    /// `alg` exactly; absent allows any algorithm of the family.
    #[test]
    fn jwk_alg_must_equal_header_alg() {
        let set = set_from(&[
            with(RSA_2048, r#""alg":"RS256""#),
            with(RSA_2048, r#""alg":"RS384""#),
            RSA_2048.to_owned(),
            with(RSA_2048, r#""alg":"PS256""#),
            with(RSA_2048, r#""alg":"rs256""#),
            with(RSA_2048, r#""alg":"RSA-OAEP-256""#),
        ]);
        assert_eq!(candidates(&set, &SigningAlg::RS256, None), [0, 2]);
        assert_eq!(candidates(&set, &SigningAlg::RS384, None), [1, 2]);
        assert_eq!(candidates(&set, &SigningAlg::PS256, None), [2, 3]);
        assert_eq!(candidates(&set, &SigningAlg::PS512, None), [2]);
        // An oct key bound to a JWE algorithm serves no JWS algorithm.
        let set = set_from(&[
            with(OCT, r#""alg":"A128KW""#),
            with(OCT, r#""alg":"HS256""#),
        ]);
        assert_eq!(candidates(&set, &SigningAlg::HS256, None), [1]);
        assert!(candidates(&set, &SigningAlg::HS384, None).is_empty());
    }

    /// RFC 9864 §2.2, ADR 0026 §2 step 8: `EdDSA` and `Ed25519` are
    /// different JWK `alg` values, although both are served by an Ed25519
    /// key.
    #[test]
    fn eddsa_is_not_ed25519() {
        let set = set_from(&[
            with(ED25519, r#""alg":"EdDSA""#),
            with(ED25519, r#""alg":"Ed25519""#),
            ED25519.to_owned(),
            X25519.to_owned(),
        ]);
        assert_eq!(candidates(&set, &SigningAlg::EdDSA, None), [0, 2]);
        assert_eq!(candidates(&set, &SigningAlg::Ed25519, None), [1, 2]);
    }

    /// RFC 7517 §4.2-§4.3: `use` absent or `sig`, and `key_ops` absent or
    /// containing `verify`.
    #[test]
    fn use_and_key_ops_must_allow_verify() {
        let set = set_from(&[
            with(EC_P256, r#""use":"sig""#),
            with(EC_P256, r#""use":"enc""#),
            with(EC_P256, r#""use":"x-custom""#),
            with(EC_P256, r#""key_ops":["verify"]"#),
            with(EC_P256, r#""key_ops":["sign"]"#),
            with(EC_P256, r#""key_ops":["sign","verify"]"#),
            with(EC_P256, r#""key_ops":[]"#),
            with(EC_P256, r#""key_ops":["encrypt","verify"]"#),
            with(EC_P256, r#""use":"sig","key_ops":["sign"]"#),
            with(EC_P256, r#""use":"sig","key_ops":["verify"]"#),
            with(EC_P256, r#""key_ops":["Verify"]"#),
        ]);
        assert_eq!(set.skipped(), 0);
        assert_eq!(candidates(&set, &SigningAlg::ES256, None), [0, 3, 5, 7, 9]);
    }

    /// ADR 0026 §2 step 8 via ADR 0029 §2 item 1: the key's family must
    /// serve the header `alg`.
    #[test]
    fn family_must_match() {
        let set = set_from(&[
            EC_P256.to_owned(),
            OCT.to_owned(),
            ec("P-384", 48).to_json().to_string(),
            RSA_2048.to_owned(),
            ED25519.to_owned(),
        ]);
        assert_eq!(candidates(&set, &SigningAlg::HS256, None), [1]);
        assert_eq!(candidates(&set, &SigningAlg::ES256, None), [0]);
        assert_eq!(candidates(&set, &SigningAlg::ES384, None), [2]);
        assert!(candidates(&set, &SigningAlg::ES512, None).is_empty());
        assert!(candidates(&set, &SigningAlg::ES256K, None).is_empty());
        assert_eq!(candidates(&set, &SigningAlg::RS256, None), [3]);
        assert_eq!(candidates(&set, &SigningAlg::EdDSA, None), [4]);
        // A kid match does not override the family.
        let set = set_from(&[with(EC_P256, r#""kid":"k""#)]);
        assert!(candidates(&set, &SigningAlg::HS256, Some("k")).is_empty());
    }

    /// RFC 8725 §3.1: `none` and unknown algorithms select nothing, even
    /// for a key whose `alg` names them.
    #[test]
    fn none_and_unknown_algorithms_select_nothing() {
        let set = set_from(&[
            OCT.to_owned(),
            with(OCT, r#""alg":"none""#),
            with(OCT, r#""alg":"HS999""#),
            RSA_2048.to_owned(),
        ]);
        for alg in [
            SigningAlg::None,
            SigningAlg::from("HS999"),
            SigningAlg::from(""),
        ] {
            assert!(candidates(&set, &alg, None).is_empty(), "{alg}");
        }
    }

    /// ADR 0029 §3: EC and OKP members with private parameters are
    /// candidates; only their public part is used to verify.
    #[test]
    fn ec_private_members_are_candidates() {
        let set = parse(&set_of(&[
            r#"{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE","kid":"1"}"#,
        ]))
        .unwrap();
        assert_eq!(candidates(&set, &SigningAlg::ES256, Some("1")), [0]);
    }

    /// ADR 0029 §4: `key_index` is the position in [`JwkSet::keys`], which
    /// leaves skipped entries out.
    #[test]
    fn indices_count_kept_keys_only() {
        let set = set_from(&[
            r#"{"kty":"XYZ"}"#.to_owned(),
            with(OCT, r#""kid":"a""#),
            "{}".to_owned(),
            with(OCT, r#""kid":"b""#),
        ]);
        assert_eq!(set.skipped(), 2);
        assert_eq!(candidates(&set, &SigningAlg::HS256, Some("b")), [1]);
        assert_eq!(candidates(&set, &SigningAlg::HS256, None), [0, 1]);
    }

    /// ADR 0008 layer 2: parser robustness and the selection filter against
    /// an independent oracle.
    mod properties {
        use proptest::prelude::*;

        use super::*;

        /// What a pool member must do to the set.
        #[derive(Clone, Copy, Debug)]
        enum Expect {
            /// Kept, with its family tag, JWK `alg`, `use` and `key_ops`.
            Keep(
                &'static str,
                Option<&'static str>,
                Option<&'static str>,
                Option<&'static [&'static str]>,
            ),
            Skip,
            /// An RSA private key: the whole set fails.
            Fatal,
        }

        /// Pool members (objects, so a `kid` can be spliced in), each with
        /// its expected outcome.
        fn pool() -> Vec<(String, Expect)> {
            use Expect::{Fatal, Keep, Skip};
            vec![
                (OCT.to_owned(), Keep("oct", None, None, None)),
                (
                    with(OCT, r#""alg":"HS384""#),
                    Keep("oct", Some("HS384"), None, None),
                ),
                (
                    with(OCT, r#""use":"enc""#),
                    Keep("oct", None, Some("enc"), None),
                ),
                (
                    with(OCT, r#""alg":"A128KW""#),
                    Keep("oct", Some("A128KW"), None, None),
                ),
                (EC_P256.to_owned(), Keep("P-256", None, None, None)),
                (
                    with(EC_P256, r#""use":"sig""#),
                    Keep("P-256", None, Some("sig"), None),
                ),
                (
                    with(EC_P256, r#""key_ops":["sign"]"#),
                    Keep("P-256", None, None, Some(&["sign"])),
                ),
                (
                    with(EC_P256, r#""key_ops":["verify"]"#),
                    Keep("P-256", None, None, Some(&["verify"])),
                ),
                (
                    ec("P-384", 48).to_json().to_string(),
                    Keep("P-384", None, None, None),
                ),
                (
                    ec("secp256k1", 32).to_json().to_string(),
                    Keep("secp256k1", None, None, None),
                ),
                (RSA_2048.to_owned(), Keep("RSA", None, None, None)),
                (
                    with(RSA_2048, r#""alg":"PS256""#),
                    Keep("RSA", Some("PS256"), None, None),
                ),
                (ED25519.to_owned(), Keep("Ed25519", None, None, None)),
                (
                    with(ED25519, r#""alg":"Ed25519""#),
                    Keep("Ed25519", Some("Ed25519"), None, None),
                ),
                (
                    with(ED25519, r#""alg":"EdDSA""#),
                    Keep("Ed25519", Some("EdDSA"), None, None),
                ),
                (
                    with(ED25519, r#""use":"x-other""#),
                    Keep("Ed25519", None, Some("x-other"), None),
                ),
                (X25519.to_owned(), Keep("X25519", None, None, None)),
                (r#"{"kty":"XYZ"}"#.to_owned(), Skip),
                (r#"{"kty":"OKP","crv":"Ed448","x":"AA"}"#.to_owned(), Skip),
                (
                    r#"{"kty":"EC","crv":"P-256","x":"AA","y":"AA"}"#.to_owned(),
                    Skip,
                ),
                (r#"{"kty":"RSA","n":"AQAB","e":"AQAB"}"#.to_owned(), Skip),
                (r#"{"kty":"oct","k":"AA=="}"#.to_owned(), Skip),
                ("{}".to_owned(), Skip),
                (r#"{"kty":"RSA","d":"AQAB"}"#.to_owned(), Fatal),
            ]
        }

        /// The ADR 0026 §2 step 8 table restated as test data: the family
        /// tag that serves each JWS `alg`.
        fn family_of(alg: &str) -> Option<&'static str> {
            Some(match alg {
                "HS256" | "HS384" | "HS512" => "oct",
                "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512" => "RSA",
                "ES256" => "P-256",
                "ES384" => "P-384",
                "ES512" => "P-521",
                "ES256K" => "secp256k1",
                "EdDSA" | "Ed25519" => "Ed25519",
                _ => return None,
            })
        }

        const KIDS: &[Option<&str>] = &[None, Some("a"), Some("b"), Some("A")];

        /// Header `alg` values: every known one, plus unknown strings.
        fn header_alg() -> impl Strategy<Value = SigningAlg> {
            let mut algs: Vec<SigningAlg> = SigningAlg::KNOWN.to_vec();
            algs.push(SigningAlg::from("HS1"));
            algs.push(SigningAlg::from("A128KW"));
            prop::sample::select(algs)
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(512))]

            /// No input makes set parsing panic, and every failure is one of
            /// the three set-level codes.
            #[test]
            fn arbitrary_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
                match JwkSet::from_json(&bytes) {
                    Ok(set) => prop_assert!(set.len() + set.skipped() <= bytes.len()),
                    Err(e) => prop_assert!(
                        matches!(e, Error::InvalidJson(_) | Error::InvalidKey(_) | Error::UnsupportedAlgorithm),
                        "{e:?}"
                    ),
                }
            }

            /// Byte mutations of RFC 7517 A.1 never panic and fail only with
            /// the set-level codes.
            #[test]
            fn mutated_a1_never_panics(
                edits in prop::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..4)
            ) {
                let mut bytes = A1.as_bytes().to_vec();
                for (index, byte) in edits {
                    let at = index.index(bytes.len());
                    bytes[at] = byte;
                }
                if let Err(e) = JwkSet::from_json(&bytes) {
                    prop_assert!(
                        matches!(e, Error::InvalidJson(_) | Error::InvalidKey(_) | Error::UnsupportedAlgorithm),
                        "{e:?}"
                    );
                }
            }

            /// Generated sets: kept, skipped and fatal members behave as the
            /// pool says, order is preserved, and the candidates are exactly
            /// the kept keys the oracle accepts, in order.
            #[test]
            fn generated_sets_and_selection_match_the_oracle(
                picks in prop::collection::vec(
                    (any::<prop::sample::Index>(), prop::sample::select(KIDS)),
                    0..12,
                ),
                alg in header_alg(),
                header_kid in prop::sample::select(KIDS),
            ) {
                let pool = pool();
                let mut members = Vec::new();
                let mut expected = Vec::new();
                let mut fatal = false;
                for (index, kid) in &picks {
                    let (json, expect) = &pool[index.index(pool.len())];
                    let json = match kid {
                        Some(kid) => with(json, &format!(r#""kid":"{kid}""#)),
                        None => json.clone(),
                    };
                    members.push(json);
                    match expect {
                        Expect::Keep(..) => expected.push((*expect, *kid)),
                        Expect::Skip => {}
                        Expect::Fatal => fatal = true,
                    }
                }
                let members: Vec<&str> = members.iter().map(String::as_str).collect();
                let result = parse(&set_of(&members));
                if fatal {
                    prop_assert_eq!(result.unwrap_err(), Error::UnsupportedAlgorithm);
                    return Ok(());
                }
                let set = result.unwrap();
                prop_assert_eq!(set.len(), expected.len());
                prop_assert_eq!(set.skipped(), picks.len() - expected.len());
                let expected_kids: Vec<Option<&str>> = expected.iter().map(|(_, kid)| *kid).collect();
                prop_assert_eq!(kids(&set), expected_kids);

                let oracle: Vec<usize> = expected
                    .iter()
                    .enumerate()
                    .filter(|(_, (expect, kid))| {
                        let Expect::Keep(family, key_alg, key_use, key_ops) = *expect else {
                            unreachable!()
                        };
                        family_of(alg.as_str()) == Some(family)
                            && key_alg.is_none_or(|a| a == alg.as_str())
                            && key_use.is_none_or(|u| u == "sig")
                            && key_ops.is_none_or(|ops| ops.contains(&"verify"))
                            && header_kid.is_none_or(|h| *kid == Some(h))
                    })
                    .map(|(index, _)| index)
                    .collect();
                prop_assert_eq!(candidates(&set, &alg, header_kid), oracle);
            }
        }
    }

    /// ADR 0054 §2: the one candidate rule, check by check. Each test uses
    /// a set whose members differ only in the property under test.
    mod rule {
        use super::*;
        use crate::jwa::{KeyMgmtAlg, SigningAlg};
        use crate::jwe::key_ops_either_direction;
        use crate::jwk::{JwkSelector, KeyOp, KeyUse};

        /// The selector for `alg` alone.
        fn by_alg(alg: &str) -> JwkSelector {
            JwkSelector::new().alg(KeyAlg::from(alg)).unwrap()
        }

        /// The indices `matching` yields, checking each key is the member
        /// at that index of `keys()`.
        fn matched(set: &JwkSet, selector: &JwkSelector) -> Vec<usize> {
            let found: Vec<(usize, &Jwk)> = set.matching(selector).collect();
            for (index, key) in &found {
                assert!(core::ptr::eq(*key, &set.keys()[*index]));
            }
            found.into_iter().map(|(index, _)| index).collect()
        }

        /// One key of every family the core imports, with no `alg`, `use`,
        /// `key_ops` or `kid`, so only the family differs.
        fn families() -> JwkSet {
            let set = set_from(&[
                OCT.to_owned(),
                RSA_2048.to_owned(),
                EC_P256.to_owned(),
                ec("P-384", 48).to_json().to_string(),
                ec("P-521", 66).to_json().to_string(),
                ec("secp256k1", 32).to_json().to_string(),
                ED25519.to_owned(),
                X25519.to_owned(),
            ]);
            assert_eq!(set.len(), 8);
            set
        }
        const OCT_I: usize = 0;
        const RSA_I: usize = 1;
        const P256_I: usize = 2;
        const P384_I: usize = 3;
        const P521_I: usize = 4;
        const K256_I: usize = 5;
        const ED25519_I: usize = 6;
        const X25519_I: usize = 7;

        /// ADR 0054 §2 item 1: the family check is the core's two tables,
        /// row by row, for every implemented JWS and JWE key management
        /// `alg` (ADR 0026 §2 step 8; RFC 7518 §3.1, §4.1; RFC 8037 §3).
        #[test]
        fn family_follows_the_core_tables_for_every_alg() {
            let set = families();
            let jws: &[(&str, &[usize])] = &[
                ("HS256", &[OCT_I]),
                ("HS384", &[OCT_I]),
                ("HS512", &[OCT_I]),
                ("RS256", &[RSA_I]),
                ("RS384", &[RSA_I]),
                ("RS512", &[RSA_I]),
                ("PS256", &[RSA_I]),
                ("PS384", &[RSA_I]),
                ("PS512", &[RSA_I]),
                ("ES256", &[P256_I]),
                ("ES384", &[P384_I]),
                ("ES512", &[P521_I]),
                ("ES256K", &[K256_I]),
                ("EdDSA", &[ED25519_I]),
                ("Ed25519", &[ED25519_I]),
            ];
            assert_eq!(
                jws.len() + 1,
                SigningAlg::KNOWN.len(),
                "every JWS alg but none"
            );
            let ecdh: &[usize] = &[P256_I, P384_I, P521_I, X25519_I];
            let jwe: &[(&str, &[usize])] = &[
                ("RSA-OAEP-256", &[RSA_I]),
                ("A128KW", &[OCT_I]),
                ("A192KW", &[OCT_I]),
                ("A256KW", &[OCT_I]),
                ("dir", &[OCT_I]),
                ("A128GCMKW", &[OCT_I]),
                ("A192GCMKW", &[OCT_I]),
                ("A256GCMKW", &[OCT_I]),
                ("PBES2-HS256+A128KW", &[OCT_I]),
                ("PBES2-HS384+A192KW", &[OCT_I]),
                ("PBES2-HS512+A256KW", &[OCT_I]),
                ("ECDH-ES", ecdh),
                ("ECDH-ES+A128KW", ecdh),
                ("ECDH-ES+A192KW", ecdh),
                ("ECDH-ES+A256KW", ecdh),
            ];
            assert_eq!(
                jwe.len(),
                KeyMgmtAlg::KNOWN.len(),
                "every JWE key management alg"
            );
            for (alg, expected) in jws.iter().chain(jwe) {
                assert_eq!(matched(&set, &by_alg(alg)), *expected, "{alg}");
            }
        }

        /// ADR 0054 §2 item 1, the consequences it names: selection by
        /// `alg` never crosses key families (ADR 0054 §7).
        #[test]
        fn family_never_crosses_for_the_named_pairs() {
            let set = families();
            let never: &[(usize, &[&str])] = &[
                (
                    OCT_I,
                    &["RS256", "ES256", "EdDSA", "ECDH-ES", "RSA-OAEP-256"],
                ),
                (RSA_I, &["HS256", "A128KW", "dir", "PBES2-HS256+A128KW"]),
                (P256_I, &["HS256", "A128KW", "dir", "PBES2-HS256+A128KW"]),
                (X25519_I, &["EdDSA"]),
                (ED25519_I, &["ECDH-ES"]),
                (K256_I, &["ECDH-ES"]),
                (P384_I, &["ES256"]),
            ];
            for (member, algs) in never {
                for alg in *algs {
                    assert!(
                        !matched(&set, &by_alg(alg)).contains(member),
                        "{member} {alg}"
                    );
                }
            }
            // A `kid` never overrides the family.
            let set = set_from(&[with(OCT, r#""kid":"k""#)]);
            assert!(matched(&set, &by_alg("ES256").kid("k")).is_empty());
        }

        /// ADR 0054 §2 item 2: a member `alg` is absent or exactly the
        /// selector's (RFC 7517 §4.4, RFC 8725 §3.1).
        #[test]
        fn jwk_alg_is_absent_or_exact() {
            // RFC 9864 §2.2: `EdDSA` and `Ed25519` differ.
            let set = set_from(&[
                with(ED25519, r#""alg":"EdDSA""#),
                with(ED25519, r#""alg":"Ed25519""#),
                ED25519.to_owned(),
            ]);
            assert_eq!(matched(&set, &by_alg("EdDSA")), [0, 2]);
            assert_eq!(matched(&set, &by_alg("Ed25519")), [1, 2]);

            let set = set_from(&[
                with(OCT, r#""alg":"A128KW""#),
                with(OCT, r#""alg":"A256KW""#),
                OCT.to_owned(),
                with(OCT, r#""alg":"x-unregistered""#),
                with(OCT, r#""alg":"HS256""#),
            ]);
            assert_eq!(set.len(), 5);
            assert_eq!(matched(&set, &by_alg("A128KW")), [0, 2]);
            assert_eq!(matched(&set, &by_alg("A256KW")), [1, 2]);
            assert_eq!(matched(&set, &by_alg("HS256")), [2, 4]);
            // A JWS alg never matches a member bound to a JWE alg, and the
            // reverse.
            assert_eq!(matched(&set, &by_alg("HS384")), [2]);
            assert_eq!(matched(&set, &by_alg("A192KW")), [2]);
            // Without a selector `alg`, the member `alg` is not checked.
            assert_eq!(matched(&set, &JwkSelector::new()), [0, 1, 2, 3, 4]);
        }

        /// ADR 0054 §2 item 2, the one exception: for `dir`, and only for
        /// `dir`, a member whose `alg` names a content encryption algorithm
        /// matches (RFC 7518 §4.5, RFC 7520 §5.6.1).
        #[test]
        fn dir_alone_matches_a_member_named_by_its_enc() {
            let set = set_from(&[
                with(OCT, r#""alg":"A256GCM""#),
                with(OCT, r#""alg":"A128CBC-HS256""#),
                with(OCT, r#""alg":"dir""#),
                with(OCT, r#""alg":"A256KW""#),
            ]);
            assert_eq!(matched(&set, &by_alg("dir")), [0, 1, 2]);
            assert_eq!(matched(&set, &by_alg("A256KW")), [3]);
            assert!(matched(&set, &by_alg("A256GCMKW")).is_empty());
            assert!(matched(&set, &by_alg("PBES2-HS256+A128KW")).is_empty());
            assert!(matched(&set, &by_alg("HS256")).is_empty());
        }

        /// ADR 0054 §2 item 3: with an effective use U, a member `use` is
        /// absent or U (RFC 7517 §4.2). U comes from `key_use`, then
        /// `key_op`, then `alg`.
        #[test]
        fn purpose_comes_from_key_use_then_key_op_then_alg() {
            let set = set_from(&[
                with(EC_P256, r#""use":"sig""#),
                with(EC_P256, r#""use":"enc""#),
                EC_P256.to_owned(),
                with(EC_P256, r#""use":"x-other""#),
            ]);
            // From `alg`: JWS → sig, JWE → enc.
            assert_eq!(matched(&set, &by_alg("ES256")), [0, 2]);
            assert_eq!(matched(&set, &by_alg("ECDH-ES")), [1, 2]);
            // From `key_op`.
            let op = |op: KeyOp| JwkSelector::new().key_op(op).unwrap();
            assert_eq!(matched(&set, &op(KeyOp::Sign)), [0, 2]);
            assert_eq!(matched(&set, &op(KeyOp::Verify)), [0, 2]);
            for enc_op in [
                KeyOp::Encrypt,
                KeyOp::Decrypt,
                KeyOp::WrapKey,
                KeyOp::UnwrapKey,
                KeyOp::DeriveKey,
                KeyOp::DeriveBits,
            ] {
                assert_eq!(matched(&set, &op(enc_op.clone())), [1, 2], "{enc_op}");
            }
            // From `key_use`.
            let key_use = |u: KeyUse| JwkSelector::new().key_use(u).unwrap();
            assert_eq!(matched(&set, &key_use(KeyUse::Sig)), [0, 2]);
            assert_eq!(matched(&set, &key_use(KeyUse::Enc)), [1, 2]);
            // Parts that agree: as each alone.
            let agree = by_alg("ES256")
                .key_use(KeyUse::Sig)
                .unwrap()
                .key_op(KeyOp::Verify);
            assert_eq!(matched(&set, &agree.unwrap()), [0, 2]);

            let set = set_from(&[
                with(RSA_2048, r#""use":"sig""#),
                with(RSA_2048, r#""use":"enc""#),
                RSA_2048.to_owned(),
            ]);
            assert_eq!(matched(&set, &by_alg("RSA-OAEP-256")), [1, 2]);
            assert_eq!(matched(&set, &by_alg("RS256")), [0, 2]);
        }

        /// ADR 0054 §2 item 3: parts that disagree on the use match
        /// nothing, even a member with neither `use` nor `key_ops`.
        #[test]
        fn disagreeing_parts_match_nothing() {
            let set = set_from(&[
                EC_P256.to_owned(),
                with(EC_P256, r#""use":"enc""#),
                with(EC_P256, r#""use":"sig""#),
                OCT.to_owned(),
            ]);
            let conflicts = [
                by_alg("ES256").key_use(KeyUse::Enc).unwrap(),
                JwkSelector::new()
                    .key_op(KeyOp::Verify)
                    .unwrap()
                    .key_use(KeyUse::Enc)
                    .unwrap(),
                by_alg("ES256").key_op(KeyOp::WrapKey).unwrap(),
                by_alg("ECDH-ES").key_use(KeyUse::Sig).unwrap(),
                by_alg("ECDH-ES").key_op(KeyOp::Sign).unwrap(),
                by_alg("A128KW").key_op(KeyOp::Verify).unwrap(),
                JwkSelector::new()
                    .key_use(KeyUse::Sig)
                    .unwrap()
                    .key_op(KeyOp::DeriveKey)
                    .unwrap(),
            ];
            for selector in &conflicts {
                assert!(matched(&set, selector).is_empty(), "{selector:?}");
                assert_eq!(
                    set.select(selector).map(|(i, _)| i),
                    Err(Error::NoMatchingKey),
                    "{selector:?}"
                );
            }
        }

        /// ADR 0054 §2 item 3: without U, `use` is not checked, so a
        /// `kid`-only selector returns a `use: enc` (or unregistered `use`)
        /// member.
        #[test]
        fn without_a_purpose_use_is_not_checked() {
            let set = set_from(&[
                with(EC_P256, r#""use":"enc","kid":"e""#),
                with(EC_P256, r#""use":"x-other","kid":"x""#),
                with(EC_P256, r#""use":"sig","kid":"s""#),
            ]);
            for (index, kid) in ["e", "x", "s"].into_iter().enumerate() {
                assert_eq!(matched(&set, &JwkSelector::new().kid(kid)), [index]);
            }
            assert_eq!(matched(&set, &JwkSelector::new()), [0, 1, 2]);
        }

        /// ADR 0054 §2 item 4, with a `key_op`: exactly [`Jwk::permits`].
        #[test]
        fn key_ops_with_a_key_op_is_permits() {
            let set = set_from(&[
                with(EC_P256, r#""key_ops":["sign"]"#),
                with(EC_P256, r#""key_ops":["verify"]"#),
                with(EC_P256, r#""key_ops":["sign","verify"]"#),
                with(EC_P256, r#""key_ops":[]"#),
                EC_P256.to_owned(),
                with(EC_P256, r#""key_ops":["Verify"]"#),
                with(EC_P256, r#""key_ops":["deriveKey"]"#),
            ]);
            for op in [KeyOp::Sign, KeyOp::Verify, KeyOp::DeriveKey, KeyOp::Encrypt] {
                let selector = JwkSelector::new().key_op(op.clone()).unwrap();
                let permits: Vec<usize> = (0..set.len())
                    .filter(|i| set.keys()[*i].permits(&op))
                    .collect();
                assert_eq!(matched(&set, &selector), permits, "{op}");
            }
            let verify = JwkSelector::new().key_op(KeyOp::Verify).unwrap();
            assert_eq!(matched(&set, &verify), [1, 2, 4]);
        }

        /// ADR 0054 §2 item 4, with an `alg` and no `key_op`: at least one
        /// operation the `alg` performs in either direction, from the JWE
        /// `key_op` table (`jwe/key.rs`) for key management.
        #[test]
        fn key_ops_with_an_alg_needs_an_op_of_either_direction() {
            let ops = [
                "wrapKey",
                "unwrapKey",
                "encrypt",
                "decrypt",
                "deriveKey",
                "deriveBits",
                "sign",
                "verify",
            ];
            let cases: &[(&str, &str, &[&str])] = &[
                (OCT, "A128KW", &["wrapKey", "unwrapKey"]),
                (OCT, "A128GCMKW", &["wrapKey", "unwrapKey"]),
                (OCT, "PBES2-HS256+A128KW", &["wrapKey", "unwrapKey"]),
                (RSA_2048, "RSA-OAEP-256", &["wrapKey", "unwrapKey"]),
                (OCT, "dir", &["encrypt", "decrypt"]),
                (EC_P256, "ECDH-ES", &["deriveKey"]),
                (X25519, "ECDH-ES+A128KW", &["deriveKey"]),
                (EC_P256, "ES256", &["sign", "verify"]),
                (OCT, "HS256", &["sign", "verify"]),
            ];
            for (material, alg, allowed) in cases {
                let members: Vec<String> = ops
                    .iter()
                    .map(|op| with(material, &format!(r#""key_ops":["{op}"]"#)))
                    .chain([with(material, r#""key_ops":[]"#), material.to_string()])
                    .collect();
                let set = set_from(&members);
                assert_eq!(set.len(), ops.len() + 2);
                let mut expected: Vec<usize> = ops
                    .iter()
                    .enumerate()
                    .filter(|(_, op)| allowed.contains(op))
                    .map(|(i, _)| i)
                    .collect();
                // No `key_ops` at all: not checked.
                expected.push(ops.len() + 1);
                assert_eq!(matched(&set, &by_alg(alg)), expected, "{alg}");
            }
        }

        /// The helper reads `jwe/key.rs` `key_op` for both directions, for
        /// every implemented JWE key management `alg`.
        #[test]
        fn the_jwe_key_ops_of_every_alg_come_from_key_op() {
            for alg in KeyMgmtAlg::KNOWN {
                let ops = key_ops_either_direction(alg);
                assert!(ops.iter().all(Option::is_some), "{alg}");
            }
            assert_eq!(
                key_ops_either_direction(&KeyMgmtAlg::from("RSA1_5")),
                [None, None]
            );
        }

        /// ADR 0054 §2 item 4, with only U: any registered operation of U
        /// (RFC 7517 §4.3).
        #[test]
        fn key_ops_with_only_a_use_needs_an_op_of_that_use() {
            let set = set_from(&[
                with(OCT, r#""key_ops":["sign"]"#),
                with(OCT, r#""key_ops":["encrypt"]"#),
                with(OCT, r#""key_ops":["x-op"]"#),
                with(OCT, r#""key_ops":[]"#),
                with(OCT, r#""key_ops":["deriveBits"]"#),
                OCT.to_owned(),
                with(OCT, r#""key_ops":["x-op","verify"]"#),
            ]);
            let key_use = |u: KeyUse| JwkSelector::new().key_use(u).unwrap();
            assert_eq!(matched(&set, &key_use(KeyUse::Sig)), [0, 5, 6]);
            assert_eq!(matched(&set, &key_use(KeyUse::Enc)), [1, 4, 5]);
            // Without U, `alg` or `key_op`, `key_ops` is not checked.
            assert_eq!(matched(&set, &JwkSelector::new()), [0, 1, 2, 3, 4, 5, 6]);
        }

        /// ADR 0054 §1.2 and §2 item 5: `kid` is exact, case-sensitive
        /// equality (RFC 7517 §4.5), never a pattern or a path
        /// (RFC 8725 §3.10). A member without a `kid` never matches a
        /// selector with one.
        #[test]
        fn kid_is_exact_equality_only() {
            let set = set_from(&[
                with(OCT, r#""kid":"a""#),
                with(OCT, r#""kid":"A""#),
                OCT.to_owned(),
                with(OCT, r#""kid":"a ""#),
                with(OCT, r#""kid":"../keys/a""#),
                with(OCT, r#""kid":"""#),
            ]);
            let kid = |kid: &str| matched(&set, &JwkSelector::new().kid(kid));
            assert_eq!(kid("a"), [0]);
            assert_eq!(kid("A"), [1]);
            assert_eq!(kid("a "), [3]);
            assert_eq!(kid("../keys/a"), [4]);
            assert_eq!(kid(""), [5]);
            for absent in ["*", "a*", "%61", "\u{0430}", "keys/a", "b"] {
                assert!(kid(absent).is_empty(), "{absent:?}");
            }
        }

        /// A selector holding an `alg` its setter refuses (impossible
        /// through the public API) matches nothing: selection fails closed.
        #[test]
        fn an_alg_the_setter_refuses_matches_nothing() {
            let set = families();
            for alg in ["A256GCM", "none", "RSA1_5"] {
                let selector = JwkSelector {
                    alg: Some(KeyAlg::from(alg)),
                    ..JwkSelector::default()
                };
                assert!(matched(&set, &selector).is_empty(), "{alg}");
            }
            let set = set_from(&[with(OCT, r#""alg":"A256GCM""#)]);
            let selector = JwkSelector {
                alg: Some(KeyAlg::from("A256GCM")),
                ..JwkSelector::default()
            };
            assert!(matched(&set, &selector).is_empty());
        }
    }

    /// ADR 0054 §4 (results) and §7 (misuse resistance).
    mod results {
        use core::cell::Cell;

        use super::*;
        use crate::jwa::SigningAlg;
        use crate::jwk::set::{Criteria, exactly_one};
        use crate::jwk::{JwkSelector, KeyUse};
        use crate::jws::{VerifyOptions, verify_compact};

        /// The index `select` returns, checking the key is the member at
        /// that index of `keys()`.
        fn selected(set: &JwkSet, selector: &JwkSelector) -> Result<usize, Error> {
            set.select(selector).map(|(index, key)| {
                assert!(core::ptr::eq(key, &set.keys()[index]));
                index
            })
        }

        fn by_alg(alg: &str) -> JwkSelector {
            JwkSelector::new().alg(KeyAlg::from(alg)).unwrap()
        }

        /// One match: its `key_index`, an index into `keys()` that leaves
        /// skipped entries out (ADR 0029 §4).
        #[test]
        fn select_returns_the_one_match_with_its_key_index() {
            let set = set_from(&[
                r#"{"kty":"XYZ","kid":"b"}"#.to_owned(),
                with(OCT, r#""kid":"a""#),
                "{}".to_owned(),
                with(OCT, r#""kid":"b""#),
            ]);
            assert_eq!(set.skipped(), 2);
            assert_eq!(selected(&set, &JwkSelector::new().kid("b")), Ok(1));
            assert_eq!(selected(&set, &JwkSelector::new().kid("a")), Ok(0));
            let rfc_a1 = parse(A1).unwrap();
            assert_eq!(
                selected(&rfc_a1, &by_alg("ES256")),
                Err(Error::NoMatchingKey)
            );
            assert_eq!(selected(&rfc_a1, &by_alg("ECDH-ES")), Ok(0));
            assert_eq!(selected(&rfc_a1, &by_alg("RS256")), Ok(1));
        }

        /// Zero matches is `NoMatchingKey`, also for an empty set and a set
        /// whose every entry was skipped.
        #[test]
        fn no_match_is_no_matching_key() {
            let empty = parse(r#"{"keys":[]}"#).unwrap();
            let all_skipped = set_from(&[r#"{"kty":"XYZ"}"#.to_owned(), "{}".to_owned()]);
            assert!(all_skipped.is_empty());
            let one = set_from(&[with(OCT, r#""kid":"a""#)]);
            for (set, selector) in [
                (&empty, JwkSelector::new()),
                (&empty, by_alg("HS256")),
                (&all_skipped, JwkSelector::new()),
                (&one, JwkSelector::new().kid("b")),
                (&one, by_alg("ES256")),
            ] {
                assert_eq!(
                    selected(set, &selector),
                    Err(Error::NoMatchingKey),
                    "{selector:?}"
                );
                assert_eq!(set.matching(&selector).count(), 0);
            }
        }

        /// Two or more matches is `MultipleMatchingKeys` (RFC 7517 §5.1:
        /// the order of a set's keys "does not imply an order of
        /// preference"), and `matching` yields them all, in order.
        #[test]
        fn several_matches_is_multiple_matching_keys() {
            let set = parse(A3).unwrap();
            assert_eq!(
                selected(&set, &JwkSelector::new()),
                Err(Error::MultipleMatchingKeys)
            );
            let all: Vec<usize> = set.matching(&JwkSelector::new()).map(|(i, _)| i).collect();
            assert_eq!(all, [0, 1]);
            // The A128KW member's own `alg` rules it out for HS256.
            assert_eq!(selected(&set, &by_alg("HS256")), Ok(1));

            let set = set_from(&[
                with(OCT, r#""kid":"k""#),
                EC_P256.to_owned(),
                with(OCT, r#""kid":"k""#),
                with(OCT, r#""kid":"k""#),
            ]);
            let selector = JwkSelector::new().kid("k");
            assert_eq!(selected(&set, &selector), Err(Error::MultipleMatchingKeys));
            let all: Vec<usize> = set.matching(&selector).map(|(i, _)| i).collect();
            assert_eq!(all, [0, 2, 3]);
        }

        /// The empty selector (ADR 0054 §1.3) on a one-key set returns
        /// that key, whatever its family.
        #[test]
        fn the_empty_selector_returns_the_only_key() {
            for member in [OCT, RSA_2048, EC_P256, ED25519, X25519] {
                let set = set_from(&[member.to_owned()]);
                assert_eq!(selected(&set, &JwkSelector::new()), Ok(0), "{member}");
            }
        }

        /// ADR 0054 §4: the scan stops at the second match. The counting
        /// predicate wraps the one used by `select`, through the same scan
        /// (`filter_keys`) and the same `exactly_one`.
        #[test]
        fn the_scan_stops_at_the_second_match() {
            let set = set_from(&[
                OCT.to_owned(),
                EC_P256.to_owned(),
                OCT.to_owned(),
                OCT.to_owned(),
                OCT.to_owned(),
                OCT.to_owned(),
            ]);
            let selector = by_alg("HS256");
            let criteria = Criteria::of(&selector);
            let scanned = Cell::new(0);
            let counting = |key: &Jwk| {
                scanned.set(scanned.get() + 1);
                criteria.matches(key)
            };
            let result = exactly_one(set.filter_keys(counting)).map(|(i, _)| i);
            assert_eq!(result, Err(Error::MultipleMatchingKeys));
            // Members 0 (match), 1 (no match) and 2 (second match).
            assert_eq!(scanned.get(), 3);

            // A single match reads to the end, to prove there is no other.
            let selector = by_alg("ES256");
            let criteria = Criteria::of(&selector);
            scanned.set(0);
            let counting = |key: &Jwk| {
                scanned.set(scanned.get() + 1);
                criteria.matches(key)
            };
            assert_eq!(
                exactly_one(set.filter_keys(counting)).map(|(i, _)| i),
                Ok(1)
            );
            assert_eq!(scanned.get(), set.len());

            // `select` gives the same answers.
            assert_eq!(
                selected(&set, &by_alg("HS256")),
                Err(Error::MultipleMatchingKeys)
            );
            assert_eq!(selected(&set, &by_alg("ES256")), Ok(1));
        }

        /// `matching` is lazy and never errors; `select` agrees with it.
        #[test]
        fn select_agrees_with_matching() {
            let set = set_from(&[
                with(EC_P256, r#""kid":"1","use":"enc""#),
                with(OCT, r#""kid":"1""#),
                with(X25519, r#""kid":"2""#),
                RSA_2048.to_owned(),
            ]);
            let selectors = [
                JwkSelector::new(),
                JwkSelector::new().kid("1"),
                JwkSelector::new().kid("2"),
                JwkSelector::new().kid("3"),
                by_alg("ECDH-ES"),
                by_alg("ECDH-ES").kid("1"),
                by_alg("RSA-OAEP-256"),
                by_alg("RS256"),
                JwkSelector::new().key_use(KeyUse::Enc).unwrap(),
            ];
            for selector in &selectors {
                let all: Vec<usize> = set.matching(selector).map(|(i, _)| i).collect();
                let expected = match all.as_slice() {
                    [] => Err(Error::NoMatchingKey),
                    [one] => Ok(*one),
                    _ => Err(Error::MultipleMatchingKeys),
                };
                assert_eq!(selected(&set, selector), expected, "{selector:?}");
            }
        }

        /// ADR 0054 §7: without an `alg`, a selector may return any
        /// family, so pass the key only to an operation with an allow-list.
        #[test]
        fn without_alg_any_family_may_be_selected() {
            let set = set_from(&[
                with(OCT, r#""kid":"o""#),
                with(EC_P256, r#""kid":"e""#),
                with(RSA_2048, r#""kid":"r""#),
                with(X25519, r#""kid":"x""#),
            ]);
            for (index, kid) in ["o", "e", "r", "x"].into_iter().enumerate() {
                assert_eq!(selected(&set, &JwkSelector::new().kid(kid)), Ok(index));
            }
            let enc = JwkSelector::new().key_use(KeyUse::Enc).unwrap();
            assert_eq!(set.matching(&enc).count(), set.len());
        }

        /// ADR 0054 §7: selection never authorizes an algorithm. A key
        /// selected for HS256 still verifies only under an allow-list that
        /// holds HS256 (RFC 8725 §3.1).
        #[test]
        fn selection_never_authorizes_an_alg() {
            // RFC 7515 Appendix A.1, signed with the RFC 7517 A.3 HMAC key.
            const RFC7515_A1: &str = concat!(
                "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9",
                ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
                ".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            );
            let set = parse(A3).unwrap();
            let (_, key) = set.select(&by_alg("HS256")).unwrap();
            let only_hs384 = [SigningAlg::HS384];
            assert_eq!(
                verify_compact(RFC7515_A1, key, &VerifyOptions::new(&only_hs384).unwrap())
                    .map(drop),
                Err(Error::AlgorithmNotAllowed)
            );
            let hs256 = [SigningAlg::HS256];
            assert!(verify_compact(RFC7515_A1, key, &VerifyOptions::new(&hs256).unwrap()).is_ok());
        }

        /// ADR 0054 §3, §7: the selected key is the member as imported,
        /// private members included (EC/OKP `d`, `oct` `k`); it is the
        /// caller's key, and `to_public` gives what may be published.
        #[test]
        fn the_selected_key_keeps_its_private_members() {
            let ec_private = r#"{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE","kid":"ec"}"#;
            let set = set_from(&[ec_private.to_owned(), with(OCT, r#""kid":"oct""#)]);
            let (_, ec) = set.select(&JwkSelector::new().kid("ec")).unwrap();
            assert!(!ec.is_public());
            let KeyMaterial::Ec(material) = ec.material() else {
                unreachable!()
            };
            assert!(material.is_private());
            assert!(ec.to_public().unwrap().is_public());
            let (_, oct) = set.select(&JwkSelector::new().kid("oct")).unwrap();
            assert!(!oct.is_public());
            assert!(oct.to_public().is_none());
        }
    }

    /// ADR 0054 §6 (Gate 1, owner): `verification_candidates` re-based on
    /// the one candidate rule yields exactly what today's ADR 0029 §2
    /// filter yields, on generated sets.
    mod equivalence {
        use proptest::prelude::*;

        use super::*;
        use crate::jwk::{JwkSelector, KeyOp};

        /// The ADR 0029 §2 filter exactly as it stood before ADR 0054
        /// (polyjose 0a7ea3c), kept verbatim as the reference for the
        /// equivalence property. Test-only; the library never calls it.
        fn reference_verification_candidate(
            key: &Jwk,
            alg: &SigningAlg,
            kid: Option<&str>,
        ) -> bool {
            key.material().serves_signing_alg(alg)
                && key
                    .alg()
                    .is_none_or(|key_alg| matches!(key_alg, KeyAlg::Signing(a) if a == alg))
                // `use` absent or `sig`, `key_ops` absent or containing `verify`.
                && key.permits(&KeyOp::Verify)
                && kid.is_none_or(|kid| key.kid() == Some(kid))
        }

        /// The reference filter over `set`, as `(key_index, key)` items.
        fn reference<'a>(
            set: &'a JwkSet,
            alg: &SigningAlg,
            kid: Option<&str>,
        ) -> Vec<(usize, &'a Jwk)> {
            set.keys()
                .iter()
                .enumerate()
                .filter(|(_, key)| reference_verification_candidate(key, alg, kid))
                .collect()
        }

        /// Items compared by index and by identity: the same member of
        /// the same set, not merely an equal one.
        fn same(a: &[(usize, &Jwk)], b: &[(usize, &Jwk)]) -> bool {
            a.len() == b.len()
                && a.iter()
                    .zip(b)
                    .all(|((i, x), (j, y))| i == j && core::ptr::eq(*x, *y))
        }

        /// Key material for the pool, each with the JWK `alg` values it
        /// may carry: every family and curve the core imports, an EC key
        /// with `d`, and the public X25519 key. The `alg`s are mostly ones
        /// the family serves (JWS, JWE key management, a `dir` `enc`), so
        /// most members import, plus an unregistered value (kept, RFC 7517
        /// §4.4) and one the family cannot serve (skipped on import), which
        /// exercises `key_index` across skipped entries.
        fn materials() -> Vec<(String, &'static [Option<&'static str>])> {
            const UNREGISTERED: Option<&str> = Some("x-unregistered");
            vec![
                (
                    OCT.to_owned(),
                    &[
                        None,
                        None,
                        Some("HS256"),
                        Some("HS384"),
                        Some("A128KW"),
                        Some("dir"),
                        Some("A256GCM"),
                        UNREGISTERED,
                        Some("ES256"),
                    ],
                ),
                (
                    RSA_2048.to_owned(),
                    &[
                        None,
                        None,
                        Some("RS256"),
                        Some("PS256"),
                        Some("RSA-OAEP-256"),
                        UNREGISTERED,
                        Some("HS256"),
                    ],
                ),
                (
                    EC_P256.to_owned(),
                    &[
                        None,
                        None,
                        Some("ES256"),
                        Some("ECDH-ES"),
                        UNREGISTERED,
                        Some("ES384"),
                    ],
                ),
                (
                    with(
                        EC_P256,
                        r#""d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE""#,
                    ),
                    &[None, Some("ES256"), Some("ECDH-ES+A128KW")],
                ),
                (
                    ec("P-384", 48).to_json().to_string(),
                    &[None, Some("ES384"), Some("ES256")],
                ),
                (
                    ec("P-521", 66).to_json().to_string(),
                    &[None, Some("ES512")],
                ),
                (
                    ec("secp256k1", 32).to_json().to_string(),
                    &[None, Some("ES256K"), Some("ECDH-ES")],
                ),
                (
                    ED25519.to_owned(),
                    &[None, None, Some("EdDSA"), Some("Ed25519"), UNREGISTERED],
                ),
                (X25519.to_owned(), &[None, Some("ECDH-ES"), Some("EdDSA")]),
            ]
        }

        const USES: &[Option<&str>] = &[
            None,
            None,
            None,
            None,
            Some("sig"),
            Some("enc"),
            Some("x-other"),
        ];
        const KEY_OPS: &[Option<&str>] = &[
            None,
            None,
            None,
            None,
            Some("[]"),
            Some(r#"["verify"]"#),
            Some(r#"["sign"]"#),
            Some(r#"["sign","verify"]"#),
            Some(r#"["encrypt"]"#),
            Some(r#"["wrapKey","unwrapKey"]"#),
            Some(r#"["deriveKey"]"#),
            Some(r#"["verify","x-op"]"#),
        ];
        /// Member `kid`s. The selector's "absent" `kid` is never one.
        const MEMBER_KIDS: &[Option<&str>] = &[None, Some("a"), Some("b"), Some("A")];
        const ABSENT_KID: &str = "absent-from-every-set";

        /// One member: indices into the material list, its `alg` list, and
        /// the `use`, `key_ops` and `kid` lists.
        type Pick = (
            prop::sample::Index,
            prop::sample::Index,
            prop::sample::Index,
            prop::sample::Index,
            prop::sample::Index,
        );

        fn member(materials: &[(String, &[Option<&str>])], pick: &Pick) -> String {
            let (material, alg, key_use, key_ops, kid) = pick;
            let (material, algs) = &materials[material.index(materials.len())];
            let mut extra = Vec::new();
            if let Some(alg) = algs[alg.index(algs.len())] {
                extra.push(format!(r#""alg":"{alg}""#));
            }
            if let Some(key_use) = USES[key_use.index(USES.len())] {
                extra.push(format!(r#""use":"{key_use}""#));
            }
            if let Some(key_ops) = KEY_OPS[key_ops.index(KEY_OPS.len())] {
                extra.push(format!(r#""key_ops":{key_ops}"#));
            }
            if let Some(kid) = MEMBER_KIDS[kid.index(MEMBER_KIDS.len())] {
                extra.push(format!(r#""kid":"{kid}""#));
            }
            if extra.is_empty() {
                material.clone()
            } else {
                with(material, &extra.join(","))
            }
        }

        /// Every `SigningAlg` polyjose knows, `none` included, plus two
        /// unknown values (one of them a JWE name).
        fn any_alg() -> impl Strategy<Value = SigningAlg> {
            let mut algs: Vec<SigningAlg> = SigningAlg::KNOWN.to_vec();
            algs.push(SigningAlg::from("HS1"));
            algs.push(SigningAlg::from("A128KW"));
            prop::sample::select(algs)
        }

        /// The header `alg`: any of [`any_alg`], or (more often, so that
        /// most cases have candidates) one that the family of some member
        /// of the set serves.
        #[derive(Clone, Debug)]
        enum HeaderAlg {
            Any(SigningAlg),
            ServedBy(prop::sample::Index, prop::sample::Index),
        }

        fn header_alg() -> impl Strategy<Value = HeaderAlg> {
            prop_oneof![
                1 => any_alg().prop_map(HeaderAlg::Any),
                3 => any::<(prop::sample::Index, prop::sample::Index)>()
                    .prop_map(|(key, alg)| HeaderAlg::ServedBy(key, alg)),
            ]
        }

        impl HeaderAlg {
            /// The `alg` for `set`. Only the generator reads the family
            /// table here; the property compares two filters, not the table.
            fn resolve(&self, set: &JwkSet) -> SigningAlg {
                match self {
                    HeaderAlg::Any(alg) => alg.clone(),
                    HeaderAlg::ServedBy(key, alg) => {
                        let served: Vec<&SigningAlg> = if set.is_empty() {
                            Vec::new()
                        } else {
                            let key = &set.keys()[key.index(set.len())];
                            SigningAlg::KNOWN
                                .iter()
                                .filter(|a| key.material().serves_signing_alg(a))
                                .collect()
                        };
                        match served.as_slice() {
                            // An empty set, or an X25519 key: no JWS alg.
                            [] => SigningAlg::ES256,
                            served => served[alg.index(served.len())].clone(),
                        }
                    }
                }
            }
        }

        /// The header `kid`: none, one some member of the set carries, or
        /// one no member carries.
        #[derive(Clone, Debug)]
        enum HeaderKid {
            None,
            Present(prop::sample::Index),
            Absent,
        }

        fn header_kid() -> impl Strategy<Value = HeaderKid> {
            prop_oneof![
                3 => Just(HeaderKid::None),
                2 => any::<prop::sample::Index>().prop_map(HeaderKid::Present),
                1 => Just(HeaderKid::Absent),
            ]
        }

        proptest! {
            // Pipeline rule 8: at most 1,000 cases per property.
            #![proptest_config(ProptestConfig::with_cases(1000))]

            #[test]
            fn verification_candidates_equals_the_reference_filter(
                picks in prop::collection::vec(any::<Pick>(), 0..=8),
                alg in header_alg(),
                kid in header_kid(),
            ) {
                let materials = materials();
                let members: Vec<String> = picks.iter().map(|p| member(&materials, p)).collect();
                let set = set_from(&members);
                let alg = alg.resolve(&set);
                let set_kids: Vec<&str> = set.keys().iter().filter_map(Jwk::kid).collect();
                let kid: Option<&str> = match &kid {
                    HeaderKid::None => None,
                    // A `kid` from the set, or the absent one if no member has one.
                    HeaderKid::Present(i) if !set_kids.is_empty() => Some(set_kids[i.index(set_kids.len())]),
                    HeaderKid::Present(_) | HeaderKid::Absent => Some(ABSENT_KID),
                };

                let expected = reference(&set, &alg, kid);
                let actual: Vec<(usize, &Jwk)> = set.verification_candidates(&alg, kid).collect();
                prop_assert!(same(&actual, &expected), "{alg} {kid:?}: {actual:?} vs {expected:?}");

                // The public selector `{ alg, key_op: verify, kid }` gives the
                // same sequence. `none` and unknown names cannot be put into
                // a selector at all (ADR 0054 §1.1), and select nothing above.
                match JwkSelector::new().alg(KeyAlg::Signing(alg.clone())) {
                    Ok(selector) => {
                        let mut selector = selector.key_op(KeyOp::Verify).unwrap();
                        if let Some(kid) = kid {
                            selector = selector.kid(kid);
                        }
                        let matched: Vec<(usize, &Jwk)> = set.matching(&selector).collect();
                        prop_assert!(same(&matched, &expected), "{selector:?}: {matched:?} vs {expected:?}");
                    }
                    Err(e) => {
                        prop_assert_eq!(e, Error::UnsupportedAlgorithm);
                        prop_assert!(alg == SigningAlg::None || !alg.is_known(), "{alg}");
                        prop_assert!(expected.is_empty());
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod selector_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a panic is a failed assertion

    use crate::Error;
    use crate::jwa::{ContentEncAlg, KeyMgmtAlg, SigningAlg};
    use crate::jwk::{JwkSelector, KeyAlg, KeyOp, KeyUse};

    #[test]
    fn new_is_the_empty_default_selector() {
        // ADR 0054 §1.3: no criterion is required.
        assert_eq!(JwkSelector::new(), JwkSelector::default());
        assert_eq!(
            format!("{:?}", JwkSelector::new()),
            "JwkSelector { kid: None, alg: None, key_use: None, key_op: None }"
        );
    }

    #[test]
    fn alg_accepts_every_implemented_jws_alg_but_none() {
        // ADR 0054 §1.1: the core's own list, not a copy.
        for alg in SigningAlg::KNOWN {
            let result = JwkSelector::new().alg(KeyAlg::Signing(alg.clone()));
            if *alg == SigningAlg::None {
                // RFC 8725 §3.1, ADR 0007: `none` never selects a key.
                assert_eq!(result, Err(Error::UnsupportedAlgorithm));
            } else {
                assert!(result.is_ok(), "{alg}");
            }
        }
    }

    #[test]
    fn alg_accepts_every_implemented_jwe_key_management_alg() {
        // ADR 0054 §1.1, including `dir` (§2.2).
        for alg in KeyMgmtAlg::KNOWN {
            assert!(
                JwkSelector::new().alg(KeyAlg::KeyMgmt(alg.clone())).is_ok(),
                "{alg}"
            );
        }
    }

    #[test]
    fn alg_rejects_none_unimplemented_unknown_and_enc_names() {
        // ADR 0054 §1.1: `none` (RFC 8725 §3.1), `RSA1_5` (ADR 0021),
        // `RSA-OAEP` (ADR 0022), unregistered names, and the names of
        // RFC 7518 §5.1 content encryption algorithms.
        let mut rejected: Vec<KeyAlg> = ["none", "RSA1_5", "RSA-OAEP", "Ed448", "XYZ", "", "hs256"]
            .into_iter()
            .map(KeyAlg::from)
            .collect();
        rejected.extend(ContentEncAlg::KNOWN.iter().cloned().map(KeyAlg::ContentEnc));
        // Non-canonical values built by hand fail closed too.
        rejected.push(KeyAlg::Signing(SigningAlg::Unknown("HS256".into())));
        rejected.push(KeyAlg::KeyMgmt(KeyMgmtAlg::Unknown("A128KW".into())));
        rejected.push(KeyAlg::ContentEnc(ContentEncAlg::Unknown("A128GCM".into())));
        rejected.push(KeyAlg::Unknown("ES256".into()));
        for alg in rejected {
            assert_eq!(
                JwkSelector::new().alg(alg.clone()),
                Err(Error::UnsupportedAlgorithm),
                "{alg:?}"
            );
        }
    }

    #[test]
    fn key_use_accepts_sig_and_enc_only() {
        // ADR 0054 §1.1, RFC 7517 §4.2.
        assert!(JwkSelector::new().key_use(KeyUse::Sig).is_ok());
        assert!(JwkSelector::new().key_use(KeyUse::Enc).is_ok());
        for other in ["", "SIG", "signature", "x"] {
            assert_eq!(
                JwkSelector::new().key_use(KeyUse::from(other)),
                Err(Error::UnsupportedAlgorithm),
                "{other:?}"
            );
        }
    }

    #[test]
    fn key_op_accepts_the_registered_ops_only() {
        // ADR 0054 §1.1, RFC 7517 §4.3.
        for op in [
            KeyOp::Sign,
            KeyOp::Verify,
            KeyOp::Encrypt,
            KeyOp::Decrypt,
            KeyOp::WrapKey,
            KeyOp::UnwrapKey,
            KeyOp::DeriveKey,
            KeyOp::DeriveBits,
        ] {
            assert!(JwkSelector::new().key_op(op.clone()).is_ok(), "{op}");
        }
        for other in ["", "Sign", "VERIFY", "wrapkey", "x"] {
            assert_eq!(
                JwkSelector::new().key_op(KeyOp::from(other)),
                Err(Error::UnsupportedAlgorithm),
                "{other:?}"
            );
        }
    }

    #[test]
    fn setters_record_their_criteria_and_compare_by_value() {
        let selector = JwkSelector::new()
            .kid("2011-04-29")
            .alg(KeyAlg::from("ES256"))
            .unwrap()
            .key_use(KeyUse::Sig)
            .unwrap()
            .key_op(KeyOp::Verify)
            .unwrap();
        // Debug shows every criterion: none is secret (ADR 0054 §1).
        assert_eq!(
            format!("{selector:?}"),
            "JwkSelector { kid: Some(\"2011-04-29\"), alg: Some(Signing(ES256)), \
             key_use: Some(Sig), key_op: Some(Verify) }"
        );
        // Setter order does not matter; a later call replaces an earlier one.
        let reordered = JwkSelector::new()
            .key_op(KeyOp::Verify)
            .unwrap()
            .key_use(KeyUse::Sig)
            .unwrap()
            .alg(KeyAlg::from("HS256"))
            .unwrap()
            .alg(KeyAlg::from("ES256"))
            .unwrap()
            .kid("other")
            .kid("2011-04-29");
        assert_eq!(reordered, selector);
        assert_eq!(selector.clone(), selector);
        assert_ne!(JwkSelector::new().kid("a"), JwkSelector::new().kid("A"));
    }
}
