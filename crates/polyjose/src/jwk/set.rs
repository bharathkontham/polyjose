//! JWK Set (RFC 7517 §5) and verification key selection (ADR 0029 §2).

use core::fmt;

use zeroize::ZeroizeOnDrop;

use super::{Jwk, MemberNames, is_unsupported_key_kind};
use crate::error::{Error, Result};
use crate::json::{self, Object, Value};

/// Detail for a JWK Set document that is valid JSON but not an object.
const NOT_AN_OBJECT: &str = "a JWK Set must be a JSON object";
/// Detail for a JWK Set without a `keys` array (RFC 7517 §5).
const NO_KEYS_ARRAY: &str = "a JWK Set must have a keys member that is an array";

/// A JWK Set (RFC 7517 §5): the usable keys of a `{"keys":[...]}`
/// document, in document order, plus its other top-level members.
///
/// Build one with [`JwkSet::from_json`] (untrusted bytes) or
/// [`JwkSet::from_object`] (an already-parsed object). See the
/// [module documentation](crate::jwk) for which members are kept, skipped
/// or fatal.
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
    ///   base64url, an RSA modulus under 2048 bits, and so on (RFC 7517 §5:
    ///   "SHOULD ignore JWKs ... that are missing required members, or for
    ///   which values are out of the supported ranges"). Skipping can only
    ///   remove verification candidates, never add one.
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
        let mut other = Object::new();
        for (name, value) in object {
            if name != "keys" {
                other.insert(name, value.clone());
            }
        }
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
    match Jwk::from_object(object) {
        Ok(jwk) => Ok(Some(jwk)),
        // With `kty` and `crv` supported, the only `UnsupportedAlgorithm`
        // left in `Jwk::from_object` is an RSA private key (ADR 0021), which
        // fails the set. Should another case ever appear, it fails the set
        // too: fail closed.
        Err(Error::UnsupportedAlgorithm) => Err(Error::UnsupportedAlgorithm),
        Err(_) => Ok(None),
    }
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
    use crate::jwk::{Jwk, JwkSet, KeyAlg, KeyType};

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

    /// An EC public key on `crv`, with coordinates of the right length (the
    /// family table does not look at the point).
    fn ec(crv: &str, len: usize) -> Jwk {
        let coordinate = crate::util::b64url_encode(&vec![7u8; len]);
        let json = format!(r#"{{"kty":"EC","crv":"{crv}","x":"{coordinate}","y":"{coordinate}"}}"#);
        Jwk::from_json(json.as_bytes()).unwrap()
    }

    fn jwk(json: &str) -> Jwk {
        Jwk::from_json(json.as_bytes()).unwrap()
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
}
