//! JWK Thumbprints (RFC 7638) and JWK Thumbprint URIs (RFC 9278).
//!
//! A thumbprint is the hash of the key's required members in a canonical
//! JSON form (RFC 7638 §3). It identifies the key, not the JWK it came in,
//! so it is a stable `kid` candidate (RFC 7638 §3.4). RFC 7638 §3.4 leaves
//! the hash to the application: polyjose offers SHA-256, SHA-384 and
//! SHA-512 ([`ThumbprintHash`], ADR 0054 §8), with SHA-256, the hash
//! RFC 9278 §5 makes mandatory to implement, as the default.
//!
//! The canonical form is unique per key because [`Jwk`] accepts only
//! canonical base64url and minimal RSA integers (RFC 7638 §7: thumbprints
//! are unique only if the implementation validates the representation).

use sha2::{Digest, Sha256, Sha384, Sha512};
use zeroize::Zeroizing;

use super::Jwk;
use crate::error::{Error, Result};
use crate::json::Object;
use crate::util::b64url_encode;

/// The RFC 9278 §3 URI prefix, `urn:ietf:params:oauth:jwk-thumbprint`,
/// and the colon before the hash name.
const URI_PREFIX: &str = "urn:ietf:params:oauth:jwk-thumbprint:";

/// The hash function H of a JWK Thumbprint (RFC 7638 §3, §3.4).
///
/// RFC 7638 §3.4 lets the application choose H. polyjose offers the SHA-2
/// hashes of the IANA "Named Information Hash Algorithm Registry" that its
/// `sha2` dependency already provides (ADR 0054 §8.1, ADR 0016), and never
/// SHA-1 (ADR 0022). The default is SHA-256, the hash RFC 9278 §5 makes
/// mandatory to implement.
///
/// ```
/// use polyjose::jwk::{Jwk, ThumbprintHash};
///
/// // RFC 7517 Appendix A.3, the AES key wrap key.
/// let jwk = Jwk::from_json(br#"{"kty":"oct","alg":"A128KW","k":"GawgguFyGrWKav7AX4VKUg"}"#)?;
/// let hash = ThumbprintHash::from_name("sha384")?;
/// assert_eq!(hash, ThumbprintHash::Sha384);
/// assert_eq!(
///     jwk.thumbprint_uri(hash),
///     "urn:ietf:params:oauth:jwk-thumbprint:sha-384:\
///      RWKwvfhC_aZql0lGhwOTuOYcIF3-SDe_AOe9odLrXTHbzzwFpG1XErxx8oku0UCe"
/// );
/// # Ok::<(), polyjose::Error>(())
/// ```
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ThumbprintHash {
    /// SHA-256 (FIPS 180-4): IANA Named Information ID 1, `sha-256`. The
    /// default (RFC 9278 §5).
    #[default]
    Sha256,
    /// SHA-384 (FIPS 180-4): IANA Named Information ID 7, `sha-384`.
    Sha384,
    /// SHA-512 (FIPS 180-4): IANA Named Information ID 8, `sha-512`.
    Sha512,
}

impl ThumbprintHash {
    /// The hash named `name`, which must be one of exactly nine strings,
    /// compared case-sensitively (ADR 0054 §8.2):
    ///
    /// | Hash | IANA name (canonical, RFC 9278 §4) | ADR 0030 §4 | panva/jose |
    /// |---|---|---|---|
    /// | SHA-256 | `sha-256` | `SHA-256` | `sha256` |
    /// | SHA-384 | `sha-384` | `SHA-384` | `sha384` |
    /// | SHA-512 | `sha-512` | `SHA-512` | `sha512` |
    ///
    /// # Errors
    ///
    /// [`Error::UnsupportedAlgorithm`] for every other string, including
    /// SHA-1 in any spelling (ADR 0022), truncated hashes such as
    /// `sha-256-128`, SHA-3 hashes, other case forms such as `Sha-256`,
    /// and names with surrounding whitespace. The IANA registry lists its
    /// names in lowercase, and RFC 6920 erratum 8174 leaves case
    /// insensitivity open, so polyjose matches exactly. The name is not
    /// echoed.
    pub fn from_name(name: &str) -> Result<ThumbprintHash> {
        match name {
            "sha-256" | "SHA-256" | "sha256" => Ok(ThumbprintHash::Sha256),
            "sha-384" | "SHA-384" | "sha384" => Ok(ThumbprintHash::Sha384),
            "sha-512" | "SHA-512" | "sha512" => Ok(ThumbprintHash::Sha512),
            _ => Err(Error::UnsupportedAlgorithm),
        }
    }

    /// The IANA Named Information "Hash Name String" of the hash, as the
    /// JWK Thumbprint URI carries it (RFC 9278 §4): `sha-256`, `sha-384`
    /// or `sha-512`.
    pub fn hash_name(self) -> &'static str {
        match self {
            ThumbprintHash::Sha256 => "sha-256",
            ThumbprintHash::Sha384 => "sha-384",
            ThumbprintHash::Sha512 => "sha-512",
        }
    }
}

impl Jwk {
    /// The JWK Thumbprint of the key with hash function `hash`
    /// (RFC 7638 §3, §3.4), base64url encoded without padding
    /// (RFC 7515 §2): 43, 64 or 86 characters for SHA-256, SHA-384 or
    /// SHA-512.
    ///
    /// The hash input holds only the required members of the key type
    /// (RFC 7638 §3.2), so `kid`, `use`, `alg`, unknown members and any
    /// other optional member never change the value (RFC 7638 §3.2.2).
    /// A private key has the thumbprint of its public key
    /// (RFC 7638 §3.2.1). The input is the same for every hash; only H
    /// changes (RFC 7638 §3 step 2).
    ///
    /// ```
    /// use polyjose::jwk::{Jwk, ThumbprintHash};
    ///
    /// // RFC 8037 Appendix A.2.
    /// let jwk = Jwk::from_json(br#"{"kty":"OKP","crv":"Ed25519",
    ///     "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#)?;
    /// assert_eq!(
    ///     jwk.thumbprint(ThumbprintHash::Sha256),
    ///     "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
    /// );
    /// assert_eq!(jwk.thumbprint(ThumbprintHash::Sha512).len(), 86);
    /// # Ok::<(), polyjose::Error>(())
    /// ```
    ///
    /// # Security
    ///
    /// For every hash (RFC 7638 §7):
    ///
    /// - **`oct` keys:** the hash input is the secret `k`. A hash of a
    ///   symmetric key can leak information about it, so its thumbprint
    ///   should be kept from parties that do not hold the key unless the
    ///   application knows the hash protects it well enough. polyjose
    ///   wipes the hash input and the hash state; the returned thumbprint
    ///   is not secret material and is not wiped.
    /// - **Passwords and other low-entropy `oct` keys:** never publish
    ///   the thumbprint of a password or other low-entropy `oct` key,
    ///   such as a PBES2 key, whose `k` is the password (RFC 7518 §4.8),
    ///   and never use it as a `kid`, although RFC 7638 §3.4 suggests
    ///   thumbprints as `kid` values: a `kid` is readable in every token
    ///   header. The thumbprint is an unsalted fast hash of the secret,
    ///   so whoever sees it can test password guesses offline at hash
    ///   speed. Publishing it undoes the protection of PBES2's salt
    ///   (`p2s`) and iteration count (`p2c`) (RFC 7518 §4.8.1.1,
    ///   §4.8.1.2). SHA-384 and SHA-512 do not change this.
    /// - **Not a blocklist:** an attacker can transform a key (an RSA
    ///   modulus 3·N, say) so it gets another thumbprint, so comparing
    ///   thumbprints cannot reliably exclude a key.
    pub fn thumbprint(&self, hash: ThumbprintHash) -> String {
        // RFC 7638 §3 step 2, with H chosen by the caller (RFC 7638 §3.4).
        let input = self.canonical_input();
        match hash {
            ThumbprintHash::Sha256 => digest_b64url::<Sha256>(input.as_bytes()),
            ThumbprintHash::Sha384 => digest_b64url::<Sha384>(input.as_bytes()),
            ThumbprintHash::Sha512 => digest_b64url::<Sha512>(input.as_bytes()),
        }
    }

    /// The JWK Thumbprint URI of the key with hash function `hash`
    /// (RFC 9278 §3): `urn:ietf:params:oauth:jwk-thumbprint:`, the
    /// [`ThumbprintHash::hash_name`] (RFC 9278 §4), `:` and
    /// [`Jwk::thumbprint`].
    ///
    /// The URI always carries the IANA name (`sha-256`, `sha-384`,
    /// `sha-512`), whichever spelling [`ThumbprintHash::from_name`] was
    /// given (ADR 0054 §8.3).
    ///
    /// ```
    /// use polyjose::jwk::{Jwk, ThumbprintHash};
    ///
    /// // RFC 9278 §6, the RFC 7638 §3.1 key.
    /// let jwk = Jwk::from_json(br#"{"kty":"RSA",
    ///     "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
    ///     "e":"AQAB","alg":"RS256","kid":"2011-04-29"}"#)?;
    /// assert_eq!(
    ///     jwk.thumbprint_uri(ThumbprintHash::Sha256),
    ///     "urn:ietf:params:oauth:jwk-thumbprint:sha-256:NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
    /// );
    /// # Ok::<(), polyjose::Error>(())
    /// ```
    ///
    /// # Security
    ///
    /// The [`Jwk::thumbprint`] cautions apply (RFC 9278 §7, RFC 7638 §7).
    /// In particular, never publish the URI of a password or other
    /// low-entropy `oct` key (PBES2, RFC 7518 §4.8), or use it as a `kid`
    /// (RFC 7638 §3.4): it carries an unsalted fast hash of the secret,
    /// which undoes PBES2's `p2s`/`p2c` protection whatever the hash.
    /// For X25519
    /// several public keys are equivalent to one another (RFC 7748 §7), so
    /// a URI used as an identifier should be bound to the actual key, for
    /// instance by a signature over that key (RFC 9278 §7.1).
    pub fn thumbprint_uri(&self, hash: ThumbprintHash) -> String {
        let name = hash.hash_name();
        let thumbprint = self.thumbprint(hash);
        let mut uri = String::with_capacity(URI_PREFIX.len() + name.len() + 1 + thumbprint.len());
        uri.push_str(URI_PREFIX);
        uri.push_str(name);
        uri.push(':');
        uri.push_str(&thumbprint);
        uri
    }

    /// The JWK SHA-256 Thumbprint of the key (RFC 7638 §3), base64url
    /// encoded without padding (RFC 7515 §2): the same as
    /// [`Jwk::thumbprint`] with [`ThumbprintHash::Sha256`].
    ///
    /// ```
    /// use polyjose::jwk::Jwk;
    ///
    /// // RFC 7638 §3.1.
    /// let jwk = Jwk::from_json(br#"{"kty":"RSA",
    ///     "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
    ///     "e":"AQAB","alg":"RS256","kid":"2011-04-29"}"#)?;
    /// assert_eq!(jwk.thumbprint_sha256(), "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
    /// # Ok::<(), polyjose::Error>(())
    /// ```
    ///
    /// # Security
    ///
    /// The [`Jwk::thumbprint`] cautions apply (RFC 7638 §7).
    pub fn thumbprint_sha256(&self) -> String {
        self.thumbprint(ThumbprintHash::Sha256)
    }

    /// The JWK Thumbprint URI of the key with SHA-256 (RFC 9278 §3):
    /// `urn:ietf:params:oauth:jwk-thumbprint:sha-256:` followed by
    /// [`Jwk::thumbprint_sha256`], the same as [`Jwk::thumbprint_uri`]
    /// with [`ThumbprintHash::Sha256`].
    ///
    /// `sha-256` is the IANA Named Information "Hash Name String" for
    /// SHA-256 (RFC 9278 §4), the hash RFC 9278 §5 makes mandatory to
    /// implement.
    ///
    /// ```
    /// use polyjose::jwk::Jwk;
    ///
    /// // RFC 8037 Appendix A.2 and A.3.
    /// let jwk = Jwk::from_json(br#"{"kty":"OKP","crv":"Ed25519",
    ///     "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#)?;
    /// assert_eq!(
    ///     jwk.thumbprint_uri_sha256(),
    ///     "urn:ietf:params:oauth:jwk-thumbprint:sha-256:kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
    /// );
    /// # Ok::<(), polyjose::Error>(())
    /// ```
    ///
    /// # Security
    ///
    /// The [`Jwk::thumbprint_uri`] cautions apply (RFC 9278 §7, §7.1).
    pub fn thumbprint_uri_sha256(&self) -> String {
        self.thumbprint_uri(ThumbprintHash::Sha256)
    }

    /// The RFC 7638 §3 step 1 hash input: a JSON object of the required
    /// members only (RFC 7638 §3.2), ordered by member name (§3.3), with
    /// no whitespace, as UTF-8.
    ///
    /// [`Jwk::thumbprint_members`] yields canonical values, and every
    /// name and value is printable ASCII (base64url, `kty` and `crv`
    /// names), which the serializer writes unescaped, as RFC 7638 §3.3
    /// requires. No member is a number or an object. So the input is
    /// defined for every key [`Jwk`] accepts.
    ///
    /// For an `oct` key the input contains the secret `k`
    /// (RFC 7638 §3.2), so the buffer is wiped on drop.
    fn canonical_input(&self) -> Zeroizing<String> {
        canonical_json(self.thumbprint_members())
    }
}

/// Serializes `members` in the RFC 7638 §3.3 order: sorted
/// lexicographically by the Unicode code points of the member names.
///
/// [`Jwk::thumbprint_members`] already inserts the members in that order;
/// sorting here makes the hash input's order independent of it.
/// [`Object::sort_members`] sorts by code point, and sorts in place, so a
/// secret `k` is never copied; the returned buffer is wiped on drop.
fn canonical_json(mut members: Object) -> Zeroizing<String> {
    members.sort_members();
    Zeroizing::new(members.to_json())
}

/// Hashes `input` with `D` (RFC 7638 §3 step 2) and base64url-encodes the
/// digest without padding (RFC 7515 §2).
///
/// The one-shot `digest` keeps the hash state inside `D`, which `sha2`'s
/// `zeroize` feature wipes on drop (ADR 0054 §8.5).
fn digest_b64url<D: Digest>(input: &[u8]) -> String {
    b64url_encode(&D::digest(input))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json;

    /// RFC 7638 §3.1: the example RSA public key, with optional members.
    const RFC7638_RSA: &str = r#"{"kty":"RSA",
        "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
        "e":"AQAB","alg":"RS256","kid":"2011-04-29"}"#;

    /// RFC 7638 §3.1: the intermediate JSON object, without the display
    /// line breaks.
    const RFC7638_RSA_INPUT: &str = r#"{"e":"AQAB","kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"}"#;

    /// RFC 8037 Appendix A.1: the Ed25519 private key.
    const RFC8037_ED25519_PRIVATE: &str = r#"{"kty":"OKP","crv":"Ed25519",
        "d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
        "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;

    /// RFC 8037 Appendix A.3: the canonicalization of the A.1/A.2 keys.
    const RFC8037_ED25519_INPUT: &str =
        r#"{"crv":"Ed25519","kty":"OKP","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;

    fn jwk(json: &str) -> Jwk {
        Jwk::from_json(json.as_bytes()).expect("test key parses")
    }

    #[test]
    fn rfc7638_3_1_canonical_input() {
        assert_eq!(
            jwk(RFC7638_RSA).canonical_input().as_str(),
            RFC7638_RSA_INPUT
        );
    }

    #[test]
    fn rfc8037_a3_canonical_input() {
        assert_eq!(
            jwk(RFC8037_ED25519_PRIVATE).canonical_input().as_str(),
            RFC8037_ED25519_INPUT
        );
    }

    #[test]
    fn rfc7638_3_1_sha256_thumbprint() {
        assert_eq!(
            jwk(RFC7638_RSA).thumbprint_sha256(),
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
        );
    }

    #[test]
    fn rfc8037_a3_sha256_thumbprint() {
        // RFC 8037 A.3 gives the hash in hex,
        // 90facafea9b1556698540f70c0117a22ea37bd5cf3ed3c47093c1707282b4b89,
        // and its base64url form, checked here.
        assert_eq!(
            jwk(RFC8037_ED25519_PRIVATE).thumbprint_sha256(),
            "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
        );
    }

    #[test]
    fn rfc9278_6_example_uri() {
        // RFC 9278 §6, without the display line break.
        assert_eq!(
            jwk(RFC7638_RSA).thumbprint_uri_sha256(),
            "urn:ietf:params:oauth:jwk-thumbprint:sha-256:NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
        );
    }

    #[test]
    fn uri_is_the_prefix_hash_name_and_thumbprint() {
        let key = jwk(RFC8037_ED25519_PRIVATE);
        let uri = key.thumbprint_uri_sha256();
        let thumbprint = uri
            .strip_prefix("urn:ietf:params:oauth:jwk-thumbprint:sha-256:")
            .expect("RFC 9278 §3 prefix and §4 hash name");
        assert_eq!(thumbprint, key.thumbprint_sha256());
    }

    // Expected values below that no RFC publishes were computed outside
    // polyjose (Python hashlib/base64 over the hand-written RFC 7638 §3.3
    // input), as test oracles.

    /// RFC 7517 Appendix A.1: the EC P-256 public key.
    const RFC7517_EC_PUBLIC: &str = r#"{"kty":"EC","crv":"P-256",
        "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
        "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
        "use":"enc","kid":"1"}"#;

    /// RFC 7517 Appendix A.2: the private key of [`RFC7517_EC_PUBLIC`].
    const RFC7517_EC_PRIVATE: &str = r#"{"kty":"EC","crv":"P-256",
        "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
        "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
        "d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",
        "use":"enc","kid":"1"}"#;

    /// RFC 7520 §3.1: the EC P-521 public key (66-octet coordinates).
    const RFC7520_P521_PUBLIC: &str = r#"{"kty":"EC",
        "kid":"bilbo.baggins@hobbiton.example","use":"sig","crv":"P-521",
        "x":"AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt",
        "y":"AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1"}"#;

    /// RFC 7520 §3.2: the private key of [`RFC7520_P521_PUBLIC`].
    const RFC7520_P521_PRIVATE: &str = r#"{"kty":"EC",
        "kid":"bilbo.baggins@hobbiton.example","use":"sig","crv":"P-521",
        "x":"AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt",
        "y":"AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1",
        "d":"AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zbKipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt"}"#;

    /// RFC 8037 Appendix A.2: the public part of [`RFC8037_ED25519_PRIVATE`].
    const RFC8037_ED25519_PUBLIC: &str = r#"{"kty":"OKP","crv":"Ed25519",
        "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;

    /// RFC 8037 Appendix A.6: Bob's X25519 public key (RFC 7748 §6.1).
    const RFC8037_X25519_PUBLIC: &str =
        r#"{"kty":"OKP","crv":"X25519","x":"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08"}"#;

    /// RFC 7517 Appendix A.3: the AES key wrap key.
    const RFC7517_OCT_AES: &str = r#"{"kty":"oct","alg":"A128KW","k":"GawgguFyGrWKav7AX4VKUg"}"#;

    /// RFC 7517 Appendix A.3: the HMAC key.
    const RFC7517_OCT_HMAC: &str = r#"{"kty":"oct",
        "k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
        "kid":"HMAC key used in JWS spec Appendix A.1 example"}"#;

    #[test]
    fn every_key_type_has_its_rfc7638_thumbprint() {
        let cases = [
            (RFC7638_RSA, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"),
            (
                RFC7517_EC_PUBLIC,
                "cn-I_WNMClehiVp51i_0VpOENW1upEerA8sEam5hn-s",
            ),
            (
                RFC7520_P521_PUBLIC,
                "dHri3SADZkrush5HU_50AoRhcKFryN-PI6jPBtPL55M",
            ),
            (
                RFC8037_ED25519_PUBLIC,
                "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k",
            ),
            (
                RFC8037_X25519_PUBLIC,
                "giQqigT_IKcuzHl0FVJ3k5ts3_TWNAxvsC08UZsfcM8",
            ),
            (
                RFC7517_OCT_AES,
                "k1JnWRfC-5zzmL72vXIuBgTLfVROXBakS4OmGcrMCoc",
            ),
            (
                RFC7517_OCT_HMAC,
                "y_x3gCJnL6oKGBBIXScabduwxTVy2Wd2bzRVEUbdUzc",
            ),
        ];
        for (json, expected) in cases {
            let key = jwk(json);
            let thumbprint = key.thumbprint_sha256();
            assert_eq!(thumbprint, expected, "{json}");
            // 32 SHA-256 octets are 43 unpadded base64url characters.
            assert_eq!(thumbprint.len(), 43);
            assert_eq!(
                key.thumbprint_uri_sha256(),
                format!("{URI_PREFIX}sha-256:{expected}")
            );
        }
    }

    #[test]
    fn canonical_input_holds_only_the_required_members_in_order() {
        // RFC 7638 §3.2 members, lexicographic (§3.3); no `d`, `kid`, `use`
        // or `alg`.
        assert_eq!(
            jwk(RFC7517_EC_PRIVATE).canonical_input().as_str(),
            r#"{"crv":"P-256","kty":"EC","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}"#
        );
        assert_eq!(
            jwk(RFC7517_OCT_AES).canonical_input().as_str(),
            r#"{"k":"GawgguFyGrWKav7AX4VKUg","kty":"oct"}"#
        );
    }

    #[test]
    fn canonical_json_orders_members_by_code_point() {
        // RFC 7638 §3.3: the hash input is ordered by member name, whatever
        // order the members arrive in. Here they arrive reversed.
        let mut members = json::Object::new();
        members.insert("n", "nnn");
        members.insert("kty", "RSA");
        members.insert("e", "AQAB");
        assert_eq!(
            canonical_json(members).as_str(),
            r#"{"e":"AQAB","kty":"RSA","n":"nnn"}"#
        );

        // §3.3 orders by Unicode code point: uppercase before lowercase,
        // and U+E000 before U+10000. UTF-16 code unit order would put
        // U+10000 (surrogates D800 DC00) first.
        let mut members = json::Object::new();
        members.insert("\u{10000}", "1");
        members.insert("\u{E000}", "2");
        members.insert("a", "3");
        members.insert("Z", "4");
        assert_eq!(
            canonical_json(members).as_str(),
            "{\"Z\":\"4\",\"a\":\"3\",\"\u{E000}\":\"2\",\"\u{10000}\":\"1\"}"
        );
    }

    #[test]
    fn oct_canonical_input_is_a_zeroizing_buffer() {
        // RFC 7638 §3.2: the symmetric key's input contains the secret `k`,
        // so it must be wiped on drop (RFC 7638 §7).
        let input: Zeroizing<String> = jwk(RFC7517_OCT_HMAC).canonical_input();
        assert!(input.starts_with(r#"{"k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ"#));
    }

    #[test]
    fn private_key_has_the_thumbprint_of_its_public_key() {
        // RFC 7638 §3.2.1, for EC (P-256, P-521) and OKP.
        let pairs = [
            (RFC7517_EC_PRIVATE, RFC7517_EC_PUBLIC),
            (RFC7520_P521_PRIVATE, RFC7520_P521_PUBLIC),
            (RFC8037_ED25519_PRIVATE, RFC8037_ED25519_PUBLIC),
        ];
        for (private, public) in pairs {
            let private = jwk(private);
            let public = jwk(public);
            assert!(!private.is_public() && public.is_public());
            assert_eq!(private.thumbprint_sha256(), public.thumbprint_sha256());
            assert_eq!(
                private.thumbprint_uri_sha256(),
                public.thumbprint_uri_sha256()
            );
            let derived = private.to_public().expect("EC and OKP have a public part");
            assert_eq!(derived.thumbprint_sha256(), public.thumbprint_sha256());
        }
    }

    #[test]
    fn optional_and_unknown_members_do_not_change_the_thumbprint() {
        // RFC 7638 §3.2.2: only required members are hashed. Same RSA key as
        // RFC 7638 §3.1, members reordered, `alg`/`kid` dropped and other
        // optional and unknown members added.
        let n = jwk(RFC7638_RSA);
        let n = n.thumbprint_members();
        let n = n.get("n").and_then(json::Value::as_str).expect("RSA n");
        let variants = [
            format!(r#"{{"n":"{n}","e":"AQAB","kty":"RSA"}}"#),
            format!(
                r#"{{"e":"AQAB","use":"sig","key_ops":["verify"],"kid":"other",
                "x5t#S256":"abc","ext":{{"nested":[1,2,"é"]}},"n":"{n}",
                "kty":"RSA","alg":"PS256"}}"#
            ),
        ];
        for json in &variants {
            assert_eq!(
                jwk(json).thumbprint_sha256(),
                "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
                "{json}"
            );
        }
    }

    #[test]
    fn a_different_key_has_a_different_thumbprint() {
        // Same curve and members, `x` of RFC 8037 A.6 Alice instead of Bob.
        let alice = jwk(
            r#"{"kty":"OKP","crv":"X25519","x":"hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo"}"#,
        );
        let bob = jwk(RFC8037_X25519_PUBLIC);
        assert_ne!(alice.thumbprint_sha256(), bob.thumbprint_sha256());
        // `kty`/`crv` are hashed too: the same 32 octets as an X25519 and
        // as an Ed25519 key. RFC 8037 A.2's `x` is used, a valid key of
        // both kinds (Bob's X25519 octets are not a torsion-free Ed25519
        // point, ADR 0043 §1).
        let as_x25519 = jwk(
            r#"{"kty":"OKP","crv":"X25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#,
        );
        let as_ed25519 = jwk(RFC8037_ED25519_PUBLIC);
        assert_ne!(
            as_ed25519.thumbprint_sha256(),
            as_x25519.thumbprint_sha256()
        );
    }

    #[test]
    fn hash_names_are_the_iana_hash_name_strings() {
        // RFC 9278 §4: the IANA Named Information Hash Name Strings
        // (IDs 1, 7, 8).
        assert_eq!(ThumbprintHash::Sha256.hash_name(), "sha-256");
        assert_eq!(ThumbprintHash::Sha384.hash_name(), "sha-384");
        assert_eq!(ThumbprintHash::Sha512.hash_name(), "sha-512");
        // RFC 9278 §5: SHA-256 is mandatory to implement, and the default.
        assert_eq!(ThumbprintHash::default(), ThumbprintHash::Sha256);
    }

    #[test]
    fn from_name_accepts_exactly_the_nine_spellings() {
        // ADR 0054 §8.2: IANA, ADR 0030 §4 and panva/jose spellings.
        let cases = [
            ("sha-256", ThumbprintHash::Sha256),
            ("SHA-256", ThumbprintHash::Sha256),
            ("sha256", ThumbprintHash::Sha256),
            ("sha-384", ThumbprintHash::Sha384),
            ("SHA-384", ThumbprintHash::Sha384),
            ("sha384", ThumbprintHash::Sha384),
            ("sha-512", ThumbprintHash::Sha512),
            ("SHA-512", ThumbprintHash::Sha512),
            ("sha512", ThumbprintHash::Sha512),
        ];
        for (name, hash) in cases {
            assert_eq!(ThumbprintHash::from_name(name), Ok(hash), "{name}");
        }
        // Every hash round-trips through its canonical name.
        for (_, hash) in cases {
            assert_eq!(ThumbprintHash::from_name(hash.hash_name()), Ok(hash));
        }
    }

    #[test]
    fn from_name_rejects_every_other_string() {
        // ADR 0054 §8.2: SHA-1 (ADR 0022), truncated and SHA-3 hashes,
        // other case forms and padded names are UnsupportedAlgorithm.
        for name in [
            "",
            "SHA-1",
            "sha-1",
            "sha1",
            "sha-256-128",
            "sha3-256",
            "Sha-256",
            "SHA256",
            "sha-256 ",
            " sha-256",
            "sha_256",
            "SHA-384 ",
            "Sha512",
            "sha-224",
            "sha-512/256",
        ] {
            assert_eq!(
                ThumbprintHash::from_name(name),
                Err(crate::Error::UnsupportedAlgorithm),
                "{name:?}"
            );
        }
    }

    #[test]
    fn sha256_methods_delegate_to_the_general_ones() {
        for json in [RFC7638_RSA, RFC8037_ED25519_PRIVATE, RFC7517_OCT_AES] {
            let key = jwk(json);
            assert_eq!(
                key.thumbprint_sha256(),
                key.thumbprint(ThumbprintHash::Sha256)
            );
            assert_eq!(
                key.thumbprint_uri_sha256(),
                key.thumbprint_uri(ThumbprintHash::Sha256)
            );
        }
    }

    mod properties {
        use proptest::prelude::*;

        use super::*;
        use crate::json::{Object, Value};

        fn member_value() -> impl Strategy<Value = Value> {
            prop_oneof![
                any::<String>().prop_map(Value::from),
                any::<bool>().prop_map(Value::from),
                Just(Value::Null),
            ]
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(256))]

            /// RFC 7638 §3.2.2: any `kid` and any unknown members, in any
            /// order, leave the thumbprint unchanged.
            #[test]
            fn extra_members_never_change_the_thumbprint(
                kid in any::<String>(),
                extra in proptest::collection::vec(("[a-z]{1,8}", member_value()), 0..6),
                kid_first in any::<bool>(),
            ) {
                for json in [RFC7517_EC_PRIVATE, RFC8037_ED25519_PRIVATE, RFC7517_OCT_HMAC] {
                    let base = jwk(json);
                    let mut object = Object::new();
                    if kid_first {
                        object.insert("kid", kid.as_str());
                    }
                    for (name, value) in base.thumbprint_members().iter() {
                        object.insert(name, value.clone());
                    }
                    if !kid_first {
                        object.insert("kid", kid.as_str());
                    }
                    for (name, value) in &extra {
                        // Prefixed so they never collide with a JWK member.
                        object.insert(format!("ext_{name}"), value.clone());
                    }
                    let key = Jwk::from_object(&object).expect("still a valid key");
                    prop_assert_eq!(key.thumbprint_sha256(), base.thumbprint_sha256());
                }
            }
        }
    }
}
