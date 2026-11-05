//! JWK Thumbprints (RFC 7638) and JWK Thumbprint URIs (RFC 9278).

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::Jwk;
use crate::util::b64url_encode;

/// The RFC 9278 §3 URI prefix, `urn:ietf:params:oauth:jwk-thumbprint`,
/// the colon separator, the RFC 9278 §4 hash name for SHA-256 and the
/// colon before the thumbprint.
const SHA256_URI_PREFIX: &str = "urn:ietf:params:oauth:jwk-thumbprint:sha-256:";

impl Jwk {
    /// The JWK SHA-256 Thumbprint of the key (RFC 7638 §3), base64url
    /// encoded without padding (RFC 7515 §2).
    ///
    /// The hash input holds only the required members of the key type
    /// (RFC 7638 §3.2), so `kid`, `use`, `alg`, unknown members and any
    /// other optional member never change the value (RFC 7638 §3.2.2).
    /// A private key has the thumbprint of its public key
    /// (RFC 7638 §3.2.1).
    pub fn thumbprint_sha256(&self) -> String {
        // RFC 7638 §3 step 2, with H = SHA-256 (RFC 7638 §3.4).
        let digest = Sha256::digest(self.canonical_input().as_bytes());
        b64url_encode(&digest)
    }

    /// The JWK Thumbprint URI of the key with SHA-256 (RFC 9278 §3):
    /// `urn:ietf:params:oauth:jwk-thumbprint:sha-256:` followed by
    /// [`Jwk::thumbprint_sha256`].
    ///
    /// `sha-256` is the IANA Named Information "Hash Name String" for
    /// SHA-256 (RFC 9278 §4), the hash RFC 9278 §5 makes mandatory to
    /// implement.
    pub fn thumbprint_uri_sha256(&self) -> String {
        let thumbprint = self.thumbprint_sha256();
        let mut uri = String::with_capacity(SHA256_URI_PREFIX.len() + thumbprint.len());
        uri.push_str(SHA256_URI_PREFIX);
        uri.push_str(&thumbprint);
        uri
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
        Zeroizing::new(self.thumbprint_members().to_json())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
