//! Utilities (ADR 0030 §4, "Utilities"): the version, the stable error codes, base64url, and
//! the unverified decode utilities (ADR 0069).
//!
//! This doesn't check the signature: anyone can write these values, so don't use them for
//! authorization or trust decisions until you verify the token. That holds for all three
//! `decode_*_unverified` functions: verify with [`jwt_verify`](crate::jwt::jwt_verify) or
//! [`jws_verify_compact`](crate::jws::jws_verify_compact). Sanitise a `kid` before using it in a
//! lookup, and take keys from your own configuration, not from `jku` or `x5u` (RFC 8725 §3.10).
//! After reading `iss` to choose a key set, verify with that issuer in `issuers`
//! (RFC 8725 §3.8). A JWK Set already selects by `kid` during
//! [`jwt_verify_with_jwks`](crate::jwt::jwt_verify_with_jwks) (ADR 0029).

use crate::error::SurfaceResult;
use crate::records::{JwsUnverified, JwtUnverified};
use crate::secret::SecretBytes;

/// The polyjose version this surface is built with, e.g. `"0.1.0"` (ADR 0030 §4).
///
/// The surface and the core share the workspace version (`version.workspace = true` in both
/// manifests), so this is the polyjose crate version.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Every stable error code, equal to [`polyjose::Error::CODES`] and in its order (ADR 0030 §4,
/// §5). Codes are append-only: `InvalidFormat` (ADR 0026), `NoMatchingKey` (ADR 0029 §4) and
/// `MultipleMatchingKeys` (ADR 0054 §5, RFC 7517 §4.5, §5.1), the newest, come last.
///
/// Every binding exposes this list, and its tests assert that the binding's own error code set
/// equals it (ADR 0030 §5).
pub fn error_codes() -> &'static [&'static str] {
    polyjose::Error::CODES
}

/// Encodes `data` as base64url without padding (RFC 4648 §5, as RFC 7515 §2 requires for JOSE).
pub fn base64url_encode(data: &[u8]) -> String {
    polyjose::util::b64url_encode(data)
}

/// Decodes strict unpadded base64url (RFC 4648 §5, RFC 7515 §2; PRD 0001 R1).
///
/// # Errors
///
/// `InvalidBase64` for padding, characters outside the URL-safe alphabet, an impossible length,
/// or non-zero trailing bits (a non-canonical encoding), as the core decides.
pub fn base64url_decode(text: &str) -> SurfaceResult<Vec<u8>> {
    Ok(polyjose::util::b64url_decode(text)?)
}

/// This doesn't check the signature: anyone can write these values, so don't use them for
/// authorization or trust decisions until you verify the token.
///
/// Reads the JOSE Protected Header of a compact JWS (3 parts) or JWE (5 parts) without verifying
/// or decrypting anything, as the core serializes it (ADR 0069 §1–§2, §4; RFC 7515 §7.1,
/// RFC 7516 §7.1). Verify the token with [`jwt_verify`](crate::jwt::jwt_verify) or
/// [`jws_verify_compact`](crate::jws::jws_verify_compact).
///
/// Sanitise a `kid` before using it in a lookup, and take keys from your own configuration, not
/// from `jku` or `x5u` (RFC 8725 §3.10).
///
/// Only the first part is read; for a nested JWT that is the outer JWE's header.
///
/// # Errors
///
/// The core's codes (`polyjose::util::decode_protected_header_unverified`): `InvalidFormat`
/// (over 1 MiB, not 3 or 5 parts), `InvalidBase64`, `InvalidJson`, `InvalidHeader`.
pub fn decode_protected_header_unverified(token: &str) -> SurfaceResult<String> {
    Ok(polyjose::util::decode_protected_header_unverified(token)?.to_json()?)
}

/// This doesn't check the signature: anyone can write these values, so don't use them for
/// authorization or trust decisions until you verify the token.
///
/// Reads the protected header and the payload of a compact JWS without verifying it
/// (ADR 0069 §1–§4; RFC 7515 §7.1). Verify the JWS with
/// [`jws_verify_compact`](crate::jws::jws_verify_compact).
///
/// Sanitise a `kid` before using it in a lookup, and take keys from your own configuration, not
/// from `jku` or `x5u` (RFC 8725 §3.10).
///
/// The core runs exactly verification's steps 1–5 (ADR 0048) and nothing after them, so
/// `alg: none`, an unknown `alg` and an unknown `crit` entry come back as data. The payload is
/// the core's wiping buffer, moved into [`SecretBytes`] without a copy (ADR 0049 §4,
/// ADR 0030 §7.2).
///
/// # Errors
///
/// The core's codes (`polyjose::util::decode_jws_unverified`): `InvalidFormat` (over 1 MiB,
/// not 3 parts, a JSON serialization), `InvalidBase64`, `InvalidJson`, `InvalidHeader`.
pub fn decode_jws_unverified(jws: &str) -> SurfaceResult<JwsUnverified> {
    let decoded = polyjose::util::decode_jws_unverified(jws)?;
    Ok(JwsUnverified {
        protected_header: decoded.protected.to_json()?,
        payload: SecretBytes::from(decoded.payload),
    })
}

/// This doesn't check the signature: anyone can write these values, so don't use them for
/// authorization or trust decisions until you verify the token.
///
/// Reads the header and the claims of a compact signed JWT without verifying or validating it
/// (ADR 0069 §1–§2, §4; RFC 7519 §7.2). Verify the token with
/// [`jwt_verify`](crate::jwt::jwt_verify).
///
/// No claim is validated (no `exp`, `nbf`, `iat`, `iss`, `sub`, `aud` or `typ` check, and no
/// clock). After reading `iss` to choose a key set, verify with that issuer in `issuers`
/// (RFC 8725 §3.8); sanitise a `kid` before using it in a lookup, and take keys from your own
/// configuration, not from `jku` or `x5u` (RFC 8725 §3.10).
///
/// # Errors
///
/// The core's codes (`polyjose::util::decode_jwt_unverified`): as
/// [`decode_jws_unverified`], plus `InvalidHeader` for `b64: false` or `cty: JWT` (RFC 7797 §7,
/// RFC 7519 §5.2), `InvalidJson` for claims that are not one JSON object, and `InvalidClaim` for
/// a mistyped registered claim. A five-part token is `InvalidFormat`.
pub fn decode_jwt_unverified(token: &str) -> SurfaceResult<JwtUnverified> {
    let decoded = polyjose::util::decode_jwt_unverified(token)?;
    Ok(JwtUnverified {
        header: decoded.header.to_json()?,
        claims: decoded.claims.to_json(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4648 §10's test vectors, written unpadded as base64url requires (RFC 7515 §2).
    const RFC4648_SECTION_10: [(&str, &str); 7] = [
        ("", ""),
        ("f", "Zg"),
        ("fo", "Zm8"),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg"),
        ("fooba", "Zm9vYmE"),
        ("foobar", "Zm9vYmFy"),
    ];

    #[test]
    fn version_is_the_workspace_version_shared_with_polyjose() {
        let workspace = include_str!("../../../Cargo.toml");
        let line = workspace
            .lines()
            .skip_while(|l| *l != "[workspace.package]")
            .find(|l| l.starts_with("version = "))
            .unwrap();
        assert_eq!(line, format!("version = \"{}\"", version()));
        for manifest in [
            include_str!("../Cargo.toml"),
            include_str!("../../../crates/polyjose/Cargo.toml"),
        ] {
            assert!(manifest.lines().any(|l| l == "version.workspace = true"));
        }
    }

    #[test]
    fn error_codes_are_the_core_codes_in_core_order() {
        assert_eq!(error_codes(), polyjose::Error::CODES);
        // ADR 0054 §5: `MultipleMatchingKeys` is appended right after `NoMatchingKey`.
        assert_eq!(
            error_codes()[error_codes().len() - 2..],
            ["NoMatchingKey", "MultipleMatchingKeys"]
        );
        assert!(error_codes().contains(&"InvalidFormat"));
    }

    #[test]
    fn encode_reproduces_rfc4648_section_10() {
        for (plain, encoded) in RFC4648_SECTION_10 {
            assert_eq!(base64url_encode(plain.as_bytes()), encoded);
        }
    }

    #[test]
    fn decode_reproduces_rfc4648_section_10() {
        for (plain, encoded) in RFC4648_SECTION_10 {
            assert_eq!(base64url_decode(encoded).unwrap(), plain.as_bytes());
        }
    }

    #[test]
    fn rfc7515_appendix_c_uses_the_url_safe_alphabet() {
        // RFC 7515 Appendix C: the octets [3, 236, 255, 224, 193] encode as "A-z_4ME".
        let octets = [3, 236, 255, 224, 193];
        assert_eq!(base64url_encode(&octets), "A-z_4ME");
        assert_eq!(base64url_decode("A-z_4ME").unwrap(), octets);
    }

    /// RFC 7515 Appendix A.1 / RFC 7519 §3.1.
    const A1: &str = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    #[test]
    fn unverified_decode_returns_the_core_results_as_json_text() {
        // ADR 0069 §1: header JSON (the core's member order, not the token's), the payload as
        // SecretBytes, claims JSON.
        assert_eq!(
            decode_protected_header_unverified(A1).unwrap(),
            r#"{"alg":"HS256","typ":"JWT"}"#
        );
        let jws = decode_jws_unverified(A1).unwrap();
        assert_eq!(jws.protected_header, r#"{"alg":"HS256","typ":"JWT"}"#);
        assert_eq!(
            jws.payload.as_bytes(),
            b"{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}"
        );
        let jwt = decode_jwt_unverified(A1).unwrap();
        assert_eq!(jwt.header, r#"{"alg":"HS256","typ":"JWT"}"#);
        assert_eq!(
            jwt.claims,
            r#"{"iss":"joe","exp":1300819380,"http://example.com/is_root":true}"#
        );
    }

    #[test]
    fn unverified_decode_reports_the_core_codes() {
        assert_eq!(
            decode_protected_header_unverified("a.b")
                .unwrap_err()
                .code(),
            "InvalidFormat"
        );
        assert_eq!(
            decode_jws_unverified("eyJ=.cA.c2ln").unwrap_err().code(),
            "InvalidBase64"
        );
        // A five-part token is not a signed JWT (ADR 0069 §2).
        assert_eq!(
            decode_jwt_unverified("a.b.c.d.e").unwrap_err().code(),
            "InvalidFormat"
        );
    }

    #[test]
    fn unverified_debug_redacts_the_payload_and_prints_lengths() {
        // ADR 0030 §7.5, ADR 0069 §5. "MARKER" is in the payload.
        let jws = decode_jws_unverified("eyJhbGciOiJub25lIn0.TUFSS0VS.").unwrap();
        assert_eq!(jws.payload.as_bytes(), b"MARKER");
        let printed = format!("{jws:?}");
        assert!(!printed.contains("MARKER"), "{printed}");
        assert!(printed.contains("<redacted>"), "{printed}");
        let jwt = decode_jwt_unverified(A1).unwrap();
        let printed = format!("{jwt:?}");
        assert!(!printed.contains("joe"), "{printed}");
    }

    #[test]
    fn decode_is_strict_and_reports_the_core_code() {
        // Padding (RFC 7515 §2), the standard alphabet's `+` and `/` (RFC 4648 §4 vs §5), an
        // impossible length, non-zero trailing bits ("Zh" would be "f" if it were accepted).
        for bad in ["Zg==", "A+z/4ME", "Z", "Zh", "Zm9v\n"] {
            let err = base64url_decode(bad).unwrap_err();
            assert_eq!(err.code(), "InvalidBase64", "{bad:?}");
        }
    }
}
