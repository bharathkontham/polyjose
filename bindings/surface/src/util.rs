//! Utilities (ADR 0030 §4, "Utilities"): the version, the stable error codes and base64url.

use crate::error::SurfaceResult;

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
