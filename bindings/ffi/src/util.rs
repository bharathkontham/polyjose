//! The utility exports (ADR 0030 §4, "Utilities"). Each is a type conversion and one surface
//! call (ADR 0030 §1, "the adapter test").

use zeroize::Zeroizing;

use crate::PolyjoseError;

/// The polyjose crate version, e.g. `0.1.0` (ADR 0030 §4).
#[uniffi::export]
pub fn version() -> String {
    polyjose_surface::util::version().to_owned()
}

/// Every stable error code, in the core's order: equal to `polyjose::Error::CODES` and to the
/// codes of [`PolyjoseError`] (ADR 0030 §5). Bindings test their code set against it.
#[uniffi::export]
pub fn error_codes() -> Vec<String> {
    polyjose_surface::util::error_codes()
        .iter()
        .map(|code| (*code).to_owned())
        .collect()
}

/// Encodes `data` as unpadded base64url (RFC 4648 §5, RFC 7515 §2).
///
/// The input may be key material, so it is wiped when the call returns (ADR 0030 §7.1). UniFFI
/// 0.32.2 lifts a `Vec<u8>` argument by copying it out of a buffer it then frees unwiped; that
/// copy is the documented residual of ADR 0030 §7.3 (restated in ADR 0058). The result is a
/// `String`, which leaves the 1 host-freed copy of ADR 0058.
#[uniffi::export]
pub fn base64url_encode(data: Vec<u8>) -> String {
    let data = Zeroizing::new(data);
    polyjose_surface::util::base64url_encode(&data)
}

/// Decodes strict unpadded base64url (RFC 4648 §5, RFC 7515 §2): padding, characters outside the
/// URL-safe alphabet, whitespace and non-canonical trailing bits fail with `InvalidBase64`.
///
/// The text is wiped when the call returns, as a precaution (ADR 0030 §7.1); a `String`
/// argument is UniFFI's only Rust-heap copy of it (0009 research §8; ADR 0030 §7.3, restated in
/// ADR 0058).
///
/// The result is not treated as key material: base64url output is not on ADR 0030 §7's list of
/// secret-bearing values, and the surface returns it as a plain `Vec<u8>`. UniFFI 0.32.2 lowers
/// it like every `Vec<u8>` result, into a buffer that grows as it is written, and the host frees
/// the final `RustBuffer`, all unwiped: **at least 2** full Rust-heap copies (the returned vector
/// and the host-freed buffer), plus a full or partial copy for each move of the growing buffer
/// (ADR 0058). Callers who decode secret bytes should wipe the `ByteArray`/`Data` they receive
/// (ADR 0030 §7.4).
#[uniffi::export]
pub fn base64url_decode(text: String) -> Result<Vec<u8>, PolyjoseError> {
    let text = Zeroizing::new(text);
    Ok(polyjose_surface::util::base64url_decode(&text)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4648 §10's base64 test vectors in the URL-safe alphabet without padding (RFC 4648 §5).
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
    fn version_is_the_surface_version() {
        assert_eq!(version(), polyjose_surface::util::version());
        assert_eq!(version(), env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn error_codes_are_the_core_codes_and_the_error_variants() {
        assert_eq!(error_codes(), polyjose::Error::CODES);
        assert_eq!(error_codes(), crate::PolyjoseError::CODES);
    }

    #[test]
    fn base64url_reproduces_rfc4648_section_10() {
        for (plain, encoded) in RFC4648_SECTION_10 {
            assert_eq!(base64url_encode(plain.as_bytes().to_vec()), encoded);
            assert_eq!(
                base64url_decode(encoded.to_owned()).unwrap(),
                plain.as_bytes()
            );
        }
    }

    #[test]
    fn base64url_uses_the_url_safe_alphabet_of_rfc7515_appendix_c() {
        let octets = vec![3, 236, 255, 224, 193];
        assert_eq!(base64url_encode(octets.clone()), "A-z_4ME");
        assert_eq!(base64url_decode("A-z_4ME".to_owned()).unwrap(), octets);
    }

    #[test]
    fn base64url_decode_failure_is_the_invalid_base64_variant() {
        for bad in ["Zg==", "A+z/4ME", "Z"] {
            let err = base64url_decode(bad.to_owned()).unwrap_err();
            assert_eq!(err.code(), "InvalidBase64", "{bad:?}");
            assert!(matches!(err, crate::PolyjoseError::InvalidBase64 { .. }));
        }
    }
}
