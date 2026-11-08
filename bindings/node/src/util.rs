//! The utility operations (ADR 0030 §4, "Utilities"): `version`, `errorCodes`,
//! `base64urlEncode`, `base64urlDecode`.
//!
//! `version` and `errorCodes` are synchronous (`bindings/js/BACKEND.md`); the base64url pair are
//! `AsyncTask`s like every other operation (ADR 0031 §2).

use napi::bindgen_prelude::AsyncTask;
use napi_derive::napi;
use polyjose_surface::{SecretBytes, SecretString};
use zeroize::Zeroizing;

use crate::task::surface_task;

/// The polyjose crate version, e.g. `0.1.0` (ADR 0030 §4). Synchronous.
#[napi]
pub fn version() -> String {
    polyjose_surface::util::version().to_owned()
}

/// Every stable error code, in the core's order: equal to `polyjose::Error::CODES` (ADR 0030 §5).
/// Synchronous.
#[napi]
pub fn error_codes() -> Vec<String> {
    polyjose_surface::util::error_codes()
        .iter()
        .map(|code| (*code).to_owned())
        .collect()
}

surface_task! {
    /// `base64urlEncode`: unpadded base64url (RFC 4648 §5, RFC 7515 §2). The input may be key
    /// material, so it is held and returned as a secret (ADR 0030 §7).
    Base64urlEncodeTask { data: Zeroizing<Vec<u8>> } -> SecretString
        = |t| Ok(SecretString::from(polyjose_surface::util::base64url_encode(&t.data)))
}

/// Encodes `data` as unpadded base64url (RFC 4648 §5, RFC 7515 §2). Resolves to a string.
// napi-rs would split the name at the digits; BACKEND.md names it without the split.
#[napi(js_name = "base64urlEncode")]
pub fn base64url_encode(data: &[u8]) -> AsyncTask<Base64urlEncodeTask> {
    AsyncTask::new(Base64urlEncodeTask {
        data: Zeroizing::new(data.to_vec()),
    })
}

surface_task! {
    /// `base64urlDecode`: strict unpadded base64url (RFC 4648 §5, RFC 7515 §2). The text may
    /// encode key material, so it is held and returned as a secret (ADR 0030 §7).
    Base64urlDecodeTask { text: Zeroizing<String> } -> SecretBytes
        = |t| polyjose_surface::util::base64url_decode(&t.text).map(SecretBytes::from)
}

/// Decodes strict unpadded base64url (RFC 4648 §5, RFC 7515 §2): padding, characters outside the
/// URL-safe alphabet, whitespace and non-canonical trailing bits reject with `InvalidBase64`.
/// Resolves to a `Uint8Array`.
// napi-rs would split the name at the digits; BACKEND.md names it without the split.
#[napi(js_name = "base64urlDecode")]
pub fn base64url_decode(text: String) -> AsyncTask<Base64urlDecodeTask> {
    AsyncTask::new(Base64urlDecodeTask {
        text: Zeroizing::new(text),
    })
}

#[cfg(test)]
mod tests {
    use napi::ScopedTask;

    use super::*;
    use crate::tests::wipes_on_drop;

    /// RFC 4648 §10's test vectors in the URL-safe alphabet without padding (RFC 4648 §5).
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
    fn version_and_error_codes_are_the_surface_values() {
        assert_eq!(version(), polyjose_surface::util::version());
        assert_eq!(error_codes(), polyjose_surface::util::error_codes());
    }

    #[test]
    fn error_codes_end_with_multiple_matching_keys() {
        // ADR 0054 §5: `MultipleMatchingKeys` is appended last, after `NoMatchingKey`, at index
        // 16, giving the 17 codes of 0.1.0. Codes are never reordered or removed (ADR 0030 §8),
        // so these indices stay; a code added later goes after them.
        let codes = error_codes();
        assert_eq!(codes.len(), 17, "{codes:?}");
        assert_eq!(codes[15], "NoMatchingKey");
        assert_eq!(codes[16], "MultipleMatchingKeys");
        assert_eq!(
            codes.last().map(String::as_str),
            Some("MultipleMatchingKeys")
        );
        let mut unique = codes.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), codes.len(), "no code twice");
    }

    #[test]
    fn base64url_reproduces_rfc4648_section_10() {
        for (plain, encoded) in RFC4648_SECTION_10 {
            let mut encode = Base64urlEncodeTask {
                data: Zeroizing::new(plain.as_bytes().to_vec()),
            };
            assert_eq!(encode.compute().unwrap().unwrap().as_str(), encoded);
            let mut decode = Base64urlDecodeTask {
                text: Zeroizing::new(encoded.to_owned()),
            };
            assert_eq!(
                decode.compute().unwrap().unwrap().as_bytes(),
                plain.as_bytes()
            );
        }
    }

    #[test]
    fn base64url_decode_failure_is_invalid_base64() {
        for bad in ["Zg==", "A+z/4ME", "Z"] {
            let mut decode = Base64urlDecodeTask {
                text: Zeroizing::new(bad.to_owned()),
            };
            let err = decode.compute().unwrap().unwrap_err();
            assert_eq!(err.code(), "InvalidBase64", "{bad:?}");
        }
    }

    #[test]
    fn inputs_are_held_in_zeroizing_owners() {
        let encode = Base64urlEncodeTask {
            data: Zeroizing::new(Vec::new()),
        };
        wipes_on_drop(&encode.data);
        let decode = Base64urlDecodeTask {
            text: Zeroizing::new(String::new()),
        };
        wipes_on_drop(&decode.text);
    }
}
