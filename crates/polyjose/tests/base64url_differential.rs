//! Differential tests: polyjose's own base64url codec against `base64ct`
//! (ADR 0016 §5: a dev-dependency used only as a test oracle).
//!
//! The oracle is `Base64UrlUnpadded::encode_string` / `decode_vec`.
//! `decode_vec` is base64ct's strict path (it rejects non-canonical pad
//! bits, RFC 4648 §3.5); `decode_in_place` is lenient and accepts "QR", so
//! it must not be used as the oracle.
use base64ct::{Base64UrlUnpadded, Encoding};
use polyjose::util::{b64url_decode, b64url_encode};
use proptest::prelude::*;

/// Both decoders must agree on accept/reject and, on accept, on the bytes.
fn assert_decoders_agree(s: &str) {
    assert_eq!(
        b64url_decode(s).ok(),
        Base64UrlUnpadded::decode_vec(s).ok(),
        "input {s:?}"
    );
}

/// Every string of up to three symbols drawn from the alphabet plus the
/// characters RFC 7515 §2 forbids, compared exhaustively (69^3 + 69^2 + 69 + 1).
#[test]
fn exhaustive_short_strings_agree_with_oracle() {
    let symbols: Vec<char> =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=+/ ."
            .chars()
            .collect();
    assert_decoders_agree("");
    for &a in &symbols {
        assert_decoders_agree(&format!("{a}"));
        for &b in &symbols {
            assert_decoders_agree(&format!("{a}{b}"));
            for &c in &symbols {
                assert_decoders_agree(&format!("{a}{b}{c}"));
            }
        }
    }
}

/// A valid oracle encoding of `bytes` with the character at `at` replaced by
/// `with` (alphabet or forbidden): mostly near-miss inputs, some still valid.
fn mutated_encoding() -> impl Strategy<Value = String> {
    (
        proptest::collection::vec(any::<u8>(), 1..64),
        any::<prop::sample::Index>(),
        prop::sample::select(
            "AQgw-_RSTUVf09=+/ \t\n.*\u{e9}"
                .chars()
                .collect::<Vec<char>>(),
        ),
    )
        .prop_map(|(bytes, at, with)| {
            let encoded = Base64UrlUnpadded::encode_string(&bytes);
            let i = at.index(encoded.len());
            let mut s = String::with_capacity(encoded.len() + 1);
            s.push_str(&encoded[..i]);
            s.push(with);
            s.push_str(&encoded[i + 1..]);
            s
        })
}

proptest! {
    // ADR 0008 layer 2: bounded case counts in the fast suite (<= 1,000).
    #![proptest_config(ProptestConfig::with_cases(500))]

    /// RFC 4648 §5 / RFC 7515 §2: identical unpadded output for any octets.
    #[test]
    fn encode_matches_oracle(bytes in proptest::collection::vec(any::<u8>(), 0..1024)) {
        prop_assert_eq!(b64url_encode(&bytes), Base64UrlUnpadded::encode_string(&bytes));
    }

    /// Alphabet-biased inputs: pure alphabet strings of every length class,
    /// alphabet mixed with `=`, `+`, `/`, whitespace and other ASCII, and
    /// one-character mutations of valid encodings.
    #[test]
    fn decode_of_alphabet_biased_strings_matches_oracle(
        s in prop_oneof![
            "[A-Za-z0-9_-]{0,96}",
            "[A-Za-z0-9_=+/ \\t\\r\\n.*%~-]{0,64}",
            mutated_encoding(),
        ]
    ) {
        assert_decoders_agree(&s);
    }

    /// Fully arbitrary text: any Unicode string, and arbitrary bytes made
    /// into a string (lossily, since the API takes `&str`).
    #[test]
    fn decode_of_arbitrary_strings_matches_oracle(
        s in prop_oneof![
            any::<String>(),
            proptest::collection::vec(any::<u8>(), 0..64)
                .prop_map(|b| String::from_utf8_lossy(&b).into_owned()),
        ]
    ) {
        assert_decoders_agree(&s);
    }
}
