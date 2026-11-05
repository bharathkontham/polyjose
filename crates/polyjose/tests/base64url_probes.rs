//! T13 tester probes: pad bits, non-ASCII input, long input, error opacity.
//! RFC 4648 §3.5 (pad bits), §4; RFC 7515 §2.
use base64ct::{Base64UrlUnpadded, Encoding};
use polyjose::Error;
use polyjose::util::{b64url_decode, b64url_encode};

const ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Final 2-char group: low 4 bits of the 2nd symbol are pad bits.
/// Final 3-char group: low 2 bits of the 3rd symbol are pad bits.
#[test]
fn nonzero_pad_bits_rejected_for_every_symbol() {
    for (i, c) in ALPHABET.chars().enumerate() {
        let two = format!("A{c}");
        let three = format!("AA{c}");
        assert_eq!(b64url_decode(&two).is_ok(), i % 16 == 0, "{two}");
        assert_eq!(b64url_decode(&three).is_ok(), i % 4 == 0, "{three}");
        // Pad bits also checked after full quanta.
        let long = format!("AAAA{two}");
        assert_eq!(b64url_decode(&long).is_ok(), i % 16 == 0, "{long}");
    }
}

#[test]
fn non_ascii_and_multibyte_rejected_without_panic() {
    for s in [
        "é",
        "ééé",
        "AAé",
        "AAAé",
        "AAAA\u{1F511}",
        "\u{0}",
        "AA\u{0}A",
        "ＡＡ",
        "\u{7f}\u{7f}",
    ] {
        assert_eq!(b64url_decode(s), Err(Error::InvalidBase64), "{s:?}");
    }
}

#[test]
fn very_long_input_round_trips_and_matches_oracle() {
    let data: Vec<u8> = (0..3_000_001u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
        .collect();
    let enc = b64url_encode(&data);
    assert_eq!(enc, Base64UrlUnpadded::encode_string(&data));
    assert_eq!(b64url_decode(&enc).unwrap(), data);
    // A single bad byte at the very end of a long input is still rejected.
    let mut bad = enc.into_bytes();
    let n = bad.len();
    bad[n - 1] = b'=';
    assert_eq!(
        b64url_decode(std::str::from_utf8(&bad).unwrap()),
        Err(Error::InvalidBase64)
    );
}

#[test]
fn error_is_single_variant_and_leaks_no_input() {
    let secret = "SECRETKEYMATERIAL+/=";
    let e = b64url_decode(secret).unwrap_err();
    assert_eq!(e, Error::InvalidBase64);
    for rendered in [format!("{e}"), format!("{e:?}")] {
        assert!(
            !rendered.contains("SECRET") && !rendered.contains("MATERIAL"),
            "{rendered}"
        );
    }
    // Every failure cause yields the identical error.
    for s in ["A", "AAAAA", "QR", "AA=", "A+A+", "A A ", "é", "AAAA\n"] {
        assert_eq!(b64url_decode(s).unwrap_err(), e, "{s:?}");
    }
}
