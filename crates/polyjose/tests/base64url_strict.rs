//! Black-box probes of the public strict base64url API (T03 tester).
use polyjose::Error;
use polyjose::util::{b64url_decode, b64url_encode};

const ALPHA: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Independent reference: accept iff the string is the canonical encoding of some octets.
fn reference_decode(s: &str) -> Option<Vec<u8>> {
    let mut vals = Vec::new();
    for b in s.bytes() {
        vals.push(ALPHA.iter().position(|&a| a == b)? as u32);
    }
    if vals.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::new();
    for chunk in vals.chunks(4) {
        let mut acc = 0u32;
        for (i, v) in chunk.iter().enumerate() {
            acc |= v << (18 - 6 * i as u32);
        }
        let n = chunk.len() * 6 / 8;
        for i in 0..n {
            out.push((acc >> (16 - 8 * i as u32)) as u8);
        }
    }
    (b64url_encode(&out) == s).then_some(out)
}

fn check(s: &str) {
    assert_eq!(b64url_decode(s).ok(), reference_decode(s), "input {s:?}");
}

#[test]
fn exhaustive_up_to_three_characters_matches_reference() {
    check("");
    for &a in ALPHA {
        check(std::str::from_utf8(&[a]).unwrap());
        for &b in ALPHA {
            check(std::str::from_utf8(&[a, b]).unwrap());
            for &c in ALPHA {
                check(std::str::from_utf8(&[a, b, c]).unwrap());
            }
        }
    }
}

#[test]
fn four_to_seven_characters_sampled_match_reference() {
    let mut x: u64 = 0x9e3779b97f4a7c15;
    for len in 4..=7usize {
        for _ in 0..20_000 {
            let s: String = (0..len)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    ALPHA[(x % 64) as usize] as char
                })
                .collect();
            check(&s);
        }
    }
}

#[test]
fn very_long_input_round_trips_and_rejects_bad_tail() {
    let bytes: Vec<u8> = (0..5_000_001u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 24) as u8)
        .collect();
    let enc = b64url_encode(&bytes);
    assert_eq!(b64url_decode(&enc).unwrap(), bytes);
    assert_eq!(b64url_decode(&format!("{enc}=")), Err(Error::InvalidBase64));
    assert_eq!(
        b64url_decode(&format!("{enc}A")).is_ok(),
        (enc.len() + 1) % 4 != 1
    );
    let mut bad = enc.clone();
    bad.replace_range(0..1, "+");
    assert_eq!(b64url_decode(&bad), Err(Error::InvalidBase64));
}

#[test]
fn multibyte_utf8_is_rejected_without_panic() {
    for s in [
        "é",
        "Zm9vé",
        "日本語",
        "😀😀",
        "Zm9\u{0301}",
        "\u{feff}Zm9v",
        "Zm9v\u{200b}",
        "ＺＭ９ｖ",
        "\u{212a}Qg",
    ] {
        assert_eq!(b64url_decode(s), Err(Error::InvalidBase64), "{s:?}");
    }
}

#[test]
fn error_is_always_the_same_and_leaks_nothing() {
    let secret = "SECRETKEYMATERIAL+/=";
    let e = b64url_decode(secret).unwrap_err();
    assert_eq!(e, Error::InvalidBase64);
    assert!(!format!("{e:?}").contains("SECRET"));
    assert!(!format!("{e}").contains("SECRET"));
    for s in ["QR", "Z", "Zg==", "+/8", " ", "é"] {
        let e2 = b64url_decode(s).unwrap_err();
        assert_eq!(format!("{e2:?}"), format!("{e:?}"));
        assert_eq!(format!("{e2}"), format!("{e}"));
    }
}
