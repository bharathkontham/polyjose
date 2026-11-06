//! F01 black-box probes through `Jwk::from_pem`: the PEM size cap (ADR 0018
//! §2) is 98,384 octets. The largest CRLF block of a 64 KiB DER under every
//! supported label, padded to the cap, is not refused for its size; one more
//! octet is, whatever the label. No timing, no allocation counting here (the
//! unit tests read buffer capacities).

#![allow(clippy::unwrap_used)] // test code: a panic is a failed assertion

use polyjose::Error;
use polyjose::jwk::Jwk;

const CAP: usize = 98_384;
const TOO_LARGE: Error = Error::InvalidKey("PEM input too large");
const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// A CRLF block of `der_len` octets of base64 (a multiple-of-3 length keeps
/// the padding canonical) under `label`, padded with spaces to `total`.
fn block(label: &str, der_len: usize, total: usize) -> String {
    let chars = der_len.div_ceil(3) * 4;
    let mut body: Vec<u8> = (0..chars).map(|i| B64[(i * 7 + 3) % 64]).collect();
    // Canonical padding for a der_len that is not a multiple of 3.
    match der_len % 3 {
        1 => {
            let n = body.len();
            body[n - 2] = b'=';
            body[n - 1] = b'=';
            body[n - 3] = b'A';
        }
        2 => {
            let n = body.len();
            body[n - 1] = b'=';
            body[n - 2] = b'A';
        }
        _ => {}
    }
    let mut text = format!("-----BEGIN {label}-----\r\n");
    for line in body.chunks(64) {
        text.push_str(std::str::from_utf8(line).unwrap());
        text.push_str("\r\n");
    }
    text.push_str(&format!("-----END {label}-----\r\n"));
    let fill = total.saturating_sub(text.len());
    text.extend(std::iter::repeat_n(' ', fill));
    text
}

#[test]
fn largest_supported_block_is_not_refused_for_size() {
    // 65,536 is the DER cap; 65,535 and 65,534 exercise padded last quanta.
    for label in [
        "PRIVATE KEY",
        "PUBLIC KEY",
        "EC PRIVATE KEY",
        "RSA PUBLIC KEY",
    ] {
        for der_len in [65_536usize, 65_535, 65_534] {
            // Tight (no whitespace) and padded to the cap.
            for total in [0usize, CAP] {
                let tight = block(label, der_len, 0);
                let t = if total == 0 {
                    tight
                } else {
                    block(label, der_len, CAP)
                };
                assert!(t.len() <= CAP, "{label} {der_len}");
                let err = Jwk::from_pem(&t).unwrap_err();
                assert_ne!(err, TOO_LARGE, "{label} {der_len} {total}");
            }
        }
    }
}

#[test]
fn one_octet_over_the_cap_is_too_large_whatever_the_label() {
    for label in [
        "PRIVATE KEY",
        "PUBLIC KEY",
        "EC PRIVATE KEY",
        "RSA PUBLIC KEY",
        "RSA PRIVATE KEY",
        "ENCRYPTED PRIVATE KEY",
        "CERTIFICATE",
        "A VERY LONG BUT SYNTACTICALLY VALID LABEL FOR OTHER",
    ] {
        let t = block(label, 300, CAP + 1);
        assert_eq!(t.len(), CAP + 1);
        assert_eq!(Jwk::from_pem(&t).unwrap_err(), TOO_LARGE, "{label}");
        let t = block(label, 300, CAP);
        assert_ne!(Jwk::from_pem(&t).unwrap_err(), TOO_LARGE, "{label} at cap");
    }
}

#[test]
fn sixty_five_mib_is_too_large() {
    let t = block("PRIVATE KEY", 300, 65 * 1024 * 1024);
    assert_eq!(Jwk::from_pem(&t).unwrap_err(), TOO_LARGE);
    let t = block("RSA PRIVATE KEY", 300, 65 * 1024 * 1024);
    assert_eq!(Jwk::from_pem(&t).unwrap_err(), TOO_LARGE);
}
