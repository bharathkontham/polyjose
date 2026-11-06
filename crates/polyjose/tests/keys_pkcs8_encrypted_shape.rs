//! B01 black-box probes: only the RFC 5958 §3 EncryptedPrivateKeyInfo shape
//! `SEQUENCE { SEQUENCE, OCTET STRING }` is `UnsupportedAlgorithm` through the
//! public API; every other leading-SEQUENCE input is `InvalidKey` (ADR 0018 §4).

use polyjose::Error;
use polyjose::jwk::Jwk;
use polyjose::keys::KeyFormat;

fn pkcs8(der: &[u8]) -> Result<Jwk, Error> {
    Jwk::from_der(der, KeyFormat::Pkcs8)
}

fn unsupported(der: &[u8]) -> bool {
    matches!(pkcs8(der), Err(Error::UnsupportedAlgorithm))
}

fn invalid(der: &[u8]) -> bool {
    matches!(pkcs8(der), Err(Error::InvalidKey(_)))
}

#[test]
fn the_exact_shape_is_unsupported_whatever_is_inside() {
    // Empty AlgorithmIdentifier and empty encryptedData.
    assert!(unsupported(&[0x30, 0x04, 0x30, 0x00, 0x04, 0x00]));
    // Garbage and BER inside encryptedData.
    assert!(unsupported(&[
        0x30, 0x09, 0x30, 0x00, 0x04, 0x05, 0x30, 0x80, 0xFF, 0x00, 0x1F
    ]));
    // Garbage inside the AlgorithmIdentifier contents.
    assert!(unsupported(&[
        0x30, 0x08, 0x30, 0x04, 0x02, 0x80, 0xFF, 0xFF, 0x04, 0x00
    ]));
    // A minimal long-form outer length (130 contents octets).
    let mut long = vec![0x30, 0x81, 0x82, 0x30, 0x00, 0x04, 0x7E];
    long.extend_from_slice(&[0xAA; 0x7E]);
    assert!(unsupported(&long));
    // A non-minimal long form is malformed DER, not an encrypted key.
    assert!(invalid(&[0x30, 0x81, 0x05, 0x30, 0x00, 0x04, 0x01, 0xAA]));
}

#[test]
fn every_other_leading_sequence_is_invalid_key() {
    let cases: [(&str, &[u8]); 9] = [
        (
            "indefinite outer length",
            &[0x30, 0x80, 0x30, 0x00, 0x04, 0x00, 0x00, 0x00],
        ),
        (
            "constructed OCTET STRING",
            &[0x30, 0x04, 0x30, 0x00, 0x24, 0x00],
        ),
        (
            "third element",
            &[0x30, 0x06, 0x30, 0x00, 0x04, 0x00, 0x05, 0x00],
        ),
        (
            "non-SEQUENCE first (OCTET STRING)",
            &[0x30, 0x04, 0x04, 0x00, 0x04, 0x00],
        ),
        (
            "trailing bytes after outer",
            &[0x30, 0x04, 0x30, 0x00, 0x04, 0x00, 0x00],
        ),
        (
            "BIT STRING second",
            &[0x30, 0x05, 0x30, 0x00, 0x03, 0x01, 0x00],
        ),
        ("only the AlgorithmIdentifier", &[0x30, 0x02, 0x30, 0x00]),
        (
            "indefinite inner SEQUENCE",
            &[0x30, 0x06, 0x30, 0x80, 0x00, 0x00, 0x04, 0x00],
        ),
        (
            "indefinite OCTET STRING",
            &[0x30, 0x06, 0x30, 0x00, 0x04, 0x80, 0x00, 0x00],
        ),
    ];
    for (what, der) in cases {
        let result = pkcs8(der);
        assert!(
            matches!(result, Err(Error::InvalidKey(_))),
            "{what}: {:?}",
            result.err()
        );
    }
}

#[test]
fn no_error_distinguishes_causes_inside_the_encrypted_shape() {
    // Same code and same Display for different garbage.
    let a = pkcs8(&[0x30, 0x04, 0x30, 0x00, 0x04, 0x00]).err();
    let b = pkcs8(&[0x30, 0x08, 0x30, 0x04, 0x02, 0x80, 0xFF, 0xFF, 0x04, 0x00]).err();
    assert_eq!(a, b);
    assert!(invalid(&[0x30, 0x02, 0x30, 0x00]));
}

#[test]
fn spki_and_encrypted_fixtures_via_public_api() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/keys");
    let mut spki = 0;
    let mut enc = 0;
    for dir in std::fs::read_dir(&root).unwrap() {
        let dir = dir.unwrap().path();
        if !dir.is_dir() {
            continue;
        }
        for f in std::fs::read_dir(&dir).unwrap() {
            let p = f.unwrap().path();
            let name = p.file_name().unwrap().to_string_lossy().into_owned();
            if !name.ends_with(".der") {
                continue;
            }
            let der = std::fs::read(&p).unwrap();
            if name.ends_with("-spki.der") && !name.starts_with("reject-") {
                assert!(invalid(&der), "{name}");
                spki += 1;
            }
            if name.starts_with("reject-") && name.ends_with("-pkcs8-encrypted.der") {
                assert!(unsupported(&der), "{name}");
                enc += 1;
            }
        }
    }
    assert!(spki >= 10 && enc >= 1, "spki={spki} enc={enc}");
}
