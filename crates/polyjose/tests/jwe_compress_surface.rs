//! F10 tester: `Encryptor::compress` in a build without `deflate` is
//! `UnsupportedAlgorithm` before any random draw, including through
//! `encrypt_reproducible` (ADR 0030 §4, ADR 0017 §5), and the error order
//! puts a malformed request before it (plan.md error contract).
#![cfg(all(not(feature = "deflate"), feature = "insecure-test-vectors"))]
#![allow(clippy::panic)]

use polyjose::insecure_test_vectors::FixedRng;
use polyjose::jwa::{ContentEncAlg as E, KeyMgmtAlg as A};
use polyjose::jwe::{Encryptor, JsonForm, Recipient, Serialization};
use polyjose::jwk::Jwk;
use polyjose::util::b64url_encode;

fn oct(n: usize) -> Jwk {
    let json = format!(r#"{{"kty":"oct","k":"{}"}}"#, b64url_encode(&vec![7u8; n]));
    Jwk::from_json(json.as_bytes()).unwrap_or_else(|e| panic!("{e}"))
}

fn code<T>(r: polyjose::Result<T>) -> &'static str {
    match r {
        Ok(_) => "ok",
        Err(e) => e.code(),
    }
}

#[test]
fn reproducible_refuses_compress_with_rng_untouched() {
    for (alg, n) in [(A::Dir, 16), (A::A128KW, 16)] {
        let e = Encryptor::new(E::A128GCM)
            .compress()
            .recipient(Recipient::new(alg, &oct(n)));
        for form in [
            Serialization::Compact,
            Serialization::Json(JsonForm::Flattened),
            Serialization::Json(JsonForm::General),
        ] {
            let mut rng = FixedRng::new(vec![0u8; 128]);
            assert_eq!(
                code(e.encrypt_reproducible(b"x", form, &mut rng, None)),
                "UnsupportedAlgorithm"
            );
            assert_eq!(rng.remaining(), 128, "{form:?} drew");
        }
    }
}

#[test]
fn malformed_form_beats_compress() {
    let e = Encryptor::new(E::A128GCM)
        .compress()
        .recipient(Recipient::new(A::A128KW, &oct(16)))
        .recipient(Recipient::new(A::A128KW, &oct(16)));
    assert_eq!(code(e.encrypt_compact(b"x")), "InvalidFormat");
    let none = Encryptor::new(E::A128GCM).compress();
    assert_eq!(code(none.encrypt_compact(b"x")), "InvalidFormat");
    // flattened with 2 recipients
    assert_eq!(
        code(e.encrypt_json(b"x", JsonForm::Flattened)),
        "InvalidFormat"
    );
}

#[test]
fn unsupported_enc_or_alg_is_unsupported_either_way() {
    // RSA-OAEP is unsupported on encrypt: same code with or without compress.
    for c in [false, true] {
        let mut e =
            Encryptor::new(E::A128GCM).recipient(Recipient::new(A::from("RSA-OAEP"), &oct(16)));
        let mut f = Encryptor::new(E::from("A999GCM")).recipient(Recipient::new(A::Dir, &oct(16)));
        if c {
            e = e.compress();
            f = f.compress();
        }
        assert_eq!(code(e.encrypt_compact(b"x")), "UnsupportedAlgorithm");
        assert_eq!(code(f.encrypt_compact(b"x")), "UnsupportedAlgorithm");
    }
}
