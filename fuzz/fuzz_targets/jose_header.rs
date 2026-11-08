#![no_main]
//! The JOSE Header parse (RFC 7515 §4, RFC 7516 §4): `Header::from_json`
//! and the JWS protected-header parse `ProtectedHeader::from_encoded`.
//!
//! - Ok ⇒ `to_json` → `from_json` gives an equal header.
//! - A protected header that parses is the same header `from_json` gives
//!   for its decoded bytes (RFC 7515 §5.2 steps 2–3).
//! - The `crit` checks (RFC 7515 §4.1.11) and the algorithm accessors never
//!   panic, and fail only with stable codes.
use libfuzzer_sys::fuzz_target;
use polyjose::header::Header;
use polyjose::jws::ProtectedHeader;
use polyjose::util::b64url_encode;
use polyjose_fuzz::check_err;

fn check<T>(r: polyjose::Result<T>) {
    if let Err(e) = r {
        check_err(&e);
    }
}

fuzz_target!(|data: &[u8]| {
    let parsed = Header::from_json(data);
    match &parsed {
        Ok(h) => {
            match h.to_json() {
                Ok(s) => match Header::from_json(s.as_bytes()) {
                    Ok(again) => assert!(again == *h, "from_json(to_json(h)) != h"),
                    Err(e) => panic!("serialized header does not re-parse: {}", e.code()),
                },
                Err(e) => check_err(&e),
            }
            check(h.to_object());
            check(h.validate_crit());
            check(h.validate_crit_understood(&["b64", "exp"]));
            check(h.signing_alg());
            check(h.key_mgmt_alg());
            check(h.content_enc_alg());
        }
        Err(e) => check_err(e),
    }
    match ProtectedHeader::from_encoded(&b64url_encode(data)) {
        Ok(p) => match &parsed {
            Ok(h) => assert!(p.header() == h, "protected header differs from from_json"),
            Err(e) => panic!(
                "protected header accepted, from_json rejected: {}",
                e.code()
            ),
        },
        Err(e) => check_err(&e),
    }
});
