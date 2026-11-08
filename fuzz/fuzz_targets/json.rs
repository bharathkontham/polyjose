#![no_main]
//! `json::parse` and `json::parse_with_limits` (RFC 8259, RFC 7493; ADR 0016).
//!
//! - Ok ⇒ serialize → parse gives an equal value, and serializing is
//!   idempotent (the deterministic writer RFC 7638 relies on).
//! - Duplicate member names are never Ok (RFC 7515 §5.2 step 4, RFC 7516
//!   §5.2 step 4): checked on the re-parsed value's serialization, which has
//!   unique names if and only if the parser rejected none.
//! - Tighter limits accept a subset of what the defaults accept.
//! - Every failure is `InvalidJson`.
use libfuzzer_sys::fuzz_target;
use polyjose::json::{self, Limits};
use polyjose_fuzz::check_err;

fuzz_target!(|data: &[u8]| {
    let full = json::parse(data);
    match &full {
        Ok(v) => {
            let s = v.to_json();
            let again = match json::parse(s.as_bytes()) {
                Ok(a) => a,
                Err(e) => panic!("serialized value does not re-parse: {}", e.code()),
            };
            assert!(again == *v, "parse(serialize(v)) != v");
            assert!(again.to_json() == s, "serialization is not idempotent");
        }
        Err(e) => {
            check_err(e);
            assert_eq!(e.code(), "InvalidJson");
        }
    }
    let mut tight = Limits::DEFAULT;
    tight.max_depth = 4;
    tight.max_entries = 8;
    tight.max_input_len = 4096;
    match json::parse_with_limits(data, &tight) {
        Ok(v) => match &full {
            Ok(f) => assert!(*f == v, "limits changed the parsed value"),
            Err(_) => panic!("accepted under tight limits but not the defaults"),
        },
        Err(e) => {
            check_err(&e);
            assert_eq!(e.code(), "InvalidJson");
        }
    }
});
