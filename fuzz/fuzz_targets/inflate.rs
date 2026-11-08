#![no_main]
//! polyjose's bounded raw DEFLATE inflate (RFC 1951 §3.2, ADR 0017), the
//! `zip: DEF` decoder of RFC 7516 §4.1.3, through the `cfg(fuzzing)` entry
//! point.
//!
//! Input: two bytes of output cap (little-endian), then the stream.
//!
//! - The output never exceeds the cap (ADR 0017 §1).
//! - Differential against `miniz_oxide` at a 1 MiB cap: when we accept,
//!   miniz_oxide accepts with the same output; when we reject, miniz_oxide
//!   rejects too, or needs more than the cap, or the stream is the one
//!   deliberate divergence (a literal/length code with a single code,
//!   RFC 1951 §3.2.7).
//! - The small cap agrees with the large one: same output when it fits,
//!   an error when it does not.
use libfuzzer_sys::fuzz_target;
use miniz_oxide::inflate::decompress_to_vec_with_limit;
use polyjose::Error;
use polyjose::fuzzing::inflate;
use polyjose_fuzz::check_err;

const CAP: usize = 1 << 20;
const SINGLE_LENGTH_CODE: &str = "deflate: literal/length code with a single code";

fuzz_target!(|data: &[u8]| {
    let Some((cap_bytes, stream)) = data.split_first_chunk::<2>() else {
        return;
    };
    let small_cap = usize::from(u16::from_le_bytes(*cap_bytes));

    let ours = inflate(stream, CAP);
    let theirs = decompress_to_vec_with_limit(stream, 2 * CAP);
    match &ours {
        Ok(out) => {
            assert!(out.len() <= CAP, "output above the cap");
            match &theirs {
                Ok(t) => assert!(out[..] == t[..], "inflate differs from miniz_oxide"),
                Err(e) => panic!("we accept, miniz_oxide rejects: {:?}", e.status),
            }
        }
        Err(e) => {
            check_err(e);
            assert_eq!(e.code(), "InvalidFormat");
            let diverges = matches!(e, Error::InvalidFormat(d) if *d == SINGLE_LENGTH_CODE);
            if let Ok(t) = &theirs {
                assert!(
                    diverges || t.len() > CAP,
                    "we reject, miniz_oxide accepts {} bytes",
                    t.len()
                );
            }
        }
    }

    match inflate(stream, small_cap) {
        Ok(out) => {
            assert!(out.len() <= small_cap, "output above the small cap");
            match &ours {
                Ok(big) => assert!(out[..] == big[..], "the cap changed the output"),
                Err(_) => panic!("accepted under the small cap only"),
            }
        }
        Err(e) => {
            check_err(&e);
            if let Ok(big) = &ours {
                assert!(
                    big.len() > small_cap,
                    "rejected under a cap the output fits"
                );
            }
        }
    }
});
