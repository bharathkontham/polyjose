#![no_main]
//! JWK and JWK Set parse (RFC 7517 §4–§5), `to_public` and RFC 7638
//! thumbprints.
//!
//! - Ok ⇒ parse(serialize(k)) serializes identically.
//! - The thumbprint is stable across the round trip, and equal for a key
//!   and its public part (RFC 7638 §3.2: only the required public members
//!   are hashed).
//! - `to_public` gives a public key.
//! - A set's members each round-trip, and selecting by a member's `kid`
//!   returns a key with that `kid` (RFC 7517 §5).
use libfuzzer_sys::fuzz_target;
use polyjose::jwk::{Jwk, JwkSelector, JwkSet, ThumbprintHash};
use polyjose_fuzz::check_err;

const HASHES: [ThumbprintHash; 3] = [
    ThumbprintHash::Sha256,
    ThumbprintHash::Sha384,
    ThumbprintHash::Sha512,
];

fn check_key(k: &Jwk) {
    let json = k.to_json();
    let again = match Jwk::from_json(json.as_bytes()) {
        Ok(a) => a,
        Err(e) => panic!("serialized JWK does not re-parse: {}", e.code()),
    };
    assert!(*again.to_json() == *json, "JWK round trip changed the key");
    let public = k.to_public();
    if let Some(p) = &public {
        assert!(p.is_public(), "to_public gave a private key");
        assert!(p.key_type() == k.key_type(), "to_public changed kty");
    }
    for h in HASHES {
        let t = k.thumbprint(h);
        assert!(
            again.thumbprint(h) == t,
            "thumbprint changed over the round trip"
        );
        if let Some(p) = &public {
            assert!(p.thumbprint(h) == t, "public part has another thumbprint");
        }
        let _ = k.thumbprint_uri(h);
    }
}

fuzz_target!(|data: &[u8]| {
    match Jwk::from_json(data) {
        Ok(k) => check_key(&k),
        Err(e) => check_err(&e),
    }
    match JwkSet::from_json(data) {
        Ok(set) => {
            assert!(set.len() == set.keys().len());
            for k in set.keys() {
                check_key(k);
            }
            if let Some(kid) = set.keys().iter().find_map(Jwk::kid) {
                match set.select(&JwkSelector::new().kid(kid)) {
                    Ok((i, k)) => {
                        assert!(i < set.len());
                        assert!(k.kid() == Some(kid), "selected a key with another kid");
                    }
                    Err(e) => check_err(&e),
                }
            }
        }
        Err(e) => check_err(&e),
    }
});
