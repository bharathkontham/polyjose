#![no_main]
//! JWS verification (RFC 7515 §5.2, RFC 7797): `jws::verify_compact` and
//! `jws::verify_json`, with fixed published keys.
//!
//! Input: a mode byte, then
//! - mode 0 / 1: a key byte (an index into `JWS_VERIFY_KEYS`), then a
//!   compact / JSON JWS, optionally followed by a zero byte and a detached
//!   payload (RFC 7515 App. F).
//! - mode 2: a signer byte, a flags byte, a tamper byte, then the protected
//!   header JSON, a zero byte, the unprotected header JSON, a zero byte and
//!   the payload. The harness signs it with its own key (ADR 0036 §2, 3a:
//!   the verifier is never weakened) and verifies it.
//!
//! - Ok ⇒ the `alg` is in the allow-list (RFC 8725 §3.1).
//! - A JWS the harness signed verifies with the same key and gives the
//!   payload back; changing any one character of a compact JWS makes it
//!   fail (RFC 7515 §5.2 step 8: the signature covers the signing input,
//!   and strict base64url (RFC 7515 §2) has one encoding per value).
//! - Every failure has a stable code.
use libfuzzer_sys::fuzz_target;
use polyjose::header::Header;
use polyjose::jwa::SigningAlg as S;
use polyjose::jwk::Jwk;
use polyjose::jws::{self, ProtectedHeader, SignOptions, Signer, Verified, VerifyOptions};
use polyjose_fuzz::{self as fx, check_err, split0};

const ALLOWED: &[S] = &[
    S::HS256,
    S::HS384,
    S::HS512,
    S::RS256,
    S::RS384,
    S::RS512,
    S::PS256,
    S::PS384,
    S::PS512,
    S::ES256,
    S::ES384,
    S::ES512,
    S::ES256K,
    S::EdDSA,
    S::Ed25519,
];

/// The signers of mode 2: an algorithm and the private key for it.
const SIGNERS: &[(S, &str)] = &[
    (S::HS256, fx::OCT_A1),
    (S::HS384, fx::OCT_A1),
    (S::HS512, fx::OCT_A1),
    (S::ES256, fx::P256_A3),
    (S::ES512, fx::P521_A4),
    (S::ES256K, fx::K256),
    (S::EdDSA, fx::ED25519),
    (S::Ed25519, fx::ED25519),
];

fn check(r: polyjose::Result<Verified>, allowed: &[S]) -> Option<Verified> {
    match r {
        Ok(v) => {
            assert!(
                allowed.contains(&v.alg),
                "verified an alg outside the allow-list"
            );
            Some(v)
        }
        Err(e) => {
            check_err(&e);
            None
        }
    }
}

fn raw(json: bool, rest: &[u8]) {
    let Some((&k, rest)) = rest.split_first() else {
        return;
    };
    let key = fx::jwk(fx::JWS_VERIFY_KEYS[usize::from(k) % fx::JWS_VERIFY_KEYS.len()]);
    let (token, detached) = split0(rest);
    let Ok(token) = core::str::from_utf8(token) else {
        return;
    };
    let Ok(base) = VerifyOptions::new(ALLOWED) else {
        return;
    };
    let opts = if rest.contains(&0) {
        base.detached_payload(detached)
    } else {
        base
    };
    let r = if json {
        jws::verify_json(token, &key, &opts)
    } else {
        jws::verify_compact(token, &key, &opts)
    };
    if let Some(v) = check(r, ALLOWED) {
        if !json {
            // RFC 7515 §7.1: one signature, a protected header only.
            assert!(v.signature_index == 0 && v.protected.is_some() && v.unprotected.is_none());
        }
    }
}

fn header(bytes: &[u8]) -> Option<Header> {
    if bytes.is_empty() {
        None
    } else {
        Header::from_json(bytes).ok()
    }
}

fn structured(data: &[u8]) {
    let [signer, flags, tamper, fields @ ..] = data else {
        return;
    };
    let (alg, key) = SIGNERS[usize::from(*signer) % SIGNERS.len()].clone();
    let key: Jwk = fx::jwk(key);
    let detached = flags & 1 != 0;
    let json = flags & 2 != 0;
    let (protected, rest) = split0(fields);
    let (unprotected, payload) = split0(rest);

    let mut h = header(protected).unwrap_or_default();
    h.alg = Some(alg.as_str().into());
    let p = match ProtectedHeader::new(h) {
        Ok(p) => p,
        Err(e) => return check_err(&e),
    };
    let opts = SignOptions::new().detached(detached);
    let signed = if json {
        let mut s = Signer::new(&key).protected(p);
        if let Some(u) = header(unprotected) {
            s = s.unprotected(u);
        }
        jws::sign_flattened(&s, payload, &opts)
    } else {
        jws::sign_compact(&p, payload, &key, &opts)
    };
    let token = match signed {
        Ok(t) => t,
        Err(e) => return check_err(&e),
    };

    let allowed = [alg.clone()];
    let Ok(base) = VerifyOptions::new(&allowed) else {
        return;
    };
    let vopts = if detached {
        base.detached_payload(payload)
    } else {
        base
    };
    let verify = |t: &str| {
        if json {
            jws::verify_json(t, &key, &vopts)
        } else {
            jws::verify_compact(t, &key, &vopts)
        }
    };
    match verify(&token) {
        Ok(v) => {
            assert!(v.alg == alg);
            assert!(
                v.payload[..] == *payload,
                "verified payload differs from the signed one"
            );
        }
        Err(e) => panic!("a JWS the harness signed does not verify: {}", e.code()),
    }

    if !json && !token.is_empty() {
        let mut bytes = token.into_bytes();
        let i = usize::from(*tamper) * 131 % bytes.len();
        if bytes[i].is_ascii() {
            bytes[i] = if bytes[i] == b'A' { b'B' } else { b'A' };
            if let Ok(t) = core::str::from_utf8(&bytes) {
                assert!(
                    verify(t).is_err(),
                    "a JWS with one character changed verifies"
                );
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    match mode % 3 {
        0 => raw(false, rest),
        1 => raw(true, rest),
        _ => structured(rest),
    }
});
