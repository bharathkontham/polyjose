#![no_main]
//! JWT verification and claims validation (RFC 7519 §7.2, ADR 0027):
//! `Claims::from_json`, `jwt::verify` and `jwt::decrypt_nested`.
//!
//! Input: a mode byte, then
//! - mode 0: a clock byte (an index into `JWT_CLOCKS`), then a token, which
//!   is verified with one key, with a JWK Set, and decrypted as a nested
//!   JWT; the same bytes are also parsed as a Claims Set.
//! - mode 1: the JWS header JSON, a zero byte and the claims bytes; the
//!   harness signs them with its own HS256 key, so the fuzzer reaches every
//!   step after the signature (ADR 0036 §2, 3a).
//! - mode 2: the outer JWE header JSON, a zero byte, the inner JWS header
//!   JSON, a zero byte and the claims; both layers are made with the
//!   harness's own keys (RFC 7519 §5.2, §7.2 step 8).
//!
//! Ok ⇒ the ADR 0027 rules held under the default policy: `exp` present
//! and not past (RFC 7519 §4.1.4, 60 s leeway), `nbf` not ahead (§4.1.5),
//! no `aud` when the policy names no audience (§4.1.3), `typ` absent or
//! `JWT` (§5.1), no `cty: JWT` on a signed JWT (§5.2), no `b64: false`
//! (RFC 7797 §7), and the claims round-trip. Policy audience, issuer,
//! subject and `typ` requirements hold when set. Every failure has a stable
//! code.
use libfuzzer_sys::fuzz_target;
use polyjose::header::Header;
use polyjose::jwa::{ContentEncAlg as E, KeyMgmtAlg as A, SigningAlg as S};
use polyjose::jwe::{DecryptPolicy, Encryptor, Recipient};
use polyjose::jws::{ProtectedHeader, SignOptions, sign_compact};
use polyjose::jwt::{self, Claims, FixedClock, Keys, Policy, VerifiedJwt, VerifiedNestedJwt};
use polyjose::util::b64url_encode;
use polyjose_fuzz::{self as fx, check_err, split0};

const ALGS: &[S] = &[
    S::HS256,
    S::HS384,
    S::HS512,
    S::ES256,
    S::ES384,
    S::EdDSA,
    S::RS256,
    S::PS256,
];

fn lower_is(s: &str, names: &[&str]) -> bool {
    let l = s.to_ascii_lowercase();
    names.contains(&l.as_str())
}

/// The default-policy invariants of a verified JWT (ADR 0027).
fn check_ok(v: &VerifiedJwt, now: i64) {
    let h = &v.header;
    assert!(h.b64 != Some(false), "b64:false accepted");
    if let Some(cty) = &h.cty {
        assert!(
            !lower_is(cty, &["jwt", "application/jwt"]),
            "cty JWT accepted on a signed JWT"
        );
    }
    if let Some(typ) = &h.typ {
        assert!(
            lower_is(typ, &["jwt", "application/jwt"]),
            "typ accepted under the default policy"
        );
    }
    let Some(exp) = v.claims.exp else {
        panic!("missing exp accepted")
    };
    assert!(exp.as_f64() > (now - 60) as f64, "expired token accepted");
    if let Some(nbf) = v.claims.nbf {
        assert!(
            nbf.as_f64() <= (now + 60) as f64,
            "token not yet valid accepted"
        );
    }
    assert!(
        v.claims.aud.is_none(),
        "aud accepted with no audience in the policy"
    );
    check_claims_round_trip(&v.claims);
}

fn check_claims_round_trip(c: &Claims) {
    match Claims::from_json(c.to_json().as_bytes()) {
        Ok(again) => assert!(again == *c, "claims round trip changed the claims"),
        Err(e) => panic!("serialized claims do not re-parse: {}", e.code()),
    }
}

fn verified(r: polyjose::Result<VerifiedJwt>, now: i64) -> Option<VerifiedJwt> {
    match r {
        Ok(v) => {
            assert!(
                ALGS.contains(&v.alg),
                "verified an alg outside the allow-list"
            );
            check_ok(&v, now);
            Some(v)
        }
        Err(e) => {
            check_err(&e);
            None
        }
    }
}

fn nested(r: polyjose::Result<VerifiedNestedJwt>, now: i64) {
    match r {
        Ok(v) => {
            let Some(cty) = v.outer_header.cty.as_deref() else {
                panic!("nested JWT without cty")
            };
            assert!(
                lower_is(cty, &["jwt", "application/jwt"]),
                "nested JWT with cty {cty:?}"
            );
            if let Some(t) = v.outer_header.typ.as_deref() {
                assert!(
                    lower_is(t, &["jwt", "application/jwt"]),
                    "outer typ accepted"
                );
            }
            check_ok(&v.inner, now);
        }
        Err(e) => check_err(&e),
    }
}

fn raw(rest: &[u8]) {
    let Some((&c, token)) = rest.split_first() else {
        return;
    };
    let now = fx::JWT_CLOCKS[usize::from(c) % fx::JWT_CLOCKS.len()];
    match Claims::from_json(token) {
        Ok(claims) => check_claims_round_trip(&claims),
        Err(e) => check_err(&e),
    }
    let Ok(token) = core::str::from_utf8(token) else {
        return;
    };
    let clock = FixedClock(now);
    let Ok(policy) = Policy::new(&clock, ALGS) else {
        return;
    };
    let oct = fx::jwk(fx::JWT_OCT);
    let p256 = fx::jwk(fx::P256_A3_PUB);
    let set = fx::jwk_set(fx::JWT_SET);
    verified(jwt::verify(token, Keys::One(&oct), &policy), now);
    verified(jwt::verify(token, Keys::One(&p256), &policy), now);
    if let Some(v) = verified(jwt::verify(token, Keys::Set(&set), &policy), now) {
        assert!(
            v.key_index.is_some_and(|i| i < set.len()),
            "set verify without a key index"
        );
    }
    let kek = fx::jwk(fx::JWT_KEK);
    let Ok(dp) = DecryptPolicy::new(&[A::A128KW, A::Dir], E::KNOWN) else {
        return;
    };
    nested(
        jwt::decrypt_nested(token, &kek, &dp, Keys::One(&oct), &policy),
        now,
    );
}

fn sign(header: &[u8], claims: &[u8], key: &polyjose::jwk::Jwk) -> Option<String> {
    let p = ProtectedHeader::from_encoded(&b64url_encode(header)).ok()?;
    match sign_compact(&p, claims, key, &SignOptions::new()) {
        Ok(t) => Some(t),
        Err(e) => {
            check_err(&e);
            None
        }
    }
}

fn signed(rest: &[u8]) {
    let (header, claims) = split0(rest);
    let key = fx::jwk(fx::JWT_OCT);
    let Some(token) = sign(header, claims, &key) else {
        return;
    };
    let now = fx::JWT_CLOCKS[0];
    let clock = FixedClock(now);
    let algs = [S::HS256, S::HS384, S::HS512];
    let Ok(policy) = Policy::new(&clock, &algs) else {
        return;
    };
    verified(jwt::verify(&token, Keys::One(&key), &policy), now);
    let set = fx::jwk_set(fx::JWT_SET);
    verified(jwt::verify(&token, Keys::Set(&set), &policy), now);

    let Ok(p) = Policy::new(&clock, &algs) else {
        return;
    };
    let p = p.audience("api").issuer("i").subject("s");
    match jwt::verify(&token, Keys::One(&key), &p) {
        Ok(v) => {
            assert!(
                v.claims.iss.as_deref() == Some("i"),
                "issuer policy not enforced"
            );
            assert!(
                v.claims.sub.as_deref() == Some("s"),
                "subject policy not enforced"
            );
            let aud_ok = v
                .claims
                .aud
                .as_ref()
                .is_some_and(|a| a.values().iter().any(|x| x == "api"));
            assert!(aud_ok, "audience policy not enforced");
        }
        Err(e) => check_err(&e),
    }
    let Ok(p) = Policy::new(&clock, &algs) else {
        return;
    };
    let p = p.expect_typ("at+jwt");
    match jwt::verify(&token, Keys::One(&key), &p) {
        Ok(v) => {
            let Some(t) = v.header.typ.as_deref() else {
                panic!("expected typ missing")
            };
            assert!(
                lower_is(t, &["at+jwt", "application/at+jwt"]),
                "typ policy not enforced"
            );
        }
        Err(e) => check_err(&e),
    }
}

fn nested_structured(rest: &[u8]) {
    let (outer, rest) = split0(rest);
    let (inner, claims) = split0(rest);
    let Ok(outer) = Header::from_json(outer) else {
        return;
    };
    let key = fx::jwk(fx::JWT_OCT);
    let inner = match sign(inner, claims, &key) {
        Some(t) => t,
        None => String::from_utf8_lossy(claims).into_owned(),
    };
    let kek = fx::jwk(fx::JWT_KEK);
    let e = Encryptor::new(E::A128GCM)
        .recipient(Recipient::new(A::A128KW, &kek))
        .protected_header(outer);
    let token = match e.encrypt_compact(inner.as_bytes()) {
        Ok(t) => t,
        Err(e) => return check_err(&e),
    };
    let now = fx::JWT_CLOCKS[0];
    let clock = FixedClock(now);
    let algs = [S::HS256];
    let Ok(policy) = Policy::new(&clock, &algs) else {
        return;
    };
    let Ok(dp) = DecryptPolicy::new(&[A::A128KW], E::KNOWN) else {
        return;
    };
    nested(
        jwt::decrypt_nested(&token, &kek, &dp, Keys::One(&key), &policy),
        now,
    );
    // RFC 7519 §7.2: a JWE is never a valid signed JWT.
    assert!(
        jwt::verify(&token, Keys::One(&key), &policy).is_err(),
        "a JWE verified as a signed JWT"
    );
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    match mode % 3 {
        0 => raw(rest),
        1 => signed(rest),
        _ => nested_structured(rest),
    }
});
