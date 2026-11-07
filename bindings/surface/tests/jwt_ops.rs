//! The JWT operations of the binding surface (ADR 0030 §4, "JWT"; feature 0013 T09), with the
//! RFC 7519 §3.1 example, the RFC 7519 conformance vectors, and tokens the surface issues itself.
//!
//! Every expected value is a core decision reached through the surface: the leeway and its cap,
//! the `typ` modes, the key-candidate bound and the error order are the core's (ADR 0027,
//! ADR 0029), and this file checks that each `JwtVerifyOptions`/`JwtSignOptions` member reaches
//! exactly one core call, and `None`/`false` none (ADR 0030 §3–§4).

use std::time::{SystemTime, UNIX_EPOCH};

use polyjose::json::{self, Object, Value};
use polyjose::jwk::{EcCurve, Jwk};
use polyjose::keys::{KeySpec, generate};
use polyjose_surface::jwt::{
    jwt_decrypt_nested, jwt_decrypt_nested_with_jwks, jwt_encrypt_nested, jwt_sign, jwt_verify,
    jwt_verify_with_jwks,
};
use polyjose_surface::records::{
    JweDecryptOptions, JweEncryptOptions, JweRecipient, JwtSignOptions, JwtVerified,
    JwtVerifyOptions,
};
use polyjose_surface::{SecretString, SurfaceResult};

/// RFC 7515 Appendix A.1's HMAC key, the key of the RFC 7519 §3.1 example.
const OCT: &str = r#"{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}"#;
/// Another HMAC key, the decoy in front of [`OCT`] in a JWK Set (RFC 7515 Appendix A.1's key
/// with its first character changed).
const DECOY: &str = r#"{"kty":"oct","k":"ByM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}"#;
/// The RFC 7519 §3.1 example JWT (identical to RFC 7515 Appendix A.1's JWS).
const RFC7519_3_1: &str = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
/// The RFC 7519 §3.1 JWT Claims Set, as a JSON value.
const RFC7519_3_1_CLAIMS: &str =
    r#"{"iss":"joe","exp":1300819380,"http://example.com/is_root":true}"#;
/// The `exp` of the RFC 7519 §3.1 example.
const EXP: i64 = 1_300_819_380;
/// 60 s before [`EXP`]: the RFC 7519 §3.1 token is valid (conformance `3-1-hs256-before-exp`).
const BEFORE_EXP: i64 = 1_300_819_320;
/// An RSA private JWK: never imported, in a key or a set (ADR 0021, ADR 0029 §3).
const RSA_PRIVATE: &str = r#"{"kty":"RSA","n":"AQAB","e":"AQAB","d":"AQAB"}"#;
/// A distinctive value standing in for key material or claims (the core's marker style).
const MARKER: &str = "pj-SECRET-marker-7f3a";

// --- Helpers ------------------------------------------------------------------------------------

fn list(names: &[&str]) -> Vec<String> {
    names.iter().map(|s| (*s).to_owned()).collect()
}

fn parse(text: &str) -> Value {
    json::parse(text.as_bytes()).expect("test JSON")
}

/// A conformance vector's `input` (ADR 0034: the surface and the core read the same files).
fn vector_input(path: &str) -> Object {
    let file = format!("{}/../../conformance/vectors/{path}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&file).expect("vector file");
    parse(&text)
        .get("input")
        .and_then(Value::as_object)
        .expect("input object")
        .clone()
}

fn member_json(object: &Object, name: &str) -> String {
    object.get(name).expect("member").to_json()
}

fn member_str(object: &Object, name: &str) -> String {
    object
        .get(name)
        .and_then(Value::as_str)
        .expect("string member")
        .to_owned()
}

/// Verify options for `algs`, at the instant `now`.
fn at(now: i64, algs: &[&str]) -> JwtVerifyOptions {
    let mut options = JwtVerifyOptions::new(list(algs));
    options.now = Some(now);
    options
}

/// HS256 verify options at [`BEFORE_EXP`].
fn hs256() -> JwtVerifyOptions {
    at(BEFORE_EXP, &["HS256"])
}

fn code<T>(result: SurfaceResult<T>) -> &'static str {
    match result {
        Ok(_) => "ok",
        Err(e) => e.code(),
    }
}

fn message<T>(result: SurfaceResult<T>) -> String {
    match result {
        Ok(_) => "ok".to_owned(),
        Err(e) => e.message().to_owned(),
    }
}

/// Signs `claims` with HS256 and [`OCT`], `options` adjusted by `adjust`.
fn sign_with(claims: &str, adjust: impl FnOnce(&mut JwtSignOptions)) -> SurfaceResult<String> {
    let mut options = JwtSignOptions::new("HS256".to_owned());
    adjust(&mut options);
    jwt_sign(claims, OCT, &options)
}

fn sign(claims: &str) -> String {
    sign_with(claims, |_| {}).expect("signs")
}

/// The JWS Protected Header of a compact `token`, as a JSON value.
fn protected_header(token: &str) -> Value {
    let part = token.split('.').next().expect("a header part");
    let bytes = polyjose::util::b64url_decode(part).expect("base64url");
    json::parse(&bytes).expect("header JSON")
}

fn jwks(members: &[&str]) -> String {
    format!(r#"{{"keys":[{}]}}"#, members.join(","))
}

fn secret(json: &str) -> SecretString {
    SecretString::from(json.to_owned())
}

/// A fresh key pair as (private JWK, public JWK).
fn key_pair(spec: KeySpec) -> (String, String) {
    let private = generate(spec).expect("generates");
    let public = private.to_public().expect("has a public part");
    (
        private.to_json().as_str().to_owned(),
        public.to_json().as_str().to_owned(),
    )
}

/// Seconds since the epoch, read the way the test itself reads the time.
fn wall_clock() -> i64 {
    let since = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("after the epoch");
    i64::try_from(since.as_secs()).expect("fits")
}

// --- Verify (RFC 7519 §7.2) -----------------------------------------------------------------

#[test]
fn rfc7519_3_1_verifies_before_exp_with_its_exact_claims() {
    let verified: JwtVerified = jwt_verify(RFC7519_3_1, OCT, &hs256()).unwrap();
    assert_eq!(parse(&verified.claims), parse(RFC7519_3_1_CLAIMS));
    assert_eq!(verified.alg, "HS256");
    assert_eq!(parse(&verified.header), parse(r#"{"alg":"HS256","typ":"JWT"}"#));
    // ADR 0029 §4, 0004 implementer note 2: a single key has no index.
    assert_eq!(verified.key_index, None);
    assert_eq!(verified.kid, None);
}

#[test]
fn rfc7519_3_1_matches_its_conformance_vector() {
    let input = vector_input("jwt/rfc7519/3-1-hs256-before-exp.json");
    let mut options = at(input.get("now").and_then(Value::as_i64).unwrap(), &["HS256"]);
    options.allowed_algs = list(&["HS256"]);
    let verified = jwt_verify(
        &member_str(&input, "token"),
        &member_json(&input, "key"),
        &options,
    )
    .unwrap();
    assert_eq!(parse(&verified.claims), parse(RFC7519_3_1_CLAIMS));
}

#[test]
fn the_default_leeway_is_the_cores() {
    // RFC 7519 §4.1.4 with the core's default leeway: valid up to the last second before
    // exp + leeway, expired from there on (conformance 3-1-hs256-within-leeway, -past-leeway).
    assert_eq!(
        code(jwt_verify(RFC7519_3_1, OCT, &at(1_300_819_439, &["HS256"]))),
        "ok"
    );
    assert_eq!(
        code(jwt_verify(RFC7519_3_1, OCT, &at(1_300_819_440, &["HS256"]))),
        "TokenExpired"
    );
}

#[test]
fn leeway_zero_expires_at_exp() {
    let mut options = at(EXP, &["HS256"]);
    options.leeway = Some(0);
    assert_eq!(code(jwt_verify(RFC7519_3_1, OCT, &options)), "TokenExpired");
    options.now = Some(EXP - 1);
    assert_eq!(code(jwt_verify(RFC7519_3_1, OCT, &options)), "ok");
}

#[test]
fn a_leeway_over_the_core_cap_is_the_cores_invalid_claim() {
    let mut options = hs256();
    options.leeway = Some(601);
    let result = jwt_verify(RFC7519_3_1, OCT, &options);
    assert_eq!(message(result), "invalid claim: leeway");
    options.leeway = Some(600);
    assert_eq!(code(jwt_verify(RFC7519_3_1, OCT, &options)), "ok");
}

#[test]
fn the_policy_is_built_before_the_token_is_read() {
    // 0004 implementer note 7: a bad leeway and a malformed token report the leeway.
    let mut options = hs256();
    options.leeway = Some(601);
    for token in ["not-a-token", "a.b.c.d.e", "{}", ""] {
        assert_eq!(
            message(jwt_verify(token, OCT, &options)),
            "invalid claim: leeway",
            "{token:?}"
        );
        assert_eq!(
            message(jwt_verify_with_jwks(token, &jwks(&[OCT]), &options)),
            "invalid claim: leeway"
        );
    }
    // The allow-list comes first (conformance README, "Step order").
    options.allowed_algs = Vec::new();
    assert_eq!(
        code(jwt_verify("not-a-token", OCT, &options)),
        "AlgorithmNotAllowed"
    );
}

#[test]
fn the_key_is_imported_before_the_policy_is_built() {
    // Conformance README "Step order": import `key` or `jwks`, then build the policy.
    let mut options = hs256();
    options.leeway = Some(601);
    assert_eq!(
        code(jwt_verify(RFC7519_3_1, r#"{"kty":"oct"}"#, &options)),
        "InvalidKey"
    );
    assert_eq!(
        code(jwt_verify_with_jwks(RFC7519_3_1, "{}", &options)),
        "InvalidKey"
    );
}

#[test]
fn an_empty_or_none_allow_list_is_refused_by_the_core() {
    for algs in [&[][..], &["none"][..], &["NOPE"][..]] {
        let options = at(BEFORE_EXP, algs);
        assert_eq!(
            code(jwt_verify(RFC7519_3_1, OCT, &options)),
            "AlgorithmNotAllowed",
            "{algs:?}"
        );
        assert_eq!(
            code(jwt_verify_with_jwks(RFC7519_3_1, &jwks(&[OCT]), &options)),
            "AlgorithmNotAllowed"
        );
    }
}

#[test]
fn a_jwe_or_a_json_jws_is_not_a_signed_jwt() {
    // ADR 0027 §7: signed and nested JWTs have separate entry points.
    let (private, _) = key_pair(KeySpec::Oct { bytes: 16 });
    let nested = jwt_encrypt_nested(
        RFC7519_3_1,
        &JweEncryptOptions::new(
            "A128GCM".to_owned(),
            vec![JweRecipient::new("A128KW".to_owned(), secret(&private))],
        ),
    )
    .unwrap();
    assert_eq!(nested.split('.').count(), 5);
    assert_eq!(code(jwt_verify(&nested, OCT, &hs256())), "InvalidFormat");
    assert_eq!(
        code(jwt_verify_with_jwks(&nested, &jwks(&[OCT]), &hs256())),
        "InvalidFormat"
    );
    let [h, p, s] = <[&str; 3]>::try_from(RFC7519_3_1.split('.').collect::<Vec<_>>()).unwrap();
    let json_jws = format!(r#"{{"protected":"{h}","payload":"{p}","signature":"{s}"}}"#);
    assert_eq!(code(jwt_verify(&json_jws, OCT, &hs256())), "InvalidFormat");
}

#[test]
fn a_tampered_token_or_the_wrong_key_fails_the_signature() {
    let tampered = format!("{}A", &RFC7519_3_1[..RFC7519_3_1.len() - 1]);
    assert_eq!(code(jwt_verify(&tampered, OCT, &hs256())), "InvalidSignature");
    assert_eq!(
        code(jwt_verify(RFC7519_3_1, DECOY, &hs256())),
        "InvalidSignature"
    );
    assert_eq!(
        code(jwt_verify(RFC7519_3_1, RSA_PRIVATE, &hs256())),
        "UnsupportedAlgorithm"
    );
}

// --- JWK Sets (ADR 0029) ----------------------------------------------------------------------

#[test]
fn a_kid_less_token_tries_the_set_in_order_and_reports_the_index() {
    let set = jwks(&[DECOY, OCT]);
    let verified = jwt_verify_with_jwks(RFC7519_3_1, &set, &hs256()).unwrap();
    assert_eq!(verified.key_index, Some(1));
    assert_eq!(verified.kid, None);
    assert_eq!(parse(&verified.claims), parse(RFC7519_3_1_CLAIMS));

    // 0004 implementer note 2: the first member is index 0, a value, not "absent".
    let first = jwt_verify_with_jwks(RFC7519_3_1, &jwks(&[OCT, DECOY]), &hs256()).unwrap();
    assert_eq!(first.key_index, Some(0));
}

#[test]
fn the_verifying_members_kid_is_reported() {
    let with_kid = OCT.replace(r#""kty""#, r#""kid":"k2","kty""#);
    let verified =
        jwt_verify_with_jwks(RFC7519_3_1, &jwks(&[DECOY, &with_kid]), &hs256()).unwrap();
    assert_eq!(verified.key_index, Some(1));
    assert_eq!(verified.kid.as_deref(), Some("k2"));
    // A single key reports its own kid, never the header's (ADR 0029 §1).
    let single = jwt_verify(RFC7519_3_1, &with_kid, &hs256()).unwrap();
    assert_eq!((single.key_index, single.kid.as_deref()), (None, Some("k2")));
}

#[test]
fn rs256_verifies_through_a_set_and_a_key() {
    // RFC 7519 Appendix A.2 / RFC 7515 Appendix A.2, the conformance vectors' own inputs.
    let input = vector_input("jwt/rfc7519/a2-rs256-jwks-second.json");
    let token = member_str(&input, "token");
    let options = at(BEFORE_EXP, &["RS256"]);
    let verified = jwt_verify_with_jwks(&token, &member_json(&input, "jwks"), &options).unwrap();
    assert_eq!(verified.alg, "RS256");
    assert_eq!(verified.key_index, Some(1));
    assert_eq!(parse(&verified.claims), parse(RFC7519_3_1_CLAIMS));

    let input = vector_input("jwt/rfc7519/a2-rs256-key.json");
    let verified = jwt_verify(&token, &member_json(&input, "key"), &options).unwrap();
    assert_eq!((verified.alg.as_str(), verified.key_index), ("RS256", None));
}

#[test]
fn a_set_without_a_candidate_is_no_matching_key() {
    let (_, ec_public) = key_pair(KeySpec::Ec(EcCurve::P256));
    for set in [jwks(&[]), jwks(&[&ec_public])] {
        assert_eq!(
            code(jwt_verify_with_jwks(RFC7519_3_1, &set, &hs256())),
            "NoMatchingKey"
        );
    }
}

#[test]
fn a_set_holding_an_rsa_private_jwk_is_unsupported() {
    // ADR 0021, ADR 0029 §3: the whole set fails at import.
    assert_eq!(
        code(jwt_verify_with_jwks(
            RFC7519_3_1,
            &jwks(&[OCT, RSA_PRIVATE]),
            &hs256()
        )),
        "UnsupportedAlgorithm"
    );
}

#[test]
fn max_key_candidates_reaches_the_core() {
    let set = jwks(&[DECOY, OCT]);
    let mut options = hs256();
    options.max_key_candidates = Some(1);
    assert_eq!(
        code(jwt_verify_with_jwks(RFC7519_3_1, &set, &options)),
        "NoMatchingKey"
    );
    options.max_key_candidates = Some(0);
    assert_eq!(
        code(jwt_verify_with_jwks(RFC7519_3_1, &jwks(&[OCT]), &options)),
        "NoMatchingKey"
    );
    // A single key is not a set (ADR 0029 §4).
    assert_eq!(code(jwt_verify(RFC7519_3_1, OCT, &options)), "ok");
    options.max_key_candidates = Some(2);
    assert_eq!(
        code(jwt_verify_with_jwks(RFC7519_3_1, &set, &options)),
        "ok"
    );
}

// --- Policy mapping (ADR 0030 §4: one member, one core call) ---------------------------------

#[test]
fn issuers_and_subject_reach_the_core() {
    let token = sign(r#"{"iss":"joe","sub":"alice","exp":1300819380}"#);
    let mut options = hs256();
    options.issuers = Some(list(&["bob", "joe"]));
    assert_eq!(code(jwt_verify(&token, OCT, &options)), "ok");
    options.issuers = Some(list(&["bob"]));
    assert_eq!(message(jwt_verify(&token, OCT, &options)), "invalid claim: iss");

    let mut options = hs256();
    options.subject = Some("alice".to_owned());
    assert_eq!(code(jwt_verify(&token, OCT, &options)), "ok");
    options.subject = Some("Alice".to_owned());
    assert_eq!(message(jwt_verify(&token, OCT, &options)), "invalid claim: sub");
}

#[test]
fn audiences_and_ignore_audience_reach_the_core() {
    let token = sign(r#"{"aud":["api","web"],"exp":1300819380}"#);
    // The core default: a token with aud and no audience configured is rejected.
    assert_eq!(message(jwt_verify(&token, OCT, &hs256())), "invalid claim: aud");

    let mut options = hs256();
    options.audiences = Some(list(&["web"]));
    assert_eq!(code(jwt_verify(&token, OCT, &options)), "ok");
    options.audiences = Some(list(&["other"]));
    assert_eq!(message(jwt_verify(&token, OCT, &options)), "invalid claim: aud");

    let mut options = hs256();
    options.ignore_audience = true;
    assert_eq!(code(jwt_verify(&token, OCT, &options)), "ok");
}

#[test]
fn max_age_reaches_the_core() {
    let token = sign(r#"{"iat":1300819220,"exp":1300819380}"#);
    let mut options = hs256();
    options.leeway = Some(0);
    options.max_age = Some(100);
    assert_eq!(code(jwt_verify(&token, OCT, &options)), "ok");
    options.max_age = Some(99);
    assert_eq!(message(jwt_verify(&token, OCT, &options)), "invalid claim: iat");
}

#[test]
fn required_claims_reach_the_core_in_order() {
    let mut options = hs256();
    options.required_claims = Some(list(&["iss"]));
    assert_eq!(code(jwt_verify(RFC7519_3_1, OCT, &options)), "ok");
    options.required_claims = Some(list(&["jti"]));
    assert_eq!(
        message(jwt_verify(RFC7519_3_1, OCT, &options)),
        "invalid claim: jti"
    );
    // ADR 0027 §9 J4: other names are checked in the order given; the core names client_id
    // and reports any other name as "required".
    options.required_claims = Some(list(&["client_id", "x-tenant"]));
    assert_eq!(
        message(jwt_verify(RFC7519_3_1, OCT, &options)),
        "invalid claim: client_id"
    );
    options.required_claims = Some(list(&["x-tenant", "client_id"]));
    assert_eq!(
        message(jwt_verify(RFC7519_3_1, OCT, &options)),
        "invalid claim: required"
    );
}

#[test]
fn allow_missing_exp_reaches_the_core() {
    let token = sign(r#"{"iss":"joe"}"#);
    assert_eq!(message(jwt_verify(&token, OCT, &hs256())), "invalid claim: exp");
    let mut options = hs256();
    options.allow_missing_exp = true;
    assert_eq!(code(jwt_verify(&token, OCT, &options)), "ok");
}

#[test]
fn typ_and_any_typ_reach_the_core() {
    let typed = sign_with(r#"{"exp":1300819380}"#, |o| {
        o.typ = Some("secevent+jwt".to_owned());
    })
    .unwrap();
    // The core default typ mode: absent or JWT only (RFC 8725 §3.11-§3.12).
    assert_eq!(code(jwt_verify(&typed, OCT, &hs256())), "InvalidHeader");

    let mut options = hs256();
    options.typ = Some("secevent+jwt".to_owned());
    assert_eq!(code(jwt_verify(&typed, OCT, &options)), "ok");
    assert_eq!(code(jwt_verify(RFC7519_3_1, OCT, &options)), "InvalidHeader");

    let mut options = hs256();
    options.any_typ = true;
    assert_eq!(code(jwt_verify(&typed, OCT, &options)), "ok");
    assert_eq!(code(jwt_verify(RFC7519_3_1, OCT, &options)), "ok");
}

#[test]
fn typ_together_with_any_typ_is_invalid_header() {
    let mut options = hs256();
    options.typ = Some("JWT".to_owned());
    options.any_typ = true;
    assert_eq!(code(jwt_verify(RFC7519_3_1, OCT, &options)), "InvalidHeader");
    assert_eq!(
        code(jwt_verify_with_jwks(RFC7519_3_1, &jwks(&[OCT]), &options)),
        "InvalidHeader"
    );
    // Like every option, before the token is read.
    assert_eq!(code(jwt_verify("x", OCT, &options)), "InvalidHeader");
}

#[test]
fn max_input_len_reaches_the_core() {
    let mut options = hs256();
    options.max_input_len = Some(16);
    assert_eq!(code(jwt_verify(RFC7519_3_1, OCT, &options)), "InvalidFormat");
    options.max_input_len = Some(u32::try_from(RFC7519_3_1.len()).unwrap());
    assert_eq!(code(jwt_verify(RFC7519_3_1, OCT, &options)), "ok");
}

#[test]
fn false_flags_call_nothing() {
    // 0004 implementer note 6: false keeps the core default, never an opt-out.
    let mut options = hs256();
    options.allow_missing_exp = false;
    options.ignore_audience = false;
    options.any_typ = false;
    let no_exp = sign(r#"{"iss":"joe"}"#);
    assert_eq!(message(jwt_verify(&no_exp, OCT, &options)), "invalid claim: exp");
    let with_aud = sign(r#"{"aud":"api","exp":1300819380}"#);
    assert_eq!(message(jwt_verify(&with_aud, OCT, &options)), "invalid claim: aud");
    let typed = sign_with(r#"{"exp":1300819380}"#, |o| o.typ = Some("x+jwt".to_owned())).unwrap();
    assert_eq!(code(jwt_verify(&typed, OCT, &options)), "InvalidHeader");
}

#[test]
fn an_unknown_profile_is_unsupported() {
    let mut options = hs256();
    options.profile = Some("id_token".to_owned());
    assert_eq!(
        code(jwt_verify(RFC7519_3_1, OCT, &options)),
        "UnsupportedAlgorithm"
    );
    options.profile = Some("ACCESS_TOKEN".to_owned());
    assert_eq!(
        code(jwt_verify(RFC7519_3_1, OCT, &options)),
        "UnsupportedAlgorithm"
    );
    // The allow-list is still checked first.
    options.allowed_algs = Vec::new();
    assert_eq!(
        code(jwt_verify(RFC7519_3_1, OCT, &options)),
        "AlgorithmNotAllowed"
    );
}

// --- The access-token profile (RFC 9068 §4, ADR 0052) -----------------------------------------

/// An RFC 9068 §2.2 Claims Set with `client_id` set to the JSON text `client_id`.
fn access_claims(client_id: &str) -> String {
    format!(
        r#"{{"iss":"https://as.example","sub":"alice","aud":"https://api.example","exp":1300819380,"iat":1300819300,"jti":"j1","client_id":{client_id}}}"#
    )
}

fn access_token(client_id: &str) -> String {
    sign_with(&access_claims(client_id), |o| o.access_token = true).unwrap()
}

fn access_options() -> JwtVerifyOptions {
    let mut options = hs256();
    options.profile = Some("access_token".to_owned());
    options.issuers = Some(list(&["https://as.example"]));
    options.audiences = Some(list(&["https://api.example"]));
    options
}

#[test]
fn the_access_token_profile_accepts_an_rfc9068_token() {
    let token = access_token(r#""s6BhdRkqt3""#);
    assert_eq!(protected_header(&token).get("typ").and_then(Value::as_str), Some("at+jwt"));
    let verified = jwt_verify(&token, OCT, &access_options()).unwrap();
    assert_eq!(parse(&verified.claims), parse(&access_claims(r#""s6BhdRkqt3""#)));
    // RFC 6749 §2.2 sets no minimum length (ADR 0052 §1).
    assert_eq!(code(jwt_verify(&access_token(r#""""#), OCT, &access_options())), "ok");
}

#[test]
fn the_access_token_profile_requires_at_jwt_issuers_and_audiences() {
    // A generic JWT typ is not at+jwt (RFC 9068 §4).
    let generic = sign(&access_claims(r#""c""#));
    assert_eq!(code(jwt_verify(&generic, OCT, &access_options())), "InvalidHeader");

    let token = access_token(r#""c""#);
    let mut options = access_options();
    options.issuers = None;
    assert_eq!(message(jwt_verify(&token, OCT, &options)), "invalid claim: iss");
    let mut options = access_options();
    options.audiences = None;
    assert_eq!(message(jwt_verify(&token, OCT, &options)), "invalid claim: aud");
    let mut options = access_options();
    options.issuers = Some(list(&["https://other.example"]));
    assert_eq!(message(jwt_verify(&token, OCT, &options)), "invalid claim: iss");
}

#[test]
fn the_access_token_profile_requires_a_string_client_id_with_no_opt_out() {
    // ADR 0052 §1, §4; 0004 F06 at the surface level.
    for client_id in ["null", "1", "true", "[]", "{}"] {
        let token = access_token(client_id);
        let mut options = access_options();
        assert_eq!(
            message(jwt_verify(&token, OCT, &options)),
            "invalid claim: client_id",
            "{client_id}"
        );
        options.ignore_audience = true;
        options.required_claims = Some(list(&["client_id"]));
        options.any_typ = true;
        options.allow_missing_exp = true;
        assert_eq!(
            message(jwt_verify(&token, OCT, &options)),
            "invalid claim: client_id",
            "{client_id}, with every opt-out"
        );
        assert_eq!(
            message(jwt_verify_with_jwks(&token, &jwks(&[OCT]), &options)),
            "invalid claim: client_id"
        );
    }
    // Without the profile, a required client_id may be any JSON value (ADR 0052 §3).
    let mut options = hs256();
    options.typ = Some("at+jwt".to_owned());
    options.audiences = Some(list(&["https://api.example"]));
    options.required_claims = Some(list(&["client_id"]));
    assert_eq!(code(jwt_verify(&access_token("null"), OCT, &options)), "ok");
}

#[test]
fn the_access_token_profile_still_lets_typ_override_at_jwt() {
    // Conformance README, "The JWT policy": a typ member overrides the profile's at+jwt.
    let token = sign(&access_claims(r#""c""#));
    let mut options = access_options();
    options.any_typ = true;
    assert_eq!(code(jwt_verify(&token, OCT, &options)), "ok");
}

// --- The clock (ADR 0030 §4, ADR 0028) -------------------------------------------------------

#[test]
fn an_explicit_now_is_a_fixed_clock() {
    // The same token, the same verdict, whatever the day (ADR 0028 §2).
    for _ in 0..2 {
        assert_eq!(code(jwt_verify(RFC7519_3_1, OCT, &hs256())), "ok");
    }
    // Outside the NumericDate range the core's clock check fails (ADR 0028 §1).
    assert_eq!(
        message(jwt_verify(RFC7519_3_1, OCT, &at(i64::MAX, &["HS256"]))),
        "invalid claim: clock"
    );
}

#[test]
fn a_missing_now_reads_the_system_clock() {
    let mut options = JwtVerifyOptions::new(list(&["HS256"]));
    options.leeway = Some(0);
    assert_eq!(options.now, None);

    // The RFC 7519 §3.1 example expired in 2011.
    assert_eq!(code(jwt_verify(RFC7519_3_1, OCT, &options)), "TokenExpired");

    // Lower bound: the clock read is at or after the test's own first read, so exp = t0 has
    // passed (RFC 7519 §4.1.4) and nbf = t0 has arrived (RFC 7519 §4.1.5).
    let t0 = wall_clock();
    let expired = sign(&format!(r#"{{"exp":{t0}}}"#));
    let started = sign(&format!(r#"{{"nbf":{t0},"exp":{}}}"#, t0 + 86_400));
    assert_eq!(code(jwt_verify(&expired, OCT, &options)), "TokenExpired");
    assert_eq!(code(jwt_verify(&started, OCT, &options)), "ok");

    // Upper bound: `iat` = t0 with `max_age` m accepts exactly now in [t0, t0 + m]. The
    // verdict is compared with the window the test reads afterwards, so no fixed duration is
    // assumed (pipeline rule 8).
    let issued = sign(&format!(r#"{{"iat":{t0},"exp":{}}}"#, t0 + 86_400));
    options.max_age = Some(1);
    let verdict = code(jwt_verify(&issued, OCT, &options));
    let t1 = wall_clock();
    if t1 <= t0 + 1 {
        assert_eq!(verdict, "ok", "the surface's time is within [{t0}, {t1}]");
    }
}

// --- Sign (RFC 7519 §7.1) --------------------------------------------------------------------

#[test]
fn hs256_sign_round_trips_the_rfc7519_3_1_claims() {
    let token = sign(RFC7519_3_1_CLAIMS);
    assert_eq!(token.split('.').count(), 3);
    let verified = jwt_verify(&token, OCT, &hs256()).unwrap();
    assert_eq!(parse(&verified.claims), parse(RFC7519_3_1_CLAIMS));
    assert_eq!(verified.alg, "HS256");
}

#[test]
fn rfc7519_3_1_issue_matches_its_conformance_vector() {
    // 3-1-hs256-issue-exact: `typ: null` is `omit_typ` (0004 implementer note 3).
    let file = format!(
        "{}/../../conformance/vectors/jwt/rfc7519/3-1-hs256-issue-exact.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let vector = parse(&std::fs::read_to_string(file).unwrap());
    let input = vector.get("input").and_then(Value::as_object).unwrap();
    let expected = vector
        .get("expect")
        .and_then(|e| e.get("token"))
        .and_then(Value::as_str)
        .unwrap();
    let mut options = JwtSignOptions::new(member_str(input, "alg"));
    options.omit_typ = input.get("typ").is_some_and(Value::is_null);
    let token = jwt_sign(
        &member_json(input, "claims"),
        &member_json(input, "key"),
        &options,
    )
    .unwrap();
    assert_eq!(token, expected);
}

#[test]
fn typ_defaults_to_the_cores_jwt() {
    let header = protected_header(&sign(RFC7519_3_1_CLAIMS));
    assert_eq!(header, parse(r#"{"alg":"HS256","typ":"JWT"}"#));
}

#[test]
fn omit_typ_access_token_and_typ_set_the_header() {
    let none = sign_with(RFC7519_3_1_CLAIMS, |o| o.omit_typ = true).unwrap();
    assert_eq!(protected_header(&none), parse(r#"{"alg":"HS256"}"#));
    let at = sign_with(RFC7519_3_1_CLAIMS, |o| o.access_token = true).unwrap();
    assert_eq!(protected_header(&at), parse(r#"{"alg":"HS256","typ":"at+jwt"}"#));
    let custom = sign_with(RFC7519_3_1_CLAIMS, |o| o.typ = Some("secevent+jwt".to_owned()))
        .unwrap();
    assert_eq!(
        protected_header(&custom),
        parse(r#"{"alg":"HS256","typ":"secevent+jwt"}"#)
    );
}

#[test]
fn typ_together_with_omit_typ_or_access_token_is_invalid_header() {
    for (omit_typ, access_token) in [(true, false), (false, true), (true, true)] {
        let result = sign_with(RFC7519_3_1_CLAIMS, |o| {
            o.typ = Some("JWT".to_owned());
            o.omit_typ = omit_typ;
            o.access_token = access_token;
        });
        assert_eq!(code(result), "InvalidHeader", "{omit_typ} {access_token}");
    }
    // omit_typ and access_token contradict each other the same way.
    let result = sign_with(RFC7519_3_1_CLAIMS, |o| {
        o.omit_typ = true;
        o.access_token = true;
    });
    assert_eq!(code(result), "InvalidHeader");
}

#[test]
fn header_members_go_through_the_cores_header_param() {
    let token = sign_with(RFC7519_3_1_CLAIMS, |o| {
        o.header = Some(r#"{"x-tenant":"a","jku":"https://example.com/jwks"}"#.to_owned());
    })
    .unwrap();
    let header = protected_header(&token);
    assert_eq!(
        header,
        parse(r#"{"alg":"HS256","typ":"JWT","x-tenant":"a","jku":"https://example.com/jwks"}"#)
    );
    // The caller's member order is kept (RFC 7515 §4, the core's header_param order).
    assert!(token.starts_with(&polyjose::util::b64url_encode(
        br#"{"alg":"HS256","typ":"JWT","x-tenant":"a","jku":"https://example.com/jwks"}"#
    )));

    // RFC 7797 §7, RFC 7515 §4.1.11, RFC 7519 §5.2, and the members the core owns.
    for header in [
        r#"{"b64":false}"#,
        r#"{"crit":["exp"]}"#,
        r#"{"cty":"JWT"}"#,
        r#"{"alg":"none"}"#,
        r#"{"typ":"JWT"}"#,
        r#"{"kid":"k"}"#,
        r#"{"jku":1}"#,
    ] {
        let result = sign_with(RFC7519_3_1_CLAIMS, |o| o.header = Some(header.to_owned()));
        assert_eq!(code(result), "InvalidHeader", "{header}");
    }
    for header in ["[]", "1", "not json", r#"{"a":1,"a":2}"#] {
        let result = sign_with(RFC7519_3_1_CLAIMS, |o| o.header = Some(header.to_owned()));
        assert_eq!(code(result), "InvalidJson", "{header}");
    }
}

#[test]
fn rsa_signing_is_unsupported_and_none_is_not_allowed() {
    // ADR 0021: no RSA private-key operations, whatever the key.
    let input = vector_input("jwt/rfc7519/a2-rs256-key.json");
    let rsa_public = member_json(&input, "key");
    for alg in ["RS256", "PS256"] {
        let options = JwtSignOptions::new(alg.to_owned());
        assert_eq!(
            code(jwt_sign(RFC7519_3_1_CLAIMS, OCT, &options)),
            "UnsupportedAlgorithm"
        );
        assert_eq!(
            code(jwt_sign(RFC7519_3_1_CLAIMS, &rsa_public, &options)),
            "UnsupportedAlgorithm"
        );
    }
    assert_eq!(
        code(jwt_sign(RFC7519_3_1_CLAIMS, RSA_PRIVATE, &JwtSignOptions::new("HS256".to_owned()))),
        "UnsupportedAlgorithm"
    );
    assert_eq!(
        code(jwt_sign(RFC7519_3_1_CLAIMS, OCT, &JwtSignOptions::new("none".to_owned()))),
        "AlgorithmNotAllowed"
    );
}

#[test]
fn bad_claims_and_keys_are_the_cores_errors() {
    let options = JwtSignOptions::new("HS256".to_owned());
    assert_eq!(code(jwt_sign("[]", OCT, &options)), "InvalidJson");
    assert_eq!(code(jwt_sign("{", OCT, &options)), "InvalidJson");
    assert_eq!(code(jwt_sign(r#"{"exp":"soon"}"#, OCT, &options)), "InvalidClaim");
    assert_eq!(code(jwt_sign("{}", r#"{"kty":"oct"}"#, &options)), "InvalidKey");
    // Conformance README "Step order": the key is imported before the claims are parsed.
    assert_eq!(code(jwt_sign("[]", r#"{"kty":"oct"}"#, &options)), "InvalidKey");
    let (_, ec_public) = key_pair(KeySpec::Ec(EcCurve::P256));
    let es256 = JwtSignOptions::new("ES256".to_owned());
    assert_ne!(code(jwt_sign("{}", &ec_public, &es256)), "ok");
}

#[test]
fn es256_and_eddsa_sign_round_trip() {
    let (private, public) = key_pair(KeySpec::Ec(EcCurve::P256));
    let token = jwt_sign(
        RFC7519_3_1_CLAIMS,
        &private,
        &JwtSignOptions::new("ES256".to_owned()),
    )
    .unwrap();
    let verified = jwt_verify(&token, &public, &at(BEFORE_EXP, &["ES256"])).unwrap();
    assert_eq!(parse(&verified.claims), parse(RFC7519_3_1_CLAIMS));
}

// --- Nested JWTs (RFC 7519 §5.2, §11.2; ADR 0027 §7) -----------------------------------------

/// Encrypts the RFC 7519 §3.1 JWT to `recipient_key` with `alg` and `enc`, then decrypts and
/// verifies it with `decrypt_key`, through one key and through a set.
fn nested_round_trip(alg: &str, enc: &str, recipient_key: &str, decrypt_key: &str) {
    let nested = jwt_encrypt_nested(
        RFC7519_3_1,
        &JweEncryptOptions::new(
            enc.to_owned(),
            vec![JweRecipient::new(alg.to_owned(), secret(recipient_key))],
        ),
    )
    .unwrap();
    assert_eq!(nested.split('.').count(), 5);
    let decrypt = JweDecryptOptions::new(list(&[alg]), list(&[enc]));

    let verified = jwt_decrypt_nested(&nested, decrypt_key, &decrypt, OCT, &hs256()).unwrap();
    let outer = parse(&verified.outer_header);
    assert_eq!(outer.get("cty").and_then(Value::as_str), Some("JWT"));
    assert_eq!(outer.get("alg").and_then(Value::as_str), Some(alg));
    assert_eq!(outer.get("enc").and_then(Value::as_str), Some(enc));
    assert_eq!(verified.recipient_index, 0);
    assert_eq!(verified.inner.alg, "HS256");
    assert_eq!(verified.inner.key_index, None);
    assert_eq!(parse(&verified.inner.claims), parse(RFC7519_3_1_CLAIMS));

    let by_set = jwt_decrypt_nested_with_jwks(
        &nested,
        decrypt_key,
        &decrypt,
        &jwks(&[DECOY, OCT]),
        &hs256(),
    )
    .unwrap();
    assert_eq!(by_set.inner.key_index, Some(1));
    assert_eq!(by_set.recipient_index, 0);
}

#[test]
fn ecdh_es_a256gcm_round_trips() {
    let (private, public) = key_pair(KeySpec::Ec(EcCurve::P256));
    nested_round_trip("ECDH-ES", "A256GCM", &public, &private);
}

#[test]
fn a128kw_a128cbc_hs256_round_trips() {
    let (key, _) = key_pair(KeySpec::Oct { bytes: 16 });
    nested_round_trip("A128KW", "A128CBC-HS256", &key, &key);
}

fn a128kw_nested() -> (String, String) {
    let (key, _) = key_pair(KeySpec::Oct { bytes: 16 });
    let nested = jwt_encrypt_nested(
        RFC7519_3_1,
        &JweEncryptOptions::new(
            "A128GCM".to_owned(),
            vec![JweRecipient::new("A128KW".to_owned(), secret(&key))],
        ),
    )
    .unwrap();
    (key, nested)
}

fn a128kw_decrypt() -> JweDecryptOptions {
    JweDecryptOptions::new(list(&["A128KW"]), list(&["A128GCM"]))
}

#[test]
fn a_signed_jwt_is_not_a_nested_jwt() {
    let (key, _) = key_pair(KeySpec::Oct { bytes: 16 });
    let decrypt = a128kw_decrypt();
    assert_eq!(
        code(jwt_decrypt_nested(RFC7519_3_1, &key, &decrypt, OCT, &hs256())),
        "InvalidFormat"
    );
    assert_eq!(
        code(jwt_decrypt_nested_with_jwks(
            RFC7519_3_1,
            &key,
            &decrypt,
            &jwks(&[OCT]),
            &hs256()
        )),
        "InvalidFormat"
    );
}

#[test]
fn the_nested_policies_reach_the_core() {
    let (key, nested) = a128kw_nested();
    // The JWE allow-lists (RFC 8725 §3.1).
    let empty = JweDecryptOptions::new(Vec::new(), list(&["A128GCM"]));
    assert_eq!(
        code(jwt_decrypt_nested(&nested, &key, &empty, OCT, &hs256())),
        "AlgorithmNotAllowed"
    );
    let other = JweDecryptOptions::new(list(&["A256KW"]), list(&["A128GCM"]));
    assert_eq!(
        code(jwt_decrypt_nested(&nested, &key, &other, OCT, &hs256())),
        "AlgorithmNotAllowed"
    );
    // Every tunable of JweDecryptOptions reaches the core.
    let mut bounded = a128kw_decrypt();
    bounded.max_input_len = Some(16);
    assert_eq!(
        code(jwt_decrypt_nested(&nested, &key, &bounded, OCT, &hs256())),
        "InvalidFormat"
    );
    let mut tuned = a128kw_decrypt();
    tuned.max_pbes2_count = Some(1000);
    tuned.max_decompressed_len = Some(1024);
    tuned.max_recipients = Some(1);
    tuned.understood_crit = Some(list(&["x-ext"]));
    assert_eq!(
        code(jwt_decrypt_nested(&nested, &key, &tuned, OCT, &hs256())),
        "ok"
    );
    // The inner JWT policy: expired, and the inner allow-list.
    assert_eq!(
        code(jwt_decrypt_nested(
            &nested,
            &key,
            &a128kw_decrypt(),
            OCT,
            &at(1_300_819_440, &["HS256"])
        )),
        "TokenExpired"
    );
    assert_eq!(
        code(jwt_decrypt_nested(
            &nested,
            &key,
            &a128kw_decrypt(),
            OCT,
            &at(BEFORE_EXP, &[])
        )),
        "AlgorithmNotAllowed"
    );
    // The wrong key-encryption key.
    let (wrong, _) = key_pair(KeySpec::Oct { bytes: 16 });
    assert_eq!(
        code(jwt_decrypt_nested(&nested, &wrong, &a128kw_decrypt(), OCT, &hs256())),
        "DecryptionFailed"
    );
}

#[test]
fn nested_inputs_are_read_in_the_conformance_order() {
    // Conformance README "Step order": decrypt key, decrypt policy, key or jwks, then the JWT
    // policy, then the token.
    let (key, nested) = a128kw_nested();
    let mut options = hs256();
    options.leeway = Some(601);
    let empty = JweDecryptOptions::new(Vec::new(), list(&["A128GCM"]));
    assert_eq!(
        code(jwt_decrypt_nested(&nested, r#"{"kty":"oct"}"#, &empty, "{}", &options)),
        "InvalidKey"
    );
    assert_eq!(
        code(jwt_decrypt_nested(&nested, &key, &empty, "{}", &options)),
        "AlgorithmNotAllowed"
    );
    assert_eq!(
        code(jwt_decrypt_nested(&nested, &key, &a128kw_decrypt(), "{}", &options)),
        "InvalidKey"
    );
    assert_eq!(
        code(jwt_decrypt_nested_with_jwks(&nested, &key, &a128kw_decrypt(), "{}", &options)),
        "InvalidKey"
    );
    assert_eq!(
        message(jwt_decrypt_nested("garbage", &key, &a128kw_decrypt(), OCT, &options)),
        "invalid claim: leeway"
    );
    assert_eq!(
        message(jwt_decrypt_nested_with_jwks(
            "garbage",
            &key,
            &a128kw_decrypt(),
            &jwks(&[OCT]),
            &options
        )),
        "invalid claim: leeway"
    );
}

#[test]
fn encrypt_nested_options_reach_the_core() {
    let (key, _) = key_pair(KeySpec::Oct { bytes: 16 });
    let recipient = || JweRecipient::new("A128KW".to_owned(), secret(&key));

    // The caller's protected header is kept, plus cty JWT (RFC 7519 §5.2).
    let mut options = JweEncryptOptions::new("A128GCM".to_owned(), vec![recipient()]);
    options.protected_header = Some(r#"{"kid":"kek-1"}"#.to_owned());
    let nested = jwt_encrypt_nested(RFC7519_3_1, &options).unwrap();
    let verified =
        jwt_decrypt_nested(&nested, &key, &a128kw_decrypt(), OCT, &hs256()).unwrap();
    let outer = parse(&verified.outer_header);
    assert_eq!(outer.get("kid").and_then(Value::as_str), Some("kek-1"));
    assert_eq!(outer.get("cty").and_then(Value::as_str), Some("JWT"));

    // A caller cty other than JWT, and compression (RFC 8725 §3.6), are refused by the core.
    let mut options = JweEncryptOptions::new("A128GCM".to_owned(), vec![recipient()]);
    options.protected_header = Some(r#"{"cty":"json"}"#.to_owned());
    assert_eq!(code(jwt_encrypt_nested(RFC7519_3_1, &options)), "InvalidHeader");
    let mut options = JweEncryptOptions::new("A128GCM".to_owned(), vec![recipient()]);
    options.compress = true;
    assert_eq!(code(jwt_encrypt_nested(RFC7519_3_1, &options)), "InvalidHeader");

    // Compact output: exactly one recipient, no unprotected header and no AAD (RFC 7516 §7.1).
    let two = JweEncryptOptions::new("A128GCM".to_owned(), vec![recipient(), recipient()]);
    assert_eq!(code(jwt_encrypt_nested(RFC7519_3_1, &two)), "InvalidFormat");
    let none = JweEncryptOptions::new("A128GCM".to_owned(), Vec::new());
    assert_eq!(code(jwt_encrypt_nested(RFC7519_3_1, &none)), "InvalidFormat");
    let mut shared = JweEncryptOptions::new("A128GCM".to_owned(), vec![recipient()]);
    shared.shared_unprotected_header = Some(r#"{"x":1}"#.to_owned());
    assert_eq!(code(jwt_encrypt_nested(RFC7519_3_1, &shared)), "InvalidFormat");
    let mut aad = JweEncryptOptions::new("A128GCM".to_owned(), vec![recipient()]);
    aad.aad = Some(polyjose_surface::SecretBytes::from(b"aad".to_vec()));
    assert_eq!(code(jwt_encrypt_nested(RFC7519_3_1, &aad)), "InvalidFormat");
    let mut per = recipient();
    per.header = Some(r#"{"x":1}"#.to_owned());
    let per = JweEncryptOptions::new("A128GCM".to_owned(), vec![per]);
    assert_eq!(code(jwt_encrypt_nested(RFC7519_3_1, &per)), "InvalidFormat");

    // Bad header JSON and keys are the core's errors.
    let mut bad = JweEncryptOptions::new("A128GCM".to_owned(), vec![recipient()]);
    bad.protected_header = Some("[]".to_owned());
    assert_eq!(code(jwt_encrypt_nested(RFC7519_3_1, &bad)), "InvalidJson");
    let bad_key = JweEncryptOptions::new(
        "A128GCM".to_owned(),
        vec![JweRecipient::new("A128KW".to_owned(), secret(r#"{"kty":"oct"}"#))],
    );
    assert_eq!(code(jwt_encrypt_nested(RFC7519_3_1, &bad_key)), "InvalidKey");

    // The inner token must be a signed compact JWS (RFC 7519 §5.2, RFC 8725 §3.2).
    let options = JweEncryptOptions::new("A128GCM".to_owned(), vec![recipient()]);
    assert_eq!(code(jwt_encrypt_nested("a.b", &options)), "InvalidFormat");
}

#[test]
fn ecdh_es_recipient_options_reach_the_core() {
    // RFC 7518 §4.6.1.2-§4.6.1.3: apu and apv go into the protected header.
    let (private, public) = key_pair(KeySpec::Ec(EcCurve::P256));
    let mut recipient = JweRecipient::new("ECDH-ES".to_owned(), secret(&public));
    recipient.apu = Some(b"Alice".to_vec());
    recipient.apv = Some(b"Bob".to_vec());
    let options = JweEncryptOptions::new("A256GCM".to_owned(), vec![recipient]);
    let nested = jwt_encrypt_nested(RFC7519_3_1, &options).unwrap();
    let decrypt = JweDecryptOptions::new(list(&["ECDH-ES"]), list(&["A256GCM"]));
    let verified = jwt_decrypt_nested(&nested, &private, &decrypt, OCT, &hs256()).unwrap();
    let outer = parse(&verified.outer_header);
    assert_eq!(outer.get("apu").and_then(Value::as_str), Some("QWxpY2U"));
    assert_eq!(outer.get("apv").and_then(Value::as_str), Some("Qm9i"));
}

#[test]
fn pbes2_recipient_options_reach_the_core() {
    // RFC 7518 §4.8.1.1-§4.8.1.2: the iteration count and salt length are the caller's.
    let password = r#"{"kty":"oct","k":"VGhlcmUgaXMgbm8gc3Bvb24"}"#;
    let mut recipient = JweRecipient::new("PBES2-HS256+A128KW".to_owned(), secret(password));
    recipient.p2c = Some(1000);
    recipient.p2s_len = Some(8);
    let options = JweEncryptOptions::new("A128GCM".to_owned(), vec![recipient]);
    let nested = jwt_encrypt_nested(RFC7519_3_1, &options).unwrap();
    let decrypt = JweDecryptOptions::new(list(&["PBES2-HS256+A128KW"]), list(&["A128GCM"]));
    let verified = jwt_decrypt_nested(&nested, password, &decrypt, OCT, &hs256()).unwrap();
    let outer = parse(&verified.outer_header);
    assert_eq!(outer.get("p2c").and_then(Value::as_i64), Some(1000));
    let p2s = outer.get("p2s").and_then(Value::as_str).unwrap();
    assert_eq!(polyjose::util::b64url_decode(p2s).unwrap().len(), 8);

    let mut low = JweRecipient::new("PBES2-HS256+A128KW".to_owned(), secret(password));
    low.p2c = Some(1);
    let options = JweEncryptOptions::new("A128GCM".to_owned(), vec![low]);
    assert_eq!(code(jwt_encrypt_nested(RFC7519_3_1, &options)), "InvalidKey");
}

// --- Secrets and defaults (ADR 0030 §3, §7) --------------------------------------------------

#[test]
fn no_error_or_debug_output_carries_a_marked_secret() {
    // Keys whose members hold the marker (21 base64url characters: no valid length), claims
    // with the marker next to a syntax error, and a marked decrypt key.
    let marked_key = format!(r#"{{"kty":"oct","k":"{MARKER}"}}"#);
    let marked_ec =
        format!(r#"{{"kty":"EC","crv":"P-256","x":"{MARKER}","y":"{MARKER}","d":"{MARKER}"}}"#);
    let marked_claims = format!(r#"{{"{MARKER}" {MARKER}}}"#);
    let marked_header = format!(r#"{{"crit":"{MARKER}"}}"#);
    let (key, nested) = a128kw_nested();
    let sign_options = JwtSignOptions::new("HS256".to_owned());
    let mut header_options = JwtSignOptions::new("HS256".to_owned());
    header_options.header = Some(marked_header);
    let errors = [
        jwt_verify(RFC7519_3_1, &marked_key, &hs256()).unwrap_err(),
        jwt_verify(RFC7519_3_1, &marked_ec, &hs256()).unwrap_err(),
        jwt_verify_with_jwks(RFC7519_3_1, &format!(r#"{{"keys":{MARKER}}}"#), &hs256())
            .unwrap_err(),
        jwt_verify(&format!("{MARKER}.{MARKER}.{MARKER}"), OCT, &hs256()).unwrap_err(),
        jwt_sign(&marked_claims, OCT, &sign_options).unwrap_err(),
        jwt_sign(RFC7519_3_1_CLAIMS, &marked_ec, &sign_options).unwrap_err(),
        jwt_sign(RFC7519_3_1_CLAIMS, OCT, &header_options).unwrap_err(),
        jwt_decrypt_nested(&nested, &marked_key, &a128kw_decrypt(), OCT, &hs256()).unwrap_err(),
        jwt_decrypt_nested(&nested, &key, &a128kw_decrypt(), &marked_ec, &hs256()).unwrap_err(),
        jwt_encrypt_nested(
            RFC7519_3_1,
            &JweEncryptOptions::new(
                "A128GCM".to_owned(),
                vec![JweRecipient::new("A128KW".to_owned(), secret(&marked_key))],
            ),
        )
        .unwrap_err(),
    ];
    for e in errors {
        for rendered in [format!("{e:?}"), e.to_string(), e.message().to_owned()] {
            assert!(!rendered.contains(MARKER), "error leaks: {rendered}");
        }
    }

    // A verified token's claims print as their length only (records' redacting Debug).
    let token = sign(&format!(r#"{{"sub":"{MARKER}","exp":1300819380}}"#));
    let verified = jwt_verify(&token, OCT, &hs256()).unwrap();
    assert!(verified.claims.contains(MARKER));
    assert!(!format!("{verified:?}").contains(MARKER));
    let nested = jwt_encrypt_nested(
        &token,
        &JweEncryptOptions::new(
            "A128GCM".to_owned(),
            vec![JweRecipient::new("A128KW".to_owned(), secret(&key))],
        ),
    )
    .unwrap();
    let verified = jwt_decrypt_nested(&nested, &key, &a128kw_decrypt(), OCT, &hs256()).unwrap();
    assert!(!format!("{verified:?}").contains(MARKER));
    assert!(!format!("{verified:#?}").contains(MARKER));
}

#[test]
fn no_numeric_literal_in_jwt_rs_restates_a_core_default() {
    // ADR 0030 §3: the leeway (60), its cap (600) and the key-candidate bound (8) live in the
    // core only. Code, not comments, is checked, up to the unit tests.
    let source = include_str!("../src/jwt.rs");
    let code = source.split("#[cfg(test)]").next().unwrap();
    for (n, line) in code.lines().enumerate() {
        let line = line.split("//").next().unwrap();
        for token in line.split(|c: char| !c.is_ascii_alphanumeric() && c != '_') {
            let digits = token.trim_end_matches(|c: char| c.is_ascii_alphabetic() || c == '_');
            assert!(
                !["60", "600", "8"].contains(&digits.trim_start_matches('0')),
                "jwt.rs line {} restates a core default: {line}",
                n + 1
            );
        }
    }
}

#[test]
fn the_decrypt_key_and_keys_are_borrowed_text() {
    // ADR 0030 §7.1: secret inputs are &str, parsed into the core's wiping Jwk/JwkSet.
    let _: fn(&str, &str, &JwtSignOptions) -> SurfaceResult<String> = jwt_sign;
    let _: fn(&str, &str, &JwtVerifyOptions) -> SurfaceResult<JwtVerified> = jwt_verify;
    let _: fn(&str, &str, &JwtVerifyOptions) -> SurfaceResult<JwtVerified> = jwt_verify_with_jwks;
    // The core types the surface parses into wipe on drop.
    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<Jwk>();
    assert_zeroize_on_drop::<polyjose::jwk::JwkSet>();
}
