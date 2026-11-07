//! The ADR 0030 §4 binding API, name by name.
//!
//! Every operation is called exactly once with the ADR's argument order, and its result is bound
//! to the return type the adapters are written against. A renamed, moved, missing or re-typed
//! operation fails to compile here, before any adapter (WASM, Node, UniFFI) notices. Behaviour is
//! tested next to each operation (T06–T09) and in the conformance run (T11); this file only pins
//! the shape, plus the four utilities, which T01 implements.

use polyjose_surface::records::{
    JweDecryptOptions, JweDecrypted, JweEncryptOptions, JweRecipient, JwkSelector, JwsSignOptions,
    JwsSigner, JwsVerified, JwsVerifyOptions, JwtNestedVerified, JwtSignOptions, JwtVerified,
    JwtVerifyOptions,
};
use polyjose_surface::{
    SecretBytes, SecretString, SurfaceError, SurfaceResult, jwe, jwk, jws, jwt, keys, util,
};
use zeroize::ZeroizeOnDrop;

/// RFC 7515 Appendix A.1's HMAC key.
const OCT: &str = r#"{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}"#;
/// RFC 7515 Appendix A.1's JWS.
const A1_JWS: &str = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

fn secret(json: &str) -> SecretString {
    SecretString::from(json.to_owned())
}

fn list(names: &[&str]) -> Vec<String> {
    names.iter().map(|s| (*s).to_owned()).collect()
}

fn jwe_options() -> JweEncryptOptions {
    JweEncryptOptions::new(
        "A256GCM".to_owned(),
        vec![JweRecipient::new("dir".to_owned(), secret(OCT))],
    )
}

// --- Utilities (implemented by T01) -----------------------------------------------------------

#[test]
fn utilities() {
    let version: &'static str = util::version();
    assert!(!version.is_empty());

    let codes: &'static [&'static str] = util::error_codes();
    assert_eq!(codes, polyjose::Error::CODES);

    let encoded: String = util::base64url_encode(b"foobar");
    assert_eq!(encoded, "Zm9vYmFy");
    let decoded: SurfaceResult<Vec<u8>> = util::base64url_decode("Zm9vYmFy");
    assert_eq!(decoded.unwrap(), b"foobar");

    let err: SurfaceError = util::base64url_decode("Zm9vYmFy==").unwrap_err();
    assert_eq!(err.code(), "InvalidBase64");
    assert!(codes.contains(&err.code()));
}

// --- JWK (T06) --------------------------------------------------------------------------------

#[test]
fn jwk_operations() {
    let _: SurfaceResult<SecretString> = jwk::jwk_parse(OCT);
    let _: SurfaceResult<String> = jwk::jwk_to_public(OCT);
    // `hash: Option<&str>`: `None` is the core default, SHA-256 (ADR 0054 §9).
    let _: SurfaceResult<String> = jwk::jwk_thumbprint(OCT, Some("SHA-256"));
    let _: SurfaceResult<String> = jwk::jwk_thumbprint(OCT, None);
    let _: SurfaceResult<String> = jwk::jwk_thumbprint_uri(OCT, Some("sha-384"));
    let _: SurfaceResult<String> = jwk::jwk_thumbprint_uri(OCT, None);
    let selector = JwkSelector {
        kid: Some("k1".to_owned()),
        alg: Some("HS256".to_owned()),
        key_use: Some("sig".to_owned()),
    };
    let jwks = format!(r#"{{"keys":[{OCT}]}}"#);
    let _: SurfaceResult<SecretString> = jwk::jwks_select(&jwks, &selector);
}

// --- Keys (T06) -------------------------------------------------------------------------------

#[test]
fn key_operations() {
    let _: SurfaceResult<SecretString> = keys::jwk_generate_oct(32);
    let _: SurfaceResult<SecretString> = keys::jwk_generate_ec("P-256");
    let _: SurfaceResult<SecretString> = keys::jwk_generate_okp("Ed25519");
    let _: SurfaceResult<SecretString> = keys::jwk_generate_for_alg("ES256");
    let _: SurfaceResult<SecretString> =
        keys::jwk_from_pem("-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----\n");
    let _: SurfaceResult<SecretString> = keys::jwk_from_der(&[0x30, 0x00], "spki");
    let _: SurfaceResult<SecretString> = keys::jwk_to_pem(OCT, "pkcs8");
    let _: SurfaceResult<SecretBytes> = keys::jwk_to_der(OCT, "pkcs8");
}

// --- JWS (T07) --------------------------------------------------------------------------------

#[test]
fn jws_operations() {
    let sign = JwsSignOptions {
        protected_header: Some(r#"{"alg":"HS256"}"#.to_owned()),
        ..JwsSignOptions::default()
    };
    let _: SurfaceResult<String> = jws::jws_sign_compact(b"payload", OCT, &sign);

    let mut signer = JwsSigner::new(secret(OCT));
    signer.unprotected_header = Some(r#"{"alg":"HS256"}"#.to_owned());
    let _: SurfaceResult<String> = jws::jws_sign_flattened(b"payload", &signer, false);
    let signers = [JwsSigner::new(secret(OCT)), JwsSigner::new(secret(OCT))];
    let _: SurfaceResult<String> = jws::jws_sign_general(b"payload", &signers, true);

    let verify = JwsVerifyOptions::new(list(&["HS256"]));
    let _: SurfaceResult<JwsVerified> = jws::jws_verify_compact(A1_JWS, OCT, &verify);
    let _: SurfaceResult<JwsVerified> = jws::jws_verify_json("{}", OCT, &verify);
}

// --- JWE (T08) --------------------------------------------------------------------------------

#[test]
fn jwe_operations() {
    let encrypt = jwe_options();
    let _: SurfaceResult<String> = jwe::jwe_encrypt_compact(b"plaintext", &encrypt);
    let _: SurfaceResult<String> = jwe::jwe_encrypt_json(b"plaintext", &encrypt, "general");

    let decrypt = JweDecryptOptions::new(list(&["dir"]), list(&["A256GCM"]));
    let _: SurfaceResult<JweDecrypted> = jwe::jwe_decrypt_compact("a.b.c.d.e", OCT, &decrypt);
    let _: SurfaceResult<JweDecrypted> = jwe::jwe_decrypt_json("{}", OCT, &decrypt);
}

// --- JWT (T09) --------------------------------------------------------------------------------

#[test]
fn jwt_operations() {
    let sign = JwtSignOptions::new("HS256".to_owned());
    let _: SurfaceResult<String> = jwt::jwt_sign(r#"{"iss":"joe"}"#, OCT, &sign);

    let mut verify = JwtVerifyOptions::new(list(&["HS256"]));
    verify.now = Some(1_300_819_320);
    let jwks = format!(r#"{{"keys":[{OCT}]}}"#);
    let _: SurfaceResult<JwtVerified> = jwt::jwt_verify(A1_JWS, OCT, &verify);
    let _: SurfaceResult<JwtVerified> = jwt::jwt_verify_with_jwks(A1_JWS, &jwks, &verify);

    let _: SurfaceResult<String> = jwt::jwt_encrypt_nested(A1_JWS, &jwe_options());
    let decrypt = JweDecryptOptions::new(list(&["dir"]), list(&["A256GCM"]));
    let _: SurfaceResult<JwtNestedVerified> =
        jwt::jwt_decrypt_nested("a.b.c.d.e", OCT, &decrypt, OCT, &verify);
    let _: SurfaceResult<JwtNestedVerified> =
        jwt::jwt_decrypt_nested_with_jwks("a.b.c.d.e", OCT, &decrypt, &jwks, &verify);
}

// --- Secret-bearing fields wipe on drop (ADR 0030 §7) -----------------------------------------

/// Compiles only if the field `field` projects to wipes itself on drop. Nothing is constructed or
/// run: this is a type-level check of each secret field of ADR 0030 §7 (keys, payload, plaintext,
/// aad), and of each secret-bearing return type.
fn assert_zeroizing<R, T: ZeroizeOnDrop>(field: fn(&R) -> &T) {
    let _ = field;
}

/// As [`assert_zeroizing`], for the success type of an operation.
fn assert_zeroizing_output<A, T: ZeroizeOnDrop>(operation: fn(A) -> SurfaceResult<T>) {
    let _ = operation;
}

#[test]
fn every_secret_field_and_output_is_zeroize_on_drop() {
    // Keys held by the multi-party records (ADR 0030 §3).
    assert_zeroizing(|s: &JwsSigner| &s.key);
    assert_zeroizing(|r: &JweRecipient| &r.key);
    // Payloads, plaintext and aad, in both directions (ADR 0030 §7, ADR 0049 §4, ADR 0050 §4).
    assert_zeroizing(|o: &JwsVerifyOptions| &o.detached_payload);
    assert_zeroizing(|v: &JwsVerified| &v.payload);
    assert_zeroizing(|o: &JweEncryptOptions| &o.aad);
    assert_zeroizing(|d: &JweDecrypted| &d.plaintext);
    assert_zeroizing(|d: &JweDecrypted| &d.aad);
    // Operations that return key material: parsed, selected, generated, imported or exported.
    assert_zeroizing_output(jwk::jwk_parse);
    assert_zeroizing_output(keys::jwk_generate_oct);
    assert_zeroizing_output(keys::jwk_generate_ec);
    assert_zeroizing_output(keys::jwk_generate_okp);
    assert_zeroizing_output(keys::jwk_generate_for_alg);
    assert_zeroizing_output(keys::jwk_from_pem);
    assert_zeroizing_output(|(jwks, selector): (&str, &JwkSelector)| {
        jwk::jwks_select(jwks, selector)
    });
    assert_zeroizing_output(|(der, format): (&[u8], &str)| keys::jwk_from_der(der, format));
    assert_zeroizing_output(|(jwk, format): (&str, &str)| keys::jwk_to_pem(jwk, format));
    assert_zeroizing_output(|(jwk, format): (&str, &str)| keys::jwk_to_der(jwk, format));
}
