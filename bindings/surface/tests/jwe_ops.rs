//! The JWE operations of the binding surface (ADR 0030 §4, "JWE"; RFC 7516, RFC 7518 §4–§5),
//! through the public surface API only.
//!
//! The RFC values are those of `conformance/vectors/jwe` (RFC 7516 App. A.3 and A.4, RFC 7520
//! §5.4 and §5.8); the security rules are the core's, passed through unchanged: allow-lists
//! (ADR 0007), RSA public-only (ADR 0021), no SHA-1 (ADR 0022), the PBES2 bound and per-token
//! budget (ADR 0023, ADR 0050 §2), protected direct modes (ADR 0050 §1) and secret results
//! (ADR 0030 §7, ADR 0050 §4).

use polyjose_surface::jwe::{
    jwe_decrypt_compact, jwe_decrypt_json, jwe_encrypt_compact, jwe_encrypt_json,
};
use polyjose_surface::records::{JweDecryptOptions, JweDecrypted, JweEncryptOptions, JweRecipient};
use polyjose_surface::{SecretBytes, SecretString, SurfaceError, util};

// --- Values from conformance/vectors/jwe ---------------------------------------------------------

/// RFC 7516 App. A.3.7 (`compact/rfc7516-a3-a128kw-a128cbc-hs256-decrypt.json`).
const A3_JWE: &str = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.AxY8DCtDaGlsbGljb3RoZQ.KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.U0m_YmjN04DJvceFICbCVQ";
/// RFC 7516 App. A.3.3's key, also the A128KW key of App. A.4.
const A3_KEY: &str = r#"{"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg"}"#;
/// "Live long and prosper." (RFC 7516 App. A.3).
const A3_PLAINTEXT_B64U: &str = "TGl2ZSBsb25nIGFuZCBwcm9zcGVyLg";

/// RFC 7516 App. A.4.7, the general JSON JWE to an RSA1_5 and an A128KW recipient
/// (`json/rfc7516-a4-general-a128kw-recipient-1-decrypt.json`).
const A4_JWE: &str = r#"{"protected":"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","unprotected":{"jku":"https://server.example.com/keys.jwks"},"recipients":[{"header":{"alg":"RSA1_5","kid":"2011-04-29"},"encrypted_key":"UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A"},{"header":{"alg":"A128KW","kid":"7"},"encrypted_key":"6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ"}],"iv":"AxY8DCtDaGlsbGljb3RoZQ","ciphertext":"KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY","tag":"Mz-VPPyU4RlcuYv1IwIvzw"}"#;

/// RFC 7520 §5.4's compact JWE (ECDH-ES+A128KW on P-384, A128GCM)
/// (`ecdh-es/rfc7520-5-4-ecdh-es-a128kw-p384-a128gcm-decrypt.json`).
const R5_4_JWE: &str = "eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImtpZCI6InBlcmVncmluLnRvb2tAdHVja2Jvcm91Z2guZXhhbXBsZSIsImVwayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMzg0IiwieCI6InVCbzRrSFB3Nmtiang1bDB4b3dyZF9vWXpCbWF6LUdLRlp1NHhBRkZrYllpV2d1dEVLNml1RURzUTZ3TmROZzMiLCJ5Ijoic3AzcDVTR2haVkMyZmFYdW1JLWU5SlUyTW84S3BvWXJGRHI1eVBOVnRXNFBnRXdaT3lRVEEtSmRhWTh0YjdFMCJ9LCJlbmMiOiJBMTI4R0NNIn0.0DJjBXri_kBcC46IkU5_Jk9BqaQeHdv2.mH-G2zVqgztUtnW_.tkZuOO9h95OgHJmkkrfLBisku8rGf6nzVxhRM3sVOhXgz5NJ76oID7lpnAi_cPWJRCjSpAaUZ5dOR3Spy7QuEkmKx8-3RCMhSYMzsXaEwDdXta9Mn5B7cCBoJKB0IgEnj_qfo1hIi-uEkUpOZ8aLTZGHfpl05jMwbKkTe2yK3mjF6SBAsgicQDVCkcY9BLluzx1RmC3ORXaM0JaHPB93YcdSDGgpgBWMVrNU1ErkjcMqMoT_wtCex3w03XdLkjXIuEr2hWgeP-nkUZTPU9EoGSPj6fAS-bSz87RCPrxZdj_iVyC6QWcqAu07WNhjzJEPc4jVntRJ6K53NgPQ5p99l3Z408OUqj4ioYezbS6vTPlQ.WuGzxmcreYjpHGJoa17EBg";
/// RFC 7520 §5.4's recipient key (P-384).
const R5_4_KEY: &str = r#"{"kty":"EC","kid":"peregrin.took@tuckborough.example","use":"enc","crv":"P-384","x":"YU4rRUzdmVqmRtWOs2OpDE_T5fsNIodcG8G5FWPrTPMyxpzsSOGaQLpe2FpxBmu2","y":"A8-yxCHxkfBz3hKZfI1jUYMjUhsEveZ9THuwFjH2sCNdtksRJU7D5-SkgaFL1ETP","d":"iTx2pk7wW-GqJkHcEkFQb2EFyYcO7RugmaW3mRrQVAOUiPommT0IdnYK2xDlZh-j"}"#;

/// RFC 7520 §5.8's compact JWE (A128KW, A128GCM)
/// (`compact/rfc7520-5-8-a128kw-a128gcm-decrypt.json`).
const R5_8_JWE: &str = "eyJhbGciOiJBMTI4S1ciLCJraWQiOiI4MWIyMDk2NS04MzMyLTQzZDktYTQ2OC04MjE2MGFkOTFhYzgiLCJlbmMiOiJBMTI4R0NNIn0.CBI6oDw8MydIx1IBntf_lQcw2MmJKIQx.Qx0pmsDa8KnJc9Jo.AwliP-KmWgsZ37BvzCefNen6VTbRK3QMA4TkvRkH0tP1bTdhtFJgJxeVmJkLD61A1hnWGetdg11c9ADsnWgL56NyxwSYjU1ZEHcGkd3EkU0vjHi9gTlb90qSYFfeF0LwkcTtjbYKCsiNJQkcIp1yeM03OmuiYSoYJVSpf7ej6zaYcMv3WwdxDFl8REwOhNImk2Xld2JXq6BR53TSFkyT7PwVLuq-1GwtGHlQeg7gDT6xW0JqHDPn_H-puQsmthc9Zg0ojmJfqqFvETUxLAF-KjcBTS5dNy6egwkYtOt8EIHK-oEsKYtZRaa8Z7MOZ7UGxGIMvEmxrGCPeJa14slv2-gaqK0kEThkaSqdYw0FkQZF.ER7MWJZ1FBI_NKvn7Zb1Lw";
/// RFC 7520 §5.8's general JSON form (`json/rfc7520-5-8-a128kw-a128gcm-general-decrypt.json`).
const R5_8_GENERAL_JWE: &str = r#"{"recipients":[{"encrypted_key":"CBI6oDw8MydIx1IBntf_lQcw2MmJKIQx"}],"protected":"eyJhbGciOiJBMTI4S1ciLCJraWQiOiI4MWIyMDk2NS04MzMyLTQzZDktYTQ2OC04MjE2MGFkOTFhYzgiLCJlbmMiOiJBMTI4R0NNIn0","iv":"Qx0pmsDa8KnJc9Jo","ciphertext":"AwliP-KmWgsZ37BvzCefNen6VTbRK3QMA4TkvRkH0tP1bTdhtFJgJxeVmJkLD61A1hnWGetdg11c9ADsnWgL56NyxwSYjU1ZEHcGkd3EkU0vjHi9gTlb90qSYFfeF0LwkcTtjbYKCsiNJQkcIp1yeM03OmuiYSoYJVSpf7ej6zaYcMv3WwdxDFl8REwOhNImk2Xld2JXq6BR53TSFkyT7PwVLuq-1GwtGHlQeg7gDT6xW0JqHDPn_H-puQsmthc9Zg0ojmJfqqFvETUxLAF-KjcBTS5dNy6egwkYtOt8EIHK-oEsKYtZRaa8Z7MOZ7UGxGIMvEmxrGCPeJa14slv2-gaqK0kEThkaSqdYw0FkQZF","tag":"ER7MWJZ1FBI_NKvn7Zb1Lw"}"#;
/// RFC 7520 §5.8's key.
const R5_8_KEY: &str = r#"{"kty":"oct","kid":"81b20965-8332-43d9-a468-82160ad91ac8","use":"enc","alg":"A128KW","k":"GZy6sIZ6wl9NJOKB-jnmVQ"}"#;
/// RFC 7520 Figure 72, the plaintext of §5.4 and §5.8.
const R5_PLAINTEXT_B64U: &str = "WW91IGNhbiB0cnVzdCB1cyB0byBzdGljayB3aXRoIHlvdSB0aHJvdWdoIHRoaWNrIGFuZCB0aGlu4oCTdG8gdGhlIGJpdHRlciBlbmQuIEFuZCB5b3UgY2FuIHRydXN0IHVzIHRvIGtlZXAgYW55IHNlY3JldCBvZiB5b3Vyc-KAk2Nsb3NlciB0aGFuIHlvdSBrZWVwIGl0IHlvdXJzZWxmLiBCdXQgeW91IGNhbm5vdCB0cnVzdCB1cyB0byBsZXQgeW91IGZhY2UgdHJvdWJsZSBhbG9uZSwgYW5kIGdvIG9mZiB3aXRob3V0IGEgd29yZC4gV2UgYXJlIHlvdXIgZnJpZW5kcywgRnJvZG8u";

// --- Helpers -----------------------------------------------------------------------------------

fn list(names: &[&str]) -> Vec<String> {
    names.iter().map(|s| (*s).to_owned()).collect()
}

fn policy(algs: &[&str], encs: &[&str]) -> JweDecryptOptions {
    JweDecryptOptions::new(list(algs), list(encs))
}

fn b64u(text: &str) -> Vec<u8> {
    util::base64url_decode(text).unwrap()
}

fn assert_code<T: core::fmt::Debug>(result: Result<T, SurfaceError>, code: &str) -> SurfaceError {
    let err = result.unwrap_err();
    assert_eq!(err.code(), code, "{}", err.message());
    err
}

// --- Decrypt: RFC values (RFC 7516 §5.2) ---------------------------------------------------------

#[test]
fn decrypt_compact_reproduces_rfc7516_a3() {
    let d = jwe_decrypt_compact(A3_JWE, A3_KEY, &policy(&["A128KW"], &["A128CBC-HS256"])).unwrap();
    assert_eq!(d.plaintext.as_bytes(), b64u(A3_PLAINTEXT_B64U));
    assert_eq!(d.plaintext.as_bytes(), b"Live long and prosper.");
    assert_eq!(
        d.protected_header.as_deref(),
        Some(r#"{"alg":"A128KW","enc":"A128CBC-HS256"}"#)
    );
    assert_eq!(d.header, r#"{"alg":"A128KW","enc":"A128CBC-HS256"}"#);
    assert_eq!(d.shared_unprotected_header, None);
    assert_eq!(d.recipient_header, None);
    assert!(d.aad.is_none());
    assert_eq!(d.recipient_index, 0);
}

#[test]
fn decrypt_compact_reproduces_rfc7520_5_4_ecdh_es_a128kw_p384() {
    let d = jwe_decrypt_compact(
        R5_4_JWE,
        R5_4_KEY,
        &policy(&["ECDH-ES+A128KW"], &["A128GCM"]),
    )
    .unwrap();
    assert_eq!(d.plaintext.as_bytes(), b64u(R5_PLAINTEXT_B64U));
    let protected = d.protected_header.as_deref().unwrap();
    assert!(protected.starts_with(r#"{"alg":"ECDH-ES+A128KW","enc":"A128GCM","kid":"peregrin.took@tuckborough.example","epk":{"#));
    assert_eq!(d.recipient_index, 0);
}

#[test]
fn decrypt_compact_reproduces_rfc7520_5_8() {
    let d = jwe_decrypt_compact(R5_8_JWE, R5_8_KEY, &policy(&["A128KW"], &["A128GCM"])).unwrap();
    assert_eq!(d.plaintext.as_bytes(), b64u(R5_PLAINTEXT_B64U));
    assert_eq!(
        d.protected_header.as_deref(),
        Some(r#"{"alg":"A128KW","enc":"A128GCM","kid":"81b20965-8332-43d9-a468-82160ad91ac8"}"#)
    );
    assert_eq!(d.recipient_index, 0);
}

#[test]
fn decrypt_json_reproduces_rfc7520_5_8_general() {
    let d = jwe_decrypt_json(
        R5_8_GENERAL_JWE,
        R5_8_KEY,
        &policy(&["A128KW"], &["A128GCM"]),
    )
    .unwrap();
    assert_eq!(d.plaintext.as_bytes(), b64u(R5_PLAINTEXT_B64U));
    assert_eq!(d.recipient_index, 0);
    assert_eq!(d.shared_unprotected_header, None);
    assert_eq!(d.recipient_header, None);
}

#[test]
fn decrypt_json_reports_the_recipient_index_and_every_header_part_of_rfc7516_a4() {
    let d = jwe_decrypt_json(
        A4_JWE,
        A3_KEY,
        &policy(&["RSA1_5", "A128KW"], &["A128CBC-HS256"]),
    )
    .unwrap();
    assert_eq!(d.plaintext.as_bytes(), b"Live long and prosper.");
    // The second recipient decrypted (RFC 7516 §7.2.1): the first is RSA1_5 (ADR 0022).
    assert_eq!(d.recipient_index, 1);
    assert_eq!(
        d.protected_header.as_deref(),
        Some(r#"{"enc":"A128CBC-HS256"}"#)
    );
    assert_eq!(
        d.shared_unprotected_header.as_deref(),
        Some(r#"{"jku":"https://server.example.com/keys.jwks"}"#)
    );
    assert_eq!(
        d.recipient_header.as_deref(),
        Some(r#"{"alg":"A128KW","kid":"7"}"#)
    );
    // The JOSE Header is the union of the three (RFC 7516 §5.2 step 4), as the core writes it.
    assert_eq!(
        d.header,
        r#"{"alg":"A128KW","enc":"A128CBC-HS256","jku":"https://server.example.com/keys.jwks","kid":"7"}"#
    );
}

// --- Decrypt: allow-lists and limits (ADR 0007, RFC 8725 §3.1) ---------------------------------

#[test]
fn an_empty_allow_list_is_algorithm_not_allowed() {
    for (algs, encs) in [
        (&[][..], &["A128CBC-HS256"][..]),
        (&["A128KW"][..], &[][..]),
        (&[][..], &[][..]),
    ] {
        let options = policy(algs, encs);
        assert_code(
            jwe_decrypt_compact(A3_JWE, A3_KEY, &options),
            "AlgorithmNotAllowed",
        );
        assert_code(
            jwe_decrypt_json(A4_JWE, A3_KEY, &options),
            "AlgorithmNotAllowed",
        );
    }
}

#[test]
fn an_alg_or_enc_outside_the_allow_list_is_algorithm_not_allowed() {
    let wrong_alg = policy(&["A256KW"], &["A128CBC-HS256"]);
    assert_code(
        jwe_decrypt_compact(A3_JWE, A3_KEY, &wrong_alg),
        "AlgorithmNotAllowed",
    );
    let wrong_enc = policy(&["A128KW"], &["A256GCM"]);
    assert_code(
        jwe_decrypt_compact(A3_JWE, A3_KEY, &wrong_enc),
        "AlgorithmNotAllowed",
    );
}

#[test]
fn every_decrypt_option_reaches_the_core() {
    let base = policy(&["A128KW"], &["A128CBC-HS256"]);

    let mut options = base.clone();
    options.max_input_len = Some(16);
    assert_code(
        jwe_decrypt_compact(A3_JWE, A3_KEY, &options),
        "InvalidFormat",
    );

    let mut options = policy(&["RSA1_5", "A128KW"], &["A128CBC-HS256"]);
    options.max_recipients = Some(1);
    assert_code(jwe_decrypt_json(A4_JWE, A3_KEY, &options), "InvalidFormat");

    // `crit` must name only understood extensions (RFC 7516 §4.1.13); the token is built by the
    // surface so that its protected header carries one.
    let mut encrypt = JweEncryptOptions::new(
        "A128CBC-HS256".to_owned(),
        vec![JweRecipient::new(
            "A128KW".to_owned(),
            SecretString::from(A3_KEY.to_owned()),
        )],
    );
    encrypt.protected_header = Some(r#"{"crit":["exp-ext"],"exp-ext":1}"#.to_owned());
    let token = jwe_encrypt_compact(b"hi", &encrypt).unwrap();
    assert_code(
        jwe_decrypt_compact(&token, A3_KEY, &base),
        "UnknownCritical",
    );
    let mut options = base.clone();
    options.understood_crit = Some(list(&["exp-ext"]));
    assert_eq!(
        jwe_decrypt_compact(&token, A3_KEY, &options)
            .unwrap()
            .plaintext
            .as_bytes(),
        b"hi"
    );

    // Without the `deflate` feature, `max_decompressed_len` changes nothing for a token that is
    // not compressed (ADR 0017).
    let mut options = base;
    options.max_decompressed_len = Some(0);
    assert!(jwe_decrypt_compact(A3_JWE, A3_KEY, &options).is_ok());
}

#[test]
fn a_malformed_key_or_token_fails_with_the_core_code() {
    let options = policy(&["A128KW"], &["A128CBC-HS256"]);
    assert_code(jwe_decrypt_compact(A3_JWE, "{", &options), "InvalidJson");
    assert_code(jwe_decrypt_json(A4_JWE, "[]", &options), "InvalidJson");
    assert_code(
        jwe_decrypt_compact("a.b.c", A3_KEY, &options),
        "InvalidFormat",
    );
    assert_code(jwe_decrypt_json("{", A3_KEY, &options), "InvalidJson");
    // The key's family must serve the alg (RFC 8725 §3.1, ADR 0007).
    assert_code(
        jwe_decrypt_compact(A3_JWE, R5_4_KEY, &options),
        "KeyAlgorithmMismatch",
    );
}

/// Keeps the result types of ADR 0030 §4 in one place: the plaintext and the AAD are secret
/// owners (ADR 0030 §7, ADR 0050 §4), and `Debug` prints neither.
#[test]
fn the_decrypted_plaintext_and_aad_are_secret_and_redacted() {
    let d: JweDecrypted =
        jwe_decrypt_compact(A3_JWE, A3_KEY, &policy(&["A128KW"], &["A128CBC-HS256"])).unwrap();
    let _: &SecretBytes = &d.plaintext;
    let _: &Option<SecretBytes> = &d.aad;
    let rendered = format!("{d:?}");
    assert!(!rendered.contains("Live long"), "{rendered}");
}

// --- Encrypt: keys -----------------------------------------------------------------------------

/// A 256-bit `oct` key (octets 0 to 31): `dir` for A256GCM and A128CBC-HS256 (RFC 7518 §5.2.3,
/// §5.3), and A256GCMKW (RFC 7518 §4.7).
const OCT_256: &str = r#"{"kty":"oct","k":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"}"#;
/// RFC 7520 §5.5's P-256 recipient key, and its public part.
const P256_PRIVATE: &str = r#"{"kty":"EC","kid":"meriadoc.brandybuck@buckland.example","use":"enc","crv":"P-256","x":"Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0","y":"HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw","d":"r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8"}"#;
const P256_PUBLIC: &str = r#"{"kty":"EC","kid":"meriadoc.brandybuck@buckland.example","use":"enc","crv":"P-256","x":"Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0","y":"HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw"}"#;
/// The X25519 key of `ecdh-es/kat-x25519-ecdh-es-a128gcm-decrypt.json` (RFC 8037 §3.2), and its
/// public part.
const X25519_PRIVATE: &str = r#"{"kty":"OKP","crv":"X25519","x":"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08","d":"XasIfmJKikt54X-Lg4AO5m87sSkmGLb9HC-LJ_-I4Os"}"#;
const X25519_PUBLIC: &str =
    r#"{"kty":"OKP","crv":"X25519","x":"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08"}"#;
/// RFC 7520 §5.3's password (Figure 96) as an `oct` key (RFC 7518 §4.8).
const PASSWORD: &str = r#"{"kty":"oct","k":"ZW50cmFwX2_igJNwZXRlcl9sb25n4oCTY3JlZGl0X3R1bg"}"#;
/// Another password, for a PBES2 recipient the key above does not open.
const OTHER_PASSWORD: &str = r#"{"kty":"oct","k":"bm90LXRoZS1wYXNzd29yZA"}"#;
/// The public part of `rsa-oaep-256/keys/rsa-2048.private.jwk` (RSA-OAEP-256 encrypts to public
/// keys only, ADR 0021).
const RSA_2048_PUBLIC: &str = r#"{"kty":"RSA","n":"tNzZIjyPSkJr-WPJsHzUF7m9m1lgV1mm1EJa5nCuxo_YdYRLmbEKaGcY6eNquHIa6oQFeh-Mg35K6jZ2Vg77QLaC_Z8YpL8Rk0jhPb6mQALM_4iQcBFT4Ce9XrRdYnsVdjziflVEJTf2_-5ZBcRTaqCf59fvgWkdKZcJwppBDnjCabj8wmWBmomY9RDECwPk9ahNyo9AZWg2CdaSg3U09NaPx39VEXvbZOQuG_yJCv58D1d7DeeEFPo8vZfpRO2mAZVHREMacrN2CbaEfQZiPMkBkAV0zg6g7zKUyEW7Osa92VJXPlQR1tko4sqbKAGBWz6WjcdXEiTLCLGgn3e5bQ","e":"AQAB"}"#;

const PLAINTEXT: &[u8] = b"The true sign of intelligence is not knowledge but imagination.";

fn recipient(alg: &str, key: &str) -> JweRecipient {
    JweRecipient::new(alg.to_owned(), SecretString::from(key.to_owned()))
}

fn encrypt_options(enc: &str, recipients: Vec<JweRecipient>) -> JweEncryptOptions {
    JweEncryptOptions::new(enc.to_owned(), recipients)
}

/// The decoded JWE Protected Header of a compact JWE (RFC 7516 §7.1, its first part).
fn compact_protected(token: &str) -> String {
    let first = token.split('.').next().unwrap();
    String::from_utf8(b64u(first)).unwrap()
}

/// The decoded `protected` member of a JWE JSON Serialization (RFC 7516 §7.2.1). The surface
/// has no JSON reader of its own, so this finds the member textually: polyjose writes it once,
/// as a base64url string.
fn json_protected(jwe: &str) -> String {
    let start = jwe.find(r#""protected":""#).unwrap() + r#""protected":""#.len();
    let end = start + jwe[start..].find('"').unwrap();
    String::from_utf8(b64u(&jwe[start..end])).unwrap()
}

// --- Encrypt: compact (RFC 7516 §7.1) ----------------------------------------------------------

#[test]
fn encrypt_compact_round_trips_every_alg_with_a256gcm_and_a128cbc_hs256() {
    // (alg, the encrypting key, the decrypting key, p2c). PBES2 runs at RFC 7518 §4.8.1.2's
    // recommended minimum, 1,000, to keep the test fast; the default count is pinned below.
    let cases: [(&str, &str, &str, Option<u32>); 8] = [
        ("dir", OCT_256, OCT_256, None),
        ("A128KW", A3_KEY, A3_KEY, None),
        ("A256GCMKW", OCT_256, OCT_256, None),
        ("ECDH-ES", P256_PUBLIC, P256_PRIVATE, None),
        ("ECDH-ES", X25519_PUBLIC, X25519_PRIVATE, None),
        ("ECDH-ES+A128KW", P256_PUBLIC, P256_PRIVATE, None),
        ("PBES2-HS256+A128KW", PASSWORD, PASSWORD, Some(1000)),
        ("ECDH-ES+A128KW", X25519_PUBLIC, X25519_PRIVATE, None),
    ];
    for enc in ["A256GCM", "A128CBC-HS256"] {
        for (alg, encrypt_key, decrypt_key, p2c) in cases {
            let mut r = recipient(alg, encrypt_key);
            r.p2c = p2c;
            let token = jwe_encrypt_compact(PLAINTEXT, &encrypt_options(enc, vec![r]))
                .unwrap_or_else(|e| panic!("{alg} {enc}: {}", e.code()));
            assert_eq!(token.split('.').count(), 5, "{alg} {enc}");
            let protected = compact_protected(&token);
            assert!(
                protected.starts_with(&format!(r#"{{"alg":"{alg}","enc":"{enc}""#)),
                "{protected}"
            );
            let d = jwe_decrypt_compact(&token, decrypt_key, &policy(&[alg], &[enc]))
                .unwrap_or_else(|e| panic!("{alg} {enc}: {}", e.code()));
            assert_eq!(d.plaintext.as_bytes(), PLAINTEXT, "{alg} {enc}");
            assert_eq!(d.protected_header.as_deref(), Some(protected.as_str()));
        }
    }
}

#[test]
fn rsa_oaep_256_encrypts_to_a_public_key_and_never_decrypts() {
    for enc in ["A256GCM", "A128CBC-HS256"] {
        let options = encrypt_options(enc, vec![recipient("RSA-OAEP-256", RSA_2048_PUBLIC)]);
        let token = jwe_encrypt_compact(PLAINTEXT, &options).unwrap();
        assert_eq!(token.split('.').count(), 5);
        assert_eq!(
            compact_protected(&token),
            format!(r#"{{"alg":"RSA-OAEP-256","enc":"{enc}"}}"#)
        );
        // RSA is public-key only (ADR 0021): decrypting is UnsupportedAlgorithm even when
        // allowed.
        assert_code(
            jwe_decrypt_compact(&token, RSA_2048_PUBLIC, &policy(&["RSA-OAEP-256"], &[enc])),
            "UnsupportedAlgorithm",
        );
    }
}

#[test]
fn rsa_oaep_and_rsa1_5_are_unsupported_on_encrypt() {
    // SHA-1 RSA-OAEP and RSA1_5 are not implemented (ADR 0022, ADR 0021).
    for alg in ["RSA-OAEP", "RSA1_5"] {
        let options = encrypt_options("A256GCM", vec![recipient(alg, RSA_2048_PUBLIC)]);
        assert_code(
            jwe_encrypt_compact(PLAINTEXT, &options),
            "UnsupportedAlgorithm",
        );
        assert_code(
            jwe_encrypt_json(PLAINTEXT, &options, "general"),
            "UnsupportedAlgorithm",
        );
    }
}

#[test]
fn compact_refuses_what_it_cannot_carry() {
    // RFC 7516 §7.1: one recipient, and no AAD or unprotected header; the core decides.
    let two = encrypt_options(
        "A256GCM",
        vec![recipient("A128KW", A3_KEY), recipient("A256GCMKW", OCT_256)],
    );
    assert_code(jwe_encrypt_compact(PLAINTEXT, &two), "InvalidFormat");

    let none = encrypt_options("A256GCM", vec![]);
    assert_code(jwe_encrypt_compact(PLAINTEXT, &none), "InvalidFormat");

    let mut aad = encrypt_options("A256GCM", vec![recipient("A128KW", A3_KEY)]);
    aad.aad = Some(SecretBytes::from(b"aad".to_vec()));
    assert_code(jwe_encrypt_compact(PLAINTEXT, &aad), "InvalidFormat");

    let mut shared = encrypt_options("A256GCM", vec![recipient("A128KW", A3_KEY)]);
    shared.shared_unprotected_header = Some(r#"{"cty":"text"}"#.to_owned());
    assert_code(jwe_encrypt_compact(PLAINTEXT, &shared), "InvalidFormat");

    let mut r = recipient("A128KW", A3_KEY);
    r.header = Some(r#"{"kid":"r1"}"#.to_owned());
    assert_code(
        jwe_encrypt_compact(PLAINTEXT, &encrypt_options("A256GCM", vec![r])),
        "InvalidFormat",
    );
}

#[test]
fn compress_is_unsupported_without_the_deflate_feature() {
    // The bindings build without `deflate` (ADR 0030 §4, ADR 0034 §3): never an uncompressed
    // JWE in its place (ADR 0017 §5).
    let mut options = encrypt_options("A256GCM", vec![recipient("A128KW", A3_KEY)]);
    options.compress = true;
    assert_code(
        jwe_encrypt_compact(PLAINTEXT, &options),
        "UnsupportedAlgorithm",
    );
    for form in ["general", "flattened"] {
        assert_code(
            jwe_encrypt_json(PLAINTEXT, &options, form),
            "UnsupportedAlgorithm",
        );
    }
}

#[test]
fn malformed_encrypt_inputs_fail_with_the_core_code() {
    let mut options = encrypt_options("A256GCM", vec![recipient("A128KW", "{")]);
    assert_code(jwe_encrypt_compact(PLAINTEXT, &options), "InvalidJson");

    options = encrypt_options("A256GCM", vec![recipient("A128KW", A3_KEY)]);
    options.protected_header = Some("[1]".to_owned());
    assert_code(jwe_encrypt_compact(PLAINTEXT, &options), "InvalidJson");

    options = encrypt_options("A256GCM", vec![recipient("A128KW", A3_KEY)]);
    options.shared_unprotected_header = Some(r#"{"kid":1}"#.to_owned());
    assert_code(
        jwe_encrypt_json(PLAINTEXT, &options, "general"),
        "InvalidHeader",
    );

    let mut r = recipient("A128KW", A3_KEY);
    r.header = Some("{".to_owned());
    options = encrypt_options("A256GCM", vec![r]);
    assert_code(
        jwe_encrypt_json(PLAINTEXT, &options, "general"),
        "InvalidJson",
    );

    // A key of the wrong size for the alg (RFC 7518 §4.4) or of the wrong family (ADR 0007).
    options = encrypt_options("A256GCM", vec![recipient("A128KW", OCT_256)]);
    assert_code(jwe_encrypt_compact(PLAINTEXT, &options), "InvalidKey");
    options = encrypt_options("A256GCM", vec![recipient("ECDH-ES", OCT_256)]);
    assert_code(
        jwe_encrypt_compact(PLAINTEXT, &options),
        "KeyAlgorithmMismatch",
    );
    // An `enc` the core does not know (ADR 0030 option D1: the core decides).
    options = encrypt_options("A512GCM", vec![recipient("A128KW", A3_KEY)]);
    assert_code(
        jwe_encrypt_compact(PLAINTEXT, &options),
        "UnsupportedAlgorithm",
    );
}

#[test]
fn every_recipient_option_reaches_the_core() {
    // ECDH-ES `apu` and `apv` (RFC 7518 §4.6.1.2, §4.6.1.3) appear base64url-encoded.
    let mut r = recipient("ECDH-ES", P256_PUBLIC);
    r.apu = Some(b"Alice".to_vec());
    r.apv = Some(b"Bob".to_vec());
    let token = jwe_encrypt_compact(PLAINTEXT, &encrypt_options("A256GCM", vec![r])).unwrap();
    let protected = compact_protected(&token);
    assert!(protected.contains(r#""apu":"QWxpY2U""#), "{protected}");
    assert!(protected.contains(r#""apv":"Qm9i""#), "{protected}");
    let d = jwe_decrypt_compact(&token, P256_PRIVATE, &policy(&["ECDH-ES"], &["A256GCM"]));
    assert_eq!(d.unwrap().plaintext.as_bytes(), PLAINTEXT);

    // PBES2 `p2c` and the `p2s` length (RFC 7518 §4.8.1.1, §4.8.1.2).
    let mut r = recipient("PBES2-HS256+A128KW", PASSWORD);
    r.p2c = Some(1000);
    r.p2s_len = Some(8);
    let token = jwe_encrypt_compact(PLAINTEXT, &encrypt_options("A128GCM", vec![r])).unwrap();
    let protected = compact_protected(&token);
    assert!(protected.contains(r#""p2c":1000"#), "{protected}");
    let p2s_start = protected.find(r#""p2s":""#).unwrap() + r#""p2s":""#.len();
    let p2s_len = protected[p2s_start..].find('"').unwrap();
    assert_eq!(b64u(&protected[p2s_start..p2s_start + p2s_len]).len(), 8);

    // Extra protected header members (RFC 7516 §4) go in with `alg` and `enc`.
    let mut options = encrypt_options("A256GCM", vec![recipient("A128KW", A3_KEY)]);
    options.protected_header = Some(r#"{"typ":"example","kid":"k1"}"#.to_owned());
    let token = jwe_encrypt_compact(PLAINTEXT, &options).unwrap();
    assert_eq!(
        compact_protected(&token),
        r#"{"alg":"A128KW","enc":"A256GCM","kid":"k1","typ":"example"}"#
    );
}

// --- Encrypt: JSON (RFC 7516 §7.2) -------------------------------------------------------------

#[test]
fn encrypt_json_flattened_carries_every_header_part_and_the_aad() {
    let mut r = recipient("A128KW", A3_KEY);
    r.header = Some(r#"{"kid":"r1"}"#.to_owned());
    let mut options = encrypt_options("A128CBC-HS256", vec![r]);
    options.protected_header = Some(r#"{"typ":"example"}"#.to_owned());
    options.shared_unprotected_header = Some(r#"{"cty":"text/plain"}"#.to_owned());
    options.aad = Some(SecretBytes::from(b"additional data".to_vec()));

    let jwe = jwe_encrypt_json(PLAINTEXT, &options, "flattened").unwrap();
    assert!(!jwe.contains("recipients"), "{jwe}");
    assert_eq!(
        json_protected(&jwe),
        r#"{"alg":"A128KW","enc":"A128CBC-HS256","typ":"example"}"#
    );

    let d = jwe_decrypt_json(&jwe, A3_KEY, &policy(&["A128KW"], &["A128CBC-HS256"])).unwrap();
    assert_eq!(d.plaintext.as_bytes(), PLAINTEXT);
    assert_eq!(d.aad.as_ref().unwrap().as_bytes(), b"additional data");
    assert_eq!(
        d.shared_unprotected_header.as_deref(),
        Some(r#"{"cty":"text/plain"}"#)
    );
    assert_eq!(d.recipient_header.as_deref(), Some(r#"{"kid":"r1"}"#));
    assert_eq!(d.recipient_index, 0);
}

#[test]
fn encrypt_json_general_to_two_recipients_with_aad_decrypts_for_each() {
    let mut options = encrypt_options(
        "A256GCM",
        vec![recipient("A128KW", A3_KEY), recipient("A256GCMKW", OCT_256)],
    );
    options.aad = Some(SecretBytes::from(b"two recipients".to_vec()));
    let jwe = jwe_encrypt_json(PLAINTEXT, &options, "general").unwrap();
    assert!(jwe.contains(r#""recipients":["#), "{jwe}");

    let both = policy(&["A128KW", "A256GCMKW"], &["A256GCM"]);
    for (key, index) in [(A3_KEY, 0), (OCT_256, 1)] {
        let d = jwe_decrypt_json(&jwe, key, &both).unwrap();
        assert_eq!(d.plaintext.as_bytes(), PLAINTEXT);
        assert_eq!(d.aad.as_ref().unwrap().as_bytes(), b"two recipients");
        assert_eq!(d.recipient_index, index);
    }
}

#[test]
fn flattened_takes_exactly_one_recipient() {
    let two = encrypt_options(
        "A256GCM",
        vec![recipient("A128KW", A3_KEY), recipient("A256GCMKW", OCT_256)],
    );
    // RFC 7516 §7.2.2: the core rejects it.
    assert_code(
        jwe_encrypt_json(PLAINTEXT, &two, "flattened"),
        "InvalidFormat",
    );
    assert_code(
        jwe_encrypt_json(PLAINTEXT, &encrypt_options("A256GCM", vec![]), "general"),
        "InvalidFormat",
    );
}

#[test]
fn an_unknown_form_is_unsupported_algorithm() {
    // ADR 0030 §5: an unknown form string is UnsupportedAlgorithm. The names are exact.
    let options = encrypt_options("A256GCM", vec![recipient("A128KW", A3_KEY)]);
    for form in ["compact", "General", "FLATTENED", "", "general "] {
        assert_code(
            jwe_encrypt_json(PLAINTEXT, &options, form),
            "UnsupportedAlgorithm",
        );
    }
}
