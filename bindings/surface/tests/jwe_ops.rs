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
