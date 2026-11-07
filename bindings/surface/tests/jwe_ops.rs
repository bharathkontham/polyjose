//! The JWE operations of the binding surface (ADR 0030 §4, "JWE"; RFC 7516, RFC 7518 §4–§5),
//! through the public surface API only.
//!
//! The RFC values are those of `conformance/vectors/jwe` (RFC 7516 App. A.3 and A.4, RFC 7520
//! §5.4 and §5.8); the security rules are the core's, passed through unchanged: allow-lists
//! (ADR 0007), RSA public-only (ADR 0021), no SHA-1 (ADR 0022), the PBES2 bound and per-token
//! budget (ADR 0023, ADR 0050 §2), protected direct modes (ADR 0050 §1) and secret results
//! (ADR 0030 §7, ADR 0050 §4).

#![allow(clippy::unwrap_used, clippy::panic)] // test code: a panic is a failed assertion

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

/// RFC 7520 §5.9's compact JWE (A128KW, A128GCM, `zip: DEF`) under the §5.8 key
/// (`zip/rfc7520-5-9-a128kw-a128gcm-def-decrypt.json`).
const R5_9_ZIP_JWE: &str = "eyJhbGciOiJBMTI4S1ciLCJraWQiOiI4MWIyMDk2NS04MzMyLTQzZDktYTQ2OC04MjE2MGFkOTFhYzgiLCJlbmMiOiJBMTI4R0NNIiwiemlwIjoiREVGIn0.5vUT2WOtQxKWcekM_IzVQwkGgzlFDwPi.p9pUq6XHY0jfEZIl.HbDtOsdai1oYziSx25KEeTxmwnh8L8jKMFNc1k3zmMI6VB8hry57tDZ61jXyezSPt0fdLVfe6Jf5y5-JaCap_JQBcb5opbmT60uWGml8blyiMQmOn9J--XhhlYg0m-BHaqfDO5iTOWxPxFMUedx7WCy8mxgDHj0aBMG6152PsM-w5E_o2B3jDbrYBKhpYA7qi3AyijnCJ7BP9rr3U8kxExCpG3mK420TjOw.VILuUwuIxaLVmh5X-T7kmA";

fn zip_policy() -> JweDecryptOptions {
    policy(&["A128KW"], &["A128GCM"])
}

/// Whether the core under test has its `deflate` feature (ADR 0017). The bindings ship without
/// it (ADR 0030 §4, ADR 0034 §3), but `cargo test --workspace --all-features` unifies it on, and
/// Cargo gives a dependent crate no `cfg` for a dependency's feature. So this asks the core, twice
/// and independently: by decrypting RFC 7520 §5.9's `zip` token and by encrypting with
/// `compress`. Each must succeed or fail with exactly `UnsupportedAlgorithm`, and the two must
/// agree; anything else fails the calling test. The callers then check the full behaviour of
/// whichever build this is, so neither answer can hide a fault.
fn deflate_enabled() -> bool {
    let probe = |result: Result<(), SurfaceError>| match result {
        Ok(()) => true,
        Err(e) => {
            assert_eq!(e.code(), "UnsupportedAlgorithm", "{}", e.message());
            false
        }
    };
    let decrypts = probe(jwe_decrypt_compact(R5_9_ZIP_JWE, R5_8_KEY, &zip_policy()).map(drop));
    let mut options = encrypt_options("A128GCM", vec![recipient("A128KW", A3_KEY)]);
    options.compress = true;
    let encrypts = probe(jwe_encrypt_compact(b"probe", &options).map(drop));
    assert_eq!(
        decrypts, encrypts,
        "the zip decrypt and encrypt probes disagree"
    );
    decrypts
}

#[test]
fn a_compressed_jwe_decrypts_only_with_the_deflate_feature() {
    if !deflate_enabled() {
        // The shipped bindings (ADR 0030 §4, ADR 0034 §3): `zip` is refused among the support
        // checks, never decrypted without inflating (ADR 0017).
        assert_code(
            jwe_decrypt_compact(R5_9_ZIP_JWE, R5_8_KEY, &zip_policy()),
            "UnsupportedAlgorithm",
        );
        return;
    }
    // With `deflate`: RFC 7520 §5.9 inflates to Figure 72 (RFC 7516 §5.2 step 17).
    let d = jwe_decrypt_compact(R5_9_ZIP_JWE, R5_8_KEY, &zip_policy()).unwrap();
    let plaintext = b64u(R5_PLAINTEXT_B64U);
    assert_eq!(d.plaintext.as_bytes(), plaintext);
    assert!(d.protected_header.unwrap().contains(r#""zip":"DEF""#));
    // `max_decompressed_len` reaches the core: the exact length inflates, one less is the
    // uniform DecryptionFailed (ADR 0017, ADR 0007).
    let len = u32::try_from(plaintext.len()).unwrap();
    let mut exact = zip_policy();
    exact.max_decompressed_len = Some(len);
    assert!(jwe_decrypt_compact(R5_9_ZIP_JWE, R5_8_KEY, &exact).is_ok());
    let mut short = zip_policy();
    short.max_decompressed_len = Some(len - 1);
    assert_code(
        jwe_decrypt_compact(R5_9_ZIP_JWE, R5_8_KEY, &short),
        "DecryptionFailed",
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
fn compress_needs_the_deflate_feature_and_never_falls_back() {
    let mut options = encrypt_options("A256GCM", vec![recipient("A128KW", A3_KEY)]);
    options.compress = true;
    if !deflate_enabled() {
        // The shipped bindings (ADR 0030 §4, ADR 0034 §3): never an uncompressed JWE in its
        // place (ADR 0017 §5).
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
        return;
    }
    // With `deflate`: `zip: DEF` is protected (RFC 7516 §4.1.3) in every serialization, and the
    // JWE round trips.
    let decrypt = policy(&["A128KW"], &["A256GCM"]);
    let token = jwe_encrypt_compact(PLAINTEXT, &options).unwrap();
    assert!(compact_protected(&token).contains(r#""zip":"DEF""#));
    let d = jwe_decrypt_compact(&token, A3_KEY, &decrypt).unwrap();
    assert_eq!(d.plaintext.as_bytes(), PLAINTEXT);
    for form in ["general", "flattened"] {
        let jwe = jwe_encrypt_json(PLAINTEXT, &options, form).unwrap();
        assert!(json_protected(&jwe).contains(r#""zip":"DEF""#), "{jwe}");
        let d = jwe_decrypt_json(&jwe, A3_KEY, &decrypt).unwrap();
        assert_eq!(d.plaintext.as_bytes(), PLAINTEXT);
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

// --- PBES2: the core's count, bound and per-token budget (ADR 0023, ADR 0050 §2) ----------------

fn pbes2(key: &str, p2c: Option<u32>) -> JweRecipient {
    let mut r = recipient("PBES2-HS256+A128KW", key);
    r.p2c = p2c;
    r
}

fn pbes2_policy() -> JweDecryptOptions {
    policy(&["PBES2-HS256+A128KW"], &["A128GCM"])
}

#[test]
fn p2c_none_is_the_core_default_and_decrypts_under_the_default_bound() {
    // `p2c: None` sets nothing, so the core writes its default count, 10,000 (ADR 0023), which
    // is also the most the default decrypt bound accepts.
    let token = jwe_encrypt_compact(
        PLAINTEXT,
        &encrypt_options("A128GCM", vec![pbes2(PASSWORD, None)]),
    )
    .unwrap();
    assert!(compact_protected(&token).contains(r#""p2c":10000"#));
    let d = jwe_decrypt_compact(&token, PASSWORD, &pbes2_policy()).unwrap();
    assert_eq!(d.plaintext.as_bytes(), PLAINTEXT);
}

#[test]
fn p2c_one_above_the_default_bound_needs_a_raised_max_pbes2_count() {
    let token = jwe_encrypt_compact(
        PLAINTEXT,
        &encrypt_options("A128GCM", vec![pbes2(PASSWORD, Some(10_001))]),
    )
    .unwrap();
    // RFC 7518 §8.8, ADR 0023: refused before any PBKDF2 work, uniformly.
    assert_code(
        jwe_decrypt_compact(&token, PASSWORD, &pbes2_policy()),
        "DecryptionFailed",
    );
    let mut raised = pbes2_policy();
    raised.max_pbes2_count = Some(20_000);
    let d = jwe_decrypt_compact(&token, PASSWORD, &raised).unwrap();
    assert_eq!(d.plaintext.as_bytes(), PLAINTEXT);
}

#[test]
fn the_pbes2_bound_is_a_budget_for_the_whole_token() {
    // ADR 0050 §2: two PBES2 recipients without `kid`, 6,000 each, are both candidates for the
    // key. The first is under another password, so it spends 6,000 and fails; the second needs
    // 6,000 more than the default 10,000 leaves.
    let jwe = jwe_encrypt_json(
        PLAINTEXT,
        &encrypt_options(
            "A128GCM",
            vec![
                pbes2(OTHER_PASSWORD, Some(6_000)),
                pbes2(PASSWORD, Some(6_000)),
            ],
        ),
        "general",
    )
    .unwrap();
    assert!(!jwe.contains("kid"), "{jwe}");
    assert_code(
        jwe_decrypt_json(&jwe, PASSWORD, &pbes2_policy()),
        "DecryptionFailed",
    );
    let mut raised = pbes2_policy();
    raised.max_pbes2_count = Some(20_000);
    let d = jwe_decrypt_json(&jwe, PASSWORD, &raised).unwrap();
    assert_eq!(d.plaintext.as_bytes(), PLAINTEXT);
    assert_eq!(d.recipient_index, 1);
}

#[test]
fn pbes2_parameters_outside_the_core_encrypt_range_are_invalid_key() {
    // Recorded core behaviour (ADR 0050 §2, RFC 7518 §4.8.1.1, §4.8.1.2): a `p2c` above the
    // 1,000,000 ceiling or below 1,000, and a `p2s` length above 256 or below 8, fail with
    // InvalidKey, before any PBKDF2 work.
    for p2c in [1_000_001, u32::MAX, 999, 0] {
        let options = encrypt_options("A128GCM", vec![pbes2(PASSWORD, Some(p2c))]);
        assert_code(jwe_encrypt_compact(PLAINTEXT, &options), "InvalidKey");
    }
    for p2s_len in [257, 7] {
        let mut r = pbes2(PASSWORD, Some(1000));
        r.p2s_len = Some(p2s_len);
        let options = encrypt_options("A128GCM", vec![r]);
        assert_code(jwe_encrypt_compact(PLAINTEXT, &options), "InvalidKey");
    }
}

// --- Direct modes need a protected alg and enc (ADR 0050 §1) --------------------------------------

/// `negative-cross-mode/audit-forged-gcmkw-as-dir.json`: the security audit's forged token, an
/// A128GCMKW key wrap relabelled as `dir` with `alg` and `enc` unprotected.
const AUDIT_FORGED_DIR: &str = r#"{"unprotected":{"alg":"dir","enc":"A128GCM"},"iv":"O7z64SOn4nzSXqYX","ciphertext":"MnP1M2KMxJATaL2fiHopzA","tag":"1iuYCU-NaRWTNmU0AQpqYg"}"#;
/// `negative-cross-mode/dir-no-protected-header.json`: an honest `dir` JWE with no protected
/// header.
const DIR_NO_PROTECTED: &str = r#"{"unprotected":{"alg":"dir","enc":"A128GCM"},"iv":"cg4gak1ok5MkDhBf","ciphertext":"kbXXRkfQJoVUOb99YK-Yww","tag":"Zkerl5MxxOenLBmWbJqhRw"}"#;
/// The key of both.
const CROSS_MODE_KEY: &str = r#"{"kty":"oct","k":"AAECAwQFBgcICQoLDA0ODw"}"#;
/// `negative-cross-mode/ecdh-es-p256-alg-shared.json`: ECDH-ES with `enc` protected but `alg` and
/// `epk` only in the shared unprotected header, and its key.
const ECDH_ES_ALG_SHARED: &str = r#"{"protected":"eyJlbmMiOiJBMTI4R0NNIn0","unprotected":{"alg":"ECDH-ES","epk":{"kty":"EC","crv":"P-256","x":"IeQwN4R8Ia0KzQMdl2ECtPtqr4uZlLli6c1-a3HxQJ4","y":"9o6N0HCvnnEbmdRm16NlvJaRXAs7yxfsPl1kJBr4TBM"}},"iv":"Hb842gFCnuL39bIE","ciphertext":"iTkAUwjKG8ia-eJCA_6MHbdYlN2CqzhcjdM65T_0zMbW07mFzmnU","tag":"oZb92a-LZdMZQHL7dRxiTg"}"#;
const ECDH_ES_ALG_SHARED_KEY: &str = r#"{"kty":"EC","crv":"P-256","x":"y7f2mVK84kO3zqFuPaCBtA3WUhkF_kVxoy_XEihK8FA","y":"-4WlU8v2oK3WvAiACn-ORltXvA0H3gDfSyC-eUdeo2s","d":"-_nytyiEI0OyVKkN9Iyyzaqcexr7wpXWDDj2a21zvFM"}"#;

#[test]
fn a_direct_mode_without_a_protected_alg_and_enc_is_invalid_header() {
    let cross_mode = policy(&["A128GCMKW", "dir"], &["A128GCM"]);
    assert_code(
        jwe_decrypt_json(AUDIT_FORGED_DIR, CROSS_MODE_KEY, &cross_mode),
        "InvalidHeader",
    );
    assert_code(
        jwe_decrypt_json(DIR_NO_PROTECTED, CROSS_MODE_KEY, &cross_mode),
        "InvalidHeader",
    );
    assert_code(
        jwe_decrypt_json(
            ECDH_ES_ALG_SHARED,
            ECDH_ES_ALG_SHARED_KEY,
            &policy(&["ECDH-ES"], &["A128GCM"]),
        ),
        "InvalidHeader",
    );
}

#[test]
fn general_json_protects_a_direct_mode_and_leaves_an_empty_recipient() {
    // ADR 0050 §1: `alg`, and for ECDH-ES `epk`, `apu` and `apv`, are in the protected header in
    // every form; the general form's one recipient entry is empty.
    let mut ecdh = recipient("ECDH-ES", P256_PUBLIC);
    ecdh.apu = Some(b"Alice".to_vec());
    ecdh.apv = Some(b"Bob".to_vec());
    let cases: [(JweRecipient, &str, &str, &[&str]); 3] = [
        (recipient("dir", OCT_256), OCT_256, "dir", &[]),
        (
            ecdh,
            P256_PRIVATE,
            "ECDH-ES",
            &[
                r#""epk":{"kty":"EC","crv":"P-256""#,
                r#""apu":"QWxpY2U","apv":"Qm9i""#,
            ],
        ),
        (
            recipient("ECDH-ES", X25519_PUBLIC),
            X25519_PRIVATE,
            "ECDH-ES",
            &[r#""epk":{"kty":"OKP","crv":"X25519""#],
        ),
    ];
    for (r, decrypt_key, alg, members) in cases {
        let jwe =
            jwe_encrypt_json(PLAINTEXT, &encrypt_options("A256GCM", vec![r]), "general").unwrap();
        assert!(jwe.contains(r#""recipients":[{}]"#), "{jwe}");
        let protected = json_protected(&jwe);
        assert!(
            protected.starts_with(&format!(r#"{{"alg":"{alg}","enc":"A256GCM""#)),
            "{protected}"
        );
        for member in members {
            assert!(protected.contains(member), "{protected}");
        }
        let d = jwe_decrypt_json(&jwe, decrypt_key, &policy(&[alg], &["A256GCM"])).unwrap();
        assert_eq!(d.plaintext.as_bytes(), PLAINTEXT);
        assert_eq!(d.recipient_header, None);
        assert_eq!(d.protected_header.as_deref(), Some(protected.as_str()));
    }
}

// --- One decryption error (ADR 0007, RFC 7516 §11.4–§11.5) --------------------------------------

/// `token` with the first character of its compact part `part` changed to another base64url
/// character (the first one keeps every bit significant, so the part stays canonical).
fn tamper(token: &str, part: usize) -> String {
    let mut parts: Vec<String> = token.split('.').map(str::to_owned).collect();
    let first = if parts[part].starts_with('A') {
        "B"
    } else {
        "A"
    };
    parts[part].replace_range(0..1, first);
    parts.join(".")
}

#[test]
fn every_failure_after_key_management_is_the_same_decryption_failed() {
    let a3 = policy(&["A128KW"], &["A128CBC-HS256"]);
    let pbes2_token = jwe_encrypt_compact(
        PLAINTEXT,
        &encrypt_options("A128GCM", vec![pbes2(PASSWORD, Some(1000))]),
    )
    .unwrap();
    let mut under_budget = pbes2_policy();
    under_budget.max_pbes2_count = Some(999);
    let gcmkw = jwe_encrypt_compact(
        PLAINTEXT,
        &encrypt_options("A256GCM", vec![recipient("A256GCMKW", OCT_256)]),
    )
    .unwrap();
    let ecdh = jwe_encrypt_compact(
        PLAINTEXT,
        &encrypt_options("A256GCM", vec![recipient("ECDH-ES", P256_PUBLIC)]),
    )
    .unwrap();

    let failures = [
        // Another 128-bit key unwraps nothing (RFC 3394 integrity check).
        jwe_decrypt_compact(A3_JWE, r#"{"kty":"oct","k":"AAAAAAAAAAAAAAAAAAAAAA"}"#, &a3),
        jwe_decrypt_compact(&tamper(A3_JWE, 1), A3_KEY, &a3),
        jwe_decrypt_compact(&tamper(A3_JWE, 2), A3_KEY, &a3),
        jwe_decrypt_compact(&tamper(A3_JWE, 3), A3_KEY, &a3),
        jwe_decrypt_compact(&tamper(A3_JWE, 4), A3_KEY, &a3),
        jwe_decrypt_compact(&pbes2_token, OTHER_PASSWORD, &pbes2_policy()),
        jwe_decrypt_compact(&pbes2_token, PASSWORD, &under_budget),
        jwe_decrypt_compact(
            &tamper(&gcmkw, 4),
            OCT_256,
            &policy(&["A256GCMKW"], &["A256GCM"]),
        ),
        jwe_decrypt_compact(
            &ecdh,
            ECDH_ES_ALG_SHARED_KEY,
            &policy(&["ECDH-ES"], &["A256GCM"]),
        ),
    ];
    let errors: Vec<SurfaceError> = failures
        .into_iter()
        .map(|r| assert_code(r, "DecryptionFailed"))
        .collect();
    for e in &errors {
        assert_eq!(e, &errors[0]);
        assert_eq!(e.message(), errors[0].message());
    }
}

// --- No input in errors (ADR 0030 §5, ADR 0007) -------------------------------------------------

/// A distinctive value standing in for key material and other input (the core's marker style).
const MARKER: &str = "pj-SECRET-marker-7f3a";

/// A valid 256-bit `oct` key whose `k` holds the marker: the marker's 21 base64url characters
/// and 22 `A`s are 43 characters, 32 octets, with zero trailing bits (RFC 4648 §5).
fn marked_oct_256() -> String {
    format!(r#"{{"kty":"oct","k":"{MARKER}{}"}}"#, "A".repeat(22))
}

fn assert_no_marker<T: core::fmt::Debug>(what: &str, result: Result<T, SurfaceError>) {
    let err = result.unwrap_err();
    for rendered in [
        err.code().to_owned(),
        err.message().to_owned(),
        err.to_string(),
        format!("{err:?}"),
    ] {
        assert!(!rendered.contains(MARKER), "{what}: {rendered}");
    }
}

#[test]
fn no_failing_path_puts_the_marker_in_the_error() {
    let marked = marked_oct_256();
    let marked_unparseable = [
        // 21 base64url characters: no base64url text has that length.
        format!(r#"{{"kty":"oct","k":"{MARKER}"}}"#),
        format!(r#"{{"kty":"EC","crv":"P-256","x":"{MARKER}","y":"{MARKER}","d":"{MARKER}"}}"#),
        // A syntax error next to the marker, where a quoting parser would echo it.
        format!(r#"{{"kty":"oct","k":"{MARKER}" {MARKER}}}"#),
    ];
    let marked_json = format!(r#"{{"kid":"{MARKER}" {MARKER}}}"#);
    let with = |alg: &str, key: &str| encrypt_options("A256GCM", vec![recipient(alg, key)]);

    // Encrypt: every failing step of `encryptor` and of the core call.
    let mut cases: Vec<(&str, JweEncryptOptions)> = Vec::new();
    for key in &marked_unparseable {
        cases.push(("unparseable key", with("A256KW", key)));
    }
    let mut o = with("A256KW", &marked);
    o.recipients[0].header = Some(marked_json.clone());
    cases.push(("recipient header", o));
    let mut o = with("A256KW", &marked);
    o.protected_header = Some(marked_json.clone());
    cases.push(("protected header", o));
    let mut o = with("A256KW", &marked);
    o.shared_unprotected_header = Some(marked_json.clone());
    cases.push(("shared header", o));
    cases.push(("key size", with("A128KW", &marked)));
    cases.push(("key family", with("ECDH-ES", &marked)));
    cases.push(("RSA1_5", with("RSA1_5", &marked)));
    cases.push(("alg name", with(MARKER, &marked)));
    cases.push((
        "enc name",
        encrypt_options(MARKER, vec![recipient("A256KW", &marked)]),
    ));
    let mut o = with("PBES2-HS256+A128KW", &marked);
    o.recipients[0].p2c = Some(1_000_001);
    cases.push(("p2c", o));
    cases.push((
        "two recipients",
        encrypt_options(
            "A256GCM",
            vec![recipient("A256KW", &marked), recipient("dir", &marked)],
        ),
    ));
    for (what, options) in &cases {
        assert_no_marker(what, jwe_encrypt_compact(PLAINTEXT, options));
        assert_no_marker(what, jwe_encrypt_json(PLAINTEXT, options, "flattened"));
    }
    // Compression: refused without `deflate`; with it, a marked key's zip JWE over the inflate
    // bound fails uniformly (ADR 0017). Either way the failing path runs.
    let mut o = with("A256KW", &marked);
    o.compress = true;
    if deflate_enabled() {
        let token = jwe_encrypt_compact(PLAINTEXT, &o).unwrap();
        let mut no_room = policy(&["A256KW"], &["A256GCM"]);
        no_room.max_decompressed_len = Some(0);
        assert_no_marker(
            "inflate bound",
            jwe_decrypt_compact(&token, &marked, &no_room),
        );
    } else {
        assert_no_marker("compress", jwe_encrypt_compact(PLAINTEXT, &o));
        assert_no_marker("compress", jwe_encrypt_json(PLAINTEXT, &o, "flattened"));
    }
    // The compact-only refusal (RFC 7516 §7.1), and an unknown form holding the marker.
    let mut o = with("A256KW", &marked);
    o.aad = Some(SecretBytes::from(MARKER.as_bytes().to_vec()));
    assert_no_marker("compact aad", jwe_encrypt_compact(PLAINTEXT, &o));
    assert_no_marker(
        "form",
        jwe_encrypt_json(PLAINTEXT, &with("A256KW", &marked), MARKER),
    );

    // Decrypt: the key, the policy, the token, the header rules and the cryptography.
    let gcmkw = jwe_encrypt_compact(PLAINTEXT, &with("A256GCMKW", OCT_256)).unwrap();
    let allowed = policy(&["A256GCMKW"], &["A256GCM"]);
    let marked_names = policy(&[MARKER], &[MARKER]);
    let mut marked_crit = allowed.clone();
    marked_crit.understood_crit = Some(list(&[MARKER]));
    let marked_token = format!("{MARKER}.{MARKER}.{MARKER}.{MARKER}.{MARKER}");
    let empty = policy(&[], &[]);
    let ecdh = policy(&["ECDH-ES+A128KW"], &["A128GCM"]);
    let compact: Vec<(&str, &str, &str, &JweDecryptOptions)> = vec![
        ("empty allow-list", &gcmkw, &marked, &empty),
        ("allow-list names", &gcmkw, &marked, &marked_names),
        ("understood crit", &gcmkw, MARKER, &marked_crit),
        ("token", &marked_token, &marked, &allowed),
        ("token part", MARKER, &marked, &allowed),
        ("wrong key", &gcmkw, &marked, &allowed),
        ("key family", R5_4_JWE, &marked, &ecdh),
    ];
    let cross_mode = policy(&["A128GCMKW", "dir"], &["A128GCM"]);
    for (what, token, key, options) in compact {
        assert_no_marker(what, jwe_decrypt_compact(token, key, options));
    }
    for key in &marked_unparseable {
        assert_no_marker(
            "unparseable key",
            jwe_decrypt_compact(&gcmkw, key, &allowed),
        );
        assert_no_marker("unparseable key", jwe_decrypt_json(A4_JWE, key, &allowed));
    }
    let marked_jwe = format!(r#"{{"protected":"{MARKER}","ciphertext":"{MARKER}"}}"#);
    for (what, jwe, options) in [
        ("empty allow-list", A4_JWE, &empty),
        ("json", marked_json.as_str(), &allowed),
        ("json members", marked_jwe.as_str(), &allowed),
        ("unprotected dir", DIR_NO_PROTECTED, &cross_mode),
    ] {
        assert_no_marker(what, jwe_decrypt_json(jwe, &marked, options));
    }
}

// --- Defaults stay in the core (ADR 0030 §3) ----------------------------------------------------

/// The core defaults of ADR 0017 (250,000), ADR 0023 (10,000; the 1,000,000 ceiling) and
/// ADR 0026 §7 (1 MiB, 16), which no surface source may repeat.
const CORE_DEFAULTS: [u64; 5] = [10_000, 1_000_000, 250_000, 1_048_576, 16];

/// `source` without its comments: line, nested block and doc comments.
///
/// A small lexer, not a Rust parser. It knows string, raw string, byte string and character
/// literals only so that a `//` or `/*` inside one is not taken for a comment; their contents are
/// kept, so a default written inside a string still counts. Everything else is kept too,
/// `#[cfg(test)]` modules included: the rule is the same as T06's scan of `bindings/surface/src`
/// (`tests/jwk_ops.rs`), so the test literals that pin a default live under `tests/`.
fn without_comments(source: &str) -> String {
    let s: Vec<char> = source.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        let c = s[i];
        let next = s.get(i + 1).copied();
        if c == '/' && next == Some('/') {
            while i < s.len() && s[i] != '\n' {
                i += 1;
            }
        } else if c == '/' && next == Some('*') {
            let mut depth = 0;
            while i < s.len() {
                if s[i] == '/' && s.get(i + 1) == Some(&'*') {
                    depth += 1;
                    i += 2;
                } else if s[i] == '*' && s.get(i + 1) == Some(&'/') {
                    depth -= 1;
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    i += 1;
                }
            }
            out.push(' ');
        } else if c == 'r'
            && (next == Some('"') || next == Some('#'))
            && (i == 0 || !(s[i - 1].is_alphanumeric() || s[i - 1] == '_') || s[i - 1] == 'b')
        {
            // A raw string r"…", r#"…"#, also after a `b`: copied up to its closing quote.
            let mut j = i + 1;
            let mut hashes = 0;
            while s.get(j) == Some(&'#') {
                hashes += 1;
                j += 1;
            }
            if s.get(j) != Some(&'"') {
                out.push(c);
                i += 1;
                continue;
            }
            let closing: Vec<char> = core::iter::once('"')
                .chain(core::iter::repeat_n('#', hashes))
                .collect();
            let body = j + 1;
            let end = (body..s.len())
                .find(|&k| s[k..].starts_with(&closing))
                .map_or(s.len(), |k| k + closing.len());
            out.extend(&s[i..end]);
            i = end;
        } else if c == '"' {
            let mut j = i + 1;
            while j < s.len() && s[j] != '"' {
                j += if s[j] == '\\' { 2 } else { 1 };
            }
            let end = (j + 1).min(s.len());
            out.extend(&s[i..end]);
            i = end;
        } else if c == '\'' {
            // A character literal ('"', '\n', '\''), copied whole, or a lifetime ('a).
            let len = if next == Some('\\') {
                s[i + 2..].iter().position(|&ch| ch == '\'').map(|p| p + 3)
            } else if s.get(i + 2) == Some(&'\'') {
                Some(3)
            } else {
                None
            };
            let end = (i + len.unwrap_or(1)).min(s.len());
            out.extend(&s[i..end]);
            i = end;
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

/// Every integer literal of `code` equal to a core default, in any radix (`0x10` is 16), with
/// underscores and type suffixes (`10_000u32`), plus the spellings `1024 * 1024` and `1 << 20`
/// of 1 MiB. Digits inside an identifier (`u16`, `A128KW`) are not literals.
fn core_default_literals(code: &str) -> Vec<String> {
    let mut found = Vec::new();
    let compact: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    for spelling in ["1024*1024", "1<<20"] {
        if compact.contains(spelling) {
            found.push(spelling.to_owned());
        }
    }
    let chars: Vec<char> = code.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let starts = chars[i].is_ascii_digit()
            && (i == 0 || !(chars[i - 1].is_alphanumeric() || chars[i - 1] == '_'));
        if !starts {
            i += 1;
            continue;
        }
        let begin = i;
        while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
            i += 1;
        }
        let token: String = chars[begin..i].iter().collect();
        let plain: String = token.chars().filter(|&c| c != '_').collect();
        let (radix, digits) = match plain.get(..2) {
            Some("0x") => (16, &plain[2..]),
            Some("0o") => (8, &plain[2..]),
            Some("0b") => (2, &plain[2..]),
            _ => (10, plain.as_str()),
        };
        // The digits end where a type suffix (`u32`, `usize`) starts; a hex digit is no suffix.
        let end = digits
            .find(|c: char| !c.is_digit(radix))
            .unwrap_or(digits.len());
        if let Ok(value) = u64::from_str_radix(&digits[..end], radix)
            && CORE_DEFAULTS.contains(&value)
        {
            found.push(token);
        }
    }
    found
}

#[test]
fn the_defaults_scanner_finds_what_it_must_and_ignores_comments() {
    let flagged = "let a = 10_000; let b = 16usize; let c = 1024 * 1024; let d = 1_000_000u32;\n\
                   let e = [0u8; 16]; let f = 250000; let g = \"10000\"; let h = 0x10;\n\
                   let i = 0xF4240; let j = 0b1_0000; let k = r#\"{\"n\":1048576}\"#;\n\
                   #[cfg(test)]\nmod tests { fn t() { let _ = 0o20; } }";
    assert_eq!(
        core_default_literals(&without_comments(flagged)),
        [
            "1024*1024",
            "10_000",
            "16usize",
            "1_000_000u32",
            "16",
            "250000",
            "10000",
            "0x10",
            "0xF4240",
            "0b1_0000",
            "1048576",
            "0o20"
        ]
    );
    let mixed = "// 10000\n/// 16 and 1024 * 1024\n//! 250000\n/* 16 /* 16 */ 16 */\n\
                   fn f<'a>(x: &'a u16) -> u16 { let c = '1'; let h = 0x11; *x + 1600 + 160 }\n\
                   const A: &str = \"A128KW P-256 HS512 x16 https://e.example/16\";\n\
                   let q = '\"'; let r = r#\"// 16\"#; fn g() -> u32 { 17 }";
    let code = without_comments(mixed);
    assert_eq!(core_default_literals(&code), ["16", "16"], "{code}");
    assert!(code.contains("fn g() -> u32"), "{code}");
}

#[test]
fn no_surface_source_repeats_a_core_default() {
    let src = concat!(env!("CARGO_MANIFEST_DIR"), "/src");
    let mut files: Vec<_> = std::fs::read_dir(src)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "rs"))
        .collect();
    files.sort();
    assert!(
        files.iter().any(|path| path.ends_with("jwe.rs")),
        "{files:?}"
    );
    for path in files {
        let source = std::fs::read_to_string(&path).unwrap();
        let found = core_default_literals(&without_comments(&source));
        assert!(
            found.is_empty(),
            "{} repeats core defaults {found:?} (ADR 0030 §3)",
            path.display()
        );
    }
}
