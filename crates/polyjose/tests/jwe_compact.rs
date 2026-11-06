//! The JWE Compact Serialization through the public API (0003 T09):
//! RFC 7516 §5.1, §5.2 and §7.1, `dir` (RFC 7518 §4.5) and A*KW, under the
//! plan.md error contract.
//!
//! - RFC 7516 A.3 and RFC 7520 §5.6 and §5.8 decrypt with the RFC key, and
//!   (with `insecure-test-vectors`) `encrypt_reproducible` reproduces the
//!   RFC's compact string byte for byte from its CEK and IV.
//! - RFC 7516 A.1 and A.2 and RFC 7520 §5.1 and §5.2 (RSA-OAEP, RSA1_5)
//!   are `UnsupportedAlgorithm` (ADRs 0021, 0022), even when allowed.
//! - One test per row of the error contract, and the uniform
//!   `DecryptionFailed`.
//! - A property test round-trips `dir` and A*KW over every `enc`.
#![allow(clippy::panic)] // test code: a panic is a failed assertion

use polyjose::Error;
use polyjose::header::Header;
use polyjose::jwa::{ContentEncAlg, KeyMgmtAlg};
use polyjose::jwe::{DecryptPolicy, Encryptor, JsonForm, Recipient, decrypt_compact};
use polyjose::jwk::Jwk;
use polyjose::util::{b64url_decode, b64url_encode};
use proptest::prelude::*;

use ContentEncAlg as E;
use KeyMgmtAlg as A;

fn jwk(json: &str) -> Jwk {
    Jwk::from_json(json.as_bytes()).unwrap_or_else(|e| panic!("{json}: {e}"))
}

fn oct(bytes: &[u8]) -> Jwk {
    jwk(&format!(
        r#"{{"kty":"oct","k":"{}"}}"#,
        b64url_encode(bytes)
    ))
}

fn policy(algs: &[KeyMgmtAlg], encs: &[ContentEncAlg]) -> DecryptPolicy {
    DecryptPolicy::new(algs, encs).unwrap_or_else(|e| panic!("{e}"))
}

fn code<T>(result: polyjose::Result<T>) -> &'static str {
    match result {
        Ok(_) => "ok",
        Err(e) => e.code(),
    }
}

/// A compact JWE from a protected header given as JSON text and raw parts
/// (RFC 7516 §7.1), built by hand so decrypt is tested apart from encrypt.
fn forge(
    header_json: &str,
    encrypted_key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> String {
    [
        b64url_encode(header_json.as_bytes()),
        b64url_encode(encrypted_key),
        b64url_encode(iv),
        b64url_encode(ciphertext),
        b64url_encode(tag),
    ]
    .join(".")
}

// ---------------------------------------------------------------------------
// RFC values
// ---------------------------------------------------------------------------

/// RFC 7516 A.3: A128KW + A128CBC-HS256.
mod a3 {
    pub const KEY: &str = r#"{"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg"}"#;
    pub const PLAINTEXT: &[u8] = b"Live long and prosper.";
    /// A.3.1, `{"alg":"A128KW","enc":"A128CBC-HS256"}`.
    pub const PROTECTED: &str = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0";
    /// A.3.2.
    #[cfg_attr(
        not(feature = "insecure-test-vectors"),
        allow(dead_code, reason = "drawn by the reproducible tests only")
    )]
    pub const CEK: [u8; 32] = [
        4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106, 206, 107, 124, 212,
        45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156, 44, 207,
    ];
    /// A.3.4.
    pub const IV: [u8; 16] = [
        3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111, 116, 104, 101,
    ];
    /// A.3.7.
    pub const COMPACT: &str = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.\
        6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.\
        AxY8DCtDaGlsbGljb3RoZQ.\
        KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.\
        U0m_YmjN04DJvceFICbCVQ";
}

/// The RFC 7520 §5 plaintext (Figure 72), with its two U+2013 dashes.
const COOKBOOK_PLAINTEXT: &str = "You can trust us to stick with you through thick and \
    thin\u{2013}to the bitter end. And you can trust us to keep any secret of yours\u{2013}closer \
    than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off \
    without a word. We are your friends, Frodo.";

/// RFC 7520 §5.6: `dir` + A128GCM.
mod c56 {
    /// §5.6.1, Figure 130.
    pub const KEY: &str = r#"{"kty":"oct","kid":"77c7e2b8-6e13-45cf-8672-617b5b45243a","use":"enc","alg":"A128GCM","k":"XctOhJAkA-pD9Lh7ZgW_2A"}"#;
    pub const KID: &str = "77c7e2b8-6e13-45cf-8672-617b5b45243a";
    /// §5.6.2, Figure 131.
    pub const IV: &str = "refa467QzzKx6QAB";
    /// §5.6.3, Figure 133.
    pub const PROTECTED: &str = "eyJhbGciOiJkaXIiLCJraWQiOiI3N2M3ZTJiOC02ZTEzLTQ1Y2YtODY3Mi02MTdiNWI0NTI0M2EiLCJlbmMiOiJBMTI4R0NNIn0";
    /// §5.6.4, Figure 136.
    pub const COMPACT: &str = "eyJhbGciOiJkaXIiLCJraWQiOiI3N2M3ZTJiOC02ZTEzLTQ1Y2YtODY3Mi02MTdiNWI0NTI0M2EiLCJlbmMiOiJBMTI4R0NNIn0\
        ..refa467QzzKx6QAB.\
        JW_i_f52hww_ELQPGaYyeAB6HYGcR559l9TYnSovc23XJoBcW29rHP8yZOZG7YhLpT1bjFuvZPjQS-m0IFtVcXkZXdH_lr_FrdYt9HRUYkshtrMmIUAyGmUnd9zMDB2n0cRDIHAzFVeJUDxkUwVAE7_YGRPdcqMyiBoCO-FBdE-Nceb4h3-FtBP-c_BIwCPTjb9o0SbdcdREEMJMyZBH8ySWMVi1gPD9yxi-aQpGbSv_F9N4IZAxscj5g-NJsUPbjk29-s7LJAGb15wEBtXphVCgyy53CoIKLHHeJHXex45Uz9aKZSRSInZI-wjsY0yu3cT4_aQ3i1o-tiE-F8Ios61EKgyIQ4CWao8PFMj8TTnp.\
        vbb32Xvllea2OtmHAdccRQ";
}

/// RFC 7520 §5.8: A128KW + A128GCM.
mod c58 {
    /// §5.8.1, Figure 151.
    pub const KEY: &str = r#"{"kty":"oct","kid":"81b20965-8332-43d9-a468-82160ad91ac8","use":"enc","alg":"A128KW","k":"GZy6sIZ6wl9NJOKB-jnmVQ"}"#;
    pub const KID: &str = "81b20965-8332-43d9-a468-82160ad91ac8";
    /// §5.8.2, Figures 152 (CEK) and 153 (IV).
    #[cfg_attr(
        not(feature = "insecure-test-vectors"),
        allow(dead_code, reason = "drawn by the reproducible tests only")
    )]
    pub const CEK: &str = "aY5_Ghmk9KxWPBLu_glx1w";
    pub const IV: &str = "Qx0pmsDa8KnJc9Jo";
    /// §5.8.4, Figure 156.
    pub const PROTECTED: &str = "eyJhbGciOiJBMTI4S1ciLCJraWQiOiI4MWIyMDk2NS04MzMyLTQzZDktYTQ2OC04MjE2MGFkOTFhYzgiLCJlbmMiOiJBMTI4R0NNIn0";
    /// §5.8.5, Figure 159.
    pub const COMPACT: &str = "eyJhbGciOiJBMTI4S1ciLCJraWQiOiI4MWIyMDk2NS04MzMyLTQzZDktYTQ2OC04MjE2MGFkOTFhYzgiLCJlbmMiOiJBMTI4R0NNIn0.\
        CBI6oDw8MydIx1IBntf_lQcw2MmJKIQx.\
        Qx0pmsDa8KnJc9Jo.\
        AwliP-KmWgsZ37BvzCefNen6VTbRK3QMA4TkvRkH0tP1bTdhtFJgJxeVmJkLD61A1hnWGetdg11c9ADsnWgL56NyxwSYjU1ZEHcGkd3EkU0vjHi9gTlb90qSYFfeF0LwkcTtjbYKCsiNJQkcIp1yeM03OmuiYSoYJVSpf7ej6zaYcMv3WwdxDFl8REwOhNImk2Xld2JXq6BR53TSFkyT7PwVLuq-1GwtGHlQeg7gDT6xW0JqHDPn_H-puQsmthc9Zg0ojmJfqqFvETUxLAF-KjcBTS5dNy6egwkYtOt8EIHK-oEsKYtZRaa8Z7MOZ7UGxGIMvEmxrGCPeJa14slv2-gaqK0kEThkaSqdYw0FkQZF.\
        ER7MWJZ1FBI_NKvn7Zb1Lw";
}

/// The five base64url segments of a compact JWE.
fn segments(token: &str) -> Vec<String> {
    token.split('.').map(str::to_owned).collect()
}

fn a3_policy() -> DecryptPolicy {
    policy(&[A::A128KW], &[E::A128CbcHs256])
}

fn kid_header(kid: &str) -> Header {
    Header::from_json(format!(r#"{{"kid":"{kid}"}}"#).as_bytes()).unwrap_or_else(|e| panic!("{e}"))
}

#[test]
fn rfc_7516_a3_decrypts() {
    assert_eq!(
        segments(a3::COMPACT)[..3],
        [
            a3::PROTECTED.to_owned(),
            "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ".to_owned(),
            b64url_encode(&a3::IV)
        ]
    );
    let d =
        decrypt_compact(a3::COMPACT, &jwk(a3::KEY), &a3_policy()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(d.plaintext(), a3::PLAINTEXT);
    assert_eq!(d.recipient(), 0);
    assert_eq!(d.header().alg.as_deref(), Some("A128KW"));
    assert_eq!(d.header().enc, Some(E::A128CbcHs256));
    assert_eq!(d.protected_header(), Some(d.header()));
    assert!(d.shared_header().is_none() && d.recipient_header().is_none() && d.aad().is_none());
}

#[test]
fn rfc_7520_5_6_dir_a128gcm_decrypts() {
    let parts = segments(c56::COMPACT);
    assert_eq!(
        [parts[0].as_str(), &parts[1], &parts[2]],
        [c56::PROTECTED, "", c56::IV]
    );
    let p = policy(&[A::Dir], &[E::A128GCM]);
    let d = decrypt_compact(c56::COMPACT, &jwk(c56::KEY), &p).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(d.plaintext(), COOKBOOK_PLAINTEXT.as_bytes());
    assert_eq!(d.header().kid.as_deref(), Some(c56::KID));
}

#[test]
fn rfc_7520_5_8_a128kw_a128gcm_decrypts() {
    let parts = segments(c58::COMPACT);
    assert_eq!([parts[0].as_str(), &parts[2]], [c58::PROTECTED, c58::IV]);
    let p = policy(&[A::A128KW], &[E::A128GCM]);
    let d = decrypt_compact(c58::COMPACT, &jwk(c58::KEY), &p).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(d.plaintext(), COOKBOOK_PLAINTEXT.as_bytes());
    assert_eq!(d.header().kid.as_deref(), Some(c58::KID));
}

/// Byte-exact reproduction (RFC 7516 A.3, RFC 7520 §5.6, §5.8): the RFC's
/// CEK and IV through `FixedRng` in the documented draw order, and its
/// exact protected-header bytes through the `insecure-test-vectors` hook.
#[cfg(feature = "insecure-test-vectors")]
mod reproducible {
    use polyjose::insecure_test_vectors::FixedRng;
    use polyjose::jwe::Serialization;

    use super::*;

    fn bytes(b64u: &str) -> Vec<u8> {
        b64url_decode(b64u).unwrap_or_else(|e| panic!("{e}"))
    }

    #[test]
    fn rfc_7516_a3_is_reproduced() {
        let rng_bytes: Vec<u8> = a3::CEK.iter().chain(&a3::IV).copied().collect();
        let mut rng = FixedRng::new(rng_bytes);
        let token = Encryptor::new(E::A128CbcHs256)
            .recipient(Recipient::new(A::A128KW, &jwk(a3::KEY)))
            .encrypt_reproducible(
                a3::PLAINTEXT,
                Serialization::Compact,
                &mut rng,
                Some(a3::PROTECTED),
            )
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(token, a3::COMPACT);
        assert_eq!(rng.remaining(), 0);
        // Without the hook, polyjose's own encoding of the same header is
        // the RFC's too (alg, then enc).
        let mut rng = FixedRng::new(a3::CEK.iter().chain(&a3::IV).copied().collect::<Vec<u8>>());
        let own = Encryptor::new(E::A128CbcHs256)
            .recipient(Recipient::new(A::A128KW, &jwk(a3::KEY)))
            .encrypt_reproducible(a3::PLAINTEXT, Serialization::Compact, &mut rng, None)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(own, a3::COMPACT);
    }

    #[test]
    fn rfc_7520_5_6_is_reproduced() {
        let mut rng = FixedRng::new(bytes(c56::IV));
        let token = Encryptor::new(E::A128GCM)
            .protected_header(kid_header(c56::KID))
            .recipient(Recipient::new(A::Dir, &jwk(c56::KEY)))
            .encrypt_reproducible(
                COOKBOOK_PLAINTEXT.as_bytes(),
                Serialization::Compact,
                &mut rng,
                Some(c56::PROTECTED),
            )
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(token, c56::COMPACT);
        assert_eq!(rng.remaining(), 0);
    }

    #[test]
    fn rfc_7520_5_8_is_reproduced() {
        let mut rng = FixedRng::new([bytes(c58::CEK), bytes(c58::IV)].concat());
        let token = Encryptor::new(E::A128GCM)
            .protected_header(kid_header(c58::KID))
            .recipient(Recipient::new(A::A128KW, &jwk(c58::KEY)))
            .encrypt_reproducible(
                COOKBOOK_PLAINTEXT.as_bytes(),
                Serialization::Compact,
                &mut rng,
                Some(c58::PROTECTED),
            )
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(token, c58::COMPACT);
        assert_eq!(rng.remaining(), 0);
    }

    #[test]
    fn the_hook_refuses_a_header_polyjose_would_not_build() {
        // plan.md: the bytes must decode to a header JSON-equal to the one
        // the library built, or InvalidFormat; nothing is emitted.
        let encryptor =
            Encryptor::new(E::A128CbcHs256).recipient(Recipient::new(A::A128KW, &jwk(a3::KEY)));
        let attempt = |protected: &str| {
            let mut rng =
                FixedRng::new(a3::CEK.iter().chain(&a3::IV).copied().collect::<Vec<u8>>());
            encryptor.encrypt_reproducible(
                a3::PLAINTEXT,
                Serialization::Compact,
                &mut rng,
                Some(protected),
            )
        };
        for json in [
            r#"{"alg":"A128KW","enc":"A128GCM"}"#,    // another enc
            r#"{"alg":"dir","enc":"A128CBC-HS256"}"#, // another alg
            r#"{"alg":"A128KW"}"#,                    // enc missing
            r#"{"alg":"A128KW","enc":"A128CBC-HS256","zip":"DEF"}"#, // an extra member
            r#"{"alg":"A128KW","enc":"A128CBC-HS256","alg":"A128KW"}"#, // not I-JSON
        ] {
            let result = attempt(&b64url_encode(json.as_bytes()));
            assert_eq!(code(result), "InvalidFormat", "{json}");
        }
        assert_eq!(code(attempt("not base64url!")), "InvalidFormat");
        // Reordered and spaced is JSON-equal: accepted verbatim.
        let reordered = b64url_encode(br#"{ "enc":"A128CBC-HS256", "alg":"A128KW" }"#);
        let token = attempt(&reordered).unwrap_or_else(|e| panic!("{e}"));
        assert!(token.starts_with(&format!("{reordered}.")));
    }

    #[test]
    fn the_spacing_vector_is_what_the_hook_produces() {
        // Pins `SPACED` below to the library's own output.
        let json = "{\"enc\" : \"A128GCM\",\r\n  \"kid\":\"t09\" , \"alg\":\"dir\"}";
        let mut rng = FixedRng::new([0x5Au8; 12]);
        let token = Encryptor::new(E::A128GCM)
            .protected_header(kid_header("t09"))
            .recipient(Recipient::new(A::Dir, &oct(&SPACED_KEY)))
            .encrypt_reproducible(
                a3::PLAINTEXT,
                Serialization::Compact,
                &mut rng,
                Some(&b64url_encode(json.as_bytes())),
            )
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(token, SPACED);
    }
}

/// The 16-byte key of RFC 7520 §5.6, used bare for [`SPACED`].
const SPACED_KEY: [u8; 16] = [
    0x5d, 0xcb, 0x4e, 0x84, 0x90, 0x24, 0x03, 0xea, 0x43, 0xf4, 0xb8, 0x7b, 0x66, 0x05, 0xbf, 0xd8,
];

/// `dir` + A128GCM over "Live long and prosper." with the protected header
/// `{"enc" : "A128GCM",\r\n  "kid":"t09" , "alg":"dir"}`: unusual spacing,
/// a CRLF and a member order polyjose would never write. Produced by the
/// library (see `the_spacing_vector_is_what_the_hook_produces`).
const SPACED: &str = "eyJlbmMiIDogIkExMjhHQ00iLA0KICAia2lkIjoidDA5IiAsICJhbGciOiJkaXIifQ\
    ..WlpaWlpaWlpaWlpa.12LlXklK7bP-KY59qpPYVAzMFnLa-w.WgZmD7T-ESaehPF8BKfIeg";

#[test]
fn the_aad_is_the_received_protected_header() {
    // RFC 7516 §5.2 steps 14-15, erratum 8676: the AAD is the header as
    // received, never a re-serialization.
    assert_eq!(b64url_encode(&SPACED_KEY), "XctOhJAkA-pD9Lh7ZgW_2A");
    let key = oct(&SPACED_KEY);
    let p = policy(&[A::Dir], &[E::A128GCM]);
    let d = decrypt_compact(SPACED, &key, &p).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(d.plaintext(), a3::PLAINTEXT);
    let received = SPACED.split('.').next().unwrap_or_default();
    let reserialized = b64url_encode(d.header().to_json().unwrap_or_default().as_bytes());
    assert_ne!(received, reserialized);
    // The same token with the re-serialized (equivalent) header fails.
    let rest = SPACED
        .split_once('.')
        .map(|(_, rest)| rest)
        .unwrap_or_default();
    let swapped = format!("{reserialized}.{rest}");
    assert_eq!(
        code(decrypt_compact(&swapped, &key, &p)),
        "DecryptionFailed"
    );
}

// ---------------------------------------------------------------------------
// Structure (RFC 7516 §5.2 steps 1-3, §7.1; ADR 0026 §7)
// ---------------------------------------------------------------------------

#[test]
fn input_over_max_input_len_is_invalid_format_before_parsing() {
    let key = jwk(a3::KEY);
    let at_limit = a3_policy().max_input_len(a3::COMPACT.len());
    assert_eq!(code(decrypt_compact(a3::COMPACT, &key, &at_limit)), "ok");
    let below = a3_policy().max_input_len(a3::COMPACT.len() - 1);
    assert_eq!(
        code(decrypt_compact(a3::COMPACT, &key, &below)),
        "InvalidFormat"
    );
    // Garbage that would be InvalidBase64 or InvalidJson is still only
    // InvalidFormat: nothing was parsed.
    let garbage = format!("{}.!.!.!.!", "=".repeat(2000));
    let small = a3_policy().max_input_len(1000);
    assert_eq!(
        code(decrypt_compact(&garbage, &key, &small)),
        "InvalidFormat"
    );
    // The default is 1 MiB.
    let huge = format!("{}.AA.AA.AA.AA", "A".repeat(1 << 20));
    assert_eq!(
        code(decrypt_compact(&huge, &key, &a3_policy())),
        "InvalidFormat"
    );
}

#[test]
fn exactly_five_segments() {
    let key = jwk(a3::KEY);
    let parts: Vec<&str> = a3::COMPACT.split('.').collect();
    for n in 1..5 {
        assert_eq!(
            code(decrypt_compact(&parts[..n].join("."), &key, &a3_policy())),
            "InvalidFormat"
        );
    }
    let six = format!("{}.", a3::COMPACT);
    assert_eq!(
        code(decrypt_compact(&six, &key, &a3_policy())),
        "InvalidFormat"
    );
    // A JWS (three parts) is not a JWE.
    let jws = "eyJhbGciOiJIUzI1NiJ9.e30.AAAA";
    assert_eq!(
        code(decrypt_compact(jws, &key, &a3_policy())),
        "InvalidFormat"
    );
}

#[test]
fn every_segment_must_be_strict_base64url() {
    let key = jwk(a3::KEY);
    let parts: Vec<&str> = a3::COMPACT.split('.').collect();
    for i in 0..5 {
        for bad in ["AA==", "A+A/", " AAAA", "AAAA\n", "Zh"] {
            let mut p = parts.clone();
            p[i] = bad;
            let token = p.join(".");
            assert_eq!(
                code(decrypt_compact(&token, &key, &a3_policy())),
                "InvalidBase64",
                "{i} {bad:?}"
            );
        }
    }
}

#[test]
fn alg_and_enc_must_be_in_the_protected_header() {
    // RFC 7516 §7.1: the protected header is the whole JOSE Header.
    let key = jwk(a3::KEY);
    for json in [r#"{"enc":"A128CBC-HS256"}"#, r#"{"alg":"A128KW"}"#, "{}"] {
        let token = forge(json, &[0; 40], &a3::IV, &[0; 32], &[0; 16]);
        assert_eq!(
            code(decrypt_compact(&token, &key, &a3_policy())),
            "InvalidHeader",
            "{json}"
        );
    }
}

// ---------------------------------------------------------------------------
// The plan.md error contract, one test per row, through decrypt_compact.
// ---------------------------------------------------------------------------

/// An RSA public key (RFC 7516 A.1.3, `n` and `e` only).
const RSA_A1: &str = r#"{"kty":"RSA","n":"oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUWcJoZmds2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3Spsk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2asbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMStPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2djYgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw","e":"AQAB"}"#;

/// Every RSA key management `alg` there is, all listed in the policy.
fn rsa_policy() -> DecryptPolicy {
    let algs = [A::RsaOaep256, A::from("RSA-OAEP"), A::from("RSA1_5")];
    policy(&algs, ContentEncAlg::KNOWN)
}

#[test]
fn unsupported_alg_is_unsupported_even_when_allowed() {
    // ADR 0021 (no RSA private-key operation), ADR 0022 (no SHA-1): the
    // support check precedes the allow-list.
    let rsa = jwk(RSA_A1);
    let other = oct(&[1; 16]);
    let unknown = policy(&[A::from("ECDH-1PU"), A::A128KW], &[E::A128GCM]);
    for alg in ["RSA-OAEP-256", "RSA-OAEP", "RSA1_5"] {
        let token = forge(
            &format!(r#"{{"alg":"{alg}","enc":"A128GCM"}}"#),
            &[1; 256],
            &[0; 12],
            &[0; 4],
            &[0; 16],
        );
        for key in [&rsa, &other] {
            assert_eq!(
                code(decrypt_compact(&token, key, &rsa_policy())),
                "UnsupportedAlgorithm",
                "{alg}"
            );
        }
    }
    let token = forge(
        r#"{"alg":"ECDH-1PU","enc":"A128GCM"}"#,
        &[],
        &[0; 12],
        &[0; 4],
        &[0; 16],
    );
    assert_eq!(
        code(decrypt_compact(&token, &other, &unknown)),
        "UnsupportedAlgorithm"
    );
    let token = forge(
        r#"{"alg":"A128KW","enc":"A128CTR"}"#,
        &[0; 24],
        &[0; 12],
        &[0; 4],
        &[0; 16],
    );
    assert_eq!(
        code(decrypt_compact(&token, &other, &unknown)),
        "UnsupportedAlgorithm"
    );
}

/// RFC 7516 A.1 (RSA-OAEP + A256GCM) and A.2 (RSA1_5 + A128CBC-HS256),
/// RFC 7520 §5.1 (RSA1_5) and §5.2 (RSA-OAEP), with each RFC's own public
/// key, are refused before any cryptography (ADRs 0021, 0022).
#[test]
fn rfc_rsa_vectors_are_unsupported() {
    let tokens = [
        (RFC_7516_A1, RSA_A1),
        (RFC_7516_A2, RSA_A2),
        (RFC_7520_5_1, RSA_5_1),
        (RFC_7520_5_2, RSA_5_2),
    ];
    for (token, key) in tokens {
        assert_eq!(token.split('.').count(), 5);
        assert_eq!(
            code(decrypt_compact(token, &jwk(key), &rsa_policy())),
            "UnsupportedAlgorithm"
        );
    }
}

#[test]
fn not_allowed_alg_or_enc_is_algorithm_not_allowed() {
    let key = jwk(a3::KEY);
    let only_dir = policy(&[A::Dir], &[E::A128CbcHs256]);
    assert_eq!(
        code(decrypt_compact(a3::COMPACT, &key, &only_dir)),
        "AlgorithmNotAllowed"
    );
    let only_gcm = policy(&[A::A128KW], &[E::A128GCM]);
    assert_eq!(
        code(decrypt_compact(a3::COMPACT, &key, &only_gcm)),
        "AlgorithmNotAllowed"
    );
}

#[test]
fn wrong_key_family_is_key_algorithm_mismatch() {
    let p = a3_policy();
    // An EC key, an RSA key, a 32-byte oct key, and an oct key whose JWK
    // alg, use or key_ops forbid A128KW unwrapping.
    let ec = jwk(
        r#"{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"}"#,
    );
    let k = "GawgguFyGrWKav7AX4VKUg";
    let keys = [
        ec,
        jwk(RSA_A1),
        oct(&[1; 32]),
        jwk(&format!(r#"{{"kty":"oct","k":"{k}","alg":"A256KW"}}"#)),
        jwk(&format!(r#"{{"kty":"oct","k":"{k}","use":"sig"}}"#)),
        jwk(&format!(
            r#"{{"kty":"oct","k":"{k}","key_ops":["wrapKey"]}}"#
        )),
    ];
    for key in &keys {
        assert_eq!(
            code(decrypt_compact(a3::COMPACT, key, &p)),
            "KeyAlgorithmMismatch",
            "{key:?}"
        );
    }
    let ops = jwk(&format!(
        r#"{{"kty":"oct","k":"{k}","key_ops":["unwrapKey"],"use":"enc","alg":"A128KW"}}"#
    ));
    assert_eq!(code(decrypt_compact(a3::COMPACT, &ops, &p)), "ok");
}

#[test]
fn kid_mismatch_is_not_a_candidate() {
    // plan.md recipient selection: kid narrows the candidates when both
    // the header and the key carry one (RFC 7516 §4.1.6).
    let p = policy(&[A::A128KW], &[E::A128GCM]);
    let k = "GZy6sIZ6wl9NJOKB-jnmVQ";
    let other = jwk(&format!(
        r#"{{"kty":"oct","k":"{k}","kid":"someone-else"}}"#
    ));
    assert_eq!(
        code(decrypt_compact(c58::COMPACT, &other, &p)),
        "KeyAlgorithmMismatch"
    );
    let none = jwk(&format!(r#"{{"kty":"oct","k":"{k}"}}"#));
    assert_eq!(code(decrypt_compact(c58::COMPACT, &none, &p)), "ok");
}

#[test]
fn unknown_crit_is_unknown_critical() {
    // RFC 7516 §4.1.13 (RFC 7515 §4.1.11), §5.2 step 5.
    let key = jwk(a3::KEY);
    let json = r#"{"alg":"A128KW","enc":"A128CBC-HS256","crit":["x-ext"],"x-ext":true}"#;
    let token = forge(json, &[0; 40], &a3::IV, &[0; 32], &[0; 16]);
    assert_eq!(
        code(decrypt_compact(&token, &key, &a3_policy())),
        "UnknownCritical"
    );
    // Understood, it gets as far as the cryptography (a forged tag).
    let understood = a3_policy().understood_crit(&["x-ext"]);
    assert_eq!(
        code(decrypt_compact(&token, &key, &understood)),
        "DecryptionFailed"
    );
    // crit before the support check: an unsupported alg with an unknown
    // crit is UnknownCritical.
    let json = r#"{"alg":"RSA1_5","enc":"A128CBC-HS256","crit":["x-ext"],"x-ext":true}"#;
    let token = forge(json, &[0; 40], &a3::IV, &[0; 32], &[0; 16]);
    assert_eq!(
        code(decrypt_compact(&token, &key, &rsa_policy())),
        "UnknownCritical"
    );
}

#[test]
fn header_structure_errors() {
    let key = jwk(a3::KEY);
    let at = |json: &str| {
        let token = forge(json, &[0; 40], &a3::IV, &[0; 32], &[0; 16]);
        code(decrypt_compact(&token, &key, &a3_policy()))
    };
    // ADR 0041 §1: a duplicate member is InvalidJson, at any depth.
    assert_eq!(
        at(r#"{"alg":"A128KW","enc":"A128CBC-HS256","alg":"A128KW"}"#),
        "InvalidJson"
    );
    assert_eq!(
        at(r#"{"alg":"A128KW","enc":"A128CBC-HS256","x":{"a":1,"a":1}}"#),
        "InvalidJson"
    );
    // Valid JSON that is not an object is InvalidJson, as for JWS
    // (ADR 0026 §2 step 4): `[1]` (WzFd) and `""` (IiI) among them.
    for json in [r#"["alg","A128KW"]"#, "[1]", r#""""#, "null", "7"] {
        assert_eq!(at(json), "InvalidJson", "{json}");
    }
    for protected in ["WzFd", "IiI"] {
        let token = format!("{protected}..AAAA.AAAA.AAAA");
        assert_eq!(
            code(decrypt_compact(&token, &key, &a3_policy())),
            "InvalidJson",
            "{protected}"
        );
    }
    // A registered parameter of the wrong type.
    assert_eq!(
        at(r#"{"alg":"A128KW","enc":"A128CBC-HS256","kid":7}"#),
        "InvalidHeader"
    );
    assert_eq!(
        at(r#"{"alg":"A128KW","enc":"A128CBC-HS256","crit":[]}"#),
        "InvalidHeader"
    );
    assert_eq!(
        at(r#"{"alg":"A128KW","enc":"A128CBC-HS256","crit":["x-a"]}"#),
        "InvalidHeader"
    );
    // A compact JWE has only the protected header, so the three-part
    // disjointness rule (RFC 7516 §7.2.1) cannot be broken here; it is
    // unit-tested in src/jwe/core.rs and exercised by T14's JSON vectors.
}

#[test]
fn zip_without_support_is_unsupported() {
    // RFC 7516 §4.1.3; ADR 0017: DEF only with the `deflate` feature.
    let key = jwk(a3::KEY);
    let token = forge(
        r#"{"alg":"A128KW","enc":"A128CBC-HS256","zip":"GZIP"}"#,
        &[0; 40],
        &a3::IV,
        &[0; 32],
        &[0; 16],
    );
    assert_eq!(
        code(decrypt_compact(&token, &key, &a3_policy())),
        "UnsupportedAlgorithm"
    );
    let token = forge(
        r#"{"alg":"A128KW","enc":"A128CBC-HS256","zip":"DEF"}"#,
        &[0; 40],
        &a3::IV,
        &[0; 32],
        &[0; 16],
    );
    let expected = if cfg!(feature = "deflate") {
        "DecryptionFailed"
    } else {
        "UnsupportedAlgorithm"
    };
    assert_eq!(code(decrypt_compact(&token, &key, &a3_policy())), expected);
}

// ---------------------------------------------------------------------------
// The uniform DecryptionFailed (RFC 7516 §11.4-§11.5)
// ---------------------------------------------------------------------------

fn tamper(token: &str, part: usize, edit: impl Fn(&mut Vec<u8>)) -> String {
    let mut parts: Vec<String> = token.split('.').map(str::to_owned).collect();
    let mut bytes = b64url_decode(&parts[part]).unwrap_or_else(|e| panic!("{e}"));
    edit(&mut bytes);
    parts[part] = b64url_encode(&bytes);
    parts.join(".")
}

#[test]
fn every_post_key_management_failure_is_one_indistinguishable_error() {
    let a3_key = jwk(a3::KEY);
    let a3p = a3_policy();
    let dir_key = jwk(c56::KEY);
    let dirp = policy(&[A::Dir], &[E::A128GCM]);
    let flip = |b: &mut Vec<u8>| b[0] ^= 0x01;
    let wrong16 = oct(&[7; 16]);
    let wrong32 = oct(&[7; 32]);
    let cases: Vec<(&str, String, &Jwk, &DecryptPolicy)> = vec![
        ("tag", tamper(a3::COMPACT, 4, flip), &a3_key, &a3p),
        ("ciphertext", tamper(a3::COMPACT, 3, flip), &a3_key, &a3p),
        ("iv", tamper(a3::COMPACT, 2, flip), &a3_key, &a3p),
        ("encrypted key", tamper(a3::COMPACT, 1, flip), &a3_key, &a3p),
        (
            "protected header",
            tamper(a3::COMPACT, 0, |b| b.insert(1, b' ')),
            &a3_key,
            &a3p,
        ),
        (
            "truncated iv",
            tamper(a3::COMPACT, 2, |b| b.truncate(15)),
            &a3_key,
            &a3p,
        ),
        (
            "truncated tag",
            tamper(a3::COMPACT, 4, |b| b.truncate(15)),
            &a3_key,
            &a3p,
        ),
        (
            "empty tag",
            tamper(a3::COMPACT, 4, Vec::clear),
            &a3_key,
            &a3p,
        ),
        (
            "extended tag",
            tamper(a3::COMPACT, 4, |b| b.push(0)),
            &a3_key,
            &a3p,
        ),
        (
            "short encrypted key",
            tamper(a3::COMPACT, 1, |b| b.truncate(32)),
            &a3_key,
            &a3p,
        ),
        ("wrong key", a3::COMPACT.to_owned(), &wrong16, &a3p),
        ("gcm tag", tamper(c56::COMPACT, 4, flip), &dir_key, &dirp),
        (
            "gcm iv",
            tamper(c56::COMPACT, 2, |b| b.truncate(11)),
            &dir_key,
            &dirp,
        ),
        (
            "dir with a non-empty encrypted key",
            tamper(c56::COMPACT, 1, |b| b.extend_from_slice(&[0; 16])),
            &dir_key,
            &dirp,
        ),
        (
            "dir key of the wrong length",
            c56::COMPACT.to_owned(),
            &wrong32,
            &dirp,
        ),
        ("dir wrong key", c56::COMPACT.to_owned(), &wrong16, &dirp),
    ];
    for (what, token, key, p) in &cases {
        let e = decrypt_compact(token, key, p).map(|_| ()).unwrap_err();
        assert_eq!(e, Error::DecryptionFailed, "{what}");
        assert_eq!(format!("{e:?}"), "DecryptionFailed", "{what}");
        assert_eq!(e.to_string(), "decryption failed", "{what}");
        assert!(std::error::Error::source(&e).is_none(), "{what}");
    }
}

// ---------------------------------------------------------------------------
// Encrypt
// ---------------------------------------------------------------------------

#[test]
fn encrypt_refuses_what_compact_cannot_carry() {
    // RFC 7516 §7.1: one recipient, a protected header only, no JWE AAD.
    let key = oct(&[1; 16]);
    let one = Encryptor::new(E::A128GCM).recipient(Recipient::new(A::A128KW, &key));
    assert_eq!(code(one.encrypt_compact(b"x")), "ok");
    let header = kid_header("a");
    let cases = [
        one.clone().recipient(Recipient::new(A::A128KW, &key)),
        one.clone().aad(*b"aad"),
        one.clone().shared_unprotected_header(header.clone()),
        Encryptor::new(E::A128GCM).recipient(Recipient::new(A::A128KW, &key).header(header)),
        Encryptor::new(E::A128GCM),
    ];
    for e in &cases {
        assert_eq!(code(e.encrypt_compact(b"x")), "InvalidFormat", "{e:?}");
    }
    // Zero recipients and `dir` with more than one are refused in JSON too
    // (the JSON writer is T14's; the pipeline refuses first).
    assert_eq!(
        code(Encryptor::new(E::A128GCM).encrypt_json(b"x", JsonForm::General)),
        "InvalidFormat"
    );
    let dir = Encryptor::new(E::A128GCM)
        .recipient(Recipient::new(A::Dir, &key))
        .recipient(Recipient::new(A::Dir, &key));
    assert_eq!(
        code(dir.encrypt_json(b"x", JsonForm::General)),
        "InvalidFormat"
    );
}

#[test]
fn encrypt_refuses_unsupported_algorithms_and_unusable_keys() {
    let key = oct(&[1; 16]);
    let to =
        |alg: KeyMgmtAlg, key: &Jwk| Encryptor::new(E::A128GCM).recipient(Recipient::new(alg, key));
    for alg in ["RSA-OAEP", "RSA1_5", "nope"] {
        assert_eq!(
            code(to(A::from(alg), &key).encrypt_compact(b"x")),
            "UnsupportedAlgorithm",
            "{alg}"
        );
    }
    assert_eq!(
        code(to(A::A256KW, &key).encrypt_compact(b"x")),
        "InvalidKey"
    );
    assert_eq!(
        code(to(A::Dir, &oct(&[1; 32])).encrypt_compact(b"x")),
        "InvalidKey"
    );
    assert_eq!(
        code(to(A::A128KW, &jwk(RSA_A1)).encrypt_compact(b"x")),
        "KeyAlgorithmMismatch"
    );
    let protected = to(A::A128KW, &key)
        .protected_header(Header::from_json(br#"{"alg":"dir"}"#).unwrap_or_else(|e| panic!("{e}")));
    assert_eq!(code(protected.encrypt_compact(b"x")), "InvalidHeader");
}

#[test]
fn encryptions_are_randomized() {
    // ADR 0005: a fresh CEK and IV from the OS CSPRNG each time.
    let key = oct(&[1; 16]);
    let e = Encryptor::new(E::A128GCM).recipient(Recipient::new(A::A128KW, &key));
    let a = e.encrypt_compact(b"same").unwrap_or_else(|e| panic!("{e}"));
    let b = e.encrypt_compact(b"same").unwrap_or_else(|e| panic!("{e}"));
    assert_ne!(a, b);
    let parts = |t: &str| t.split('.').map(str::to_owned).collect::<Vec<_>>();
    let (pa, pb) = (parts(&a), parts(&b));
    assert_eq!(pa[0], pb[0]);
    assert_ne!(pa[1], pb[1]);
    assert_ne!(pa[2], pb[2]);
}

// ---------------------------------------------------------------------------
// Property: compact round trip of dir and A*KW over every enc.
// ---------------------------------------------------------------------------

fn alg_strategy() -> impl Strategy<Value = KeyMgmtAlg> {
    prop_oneof![
        Just(A::Dir),
        Just(A::A128KW),
        Just(A::A192KW),
        Just(A::A256KW)
    ]
}

fn enc_strategy() -> impl Strategy<Value = ContentEncAlg> {
    proptest::sample::select(ContentEncAlg::KNOWN.to_vec())
}

fn key_len(alg: &KeyMgmtAlg, enc: &ContentEncAlg) -> usize {
    match alg {
        A::A128KW => 16,
        A::A192KW => 24,
        A::A256KW => 32,
        _ => match enc {
            E::A128CbcHs256 => 32,
            E::A192CbcHs384 => 48,
            E::A256CbcHs512 => 64,
            E::A128GCM => 16,
            E::A192GCM => 24,
            _ => 32,
        },
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn compact_round_trips(
        alg in alg_strategy(),
        enc in enc_strategy(),
        seed in proptest::collection::vec(any::<u8>(), 64),
        plaintext in proptest::collection::vec(any::<u8>(), 0..300),
    ) {
        let key = oct(&seed[..key_len(&alg, &enc)]);
        let token = Encryptor::new(enc.clone())
            .recipient(Recipient::new(alg.clone(), &key))
            .encrypt_compact(&plaintext)
            .unwrap_or_else(|e| panic!("{alg} {enc}: {e}"));
        let p = policy(std::slice::from_ref(&alg), std::slice::from_ref(&enc));
        let d = decrypt_compact(&token, &key, &p).unwrap_or_else(|e| panic!("{alg} {enc}: {e}"));
        prop_assert_eq!(d.plaintext(), plaintext.as_slice());
        prop_assert_eq!(d.header().alg.as_deref(), Some(alg.as_str()));
        prop_assert_eq!(d.header().enc.as_ref(), Some(&enc));
        // One flipped tag bit is DecryptionFailed.
        let mut parts: Vec<String> = token.split('.').map(str::to_owned).collect();
        let mut tag = b64url_decode(&parts[4]).unwrap_or_else(|e| panic!("{e}"));
        tag[0] ^= 0x80;
        parts[4] = b64url_encode(&tag);
        let tampered = parts.join(".");
        prop_assert_eq!(decrypt_compact(&tampered, &key, &p).map(|_| ()), Err(Error::DecryptionFailed));
    }
}

// ---------------------------------------------------------------------------
// RSA vectors (refused; kept verbatim from the RFCs)
// ---------------------------------------------------------------------------

/// RFC 7516 A.2.3: the RSA public key (`n` and `e`).
const RSA_A2: &str = r#"{"kty":"RSA","n":"sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw","e":"AQAB"}"#;

/// RFC 7520 §5.1.1, Figure 73: the public part.
const RSA_5_1: &str = r#"{"kty":"RSA","kid":"frodo.baggins@hobbiton.example","use":"enc","n":"maxhbsmBtdQ3CNrKvprUE6n9lYcregDMLYNeTAWcLj8NnPU9XIYegTHVHQjxKDSHP2l-F5jS7sppG1wgdAqZyhnWvXhYNvcM7RfgKxqNx_xAHx6f3yy7s-M9PSNCwPC2lh6UAkR4I00EhV9lrypM9Pi4lBUop9t5fS9W5UNwaAllhrd-osQGPjIeI1deHTwx-ZTHu3C60Pu_LJIl6hKn9wbwaUmA4cR5Bd2pgbaY7ASgsjCUbtYJaNIHSoHXprUdJZKUMAzV0WOKPfA6OPI4oypBadjvMZ4ZAj3BnXaSYsEZhaueTXvZB4eZOAjIyh2e_VOIKVMsnDrJYAVotGlvMQ","e":"AQAB"}"#;

/// RFC 7520 §5.2.1, Figure 84: the public part.
const RSA_5_2: &str = r#"{"kty":"RSA","kid":"samwise.gamgee@hobbiton.example","use":"enc","n":"wbdxI55VaanZXPY29Lg5hdmv2XhvqAhoxUkanfzf2-5zVUxa6prHRrI4pP1AhoqJRlZfYtWWd5mmHRG2pAHIlh0ySJ9wi0BioZBl1XP2e-C-FyXJGcTy0HdKQWlrfhTm42EW7Vv04r4gfao6uxjLGwfpGrZLarohiWCPnkNrg71S2CuNZSQBIPGjXfkmIy2tl_VWgGnL22GplyXj5YlBLdxXp3XeStsqo571utNfoUTU8E4qdzJ3U1DItoVkPGsMwlmmnJiwA7sXRItBCivR4M5qnZtdw-7v4WuR4779ubDuJ5nalMv2S66-RPcnFAzWSKxtBDnFJJDGIUe7Tzizjg1nms0Xq_yPub_UOlWn0ec85FCft1hACpWG8schrOBeNqHBODFskYpUc2LC5JA2TaPF2dA67dg1TTsC_FupfQ2kNGcE1LgprxKHcVWYQb86B-HozjHZcqtauBzFNV5tbTuB-TpkcvJfNcFLlH3b8mb-H_ox35FjqBSAjLKyoeqfKTpVjvXhd09knwgJf6VKq6UC418_TOljMVfFTWXUxlnfhOOnzW6HSSzD1c9WrCuVzsUMv54szidQ9wf1cYWf3g5qFDxDQKis99gcDaiCAwM3yEBIzuNeeCa5dartHDb1xEB_HcHSeYbghbMjGfasvKn0aZRsnTyC0xhWBlsolZE","e":"AQAB"}"#;

/// RFC 7516 A.1.7 (RSA-OAEP + A256GCM).
const RFC_7516_A1: &str = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg.48V1_ALb6US04U3b.5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A.XFBoMYUZodetZdvTiFvSkQ";

/// RFC 7516 A.2.7 (RSA1_5 + A128CBC-HS256).
const RFC_7516_A2: &str = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A.AxY8DCtDaGlsbGljb3RoZQ.KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.9hH0vgRfYgPnAHOd8stkvw";

/// RFC 7520 §5.1.5, Figure 81 (RSA1_5 + A128CBC-HS256).
const RFC_7520_5_1: &str = "eyJhbGciOiJSU0ExXzUiLCJraWQiOiJmcm9kby5iYWdnaW5zQGhvYmJpdG9uLmV4YW1wbGUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.laLxI0j-nLH-_BgLOXMozKxmy9gffy2gTdvqzfTihJBuuzxg0V7yk1WClnQePFvG2K-pvSlWc9BRIazDrn50RcRai__3TDON395H3c62tIouJJ4XaRvYHFjZTZ2GXfz8YAImcc91Tfk0WXC2F5Xbb71ClQ1DDH151tlpH77f2ff7xiSxh9oSewYrcGTSLUeeCt36r1Kt3OSj7EyBQXoZlN7IxbyhMAfgIe7Mv1rOTOI5I8NQqeXXW8VlzNmoxaGMny3YnGir5Wf6Qt2nBq4qDaPdnaAuuGUGEecelIO1wx1BpyIfgvfjOhMBs9M8XL223Fg47xlGsMXdfuY-4jaqVw.bbd5sTkYwhAIqfHsx8DayA.0fys_TY_na7f8dwSfXLiYdHaA2DxUjD67ieF7fcVbIR62JhJvGZ4_FNVSiGc_raa0HnLQ6s1P2sv3Xzl1p1l_o5wR_RsSzrS8Z-wnI3Jvo0mkpEEnlDmZvDu_k8OWzJv7eZVEqiWKdyVzFhPpiyQU28GLOpRc2VbVbK4dQKPdNTjPPEmRqcaGeTWZVyeSUvf5k59yJZxRuSvWFf6KrNtmRdZ8R4mDOjHSrM_s8uwIFcqt4r5GX8TKaI0zT5CbL5Qlw3sRc7u_hg0yKVOiRytEAEs3vZkcfLkP6nbXdC_PkMdNS-ohP78T2O6_7uInMGhFeX4ctHG7VelHGiT93JfWDEQi5_V9UN1rhXNrYu-0fVMkZAKX3VWi7lzA6BP430m.kvKuFBXHe5mQr4lqgobAUg";

/// RFC 7520 §5.2.5, Figure 92 (RSA-OAEP + A256GCM).
const RFC_7520_5_2: &str = "eyJhbGciOiJSU0EtT0FFUCIsImtpZCI6InNhbXdpc2UuZ2FtZ2VlQGhvYmJpdG9uLmV4YW1wbGUiLCJlbmMiOiJBMjU2R0NNIn0.rT99rwrBTbTI7IJM8fU3Eli7226HEB7IchCxNuh7lCiud48LxeolRdtFF4nzQibeYOl5S_PJsAXZwSXtDePz9hk-BbtsTBqC2UsPOdwjC9NhNupNNu9uHIVftDyucvI6hvALeZ6OGnhNV4v1zx2k7O1D89mAzfw-_kT3tkuorpDU-CpBENfIHX1Q58-Aad3FzMuo3Fn9buEP2yXakLXYa15BUXQsupM4A1GD4_H4Bd7V3u9h8Gkg8BpxKdUV9ScfJQTcYm6eJEBz3aSwIaK4T3-dwWpuBOhROQXBosJzS1asnuHtVMt2pKIIfux5BC6huIvmY7kzV7W7aIUrpYm_3H4zYvyMeq5pGqFmW2k8zpO878TRlZx7pZfPYDSXZyS0CfKKkMozT_qiCwZTSz4duYnt8hS4Z9sGthXn9uDqd6wycMagnQfOTs_lycTWmY-aqWVDKhjYNRf03NiwRtb5BE-tOdFwCASQj3uuAgPGrO2AWBe38UjQb0lvXn1SpyvYZ3WFc7WOJYaTa7A8DRn6MC6T-xDmMuxC0G7S2rscw5lQQU06MvZTlFOt0UvfuKBa03cxA_nIBIhLMjY2kOTxQMmpDPTr6Cbo8aKaOnx6ASE5Jx9paBpnNmOOKH35j_QlrQhDWUN6A2Gg8iFayJ69xDEdHAVCGRzN3woEI2ozDRs.-nBoKLH0YkLZPSI9.o4k2cnGN8rSSw3IDo1YuySkqeS_t2m1GXklSgqBdpACm6UJuJowOHC5ytjqYgRL-I-soPlwqMUf4UgRWWeaOGNw6vGW-xyM01lTYxrXfVzIIaRdhYtEMRBvBWbEwP7ua1DRfvaOjgZv6Ifa3brcAM64d8p5lhhNcizPersuhw5f-pGYzseva-TUaL8iWnctc-sSwy7SQmRkfhDjwbz0fz6kFovEgj64X1I5s7E6GLp5fnbYGLa1QUiML7Cc2GxgvI7zqWo0YIEc7aCflLG1-8BboVWFdZKLK9vNoycrYHumwzKluLWEbSVmaPpOslY2n525DxDfWaVFUfKQxMF56vn4B9QMpWAbnypNimbM8zVOw.UCGiqJxhBI3IFVdPalHHvA";
