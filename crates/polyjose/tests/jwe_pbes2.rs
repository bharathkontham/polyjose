//! PBES2-HS256+A128KW, PBES2-HS384+A192KW and PBES2-HS512+A256KW through
//! the public API (0003 T12): RFC 7518 §4.8, ADR 0023 and the plan.md error
//! contract.
//!
//! - RFC 7520 §5.3 (read from the vendored ietf-jose cookbook) and RFC 7517
//!   Appendix C decrypt with their passwords, and (with
//!   `insecure-test-vectors`) `encrypt_reproducible` reproduces both
//!   compact strings byte for byte from their CEK, `p2s` and IV.
//! - Every `p2s`/`p2c` fault is `DecryptionFailed`, the same error as a
//!   wrong password or a bad tag; `p2c = 2^32 - 1` returns at once (RFC
//!   7518 §8.8; CVE-2022-36083, CVE-2023-52428, CVE-2023-51775). That PBKDF2
//!   never runs is asserted by the unit tests in `jwe/pbes2.rs` with the
//!   `pbkdf2_derivations` counter; there are no timing assertions here.
//! - Encrypt emits `p2s` (16 random octets) and `p2c` (10,000) by default
//!   and refuses weak parameters with `InvalidKey`.
#![allow(clippy::panic)] // test code: a panic is a failed assertion

use polyjose::Error;
use polyjose::header::Header;
use polyjose::json::{self, Value};
use polyjose::jwa::{ContentEncAlg, KeyMgmtAlg};
use polyjose::jwe::{DecryptPolicy, Decrypted, Encryptor, Recipient, decrypt_compact};
use polyjose::jwk::Jwk;
use polyjose::util::{b64url_decode, b64url_encode};
use proptest::prelude::*;

use ContentEncAlg as E;
use KeyMgmtAlg as A;

/// The three PBES2 algorithms (RFC 7518 §4.8).
const FAMILY: [KeyMgmtAlg; 3] = [
    A::Pbes2Hs256A128KW,
    A::Pbes2Hs384A192KW,
    A::Pbes2Hs512A256KW,
];

/// A PBES2 password as an `oct` JWK: the password octets are `k` (RFC 7518
/// §4.8, §6.4).
fn password(pw: &[u8]) -> Jwk {
    let json = format!(r#"{{"kty":"oct","k":"{}"}}"#, b64url_encode(pw));
    Jwk::from_json(json.as_bytes()).unwrap_or_else(|e| panic!("{e}"))
}

fn policy(algs: &[KeyMgmtAlg], encs: &[ContentEncAlg]) -> DecryptPolicy {
    DecryptPolicy::new(algs, encs).unwrap_or_else(|e| panic!("{e}"))
}

fn family_policy() -> DecryptPolicy {
    policy(&FAMILY, E::KNOWN)
}

fn code<T>(result: &polyjose::Result<T>) -> &'static str {
    match result {
        Ok(_) => "ok",
        Err(e) => e.code(),
    }
}

fn bytes(b64u: &str) -> Vec<u8> {
    b64url_decode(b64u).unwrap_or_else(|e| panic!("{e}"))
}

/// `token` with its protected header replaced by `header_json` (RFC 7516
/// §7.1); the other four parts are unchanged.
fn with_header(token: &str, header_json: &str) -> String {
    let mut parts: Vec<String> = token.split('.').map(str::to_owned).collect();
    parts[0] = b64url_encode(header_json.as_bytes());
    parts.join(".")
}

/// `token` with one bit of its authentication tag flipped.
fn with_bad_tag(token: &str) -> String {
    let mut parts: Vec<String> = token.split('.').map(str::to_owned).collect();
    let mut tag = bytes(&parts[4]);
    tag[0] ^= 1;
    parts[4] = b64url_encode(&tag);
    parts.join(".")
}

// ---------------------------------------------------------------------------
// RFC values
// ---------------------------------------------------------------------------

/// RFC 7520 §5.3 (PBES2-HS512+A256KW + A128CBC-HS256, p2c 8192), read from
/// the vendored ietf-jose cookbook (Unlicense), never transcribed.
mod c53 {
    use super::*;

    const COOKBOOK: &str = include_str!(
        "third_party/ietf-jose-cookbook/jwe/5_3.key_wrap_using_pbes2-aes-keywrap_with-aes-cbc-hmac-sha2.json"
    );

    pub struct Example {
        pub plaintext: Vec<u8>,
        pub password: Vec<u8>,
        #[cfg_attr(
            not(feature = "insecure-test-vectors"),
            allow(dead_code, reason = "drawn by the reproducible tests only")
        )]
        pub cek: Vec<u8>,
        #[cfg_attr(
            not(feature = "insecure-test-vectors"),
            allow(dead_code, reason = "drawn by the reproducible tests only")
        )]
        pub p2s: Vec<u8>,
        #[cfg_attr(
            not(feature = "insecure-test-vectors"),
            allow(dead_code, reason = "drawn by the reproducible tests only")
        )]
        pub iv: Vec<u8>,
        pub p2c: u64,
        pub protected_b64u: String,
        pub compact: String,
    }

    fn str_at<'a>(v: &'a Value, path: &[&str]) -> &'a str {
        let mut at = v;
        for name in path {
            at = at
                .get(name)
                .unwrap_or_else(|| panic!("cookbook: no {path:?}"));
        }
        at.as_str()
            .unwrap_or_else(|| panic!("cookbook: {path:?} not a string"))
    }

    pub fn example() -> Example {
        let v = json::parse(COOKBOOK.as_bytes()).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(str_at(&v, &["input", "alg"]), "PBES2-HS512+A256KW");
        assert_eq!(str_at(&v, &["input", "enc"]), "A128CBC-HS256");
        let p2c = v
            .get("encrypting_key")
            .and_then(|k| k.get("iteration_count"))
            .and_then(Value::as_u64)
            .unwrap_or_else(|| panic!("cookbook: no iteration_count"));
        let p2s = str_at(&v, &["encrypting_key", "salt"]);
        assert_eq!(str_at(&v, &["encrypting_content", "protected", "p2s"]), p2s);
        Example {
            plaintext: str_at(&v, &["input", "plaintext"]).as_bytes().to_vec(),
            password: str_at(&v, &["input", "pwd"]).as_bytes().to_vec(),
            cek: bytes(str_at(&v, &["generated", "cek"])),
            p2s: bytes(p2s),
            iv: bytes(str_at(&v, &["generated", "iv"])),
            p2c,
            protected_b64u: str_at(&v, &["encrypting_content", "protected_b64u"]).to_owned(),
            compact: str_at(&v, &["output", "compact"]).to_owned(),
        }
    }
}

/// RFC 7517 Appendix C: PBES2-HS256+A128KW + A128CBC-HS256, p2c 4096. The
/// values were extracted from the RFC text by a script that cross-checks
/// its sections (C.2, C.5, C.6 and C.8 against C.9; C.1 octets against
/// the displayed JWK; C.4 against Python's `hashlib.pbkdf2_hmac`).
mod appendix_c {
    /// C.4: the passphrase.
    pub const PASSWORD: &str = "Thus from my lips, by yours, my sin is purged.";
    /// C.1: the plaintext octets (the RSA private key JWK), base64url.
    pub const PLAINTEXT_B64U: &str = "eyJrdHkiOiJSU0EiLCJraWQiOiJqdWxpZXRAY2FwdWxldC5saXQiLCJ1c2UiOiJlbmMiLCJuIjoidDZROFBXU2kx\
        ZGtKajloVFA4aE5ZRmx2YWRNN0RmbFc5bVdlcE9KaEo2Nnc3bnlvSzFnUE5xRk1TUVJ5TzEyNUdwLVRFa29kaFdy\
        MGl1ampIVng3QmNWMGxsUzR3NUFDR2dQcmNBZDZaY1NSMC1JcW9tLVFGY05QOFNqZzA4Nk13b3FRVV9MWXl3bEFH\
        WjIxV1NkU19QRVJ5R0ZpTm5qM1FRbE84WW5zNWpDdExDUndMSEwwUGIxZkV2NDVBdVJJdVVmVmNQeVNCV1luRHlH\
        eHZqWUdEU00tQXFXUzl6SVEyWmlsZ1QtR3FVbWlwZzBYT0MwQ2MyMHJnTGUyeW1MSGpwSGNpQ0tWQWJZNS1MMzIt\
        bFNlWk8tT3M2VTE1X2FYcms5R3c4Y1BVYVgxX0k4c0xHdVNpVmR0M0NfRm4yUFozWjhpNzQ0RlBGR0djRzFxczJX\
        ei1RIiwiZSI6IkFRQUIiLCJkIjoiR1J0YklRbWhPWnR5c3pmZ0tkZzR1X04tUl9tWkdVXzlrN0pRX2puMURuZlR1\
        TWRTTnByVGVhU1R5V2ZTTmt1YUF3bk9FYklRVnkxSVFiV1ZWMjVOWTN5YmNfSWhVSnRmcmk3YkFYWUVSZVdhQ2wz\
        aGRsUEtYeTlVdnFQWUdSMGtJWFRRUnFucy1kVko3amFobEk3THlja3JwVG1yTThkV0JvNF9QTWFlbk5uUGlRZ08w\
        eG51VG94dXRSWkpmSnZHNE94NGthM0dPUlFkOUNzQ1oydnNVRG1zWE9mVUVOT3lNcUFEQzZwMU0zaDMzdHN1clkx\
        NWs5cU1TcEc5T1hfSUpBWG14ekFoX3RXaVpPd2sySzR5eEg5dFMzTHExeVg4QzFFV21lUkRrSzJhaGVjRzg1LW9M\
        S1F0NVZFcFdIS21qT2lfZ0pTZFNncWNOOTZYNTJlc0FRIiwicCI6IjJyblNPVjRoS1NOOHNTNENnY1FIRmJzMDhY\
        Ym9GRHFLdW0zc2M0aDNHUnhyVG1RZGwxWks5dXctUElIZlFQMEZreFhWcngtV0UtWkVicnFpdkhfMmlDTFVTN3dB\
        bDZYdkFSdDFLa0lhVXhQUFNZQjl5azMxczBROFVLOTZFM19PckFEQVl0QUpzLU0zSnhDTGZOZ3FoNTZIRG5FVFRR\
        aEgzckNUNVQzeUp3cyIsInEiOiIxdV9SaUZEUDdMQlloM040R1hMVDlPcFNLWVAwdVFaeWlhWndCdE9DQk5KZ1F4\
        YWoxMFJXanNadTBjNkllZGlzNFM3Ql9jb1NLQjBLajlQYVBhQnpnLUl5U1J2dmNRdVBhbVF1NjZyaU1oalZ0RzZU\
        bFY4Q0xDWUtyWWw1MnppcUswRV95bTJRbmt3c1VYN2VZVEI3TGJBSFJLOUdxb2NERTVCMGY4MDhJNHMiLCJkcCI6\
        IktrTVRXcUJVZWZWd1oyX0RiajFwUFFxeUhTSGpqOTBMNXhfTU96cVlBSk1jTE1adGJVdHdLcXZWRHEzdGJFbzNa\
        SWNvaGJEdHQ2U2JmbVd6Z2dhYnBReE54dUJwb09PZl9hX0hnTVhLX2xocWlnSTR5X2txUzF3WTUySXdqVW41cmdS\
        ckoteVlvMWg0MUtSLXZ6MnBZaEVBZVlyaHR0V3R4VnFMQ1JWaUQ2YyIsImRxIjoiQXZmUzAtZ1J4dm4wYndKb01T\
        bkZ4WWNLMVdudUVqUUZsdU1HZndHaXRRQld0ZloxRXI3dDF4RGtiTjlHUVRCOXlxcERvWWFOMDZIN0NGdHJreGhK\
        SUJRYWo2bmtGNUtLUzNUUXRRNXFDemtPa214SWUzS1JiQnltWHhrYjVxd1VwWDVFTEQ1eEZjNkZlaWFmV1lZNjNU\
        bW1FQXVfbFJGQ09KM3hEZWEtb3RzIiwicWkiOiJsU1FpLXc5Q3B5VVJlTUVyUDFSc0JMazd3TnRPdnM1RVFwUHFt\
        dU12cVc1N05CVWN6U2NFb1B3bVVxcWFidTlWMC1QeTRkUTU3X2JhcG9LUnUxUjkwYnZ1Rm5VNjNTSFdFRmdsWlF2\
        SkRNZUF2bWo0c20tRnAwb1l1X25lb3RnUTBoemJJNWdyeTdhamRZeTktMmxOeF83NmFCWm9PVXU5SENKLVVzZlNP\
        STgifQ";
    /// C.3: the CEK.
    #[cfg_attr(
        not(feature = "insecure-test-vectors"),
        allow(dead_code, reason = "drawn by the reproducible tests only")
    )]
    pub const CEK: &str = "bxsZNEIdFE5csDjwQdBScKGDJDfK7LmsgReZwsMw_bY";
    /// C.2: the Salt Input `p2s`.
    #[cfg_attr(
        not(feature = "insecure-test-vectors"),
        allow(dead_code, reason = "drawn by the reproducible tests only")
    )]
    pub const P2S: &str = "2WCTcJZ1Rvd_CJuJripQ1w";
    /// C.6: the JWE Initialization Vector.
    #[cfg_attr(
        not(feature = "insecure-test-vectors"),
        allow(dead_code, reason = "drawn by the reproducible tests only")
    )]
    pub const IV: &str = "Ye9j1qs22DmRSAddIh-VnA";
    /// C.2: the encoded JWE Protected Header.
    pub const PROTECTED: &str = "eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJwMnMiOiIyV0NUY0paMVJ2ZF9DSnVKcmlwUTF3IiwicDJjIjo0MDk2LCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiY3R5IjoiandrK2pzb24ifQ";
    /// C.9: the JWE Compact Serialization.
    pub const COMPACT: &str = "eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJwMnMiOiIyV0NUY0paMVJ2ZF9DSnVKcmlwUTF3IiwicDJjIjo0\
        MDk2LCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiY3R5IjoiandrK2pzb24ifQ.TrqXOwuNUfDV9VPTNbyGvEJ9JMjef\
        AVn-TR1uIxR9p6hsRQh9Tk7BA.Ye9j1qs22DmRSAddIh-VnA.AwhB8lxrlKjFn02LGWEqg27H4Tg9fyZAbFv3p5Z\
        icHpj64QyHC44qqlZ3JEmnZTgQowIqZJ13jbyHB8LgePiqUJ1hf6M2HPLgzw8L-mEeQ0jvDUTrE07NtOerBk8bwB\
        QyZ6g0kQ3DEOIglfYxV8-FJvNBYwbqN1Bck6d_i7OtjSHV-8DIrp-3JcRIe05YKy3Oi34Z_GOiAc1EK21B11c_AE\
        11PII_wvvtRiUiG8YofQXakWd1_O98Kap-UgmyWPfreUJ3lJPnbD4Ve95owEfMGLOPflo2MnjaTDCwQokoJ_xplQ\
        2vNPz8iguLcHBoKllyQFJL2mOWBwqhBo9Oj-O800as5mmLsvQMTflIrIEbbTMzHMBZ8EFW9fWwwFu0DWQJGkMNhm\
        BZQ-3lvqTc-M6-gWA6D8PDhONfP2Oib2HGizwG1iEaX8GRyUpfLuljCLIe1DkGOewhKuKkZh04DKNM5Nbugf2atm\
        U9OP0Ldx5peCUtRG1gMVl7Qup5ZXHTjgPDr5b2N731UooCGAUqHdgGhg0JVJ_ObCTdjsH4CF1SJsdUhrXvYx3HJh\
        2Xd7CwJRzU_3Y1GxYU6-s3GFPbirfqqEipJDBTHpcoCmyrwYjYHFgnlqBZRotRrS95g8F95bRXqsaDY7UgQGwBQB\
        wy665d0zpvTasvfXf_c0MWAl-neFaKOW_Px6g4EUDjG1GWSXV9cLStLw_0ovdApDIFLHYHePyagyHjouQUuGiq7B\
        sYwYrwaF06tgB8hV8omLNfMEmDPJaZUzMuHw6tBDwGkzD-tS_ub9hxrpJ4UsOWnt5rGUyoN2N_c1-TQlXxm5oto1\
        4MxnoAyBQBpwIEgSH3Y4ZhwKBhHPjSo0cdwuNdYbGPpb-YUvF-2NZzODiQ1OvWQBRHSbPWYz_xbGkgD504LRtqRw\
        CO7CC_CyyURi1sEssPVsMJRX_U4LFEOc82TiDdqjKOjRUfKK5rqLi8nBE9soQ0DSaOoFQZiGrBrqxDsNYiAYAmxx\
        kos-i3nX4qtByVx85sCE5U_0MqG7COxZWMOPEFrDaepUV-cOyrvoUIng8i8ljKBKxETY2BgPegKBYCxsAUcAkKam\
        SCC9AiBxA0UOHyhTqtlvMksO7AEhNC2-YzPyx1FkhMoS4LLe6E_pFsMlmjA6P1NSge9C5G5tETYXGAn6b1xZbHtm\
        wrPScro9LWhVmAaA7_bxYObnFUxgWtK4vzzQBjZJ36UTk4OTB-JvKWgfVWCFsaw5WCHj6Oo4jpO7d2yN7WMfAj2h\
        TEabz9wumQ0TMhBduZ-QON3pYObSy7TSC1vVme0NJrwF_cJRehKTFmdlXGVldPxZCplr7ZQqRQhF8JP-l4mEQVnC\
        aWGn9ONHlemczGOS-A-wwtnmwjIB1V_vgJRf4FdpV-4hUk4-QLpu3-1lWFxrtZKcggq3tWTduRo5_QebQbUUT_VS\
        CgsFcOmyWKoj56lbxthN19hq1XGWbLGfrrR6MWh23vk01zn8FVwi7uFwEnRYSafsnWLa1Z5TpBj9GvAdl2H9NHwz\
        pB5NqHpZNkQ3NMDj13Fn8fzO0JB83Etbm_tnFQfcb13X3bJ15Cz-Ww1MGhvIpGGnMBT_ADp9xSIyAM9dQ1yeVXk-\
        AIgWBUlN5uyWSGyCxp0cJwx7HxM38z0UIeBu-MytL-eqndM7LxytsVzCbjOTSVRmhYEMIzUAnS1gs7uMQAGRdgRI\
        ElTJESGMjb_4bZq9s6Ve1LKkSi0_QDsrABaLe55UY0zF4ZSfOV5PMyPtocwV_dcNPlxLgNAD1BFX_Z9kAdMZQW6f\
        AmsfFle0zAoMe4l9pMESH0JB4sJGdCKtQXj1cXNydDYozF7l8H00BV_Er7zd6VtIw0MxwkFCTatsv_R-GsBCH218\
        RgVPsfYhwVuT8R4HarpzsDBufC4r8_c8fc9Z278sQ081jFjOja6L2x0N_ImzFNXU6xwO-Ska-QeuvYZ3X_L31ZOX\
        4Llp-7QSfgDoHnOxFv1Xws-D5mDHD3zxOup2b2TppdKTZb9eW2vxUVviM8OI9atBfPKMGAOv9omA-6vv5IxUH0-l\
        WMiHLQ_g8vnswp-Jav0c4t6URVUzujNOoNd_CBGGVnHiJTCHl88LQxsqLHHIu4Fz-U2SGnlxGTj0-ihit2ELGRv4\
        vO8E1BosTmf0cx3qgG0Pq0eOLBDIHsrdZ_CCAiTc0HVkMbyq1M6qEhM-q5P6y1QCIrwg.0HFmhOzsQ98nNWJjIHk\
        R7A";
}

// ---------------------------------------------------------------------------
// RFC 7520 §5.3 and RFC 7517 Appendix C
// ---------------------------------------------------------------------------

fn decrypt_c53(policy: &DecryptPolicy) -> polyjose::Result<Decrypted> {
    let ex = c53::example();
    decrypt_compact(&ex.compact, &password(&ex.password), policy)
}

fn decrypt_appendix_c(policy: &DecryptPolicy) -> polyjose::Result<Decrypted> {
    decrypt_compact(
        appendix_c::COMPACT,
        &password(appendix_c::PASSWORD.as_bytes()),
        policy,
    )
}

#[test]
fn rfc_7520_5_3_decrypts_under_the_default_bound() {
    // RFC 7520 §5.3: p2c 8192 is inside the 10,000 default (ADR 0023).
    let ex = c53::example();
    assert_eq!(ex.p2c, 8192);
    assert_eq!(
        ex.password,
        "entrap_o\u{2013}peter_long\u{2013}credit_tun".as_bytes()
    );
    assert!(ex.compact.starts_with(&format!("{}.", ex.protected_b64u)));
    let out = decrypt_c53(&policy(&[A::Pbes2Hs512A256KW], &[E::A128CbcHs256]))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(out.plaintext(), ex.plaintext.as_slice());
    assert_eq!(out.recipient(), 0);
    let h = out.header();
    assert_eq!(h.alg.as_deref(), Some("PBES2-HS512+A256KW"));
    assert_eq!(h.cty.as_deref(), Some("jwk-set+json"));
    assert_eq!(h.p2c, Some(8192));
    assert_eq!(h.p2s.as_deref().map(bytes), Some(ex.p2s));
}

#[test]
fn rfc_7517_appendix_c_decrypts_under_the_default_bound() {
    // RFC 7517 Appendix C: p2c 4096 is inside the 10,000 default.
    assert!(appendix_c::COMPACT.starts_with(&format!("{}.", appendix_c::PROTECTED)));
    let out = decrypt_appendix_c(&policy(&[A::Pbes2Hs256A128KW], &[E::A128CbcHs256]))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        out.plaintext(),
        bytes(appendix_c::PLAINTEXT_B64U).as_slice()
    );
    let h = out.header();
    assert_eq!(h.alg.as_deref(), Some("PBES2-HS256+A128KW"));
    assert_eq!(h.cty.as_deref(), Some("jwk+json"));
    assert_eq!(h.p2c, Some(4096));
    // The plaintext is the RSA private key JWK of Appendix C.1.
    let jwk = json::parse(out.plaintext()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        jwk.get("kid").and_then(Value::as_str),
        Some("juliet@capulet.lit")
    );
}

#[test]
fn rfc_vectors_fail_once_the_bound_is_below_their_count() {
    // ADR 0023: max_pbes2_count is inclusive.
    let c53 = family_policy();
    assert_eq!(code(&decrypt_c53(&c53.clone().max_pbes2_count(8192))), "ok");
    assert_eq!(
        code(&decrypt_c53(&c53.max_pbes2_count(8191))),
        "DecryptionFailed"
    );
    let c = family_policy();
    assert_eq!(
        code(&decrypt_appendix_c(&c.clone().max_pbes2_count(4096))),
        "ok"
    );
    assert_eq!(
        code(&decrypt_appendix_c(&c.max_pbes2_count(4095))),
        "DecryptionFailed"
    );
}

#[test]
fn rfc_vectors_need_the_pbes2_alg_allowed() {
    // RFC 8725 §3.1, ADR 0007: the allow-list is checked before any work.
    assert_eq!(
        code(&decrypt_c53(&policy(
            &[A::Pbes2Hs256A128KW],
            &[E::A128CbcHs256]
        ))),
        "AlgorithmNotAllowed"
    );
}

// ---------------------------------------------------------------------------
// The error contract (decrypt)
// ---------------------------------------------------------------------------

/// The RFC 7520 §5.3 protected header with `p2s` and `p2c` replaced
/// (`None` drops the member); the other members are the RFC's.
fn c53_header(p2s: Option<&str>, p2c: Option<&str>) -> String {
    let mut members = vec![r#""alg":"PBES2-HS512+A256KW""#.to_owned()];
    if let Some(p2s) = p2s {
        members.push(format!(r#""p2s":{p2s}"#));
    }
    if let Some(p2c) = p2c {
        members.push(format!(r#""p2c":{p2c}"#));
    }
    members.push(r#""cty":"jwk-set+json","enc":"A128CBC-HS256""#.to_owned());
    format!("{{{}}}", members.join(","))
}

fn decrypt_forged(header_json: &str, policy: &DecryptPolicy) -> polyjose::Result<Decrypted> {
    let ex = c53::example();
    decrypt_compact(
        &with_header(&ex.compact, header_json),
        &password(&ex.password),
        policy,
    )
}

const C53_P2S: &str = r#""8Q1SzinasR3xchYz6ZZcHA""#;

#[test]
fn the_unchanged_forged_header_still_decrypts() {
    // The forging helper re-encodes the same JSON members, so the RFC's
    // own header (byte-identical JSON) decrypts; the faults below are the
    // only change.
    let json = c53_header(Some(C53_P2S), Some("8192"));
    assert_eq!(
        b64url_encode(json.as_bytes()),
        c53::example().protected_b64u
    );
    assert_eq!(code(&decrypt_forged(&json, &family_policy())), "ok");
}

#[test]
fn every_p2s_and_p2c_fault_is_decryption_failed() {
    // RFC 7518 §4.8.1.1–§4.8.1.2, §8.8; ADR 0023; plan.md error contract.
    let ceiling_plus_one = (DecryptPolicy::MAX_PBES2_COUNT_CEILING + 1).to_string();
    // The first 7 octets of the RFC's salt input, canonically encoded, so
    // only the length is at fault.
    let seven = format!(r#""{}""#, b64url_encode(&c53::example().p2s[..7]));
    assert_eq!(bytes(seven.trim_matches('"')).len(), 7);
    let cases: [(&str, Option<&str>, Option<&str>); 9] = [
        ("p2c bound + 1", Some(C53_P2S), Some("10001")),
        ("p2c 2^32 - 1", Some(C53_P2S), Some("4294967295")),
        ("p2c 2^53 - 1", Some(C53_P2S), Some("9007199254740991")),
        ("p2c ceiling + 1", Some(C53_P2S), Some(&ceiling_plus_one)),
        ("p2c missing", Some(C53_P2S), None),
        ("p2s missing", None, Some("8192")),
        ("p2s 7 octets", Some(&seven), Some("8192")),
        ("p2s empty", Some(r#""""#), Some("8192")),
        (
            "p2s not base64url",
            Some(r#""8Q1Szinas+3xchYz6ZZcHA""#),
            Some("8192"),
        ),
    ];
    // A bound raised past the ceiling is clamped to it (ADR 0023).
    let raised = family_policy().max_pbes2_count(u32::MAX);
    for (what, p2s, p2c) in cases {
        let json = c53_header(p2s, p2c);
        for policy in [&family_policy(), &raised] {
            assert_eq!(
                decrypt_forged(&json, policy).map(|_| ()),
                Err(Error::DecryptionFailed),
                "{what}"
            );
        }
    }
}

#[test]
fn a_p2c_of_2_pow_32_minus_1_returns_promptly() {
    // RFC 7518 §8.8, research.md §4.2: a hostile count is refused before
    // PBKDF2 runs. This only has to finish; a regression would run 2^32
    // iterations and hang the suite. No wall-clock assertion (ADR 0009).
    let json = c53_header(Some(C53_P2S), Some("4294967295"));
    for alg in [
        "PBES2-HS256+A128KW",
        "PBES2-HS384+A192KW",
        "PBES2-HS512+A256KW",
    ] {
        let json = json.replace("PBES2-HS512+A256KW", alg);
        let result = decrypt_forged(&json, &family_policy().max_pbes2_count(u32::MAX));
        assert_eq!(result.map(|_| ()), Err(Error::DecryptionFailed), "{alg}");
    }
}

#[test]
fn a_p2c_that_is_not_a_positive_integer_is_an_invalid_header() {
    // RFC 7518 §4.8.1.2: p2c is "a positive JSON integer". A zero, negative,
    // fractional or non-number p2c is a registered parameter of the wrong
    // type, refused while parsing the header (plan.md error contract, steps
    // 3–4) before key management starts.
    for p2c in ["0", "-1", "1.5", r#""8192""#, "null"] {
        let json = c53_header(Some(C53_P2S), Some(p2c));
        assert_eq!(
            code(&decrypt_forged(&json, &family_policy())),
            "InvalidHeader",
            "p2c {p2c}"
        );
    }
}

#[test]
fn a_wrong_password_is_the_same_error_as_a_bad_tag() {
    // RFC 7516 §11.5: no oracle between a key-unwrap failure and a tag
    // failure.
    let ex = c53::example();
    let wrong = decrypt_compact(
        &ex.compact,
        &password(b"entrap_o-peter_long-credit_tun"),
        &family_policy(),
    );
    let bad_tag = decrypt_compact(
        &with_bad_tag(&ex.compact),
        &password(&ex.password),
        &family_policy(),
    );
    assert_eq!(wrong.as_ref().map(|_| ()), Err(&Error::DecryptionFailed));
    assert_eq!(wrong.map(|_| ()), bad_tag.map(|_| ()));
    // The same for an encrypted key changed in one bit.
    let mut parts: Vec<String> = ex.compact.split('.').map(str::to_owned).collect();
    let mut ek = bytes(&parts[1]);
    ek[3] ^= 0x80;
    parts[1] = b64url_encode(&ek);
    let tampered = decrypt_compact(&parts.join("."), &password(&ex.password), &family_policy());
    assert_eq!(tampered.map(|_| ()), Err(Error::DecryptionFailed));
}

#[test]
fn a_different_alg_in_the_family_does_not_decrypt() {
    // RFC 7518 §4.8.1.1: alg is part of the salt, and fixes the PRF and KW
    // key size, so swapping it changes the derived key.
    for alg in ["PBES2-HS256+A128KW", "PBES2-HS384+A192KW"] {
        let json = c53_header(Some(C53_P2S), Some("8192")).replace("PBES2-HS512+A256KW", alg);
        assert_eq!(
            decrypt_forged(&json, &family_policy()).map(|_| ()),
            Err(Error::DecryptionFailed),
            "{alg}"
        );
    }
}

// ---------------------------------------------------------------------------
// Encrypt
// ---------------------------------------------------------------------------

fn encrypt(
    alg: KeyMgmtAlg,
    enc: ContentEncAlg,
    r: impl FnOnce(Recipient) -> Recipient,
) -> polyjose::Result<String> {
    Encryptor::new(enc)
        .recipient(r(Recipient::new(alg, &password(b"Hunter2, but longer"))))
        .encrypt_compact(b"PBES2 plaintext")
}

fn protected_of(token: &str) -> Header {
    let first = token.split('.').next().unwrap_or_default();
    Header::from_json(&bytes(first)).unwrap_or_else(|e| panic!("{e}"))
}

#[test]
fn encrypt_puts_a_16_octet_p2s_and_p2c_10000_in_the_protected_header() {
    // RFC 7518 §4.8.1.1–§4.8.1.2, ADR 0023; plan.md: compact puts the key
    // management parameters in the protected header.
    for alg in FAMILY {
        let token = encrypt(alg.clone(), E::A128GCM, |r| r).unwrap_or_else(|e| panic!("{e}"));
        let h = protected_of(&token);
        assert_eq!(h.alg.as_deref(), Some(alg.as_str()));
        assert_eq!(h.p2c, Some(10_000));
        assert_eq!(h.p2s.as_deref().map(|s| bytes(s).len()), Some(16));
        let out = decrypt_compact(&token, &password(b"Hunter2, but longer"), &family_policy())
            .unwrap_or_else(|e| panic!("{alg}: {e}"));
        assert_eq!(out.plaintext(), b"PBES2 plaintext");
    }
}

#[test]
fn two_encryptions_draw_different_salt_inputs() {
    let a = protected_of(
        &encrypt(A::Pbes2Hs256A128KW, E::A128GCM, |r| r.p2c(1000))
            .unwrap_or_else(|e| panic!("{e}")),
    );
    let b = protected_of(
        &encrypt(A::Pbes2Hs256A128KW, E::A128GCM, |r| r.p2c(1000))
            .unwrap_or_else(|e| panic!("{e}")),
    );
    assert_ne!(a.p2s, b.p2s);
}

#[test]
fn encrypt_refuses_a_count_below_1000_or_a_salt_input_below_8_octets() {
    // RFC 7518 §4.8.1.2 ("A minimum iteration count of 1000 is
    // RECOMMENDED"), §4.8.1.1 ("8 or more octets MUST be used").
    for alg in FAMILY {
        for r in [
            (|r: Recipient| r.p2c(999)) as fn(Recipient) -> Recipient,
            |r| r.p2c(0),
            |r| r.p2s_len(7),
            |r| r.p2s_len(0),
        ] {
            assert_eq!(
                code(&encrypt(alg.clone(), E::A256GCM, r)),
                "InvalidKey",
                "{alg}"
            );
        }
        let ok = encrypt(alg.clone(), E::A256GCM, |r| r.p2c(1000).p2s_len(8));
        let h = protected_of(&ok.unwrap_or_else(|e| panic!("{e}")));
        assert_eq!(
            (h.p2c, h.p2s.as_deref().map(|s| bytes(s).len())),
            (Some(1000), Some(8))
        );
    }
}

#[test]
fn a_count_above_the_bound_encrypts_but_needs_a_raised_policy() {
    // ADR 0023: the encrypt side may use more than 10,000 iterations; the
    // decrypt side accepts them only when the caller raises the bound.
    let token = encrypt(A::Pbes2Hs256A128KW, E::A128CbcHs256, |r| r.p2c(10_001))
        .unwrap_or_else(|e| panic!("{e}"));
    let key = password(b"Hunter2, but longer");
    assert_eq!(
        decrypt_compact(&token, &key, &family_policy()).map(|_| ()),
        Err(Error::DecryptionFailed)
    );
    let raised = family_policy().max_pbes2_count(10_001);
    assert_eq!(code(&decrypt_compact(&token, &key, &raised)), "ok");
}

#[test]
fn a_symmetric_key_bound_to_another_alg_is_refused() {
    // RFC 8725 §3.1, RFC 7517 §4.4: a JWK whose alg is A128KW is not a
    // PBES2 password.
    let key = Jwk::from_json(br#"{"kty":"oct","alg":"A128KW","k":"GawgguFyGrWKav7AX4VKUg"}"#)
        .unwrap_or_else(|e| panic!("{e}"));
    let result = Encryptor::new(E::A128GCM)
        .recipient(Recipient::new(A::Pbes2Hs256A128KW, &key))
        .encrypt_compact(b"x");
    assert_eq!(code(&result), "KeyAlgorithmMismatch");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    /// RFC 7516 §5.1/§5.2 with RFC 7518 §4.8: any password and plaintext
    /// round-trip through every PBES2 alg and every enc.
    #[test]
    fn round_trips(
        alg in 0usize..3,
        enc in 0usize..E::KNOWN.len(),
        pw in proptest::collection::vec(any::<u8>(), 1..48),
        plaintext in proptest::collection::vec(any::<u8>(), 0..200),
        p2s_len in 8usize..40,
    ) {
        let alg = FAMILY[alg].clone();
        let enc = E::KNOWN[enc].clone();
        let key = password(&pw);
        let token = Encryptor::new(enc.clone())
            .recipient(Recipient::new(alg.clone(), &key).p2c(1000).p2s_len(p2s_len))
            .encrypt_compact(&plaintext)
            .unwrap_or_else(|e| panic!("{e}"));
        let out = decrypt_compact(&token, &key, &policy(&[alg], &[enc]))
            .unwrap_or_else(|e| panic!("{e}"));
        prop_assert_eq!(out.plaintext(), plaintext.as_slice());
    }
}

// ---------------------------------------------------------------------------
// Exact reproduction (insecure-test-vectors)
// ---------------------------------------------------------------------------

#[cfg(feature = "insecure-test-vectors")]
mod reproducible {
    use polyjose::insecure_test_vectors::FixedRng;
    use polyjose::jwe::Serialization;

    use super::*;

    fn header(json: &str) -> Header {
        Header::from_json(json.as_bytes()).unwrap_or_else(|e| panic!("{json}: {e}"))
    }

    #[test]
    fn rfc_7520_5_3_is_reproduced() {
        // plan.md RNG draw order: the CEK, then the recipient's p2s, then
        // the content IV.
        let ex = c53::example();
        let mut rng = FixedRng::new([ex.cek.clone(), ex.p2s.clone(), ex.iv.clone()].concat());
        let token = Encryptor::new(E::A128CbcHs256)
            .protected_header(header(r#"{"cty":"jwk-set+json"}"#))
            .recipient(
                Recipient::new(A::Pbes2Hs512A256KW, &password(&ex.password))
                    .p2c(u32::try_from(ex.p2c).unwrap_or_else(|e| panic!("{e}")))
                    .p2s_len(ex.p2s.len()),
            )
            .encrypt_reproducible(
                &ex.plaintext,
                Serialization::Compact,
                &mut rng,
                Some(&ex.protected_b64u),
            )
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(token, ex.compact);
        assert_eq!(rng.remaining(), 0);
    }

    #[test]
    fn rfc_7517_appendix_c_is_reproduced() {
        let rng_bytes = [
            bytes(appendix_c::CEK),
            bytes(appendix_c::P2S),
            bytes(appendix_c::IV),
        ]
        .concat();
        let mut rng = FixedRng::new(rng_bytes);
        let token = Encryptor::new(E::A128CbcHs256)
            .protected_header(header(r#"{"cty":"jwk+json"}"#))
            .recipient(
                Recipient::new(
                    A::Pbes2Hs256A128KW,
                    &password(appendix_c::PASSWORD.as_bytes()),
                )
                .p2c(4096),
            )
            .encrypt_reproducible(
                &bytes(appendix_c::PLAINTEXT_B64U),
                Serialization::Compact,
                &mut rng,
                Some(appendix_c::PROTECTED),
            )
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(token, appendix_c::COMPACT);
        assert_eq!(rng.remaining(), 0);
    }

    #[test]
    fn a_protected_header_with_another_p2c_is_refused() {
        // plan.md: the given protected header must be JSON-equal to the one
        // polyjose builds, so it cannot smuggle a different p2c.
        let ex = c53::example();
        let mut rng = FixedRng::new([ex.cek.clone(), ex.p2s.clone(), ex.iv.clone()].concat());
        let result = Encryptor::new(E::A128CbcHs256)
            .protected_header(header(r#"{"cty":"jwk-set+json"}"#))
            .recipient(Recipient::new(A::Pbes2Hs512A256KW, &password(&ex.password)).p2c(8193))
            .encrypt_reproducible(
                &ex.plaintext,
                Serialization::Compact,
                &mut rng,
                Some(&ex.protected_b64u),
            );
        assert_eq!(code(&result), "InvalidFormat");
    }
}
