//! Tester-owned, independent checks for ADR 0043 (T17).
//!
//! Every value is derived outside polyjose and outside the RustCrypto/dalek
//! crates: SEC 1 v2 §2.2.1 affine arithmetic and RFC 8032 §5.1 Edwards
//! arithmetic in pure Python, with the EC public points cross-checked
//! against `openssl ec` and the Ed25519 torsion points found by multiplying
//! arbitrary curve points by L. The mixed-order keys are a valid key plus a
//! point of order 8 (RFC 8037 A.1 x + T8, RFC 8032 §7.1 TEST 2 x + T8).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a panic is a failed assertion

use polyjose::Error;
use polyjose::jwk::{Jwk, JwkSet};

/// (crv, d1, x1, y1 = (d1·G), d2 (another valid scalar), −y1, n − d1, d1 + 1).
type Row = (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
);

const EC: [Row; 4] = [
    (
        "P-256",
        "mnrpLRljg5bos2e6dfV9HKXHiYFDOyBpyyrcQ_zcyOA",
        "apuhgGyAcEQtkvYMiCj5PzLLceJ_jh0anI0Dy9vDSHM",
        "c5VV1BL9fh7FzXyfgHmr3XxVGK_cKkQ0LWsc1PuTErY",
        "vp9GBLpQdHCSozPIDxBEi4tEyUJLr-yaR6hGI31U5nY",
        "jGqqKu0CgeI6MoNgf4ZUIoOq51Ej1bvL0pTjKwRs7Uk",
        "ZYUW0eacfGoXTJhFigqC4xcfcSxj3H4bKI7ufv-GXHE",
        "mnrpLRljg5bos2e6dfV9HKXHiYFDOyBpyyrcQ_zcyOE",
    ),
    (
        "P-384",
        "qFvfTQdYfvorMevkWsKIaxTOEuCHgKpqcURFzcrZJMRKfFKw-IR-TboJe8Vwifeh",
        "9Wld0RXOtq63ND39zSCwd1cN_TkF2nU99HEZp-NDrO16H8lDL2LnTG3uEpIbeOue",
        "5o2RVMkL1r1_Nv5tpSAgH1Rvaj4HehCKgK9tgC0RLRrezWgzKo6piXo23uxg1m5o",
        "_cO29dMVbh9P_KjCrJ5lgXSnisesT0YRwJBTX7eTlbt69AfVNcEyps0_tKGbVbar",
        "GXJuqzb0KUKAyQGSWt_f4KuQlcH4he91f1CSf9Lu0uQhMpfL1XFWdoXJIRSfKZGX",
        "V6QgsvingQXUzhQbpT13lOsx7R94f1WVVh8HtCleCRsNnbsBUCwpLTLinaVcOzHS",
        "qFvfTQdYfvorMevkWsKIaxTOEuCHgKpqcURFzcrZJMRKfFKw-IR-TboJe8Vwifei",
    ),
    (
        "P-521",
        "AevtPysY3nLzcXYyTNxzocULfSa7xS8b_17PxRcE1RVcTMRXs4uonGKC8hHghH5lrp7xDxow6PnLyajR6eux3d9s",
        "AfnmhrOODxOMwWJx7cepapSVJkHy13kmYX-PA1pAssfwVePhzPzLIl3PEOkjds3qgc6U3OZ8fGtD8sIyeV3qBI6U",
        "AOtsfns0iPPFlcxfz5VDWxuVlK3S2K0VA6ecznHE94FoaOMxZ-8r92QQEjUDNR_VBI_QdPxSQP8TaD9_SlCImXXh",
        "AIEySy4bB348wkOulCkiD9mSg1JOSB_6UL9Znk-jP0gnw8GuKLakSeotPwMcfODDaZqW9uO6XeDU75dtEyZ4adGa",
        "ARSTgYTLdww6ajOgMGq8pORqa1ItJ1Lq_FhjMY47CH6XlxzOmBDUCJvv7cr8yuAq-3AviwOtvwDsl8CAta93Zooe",
        "ABQSwNTnIY0MjonNsyOMXjr0gtlEOtDkAKEwOuj7KuqjrY0u0_gWkzPojbogxHij9zFKpq-HoKJ75RKdzTLfWoSd",
        "AevtPysY3nLzcXYyTNxzocULfSa7xS8b_17PxRcE1RVcTMRXs4uonGKC8hHghH5lrp7xDxow6PnLyajR6eux3d9t",
    ),
    (
        "secp256k1",
        "xo_RefBT2AHd1E1ptte2InNJxhbxTUqVx52PMtcwNGY",
        "nTc6QCo7freLrAN-kgS5cMWu7Pd14f9f1k7gMirSCKA",
        "MqZwSuX8fBoVQSDiw7zxcIeQq7dj1UpOXkKSsXPModU",
        "JVQaesnXBErbGlfwlWjglD_SKZHwH_MMH3q4A5CUWJs",
        "zVmPtRoDg-Xqvt8dPEMOj3hvVEicKrWxob1tTYwzWlo",
        "OXAuhg-sJ_4iK7KWSShJ3EdlFs-9-1Wl-DTPWfkGDNs",
        "xo_RefBT2AHd1E1ptte2InNJxhbxTUqVx52PMtcwNGc",
    ),
];

fn ec(crv: &str, x: &str, y: &str, d: &str) -> String {
    format!(r#"{{"kty":"EC","crv":"{crv}","x":"{x}","y":"{y}","d":"{d}"}}"#)
}

fn ed(x: &str, d: Option<&str>) -> String {
    let d = d.map(|d| format!(r#","d":"{d}""#)).unwrap_or_default();
    format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{x}"{d}}}"#)
}

#[test]
fn ec_consistent_pairs_import_on_all_four_curves() {
    for (crv, d1, x1, y1, ..) in EC {
        assert!(
            Jwk::from_json(ec(crv, x1, y1, d1).as_bytes()).is_ok(),
            "{crv}"
        );
        // The public half alone imports too.
        let public = format!(r#"{{"kty":"EC","crv":"{crv}","x":"{x1}","y":"{y1}"}}"#);
        assert!(Jwk::from_json(public.as_bytes()).is_ok(), "{crv}");
    }
}

#[test]
fn ec_mismatched_pairs_are_one_fixed_invalid_key_on_all_four_curves() {
    let expected = Error::InvalidKey("EC private key d does not match x and y");
    for (crv, d1, x1, y1, d2, neg_y1, n_minus_d1, d1_plus_1) in EC {
        for (what, y, d) in [
            ("another scalar", y1, d2),
            ("the negated point", neg_y1, d1),
            ("n - d", y1, n_minus_d1),
            ("d + 1", y1, d1_plus_1),
        ] {
            let json = ec(crv, x1, y, d);
            let e = Jwk::from_json(json.as_bytes()).unwrap_err();
            assert_eq!(e, expected, "{crv}: {what}");
            assert_eq!(e.code(), "InvalidKey");
            let shown = format!("{e} {e:?}");
            for secret in [d, x1, y] {
                assert!(!shown.contains(secret), "{crv}: {what}: {shown}");
            }
        }
    }
}

#[test]
fn ed25519_torsion_components_are_refused_and_torsion_free_keys_import() {
    const MIXED_A1_T8: &str = "kVgxKpqNbjs0yJHW1hRE-LghHFEX660VvbC9aLB-AkU";
    const MIXED_T2_T8: &str = "AWnTwC8-3RIcr74d_UXEz0qsIWp5425jJkGfKmVNLUY";
    let expected = Error::InvalidKey("Ed25519 public key is invalid");
    for x in [MIXED_A1_T8, MIXED_T2_T8] {
        assert_eq!(
            Jwk::from_json(ed(x, None).as_bytes()).unwrap_err(),
            expected
        );
        // With any d the point error comes first (check order).
        let with_d = ed(x, Some("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"));
        assert_eq!(Jwk::from_json(with_d.as_bytes()).unwrap_err(), expected);
    }
    // Torsion-free: RFC 8037 A.1, RFC 8032 §7.1 TEST 1 and TEST 2.
    let hex = |s: &str| -> String {
        let b: Vec<u8> = (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect();
        polyjose::util::b64url_encode(&b)
    };
    for x in [
        "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo".to_owned(),
        hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
        hex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"),
    ]
    .iter()
    {
        assert!(Jwk::from_json(ed(x, None).as_bytes()).is_ok(), "{x}");
    }
}

#[test]
fn jwk_set_skips_mixed_order_members() {
    let doc = format!(
        r#"{{"keys":[{},{},{}]}}"#,
        ed("kVgxKpqNbjs0yJHW1hRE-LghHFEX660VvbC9aLB-AkU", None),
        ed("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo", None),
        ed("AWnTwC8-3RIcr74d_UXEz0qsIWp5425jJkGfKmVNLUY", None),
    );
    let set = JwkSet::from_json(doc.as_bytes()).unwrap();
    assert_eq!((set.len(), set.skipped()), (1, 2));
}
