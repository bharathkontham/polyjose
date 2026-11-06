//! On-curve validation at JWK import (ADR 0041 §4, ADR 0007): EC points
//! must be on their curve (SEC 1 §3.2.2.1, RFC 7518 §6.2.1), EC private
//! scalars `d` in [1, n−1] (SEC 1 §3.2.1, RFC 7518 §6.2.2.1), and Ed25519
//! public keys must decode (RFC 8032 §5.1.3) to a point that is not of small
//! order. Every rejection is `InvalidKey` with a fixed detail, and a JWK Set
//! skips such a member instead of failing (ADR 0041 §2, RFC 7517 §5).
//!
//! The curve constants below (generators G, −G, the group orders n and the
//! field primes p) are the published SEC 2 / FIPS 186-5 values. They were
//! checked independently of polyjose and of RustCrypto with a few lines of
//! Python big-integer arithmetic (G on the curve, n·G the identity,
//! (n−1)·G = −G).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a panic is a failed assertion

use polyjose::Error;
use polyjose::jwk::{Jwk, JwkSet, KeyMaterial};

/// One curve's test values, base64url of the fixed-length big-endian octets.
struct Curve {
    crv: &'static str,
    /// The generator G (d = 1).
    gx: &'static str,
    gy: &'static str,
    /// The y coordinate of −G = (n−1)·G, that is p − Gy.
    neg_gy: &'static str,
    /// n − 1, the largest valid scalar.
    n_minus_1: &'static str,
    /// n, the group order: the smallest invalid scalar above the range.
    n: &'static str,
    /// The field prime p, as an x coordinate (not a field element).
    p: &'static str,
    /// Gy with its lowest bit flipped: (Gx, Gy ^ 1) is not on the curve.
    gy_flipped: &'static str,
    /// 1 and 0 and all-ones, at the curve's scalar length.
    one: &'static str,
    zero: &'static str,
    all_ones: &'static str,
}

const CURVES: [Curve; 4] = [
    Curve {
        crv: "P-256",
        gx: "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY",
        gy: "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU",
        neg_gy: "sBy9HAHlgGVxGBS1g_Bh6dQxzKmUzqExNEm_l8hArgo",
        n_minus_1: "_____wAAAAD__________7zm-q2nF56E87nKwvxjJVA",
        n: "_____wAAAAD__________7zm-q2nF56E87nKwvxjJVE",
        p: "_____wAAAAEAAAAAAAAAAAAAAAD_______________8",
        gy_flipped: "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfQ",
        one: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE",
        zero: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        all_ones: "__________________________________________8",
    },
    Curve {
        crv: "P-384",
        gx: "qofKIr6LBTeOscce8yCtdG4dO2KLp5uYWfdB4IJUKjhVAvJdv1UpbDpUXjhydgq3",
        gy: "NhfeSpYmLG9dnpi_kpLcKfj0Hb0omhR86doxE7XwuMAKYLHOHX6BnXpDHXyQ6g5f",
        neg_gy: "yeghtWnZ05CiYWdAbW0j1gcL4kLXZeuDFiXO7EoPRz71n04w4oF-YoW84oRvFfGg",
        n_minus_1: "________________________________x2NNgfQ3Ld9YGg2ySLCneuzsGWrMxSly",
        n: "________________________________x2NNgfQ3Ld9YGg2ySLCneuzsGWrMxSlz",
        p: "__________________________________________7_____AAAAAAAAAAD_____",
        gy_flipped: "NhfeSpYmLG9dnpi_kpLcKfj0Hb0omhR86doxE7XwuMAKYLHOHX6BnXpDHXyQ6g5e",
        one: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB",
        zero: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        all_ones: "________________________________________________________________",
    },
    Curve {
        crv: "P-521",
        gx: "AMaFjga3BATpzZ4-y2YjlbRCnGSBOQU_tSH4KK9ga009uqFLXnfv51ko_h3BJ6L_qN4zSLPBhWpCm_l-fjHC5b1m",
        gy: "ARg5KWp4mjvABFyKX7QsfRvZmPVESVebRGgXr70XJz5mLJfucple9CZAxVC5AT-tB2E1PHCGonLCQIi-lHaf0WZQ",
        neg_gy: "AOfG1pWHZcQ_-6N1oEvTguQmZwq7tqhku5foUELo2MGZ02gRjWahC9m_Oq9G_sBS-J7Kw495XY09v3dBa4lgLpmv",
        n_minus_1: "Af__________________________________________-lGGh4O_L5Zrf8wBSPcJpdA7tcm4iZxHrrtvtx6ROGQI",
        n: "Af__________________________________________-lGGh4O_L5Zrf8wBSPcJpdA7tcm4iZxHrrtvtx6ROGQJ",
        p: "Af______________________________________________________________________________________",
        gy_flipped: "ARg5KWp4mjvABFyKX7QsfRvZmPVESVebRGgXr70XJz5mLJfucple9CZAxVC5AT-tB2E1PHCGonLCQIi-lHaf0WZR",
        one: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB",
        zero: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        all_ones: "________________________________________________________________________________________",
    },
    Curve {
        crv: "secp256k1",
        gx: "eb5mfvncu6xVoGKVzocLBwKb_NstzijZWfKBWxb4F5g",
        gy: "SDradyajxGVdpPv8DhEIqP0XtEimhVQZnEfQj_sQ1Lg",
        neg_gy: "t8UliNlcO5qiWwQD8e73VwLoS7dZeqvmY7gvbwTvJ3c",
        n_minus_1: "_____________________rqu3OavSKA7v9JejNA2QUA",
        n: "_____________________rqu3OavSKA7v9JejNA2QUE",
        p: "_____________________________________v___C8",
        gy_flipped: "SDradyajxGVdpPv8DhEIqP0XtEimhVQZnEfQj_sQ1Lk",
        one: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE",
        zero: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        all_ones: "__________________________________________8",
    },
];

/// The detail of an off-curve (or identity) EC point.
const NOT_ON_CURVE: Error = Error::InvalidKey("EC point is not on the curve");
/// The detail of an EC `d` outside [1, n−1].
const SCALAR_RANGE: Error = Error::InvalidKey("EC private key d is out of range");
/// The detail of an Ed25519 `x` that is not a valid public key.
const BAD_ED25519: Error = Error::InvalidKey("Ed25519 public key is invalid");

fn ec(crv: &str, x: &str, y: &str, d: Option<&str>) -> String {
    let d = d.map(|d| format!(r#","d":"{d}""#)).unwrap_or_default();
    format!(r#"{{"kty":"EC","crv":"{crv}","x":"{x}","y":"{y}"{d}}}"#)
}

fn okp(crv: &str, x: &str) -> String {
    format!(r#"{{"kty":"OKP","crv":"{crv}","x":"{x}"}}"#)
}

fn import(json: &str) -> Result<Jwk, Error> {
    Jwk::from_json(json.as_bytes())
}

#[test]
fn generator_and_its_negation_are_accepted_with_the_boundary_scalars() {
    for c in &CURVES {
        // d = 1 with G, and d = n − 1 with −G: the two ends of [1, n−1],
        // each with its own public point.
        let lo = import(&ec(c.crv, c.gx, c.gy, Some(c.one)));
        assert!(lo.is_ok(), "{}: d = 1 with G: {lo:?}", c.crv);
        let hi = import(&ec(c.crv, c.gx, c.neg_gy, Some(c.n_minus_1)));
        assert!(hi.is_ok(), "{}: d = n − 1 with −G: {hi:?}", c.crv);
        let public = import(&ec(c.crv, c.gx, c.gy, None));
        assert!(public.is_ok(), "{}: G as a public key: {public:?}", c.crv);
    }
}

#[test]
fn zero_point_is_rejected_on_every_curve() {
    // (0, 0) is how some encoders spell the point at infinity; it satisfies
    // no curve equation here (b ≠ 0 on all four curves). The 0001 audit's
    // reproduction input on P-256.
    for c in &CURVES {
        assert_eq!(
            import(&ec(c.crv, c.zero, c.zero, None)).err(),
            Some(NOT_ON_CURVE),
            "{}",
            c.crv
        );
    }
}

#[test]
fn off_curve_point_is_rejected_on_every_curve() {
    for c in &CURVES {
        assert_eq!(
            import(&ec(c.crv, c.gx, c.gy_flipped, None)).err(),
            Some(NOT_ON_CURVE),
            "{}",
            c.crv
        );
        // Also with a valid `d`: the public point is checked whatever else
        // the key holds.
        assert_eq!(
            import(&ec(c.crv, c.gx, c.gy_flipped, Some(c.one))).err(),
            Some(NOT_ON_CURVE),
            "{} with d",
            c.crv
        );
    }
}

#[test]
fn coordinate_that_is_not_a_field_element_is_rejected() {
    // x = p is not reduced modulo p (SEC 1 §2.3.4 requires 0 ≤ x < p).
    for c in &CURVES {
        assert_eq!(
            import(&ec(c.crv, c.p, c.gy, None)).err(),
            Some(NOT_ON_CURVE),
            "{}",
            c.crv
        );
    }
    // On P-521, Gx + p still fits in 66 octets and is congruent to Gx, so
    // only the range check (not the curve equation) can reject it.
    let gx_plus_p =
        "AsaFjga3BATpzZ4-y2YjlbRCnGSBOQU_tSH4KK9ga009uqFLXnfv51ko_h3BJ6L_qN4zSLPBhWpCm_l-fjHC5b1l";
    assert_eq!(
        import(&ec("P-521", gx_plus_p, CURVES[2].gy, None)).err(),
        Some(NOT_ON_CURVE)
    );
}

#[test]
fn scalar_outside_one_to_n_minus_one_is_rejected() {
    for c in &CURVES {
        // The public point is valid, so `d` alone decides.
        for (what, d) in [("0", c.zero), ("n", c.n), ("all ones", c.all_ones)] {
            assert_eq!(
                import(&ec(c.crv, c.gx, c.gy, Some(d))).err(),
                Some(SCALAR_RANGE),
                "{}: d = {what}",
                c.crv
            );
        }
    }
}

#[test]
fn audit_reproduction_inputs_are_rejected() {
    // The 0001 audit's three P-256 inputs: the point (0, 0), d = 0 and
    // d = 2^256 − 1 (with the RFC 7517 Appendix A.1 public point).
    let x = "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4";
    let y = "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM";
    let p256 = &CURVES[0];
    assert_eq!(
        import(&ec("P-256", p256.zero, p256.zero, None)).err(),
        Some(NOT_ON_CURVE)
    );
    assert_eq!(
        import(&ec("P-256", x, y, Some(p256.zero))).err(),
        Some(SCALAR_RANGE)
    );
    assert_eq!(
        import(&ec("P-256", x, y, Some(p256.all_ones))).err(),
        Some(SCALAR_RANGE)
    );
    // The RFC 7517 A.2 private key itself is fine.
    assert!(
        import(&ec(
            "P-256",
            x,
            y,
            Some("870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE")
        ))
        .is_ok()
    );
}

#[test]
fn structural_errors_still_come_before_the_curve_checks() {
    // A wrong length is reported as such, not as an off-curve point
    // (check order, crate::jwk docs).
    let p256 = &CURVES[0];
    assert_eq!(
        import(&ec("P-256", "AAAA", p256.zero, None)).err(),
        Some(Error::InvalidKey("x has the wrong length for crv"))
    );
    assert_eq!(
        import(&ec("P-256", p256.zero, p256.zero, Some("AAAA"))).err(),
        Some(Error::InvalidKey("d has the wrong length for crv"))
    );
    // An off-curve point with an out-of-range `d`: the point is reported.
    assert_eq!(
        import(&ec("P-256", p256.zero, p256.zero, Some(p256.zero))).err(),
        Some(NOT_ON_CURVE)
    );
}

#[test]
fn ed25519_public_keys_that_do_not_decode_or_are_small_order_are_rejected() {
    for (what, x) in [
        // y = 2: (y² − 1)/(d·y² + 1) has no square root (RFC 8032 §5.1.3 step 3).
        ("undecodable", "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        // y = p + 3: not canonical, y ≥ p (RFC 8032 §5.1.3 step 1), although
        // it decodes to a point of large order under ZIP-215 rules.
        (
            "non-canonical",
            "8P_______________________________________38",
        ),
        // The identity (0, 1): order 1.
        ("identity", "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        // A point of order 8.
        ("order 8", "xxdqcD1N2E-6PAt2DRBnDyogU_osOczGTsf9d5KsA3o"),
        // (0, −1): order 2.
        ("order 2", "7P_______________________________________38"),
    ] {
        assert_eq!(
            import(&okp("Ed25519", x)).err(),
            Some(BAD_ED25519),
            "Ed25519 x {what}"
        );
    }
    // The RFC 8037 Appendix A.2 key is fine.
    assert!(
        import(&okp(
            "Ed25519",
            "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
        ))
        .is_ok()
    );
}

#[test]
fn x25519_keys_keep_the_length_check_only() {
    // RFC 7748 §5: every 32-octet string is a valid X25519 u-coordinate, so
    // there is no decoding failure; small-order inputs are a property of the
    // shared secret, which ECDH-ES checks (feature 0003).
    for x in [
        "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "8P_______________________________________38",
    ] {
        let jwk = import(&okp("X25519", x));
        assert!(jwk.is_ok(), "X25519 x {x}: {jwk:?}");
    }
}

#[test]
fn rejections_never_contain_key_material() {
    let p256 = &CURVES[0];
    for json in [
        ec("P-256", p256.zero, p256.zero, None),
        ec("P-256", p256.gx, p256.gy, Some(p256.n)),
        okp("Ed25519", "xxdqcD1N2E-6PAt2DRBnDyogU_osOczGTsf9d5KsA3o"),
    ] {
        let e = import(&json).unwrap_err();
        let shown = format!("{e} {e:?}");
        for value in [p256.gx, p256.n, "xxdqcD1N2E", "AAAAAAAAAAAA"] {
            assert!(!shown.contains(value), "{shown}");
        }
    }
}

#[test]
fn jwk_set_skips_invalid_curve_members() {
    // ADR 0041 §2: an off-curve EC point, an out-of-range `d` and a
    // small-order Ed25519 key are skipped like any invalid member
    // (RFC 7517 §5), never fatal, and the valid keys stay in order.
    let p256 = &CURVES[0];
    let doc = format!(
        r#"{{"keys":[{},{},{},{},{}]}}"#,
        ec("P-256", p256.zero, p256.zero, None),
        ec("P-256", p256.gx, p256.gy, None),
        ec("P-256", p256.gx, p256.gy, Some(p256.zero)),
        okp("Ed25519", "xxdqcD1N2E-6PAt2DRBnDyogU_osOczGTsf9d5KsA3o"),
        okp("Ed25519", "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"),
    );
    let set = JwkSet::from_json(doc.as_bytes()).expect("the set itself is valid");
    assert_eq!((set.len(), set.skipped()), (2, 3));
    assert!(matches!(set.keys()[0].material(), KeyMaterial::Ec(_)));
    assert!(matches!(set.keys()[1].material(), KeyMaterial::Okp(_)));
}
