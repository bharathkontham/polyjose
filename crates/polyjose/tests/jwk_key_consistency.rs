//! Private/public consistency at JWK import (ADR 0043 §3, amending
//! ADR 0041 §4): a private `EC` key whose `d·G` is not (`x`, `y`)
//! (SEC 1 v2 §3.2.1: Q = d·G; RFC 7518 §6.2.2.1), or a private `Ed25519`
//! key whose `d` does not derive `x` (RFC 8032 §5.1.5; RFC 8037 §2), is
//! `InvalidKey` with a fixed detail. A mismatched pair is the root of
//! RUSTSEC-2022-0093 (the ed25519-dalek v1 double-public-key signing
//! oracle). A JWK Set skips such a member (ADR 0041 §2, RFC 7517 §5).
//!
//! Every value below was derived independently of polyjose and of the
//! RustCrypto/dalek crates, with pure Python big-integer arithmetic
//! (`hashlib` only): SEC 1 v2 §2.2.1 affine point arithmetic over the
//! SEC 2 / FIPS 186-5 domain parameters (G on the curve, n·G the identity,
//! (n−1)·G = −G, 1·G ≠ −G, 2·G ≠ G), and the RFC 8032 §5.1.5 key
//! derivation (the RFC 8037 A.1 `d` derives the A.1 `x` and not the
//! RFC 8032 §7.1 TEST 2 public key; the TEST 2 secret derives the TEST 2
//! public key). The RFC keys were copied from the RFC texts.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a panic is a failed assertion

use polyjose::Error;
use polyjose::jwk::{Jwk, JwkSet, KeyMaterial};

/// The detail of an `EC` private key whose `d` does not derive (`x`, `y`).
const EC_MISMATCH: Error = Error::InvalidKey("EC private key d does not match x and y");
/// The detail of an `Ed25519` private key whose `d` does not derive `x`.
const ED25519_MISMATCH: Error = Error::InvalidKey("Ed25519 private key d does not match x");

/// One curve's values, base64url of the fixed-length big-endian octets.
struct Curve {
    crv: &'static str,
    /// The generator G = 1·G.
    gx: &'static str,
    gy: &'static str,
    /// The y coordinate of −G = (n−1)·G.
    neg_gy: &'static str,
    /// The scalars 1, 2 and n − 1.
    one: &'static str,
    two: &'static str,
    n_minus_1: &'static str,
}

const CURVES: [Curve; 4] = [
    Curve {
        crv: "P-256",
        gx: "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY",
        gy: "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU",
        neg_gy: "sBy9HAHlgGVxGBS1g_Bh6dQxzKmUzqExNEm_l8hArgo",
        one: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE",
        two: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI",
        n_minus_1: "_____wAAAAD__________7zm-q2nF56E87nKwvxjJVA",
    },
    Curve {
        crv: "P-384",
        gx: "qofKIr6LBTeOscce8yCtdG4dO2KLp5uYWfdB4IJUKjhVAvJdv1UpbDpUXjhydgq3",
        gy: "NhfeSpYmLG9dnpi_kpLcKfj0Hb0omhR86doxE7XwuMAKYLHOHX6BnXpDHXyQ6g5f",
        neg_gy: "yeghtWnZ05CiYWdAbW0j1gcL4kLXZeuDFiXO7EoPRz71n04w4oF-YoW84oRvFfGg",
        one: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB",
        two: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC",
        n_minus_1: "________________________________x2NNgfQ3Ld9YGg2ySLCneuzsGWrMxSly",
    },
    Curve {
        crv: "P-521",
        gx: "AMaFjga3BATpzZ4-y2YjlbRCnGSBOQU_tSH4KK9ga009uqFLXnfv51ko_h3BJ6L_qN4zSLPBhWpCm_l-fjHC5b1m",
        gy: "ARg5KWp4mjvABFyKX7QsfRvZmPVESVebRGgXr70XJz5mLJfucple9CZAxVC5AT-tB2E1PHCGonLCQIi-lHaf0WZQ",
        neg_gy: "AOfG1pWHZcQ_-6N1oEvTguQmZwq7tqhku5foUELo2MGZ02gRjWahC9m_Oq9G_sBS-J7Kw495XY09v3dBa4lgLpmv",
        one: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB",
        two: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC",
        n_minus_1: "Af__________________________________________-lGGh4O_L5Zrf8wBSPcJpdA7tcm4iZxHrrtvtx6ROGQI",
    },
    Curve {
        crv: "secp256k1",
        gx: "eb5mfvncu6xVoGKVzocLBwKb_NstzijZWfKBWxb4F5g",
        gy: "SDradyajxGVdpPv8DhEIqP0XtEimhVQZnEfQj_sQ1Lg",
        neg_gy: "t8UliNlcO5qiWwQD8e73VwLoS7dZeqvmY7gvbwTvJ3c",
        one: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE",
        two: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI",
        n_minus_1: "_____________________rqu3OavSKA7v9JejNA2QUA",
    },
];

/// RFC 7517 Appendix A.2: the P-256 private key (`d` with its own point).
const A2_X: &str = "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4";
const A2_Y: &str = "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM";
const A2_D: &str = "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE";
/// RFC 7515 Appendix A.3.1: the ES256 key's public point.
const A3_X: &str = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU";
const A3_Y: &str = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0";

/// RFC 8037 Appendix A.1: the Ed25519 key pair.
const ED_A1_X: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
const ED_A1_D: &str = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A";
/// RFC 8032 §7.1 TEST 2: the public key 3d4017c3…f4660c and its secret
/// key 4ccd089b…b8a6fb, base64url.
const ED_T2_X: &str = "PUAXw-hDiVqStwqnTRt-vJyYLM8uxJaMwM1V8Sr0Zgw";
const ED_T2_D: &str = "TM0Imyj_ltqdtsNG7BFOD1uKMZ81q6Yk2oz27U-4pvs";

fn ec(crv: &str, x: &str, y: &str, d: &str) -> String {
    format!(r#"{{"kty":"EC","crv":"{crv}","x":"{x}","y":"{y}","d":"{d}"}}"#)
}

fn ed25519(x: &str, d: &str) -> String {
    format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{x}","d":"{d}"}}"#)
}

fn import(json: &str) -> Result<Jwk, Error> {
    Jwk::from_json(json.as_bytes())
}

#[test]
fn ec_private_keys_whose_d_derives_another_point_are_rejected() {
    for c in &CURVES {
        // Each point is on the curve and each d is in [1, n − 1], so only
        // the pairing is wrong: 1·G = G ≠ −G, (n−1)·G = −G ≠ G, 2·G ≠ G.
        for (what, y, d) in [
            ("d = 1 with −G", c.neg_gy, c.one),
            ("d = n − 1 with G", c.gy, c.n_minus_1),
            ("d = 2 with G", c.gy, c.two),
        ] {
            assert_eq!(
                import(&ec(c.crv, c.gx, y, d)).err(),
                Some(EC_MISMATCH),
                "{}: {what}",
                c.crv
            );
        }
    }
}

#[test]
fn ec_private_keys_whose_d_derives_the_point_are_accepted() {
    for c in &CURVES {
        for (what, y, d) in [
            ("d = 1 with G", c.gy, c.one),
            ("d = n − 1 with −G", c.neg_gy, c.n_minus_1),
        ] {
            let key = import(&ec(c.crv, c.gx, y, d));
            assert!(key.is_ok(), "{}: {what}: {key:?}", c.crv);
        }
    }
    // RFC 7517 A.2 is consistent by construction.
    assert!(import(&ec("P-256", A2_X, A2_Y, A2_D)).is_ok());
}

#[test]
fn rfc7517_a2_d_with_the_rfc7515_a3_point_is_rejected() {
    // Two published, individually valid P-256 values that do not belong
    // together: the RFC 7517 A.2 `d` and the RFC 7515 A.3 public point.
    assert_eq!(
        import(&ec("P-256", A3_X, A3_Y, A2_D)).err(),
        Some(EC_MISMATCH)
    );
}

#[test]
fn ed25519_private_keys_whose_d_derives_another_x_are_rejected() {
    // The RFC 8037 A.1 `d` with the RFC 8032 §7.1 TEST 2 public key, the
    // TEST 2 secret with the A.1 `x`, and an arbitrary seed with A.1's `x`.
    let sevens = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc";
    for (what, x, d) in [
        ("A.1 d, TEST 2 x", ED_T2_X, ED_A1_D),
        ("TEST 2 d, A.1 x", ED_A1_X, ED_T2_D),
        ("seed of 7s, A.1 x", ED_A1_X, sevens),
    ] {
        assert_eq!(
            import(&ed25519(x, d)).err(),
            Some(ED25519_MISMATCH),
            "{what}"
        );
    }
}

#[test]
fn ed25519_private_keys_whose_d_derives_x_are_accepted() {
    for (what, x, d) in [
        ("RFC 8037 A.1", ED_A1_X, ED_A1_D),
        ("RFC 8032 TEST 2", ED_T2_X, ED_T2_D),
    ] {
        let key = import(&ed25519(x, d));
        assert!(key.is_ok(), "{what}: {key:?}");
    }
}

#[test]
fn the_point_and_the_scalar_range_are_reported_before_the_pairing() {
    // Check order (crate::jwk docs): point, then the range of d, then
    // whether d derives the point.
    let p256 = &CURVES[0];
    let flipped_gy = "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfQ";
    assert_eq!(
        import(&ec("P-256", p256.gx, flipped_gy, p256.two)).err(),
        Some(Error::InvalidKey("EC point is not on the curve"))
    );
    let zero = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    assert_eq!(
        import(&ec("P-256", p256.gx, p256.neg_gy, zero)).err(),
        Some(Error::InvalidKey("EC private key d is out of range"))
    );
    // An Ed25519 `x` that is no valid public key is reported as such, not
    // as a mismatch with `d`.
    let identity = "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    assert_eq!(
        import(&ed25519(identity, ED_A1_D)).err(),
        Some(Error::InvalidKey("Ed25519 public key is invalid"))
    );
    // A pairing problem is still a malformed key whatever its `alg`
    // (ADR 0018 Q3): InvalidKey wins over KeyAlgorithmMismatch.
    let with_alg = format!(
        r#"{{"kty":"EC","crv":"P-256","x":"{A3_X}","y":"{A3_Y}","d":"{A2_D}","alg":"ES384"}}"#
    );
    assert_eq!(import(&with_alg).err(), Some(EC_MISMATCH));
}

#[test]
fn mismatch_errors_never_contain_key_material() {
    for json in [ec("P-256", A3_X, A3_Y, A2_D), ed25519(ED_T2_X, ED_A1_D)] {
        let e = import(&json).unwrap_err();
        let shown = format!("{e} {e:?}");
        for value in [
            A3_X,
            A3_Y,
            A2_D,
            ED_T2_X,
            ED_A1_D,
            &A2_D[..8],
            &ED_A1_D[..8],
        ] {
            assert!(!shown.contains(value), "{shown}");
        }
    }
}

#[test]
fn jwk_set_skips_mismatched_private_members() {
    // ADR 0041 §2: a member that fails validation is skipped (RFC 7517 §5),
    // never fatal, and the consistent keys stay in order.
    let p256 = &CURVES[0];
    let doc = format!(
        r#"{{"keys":[{},{},{},{}]}}"#,
        ec("P-256", A3_X, A3_Y, A2_D),
        ec("P-256", p256.gx, p256.gy, p256.one),
        ed25519(ED_T2_X, ED_A1_D),
        ed25519(ED_A1_X, ED_A1_D),
    );
    let set = JwkSet::from_json(doc.as_bytes()).expect("the set itself is valid");
    assert_eq!((set.len(), set.skipped()), (2, 2));
    assert!(matches!(set.keys()[0].material(), KeyMaterial::Ec(_)));
    assert!(matches!(set.keys()[1].material(), KeyMaterial::Okp(_)));
}

#[test]
fn x25519_private_keys_are_not_yet_checked_for_consistency() {
    // ADR 0043 §3 also covers X25519 (`d` → `x`, RFC 7748 §6.1), but the
    // 0002 tree has no X25519 primitive to derive `x` with; feature 0003
    // adds the check when x25519-dalek lands (lead and orchestrator,
    // 2026-11-06). Until then a mismatched X25519 pair imports: RFC 7748
    // §6.1 Alice's private key with Bob's public key.
    let alice_d = "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo";
    let bob_x = "3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08";
    let json = format!(r#"{{"kty":"OKP","crv":"X25519","x":"{bob_x}","d":"{alice_d}"}}"#);
    assert!(import(&json).is_ok());
}
