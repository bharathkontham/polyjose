//! The JWE recipient key rules that are visible through the public API
//! (0003 T05), with the RFC 7520 §3 keys and crafted negatives.
//!
//! The binding itself (`jwe::key::RecipientKey`, crate-internal until the
//! pipeline lands in 0003 T09) is unit-tested in `src/jwe/key.rs`. What a
//! caller can observe today is that every key the binding relies on was
//! validated at import (ADR 0041 §4, ADR 0043 §3), that the JWK members the
//! binding reads (`kid`, `use`, `key_ops`, `alg`) are exposed, and that
//! the RSA, `RSA-OAEP` and `RSA1_5` refusals happen before any JWE code
//! runs (ADRs 0021, 0022).
#![allow(clippy::panic)] // test code: a panic is a failed assertion

use polyjose::Error;
use polyjose::jwa::KeyMgmtAlg;
use polyjose::jwk::{EcCurve, Jwk, KeyAlg, KeyMaterial, KeyOp, KeyType, KeyUse, OkpCurve};

fn import(json: &str) -> polyjose::Result<Jwk> {
    Jwk::from_json(json.as_bytes())
}

fn jwk(json: &str) -> Jwk {
    import(json).unwrap_or_else(|e| panic!("{e}: {json}"))
}

const KID_BILBO: &str = "bilbo.baggins@hobbiton.example";

/// RFC 7520 §3.1 (Figure 1): P-521 public key.
const RFC7520_3_1: &str = r#"{"kty":"EC","kid":"bilbo.baggins@hobbiton.example","use":"sig","crv":"P-521","x":"AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt","y":"AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1"}"#;

/// RFC 7520 §3.2 (Figure 2): the matching P-521 private key's `d`.
const RFC7520_3_2_D: &str =
    "AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zbKipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt";

/// RFC 7520 §3.3 (Figure 3): RSA 2048-bit public key, `n`.
const RFC7520_3_3_N: &str = "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw";

/// RFC 7520 §3.5 (Figure 5): HMAC SHA-256 key.
const RFC7520_3_5: &str = r#"{"kty":"oct","kid":"018c0ae5-4d9b-471b-bfd6-eef314bc7037","use":"sig","alg":"HS256","k":"hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"}"#;

/// RFC 7520 §3.6 (Figure 6): AES 256-bit symmetric encryption key.
const RFC7520_3_6: &str = r#"{"kty":"oct","kid":"1e571774-2e08-40da-8308-e8d68773842d","use":"enc","alg":"A256GCM","k":"AAPapAv4LbFbiVawEjagUBluYqN5rhna-8nuldDvOx8"}"#;

/// RFC 7520 §3.1 with `members` in place of `"use":"sig"`.
fn p521_with(members: &str) -> String {
    RFC7520_3_1.replace(r#""use":"sig""#, members)
}

fn p521_private_with(members: &str) -> String {
    p521_with(&format!(r#"{members},"d":"{RFC7520_3_2_D}""#))
}

fn rsa_with(members: &str) -> String {
    format!(r#"{{"kty":"RSA","kid":"{KID_BILBO}"{members},"n":"{RFC7520_3_3_N}","e":"AQAB"}}"#)
}

/// RFC 7520 §3.4 (Figure 4): RSA private key members after `n` and `e`.
const RFC7520_3_4_PRIVATE: &str = r#","d":"bWUC9B-EFRIo8kpGfh0ZuyGPvMNKvYWNtB_ikiH9k20eT-O1q_I78eiZkpXxXQ0UTEs2LsNRS-8uJbvQ-A1irkwMSMkK1J3XTGgdrhCku9gRldY7sNA_AKZGh-Q661_42rINLRCe8W-nZ34ui_qOfkLnK9QWDDqpaIsA-bMwWWSDFu2MUBYwkHTMEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU6l-DqEiWxqg82sXt2h-LMnT3046AOYJoRioz75tSUQfGCshWTBnP5uDjd18kKhyv07lhfSJdrPdM5Plyl21hsFf4L_mHCuoFau7gdsPfHPxxjVOcOpBrQzwQ","p":"3Slxg_DwTXJcb6095RoXygQCAZ5RnAvZlno1yhHtnUex_fp7AZ_9nRaO7HX_-SFfGQeutao2TDjDAWU4Vupk8rw9JR0AzZ0N2fvuIAmr_WCsmGpeNqQnev1T7IyEsnh8UMt-n5CafhkikzhEsrmndH6LxOrvRJlsPp6Zv8bUq0k","q":"uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7anV5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0s7pFc","dp":"B8PVvXkvJrj2L-GYQ7v3y9r6Kw5g9SahXBwsWUzp19TVlgI-YV85q1NIb1rxQtD-IsXXR3-TanevuRPRt5OBOdiMGQp8pbt26gljYfKU_E9xn-RULHz0-ed9E9gXLKD4VGngpz-PfQ_q29pk5xWHoJp009Qf1HvChixRX59ehik","dq":"CLDmDGduhylc9o7r84rEUVn7pzQ6PF83Y-iBZx5NT-TpnOZKF1pErAMVeKzFEl41DlHHqqBLSM0W1sOFbwTxYWZDm6sI6og5iTbwQGIC3gnJKbi_7k_vJgGHwHxgPaX2PnvP-zyEkDERuf-ry4c_Z11Cq9AqC2yeL6kdKT1cYF8","qi":"3PiqvXQN0zwMeE-sBvZgi289XP9XCQF3VWqPzMKnIgQp7_Tugo6-NZBKCQsMf3HaEGBjTVJs_jcK8-TRXvaKe-7ZMaQj8VfBdYkssbu0NKDDhjJ-GtiseaDVWt7dcH0cfwxgFUHpQh7FoCrjFJ6h6ZEpMF6xmujs4qMpPz8aaI4""#;

/// RFC 7748 §6.1 Bob's X25519 public key (RFC 8037 §A.6).
const X25519_X: &str = "3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08";

/// Every RFC 7520 §3 key imports, exposes its `kid` for recipient
/// selection (RFC 7516 §4.1.6, RFC 7517 §4.5), and is marked `use: sig`
/// except §3.6, so only §3.6 may serve JWE (RFC 7517 §4.2).
#[test]
fn rfc7520_section_3_keys_import_and_expose_kid_and_use() {
    let keys = [
        (RFC7520_3_1.to_owned(), KID_BILBO, KeyUse::Sig),
        (p521_private_with(r#""use":"sig""#), KID_BILBO, KeyUse::Sig),
        (rsa_with(r#","use":"sig""#), KID_BILBO, KeyUse::Sig),
        (
            RFC7520_3_5.to_owned(),
            "018c0ae5-4d9b-471b-bfd6-eef314bc7037",
            KeyUse::Sig,
        ),
        (
            RFC7520_3_6.to_owned(),
            "1e571774-2e08-40da-8308-e8d68773842d",
            KeyUse::Enc,
        ),
    ];
    let jwe_ops = [
        KeyOp::WrapKey,
        KeyOp::UnwrapKey,
        KeyOp::Encrypt,
        KeyOp::Decrypt,
        KeyOp::DeriveKey,
    ];
    for (json, kid, key_use) in &keys {
        let key = jwk(json);
        assert_eq!(key.kid(), Some(*kid));
        assert_eq!(key.key_use(), Some(key_use));
        for op in &jwe_ops {
            assert_eq!(key.permits(op), *key_use == KeyUse::Enc, "{kid} {op}");
        }
    }
}

/// RFC 7520 §3.6 names its `enc` (`A256GCM`) as its `alg`: the form of a
/// `dir` key (RFC 7518 §4.5), on a 32-octet `oct` key.
#[test]
fn rfc7520_3_6_is_a_dir_key_for_a256gcm() {
    let key = jwk(RFC7520_3_6);
    assert_eq!(key.alg().map(KeyAlg::as_str), Some("A256GCM"));
    assert!(matches!(key.alg(), Some(KeyAlg::ContentEnc(_))));
    let KeyMaterial::Oct(k) = key.material() else {
        panic!("not oct")
    };
    assert_eq!(k.len(), 32);
}

/// ADR 0021: an RSA private JWK, RFC 7520 §3.4, never imports, so JWE can
/// never be handed one.
#[test]
fn rfc7520_3_4_rsa_private_key_is_unsupported() {
    let private = format!(
        r#"{{"kty":"RSA","kid":"{KID_BILBO}","use":"sig","n":"{RFC7520_3_3_N}","e":"AQAB"{RFC7520_3_4_PRIVATE}}}"#
    );
    assert_eq!(
        import(&private).map(|_| ()),
        Err(Error::UnsupportedAlgorithm)
    );
    // One private member is enough.
    let d_only = rsa_with(r#","d":"AQAB""#);
    assert_eq!(
        import(&d_only).map(|_| ()),
        Err(Error::UnsupportedAlgorithm)
    );
}

/// ADRs 0021, 0022: `RSA-OAEP` (SHA-1) and `RSA1_5` are not implemented,
/// as a header `alg` or as a JWK `alg`.
#[test]
fn rsa_oaep_and_rsa1_5_are_unsupported() {
    for name in ["RSA-OAEP", "RSA1_5"] {
        assert!(!KeyMgmtAlg::from(name).is_known(), "{name}");
        let key = rsa_with(&format!(r#","alg":"{name}""#));
        assert_eq!(import(&key).map(|_| ()), Err(Error::UnsupportedAlgorithm));
    }
    let key = jwk(&rsa_with(r#","use":"enc","alg":"RSA-OAEP-256""#));
    assert_eq!(key.key_type(), KeyType::Rsa);
    assert!(key.permits(&KeyOp::WrapKey));
}

/// RFC 7518 §6.2.1: the curve, full-length coordinates (§6.2.1.2–§6.2.1.3:
/// 66 octets for P-521), a point on the curve (ADR 0041 §4) and `d` the
/// private key of that point (§6.2.2.1, ADR 0043 §3).
#[test]
fn ec_keys_are_validated_at_import() {
    let key = jwk(&p521_private_with(r#""use":"enc""#));
    let KeyMaterial::Ec(ec) = key.material() else {
        panic!("not EC")
    };
    assert_eq!(
        (ec.crv(), ec.x().len(), ec.y().len()),
        (EcCurve::P521, 66, 66)
    );
    assert!(ec.is_private());

    let x =
        "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt";
    // Off the curve: y + 1 in its last octet.
    let off_curve = RFC7520_3_1.replace("HqHZR1", "HqHZR2");
    // `x` without its leading zero octet (65 octets).
    let short_x = RFC7520_3_1.replace(
        x,
        "cpkss6wI7PPlxj3t7A1RqMH3nvL4L5Tzxze_XeeYZnHqxiX-gle70DlGRMqqOq-PJ6RYX7vK0PJFdiAIXlyPQq0",
    );
    // Another `d`: in range, but not the private key of this point.
    let wrong_d = p521_with(&format!(
        r#""use":"enc","d":"{}""#,
        RFC7520_3_2_D.replace("AAhR", "AAhS")
    ));
    // d = 0 is outside [1, n - 1].
    let zero_d = p521_with(&format!(r#""use":"enc","d":"{}""#, "A".repeat(88)));
    let cases = [
        (&off_curve, "EC point is not on the curve"),
        (&short_x, "x has the wrong length for crv"),
        (&wrong_d, "EC private key d does not match x and y"),
        (&zero_d, "EC private key d is out of range"),
    ];
    for (bad, detail) in cases {
        assert_eq!(
            import(bad).map(|_| ()),
            Err(Error::InvalidKey(detail)),
            "{bad}"
        );
    }
    // Curves other than P-256, P-384, P-521 and secp256k1 are not keys at
    // all (RFC 7518 §6.2.1.1).
    for crv in ["P-192", "p-521", "X25519"] {
        let other = RFC7520_3_1.replace(r#""crv":"P-521""#, &format!(r#""crv":"{crv}""#));
        assert_eq!(
            import(&other).map(|_| ()),
            Err(Error::UnsupportedAlgorithm),
            "{crv}"
        );
    }
}

/// RFC 8037 §2: an X25519 `x` (and `d`) is 32 octets; RFC 8037 §3.2: an
/// Ed25519 key "MUST NOT be used for ECDH-ES", so a JWK naming that pairing
/// does not import.
#[test]
fn okp_keys_are_validated_at_import() {
    let x25519 = jwk(&format!(
        r#"{{"kty":"OKP","crv":"X25519","x":"{X25519_X}"}}"#
    ));
    let KeyMaterial::Okp(okp) = x25519.material() else {
        panic!("not OKP")
    };
    assert_eq!((okp.crv(), okp.x().len()), (OkpCurve::X25519, 32));
    let short = r#"{"kty":"OKP","crv":"X25519","x":"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IKw"}"#;
    assert!(matches!(import(short), Err(Error::InvalidKey(_))));

    let ed25519_for_ecdh = r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","alg":"ECDH-ES"}"#;
    assert_eq!(
        import(ed25519_for_ecdh).map(|_| ()),
        Err(Error::KeyAlgorithmMismatch)
    );
    let x25519_for_ecdh =
        format!(r#"{{"kty":"OKP","crv":"X25519","x":"{X25519_X}","alg":"ECDH-ES+A128KW"}}"#);
    assert!(import(&x25519_for_ecdh).is_ok());
}

/// RFC 7517 §4.4: a JWK `alg` of another family does not import; so an EC
/// key never names A128KW and an `oct` key never names ECDH-ES.
#[test]
fn a_jwk_alg_of_another_family_does_not_import() {
    let ec_for_kw = p521_with(r#""alg":"A128KW""#);
    assert_eq!(
        import(&ec_for_kw).map(|_| ()),
        Err(Error::KeyAlgorithmMismatch)
    );
    let oct_for_ecdh = r#"{"kty":"oct","k":"GZy6sIZ6wl9NJOKB-jnmVQ","alg":"ECDH-ES"}"#;
    assert_eq!(
        import(oct_for_ecdh).map(|_| ()),
        Err(Error::KeyAlgorithmMismatch)
    );
    let rsa_for_dir = rsa_with(r#","alg":"dir""#);
    assert_eq!(
        import(&rsa_for_dir).map(|_| ()),
        Err(Error::KeyAlgorithmMismatch)
    );
}

/// RFC 7517 §4.3: `key_ops` names the JWE operations the binding checks:
/// `wrapKey`/`unwrapKey`, `encrypt`/`decrypt` and `deriveKey`; and `use`
/// and `key_ops` must agree (a MUST), so `enc` with `sign` does not import.
#[test]
fn key_ops_carry_the_jwe_operations() {
    let key = jwk(r#"{"kty":"oct","k":"GZy6sIZ6wl9NJOKB-jnmVQ","key_ops":["wrapKey"]}"#);
    assert!(key.permits(&KeyOp::WrapKey));
    assert!(!key.permits(&KeyOp::UnwrapKey));
    assert!(!key.permits(&KeyOp::Encrypt));
    let key = jwk(&p521_private_with(r#""key_ops":["deriveKey"]"#));
    assert!(key.permits(&KeyOp::DeriveKey));
    assert!(!key.permits(&KeyOp::DeriveBits));
    let inconsistent =
        r#"{"kty":"oct","k":"GZy6sIZ6wl9NJOKB-jnmVQ","use":"enc","key_ops":["sign"]}"#;
    assert!(matches!(import(inconsistent), Err(Error::InvalidKey(_))));
}

/// ADR 0007: `Debug` of a private key prints no secret. Marker values make
/// any rendering of the secret octets visible.
#[test]
fn debug_of_private_keys_prints_no_secret() {
    let marker = "xcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcU"; // 0xC5 x 32
    let oct = jwk(&format!(r#"{{"kty":"oct","k":"{marker}"}}"#));
    let ec = jwk(&p521_private_with(r#""use":"enc""#));
    for (key, secret) in [(&oct, marker), (&ec, RFC7520_3_2_D)] {
        let debug = format!("{key:?}");
        assert!(!debug.contains(secret), "{debug}");
        assert!(!debug.contains("197, 197"), "{debug}");
        assert!(!debug.to_lowercase().contains("c5c5"), "{debug}");
        assert!(debug.contains("<redacted>"), "{debug}");
    }
}
