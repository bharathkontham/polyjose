//! Generated keys (`keys::generate`, ADR 0018 §5) through the PEM/DER
//! facade (ADR 0018 §3):
//!
//! - for each `KeySpec` of an asymmetric key (EC P-256, P-384, P-521,
//!   secp256k1; OKP Ed25519, X25519), `generate` → `to_pem` in every format
//!   the matrix allows → `from_pem` gives the same JWK;
//! - the JWK passes the typed-JWK validation (`Jwk::from_json`; ADR 0041
//!   §4, ADR 0043) after a JSON round trip;
//! - `to_pem(Spki)` of the private key equals `to_pem(Spki)` of its
//!   `to_public()`;
//! - `generate_for` binds `alg` (RFC 8725 §3.1), which PEM does not carry.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a panic is a failed assertion

use polyjose::Error;
use polyjose::jwa::SigningAlg;
use polyjose::jwk::{EcCurve, Jwk, OkpCurve};
use polyjose::keys::{KeyFormat, KeySpec, generate, generate_for};
use zeroize::Zeroizing;

/// Every asymmetric `KeySpec` and the formats the matrix allows for its
/// private key: whether each keeps the private part.
fn specs() -> Vec<(KeySpec, Vec<(KeyFormat, bool)>)> {
    let ec = vec![
        (KeyFormat::Pkcs8, true),
        (KeyFormat::Sec1, true),
        (KeyFormat::Spki, false),
    ];
    let okp = vec![(KeyFormat::Pkcs8, true), (KeyFormat::Spki, false)];
    let mut out: Vec<(KeySpec, Vec<(KeyFormat, bool)>)> = [
        EcCurve::P256,
        EcCurve::P384,
        EcCurve::P521,
        EcCurve::Secp256k1,
    ]
    .into_iter()
    .map(|crv| (KeySpec::Ec(crv), ec.clone()))
    .collect();
    for crv in [OkpCurve::Ed25519, OkpCurve::X25519] {
        out.push((KeySpec::Okp(crv), okp.clone()));
    }
    out
}

#[test]
fn generated_keys_round_trip_through_pem_in_every_allowed_format() {
    for (spec, formats) in specs() {
        // A few keys per spec, so one lucky encoding proves nothing alone.
        for _ in 0..4 {
            let jwk = generate(spec).unwrap();
            let public = jwk.to_public().unwrap();
            for (format, keeps_private) in &formats {
                let pem: Zeroizing<String> = jwk.to_pem(*format).unwrap();
                let back =
                    Jwk::from_pem(&pem).unwrap_or_else(|e| panic!("{spec:?} {format:?}: {e:?}"));
                let want = if *keeps_private { &jwk } else { &public };
                assert_eq!(back.to_object(), want.to_object(), "{spec:?} {format:?}");
                // And the DER entry points agree with the PEM ones.
                let der: Zeroizing<Vec<u8>> = jwk.to_der(*format).unwrap();
                let from_der = Jwk::from_der(&der, *format).unwrap();
                assert_eq!(
                    from_der.to_object(),
                    back.to_object(),
                    "{spec:?} {format:?}"
                );
            }
        }
    }
}

#[test]
fn generated_keys_validate_after_a_json_round_trip() {
    for (spec, formats) in specs() {
        let jwk = generate(spec).unwrap();
        let json = jwk.to_json();
        let reparsed =
            Jwk::from_json(json.as_bytes()).unwrap_or_else(|e| panic!("{spec:?}: {e:?}"));
        assert_eq!(reparsed.to_object(), jwk.to_object(), "{spec:?}");
        // The PEM import of the reparsed key is validated the same way.
        for (format, _) in formats {
            let back = Jwk::from_pem(&reparsed.to_pem(format).unwrap()).unwrap();
            let again = Jwk::from_json(back.to_json().as_bytes()).unwrap();
            assert_eq!(again.to_object(), back.to_object(), "{spec:?} {format:?}");
        }
    }
}

#[test]
fn spki_of_a_private_key_is_spki_of_its_public_key() {
    for (spec, _) in specs() {
        let jwk = generate(spec).unwrap();
        let public = jwk.to_public().unwrap();
        assert_eq!(
            *jwk.to_pem(KeyFormat::Spki).unwrap(),
            *public.to_pem(KeyFormat::Spki).unwrap(),
            "{spec:?}"
        );
        assert_eq!(
            *jwk.to_der(KeyFormat::Spki).unwrap(),
            *public.to_der(KeyFormat::Spki).unwrap(),
            "{spec:?}"
        );
    }
}

#[test]
fn generated_keys_refuse_the_formats_the_matrix_forbids() {
    for (spec, allowed) in specs() {
        let jwk = generate(spec).unwrap();
        let public = jwk.to_public().unwrap();
        for format in [
            KeyFormat::Pkcs8,
            KeyFormat::Sec1,
            KeyFormat::Spki,
            KeyFormat::Pkcs1,
        ] {
            if !allowed.iter().any(|(f, _)| *f == format) {
                assert_eq!(
                    jwk.to_pem(format).unwrap_err(),
                    Error::UnsupportedAlgorithm,
                    "{spec:?} {format:?}"
                );
            }
        }
        for format in [KeyFormat::Pkcs8, KeyFormat::Sec1] {
            let want = if allowed.iter().any(|(f, _)| *f == format) {
                Error::InvalidKey("private key required")
            } else {
                Error::UnsupportedAlgorithm
            };
            assert_eq!(
                public.to_pem(format).unwrap_err(),
                want,
                "{spec:?} {format:?}"
            );
        }
    }
    for bytes in [16, 32, 64] {
        let oct = generate(KeySpec::Oct { bytes }).unwrap();
        assert_eq!(
            oct.to_pem(KeyFormat::Pkcs8).unwrap_err(),
            Error::UnsupportedAlgorithm
        );
    }
}

#[test]
fn alg_bound_by_generate_for_is_not_carried_by_pem() {
    // The JWK `alg` member (RFC 7517 §4.4) has no place in PKCS#8 or SPKI,
    // so the imported key is unbound; the key material is the same.
    for alg in [SigningAlg::ES256, SigningAlg::ES256K, SigningAlg::Ed25519] {
        let jwk = generate_for(alg.clone()).unwrap();
        assert_eq!(jwk.alg().map(|a| a.as_str()), Some(alg.as_str()));
        let back = Jwk::from_pem(&jwk.to_pem(KeyFormat::Pkcs8).unwrap()).unwrap();
        assert_eq!(back.alg(), None);
        assert_eq!(
            back.thumbprint_sha256(),
            jwk.thumbprint_sha256(),
            "{alg:?}: same key"
        );
    }
}
