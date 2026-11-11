//! Feature 0005 regression spot checks through the public API only: every `KeySpec`
//! generates, `generate_for`'s table, and the refusals that must all be `UnsupportedAlgorithm`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a panic is a failed assertion

use std::path::Path;

use polyjose::Error;
use polyjose::jwa::{ContentEncAlg, KeyMgmtAlg, SigningAlg};
use polyjose::jwk::{EcCurve, Jwk, KeyMaterial, OkpCurve};
use polyjose::keys::{KeyFormat, KeySpec, generate, generate_for};

fn fixture(rel: &str) -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/data/keys")
            .join(rel),
    )
    .unwrap()
}

#[test]
fn every_keyspec_generates_a_valid_distinct_key() {
    let specs = [
        KeySpec::Oct { bytes: 32 },
        KeySpec::Ec(EcCurve::P256),
        KeySpec::Ec(EcCurve::P384),
        KeySpec::Ec(EcCurve::P521),
        KeySpec::Ec(EcCurve::Secp256k1),
        KeySpec::Okp(OkpCurve::Ed25519),
        KeySpec::Okp(OkpCurve::X25519),
    ];
    for spec in specs {
        let a = generate(spec).unwrap();
        let b = generate(spec).unwrap();
        assert_ne!(
            a.to_json().as_str(),
            b.to_json().as_str(),
            "{spec:?} repeated a key"
        );
        Jwk::from_json(a.to_json().as_bytes()).unwrap();
    }
}

#[test]
fn generate_for_table() {
    use SigningAlg as S;
    let oct = |alg: &Jwk| match alg.material() {
        KeyMaterial::Oct(k) => k.len(),
        _ => panic!("not oct"),
    };
    assert_eq!(oct(&generate_for(S::HS256).unwrap()), 32);
    assert_eq!(oct(&generate_for(S::HS384).unwrap()), 48);
    assert_eq!(oct(&generate_for(S::HS512).unwrap()), 64);
    assert_eq!(oct(&generate_for(KeyMgmtAlg::A128KW).unwrap()), 16);
    assert_eq!(oct(&generate_for(KeyMgmtAlg::A192GCMKW).unwrap()), 24);
    assert_eq!(oct(&generate_for(KeyMgmtAlg::A256KW).unwrap()), 32);
    assert_eq!(oct(&generate_for(ContentEncAlg::A128CbcHs256).unwrap()), 32);
    assert_eq!(oct(&generate_for(ContentEncAlg::A192CbcHs384).unwrap()), 48);
    assert_eq!(oct(&generate_for(ContentEncAlg::A256CbcHs512).unwrap()), 64);
    assert_eq!(oct(&generate_for(ContentEncAlg::A192GCM).unwrap()), 24);
    for (alg, crv) in [
        (S::ES256, EcCurve::P256),
        (S::ES384, EcCurve::P384),
        (S::ES512, EcCurve::P521),
        (S::ES256K, EcCurve::Secp256k1),
    ] {
        match generate_for(alg.clone()).unwrap().material() {
            KeyMaterial::Ec(k) => assert_eq!(k.crv(), crv),
            _ => panic!("not EC"),
        }
    }
    for alg in [S::EdDSA, S::Ed25519] {
        match generate_for(alg).unwrap().material() {
            KeyMaterial::Okp(k) => assert_eq!(k.crv(), OkpCurve::Ed25519),
            _ => panic!("not OKP"),
        }
    }
    assert_eq!(
        generate_for(S::ES256).unwrap().alg().unwrap().as_str(),
        "ES256"
    );
    for alg in [
        KeyMgmtAlg::EcdhEs,
        KeyMgmtAlg::EcdhEsA128KW,
        KeyMgmtAlg::EcdhEsA192KW,
        KeyMgmtAlg::EcdhEsA256KW,
    ] {
        assert!(matches!(generate_for(alg), Err(Error::InvalidKey(_))));
    }
    for alg in [
        S::RS256,
        S::RS384,
        S::RS512,
        S::PS256,
        S::PS384,
        S::PS512,
        S::None,
    ] {
        assert!(matches!(
            generate_for(alg),
            Err(Error::UnsupportedAlgorithm)
        ));
    }
    assert!(matches!(
        generate_for(KeyMgmtAlg::RsaOaep256),
        Err(Error::UnsupportedAlgorithm)
    ));
    assert!(matches!(
        generate_for(KeyMgmtAlg::Dir),
        Err(Error::UnsupportedAlgorithm)
    ));
    assert!(matches!(
        generate_for(KeyMgmtAlg::Pbes2Hs256A128KW),
        Err(Error::UnsupportedAlgorithm)
    ));
    assert!(matches!(
        generate_for(S::Unknown("X".into())),
        Err(Error::UnsupportedAlgorithm)
    ));
}

#[test]
fn unsupported_inputs_are_unsupported_algorithm() {
    // ADR 0067 §3: multi-prime RSA private keys stay unsupported (the
    // two-prime ones import; see the next test).
    for f in [
        "openssl/reject-rsa2048-3prime-private-pkcs8.pem",
        "openssl/reject-rsa2048-3prime-private-pkcs1.pem",
        "openssl/reject-rsa2048-pkcs8-encrypted.pem",
        "openssl/reject-ec-p256-pkcs8-encrypted.pem",
        "openssl/reject-ed25519-pkcs8-encrypted.pem",
        "openssl/reject-ed448-pkcs8.pem",
        "openssl/reject-ed448-spki.pem",
        "openssl/reject-x448-pkcs8.pem",
        "openssl/reject-rsapss2048-spki.pem",
        "openssl/reject-rsapss2048-private-pkcs8.pem",
        "openssl/reject-rsa2048-pkcs1-legacy-encrypted.pem",
    ] {
        let pem = String::from_utf8(fixture(f)).unwrap();
        assert!(
            matches!(Jwk::from_pem(&pem), Err(Error::UnsupportedAlgorithm)),
            "{f}"
        );
    }
    assert!(matches!(
        Jwk::from_der(
            &fixture("openssl/reject-ec-p256-pkcs8-encrypted.der"),
            KeyFormat::Pkcs8
        ),
        Err(Error::UnsupportedAlgorithm)
    ));
}

#[test]
fn two_prime_rsa_private_keys_import_in_every_form() {
    // ADR 0067: PKCS#8 (RFC 5958) and PKCS#1 RSAPrivateKey (RFC 8017
    // App. A.1.2), PEM and DER, all give the one private key whose public
    // half is rsa2048-spki.pem. The fixtures keep their `reject-` names.
    let public = Jwk::from_pem(&String::from_utf8(fixture("openssl/rsa2048-spki.pem")).unwrap())
        .unwrap()
        .to_object();
    let keys = [
        Jwk::from_pem(
            &String::from_utf8(fixture("openssl/reject-rsa2048-private-pkcs8.pem")).unwrap(),
        ),
        Jwk::from_pem(
            &String::from_utf8(fixture("openssl/reject-rsa2048-private-pkcs1.pem")).unwrap(),
        ),
        Jwk::from_der(
            &fixture("openssl/reject-rsa2048-private-pkcs8.der"),
            KeyFormat::Pkcs8,
        ),
        Jwk::from_der(
            &fixture("openssl/reject-rsa2048-private-pkcs1.der"),
            KeyFormat::Pkcs1,
        ),
    ];
    for (i, key) in keys.iter().enumerate() {
        let key = key.as_ref().unwrap_or_else(|e| panic!("{i}: {e}"));
        let KeyMaterial::Rsa(rsa) = key.material() else {
            panic!("{i}: not RSA")
        };
        assert!(rsa.is_private(), "{i}");
        assert_eq!(key.to_public().unwrap().to_object(), public, "{i}");
    }
}

#[test]
fn pem_and_der_never_yield_oct_and_oct_never_exports() {
    let k = generate(KeySpec::Oct { bytes: 32 }).unwrap();
    for f in [
        KeyFormat::Pkcs8,
        KeyFormat::Sec1,
        KeyFormat::Spki,
        KeyFormat::Pkcs1,
    ] {
        assert!(k.to_der(f).is_err());
        assert!(k.to_pem(f).is_err());
    }
    for rel in [
        "openssl/ec-p256-pkcs8.der",
        "openssl/rsa2048-spki.der",
        "openssl/ed25519-pkcs8.der",
    ] {
        let der = fixture(rel);
        for f in [
            KeyFormat::Pkcs8,
            KeyFormat::Sec1,
            KeyFormat::Spki,
            KeyFormat::Pkcs1,
        ] {
            if let Ok(j) = Jwk::from_der(&der, f) {
                assert!(!matches!(j.material(), KeyMaterial::Oct(_)));
            }
        }
    }
}

#[test]
fn rsa_keys_round_trip_and_public_rsa_has_no_private_form() {
    let pem = String::from_utf8(fixture("openssl/rsa2048-spki.pem")).unwrap();
    let k = Jwk::from_pem(&pem).unwrap();
    assert_eq!(k.to_pem(KeyFormat::Spki).unwrap().as_str(), pem);
    // ADR 0067: PKCS#8 of an RSA public key needs a private key.
    assert_eq!(
        k.to_pem(KeyFormat::Pkcs8).map(|_| ()),
        Err(Error::InvalidKey("private key required"))
    );
    assert!(k.to_pem(KeyFormat::Sec1).is_err());
    // ADR 0067: the private key round-trips through PKCS#8, and its SPKI
    // export is the public fixture.
    let private_pem =
        String::from_utf8(fixture("openssl/reject-rsa2048-private-pkcs8.pem")).unwrap();
    let private = Jwk::from_pem(&private_pem).unwrap();
    assert_eq!(
        private.to_pem(KeyFormat::Pkcs8).unwrap().as_str(),
        private_pem
    );
    assert_eq!(private.to_pem(KeyFormat::Spki).unwrap().as_str(), pem);
    assert!(private.to_pem(KeyFormat::Sec1).is_err());
}
