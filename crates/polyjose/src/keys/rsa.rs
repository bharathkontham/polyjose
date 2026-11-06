//! RSA public keys (RFC 7518 §6.3.1) to and from SPKI with rsaEncryption and
//! NULL parameters (RFC 3279 §2.3.1, RFC 8017 App. A.1) and the standalone
//! PKCS#1 RSAPublicKey (RFC 8017 App. A.1.1, OpenSSL's `RSA PUBLIC KEY`).
//!
//! Every RSA private key encoding (RFC 8017 App. A.1.2 RSAPrivateKey, in
//! PKCS#8 or PKCS#1) is rejected as unsupported (ADR 0021), and none of its
//! private INTEGERs is ever parsed:
//!
//! - PKCS#8 with rsaEncryption: `pkcs8::decode` returns on the
//!   AlgorithmIdentifier and never opens privateKey.
//! - PEM `RSA PRIVATE KEY`: `pem::decode` refuses the BEGIN line before the
//!   body is decoded.
//! - PKCS#1 DER: `pkcs1::decode` recognizes the RSAPrivateKey shape from
//!   its version and the framing of the INTEGERs after it.
//! - A PKCS#1 RSAPrivateKey read as PKCS#8 or SEC1 (under `PRIVATE KEY` or
//!   `EC PRIVATE KEY`, ADR 0018 §3): `pkcs8::decode` and
//!   `sec1::decode_standalone` fail their own parse, then
//!   `pkcs1::relabel_rsa_private_key` recognizes the same framing.
//!
//! This module never uses the rsa crate: an RSA public key is two DER
//! INTEGERs, and [`Jwk::from_object`](crate::jwk::Jwk::from_object), reached
//! through `jwk_build::rsa_public_jwk`, checks that they are a usable key
//! (a modulus of 2048–8192 bits, [`RSA_MODULUS_BITS`]: at least 2048 by
//! RFC 7518 §3.3, §4.2 and ADR 0007, at most 8192 by ADR 0026 §2 step 8;
//! odd `n`; odd `e` with 3 ≤ e < n, RFC 8017 §3.1).
//!
//! [`RSA_MODULUS_BITS`]: crate::jwk::RSA_MODULUS_BITS

use zeroize::Zeroizing;

use super::jwk_build;
use super::pkcs1::{self, RsaPublicParts};
use super::spki;
use super::types::{AlgId, SpkiParts};
use crate::error::{Error, Result};
use crate::jwk::{Jwk, RsaPublicKey};

/// Imports the RSA public key of a SubjectPublicKeyInfo (RFC 5280 §4.1.2.7)
/// that `spki::decode` classified as rsaEncryption with NULL parameters
/// (RFC 3279 §2.3.1). Its subjectPublicKey "MUST" be an RSAPublicKey
/// (RFC 3279 §2.3.1, RFC 8017 App. A.1.1), decoded by
/// `pkcs1::decode_public`.
///
/// No `alg` is set: an SPKI does not carry one (RFC 7517 §4.4 is optional).
///
/// # Errors
///
/// [`Error::InvalidKey`] when `parts` is not an rsaEncryption key, when the
/// subjectPublicKey is not a well-formed RSAPublicKey (a negative or
/// non-minimal INTEGER, an extra field, an EC point), and for whatever
/// [`Jwk::from_object`] refuses: a modulus outside 2048–8192 bits
/// ([`RSA_MODULUS_BITS`](crate::jwk::RSA_MODULUS_BITS); RFC 7518 §3.3,
/// ADR 0026 §2 step 8), an even modulus, an exponent that is even or
/// outside 3 ≤ e < n.
pub(crate) fn from_spki(parts: SpkiParts<'_>) -> Result<Jwk> {
    if parts.alg != AlgId::RsaEncryption {
        return Err(Error::InvalidKey("the key is not an RSA key"));
    }
    to_jwk(pkcs1::decode_public(parts.subject_public_key)?)
}

/// Imports standalone PKCS#1 DER (`KeyFormat::Pkcs1`, the body of an
/// `RSA PUBLIC KEY` PEM block): an RSAPublicKey (RFC 8017 App. A.1.1),
/// told apart from an RSAPrivateKey (App. A.1.2) by `pkcs1::decode`.
///
/// # Errors
///
/// [`Error::UnsupportedAlgorithm`] for an RSAPrivateKey (ADR 0021), refused
/// before any private INTEGER is parsed. [`Error::InvalidKey`] for any other
/// DER that is not an RSAPublicKey, and for whatever [`Jwk::from_object`]
/// refuses (see [`from_spki`]).
pub(crate) fn from_pkcs1(der: &[u8]) -> Result<Jwk> {
    to_jwk(pkcs1::decode(der)?)
}

/// The JWK of an RSAPublicKey: `n` and `e` as Base64urlUInt in the fewest
/// octets (RFC 7518 §2, §6.3.1.1, §6.3.1.2), which the DER magnitudes
/// already are, validated by [`Jwk::from_object`].
fn to_jwk(key: RsaPublicParts<'_>) -> Result<Jwk> {
    jwk_build::rsa_public_jwk(key.n, key.e, None)
}

/// Exports an RSA public key as a DER SubjectPublicKeyInfo (RFC 5280
/// §4.1.2.7): the rsaEncryption + NULL AlgorithmIdentifier (RFC 3279
/// §2.3.1) and the RSAPublicKey in a BIT STRING with no unused bits, the
/// layout OpenSSL 4 emits (ADR 0018 §3).
pub(crate) fn to_spki(key: &RsaPublicKey) -> Result<Zeroizing<Vec<u8>>> {
    let rsa_public_key = to_pkcs1(key)?;
    spki::encode(&SpkiParts {
        alg: AlgId::RsaEncryption,
        subject_public_key: &rsa_public_key,
    })
}

/// Exports an RSA public key as a DER PKCS#1 RSAPublicKey (RFC 8017
/// App. A.1.1), the body of OpenSSL's `RSA PUBLIC KEY` PEM block.
pub(crate) fn to_pkcs1(key: &RsaPublicKey) -> Result<Zeroizing<Vec<u8>>> {
    pkcs1::encode_public(key.n(), key.e())
}

#[cfg(test)]
mod tests {
    use super::super::der::fixtures;
    use super::super::types::{AlgId, Label};
    use super::super::{oid, pem, pkcs8};
    use super::*;
    use crate::jwk::KeyMaterial;

    /// The JWK of a committed `.jwk.json` fixture.
    fn jwk_fixture(dir: &str, file: &str) -> Jwk {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/data/keys")
            .join(dir)
            .join(file);
        let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        Jwk::from_json(&bytes).unwrap_or_else(|e| panic!("{file}: {e:?}"))
    }

    /// The text of a committed PEM fixture.
    fn pem_text(dir: &str, file: &str) -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/data/keys")
            .join(dir)
            .join(file);
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
    }

    fn rsa(jwk: &Jwk) -> &RsaPublicKey {
        let KeyMaterial::Rsa(key) = jwk.material() else {
            panic!("an RSA key")
        };
        key
    }

    fn assert_same_key(actual: &Jwk, expected: &Jwk, what: &str) {
        assert_eq!(*actual.to_json(), *expected.to_json(), "{what}");
    }

    /// `der` through the SPKI container (T02) and this mapper.
    fn import_spki(der: &[u8]) -> Result<Jwk> {
        from_spki(spki::decode(der)?)
    }

    /// The positive RSA fixtures: directory, file, whether it is SPKI (else
    /// PKCS#1 RSAPublicKey), and the expected JWK file. Both the `.der` and
    /// the `.pem` form are listed where both are committed.
    fn positive() -> Vec<(&'static str, String, bool, String)> {
        let mut out = Vec::new();
        for (dir, prefix) in [("openssl", "rsa"), ("rfc", "rfc7517-a1-rsa")] {
            for file in fixtures::files(dir, |name| name.starts_with(prefix)) {
                let stem = file.rsplit_once('.').unwrap().0.to_owned();
                let spki = stem.ends_with("-spki");
                assert!(spki || stem.ends_with("-pkcs1-pub"), "{file}");
                let expected = if dir == "openssl" {
                    format!("expected/{stem}.jwk.json")
                } else {
                    format!("{stem}.jwk.json")
                };
                out.push((dir, file, spki, expected));
            }
        }
        // openssl: rsa2048-spki (der, pem), rsa3072-spki, rsa4096-spki,
        // rsa2048-pkcs1-pub (der, pem), rsa4096-pkcs1-pub; RFC 7517 A.1 as
        // SPKI and PKCS#1 (der, pem each).
        assert_eq!(out.len(), 11);
        out
    }

    fn import(der: &[u8], spki: bool) -> Result<Jwk> {
        if spki {
            import_spki(der)
        } else {
            from_pkcs1(der)
        }
    }

    #[test]
    fn rfc7517_a1_imports_to_the_rfc_jwk_and_exports_back() {
        // RFC 7517 App. A.1: `n` as a minimal Base64urlUInt (RFC 7518 §2,
        // §6.3.1.1), `e` = AQAB.
        let expected = jwk_fixture("rfc", "rfc7517-a1-rsa-spki.jwk.json");
        assert_eq!(rsa(&expected).e(), &[0x01, 0x00, 0x01]);
        let spki_der = fixtures::load("rfc", "rfc7517-a1-rsa-spki.der");
        let pkcs1_der = fixtures::load("rfc", "rfc7517-a1-rsa-pkcs1-pub.der");
        let from_spki_der = import_spki(&spki_der).unwrap();
        let from_pkcs1_der = from_pkcs1(&pkcs1_der).unwrap();
        assert_same_key(&from_spki_der, &expected, "SPKI");
        assert_same_key(&from_pkcs1_der, &expected, "PKCS#1");
        assert_eq!(rsa(&from_spki_der).modulus_bits(), 2048);
        for jwk in [&from_spki_der, &from_pkcs1_der] {
            assert_eq!(&to_spki(rsa(jwk)).unwrap()[..], &spki_der[..]);
            assert_eq!(&to_pkcs1(rsa(jwk)).unwrap()[..], &pkcs1_der[..]);
        }
    }

    #[test]
    fn every_positive_fixture_imports_and_exports_byte_for_byte() {
        // ADR 0018 §3: import to the expected JWK, and export in the layout
        // OpenSSL 4 emits, as DER and as PEM, in the fixture's own format.
        for (dir, file, spki, expected) in positive() {
            let der = fixtures::load(dir, &file);
            let jwk = import(&der, spki).unwrap_or_else(|e| panic!("{file}: {e:?}"));
            assert_same_key(&jwk, &jwk_fixture(dir, &expected), &file);
            assert!(jwk.is_public() && jwk.alg().is_none(), "{file}");
            let (exported, label) = if spki {
                (to_spki(rsa(&jwk)).unwrap(), Label::PublicKey)
            } else {
                (to_pkcs1(rsa(&jwk)).unwrap(), Label::RsaPublic)
            };
            assert_eq!(&exported[..], &der[..], "{file}");
            if file.ends_with(".pem") {
                let text = pem::encode(label, &exported).unwrap();
                assert_eq!(text.as_str(), pem_text(dir, &file), "{file}");
            }
        }
    }

    #[test]
    fn spki_and_pkcs1_exports_carry_the_same_rsa_public_key() {
        // RFC 3279 §2.3.1: the rsaEncryption subjectPublicKey is the
        // RSAPublicKey, so the PKCS#1 export is the SPKI's BIT STRING
        // contents, and the other format of the same key matches its own
        // fixture where one is committed.
        for (dir, file, spki, _) in positive() {
            let der = fixtures::load(dir, &file);
            let jwk = import(&der, spki).unwrap();
            let as_spki = to_spki(rsa(&jwk)).unwrap();
            let as_pkcs1 = to_pkcs1(rsa(&jwk)).unwrap();
            let parts = spki::decode(&as_spki).unwrap();
            assert_eq!(parts.alg, AlgId::RsaEncryption, "{file}");
            assert_eq!(parts.subject_public_key, &as_pkcs1[..], "{file}");
            let other = if spki {
                file.replace("-spki", "-pkcs1-pub")
            } else {
                file.replace("-pkcs1-pub", "-spki")
            };
            if fixtures::files(dir, |name| name == other).len() == 1 {
                let other_der = fixtures::load(dir, &other);
                let exported = if spki { &as_pkcs1 } else { &as_spki };
                assert_eq!(&exported[..], &other_der[..], "{file} as {other}");
            }
        }
    }

    #[test]
    fn the_crate_pem_decoder_feeds_the_same_keys() {
        // The positive PEM fixtures through polyjose's own RFC 7468 codec
        // (T03) rather than the test oracle: the label names the structure.
        for (dir, file, spki, expected) in positive() {
            if !file.ends_with(".pem") {
                continue;
            }
            let (label, der) = pem::decode(&pem_text(dir, &file)).unwrap();
            assert_eq!(
                label,
                if spki {
                    Label::PublicKey
                } else {
                    Label::RsaPublic
                }
            );
            let jwk = import(&der, spki).unwrap();
            assert_same_key(&jwk, &jwk_fixture(dir, &expected), &file);
        }
    }

    fn is_invalid<T>(result: &Result<T>) -> bool {
        matches!(result, Err(Error::InvalidKey(_)))
    }

    fn is_unsupported<T>(result: &Result<T>) -> bool {
        matches!(result, Err(Error::UnsupportedAlgorithm))
    }

    /// The `InvalidKey` detail of `result`.
    fn detail<T>(result: Result<T>) -> &'static str {
        match result {
            Err(Error::InvalidKey(detail)) => detail,
            Err(other) => panic!("expected InvalidKey, got {other:?}"),
            Ok(_) => panic!("expected InvalidKey, got a key"),
        }
    }

    #[test]
    fn malformed_rsa_public_key_vectors_are_invalid() {
        // N60 rsaEncryption without NULL (RFC 3279 §2.3.1), N61 negative
        // and N62 non-minimal modulus (X.690 §8.3.2, §8.3.3), N66 an EC
        // point where the RSAPublicKey belongs (RFC 3279 §2.3.1): the
        // encoding. N63 e = 1 (RFC 8017 §3.1) and N64 a 1024-bit modulus
        // (RFC 7518 §3.3, §4.2, ADR 0007): the JWK validation.
        for id in ["N60", "N61", "N62", "N66"] {
            assert!(is_invalid(&import_spki(&fixtures::negative(id))), "{id}");
        }
        assert_eq!(
            detail(import_spki(&fixtures::negative("N63"))),
            "RSA exponent must be odd and greater than 1"
        );
        assert_eq!(
            detail(import_spki(&fixtures::negative("N64"))),
            "RSA modulus is shorter than 2048 bits"
        );
        // N65: a third INTEGER after modulus and publicExponent (RFC 8017
        // App. A.1.1).
        assert!(is_invalid(&from_pkcs1(&fixtures::negative("N65"))));
    }

    #[test]
    fn rsa1024_public_keys_are_refused_by_the_jwk_validation() {
        // RFC 7518 §3.3, §4.2 and ADR 0007: at least 2048 bits, enforced by
        // Jwk::from_object (0001 T05), through both PEM decoders.
        for (file, spki) in [
            ("reject-rsa1024-spki.pem", true),
            ("reject-rsa1024-pkcs1-pub.pem", false),
        ] {
            let oracle = fixtures::load("openssl", file);
            let (_, ours) = pem::decode(&pem_text("openssl", file)).unwrap();
            assert_eq!(&ours[..], &oracle[..], "{file}");
            assert_eq!(
                detail(import(&ours, spki)),
                "RSA modulus is shorter than 2048 bits",
                "{file}"
            );
        }
    }

    #[test]
    fn from_spki_refuses_a_key_of_another_type() {
        for file in ["ec-p256-spki.der", "ed25519-spki.pem", "x25519-spki.pem"] {
            let der = fixtures::load("openssl", file);
            let parts = spki::decode(&der).unwrap();
            assert_eq!(
                detail(from_spki(parts)),
                "the key is not an RSA key",
                "{file}"
            );
        }
    }

    /// `text` through polyjose's PEM codec, then the structure its label
    /// names: PKCS#8 for `PRIVATE KEY`, SPKI for `PUBLIC KEY`, PKCS#1 for
    /// `RSA PUBLIC KEY` (the T08 dispatch, reduced to what RSA needs).
    fn import_pem(text: &str) -> Result<()> {
        let (label, der) = pem::decode(text)?;
        match label {
            Label::PrivateKey => pkcs8::decode(&der).map(drop),
            Label::PublicKey => import_spki(&der).map(drop),
            Label::RsaPublic => from_pkcs1(&der).map(drop),
            other => panic!("pem::decode returned {other:?}"),
        }
    }

    /// Every RSA private key fixture of the acceptance criteria (ADR 0021),
    /// with whether it is PKCS#8 (else PKCS#1 RSAPrivateKey) and whether the
    /// test oracle can turn it into DER (legacy encrypted PEM has RFC 1421
    /// headers, which RFC 7468 does not allow).
    fn rsa_private_fixtures() -> Vec<(&'static str, String, bool, bool)> {
        let mut out = Vec::new();
        for bits in [1024, 2048, 3072, 4096] {
            for ext in ["pem", "der"] {
                let file = format!("reject-rsa{bits}-private-pkcs8.{ext}");
                if fixtures::files("openssl", |name| name == file).len() == 1 {
                    out.push(("openssl", file, true, true));
                }
            }
        }
        for (file, pkcs8, oracle) in [
            ("reject-rsa2048-private-pkcs1.pem", false, true),
            ("reject-rsa2048-private-pkcs1.der", false, true),
            ("reject-rsa2048-3prime-private-pkcs8.pem", true, true),
            ("reject-rsa2048-3prime-private-pkcs1.pem", false, true),
            ("reject-rsa2048-pkcs8-encrypted.pem", true, true),
            ("reject-rsa2048-pkcs1-legacy-encrypted.pem", false, false),
        ] {
            out.push(("openssl", file.to_owned(), pkcs8, oracle));
        }
        for bits in [1024, 2048, 4096] {
            let file = format!("reject-rfc9500-testRSA{bits}-private-pkcs1.pem");
            out.push(("rfc", file, false, true));
        }
        // rsa{1024,2048,3072,4096}-private-pkcs8.pem, the 2048-bit .der,
        // and the nine others listed.
        assert_eq!(out.len(), 14);
        out
    }

    #[test]
    fn every_rsa_private_key_fixture_is_unsupported() {
        // ADR 0021 end to end. PEM through polyjose's codec: `RSA PRIVATE
        // KEY` and `ENCRYPTED PRIVATE KEY` are refused from the BEGIN line,
        // and `PRIVATE KEY` (PKCS#8 rsaEncryption) by pkcs8::decode on the
        // AlgorithmIdentifier. DER through the decoder of its format.
        for (dir, file, pkcs8, oracle) in rsa_private_fixtures() {
            if file.ends_with(".pem") {
                let result = import_pem(&pem_text(dir, &file));
                assert!(is_unsupported(&result), "{file}: {:?}", result.err());
            }
            if oracle {
                let der = fixtures::load(dir, &file);
                let result = if pkcs8 {
                    pkcs8::decode(&der).map(drop)
                } else {
                    from_pkcs1(&der).map(drop)
                };
                assert!(is_unsupported(&result), "{file} as DER: {:?}", result.err());
            }
        }
        // N67: a minimal PKCS#8 with rsaEncryption.
        assert!(is_unsupported(&pkcs8::decode(&fixtures::negative("N67"))));
    }

    #[test]
    fn pkcs8_rsa_private_keys_are_refused_before_private_key_is_opened() {
        // pkcs8::decode returns on the rsaEncryption AlgorithmIdentifier
        // (ADR 0021): with the privateKey's identifier octet replaced by
        // the high-tag-number form, which any read of that element rejects
        // as InvalidKey (X.690 §8.1.2.4), the result is still
        // UnsupportedAlgorithm.
        let mut keys = vec![fixtures::negative("N67")];
        for (dir, file, pkcs8, oracle) in rsa_private_fixtures() {
            if pkcs8 && oracle && !file.contains("encrypted") {
                keys.push(fixtures::load(dir, &file));
            }
        }
        assert_eq!(keys.len(), 7);
        for mut der in keys {
            let at = der
                .windows(oid::ALG_RSA_ENCRYPTION.len())
                .position(|window| window == oid::ALG_RSA_ENCRYPTION)
                .unwrap()
                + oid::ALG_RSA_ENCRYPTION.len();
            assert_eq!(der[at], 0x04, "privateKey is an OCTET STRING");
            der[at] = 0x1F;
            assert!(is_unsupported(&pkcs8::decode(&der)));
        }
    }

    #[test]
    fn rsa_pss_keys_are_unsupported() {
        // id-RSASSA-PSS (RFC 4055 §3.1) is not rsaEncryption: unsupported
        // in SPKI and in PKCS#8 (ADR 0018 §4 step 1).
        let result = import_pem(&pem_text("openssl", "reject-rsapss2048-spki.pem"));
        assert!(is_unsupported(&result), "{:?}", result.err());
        let result = import_pem(&pem_text("openssl", "reject-rsapss2048-private-pkcs8.pem"));
        assert!(is_unsupported(&result), "{:?}", result.err());
    }

    #[test]
    fn errors_carry_no_key_bytes() {
        // Errors are static strings (T02 contract): no modulus octet, and no
        // octet of a refused private key, reaches Debug or Display. 0xA5
        // shows up as "a5"/"A5" in hex, "165" in decimal and "paWl" in
        // base64url.
        let marker = [0xA5u8; 128];
        let mut even = [0xA5u8; 256];
        even[255] = 0xA4;
        let mut private = vec![0x30, 0x81, 0x00, 0x02, 0x01, 0x00];
        for _ in 0..8 {
            private.extend_from_slice(&[0x02, 0x10]);
            private.extend_from_slice(&[0xA5; 16]);
        }
        private[2] = u8::try_from(private.len() - 3).unwrap();
        let spki_of = |n: &[u8]| {
            let pkcs1 = pkcs1::encode_public(n, &[0x01, 0x00, 0x01]).unwrap();
            spki::encode(&SpkiParts {
                alg: AlgId::RsaEncryption,
                subject_public_key: &pkcs1,
            })
            .unwrap()
        };
        let errors = [
            import_spki(&spki_of(&marker)).unwrap_err(),
            import_spki(&spki_of(&even)).unwrap_err(),
            from_pkcs1(&pkcs1::encode_public(&marker, &[0xA5]).unwrap()).unwrap_err(),
            from_pkcs1(&private).unwrap_err(),
        ];
        assert_eq!(errors[3], Error::UnsupportedAlgorithm);
        for error in errors {
            for text in [
                format!("{error:?}"),
                format!("{error}"),
                format!("{error:#?}"),
            ] {
                for needle in ["a5", "A5", "165", "paWl"] {
                    assert!(!text.contains(needle), "{text}");
                }
            }
        }
    }
}

/// Tester additions (feature 0005, T07): adversarial modulus and exponent
/// encodings, and the PEM and PKCS#8 early-return paths for RSA private keys.
#[cfg(test)]
mod adversarial {
    use super::super::types::{AlgId, SpkiParts};
    use super::super::{pem, pkcs8, spki};
    use super::*;

    /// A DER INTEGER with exactly these contents octets (no normalisation).
    fn int(contents: &[u8]) -> Vec<u8> {
        let mut out = vec![0x02];
        push_len(&mut out, contents.len());
        out.extend_from_slice(contents);
        out
    }

    fn push_len(out: &mut Vec<u8>, len: usize) {
        match len {
            0..=0x7F => out.push(u8::try_from(len).unwrap()),
            0x80..=0xFF => out.extend_from_slice(&[0x81, u8::try_from(len).unwrap()]),
            _ => {
                let [high, low] = u16::try_from(len).unwrap().to_be_bytes();
                out.extend_from_slice(&[0x82, high, low]);
            }
        }
    }

    /// `SEQUENCE { n, e }` where both are raw INTEGER contents.
    fn raw_public(n: &[u8], e: &[u8]) -> Vec<u8> {
        let mut body = int(n);
        body.extend_from_slice(&int(e));
        let mut out = vec![0x30];
        push_len(&mut out, body.len());
        out.extend_from_slice(&body);
        out
    }

    fn detail<T>(result: Result<T>) -> &'static str {
        match result {
            Err(Error::InvalidKey(detail)) => detail,
            Err(other) => panic!("expected InvalidKey, got {other:?}"),
            Ok(_) => panic!("expected InvalidKey, got a key"),
        }
    }

    /// A 256-octet odd modulus with the top bit set (2048 bits).
    fn n2048() -> Vec<u8> {
        let mut n = vec![0xC3; 256];
        n[255] = 0xC1;
        n
    }

    fn with_sign_octet(n: &[u8]) -> Vec<u8> {
        let mut out = vec![0x00];
        out.extend_from_slice(n);
        out
    }

    #[test]
    fn modulus_sign_octet_is_required_exactly_when_the_top_bit_is_set() {
        let n = n2048();
        let key = from_pkcs1(&raw_public(&with_sign_octet(&n), &[0x01, 0x00, 0x01])).unwrap();
        assert_eq!(rsa(&key).n(), &n[..], "the sign octet is not part of n");
        assert_eq!(rsa(&key).modulus_bits(), 2048);
        // Without the sign octet the INTEGER is negative (X.690 §8.3.3).
        assert!(matches!(
            from_pkcs1(&raw_public(&n, &[0x01, 0x00, 0x01])),
            Err(Error::InvalidKey(_))
        ));
        // A sign octet where the top bit is clear is non-minimal (§8.3.2).
        let mut small_top = vec![0x7F; 256];
        small_top[255] = 0x01;
        assert!(matches!(
            from_pkcs1(&raw_public(&with_sign_octet(&small_top), &[0x03])),
            Err(Error::InvalidKey(_))
        ));
    }

    fn rsa(jwk: &Jwk) -> &RsaPublicKey {
        let crate::jwk::KeyMaterial::Rsa(key) = jwk.material() else {
            panic!("an RSA key")
        };
        key
    }

    #[test]
    fn exponent_with_a_leading_zero_is_non_minimal() {
        let n = with_sign_octet(&n2048());
        for e in [
            &[0x00, 0x03][..],
            &[0x00, 0x01, 0x00, 0x01][..],
            &[0x00, 0x00, 0x03][..],
        ] {
            assert!(
                matches!(from_pkcs1(&raw_public(&n, e)), Err(Error::InvalidKey(_))),
                "{e:?}"
            );
        }
        // 0x00 0x81 is the minimal DER of 129 (top bit set): accepted, odd.
        let key = from_pkcs1(&raw_public(&n, &[0x00, 0x81])).unwrap();
        assert_eq!(rsa(&key).e(), &[0x81]);
        assert_eq!(
            &to_pkcs1(rsa(&key)).unwrap()[..],
            &raw_public(&n, &[0x00, 0x81])[..]
        );
    }

    #[test]
    fn a_2047_bit_modulus_is_refused_and_2048_is_accepted() {
        let mut n = vec![0x7F; 256];
        n[255] = 0xFF;
        assert_eq!(
            detail(from_pkcs1(&raw_public(&n, &[0x01, 0x00, 0x01]))),
            "RSA modulus is shorter than 2048 bits"
        );
        let mut n = vec![0x80; 256];
        n[255] = 0x01;
        let key = from_pkcs1(&raw_public(&with_sign_octet(&n), &[0x01, 0x00, 0x01])).unwrap();
        assert_eq!(rsa(&key).modulus_bits(), 2048);
    }

    #[test]
    fn odd_and_even_n_and_e() {
        let mut n = n2048();
        let e = [0x01, 0x00, 0x01];
        assert!(from_pkcs1(&raw_public(&with_sign_octet(&n), &e)).is_ok());
        n[255] = 0xC0;
        assert_eq!(
            detail(from_pkcs1(&raw_public(&with_sign_octet(&n), &e))),
            "RSA modulus must be odd"
        );
        let n = with_sign_octet(&n2048());
        for even in [&[0x02][..], &[0x01, 0x00][..], &[0x01, 0x00, 0x00][..]] {
            assert_eq!(
                detail(from_pkcs1(&raw_public(&n, even))),
                "RSA exponent must be odd and greater than 1",
                "{even:?}"
            );
        }
        for bad in [&[0x01][..], &[0x00][..]] {
            assert!(matches!(
                from_pkcs1(&raw_public(&n, bad)),
                Err(Error::InvalidKey(_))
            ));
        }
        assert!(from_pkcs1(&raw_public(&n, &[0x03])).is_ok());
    }

    #[test]
    fn exponent_not_less_than_the_modulus_is_refused() {
        let n = n2048();
        let signed = with_sign_octet(&n);
        // e == n (odd): not below the modulus.
        assert_eq!(
            detail(from_pkcs1(&raw_public(&signed, &signed))),
            "RSA exponent must be less than the modulus"
        );
        // e longer than n.
        let mut longer = vec![0x01];
        longer.extend_from_slice(&n);
        assert_eq!(
            detail(from_pkcs1(&raw_public(&signed, &longer))),
            "RSA exponent must be less than the modulus"
        );
        // e == n - 2 (odd, below n) is within the rule.
        let mut below = n.clone();
        below[255] -= 2;
        assert!(from_pkcs1(&raw_public(&signed, &with_sign_octet(&below))).is_ok());
    }

    #[test]
    fn modulus_above_8192_bits_is_refused_at_import() {
        // jwk.rs enforces 2048..=8192 bits at import (RFC 7518 §3.3,
        // ADR 0026 §2 step 8), so the mapper refuses 8193 and larger moduli
        // from PKCS#1 and SPKI alike; 8192 still round-trips unchanged.
        let e = [0x01, 0x00, 0x01];
        for bytes in [1025usize, 1100] {
            let mut n = vec![0x80; bytes];
            n[bytes - 1] = 0x01;
            let der = raw_public(&with_sign_octet(&n), &e);
            assert_eq!(
                detail(from_pkcs1(&der)),
                "RSA modulus is longer than 8192 bits",
                "{bytes}"
            );
            let spki_der = spki::encode(&SpkiParts {
                alg: AlgId::RsaEncryption,
                subject_public_key: &der,
            })
            .unwrap();
            assert_eq!(
                detail(import_spki_der(&spki_der)),
                "RSA modulus is longer than 8192 bits",
                "{bytes}"
            );
        }
        // 8193 bits exactly: 1025 octets with a top octet of 0x01.
        let mut n = vec![0x55; 1025];
        n[0] = 0x01;
        n[1024] = 0x01;
        assert_eq!(
            detail(from_pkcs1(&raw_public(&n, &e))),
            "RSA modulus is longer than 8192 bits"
        );
        // 8192 bits: imports and exports back unchanged.
        let mut n = vec![0x80; 1024];
        n[1023] = 0x01;
        let der = raw_public(&with_sign_octet(&n), &e);
        let key = from_pkcs1(&der).unwrap();
        assert_eq!(rsa(&key).modulus_bits(), 8192);
        assert_eq!(&to_pkcs1(rsa(&key)).unwrap()[..], &der[..]);
        let spki_der = to_spki(rsa(&key)).unwrap();
        assert!(import_spki_der(&spki_der).is_ok());
    }

    fn import_spki_der(der: &[u8]) -> Result<Jwk> {
        from_spki(spki::decode(der)?)
    }

    #[test]
    fn spki_with_a_trailing_byte_or_wrong_bit_string_is_invalid() {
        let pkcs1 = pkcs1::encode_public(&n2048(), &[0x01, 0x00, 0x01]).unwrap();
        let der = spki::encode(&SpkiParts {
            alg: AlgId::RsaEncryption,
            subject_public_key: &pkcs1,
        })
        .unwrap();
        assert!(import_spki_der(&der).is_ok());
        let mut trailing = der.to_vec();
        trailing.push(0);
        assert!(import_spki_der(&trailing).is_err());
        let mut truncated = der.to_vec();
        truncated.pop();
        assert!(import_spki_der(&truncated).is_err());
    }

    #[test]
    fn rsa_private_pem_is_refused_before_its_body_is_decoded() {
        // The literal criterion for PEM: the BEGIN line decides. A body that
        // is not even base64 still gives UnsupportedAlgorithm, so no body
        // octet can have been decoded.
        for label in ["RSA PRIVATE KEY", "ENCRYPTED PRIVATE KEY"] {
            let text = format!(
                "-----BEGIN {label}-----\n!!!not base64 at all!!!\n-----END {label}-----\n"
            );
            assert_eq!(pem::decode(&text).unwrap_err(), Error::UnsupportedAlgorithm);
            // Truncated: no END line at all.
            let text = format!("-----BEGIN {label}-----\nAAAA\n");
            assert_eq!(pem::decode(&text).unwrap_err(), Error::UnsupportedAlgorithm);
        }
    }

    #[test]
    fn pkcs8_rsa_encryption_returns_on_the_algorithm_identifier() {
        // rsaEncryption AlgorithmIdentifier followed by an OCTET STRING whose
        // contents are not DER at all, and by nothing at all after the
        // AlgorithmIdentifier: both are UnsupportedAlgorithm, never a parse
        // error from privateKey.
        let alg = [
            0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05,
            0x00,
        ];
        let mut with_garbage = vec![0x02, 0x01, 0x00];
        with_garbage.extend_from_slice(&alg);
        with_garbage.extend_from_slice(&[0x04, 0x04, 0xA5, 0xA5, 0xA5, 0xA5]);
        let mut without = vec![0x02, 0x01, 0x00];
        without.extend_from_slice(&alg);
        for body in [with_garbage, without] {
            let mut der = vec![0x30];
            push_len(&mut der, body.len());
            der.extend_from_slice(&body);
            assert_eq!(
                pkcs8::decode(&der).map(drop).unwrap_err(),
                Error::UnsupportedAlgorithm
            );
        }
    }
}
