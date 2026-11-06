//! The JWE JSON Serialization through the public API (0003 T14): RFC 7516
//! §5.1, §5.2 and §7.2 (general §7.2.1, flattened §7.2.2), with shared and
//! per-recipient unprotected headers, the JWE AAD and several recipients,
//! under the plan.md error contract.
//!
//! - RFC 7516 A.4 (general, RSA1_5 + A128KW) and A.5 (flattened) decrypt
//!   with the A128KW key; A.4 reports `recipient == 1`.
//! - RFC 7520 §5.6, §5.8, §5.10, §5.11 and §5.12 decrypt in both JSON
//!   forms. The values are read from the vendored ietf-jose cookbook at
//!   test time, never transcribed.
//! - With `insecure-test-vectors`, `encrypt_reproducible` reproduces the
//!   flattened §5.6, §5.8 and §5.10 outputs exactly. The other RFC JSON
//!   outputs carry `alg` where polyjose's encryptor never puts it (the
//!   general forms have it in the protected header; §5.11, §5.12 and A.5
//!   in an unprotected one), so they are decrypt-only: the tests below
//!   show the hook refusing them and that only the header placement
//!   differs.
//! - Several recipients on encrypt, recipient selection in the plan.md
//!   order, the negative cases of the task, and a property round trip.
#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)] // test code: a panic is a failed assertion

use polyjose::Error;
use polyjose::json::{self, Object, Value};
use polyjose::jwa::{ContentEncAlg, KeyMgmtAlg};
use polyjose::jwe::{
    DecryptPolicy, Decrypted, Encryptor, Recipient, decrypt_compact, decrypt_json,
};
use polyjose::jwk::Jwk;
use polyjose::util::{b64url_decode, b64url_encode};

use ContentEncAlg as E;
use KeyMgmtAlg as A;

fn jwk(json: &str) -> Jwk {
    Jwk::from_json(json.as_bytes()).unwrap_or_else(|e| panic!("{json}: {e}"))
}

fn oct_kid(bytes: &[u8], kid: &str) -> Jwk {
    jwk(&format!(
        r#"{{"kty":"oct","kid":"{kid}","k":"{}"}}"#,
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

fn decrypt(jwe: &str, key: &Jwk, policy: &DecryptPolicy) -> Decrypted {
    decrypt_json(jwe, key, policy).unwrap_or_else(|e| panic!("{e}: {jwe}"))
}

fn object(jwe: &str) -> Object {
    json::parse(jwe.as_bytes())
        .unwrap_or_else(|e| panic!("{e}"))
        .into_object()
        .unwrap_or_else(|| panic!("not an object"))
}

/// `jwe` with `f` applied to its top-level object.
fn edit(jwe: &str, f: impl FnOnce(&mut Object)) -> String {
    let mut top = object(jwe);
    f(&mut top);
    top.to_json()
}

/// `f` applied to the object member `name` of `object` (created if
/// absent).
fn edit_member(object: &mut Object, name: &str, f: impl FnOnce(&mut Object)) {
    let mut member = object
        .remove(name)
        .and_then(Value::into_object)
        .unwrap_or_default();
    f(&mut member);
    object.insert(name, member);
}

// ---------------------------------------------------------------------------
// RFC 7516 A.4 and A.5
// ---------------------------------------------------------------------------

/// RFC 7516 A.4 and A.5 (values of A.2 and A.3).
mod a4 {
    /// A.3's A128KW key (A.3.3). A.4 gives it the `kid` "7".
    pub const KEY: &str = r#"{"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg"}"#;
    pub const KEY_KID_7: &str = r#"{"kty":"oct","kid":"7","k":"GawgguFyGrWKav7AX4VKUg"}"#;
    /// A.2's RSA public key (A.2.3; the private members are not imported,
    /// ADR 0021).
    pub const RSA: &str = r#"{"kty":"RSA","n":"sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw","e":"AQAB"}"#;
    pub const PLAINTEXT: &[u8] = b"Live long and prosper.";
    pub const JKU: &str = "https://server.example.com/keys.jwks";
    /// A.4.7, without the display line breaks.
    pub const GENERAL: &str = concat!(
        r#"{"protected":"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","#,
        r#""unprotected":{"jku":"https://server.example.com/keys.jwks"},"#,
        r#""recipients":[{"header":{"alg":"RSA1_5","kid":"2011-04-29"},"#,
        r#""encrypted_key":"UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-"#,
        r#"kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKx"#,
        r#"GHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3"#,
        r#"YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPh"#,
        r#"cCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPg"#,
        r#"wCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A"},"#,
        r#"{"header":{"alg":"A128KW","kid":"7"},"#,
        r#""encrypted_key":"6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ"}],"#,
        r#""iv":"AxY8DCtDaGlsbGljb3RoZQ","#,
        r#""ciphertext":"KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY","#,
        r#""tag":"Mz-VPPyU4RlcuYv1IwIvzw"}"#,
    );
    /// A.5, without the display line breaks.
    pub const FLATTENED: &str = concat!(
        r#"{"protected":"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","#,
        r#""unprotected":{"jku":"https://server.example.com/keys.jwks"},"#,
        r#""header":{"alg":"A128KW","kid":"7"},"#,
        r#""encrypted_key":"6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ","#,
        r#""iv":"AxY8DCtDaGlsbGljb3RoZQ","#,
        r#""ciphertext":"KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY","#,
        r#""tag":"Mz-VPPyU4RlcuYv1IwIvzw"}"#,
    );
}

fn a4_policy(algs: &[KeyMgmtAlg]) -> DecryptPolicy {
    policy(algs, &[E::A128CbcHs256])
}

#[test]
fn rfc_7516_a4_decrypts_with_the_a128kw_key_as_recipient_1() {
    // RFC 7516 §5.2 step 6: the recipient the key can serve; the RSA1_5
    // one (index 0) is never a candidate (ADRs 0021, 0022).
    for algs in [&[A::A128KW][..], &[A::A128KW, A::from("RSA1_5")]] {
        for key in [a4::KEY, a4::KEY_KID_7] {
            let d = decrypt(a4::GENERAL, &jwk(key), &a4_policy(algs));
            assert_eq!(d.plaintext(), a4::PLAINTEXT);
            assert_eq!(d.recipient(), 1);
            // §5.2 step 4: the JOSE Header is the union of the three.
            assert_eq!(d.header().alg.as_deref(), Some("A128KW"));
            assert_eq!(d.header().kid.as_deref(), Some("7"));
            assert_eq!(d.header().enc, Some(E::A128CbcHs256));
            assert_eq!(d.header().jku.as_deref(), Some(a4::JKU));
            let protected = d.protected_header().unwrap();
            assert!(protected.alg.is_none() && protected.enc == Some(E::A128CbcHs256));
            assert_eq!(d.shared_header().unwrap().jku.as_deref(), Some(a4::JKU));
            assert_eq!(d.recipient_header().unwrap().kid.as_deref(), Some("7"));
            assert!(d.aad().is_none());
        }
    }
}

#[test]
fn rfc_7516_a4_with_only_an_rsa_key_is_unsupported() {
    // RSA1_5 is UnsupportedAlgorithm (ADRs 0021, 0022); the A128KW
    // recipient cannot use an RSA key (KeyAlgorithmMismatch), which ranks
    // below it (plan.md recipient selection).
    let rsa = jwk(a4::RSA);
    let both = a4_policy(&[A::from("RSA1_5"), A::A128KW]);
    assert_eq!(
        decrypt_json(a4::GENERAL, &rsa, &both).map(|_| ()),
        Err(Error::UnsupportedAlgorithm)
    );
    // With only RSA1_5 allowed, the A128KW recipient is not allowed, and
    // AlgorithmNotAllowed ranks first.
    let rsa_only = a4_policy(&[A::from("RSA1_5")]);
    assert_eq!(
        decrypt_json(a4::GENERAL, &rsa, &rsa_only).map(|_| ()),
        Err(Error::AlgorithmNotAllowed)
    );
    // A key that cannot serve the A128KW recipient (a kid mismatch) gives
    // the same ranking.
    let other_kid = oct_kid(&b64url_decode("GawgguFyGrWKav7AX4VKUg").unwrap(), "8");
    assert_eq!(
        decrypt_json(a4::GENERAL, &other_kid, &both).map(|_| ()),
        Err(Error::UnsupportedAlgorithm)
    );
}

#[test]
fn rfc_7516_a5_flattened_decrypts() {
    let d = decrypt(a4::FLATTENED, &jwk(a4::KEY), &a4_policy(&[A::A128KW]));
    assert_eq!(d.plaintext(), a4::PLAINTEXT);
    assert_eq!(d.recipient(), 0);
    assert_eq!(d.header().jku.as_deref(), Some(a4::JKU));
    assert_eq!(d.recipient_header().unwrap().alg.as_deref(), Some("A128KW"));
}

#[test]
fn rfc_7516_a5_is_a4_flattened() {
    // RFC 7516 A.5: "the same as those for the second recipient of the
    // previous example". Keeping only recipient 1 of A.4 and flattening
    // it (§7.2.2) gives A.5.
    let general_one = edit(a4::GENERAL, |top| {
        let Some(Value::Array(mut entries)) = top.remove("recipients") else {
            panic!("no recipients");
        };
        top.insert("recipients", vec![entries.remove(1)]);
    });
    let d = decrypt(&general_one, &jwk(a4::KEY), &a4_policy(&[A::A128KW]));
    assert_eq!((d.plaintext(), d.recipient()), (a4::PLAINTEXT, 0));
    let flattened = edit(&general_one, |top| {
        let Some(Value::Array(mut entries)) = top.remove("recipients") else {
            panic!("no recipients");
        };
        let Value::Object(entry) = entries.remove(0) else {
            panic!("not an object");
        };
        for (name, value) in entry {
            top.insert(name.as_str(), value);
        }
    });
    assert_eq!(object(&flattened), object(a4::FLATTENED));
}

// ---------------------------------------------------------------------------
// RFC 7520 §5 (ietf-jose cookbook, read at test time)
// ---------------------------------------------------------------------------

/// One RFC 7520 §5 example, from the vendored cookbook JSON
/// (`tests/third_party/ietf-jose-cookbook/`).
struct Example {
    key: Jwk,
    kid: String,
    alg: KeyMgmtAlg,
    enc: ContentEncAlg,
    plaintext: Vec<u8>,
    /// The bytes `FixedRng` must yield: the CEK (if generated), then the
    /// content IV (plan.md RNG draw order).
    #[cfg_attr(
        not(feature = "insecure-test-vectors"),
        allow(dead_code, reason = "drawn by the reproducible tests only")
    )]
    rng: Vec<u8>,
    aad: Option<Vec<u8>>,
    /// `encrypting_content.protected_b64u`, if the example has one.
    protected_b64: Option<String>,
    /// `output.json`, the general form.
    general: Value,
    /// `output.json_flat`, the flattened form.
    flattened: Value,
}

macro_rules! cookbook {
    ($file:literal) => {
        Example::load(include_str!(concat!(
            "third_party/ietf-jose-cookbook/jwe/",
            $file
        )))
    };
}

impl Example {
    fn load(text: &str) -> Example {
        let doc = json::parse(text.as_bytes()).unwrap_or_else(|e| panic!("{e}"));
        let path = |names: &[&str]| -> Option<Value> {
            let mut v = &doc;
            for name in names {
                v = v.get(name)?;
            }
            Some(v.clone())
        };
        let string = |names: &[&str]| path(names).map(|v| v.as_str().unwrap().to_owned());
        let bytes = |names: &[&str]| string(names).map(|s| b64url_decode(&s).unwrap());
        let key = path(&["input", "key"]).unwrap();
        let rng = [bytes(&["generated", "cek"]), bytes(&["generated", "iv"])]
            .into_iter()
            .flatten()
            .flatten()
            .collect();
        Example {
            key: Jwk::from_json(key.to_json().as_bytes()).unwrap(),
            kid: key.get("kid").and_then(Value::as_str).unwrap().to_owned(),
            alg: A::from(string(&["input", "alg"]).unwrap().as_str()),
            enc: E::from(string(&["input", "enc"]).unwrap().as_str()),
            plaintext: string(&["input", "plaintext"]).unwrap().into_bytes(),
            rng,
            aad: bytes(&["generated", "aad_b64u"]),
            protected_b64: string(&["encrypting_content", "protected_b64u"]),
            general: path(&["output", "json"]).unwrap(),
            flattened: path(&["output", "json_flat"]).unwrap(),
        }
    }

    fn policy(&self) -> DecryptPolicy {
        policy(
            std::slice::from_ref(&self.alg),
            std::slice::from_ref(&self.enc),
        )
    }

    /// Decrypts `jwe` with the example's key and checks the plaintext,
    /// the AAD and the `kid` of the header used.
    fn decrypts(&self, jwe: &Value) -> Decrypted {
        let d = decrypt(&jwe.to_json(), &self.key, &self.policy());
        assert_eq!(d.plaintext(), self.plaintext);
        assert_eq!(d.recipient(), 0);
        assert_eq!(d.aad(), self.aad.as_deref());
        assert_eq!(d.header().kid.as_deref(), Some(self.kid.as_str()));
        assert_eq!(d.header().alg.as_deref(), Some(self.alg.as_str()));
        assert_eq!(d.header().enc.as_ref(), Some(&self.enc));
        d
    }
}

fn c5_6() -> Example {
    cookbook!("5_6.direct_encryption_using_aes-gcm.json")
}
fn c5_8() -> Example {
    cookbook!("5_8.key_wrap_using_aes-keywrap_with_aes-gcm.json")
}
fn c5_10() -> Example {
    cookbook!("5_10.including_additional_authentication_data.json")
}
fn c5_11() -> Example {
    cookbook!("5_11.protecting_specific_header_fields.json")
}
fn c5_12() -> Example {
    cookbook!("5_12.protecting_content_only.json")
}

#[test]
fn rfc_7520_5_6_dir_decrypts_in_both_forms() {
    let ex = c5_6();
    // RFC 7520 §5.6.5 prints the same object as "general" and "flattened":
    // with no `recipients` member it is the flattened syntax (RFC 7516
    // §7.2.2).
    assert!(ex.general.get("recipients").is_none());
    assert_eq!(ex.general, ex.flattened);
    ex.decrypts(&ex.flattened);
    ex.decrypts(&ex.general);
    // The RFC 7516 §7.2.1 general form of the same JWE: one recipient with
    // neither header nor encrypted key.
    let mut general = ex.flattened.clone().into_object().unwrap();
    general.insert("recipients", vec![Value::from(Object::new())]);
    let d = ex.decrypts(&Value::from(general));
    assert!(d.recipient_header().is_none());
}

#[test]
fn rfc_7520_5_8_a128kw_decrypts_in_both_forms() {
    let ex = c5_8();
    assert!(ex.general.get("recipients").is_some());
    ex.decrypts(&ex.general);
    ex.decrypts(&ex.flattened);
}

#[test]
fn rfc_7520_5_10_aad_decrypts_in_both_forms() {
    let ex = c5_10();
    assert!(
        ex.aad
            .as_ref()
            .is_some_and(|aad| aad.starts_with(b"[\"vcard\""))
    );
    ex.decrypts(&ex.general);
    ex.decrypts(&ex.flattened);
}

#[test]
fn rfc_7520_5_11_unprotected_alg_decrypts_in_both_forms() {
    // §5.11: only `enc` is protected; `alg` and `kid` are in the shared
    // unprotected header.
    let ex = c5_11();
    for jwe in [&ex.general, &ex.flattened] {
        let d = ex.decrypts(jwe);
        assert!(d.protected_header().unwrap().alg.is_none());
        assert_eq!(d.shared_header().unwrap().alg.as_deref(), Some("A128KW"));
    }
}

#[test]
fn rfc_7520_5_12_no_protected_header_decrypts_in_both_forms() {
    // §5.12: no protected header at all; the AAD is the empty string
    // (RFC 7516 §5.1 step 14).
    let ex = c5_12();
    assert!(ex.protected_b64.is_none());
    for jwe in [&ex.general, &ex.flattened] {
        assert!(jwe.get("protected").is_none());
        let d = ex.decrypts(jwe);
        assert!(d.protected_header().is_none());
        assert_eq!(d.shared_header().unwrap().enc, Some(E::A128GCM));
    }
}

#[test]
fn the_unprotected_headers_are_not_integrity_protected() {
    // RFC 7516 §7.2.1 (unprotected members are not integrity protected),
    // RFC 7520 §5.11: changing a member that plays no part in key
    // selection still decrypts.
    let ex = c5_11();
    let tampered = edit(&ex.flattened.to_json(), |top| {
        edit_member(top, "unprotected", |u| {
            u.insert("jku", "https://attacker.example/keys");
        });
    });
    let d = decrypt(&tampered, &ex.key, &ex.policy());
    assert_eq!(d.plaintext(), ex.plaintext);
    assert_eq!(
        d.header().jku.as_deref(),
        Some("https://attacker.example/keys")
    );
    let a5 = edit(a4::FLATTENED, |top| {
        edit_member(top, "unprotected", |u| {
            u.insert("jku", "https://attacker.example/keys");
            u.insert("typ", "x");
        });
    });
    let d = decrypt(&a5, &jwk(a4::KEY), &a4_policy(&[A::A128KW]));
    assert_eq!(d.plaintext(), a4::PLAINTEXT);
}

#[test]
fn a_tampered_protected_header_or_aad_fails() {
    // RFC 7516 §5.2 steps 14-16: the AAD covers the received protected
    // header and the JWE AAD.
    let ex = c5_10();
    for form in [&ex.general, &ex.flattened] {
        let aad = edit(&form.to_json(), |top| {
            top.insert("aad", b64url_encode(b"[\"vcard\",[]]"));
        });
        assert_eq!(
            code(decrypt_json(&aad, &ex.key, &ex.policy())),
            "DecryptionFailed"
        );
        let removed = edit(&form.to_json(), |top| {
            top.remove("aad");
        });
        assert_eq!(
            code(decrypt_json(&removed, &ex.key, &ex.policy())),
            "DecryptionFailed"
        );
        // The same header, re-encoded: equal JSON, different bytes.
        let reencoded = edit(&form.to_json(), |top| {
            let protected =
                r#"{"enc":"A128GCM","kid":"81b20965-8332-43d9-a468-82160ad91ac8","alg":"A128KW"}"#;
            top.insert("protected", b64url_encode(protected.as_bytes()));
        });
        assert_eq!(
            code(decrypt_json(&reencoded, &ex.key, &ex.policy())),
            "DecryptionFailed"
        );
    }
    // §5.12 has no protected header and no AAD; adding either breaks it.
    let ex = c5_12();
    let with_aad = edit(&ex.flattened.to_json(), |top| {
        top.insert("aad", "AA");
    });
    assert_eq!(
        code(decrypt_json(&with_aad, &ex.key, &ex.policy())),
        "DecryptionFailed"
    );
}

#[test]
fn a_json_aad_cannot_move_to_the_compact_serialization() {
    // RFC 7516 §7.1: the compact serialization has no JWE AAD. Its parts
    // moved into a compact JWE drop the AAD, so the tag no longer
    // verifies (§5.2 step 15); and the encryptor refuses AAD for compact.
    let ex = c5_10();
    let f = ex.flattened.clone();
    let part = |name: &str| f.get(name).and_then(Value::as_str).unwrap().to_owned();
    let compact = [
        part("protected"),
        part("encrypted_key"),
        part("iv"),
        part("ciphertext"),
        part("tag"),
    ]
    .join(".");
    assert_eq!(
        code(decrypt_compact(&compact, &ex.key, &ex.policy())),
        "DecryptionFailed"
    );
    let encryptor = Encryptor::new(E::A128GCM)
        .aad(ex.aad.clone().unwrap())
        .recipient(Recipient::new(A::A128KW, &ex.key));
    assert_eq!(
        encryptor.encrypt_compact(b"x"),
        Err(Error::InvalidFormat("compact JWE cannot carry a JWE AAD"))
    );
}

/// Byte-exact reproduction where polyjose's header placement is the RFC's
/// (RFC 7520 §5.6, §5.8 and §5.10, flattened): the RFC's CEK and IV through
/// `FixedRng`, and its exact protected-header bytes through the
/// `insecure-test-vectors` hook.
#[cfg(feature = "insecure-test-vectors")]
mod reproducible {
    use polyjose::header::Header;
    use polyjose::insecure_test_vectors::FixedRng;
    use polyjose::jwe::{JsonForm, Serialization};

    use super::*;

    fn header(json: &str) -> Header {
        Header::from_json(json.as_bytes()).unwrap_or_else(|e| panic!("{json}: {e}"))
    }

    const FLATTENED: Serialization = Serialization::Json(JsonForm::Flattened);
    const GENERAL: Serialization = Serialization::Json(JsonForm::General);

    fn encryptor(ex: &Example, protected_kid: bool) -> Encryptor {
        let mut e =
            Encryptor::new(ex.enc.clone()).recipient(Recipient::new(ex.alg.clone(), &ex.key));
        if protected_kid {
            e = e.protected_header(header(&format!(r#"{{"kid":"{}"}}"#, ex.kid)));
        }
        if let Some(aad) = &ex.aad {
            e = e.aad(aad.clone());
        }
        e
    }

    fn reproduce(ex: &Example, e: &Encryptor, form: Serialization) -> polyjose::Result<Value> {
        let mut rng = FixedRng::new(ex.rng.clone());
        let out =
            e.encrypt_reproducible(&ex.plaintext, form, &mut rng, ex.protected_b64.as_deref())?;
        assert_eq!(rng.remaining(), 0, "every RFC random value is drawn");
        Ok(json::parse(out.as_bytes()).unwrap())
    }

    #[test]
    fn rfc_7520_flattened_outputs_are_reproduced() {
        for ex in [c5_6(), c5_8(), c5_10()] {
            let out = reproduce(&ex, &encryptor(&ex, true), FLATTENED).unwrap();
            // JSON-equal (member order aside, RFC 8259 §4).
            assert_eq!(out, ex.flattened);
            // And it decrypts.
            ex.decrypts(&out);
        }
    }

    #[test]
    fn rfc_7520_general_outputs_put_alg_where_polyjose_does_not() {
        // The RFC 7520 general outputs of §5.6, §5.8 and §5.10 keep `alg`
        // in the protected header; polyjose's general form puts it in the
        // recipient's header (plan.md, as RFC 7520 §5.13). The hook refuses
        // the RFC's header, so these are decrypt-only vectors.
        for ex in [c5_6(), c5_8(), c5_10()] {
            let e = encryptor(&ex, true);
            assert_eq!(
                reproduce(&ex, &e, GENERAL).map(|_| ()),
                Err(Error::InvalidFormat(
                    "protected header does not match the built header"
                ))
            );
            // Without the hook, the same draws give the RFC's encrypted
            // key, IV and ciphertext; only the placement of `alg`, and so
            // the AAD and the tag, differ.
            let mut rng = FixedRng::new(ex.rng.clone());
            let out = e
                .encrypt_reproducible(&ex.plaintext, GENERAL, &mut rng, None)
                .unwrap();
            let out = json::parse(out.as_bytes()).unwrap();
            for name in ["iv", "ciphertext", "aad"] {
                assert_eq!(out.get(name), ex.flattened.get(name), "{name}");
            }
            let entry = &out.get("recipients").unwrap().as_array().unwrap()[0];
            assert_eq!(
                entry.get("encrypted_key"),
                ex.flattened.get("encrypted_key")
            );
            assert_eq!(
                entry.get("header").and_then(|h| h.get("alg")),
                Some(&Value::from(ex.alg.as_str()))
            );
            assert_ne!(out.get("tag"), ex.flattened.get("tag"));
            ex.decrypts(&out);
        }
    }

    #[test]
    fn rfc_7520_5_11_and_5_12_and_rfc_7516_a5_keep_alg_unprotected() {
        // §5.11 (protected `enc` only) and §5.12 (no protected header) put
        // `alg` in the shared unprotected header, RFC 7516 A.5 in the
        // per-recipient one. polyjose always protects `alg` in the
        // flattened form, and never puts it in the shared header: a
        // documented omission (plan.md lead refinement 15), decrypt-only.
        for ex in [c5_11(), c5_12()] {
            let e = encryptor(&ex, false);
            let protected = ex.protected_b64.clone().unwrap_or_default();
            let mut rng = FixedRng::new(ex.rng.clone());
            assert_eq!(
                code(e.encrypt_reproducible(&ex.plaintext, FLATTENED, &mut rng, Some(&protected))),
                "InvalidFormat"
            );
            // The RFC's own outputs still decrypt.
            ex.decrypts(&ex.flattened);
            ex.decrypts(&ex.general);
        }
        // §5.12 has no protected header; polyjose always protects `enc`.
        let ex = c5_12();
        let mut rng = FixedRng::new(ex.rng.clone());
        assert_eq!(
            code(encryptor(&ex, false).encrypt_reproducible(
                &ex.plaintext,
                GENERAL,
                &mut rng,
                Some("")
            )),
            "InvalidFormat"
        );
        // §5.11 general: polyjose's protected header is the RFC's
        // (`{"enc":"A128GCM"}`), so the AAD, and with the RFC's draws the
        // encrypted key, IV, ciphertext and tag, are the RFC's. Only `alg`
        // sits in the recipient's header instead of the shared one.
        let ex = c5_11();
        let e = Encryptor::new(ex.enc.clone())
            .shared_unprotected_header(header(&format!(r#"{{"kid":"{}"}}"#, ex.kid)))
            .recipient(Recipient::new(ex.alg.clone(), &ex.key));
        let out = reproduce(&ex, &e, GENERAL).unwrap();
        for name in ["protected", "iv", "ciphertext", "tag"] {
            assert_eq!(out.get(name), ex.general.get(name), "{name}");
        }
        let entry = |jwe: &Value| jwe.get("recipients").unwrap().as_array().unwrap()[0].clone();
        assert_eq!(
            entry(&out).get("encrypted_key"),
            entry(&ex.general).get("encrypted_key")
        );
        assert_eq!(
            entry(&out).get("header").map(Value::to_json).as_deref(),
            Some(r#"{"alg":"A128KW"}"#)
        );
        assert_eq!(
            out.get("unprotected").map(Value::to_json),
            Some(format!(r#"{{"kid":"{}"}}"#, ex.kid))
        );
        assert_ne!(out, ex.general);
        ex.decrypts(&out);
        // A.5: `{"enc":"A128CBC-HS256"}` is not what polyjose builds for
        // a flattened A128KW recipient.
        let a3_cek_iv = [
            &[
                4u8, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106, 206, 107,
                124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156, 44, 207,
            ][..],
            &[
                3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111, 116, 104, 101,
            ],
        ]
        .concat();
        let mut rng = FixedRng::new(a3_cek_iv);
        let e = Encryptor::new(E::A128CbcHs256)
            .shared_unprotected_header(header(&format!(r#"{{"jku":"{}"}}"#, a4::JKU)))
            .recipient(Recipient::new(A::A128KW, &jwk(a4::KEY)).header(header(r#"{"kid":"7"}"#)));
        assert_eq!(
            code(e.encrypt_reproducible(
                a4::PLAINTEXT,
                FLATTENED,
                &mut rng,
                Some("eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0")
            )),
            "InvalidFormat"
        );
    }
}
