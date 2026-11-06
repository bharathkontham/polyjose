//! `zip` in the JWE JSON Serialization with the `deflate` feature on
//! (0003 T18, deferred from T15): RFC 7516 §4.1.3, §7.2.1 and §7.2.2.
//!
//! RFC 7516 §4.1.3: `zip` "MUST be integrity protected; therefore, it MUST
//! occur only within the JWE Protected Header". So even in a build that can
//! inflate, `zip` in the JWE Shared Unprotected Header or a Per-Recipient
//! Unprotected Header (the flattened form's `header` member included) is
//! `InvalidHeader`, raised with the other header checks (RFC 7516 §5.2
//! steps 3-4, plan.md error contract) before any key is tried. Each case
//! starts from the RFC 7520 §5.9 JSON JWE (read from the vendored ietf-jose
//! cookbook at test time) with `zip` moved out of its protected header; a
//! control shows that the same token without `zip` anywhere gets past the
//! header checks and fails only at the tag (`DecryptionFailed`, the
//! protected header being the AAD), so the `InvalidHeader` is the
//! placement rule and nothing else. On encrypt, polyjose sets `zip` itself
//! (`Encryptor::compress`) and refuses it in every caller header.
#![cfg(feature = "deflate")]
#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)] // test code: a panic is a failed assertion

use polyjose::header::Header;
use polyjose::json::{self, Object, Value};
use polyjose::jwa::{ContentEncAlg, KeyMgmtAlg};
use polyjose::jwe::{DecryptPolicy, Encryptor, JsonForm, Recipient, decrypt_json};
use polyjose::jwk::Jwk;
use polyjose::util::{b64url_decode, b64url_encode};

/// RFC 7520 §5.9 (A128KW + A128GCM, `zip: "DEF"`), from the vendored
/// ietf-jose cookbook.
const COOKBOOK_5_9: &str =
    include_str!("third_party/ietf-jose-cookbook/jwe/5_9.compressed_content.json");

fn object(text: &str) -> Object {
    json::parse(text.as_bytes())
        .unwrap_or_else(|e| panic!("{e}"))
        .into_object()
        .unwrap_or_else(|| panic!("not an object: {text}"))
}

/// The member at `path` (a non-empty list of names) of `object`.
fn member<'a>(object: &'a Object, path: &[&str]) -> &'a Value {
    let Some((last, parents)) = path.split_last() else {
        panic!("empty path");
    };
    let mut at = object;
    for name in parents {
        at = at
            .get(name)
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("no object at {name} of {path:?}"));
    }
    at.get(last).unwrap_or_else(|| panic!("no member {path:?}"))
}

fn str_at<'a>(object: &'a Object, path: &[&str]) -> &'a str {
    member(object, path)
        .as_str()
        .unwrap_or_else(|| panic!("{path:?} is not a string"))
}

/// The §5.9 example: its key, plaintext and the two JSON outputs.
struct Example {
    key: Jwk,
    plaintext: Vec<u8>,
    general: Object,
    flattened: Object,
}

fn example() -> Example {
    let doc = object(COOKBOOK_5_9);
    let key = member(&doc, &["input", "key"])
        .as_object()
        .unwrap_or_else(|| panic!("input.key"))
        .to_json();
    let json_of = |name: &str| {
        member(&doc, &["output", name])
            .as_object()
            .unwrap_or_else(|| panic!("output.{name}"))
            .clone()
    };
    Example {
        key: Jwk::from_json(key.as_bytes()).unwrap_or_else(|e| panic!("{e}")),
        plaintext: str_at(&doc, &["input", "plaintext"]).as_bytes().to_vec(),
        general: json_of("json"),
        flattened: json_of("json_flat"),
    }
}

fn policy() -> DecryptPolicy {
    DecryptPolicy::new(&[KeyMgmtAlg::A128KW], &[ContentEncAlg::A128GCM])
        .unwrap_or_else(|e| panic!("{e}"))
}

fn code<T>(result: polyjose::Result<T>) -> &'static str {
    match result {
        Ok(_) => "ok",
        Err(e) => e.code(),
    }
}

/// `jwe` with `zip` removed from its protected header, which is
/// re-encoded with its other members in their order.
fn unprotect_zip(jwe: &Object) -> Object {
    let protected = b64url_decode(str_at(jwe, &["protected"])).unwrap_or_else(|e| panic!("{e}"));
    let mut header = object(core::str::from_utf8(&protected).unwrap_or_else(|e| panic!("{e}")));
    assert_eq!(
        header.remove("zip"),
        Some(Value::from("DEF")),
        "§5.9 has zip"
    );
    let mut out = jwe.clone();
    out.insert("protected", b64url_encode(header.to_json().as_bytes()));
    out
}

/// `f` applied to the object member `name` of `object` (created if absent).
fn edit_member(object: &mut Object, name: &str, f: impl FnOnce(&mut Object)) {
    let mut inner = object
        .remove(name)
        .and_then(Value::into_object)
        .unwrap_or_default();
    f(&mut inner);
    object.insert(name, inner);
}

/// `f` applied to `recipients[0]` of a general JWE.
fn edit_first_recipient(jwe: &mut Object, f: impl FnOnce(&mut Object)) {
    let Some(Value::Array(mut entries)) = jwe.remove("recipients") else {
        panic!("no recipients");
    };
    let Some(Value::Object(entry)) = entries.first_mut() else {
        panic!("recipient 0 is not an object");
    };
    f(entry);
    jwe.insert("recipients", entries);
}

fn add_zip(header: &mut Object) {
    header.insert("zip", "DEF");
}

#[test]
fn rfc7520_5_9_json_forms_decrypt_with_zip_protected() {
    // RFC 7516 §5.2 step 17 (the control for everything below).
    let ex = example();
    for jwe in [&ex.general, &ex.flattened] {
        let out = decrypt_json(&jwe.to_json(), &ex.key, &policy())
            .unwrap_or_else(|e| panic!("{e}: {}", jwe.to_json()));
        assert_eq!(out.plaintext(), ex.plaintext.as_slice());
        assert_eq!(out.recipient(), 0);
    }
}

#[test]
fn without_zip_anywhere_the_header_checks_pass_and_the_tag_fails() {
    // Removing `zip` changes the protected header, which is the AAD
    // (RFC 7516 §5.1 step 14): the token gets past steps 1-5 and every
    // allow-list and key check, and fails only at the tag.
    let ex = example();
    for jwe in [&ex.general, &ex.flattened] {
        let stripped = unprotect_zip(jwe).to_json();
        assert_eq!(
            code(decrypt_json(&stripped, &ex.key, &policy())),
            "DecryptionFailed",
            "{stripped}"
        );
    }
}

#[test]
fn zip_in_the_shared_unprotected_header_is_invalid_header() {
    let ex = example();
    for jwe in [&ex.general, &ex.flattened] {
        let mut moved = unprotect_zip(jwe);
        edit_member(&mut moved, "unprotected", add_zip);
        let text = moved.to_json();
        assert_eq!(
            code(decrypt_json(&text, &ex.key, &policy())),
            "InvalidHeader",
            "{text}"
        );
    }
}

#[test]
fn zip_in_a_per_recipient_header_is_invalid_header() {
    let ex = example();
    // General: recipients[0].header (RFC 7516 §7.2.1).
    let mut general = unprotect_zip(&ex.general);
    edit_first_recipient(&mut general, |entry| edit_member(entry, "header", add_zip));
    // Flattened: the top-level header member (RFC 7516 §7.2.2).
    let mut flattened = unprotect_zip(&ex.flattened);
    edit_member(&mut flattened, "header", add_zip);
    for jwe in [general, flattened] {
        let text = jwe.to_json();
        assert_eq!(
            code(decrypt_json(&text, &ex.key, &policy())),
            "InvalidHeader",
            "{text}"
        );
    }
}

#[test]
fn zip_both_protected_and_unprotected_is_invalid_header() {
    // RFC 7516 §7.2.1: the header locations must be disjoint, and `zip`
    // may only be protected; either rule refuses it.
    let ex = example();
    let mut shared = ex.general.clone();
    edit_member(&mut shared, "unprotected", add_zip);
    let mut recipient = ex.general.clone();
    edit_first_recipient(&mut recipient, |entry| {
        edit_member(entry, "header", add_zip)
    });
    for jwe in [shared, recipient] {
        let text = jwe.to_json();
        assert_eq!(
            code(decrypt_json(&text, &ex.key, &policy())),
            "InvalidHeader",
            "{text}"
        );
    }
}

#[test]
fn encrypt_refuses_zip_in_any_caller_header() {
    // polyjose sets `zip` itself when compressing (RFC 7516 §5.1 step 11)
    // and refuses it from the caller in every header location.
    let ex = example();
    let zip = || Header::from_json(br#"{"zip":"DEF"}"#).unwrap_or_else(|e| panic!("{e}"));
    let base = || Encryptor::new(ContentEncAlg::A128GCM).compress();
    let recipient = || Recipient::new(KeyMgmtAlg::A128KW, &ex.key);
    let cases = [
        base().protected_header(zip()).recipient(recipient()),
        base()
            .shared_unprotected_header(zip())
            .recipient(recipient()),
        base().recipient(recipient().header(zip())),
    ];
    for (i, encryptor) in cases.iter().enumerate() {
        for form in [JsonForm::General, JsonForm::Flattened] {
            assert_eq!(
                code(encryptor.encrypt_json(&ex.plaintext, form)),
                "InvalidHeader",
                "case {i}, {form:?}"
            );
        }
    }
    // The control: compressing without a caller `zip` round-trips.
    let jwe = base()
        .recipient(recipient())
        .encrypt_json(&ex.plaintext, JsonForm::General)
        .unwrap_or_else(|e| panic!("{e}"));
    let out = decrypt_json(&jwe, &ex.key, &policy()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(out.plaintext(), ex.plaintext.as_slice());
}
