//! Adversarial checks of the compact JWE pipeline (0003 T09, tester): the
//! check order, error text free of attacker input, enc substitution, no
//! secrets in `Debug`, and parser robustness. Public API only.
#![allow(clippy::panic)] // test code: a panic is a failed assertion

use polyjose::Error;
use polyjose::jwa::{ContentEncAlg, KeyMgmtAlg};
use polyjose::jwe::{DecryptPolicy, Encryptor, Recipient, decrypt_compact};
use polyjose::jwk::Jwk;
use polyjose::util::b64url_encode;
use proptest::prelude::*;

use ContentEncAlg as E;
use KeyMgmtAlg as A;

const A3: &str = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.\
    6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.\
    AxY8DCtDaGlsbGljb3RoZQ.\
    KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.\
    U0m_YmjN04DJvceFICbCVQ";
const A3_K: &str = "GawgguFyGrWKav7AX4VKUg";

fn oct(bytes: &[u8]) -> Jwk {
    Jwk::from_json(format!(r#"{{"kty":"oct","k":"{}"}}"#, b64url_encode(bytes)).as_bytes())
        .unwrap_or_else(|e| panic!("{e}"))
}

fn a3_key() -> Jwk {
    Jwk::from_json(format!(r#"{{"kty":"oct","k":"{A3_K}"}}"#).as_bytes())
        .unwrap_or_else(|e| panic!("{e}"))
}

fn policy(algs: &[KeyMgmtAlg], encs: &[ContentEncAlg]) -> DecryptPolicy {
    DecryptPolicy::new(algs, encs).unwrap_or_else(|e| panic!("{e}"))
}

fn forge(header_json: &str, ek: &[u8]) -> String {
    format!(
        "{}.{}.{}.{}.{}",
        b64url_encode(header_json.as_bytes()),
        b64url_encode(ek),
        b64url_encode(&[0; 16]),
        b64url_encode(&[0; 32]),
        b64url_encode(&[0; 16])
    )
}

fn err(token: &str, key: &Jwk, p: &DecryptPolicy) -> Error {
    match decrypt_compact(token, key, p) {
        Ok(_) => panic!("must fail: {token}"),
        Err(e) => e,
    }
}

#[test]
fn check_order_support_then_allow_list_then_key_family() {
    let ec = Jwk::from_json(
        br#"{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"}"#,
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let oct16 = oct(&[1; 16]);
    let narrow = policy(&[A::A128KW], &[E::A128GCM]);
    // An unsupported alg that is NOT in the policy: support comes first.
    for alg in ["none", "RSA1_5", "RSA-OAEP", "RSA-OAEP-256", "bogus", ""] {
        let t = forge(&format!(r#"{{"alg":"{alg}","enc":"A128GCM"}}"#), &[1; 40]);
        assert_eq!(
            err(&t, &oct16, &narrow),
            Error::UnsupportedAlgorithm,
            "{alg:?}"
        );
    }
    // An unsupported enc beats a not-allowed alg and a wrong key family.
    let t = forge(r#"{"alg":"dir","enc":"A128CTR"}"#, &[]);
    assert_eq!(err(&t, &ec, &narrow), Error::UnsupportedAlgorithm);
    // Allow-list before key family: dir is implemented, not allowed, and
    // the EC key could not serve it either.
    let t = forge(r#"{"alg":"dir","enc":"A128GCM"}"#, &[]);
    assert_eq!(err(&t, &ec, &narrow), Error::AlgorithmNotAllowed);
    // Allowed alg, enc not allowed, wrong family: still NotAllowed.
    let t = forge(r#"{"alg":"A128KW","enc":"A256GCM"}"#, &[1; 24]);
    assert_eq!(err(&t, &ec, &narrow), Error::AlgorithmNotAllowed);
    // Allowed on both, wrong family: mismatch.
    let t = forge(r#"{"alg":"A128KW","enc":"A128GCM"}"#, &[1; 24]);
    assert_eq!(err(&t, &ec, &narrow), Error::KeyAlgorithmMismatch);
    // Empty allow-lists (rejected or not allowed), never a decrypt.
    if let Ok(empty) = DecryptPolicy::new(&[], &[]) {
        assert_eq!(err(A3, &a3_key(), &empty), Error::AlgorithmNotAllowed);
    }
    // crit is step 5, before the support check, even for an unknown enc.
    let t = forge(
        r#"{"alg":"none","enc":"A128CTR","crit":["x-q"],"x-q":1}"#,
        &[],
    );
    assert_eq!(err(&t, &oct16, &narrow), Error::UnknownCritical);
    // Missing alg/enc (step 4) before crit (step 5).
    let t = forge(r#"{"enc":"A128GCM","crit":["x-q"],"x-q":1}"#, &[]);
    assert_eq!(
        err(&t, &oct16, &narrow),
        Error::InvalidHeader("missing alg")
    );
}

#[test]
fn alg_none_and_alg_confusion_never_decrypt() {
    let key = a3_key();
    // The token claims dir while the policy only allows A128KW.
    let t = forge(r#"{"alg":"dir","enc":"A128CBC-HS256"}"#, &[]);
    assert_eq!(
        err(&t, &key, &policy(&[A::A128KW], &[E::A128CbcHs256])),
        Error::AlgorithmNotAllowed
    );
    // dir allowed, key is the A128KW key (16 bytes) but enc needs 32:
    // DecryptionFailed, not a length-revealing error.
    assert_eq!(
        err(&t, &key, &policy(&[A::Dir], &[E::A128CbcHs256])),
        Error::DecryptionFailed
    );
}

#[test]
fn enc_substitution_in_the_protected_header_is_decryption_failed() {
    // The A.3 token with `enc` rewritten to every other allowed enc: the
    // header is tampered, so it can never verify, whatever the key size.
    let key = a3_key();
    let all = policy(&[A::A128KW], ContentEncAlg::KNOWN);
    let parts: Vec<&str> = A3.split('.').collect();
    for enc in ContentEncAlg::KNOWN {
        let header = format!(r#"{{"alg":"A128KW","enc":"{}"}}"#, enc.as_str());
        let token = format!(
            "{}.{}.{}.{}.{}",
            b64url_encode(header.as_bytes()),
            parts[1],
            parts[2],
            parts[3],
            parts[4]
        );
        if *enc == E::A128CbcHs256 {
            // The same header bytes as received: the token is valid.
            assert!(decrypt_compact(&token, &key, &all).is_ok());
            continue;
        }
        let e = err(&token, &key, &all);
        assert_eq!(e, Error::DecryptionFailed, "{enc}");
        assert_eq!(format!("{e:?}"), "DecryptionFailed");
        assert_eq!(e.to_string(), "decryption failed");
    }
}

#[test]
fn error_text_never_carries_attacker_input() {
    const M: &str = "ZZMARKERZZ";
    let key = a3_key();
    let p = policy(&[A::A128KW], &[E::A128CbcHs256]);
    let wide = policy(&[A::A128KW, A::Dir], ContentEncAlg::KNOWN);
    let headers = [
        format!(r#"{{"alg":"{M}","enc":"A128GCM"}}"#),
        format!(r#"{{"alg":"A128KW","enc":"{M}"}}"#),
        format!(r#"{{"alg":"A128KW","enc":"A128CBC-HS256","zip":"{M}"}}"#),
        format!(r#"{{"alg":"A128KW","enc":"A128CBC-HS256","crit":["{M}"],"{M}":1}}"#),
        format!(r#"{{"alg":"A128KW","enc":"A128CBC-HS256","crit":["{M}"]}}"#),
        format!(r#"{{"alg":"A128KW","enc":"A128CBC-HS256","kid":"{M}"}}"#),
        format!(r#"{{"alg":"A128KW","enc":"A128CBC-HS256","kid":7,"{M}":1}}"#),
        format!(r#"{{"alg":"A128KW","enc":"A128CBC-HS256","{M}":1,"{M}":2}}"#),
        format!(r#"{{"alg":"{M}","alg":"{M}","enc":"A128GCM"}}"#),
        format!(r#"{{"{M}":1}}"#),
        format!(r#""{M}""#),
        format!(r#"[{M}]"#),
        format!(r#"{{"alg":"A128KW","enc":"A128CBC-HS256","jwk":"{M}"}}"#),
        format!(
            r#"{{"alg":"A128KW","enc":"A128CBC-HS256","typ":{{"{M}":[1,{{"{M}":2,"{M}":3}}]}}}}"#
        ),
    ];
    let mut tokens: Vec<String> = headers.iter().map(|h| forge(h, &[1; 40])).collect();
    tokens.push(format!("{M}.{M}.{M}.{M}.{M}"));
    tokens.push(format!("{M}.{M}"));
    tokens.push(format!("{}.AA.AA.AA.AA", b64url_encode(M.as_bytes())));
    tokens.push(format!("{M}{M}{M}"));
    for t in &tokens {
        for pol in [&p, &wide] {
            let e = err(t, &key, pol);
            for text in [format!("{e:?}"), e.to_string()] {
                assert!(!text.contains(M), "{t:?} leaked into {text:?}");
                assert!(
                    !text.contains("A128KW") && !text.contains("A128CBC"),
                    "{text:?}"
                );
            }
        }
    }
}

#[test]
fn no_key_material_in_debug_or_errors() {
    let key = a3_key();
    let marker = "TOPSECRETPLAINTEXT";
    let e = Encryptor::new(E::A128GCM).recipient(Recipient::new(A::A128KW, &key));
    let recipient = Recipient::new(A::A128KW, &key);
    let p = policy(&[A::A128KW], &[E::A128CbcHs256]);
    let d = decrypt_compact(A3, &key, &p).unwrap_or_else(|e| panic!("{e}"));
    let token = e
        .encrypt_compact(marker.as_bytes())
        .unwrap_or_else(|e| panic!("{e}"));
    let d2 = decrypt_compact(&token, &key, &policy(&[A::A128KW], &[E::A128GCM]))
        .unwrap_or_else(|e| panic!("{e}"));
    let k_bytes = [
        A3_K.to_owned(),
        // the CEK of RFC 7516 A.3.2, as base64url
        "BNMfxVSd_P4LZJ36P6pqzmt81C1vawnbyLEA8I-cLM8".to_owned(),
    ];
    for dump in [
        format!("{key:?}"),
        format!("{e:?}"),
        format!("{recipient:?}"),
        format!("{p:?}"),
        format!("{d:?}"),
        format!("{d2:?}"),
        format!("{:?}", err(A3, &oct(&[9; 16]), &p)),
    ] {
        for k in &k_bytes {
            assert!(!dump.contains(k.as_str()), "{dump}");
        }
        assert!(!dump.contains("Live long and prosper"), "{dump}");
        assert!(!dump.contains(marker), "{dump}");
        assert!(!dump.contains("[4, 211, 31"), "{dump}");
    }
}

#[test]
fn gcm_wrapped_token_every_part_tamper_is_decryption_failed() {
    let key = oct(&[7; 16]);
    let token = Encryptor::new(E::A128GCM)
        .recipient(Recipient::new(A::A128KW, &key))
        .encrypt_compact(b"adversarial")
        .unwrap_or_else(|e| panic!("{e}"));
    let p = policy(&[A::A128KW], &[E::A128GCM]);
    assert!(decrypt_compact(&token, &key, &p).is_ok());
    let parts: Vec<String> = token.split('.').map(str::to_owned).collect();
    for i in 1..5 {
        let mut raw = polyjose::util::b64url_decode(&parts[i]).unwrap_or_else(|e| panic!("{e}"));
        let variants: Vec<Vec<u8>> = {
            let mut v = Vec::new();
            for bit in 0..raw.len().min(4) * 8 {
                let mut r = raw.clone();
                r[bit / 8] ^= 1 << (bit % 8);
                v.push(r);
            }
            if !raw.is_empty() {
                v.push(raw[..raw.len() - 1].to_vec());
            }
            raw.push(0);
            v.push(raw);
            v
        };
        for r in variants {
            let mut q = parts.clone();
            q[i] = b64url_encode(&r);
            let e = err(&q.join("."), &key, &p);
            assert_eq!(e, Error::DecryptionFailed, "part {i}");
            assert!(std::error::Error::source(&e).is_none());
        }
    }
    // Truncating the CBC-HS ciphertext to a non-block length.
    let cbc = Encryptor::new(E::A128CbcHs256)
        .recipient(Recipient::new(A::A128KW, &key))
        .encrypt_compact(b"adversarial text over a block")
        .unwrap_or_else(|e| panic!("{e}"));
    let pc = policy(&[A::A128KW], &[E::A128CbcHs256]);
    let mut q: Vec<String> = cbc.split('.').map(str::to_owned).collect();
    let mut ct = polyjose::util::b64url_decode(&q[3]).unwrap_or_else(|e| panic!("{e}"));
    ct.truncate(ct.len() - 3);
    q[3] = b64url_encode(&ct);
    assert_eq!(err(&q.join("."), &key, &pc), Error::DecryptionFailed);
    ct.clear();
    q[3] = String::new();
    assert_eq!(err(&q.join("."), &key, &pc), Error::DecryptionFailed);
}

#[test]
fn dir_encrypt_and_decrypt_edge_cases() {
    let key = oct(&[3; 16]);
    let token = Encryptor::new(E::A128GCM)
        .recipient(Recipient::new(A::Dir, &key))
        .encrypt_compact(b"dir")
        .unwrap_or_else(|e| panic!("{e}"));
    // The encrypted key is empty on encrypt.
    assert_eq!(token.split('.').nth(1), Some(""));
    let p = policy(&[A::Dir], &[E::A128GCM]);
    assert!(decrypt_compact(&token, &key, &p).is_ok());
    // 1-byte, 15-, 17- and 32-byte keys for A128GCM, and a missing key.
    for len in [1usize, 15, 17, 32] {
        assert_eq!(
            err(&token, &oct(&vec![3; len]), &p),
            Error::DecryptionFailed
        );
    }
    // A non-empty encrypted key, of any length.
    for n in [1usize, 16, 40] {
        let mut q: Vec<String> = token.split('.').map(str::to_owned).collect();
        q[1] = b64url_encode(&vec![0; n]);
        assert_eq!(err(&q.join("."), &key, &p), Error::DecryptionFailed);
    }
    // dir with a 24-byte key and A128GCM on encrypt is InvalidKey.
    assert_eq!(
        Encryptor::new(E::A128GCM)
            .recipient(Recipient::new(A::Dir, &oct(&[3; 24])))
            .encrypt_compact(b"x")
            .map(|_| ()),
        Err(Error::InvalidKey(
            "dir key length must equal the enc key length"
        ))
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    /// Untrusted input never panics and never decrypts to a wrong result.
    #[test]
    fn decrypt_compact_never_panics_on_mutated_tokens(
        edits in proptest::collection::vec((0usize..400, any::<u8>()), 1..6),
        junk in "\\PC{0,120}",
    ) {
        let key = a3_key();
        let p = policy(&[A::A128KW, A::Dir], ContentEncAlg::KNOWN);
        let mut bytes = A3.as_bytes().to_vec();
        for (i, b) in edits {
            let i = i % bytes.len();
            bytes[i] = b;
        }
        let token = String::from_utf8_lossy(&bytes).into_owned();
        match decrypt_compact(&token, &key, &p) {
            Ok(d) => prop_assert_eq!(d.plaintext(), b"Live long and prosper."),
            Err(e) => prop_assert!(!e.to_string().is_empty()),
        }
        let _ = decrypt_compact(&junk, &key, &p);
        let _ = decrypt_compact(&format!("{junk}.{junk}.{junk}.{junk}.{junk}"), &key, &p);
    }
}
