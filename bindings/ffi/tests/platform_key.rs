//! The six `…_with_platform_key` exports and the `PlatformKey` foreign trait (feature 0025 T02;
//! ADR 0071 §5), driven from Rust with a Rust implementation of the trait: the same calls the
//! generated Kotlin and Swift make, without the FFI. Each export converts its arguments, wraps the
//! host key and makes its one surface call; the key's results and errors pass through the adapter
//! unchanged (ADR 0030 §1). The UniFFI path itself (host objects, host exceptions) is tested on
//! the JVM, Android, macOS and the iOS Simulator.
//!
//! The key is RFC 7515 Appendix A.3.1's P-256 key. Signing goes through polyjose's JWK path and
//! re-encodes R‖S as the DER `Ecdsa-Sig-Value` a platform returns (RFC 3279 §2.2.3); ECDH uses
//! `p256::ecdh` (RFC 7518 §4.6.2), a test oracle only (ADR 0016 §5).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a panic is a failed assertion

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use polyjose::jwk::Jwk;
use polyjose::jws::{ProtectedHeader, SignOptions, sign_compact};
use polyjose::util::b64url_decode;
use polyjose_ffi::jwe::{
    jwe_decrypt_compact_with_platform_key, jwe_decrypt_json_with_platform_key, jwe_encrypt_compact,
    jwe_encrypt_json,
};
use polyjose_ffi::jws::{jws_sign_compact_with_platform_key, jws_verify_compact};
use polyjose_ffi::jwt::{
    jwt_decrypt_nested_with_platform_key, jwt_decrypt_nested_with_platform_key_and_jwks,
    jwt_encrypt_nested, jwt_sign_with_platform_key, jwt_verify,
};
use polyjose_ffi::records::{
    JweDecryptOptions, JweEncryptOptions, JweRecipient, JwsSignOptions, JwsVerifyOptions,
    JwtSignOptions, JwtVerifyOptions,
};
use polyjose_ffi::{PlatformKey, PlatformKeyError, PolyjoseError};

/// RFC 7515 Appendix A.3.1: the P-256 key of ES256.
const P256: &str = r#"{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"}"#;
const CLAIMS: &str = r#"{"iss":"joe","sub":"platform"}"#;
const PLAINTEXT: &[u8] = b"platform keys sign and decrypt";

/// A software key over [`P256`], counting its private-key calls.
struct Soft {
    secret: Jwk,
    algorithms: Vec<String>,
    fail: Option<PlatformKeyError>,
    private_calls: AtomicUsize,
}

fn soft(algorithms: &[&str], fail: Option<PlatformKeyError>) -> Arc<Soft> {
    Arc::new(Soft {
        secret: Jwk::from_json(P256.as_bytes()).unwrap(),
        algorithms: algorithms.iter().map(|a| (*a).to_owned()).collect(),
        fail,
        private_calls: AtomicUsize::new(0),
    })
}

fn public_jwk() -> String {
    let secret = Jwk::from_json(P256.as_bytes()).unwrap();
    secret.to_public().unwrap().to_json().to_string()
}

impl Soft {
    fn private(&self) -> Result<(), PlatformKeyError> {
        self.private_calls.fetch_add(1, Ordering::SeqCst);
        self.fail.map_or(Ok(()), Err)
    }
}

impl PlatformKey for Soft {
    fn public_jwk(&self) -> Result<String, PlatformKeyError> {
        Ok(public_jwk())
    }

    fn algorithms(&self) -> Result<Vec<String>, PlatformKeyError> {
        Ok(self.algorithms.clone())
    }

    fn sign(&self, alg: String, signing_input: Vec<u8>) -> Result<Vec<u8>, PlatformKeyError> {
        self.private()?;
        assert_eq!(alg, "ES256");
        let text = String::from_utf8(signing_input).unwrap();
        let (header, payload) = text.split_once('.').unwrap();
        let protected = ProtectedHeader::from_encoded(header).unwrap();
        let payload = b64url_decode(payload).unwrap();
        let jws = sign_compact(&protected, &payload, &self.secret, &SignOptions::new()).unwrap();
        let rs = b64url_decode(jws.rsplit('.').next().unwrap()).unwrap();
        let (r, s) = rs.split_at(32);
        let mut body = der_integer(r);
        body.extend(der_integer(s));
        let mut der = vec![0x30, u8::try_from(body.len()).unwrap()];
        der.extend(body);
        Ok(der)
    }

    fn agree(&self, peer_public_key: Vec<u8>) -> Result<Vec<u8>, PlatformKeyError> {
        self.private()?;
        let object = self.secret.to_object();
        let d = b64url_decode(object.get("d").and_then(|v| v.as_str()).unwrap()).unwrap();
        let secret = p256::SecretKey::from_slice(&d).unwrap();
        let peer = p256::PublicKey::from_sec1_bytes(&peer_public_key).unwrap();
        let z = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
        Ok(z.raw_secret_bytes().to_vec())
    }

    fn decrypt_key(&self, _: String, _: Vec<u8>) -> Result<Vec<u8>, PlatformKeyError> {
        self.private()?;
        panic!("an EC key is never asked to decrypt a key");
    }
}

/// A non-negative DER INTEGER (X.690 §8.3) of the big-endian `magnitude`.
fn der_integer(magnitude: &[u8]) -> Vec<u8> {
    let first = magnitude.iter().position(|&b| b != 0).unwrap_or(0);
    let mut contents = magnitude[first..].to_vec();
    if contents[0] & 0x80 != 0 {
        contents.insert(0, 0);
    }
    let mut out = vec![0x02, u8::try_from(contents.len()).unwrap()];
    out.extend(contents);
    out
}

fn list(names: &[&str]) -> Vec<String> {
    names.iter().map(|s| (*s).to_owned()).collect()
}

fn sign_options() -> JwsSignOptions {
    JwsSignOptions {
        protected_header: Some(r#"{"alg":"ES256"}"#.to_owned()),
        protected_b64u: None,
        detached: false,
    }
}

fn jwt_sign_options() -> JwtSignOptions {
    JwtSignOptions {
        alg: "ES256".to_owned(),
        typ: None,
        omit_typ: false,
        access_token: false,
        header: None,
    }
}

fn jwt_verify_options() -> JwtVerifyOptions {
    JwtVerifyOptions {
        allowed_algs: list(&["ES256"]),
        now: Some(1_700_000_000),
        issuers: None,
        audiences: None,
        subject: None,
        leeway: None,
        max_age: None,
        required_claims: None,
        allow_missing_exp: true,
        ignore_audience: false,
        typ: None,
        any_typ: false,
        profile: None,
        max_key_candidates: None,
        max_input_len: None,
    }
}

fn decrypt_options(alg: &str) -> JweDecryptOptions {
    JweDecryptOptions {
        allowed_algs: list(&[alg]),
        allowed_enc: list(&["A256GCM"]),
        max_pbes2_count: None,
        max_decompressed_len: None,
        max_input_len: None,
        max_recipients: None,
        understood_crit: None,
    }
}

fn encrypt_options(alg: &str) -> JweEncryptOptions {
    JweEncryptOptions {
        enc: "A256GCM".to_owned(),
        recipients: vec![JweRecipient {
            alg: alg.to_owned(),
            key: public_jwk(),
            header: None,
            apu: None,
            apv: None,
            p2c: None,
            p2s_len: None,
        }],
        protected_header: None,
        shared_unprotected_header: None,
        aad: None,
        compress: false,
    }
}

fn signed_jwt() -> String {
    jwt_sign_with_platform_key(
        CLAIMS.to_owned(),
        soft(&["ES256"], None),
        jwt_sign_options(),
    )
    .unwrap()
}

fn code(e: &PolyjoseError) -> String {
    e.code()
}

#[test]
fn the_sign_exports_produce_tokens_the_public_jwk_verifies() {
    let key = soft(&["ES256"], None);
    let token = jws_sign_compact_with_platform_key(PLAINTEXT.to_vec(), key.clone(), sign_options())
        .unwrap();
    assert_eq!(key.private_calls.load(Ordering::SeqCst), 1);
    let verified = jws_verify_compact(
        token,
        public_jwk(),
        JwsVerifyOptions {
            allowed_algs: list(&["ES256"]),
            detached_payload: None,
            max_input_len: None,
            max_signatures: None,
        },
    )
    .unwrap();
    assert_eq!(verified.payload, PLAINTEXT);

    let verified = jwt_verify(signed_jwt(), public_jwk(), jwt_verify_options()).unwrap();
    assert_eq!(verified.claims, CLAIMS);
}

#[test]
fn the_decrypt_exports_return_the_plaintext() {
    for alg in ["ECDH-ES", "ECDH-ES+A256KW"] {
        let token = jwe_encrypt_compact(PLAINTEXT.to_vec(), encrypt_options(alg)).unwrap();
        let decrypted =
            jwe_decrypt_compact_with_platform_key(token, soft(&[alg], None), decrypt_options(alg))
                .unwrap();
        assert_eq!(decrypted.plaintext, PLAINTEXT, "{alg}");
        let jwe = jwe_encrypt_json(
            PLAINTEXT.to_vec(),
            encrypt_options(alg),
            "flattened".to_owned(),
        )
        .unwrap();
        let decrypted =
            jwe_decrypt_json_with_platform_key(jwe, soft(&[alg], None), decrypt_options(alg))
                .unwrap();
        assert_eq!(decrypted.plaintext, PLAINTEXT, "{alg}");
    }
}

#[test]
fn the_nested_exports_decrypt_and_verify() {
    let token = jwt_encrypt_nested(signed_jwt(), encrypt_options("ECDH-ES")).unwrap();
    let one = jwt_decrypt_nested_with_platform_key(
        token.clone(),
        soft(&["ECDH-ES"], None),
        decrypt_options("ECDH-ES"),
        public_jwk(),
        jwt_verify_options(),
    )
    .unwrap();
    assert_eq!(one.inner.claims, CLAIMS);
    let set = jwt_decrypt_nested_with_platform_key_and_jwks(
        token,
        soft(&["ECDH-ES"], None),
        decrypt_options("ECDH-ES"),
        format!(r#"{{"keys":[{}]}}"#, public_jwk()),
        jwt_verify_options(),
    )
    .unwrap();
    assert_eq!(set.inner.claims, CLAIMS);
}

#[test]
fn the_keys_errors_reach_the_caller_as_the_polyjose_codes() {
    let token = jwe_encrypt_compact(PLAINTEXT.to_vec(), encrypt_options("ECDH-ES")).unwrap();
    for (e, signing, decrypting) in [
        (PlatformKeyError::NotFound, "KeyNotFound", "KeyNotFound"),
        (
            PlatformKeyError::UserAuthenticationRequired,
            "UserAuthenticationRequired",
            "UserAuthenticationRequired",
        ),
        (
            PlatformKeyError::Failed,
            "PlatformKeyFailed",
            "DecryptionFailed",
        ),
    ] {
        let err = jws_sign_compact_with_platform_key(
            PLAINTEXT.to_vec(),
            soft(&["ES256"], Some(e)),
            sign_options(),
        )
        .unwrap_err();
        assert_eq!(code(&err), signing, "{e:?}");
        let err = jwt_sign_with_platform_key(
            CLAIMS.to_owned(),
            soft(&["ES256"], Some(e)),
            jwt_sign_options(),
        )
        .unwrap_err();
        assert_eq!(code(&err), signing, "{e:?}");
        let Err(err) = jwe_decrypt_compact_with_platform_key(
            token.clone(),
            soft(&["ECDH-ES"], Some(e)),
            decrypt_options("ECDH-ES"),
        ) else {
            panic!("decrypted with a failing key");
        };
        assert_eq!(code(&err), decrypting, "{e:?}");
    }
}

#[test]
fn an_alg_outside_the_allow_list_never_reaches_the_key() {
    let token = jwe_encrypt_compact(PLAINTEXT.to_vec(), encrypt_options("ECDH-ES")).unwrap();
    let key = soft(&["ECDH-ES"], None);
    let Err(err) = jwe_decrypt_compact_with_platform_key(
        token,
        key.clone(),
        decrypt_options("ECDH-ES+A256KW"),
    ) else {
        panic!("decrypted outside the allow-list");
    };
    assert_eq!(code(&err), "AlgorithmNotAllowed");
    assert_eq!(key.private_calls.load(Ordering::SeqCst), 0);
}
