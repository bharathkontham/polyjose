//! The six `…_with_platform_key` operations of the surface (feature 0025 T02; ADR 0071 §5), with a
//! software [`PlatformKey`] written here: each operation round-trips with the matching JWK
//! operation, and the key's errors and misuse reach the caller as the core's codes (ADR 0071 §2,
//! §4, §6). The core's own platform-key suites test every algorithm and check; these tests prove
//! that each surface operation makes its one core call with the key bridged unchanged.
//!
//! - **Signing** goes through polyjose's own JWK path on the private key (RFC 7515 Appendix A.3,
//!   ES256), and the R‖S result is re-encoded as the DER `Ecdsa-Sig-Value` a platform returns
//!   (RFC 3279 §2.2.3).
//! - **ECDH** uses `p256::ecdh` (RFC 7518 §4.6.2), a test oracle only (ADR 0016 §5).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a panic is a failed assertion

use std::sync::Mutex;

use polyjose::jwk::Jwk;
use polyjose::jws::{ProtectedHeader, SignOptions, sign_compact};
use polyjose::util::b64url_decode;
use polyjose_surface::platform_key::{PlatformKey, PlatformKeyError};
use polyjose_surface::records::{
    JweDecryptOptions, JweEncryptOptions, JweRecipient, JwsSignOptions, JwsVerifyOptions,
    JwtSignOptions, JwtVerifyOptions,
};
use polyjose_surface::{SecretBytes, SecretString, jwe, jws, jwt};

/// RFC 7515 Appendix A.3.1: the P-256 key of ES256.
const P256: &str = r#"{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"}"#;

const PLAINTEXT: &[u8] = b"The true sign of intelligence is not knowledge but imagination.";

/// The calls a [`Soft`] key received: (public JWK and algorithms, private-key steps).
#[derive(Default)]
struct Calls {
    public: usize,
    private: usize,
}

/// A software platform key over a private P-256 JWK.
struct Soft {
    secret: Jwk,
    public: String,
    algorithms: Vec<String>,
    /// Returned by every method instead of a result, when set.
    fail: Option<PlatformKeyError>,
    calls: Mutex<Calls>,
}

impl Soft {
    fn new(algorithms: &[&str]) -> Soft {
        let secret = Jwk::from_json(P256.as_bytes()).unwrap();
        Soft {
            public: secret.to_public().unwrap().to_json().to_string(),
            secret,
            algorithms: algorithms.iter().map(|a| (*a).to_owned()).collect(),
            fail: None,
            calls: Mutex::new(Calls::default()),
        }
    }

    fn failing(algorithms: &[&str], e: PlatformKeyError) -> Soft {
        Soft {
            fail: Some(e),
            ..Soft::new(algorithms)
        }
    }

    fn private_calls(&self) -> usize {
        self.calls.lock().unwrap().private
    }

    fn all_calls(&self) -> usize {
        let calls = self.calls.lock().unwrap();
        calls.public + calls.private
    }

    fn public_call(&self) -> Result<(), PlatformKeyError> {
        self.calls.lock().unwrap().public += 1;
        self.fail.map_or(Ok(()), Err)
    }

    fn private_call(&self) -> Result<(), PlatformKeyError> {
        self.calls.lock().unwrap().private += 1;
        self.fail.map_or(Ok(()), Err)
    }

    /// The private scalar `d`, decoded.
    fn d(&self) -> Vec<u8> {
        let object = self.secret.to_object();
        let d = object.get("d").and_then(|v| v.as_str()).unwrap();
        b64url_decode(d).unwrap()
    }
}

impl PlatformKey for Soft {
    fn public_jwk(&self) -> Result<String, PlatformKeyError> {
        self.public_call()?;
        Ok(self.public.clone())
    }

    fn algorithms(&self) -> Result<Vec<String>, PlatformKeyError> {
        self.public_call()?;
        Ok(self.algorithms.clone())
    }

    fn sign(&self, alg: &str, signing_input: &[u8]) -> Result<Vec<u8>, PlatformKeyError> {
        self.private_call()?;
        assert_eq!(alg, "ES256");
        let (header, payload) = core::str::from_utf8(signing_input)
            .unwrap()
            .split_once('.')
            .unwrap();
        let protected = ProtectedHeader::from_encoded(header).unwrap();
        let payload = b64url_decode(payload).unwrap();
        let jws = sign_compact(&protected, &payload, &self.secret, &SignOptions::new()).unwrap();
        Ok(der_signature(
            &b64url_decode(jws.rsplit('.').next().unwrap()).unwrap(),
        ))
    }

    fn agree(&self, peer_public_key: &[u8]) -> Result<SecretBytes, PlatformKeyError> {
        self.private_call()?;
        let secret = p256::SecretKey::from_slice(&self.d()).unwrap();
        let peer = p256::PublicKey::from_sec1_bytes(peer_public_key).unwrap();
        let z = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
        Ok(SecretBytes::from(z.raw_secret_bytes().to_vec()))
    }

    fn decrypt_key(&self, _: &str, _: &[u8]) -> Result<SecretBytes, PlatformKeyError> {
        self.private_call()?;
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

/// The DER `Ecdsa-Sig-Value` (RFC 3279 §2.2.3) of a P-256 R‖S signature.
fn der_signature(rs: &[u8]) -> Vec<u8> {
    let (r, s) = rs.split_at(rs.len() / 2);
    let mut body = der_integer(r);
    body.extend(der_integer(s));
    let mut out = vec![0x30, u8::try_from(body.len()).unwrap()];
    out.extend(body);
    out
}

fn list(names: &[&str]) -> Vec<String> {
    names.iter().map(|s| (*s).to_owned()).collect()
}

fn es256_header() -> JwsSignOptions {
    JwsSignOptions {
        protected_header: Some(r#"{"alg":"ES256"}"#.to_owned()),
        ..JwsSignOptions::default()
    }
}

fn verify_options() -> JwtVerifyOptions {
    let mut options = JwtVerifyOptions::new(list(&["ES256"]));
    options.now = Some(1_700_000_000);
    options.allow_missing_exp = true;
    options
}

fn decrypt_options(alg: &str) -> JweDecryptOptions {
    JweDecryptOptions::new(list(&[alg]), list(&["A256GCM"]))
}

/// Encrypts `plaintext` to the public half of [`P256`] with `alg`.
fn encrypt_to_key(alg: &str, plaintext: &[u8], compact: bool) -> String {
    let public = Soft::new(&[]).public;
    let options = JweEncryptOptions::new(
        "A256GCM".to_owned(),
        vec![JweRecipient::new(
            alg.to_owned(),
            SecretString::from(public),
        )],
    );
    if compact {
        jwe::jwe_encrypt_compact(plaintext, &options).unwrap()
    } else {
        jwe::jwe_encrypt_json(plaintext, &options, "general").unwrap()
    }
}

fn signed_jwt() -> String {
    let key = Soft::new(&["ES256"]);
    jwt::jwt_sign_with_platform_key(
        r#"{"iss":"joe","sub":"platform"}"#,
        &key,
        &JwtSignOptions::new("ES256".to_owned()),
    )
    .unwrap()
}

// --- Signing (RFC 7515 §5.1; RFC 7518 §3.4; ADR 0071 §3) -------------------------------------------

#[test]
fn jws_sign_compact_with_platform_key_verifies_with_the_public_jwk() {
    let key = Soft::new(&["ES256"]);
    let token = jws::jws_sign_compact_with_platform_key(PLAINTEXT, &key, &es256_header()).unwrap();
    assert_eq!(key.private_calls(), 1);
    let verified = jws::jws_verify_compact(
        &token,
        &key.public,
        &JwsVerifyOptions::new(list(&["ES256"])),
    )
    .unwrap();
    assert_eq!(verified.payload.as_bytes(), PLAINTEXT);
    assert_eq!(verified.alg, "ES256");
}

#[test]
fn jwt_sign_with_platform_key_verifies_with_the_public_jwk() {
    let verified =
        jwt::jwt_verify(&signed_jwt(), &Soft::new(&[]).public, &verify_options()).unwrap();
    assert_eq!(verified.claims, r#"{"iss":"joe","sub":"platform"}"#);
}

// --- Decryption (RFC 7516 §5.2; RFC 7518 §4.6; ADR 0071 §4) ----------------------------------------

#[test]
fn jwe_decrypt_compact_with_platform_key_returns_the_plaintext() {
    for alg in ["ECDH-ES", "ECDH-ES+A256KW"] {
        let key = Soft::new(&[alg]);
        let token = encrypt_to_key(alg, PLAINTEXT, true);
        let decrypted =
            jwe::jwe_decrypt_compact_with_platform_key(&token, &key, &decrypt_options(alg))
                .unwrap();
        assert_eq!(decrypted.plaintext.as_bytes(), PLAINTEXT, "{alg}");
        assert_eq!(key.private_calls(), 1, "{alg}");
    }
}

#[test]
fn jwe_decrypt_json_with_platform_key_returns_the_plaintext() {
    let key = Soft::new(&["ECDH-ES+A256KW"]);
    let jwe = encrypt_to_key("ECDH-ES+A256KW", PLAINTEXT, false);
    let decrypted =
        jwe::jwe_decrypt_json_with_platform_key(&jwe, &key, &decrypt_options("ECDH-ES+A256KW"))
            .unwrap();
    assert_eq!(decrypted.plaintext.as_bytes(), PLAINTEXT);
    assert_eq!(decrypted.recipient_index, 0);
}

#[test]
fn the_nested_decrypts_with_platform_key_verify_the_inner_jwt() {
    let public = Soft::new(&[]).public;
    let options = JweEncryptOptions::new(
        "A256GCM".to_owned(),
        vec![JweRecipient::new(
            "ECDH-ES".to_owned(),
            SecretString::from(public.clone()),
        )],
    );
    let token = jwt::jwt_encrypt_nested(&signed_jwt(), &options).unwrap();
    let key = Soft::new(&["ECDH-ES"]);
    let one = jwt::jwt_decrypt_nested_with_platform_key(
        &token,
        &key,
        &decrypt_options("ECDH-ES"),
        &public,
        &verify_options(),
    )
    .unwrap();
    assert_eq!(one.inner.claims, r#"{"iss":"joe","sub":"platform"}"#);
    let jwks = format!(r#"{{"keys":[{public}]}}"#);
    let set = jwt::jwt_decrypt_nested_with_platform_key_and_jwks(
        &token,
        &key,
        &decrypt_options("ECDH-ES"),
        &jwks,
        &verify_options(),
    )
    .unwrap();
    assert_eq!(set.inner.claims, one.inner.claims);
    assert_eq!(set.inner.key_index, Some(0));
    assert_eq!(key.private_calls(), 2);
}

// --- Errors and misuse (ADR 0071 §2, §4, §6) -------------------------------------------------------

#[test]
fn the_keys_errors_surface_as_the_core_codes() {
    let token = encrypt_to_key("ECDH-ES", PLAINTEXT, true);
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
        let key = Soft::failing(&["ES256"], e);
        let err =
            jws::jws_sign_compact_with_platform_key(PLAINTEXT, &key, &es256_header()).unwrap_err();
        assert_eq!(err.code(), signing, "{e:?}");
        let key = Soft::failing(&["ECDH-ES"], e);
        let err =
            jwe::jwe_decrypt_compact_with_platform_key(&token, &key, &decrypt_options("ECDH-ES"))
                .unwrap_err();
        assert_eq!(err.code(), decrypting, "{e:?}");
    }
}

#[test]
fn misuse_is_refused_before_the_private_key_is_used() {
    // An alg outside the allow-list never reaches the key (RFC 8725 §3.1).
    let key = Soft::new(&["ECDH-ES"]);
    let token = encrypt_to_key("ECDH-ES", PLAINTEXT, true);
    let err = jwe::jwe_decrypt_compact_with_platform_key(
        &token,
        &key,
        &decrypt_options("ECDH-ES+A256KW"),
    )
    .unwrap_err();
    assert_eq!(err.code(), "AlgorithmNotAllowed");
    assert_eq!(key.all_calls(), 0);

    // An algorithm the key's algorithms() omit is a key binding failure.
    let key = Soft::new(&["ES384"]);
    let err =
        jws::jws_sign_compact_with_platform_key(PLAINTEXT, &key, &es256_header()).unwrap_err();
    assert_eq!(err.code(), "KeyAlgorithmMismatch");
    assert_eq!(key.private_calls(), 0);

    // An EC key asked for RS256: the wrong family.
    let key = Soft::new(&["RS256"]);
    let err = jwt::jwt_sign_with_platform_key("{}", &key, &JwtSignOptions::new("RS256".to_owned()))
        .unwrap_err();
    assert_eq!(err.code(), "KeyAlgorithmMismatch");
    assert_eq!(key.private_calls(), 0);
}
