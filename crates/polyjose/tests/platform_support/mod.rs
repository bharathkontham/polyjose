//! A software [`PlatformKey`] for the platform-key tests (feature 0025 T01,
//! ADR 0071 §9): it wraps a private JWK and performs the private-key step
//! with software, counting every call and able to misbehave on request.
//!
//! - **Signing** goes through polyjose's own JWK path: the JWS Signing
//!   Input `BASE64URL(header) '.' BASE64URL(payload)` is split and signed
//!   with `jws::sign_compact`, and an ES\* result is re-encoded from R‖S to
//!   the DER `Ecdsa-Sig-Value` a platform returns (RFC 3279 §2.2.3). So the
//!   signing tests need a protected header holding `alg` and `b64` true.
//! - **ECDH** uses the curve crates' `ecdh::diffie_hellman` (RFC 7518 §4.6.2
//!   Z), and **RSA-OAEP-256** the `rsa` crate's OAEP decryption (RFC 8017
//!   §7.1.2): test oracles only, as ADR 0016 §5 allows.
#![allow(
    dead_code,
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "a shared test fixture module; each test crate uses a subset, and a panic is a failed assertion"
)]

use std::sync::Mutex;

use polyjose::json::{self, Value};
use polyjose::jwk::Jwk;
use polyjose::jws::{ProtectedHeader, SignOptions, sign_compact};
use polyjose::util::b64url_decode;
use polyjose::{PlatformKey, PlatformKeyError};
use zeroize::Zeroizing;

/// The calls a [`Fake`] received.
#[derive(Debug, Default, Clone)]
pub struct Calls {
    pub public_jwk: usize,
    pub algorithms: usize,
    pub sign: usize,
    pub agree: usize,
    pub decrypt_key: usize,
    /// Every `peer_public_key` passed to `agree`, in order.
    pub peers: Vec<Vec<u8>>,
}

impl Calls {
    /// Calls that need the private key.
    pub fn private(&self) -> usize {
        self.sign + self.agree + self.decrypt_key
    }

    /// Every call.
    pub fn all(&self) -> usize {
        self.public_jwk + self.algorithms + self.private()
    }
}

/// How a [`Fake`] spoils its signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignFault {
    /// A correct signature.
    None,
    /// R‖S instead of DER (ES\*).
    RawRs,
    /// One octet short.
    Truncated,
    /// Nothing.
    Empty,
}

/// How a [`Fake`] spoils its `agree` or `decrypt_key` result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretFault {
    /// The correct value.
    None,
    /// One octet short.
    Short,
    /// The right length, one bit flipped.
    Flipped,
}

/// A software platform key.
pub struct Fake {
    /// The key that performs the private step.
    secret: Jwk,
    /// What `public_jwk` returns.
    pub public_json: String,
    /// What `algorithms` returns.
    pub algorithms: Vec<String>,
    /// Errors to return instead, per method.
    pub fail_public_jwk: Option<PlatformKeyError>,
    pub fail_algorithms: Option<PlatformKeyError>,
    pub fail_sign: Option<PlatformKeyError>,
    pub fail_agree: Option<PlatformKeyError>,
    pub fail_decrypt_key: Option<PlatformKeyError>,
    pub sign_fault: SignFault,
    pub secret_fault: SecretFault,
    calls: Mutex<Calls>,
}

impl Fake {
    /// A fake holding the private JWK `private_json`, whose `public_jwk`
    /// is its public part and whose `algorithms` is `algs`.
    pub fn new(private_json: &str, algs: &[&str]) -> Fake {
        let secret = Jwk::from_json(private_json.as_bytes())
            .unwrap_or_else(|e| panic!("{e}: {private_json}"));
        let public = secret.to_public().expect("an asymmetric key");
        Fake {
            public_json: public.to_json().to_string(),
            secret,
            algorithms: algs.iter().map(|a| (*a).to_owned()).collect(),
            fail_public_jwk: None,
            fail_algorithms: None,
            fail_sign: None,
            fail_agree: None,
            fail_decrypt_key: None,
            sign_fault: SignFault::None,
            secret_fault: SecretFault::None,
            calls: Mutex::new(Calls::default()),
        }
    }

    /// The calls so far.
    pub fn calls(&self) -> Calls {
        self.calls.lock().unwrap().clone()
    }

    /// The public JWK the fake reports, imported.
    pub fn public(&self) -> Jwk {
        Jwk::from_json(self.public_json.as_bytes()).unwrap()
    }

    /// A base64url member of the private JWK, decoded.
    fn member(&self, name: &str) -> Zeroizing<Vec<u8>> {
        let object = self.secret.to_object();
        let text = object
            .get(name)
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("no {name}"));
        Zeroizing::new(b64url_decode(text).unwrap())
    }

    /// The software signature, in the platform's form.
    fn software_sign(&self, alg: &str, signing_input: &[u8]) -> Vec<u8> {
        let text = core::str::from_utf8(signing_input).unwrap();
        let (header, payload) = text.split_once('.').unwrap();
        let protected = ProtectedHeader::from_encoded(header).unwrap();
        let payload = b64url_decode(payload).unwrap();
        let jws = sign_compact(&protected, &payload, &self.secret, &SignOptions::new())
            .unwrap_or_else(|e| panic!("software sign {alg}: {e}"));
        let signature = b64url_decode(jws.rsplit('.').next().unwrap()).unwrap();
        let ecdsa = alg.starts_with("ES");
        match self.sign_fault {
            SignFault::None if ecdsa => der_signature(&signature),
            SignFault::None | SignFault::RawRs => signature,
            SignFault::Truncated if ecdsa => {
                let der = der_signature(&signature);
                der[..der.len() - 1].to_vec()
            }
            SignFault::Truncated => signature[..signature.len() - 1].to_vec(),
            SignFault::Empty => Vec::new(),
        }
    }

    fn spoil(&self, mut value: Vec<u8>) -> Zeroizing<Vec<u8>> {
        match self.secret_fault {
            SecretFault::None => {}
            SecretFault::Short => {
                value.pop();
            }
            SecretFault::Flipped => value[0] ^= 1,
        }
        Zeroizing::new(value)
    }

    fn software_agree(&self, peer: &[u8]) -> Result<Vec<u8>, PlatformKeyError> {
        let d = self.member("d");
        macro_rules! agree {
            ($krate:ident) => {{
                let secret =
                    $krate::SecretKey::from_slice(&d).map_err(|_| PlatformKeyError::Failed)?;
                let public = $krate::PublicKey::from_sec1_bytes(peer)
                    .map_err(|_| PlatformKeyError::Failed)?;
                let shared =
                    $krate::ecdh::diffie_hellman(secret.to_nonzero_scalar(), public.as_affine());
                shared.raw_secret_bytes().to_vec()
            }};
        }
        let crv = self.secret.to_object();
        Ok(match crv.get("crv").and_then(Value::as_str) {
            Some("P-256") => agree!(p256),
            Some("P-384") => agree!(p384),
            Some("P-521") => agree!(p521),
            _ => return Err(PlatformKeyError::Failed),
        })
    }

    fn software_decrypt(&self, encrypted_key: &[u8]) -> Result<Vec<u8>, PlatformKeyError> {
        let uint = |name: &str| {
            let bytes = self.member(name);
            let bits = u32::try_from(bytes.len() * 8).unwrap();
            rsa::BoxedUint::from_be_slice(&bytes, bits).unwrap()
        };
        let key = rsa::PrivateKey::from_components(
            uint("n"),
            uint("e"),
            uint("d"),
            vec![uint("p"), uint("q")],
        )
        .unwrap();
        key.oaep_decrypt::<sha2::Sha256>(encrypted_key)
            .map_err(|_| PlatformKeyError::Failed)
    }
}

impl PlatformKey for Fake {
    fn public_jwk(&self) -> Result<String, PlatformKeyError> {
        self.calls.lock().unwrap().public_jwk += 1;
        match self.fail_public_jwk {
            Some(e) => Err(e),
            None => Ok(self.public_json.clone()),
        }
    }

    fn algorithms(&self) -> Result<Vec<String>, PlatformKeyError> {
        self.calls.lock().unwrap().algorithms += 1;
        match self.fail_algorithms {
            Some(e) => Err(e),
            None => Ok(self.algorithms.clone()),
        }
    }

    fn sign(&self, alg: &str, signing_input: &[u8]) -> Result<Vec<u8>, PlatformKeyError> {
        self.calls.lock().unwrap().sign += 1;
        match self.fail_sign {
            Some(e) => Err(e),
            None => Ok(self.software_sign(alg, signing_input)),
        }
    }

    fn agree(&self, peer_public_key: &[u8]) -> Result<Zeroizing<Vec<u8>>, PlatformKeyError> {
        {
            let mut calls = self.calls.lock().unwrap();
            calls.agree += 1;
            calls.peers.push(peer_public_key.to_vec());
        }
        if let Some(e) = self.fail_agree {
            return Err(e);
        }
        Ok(self.spoil(self.software_agree(peer_public_key)?))
    }

    fn decrypt_key(
        &self,
        alg: &str,
        encrypted_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, PlatformKeyError> {
        self.calls.lock().unwrap().decrypt_key += 1;
        assert_eq!(alg, "RSA-OAEP-256");
        if let Some(e) = self.fail_decrypt_key {
            return Err(e);
        }
        Ok(self.spoil(self.software_decrypt(encrypted_key)?))
    }
}

/// A non-negative DER INTEGER (X.690 §8.3) of the big-endian `magnitude`.
fn der_integer(magnitude: &[u8]) -> Vec<u8> {
    let first = magnitude
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(magnitude.len() - 1);
    let mut contents = magnitude[first..].to_vec();
    if contents[0] & 0x80 != 0 {
        contents.insert(0, 0);
    }
    let mut out = vec![0x02, u8::try_from(contents.len()).unwrap()];
    out.extend(contents);
    out
}

/// The DER `Ecdsa-Sig-Value` (RFC 3279 §2.2.3) of an R‖S signature.
pub fn der_signature(rs: &[u8]) -> Vec<u8> {
    let (r, s) = rs.split_at(rs.len() / 2);
    let mut body = der_integer(r);
    body.extend(der_integer(s));
    let mut out = vec![0x30];
    let len = u8::try_from(body.len()).unwrap();
    if len >= 0x80 {
        out.push(0x81);
    }
    out.push(len);
    out.extend(body);
    out
}

/// RFC 7520 §3.2 (Figure 2): the P-521 private key of §4.3 (ES512).
pub const RFC7520_3_2: &str = r#"{"kty":"EC","kid":"bilbo.baggins@hobbiton.example","use":"sig","crv":"P-521","x":"AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt","y":"AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1","d":"AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zbKipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt"}"#;

/// The RFC 7520 §3.4 (Figure 4) RSA private key of §4.1 (RS256) and §4.2
/// (PS384), as vendored in `tests/data/keys/rfc/`.
pub fn rfc7520_3_4() -> String {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/keys/rfc/rfc7520-3.4-rsa-private.jwk.json"
    );
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// RFC 7515 Appendix A.3.1: the P-256 key of ES256.
pub const RFC7515_A3: &str = r#"{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"}"#;

/// The first RSA private JWK (with `qi`) found in a conformance vector,
/// as JSON text.
pub fn rsa_private_from_vector(relative: &str) -> String {
    let path = format!(
        "{}/../../conformance/vectors/{relative}",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    fn find(value: &Value) -> Option<String> {
        if let Some(object) = value.as_object() {
            if object.get("kty").and_then(Value::as_str) == Some("RSA") && object.contains("qi") {
                return Some(object.to_json());
            }
            return object.iter().find_map(|(_, v)| find(v));
        }
        value.as_array()?.iter().find_map(find)
    }
    find(&json::parse(&text).unwrap()).unwrap_or_else(|| panic!("no RSA private key in {path}"))
}

/// RSA private keys of 2048, 3072 and 4096 bits. The 4096-bit one is
/// RFC 7520 Figure 84, whose `"alg":"RSA-OAEP"` (SHA-1, not implemented,
/// ADR 0022) is dropped.
pub fn rsa_keys() -> [String; 3] {
    [
        rfc7520_3_4(),
        rsa_private_from_vector("jwe/rsa-oaep-256/decrypt-3072-a256cbc-hs512.json"),
        without(
            &rsa_private_from_vector(
                "jwt/rfc7520-nested/6-8-fig236-fig84-private-key-unsupported.json",
            ),
            &["alg"],
        ),
    ]
}

/// `json` without the members `names` (a JWK text).
pub fn without(json: &str, names: &[&str]) -> String {
    let value = json::parse(json.as_bytes()).unwrap();
    let mut object = value.into_object().unwrap();
    for name in names {
        object.remove(name);
    }
    object.to_json()
}

/// `json` with `name` set to the string `value` (a JWK text).
pub fn with(json: &str, name: &str, value: &str) -> String {
    let parsed = json::parse(json.as_bytes()).unwrap();
    let mut object = parsed.into_object().unwrap();
    object.insert(name, value);
    object.to_json()
}
