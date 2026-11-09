# polyjose

JSON Object Signing and Encryption in pure Rust: JWS, JWE, JWK, JWA and JWT (RFC 7515 to 7519),
built from RustCrypto and dalek primitives, with no OpenSSL, `ring` or `aws-lc`. Verify and decrypt
always take an explicit algorithm allow-list, `none` is never accepted, and secrets are zeroized
when dropped (RFC 8725).

The same core ships as `@polyjose/node`, `@polyjose/wasm`, a Kotlin library for Android and the JVM,
and a Swift package. See <https://polyjose.dev> for every platform.

## Install

```sh
cargo add polyjose
```

Rust 1.89 or later. The crate has no default features. `deflate` adds JWE compression (`zip: DEF`,
RFC 7516 §4.1.3), which is off by default because compressing before encrypting can leak plaintext
(RFC 8725 §3.6). Never enable `insecure-test-vectors`: it exists only for polyjose's own tests.

## Quick start: sign and verify a JWT

```rust
use polyjose::jwa::SigningAlg;
use polyjose::jwt::{self, Audience, Claims, Clock, IssueOptions, Keys, NumericDate, Policy, SystemClock};
use polyjose::keys;

fn main() -> Result<(), polyjose::Error> {
    // An ES256 key pair (RFC 7518 §3.4). The verifier needs only the public half.
    let private_key = keys::generate_for(SigningAlg::ES256)?;
    let public_key = private_key.to_public().expect("an EC key has a public half");

    // Issue a token that expires in five minutes (RFC 7519 §4.1).
    let now = SystemClock.now()?;
    let mut claims = Claims::new();
    claims.iss = Some("https://issuer.example".into());
    claims.sub = Some("user-123".into());
    claims.aud = Some(Audience::One("https://api.example".into()));
    claims.exp = NumericDate::from_secs(now + 300);
    let token = jwt::sign(&claims, &IssueOptions::new(SigningAlg::ES256), &private_key)?;

    // Verify it. The allow-list names the algorithms you accept: the token's own `alg` is never
    // trusted alone (RFC 8725 §3.1). `exp` is required and checked with 60 seconds of leeway, and
    // the issuer and audience must match (RFC 8725 §3.8, §3.9).
    let algs = [SigningAlg::ES256];
    let policy = Policy::new(&SystemClock, &algs)?
        .issuer("https://issuer.example")
        .audience("https://api.example");
    let verified = jwt::verify(&token, Keys::One(&public_key), &policy)?;
    assert_eq!(verified.claims.sub.as_deref(), Some("user-123"));
    Ok(())
}
```

Every failure is a `polyjose::Error`; `err.code()` gives a stable string, such as `TokenExpired`
or `AlgorithmNotAllowed`, that is the same on every platform.

## Encrypt and decrypt (JWE)

```rust
use polyjose::jwa::{ContentEncAlg, KeyMgmtAlg};
use polyjose::jwe::{self, DecryptPolicy, Encryptor, Recipient};
use polyjose::jwk::EcCurve;
use polyjose::keys::{self, KeySpec};

fn main() -> Result<(), polyjose::Error> {
    // The recipient's P-256 key pair. The sender needs only the public half.
    let recipient = keys::generate(KeySpec::Ec(EcCurve::P256))?;
    let recipient_public = recipient.to_public().expect("an EC key has a public half");

    // ECDH-ES+A256KW (RFC 7518 §4.6) wraps a fresh A256GCM content key (RFC 7518 §5.3).
    let token = Encryptor::new(ContentEncAlg::A256GCM)
        .recipient(Recipient::new(KeyMgmtAlg::EcdhEsA256KW, &recipient_public))
        .encrypt_compact(b"top secret")?;

    // Decrypting names the `alg` and `enc` values you accept (RFC 8725 §3.1).
    let policy = DecryptPolicy::new(&[KeyMgmtAlg::EcdhEsA256KW], &[ContentEncAlg::A256GCM])?;
    let decrypted = jwe::decrypt_compact(&token, &recipient, &policy)?;
    assert_eq!(decrypted.plaintext(), b"top secret");
    Ok(())
}
```

The plaintext is wiped from memory when `decrypted` is dropped.

## Documentation

- Guides for every platform: <https://polyjose.dev>
- Getting started in Rust: <https://polyjose.dev/start/rust/>
- API reference: <https://docs.rs/polyjose>
- Security model: <https://polyjose.dev/security/model/>
- Source, issues and changelog: <https://github.com/bharathkontham/polyjose>

## License

MIT. See <https://github.com/bharathkontham/polyjose/blob/main/LICENSE>.
