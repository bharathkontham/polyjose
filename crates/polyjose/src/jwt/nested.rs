//! Nested JWTs: a signed JWT encrypted as a compact JWE, at depth 1
//! (RFC 7519 §5.2, §7.1 step 5, §7.2 step 8, §11.2; RFC 8725 §3.3,
//! §3.11; ADR 0027 §7).

use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::header::Header;
use crate::json::{self, Value};
use crate::jwa::SigningAlg;
#[cfg(doc)]
use crate::jwe::Decrypted;
use crate::jwe::{DecryptPolicy, Encryptor, decrypt_compact};
use crate::jwk::Jwk;
use crate::util::b64url_decode;

use super::typ::{JWT, Layer, check_jwt_header, media_type_eq};
use super::verify::verify_inner;
use super::{Audience, Claims, Keys, Policy, VerifiedJwt};

/// A decrypted, verified and validated nested JWT (RFC 7519 §7.2).
///
/// `Debug` prints no key material and no claim string of the decrypted
/// inner token (workspace secrets rule, ADR 0049 §4): the inner claims
/// print through [`Claims`]' redacting `Debug` (see [`Claims`#debug]),
/// as in [`VerifiedJwt`]. The inner token's compact serialization, payload
/// and signature are not held, so they never print. The inner and outer
/// headers print through [`Header`]'s `Debug`: typed parameters such as
/// `alg`, `kid` and `typ` in full, JSON objects redacted (see
/// [`Header`#debug]).
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct VerifiedNestedJwt {
    /// The inner signed JWT, verified with the caller's keys and validated
    /// against the caller's policy (RFC 8725 §3.3).
    pub inner: VerifiedJwt,
    /// The outer JWE Protected Header (RFC 7516 §4), which the JWE's
    /// authentication tag covers. A JWT is compact, so this is the whole
    /// outer JOSE Header (RFC 7516 §7.1).
    pub outer_header: Header,
    /// The index of the JWE recipient that decrypted: always `0`, since a
    /// compact JWE has one recipient (RFC 7516 §7.1).
    pub recipient: usize,
}

/// Encrypts the signed JWT `signed_jwt` with `encryptor` as a compact JWE
/// whose protected header carries `cty: "JWT"` (RFC 7519 §5.2, §7.1
/// step 5): the sign-then-encrypt order of RFC 7519 §11.2.
///
/// - `signed_jwt` must be shaped like a compact JWS (RFC 7515 §7.1):
///   exactly three parts of base64url characters with non-empty header
///   and signature parts, not a JSON serialization (RFC 7519 §1, ADR 0027
///   §6–§7). An empty signature part is an Unsecured JWS (RFC 7519 §6),
///   which is never produced (RFC 8725 §3.2, ADR 0007).
/// - Of `signed_jwt`, only the JWS Protected Header is decoded (it is not
///   secret; RFC 7515 §5.2 steps 2–3), and only its `alg` is read: it
///   must be a string (RFC 7515 §4.1.1) other than `none` (RFC 7518 §3.6;
///   RFC 8725 §3.2; ADR 0027 §8, as for [`sign`](fn@super::sign)). The
///   payload is never decoded or copied, and the signature is the
///   receiver's to verify.
/// - The JWE Protected Header is a **copy** of the one set on `encryptor`
///   with [`Encryptor::protected_header`] (its other parameters, such as
///   `typ` or `kid`, are kept) plus `cty: "JWT"`, spelled exactly as
///   RFC 7519 §5.2 requires. A caller `cty` equal to `JWT` under the
///   media-type comparison (RFC 7515 §4.1.10, so `jwt` or
///   `application/JWT`) is rewritten to `JWT`; any other `cty` is
///   refused (ADR 0027 §7). `encryptor` itself is not changed.
/// - **No compression**: RFC 8725 §3.6 says compression before
///   encryption "SHOULD NOT" be done (compressed data "often reveals
///   information about the plaintext"). An `encryptor` built with [`Encryptor::compress`], or
///   whose protected header sets `zip` (RFC 7516 §4.1.3), is refused in
///   every build, with or without the `deflate` feature (ADR 0017).
///   [`decrypt_nested`] still accepts a compressed nested JWT.
/// - The output is the JWE Compact Serialization (RFC 7516 §7.1), so
///   `encryptor` needs exactly one recipient and no unprotected header or
///   AAD.
/// - Nested under a policy with an explicit type (such as
///   [`Policy::access_token`]), the outer `typ` must be omitted or match
///   that type; see [`decrypt_nested`].
/// - **Confidentiality, not exclusivity.** The JWE hides the signed JWT
///   and its signature (RFC 7519 §11.2), but `signed_jwt` stays a valid
///   signed JWT on its own: the recipient, or anyone who later gets the
///   plaintext, can present it to [`verify`](fn@super::verify). To have a
///   token accepted only in nested form, sign it with a `typ` used only
///   for nested tokens ([`IssueOptions::typ`](super::IssueOptions::typ))
///   or with an `aud` only the nested verifier accepts, and check that on
///   the receiving side (RFC 8725 §3.3, §3.11–§3.12; see
///   [`decrypt_nested`]).
///
/// # Errors
///
/// The checks run in this order and the first failure decides the error.
/// Steps 1–4 run before anything is encrypted or drawn from the random
/// source:
///
/// 1. **Shape**: [`Error::InvalidFormat`] if `signed_jwt` is not a
///    three-part compact JWS, its signature part is empty, or its
///    protected header is not base64url-encoded JSON object text
///    (RFC 7515 §5.2 steps 2–3).
/// 2. **The inner `alg`**: [`Error::InvalidHeader`]`("alg")` if it is
///    missing or not a string; [`Error::AlgorithmNotAllowed`] if it is
///    `none`.
/// 3. **The caller's `cty`**: [`Error::InvalidHeader`]`("cty")` if the
///    encryptor's protected header sets a `cty` other than `JWT`.
/// 4. **Compression**: [`Error::InvalidHeader`]`("zip")` if the encryptor
///    compresses or its protected header sets `zip` (RFC 8725 §3.6).
/// 5. **Encryption**: the errors of [`Encryptor::encrypt_compact`].
pub fn encrypt_nested(signed_jwt: &str, encryptor: &Encryptor) -> Result<String> {
    // 1. Shape (RFC 7515 §7.1), with a signature (RFC 8725 §3.2).
    let inner_header = check_compact_jws_shape(signed_jwt)?;
    // 2. The inner `alg`, from the protected header only (RFC 8725 §3.2).
    check_inner_alg(inner_header)?;
    // 3. RFC 7519 §5.2, §7.1 step 5: the caller's header, copied, plus cty.
    let mut protected = encryptor.protected().cloned().unwrap_or_default();
    if protected
        .cty
        .as_deref()
        .is_some_and(|cty| !media_type_eq(cty, JWT))
    {
        return Err(Error::InvalidHeader("cty"));
    }
    // 4. RFC 8725 §3.6: no compression before encryption.
    if encryptor.compresses() || protected.zip.is_some() {
        return Err(Error::InvalidHeader("zip"));
    }
    protected.cty = Some(JWT.into());
    encryptor
        .clone()
        .protected_header(protected)
        .encrypt_compact(signed_jwt.as_bytes())
}

/// Checks that `token` is shaped like a JWS Compact Serialization
/// (RFC 7515 §7.1): three `.`-separated parts of base64url characters
/// (RFC 7515 §2, no padding), the first (the protected header) and the
/// last (the signature) non-empty. An empty signature is an Unsecured JWS
/// (RFC 7519 §6), never produced (RFC 8725 §3.2). Nothing is decoded or
/// copied, so a secret payload is not duplicated.
///
/// Returns the encoded protected header part.
///
/// # Errors
///
/// [`Error::InvalidFormat`] for any other shape.
fn check_compact_jws_shape(token: &str) -> Result<&str> {
    const NOT_A_JWS: Error = Error::InvalidFormat("a nested JWT encrypts a compact JWS");
    let mut parts = token.split('.');
    let (Some(header), Some(_), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(NOT_A_JWS);
    };
    let base64url = |b: u8| b.is_ascii_alphanumeric() || b == b'-' || b == b'_';
    if header.is_empty()
        || signature.is_empty()
        || !token.bytes().all(|b| b == b'.' || base64url(b))
    {
        return Err(NOT_A_JWS);
    }
    Ok(header)
}

/// Refuses an inner JWS whose protected header has no usable `alg`, or
/// `alg: none` (RFC 7518 §3.6; RFC 8725 §3.2: `none` is never produced;
/// ADR 0007, ADR 0027 §8).
///
/// `encoded` is the JWS Protected Header part, which is not secret: it is
/// base64url-decoded and parsed as JSON (RFC 7515 §5.2 steps 2–3), and
/// only its `alg` member is read. A duplicate member name is a parse
/// error (RFC 7515 §5.2 step 4), so a second `alg` cannot hide `none`.
/// Any other string `alg` is left to the receiver's allow-list
/// (RFC 8725 §3.1).
///
/// # Errors
///
/// - [`Error::InvalidFormat`] if `encoded` is not base64url-encoded
///   UTF-8 JSON object text.
/// - [`Error::InvalidHeader`]`("alg")` if `alg` is missing or not a
///   string (RFC 7515 §4.1.1: it "MUST be present").
/// - [`Error::AlgorithmNotAllowed`] if `alg` is `none`.
fn check_inner_alg(encoded: &str) -> Result<()> {
    const UNDECODABLE: Error =
        Error::InvalidFormat("the inner JWS Protected Header is not base64url JSON");
    let json = b64url_decode(encoded).map_err(|_| UNDECODABLE)?;
    let header = json::parse(&json)
        .ok()
        .and_then(Value::into_object)
        .ok_or(UNDECODABLE)?;
    match header.get("alg").and_then(Value::as_str) {
        None => Err(Error::InvalidHeader("alg")),
        Some(alg) if SigningAlg::from(alg) == SigningAlg::None => Err(Error::AlgorithmNotAllowed),
        Some(_) => Ok(()),
    }
}

/// Decrypts the nested JWT `token` with `decrypt_key` under
/// `decrypt_policy`, then verifies and validates the inner signed JWT
/// with `keys` and `policy` (RFC 7519 §7.2 step 8; RFC 8725 §3.3;
/// ADR 0027 §7, §9).
///
/// Both layers use the caller's keys and algorithms, and neither layer's
/// header selects the other's keys (RFC 8725 §3.3). The outer `cty` must
/// be `JWT` and is read, with `typ`, from the JWE Protected Header only
/// (ADR 0050 §3). The decrypted inner token is wiped after use.
///
/// The steps run in the ADR 0027 §9 order, and the first failure decides
/// the error:
///
/// 1. **Shape**: a JWT is compact (RFC 7519 §1, §7.2 step 1), so a JWE
///    JSON Serialization, flattened or general, is
///    [`Error::InvalidFormat`] (ADR 0027 §6); so is anything other than
///    five parts, such as a three-part signed JWT (ADR 0027 §7: signed and
///    nested JWTs have separate entry points).
/// 2. **The JWE** (RFC 7516 §5.2): [`decrypt_compact`] with its error
///    contract unchanged, so every failure after key management, a
///    tampered tag included, is [`Error::DecryptionFailed`], before
///    anything of the inner token is looked at.
/// 3. **N1, the outer header**:
///    `cty` must be `JWT` (RFC 7519 §5.2, compared per RFC 7515 §4.1.10)
///    and a `typ`, if present, must satisfy `policy`'s `typ` mode
///    (ADR 0027 §7) → else [`Error::InvalidHeader`]. Both are read from
///    [`Decrypted::protected_header`] only, never from the joint header
///    (ADR 0050 §3); a compact JWE has no unprotected header (RFC 7516
///    §7.1). An encrypt-only JWT (no `cty`) is therefore rejected.
///
///    **Outer `typ` under an explicit-type policy.** With
///    [`Policy::access_token`] or [`Policy::expect_typ`], an outer `typ`
///    that is present must match the same type as the inner one
///    (ADR 0027 §7), so an outer `typ: JWT`, a common issuer habit, is
///    [`Error::InvalidHeader`]`("typ")` even when the inner JWT is
///    correctly typed. RFC 8725 §3.11 requires explicit typing on the
///    inner JWT only, so issuers should omit the outer `typ`
///    ([`encrypt_nested`] adds none of its own).
/// 4. **The inner token**, depth 1: the plaintext must be a three-part
///    compact JWS. A five-part plaintext (a JWE) is
///    [`Error::InvalidFormat`] and an inner JWS whose own `cty` is `JWT`
///    is [`Error::InvalidHeader`] (ADR 0027 §7). Then every step of
///    [`verify`](fn@super::verify) on it (ADR 0027 §9 steps 1–J10): its
///    `alg` against `policy`'s allow-list (`none` never), its signature
///    with `keys`, explicit typing (RFC 8725 §3.11: on the inner JWT),
///    and the claims.
/// 5. **N2, replicated claims** (RFC 7519 §5.3): an `iss`, `sub` or `aud`
///    in the outer protected header must be JSON-equal to the inner claim:
///    same JSON type and value, so the form matters (an outer
///    `"aud":["a"]` differs from an inner `"aud":"a"`), and an outer claim
///    the inner Claims Set lacks is a mismatch → [`Error::InvalidClaim`].
///
/// **Secrecy** (ADR 0049 §4, ADR 0027 §7): the inner token stays in the
/// decrypted plaintext's wiping buffer, is read in place, and is wiped
/// when this function returns, on success and on every error. No error
/// carries any of it, and the result's `Debug` prints no claim string:
/// each prints as `"<redacted>"` (see [`VerifiedNestedJwt`]).
///
/// **What success proves** (RFC 7519 §11.2; RFC 8725 §3.3). The outer JWE
/// gives confidentiality, and the inner signature authenticates the
/// issuer. Success does not mean that the issuer encrypted the token, or
/// that the token was never seen in clear text:
///
/// - Anyone able to decrypt, the intended recipient included, can take out
///   the inner JWS and present it to [`verify`](fn@super::verify), which
///   accepts it like any signed JWT of that issuer.
/// - Anyone holding a signed JWT of the issuer can wrap it in a JWE for
///   this recipient when the key management mode lets anyone encrypt:
///   `ECDH-ES` and `ECDH-ES+A*KW`, `RSA-OAEP-256` to a published key, or
///   `PBES2-*` with a known password. Only symmetric key management
///   (`dir`, `A*KW`, `A*GCMKW`) under a key shared solely with the issuer
///   limits who can produce the outer layer, to the holders of that key.
///
/// No forgery follows, since the inner signature and every check of
/// `policy` still apply. A deployment that must accept a token only in
/// nested form makes that visible inside the signed inner JWT, in its
/// protected header or its claims, and checks it here (RFC 8725
/// §3.11–§3.12):
///
/// - a distinct explicit `typ` on the inner JWT, put only on the tokens
///   the issuer nests ([`IssueOptions::typ`](super::IssueOptions::typ)) and
///   required with [`Policy::expect_typ`]. A signed-JWT policy in
///   [`TypMode::Default`](super::TypMode::Default) then rejects the
///   extracted inner token, and a signed JWT the issuer did not nest
///   fails this policy; or
/// - a distinct `aud` that only the nested verifier's policy accepts
///   ([`Policy::audience`]).
///
/// A signed-JWT verifier with [`Policy::any_typ`], or one expecting the
/// same `typ` or `aud`, still accepts the inner token.
///
/// ```
/// use polyjose::Error;
/// use polyjose::jwa::{ContentEncAlg, KeyMgmtAlg, SigningAlg};
/// use polyjose::jwe::{DecryptPolicy, Encryptor, Recipient};
/// use polyjose::jwk::Jwk;
/// use polyjose::jwt::{self, Claims, FixedClock, IssueOptions, Keys, NumericDate, Policy};
///
/// // RFC 7515 Appendix A.1.1's HMAC key and RFC 7520 §5.8.1's A128KW key.
/// let signing_key = Jwk::from_json(br#"{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}"#)?;
/// let kek = Jwk::from_json(br#"{"kty":"oct","k":"GZy6sIZ6wl9NJOKB-jnmVQ"}"#)?;
/// let encryptor = Encryptor::new(ContentEncAlg::A128GCM)
///     .recipient(Recipient::new(KeyMgmtAlg::A128KW, &kek));
/// let decrypt_policy = DecryptPolicy::new(&[KeyMgmtAlg::A128KW], &[ContentEncAlg::A128GCM])?;
///
/// let mut claims = Claims::new();
/// claims.exp = NumericDate::from_secs(1_300_819_380);
///
/// // The issuer types the tokens it nests with an application type of its own.
/// const NESTED_ONLY: &str = "example-nested+jwt";
/// let inner = jwt::sign(&claims, &IssueOptions::new(SigningAlg::HS256).typ(NESTED_ONLY), &signing_key)?;
/// let nested = jwt::encrypt_nested(&inner, &encryptor)?;
///
/// let clock = FixedClock(1_300_819_320);
/// let algs = [SigningAlg::HS256];
/// let nested_policy = Policy::new(&clock, &algs)?.expect_typ(NESTED_ONLY);
/// let signed_policy = Policy::new(&clock, &algs)?;
/// let keys = Keys::One(&signing_key);
///
/// assert!(jwt::decrypt_nested(&nested, &kek, &decrypt_policy, keys, &nested_policy).is_ok());
///
/// // The inner JWS, taken out and presented alone, fails a signed-JWT policy.
/// let replayed = jwt::verify(&inner, keys, &signed_policy);
/// assert_eq!(replayed.unwrap_err(), Error::InvalidHeader("typ"));
///
/// // A signed JWT the issuer did not nest, wrapped by someone else, fails here.
/// let plain = jwt::sign(&claims, &IssueOptions::new(SigningAlg::HS256), &signing_key)?;
/// let wrapped = jwt::encrypt_nested(&plain, &encryptor)?;
/// let rewrapped = jwt::decrypt_nested(&wrapped, &kek, &decrypt_policy, keys, &nested_policy);
/// assert_eq!(rewrapped.unwrap_err(), Error::InvalidHeader("typ"));
/// # Ok::<(), polyjose::Error>(())
/// ```
///
/// **Opaque to clients.** As with [`verify`](fn@super::verify), the error
/// codes below are for logs and diagnostics. A server should answer the
/// client with one opaque "invalid token" (RFC 6750 §3.1
/// `invalid_token`), and not reveal which layer or check failed (see
/// [the error module](crate::error#codes-are-for-logs-not-for-clients)).
///
/// # Errors
///
/// First the JWE errors of [`decrypt_compact`]
/// (every failure after key management is [`Error::DecryptionFailed`]);
/// then [`Error::InvalidHeader`] for the outer `cty`/`typ`; then every
/// error of [`verify`](fn@super::verify) for the inner token; then
/// [`Error::InvalidClaim`] if an `iss`, `sub` or `aud` replicated in the
/// outer header differs from the inner claim (RFC 7519 §5.3). A
/// three-part token or a JSON serialization is [`Error::InvalidFormat`].
pub fn decrypt_nested(
    token: &str,
    decrypt_key: &Jwk,
    decrypt_policy: &DecryptPolicy,
    keys: Keys<'_>,
    policy: &Policy<'_>,
) -> Result<VerifiedNestedJwt> {
    // Step 1 (ADR 0027 §6): compact only. The compact parser below would
    // reject a JSON JWE too, but by its dots it could call one
    // InvalidBase64; the shape is the stable answer.
    if is_json_serialization(token) {
        return Err(Error::InvalidFormat("a JWT uses the compact serialization"));
    }

    // Step 2: the 0003 JWE error contract, five parts first.
    let decrypted = decrypt_compact(token, decrypt_key, decrypt_policy)?;

    // N1 (ADR 0027 §7, ADR 0050 §3): from the protected header only. A
    // compact JWE always has one and never has the unprotected parts;
    // they are passed anyway, so a change there could only fail closed.
    let outer_header = decrypted
        .protected_header()
        .cloned()
        .ok_or(Error::InvalidHeader("cty"))?;
    check_outer(
        &outer_header,
        &[decrypted.shared_header(), decrypted.recipient_header()],
        policy,
    )?;
    let recipient = decrypted.recipient();

    // Step 4: the inner token, read in place from the wiping buffer
    // (ADR 0049 §4), which drops on every path out of this function.
    let plaintext: Zeroizing<Vec<u8>> = decrypted.into_plaintext();
    let inner_token = core::str::from_utf8(&plaintext)
        .map_err(|_| Error::InvalidFormat("the inner token is not a compact JWS"))?;
    let inner = verify_inner(inner_token, keys, policy)?;

    // N2 (RFC 7519 §5.3).
    check_replicated_claims(&outer_header, &inner.claims)?;

    Ok(VerifiedNestedJwt {
        inner,
        outer_header,
        recipient,
    })
}

/// Whether `token` is shaped like a JOSE JSON Serialization (RFC 7515
/// §7.2, RFC 7516 §7.2): a JSON object, after any JSON whitespace
/// (RFC 8259 §2). A compact serialization is base64url and `.` only
/// (RFC 7516 §7.1), so it never starts with `{`.
fn is_json_serialization(token: &str) -> bool {
    token
        .trim_start_matches([' ', '\t', '\n', '\r'])
        .starts_with('{')
}

/// N1 (ADR 0027 §7, §9): the outer JWE header rules of a nested JWT.
///
/// `protected` is the JWE Protected Header, the only one the JWE's
/// authentication tag covers (RFC 7516 §5.1 step 14). `unprotected` holds
/// any JWE Shared or Per-Recipient Unprotected Header; a compact JWE has
/// none (RFC 7516 §7.1). `cty` and `typ` are read from `protected` only
/// (ADR 0050 §3), and an unprotected header that sets either is rejected
/// ([`check_jwt_header`]).
///
/// # Errors
///
/// [`Error::InvalidHeader`] if `cty` is not `JWT` (RFC 7519 §5.2), if
/// `typ` fails the policy's `typ` mode (ADR 0027 §5, §7), or if an
/// unprotected header sets `cty` or `typ`.
fn check_outer(protected: &Header, unprotected: &[Option<&Header>], p: &Policy<'_>) -> Result<()> {
    for header in unprotected.iter().flatten() {
        check_jwt_header(protected, Some(header), p, Layer::Outer)?;
    }
    check_jwt_header(protected, None, p, Layer::Outer)
}

/// N2: the claims replicated as header parameters (RFC 7519 §5.3: the
/// receiver "SHOULD verify that their values are identical"; ADR 0027 §7
/// makes it a MUST).
///
/// For each of `iss`, `sub` and `aud` present in `outer` (the outer JWE
/// Protected Header; ADR 0050 §3), the inner Claims Set must hold the
/// same claim with a **JSON-equal** value: same JSON type and same value.
/// So the form matters: an outer `"aud":["a"]` does not equal an inner
/// `"aud":"a"`, an array must match element for element and in order, and
/// comparison is exact and case-sensitive (RFC 7519 §2, §7.3: StringOrURI
/// values are compared with no transformation). An outer claim the inner
/// Claims Set lacks is a mismatch. Other replicated claims are not
/// checked.
///
/// # Errors
///
/// [`Error::InvalidClaim`]`(name)` for the first mismatch, in the order
/// `iss`, `sub`, `aud`.
fn check_replicated_claims(outer: &Header, claims: &Claims) -> Result<()> {
    let string = |s: &Option<String>| s.as_deref().map(Value::from);
    let audience = |aud: &Audience| match aud {
        Audience::One(one) => Value::from(one.as_str()),
        Audience::Many(many) => {
            Value::Array(many.iter().map(|a| Value::from(a.as_str())).collect())
        }
    };
    let replicated: [(&'static str, Option<Value>); 3] = [
        ("iss", string(&claims.iss)),
        ("sub", string(&claims.sub)),
        ("aud", claims.aud.as_ref().map(audience)),
    ];
    for (name, inner) in replicated {
        if let Some(outer_value) = outer.other_params().get(name)
            && inner.as_ref() != Some(outer_value)
        {
            return Err(Error::InvalidClaim(name));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwa::{ContentEncAlg, KeyMgmtAlg, SigningAlg};
    use crate::jwe::{JsonForm, Recipient, decrypt_json};
    use crate::jws::{ProtectedHeader, SignOptions, sign_compact};
    use crate::jwt::FixedClock;

    /// RFC 7515 Appendix A.1.1: the HMAC key of RFC 7519 §3.1.
    const OCT_64: &str = r#"{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}"#;
    /// RFC 7520 §5.8.1: the A128KW key-encryption key.
    const KEK: &str = r#"{"kty":"oct","k":"GZy6sIZ6wl9NJOKB-jnmVQ"}"#;
    const HS256: [SigningAlg; 1] = [SigningAlg::HS256];
    const NOW: i64 = 1_300_819_320;

    fn jwk(json: &str) -> Jwk {
        Jwk::from_json(json.as_bytes()).expect("test key")
    }

    fn decrypt_policy() -> DecryptPolicy {
        DecryptPolicy::new(&[KeyMgmtAlg::A128KW], &[ContentEncAlg::A128GCM]).expect("policy")
    }

    fn header(json: &str) -> Header {
        Header::from_json(json.as_bytes()).expect("header")
    }

    /// An HS256 JWS over `claims`, with protected header `{"alg":"HS256"}`.
    fn inner(claims: &str) -> String {
        let mut h = Header::new();
        h.alg = Some("HS256".into());
        let protected = ProtectedHeader::new(h).expect("protected header");
        sign_compact(
            &protected,
            claims.as_bytes(),
            &jwk(OCT_64),
            &SignOptions::new(),
        )
        .expect("JWS")
    }

    fn encryptor(protected: Option<Header>) -> Encryptor {
        let e = Encryptor::new(ContentEncAlg::A128GCM)
            .recipient(Recipient::new(KeyMgmtAlg::A128KW, &jwk(KEK)));
        match protected {
            Some(h) => e.protected_header(h),
            None => e,
        }
    }

    fn nested(claims: &str, protected: &str) -> String {
        encryptor(Some(header(protected)))
            .encrypt_compact(inner(claims).as_bytes())
            .expect("JWE")
    }

    fn run(token: &str) -> Result<VerifiedNestedJwt> {
        let clock = FixedClock(NOW);
        let policy = Policy::new(&clock, &HS256).expect("policy");
        let key = jwk(OCT_64);
        decrypt_nested(
            token,
            &jwk(KEK),
            &decrypt_policy(),
            Keys::One(&key),
            &policy,
        )
    }

    const CLAIMS: &str = r#"{"iss":"joe","sub":"s","exp":1300819380}"#;

    /// The protected header of compact JWE `token`, as sent.
    fn outer_header_of(token: &str) -> Header {
        let first = token.split('.').next().expect("a part");
        let json = crate::util::b64url_decode(first).expect("base64url");
        Header::from_json(&json).expect("header")
    }

    /// RFC 7519 §5.2, §7.1 step 5: `encrypt_nested` adds `cty: "JWT"`,
    /// keeps the caller's other protected parameters, leaves the caller's
    /// encryptor unchanged, and the result decrypts and verifies.
    #[test]
    fn encrypt_nested_adds_cty_jwt_to_a_copy() {
        let jws = inner(CLAIMS);
        for (caller, typ) in [
            (None, None),
            (
                Some(r#"{"typ":"JWT","kid":"k1","x-tenant":"a"}"#),
                Some("JWT"),
            ),
            (Some(r#"{"cty":"JWT"}"#), None),
            (Some(r#"{"cty":"jwt"}"#), None),
            (Some(r#"{"cty":"application/JWT"}"#), None),
        ] {
            let e = encryptor(caller.map(header));
            let before = e.protected().cloned();
            let token = encrypt_nested(&jws, &e).expect("nested JWT");
            assert_eq!(
                e.protected().cloned(),
                before,
                "{caller:?}: caller unchanged"
            );
            let h = outer_header_of(&token);
            // RFC 7519 §5.2: "the value MUST be "JWT"", spelled exactly.
            assert_eq!(h.cty.as_deref(), Some("JWT"), "{caller:?}");
            assert_eq!(h.typ.as_deref(), typ, "{caller:?}");
            if caller.is_some_and(|c| c.contains("kid")) {
                assert_eq!(h.kid.as_deref(), Some("k1"));
                assert!(h.other_params().contains("x-tenant"));
            }
            let v = run(&token).expect("round trip");
            assert_eq!(v.outer_header, h, "{caller:?}");
        }
    }

    /// ADR 0027 §7: a caller `cty` that is not `JWT` under the RFC 7515
    /// §4.1.10 comparison is `InvalidHeader`, not silently overridden.
    #[test]
    fn encrypt_nested_refuses_a_different_caller_cty() {
        let jws = inner(CLAIMS);
        for cty in ["JOSE", "at+jwt", "JWT ", "text/JWT", "application/jose"] {
            let e = encryptor(Some(header(&format!(r#"{{"cty":"{cty}"}}"#))));
            assert!(
                matches!(encrypt_nested(&jws, &e), Err(Error::InvalidHeader(_))),
                "{cty:?}"
            );
        }
    }

    /// RFC 7515 §7.1, ADR 0027 §7: the input must be shaped like a compact
    /// JWS: three parts of base64url characters, non-empty header and
    /// signature parts (RFC 8725 §3.2), and no JSON serialization.
    /// Checked before the `cty`.
    #[test]
    fn encrypt_nested_needs_a_three_part_compact_jws() {
        let jws = inner(CLAIMS);
        let jwe = encrypt_nested(&jws, &encryptor(None)).expect("nested JWT");
        let bad_cty = encryptor(Some(header(r#"{"cty":"JOSE"}"#)));
        for input in [
            "",
            "a",
            "a.b",
            "a.b.c.d",
            jwe.as_str(),
            ".b.c",
            "a.b+.c",
            "a.b.c=",
            "a.b.",
            " a.b.c",
            "{\"payload\":\"x.y.z\"}",
        ] {
            for e in [encryptor(None), bad_cty.clone()] {
                assert!(
                    matches!(encrypt_nested(input, &e), Err(Error::InvalidFormat(_))),
                    "{input:?}"
                );
            }
        }
    }

    /// RFC 7519 §7.2 step 8: the happy path, with the outer protected
    /// header, the recipient index and the inner result.
    #[test]
    fn a_nested_jwt_decrypts_and_verifies() {
        let token = nested(CLAIMS, r#"{"cty":"JWT"}"#);
        let v = run(&token).expect("nested JWT");
        assert_eq!(v.inner.claims.iss.as_deref(), Some("joe"));
        assert_eq!(v.inner.alg, SigningAlg::HS256);
        assert_eq!(v.recipient, 0);
        assert_eq!(v.outer_header.cty.as_deref(), Some("JWT"));
        assert_eq!(v.outer_header.alg.as_deref(), Some("A128KW"));
    }

    /// ADR 0050 §3, ADR 0049 §2 (contract criterion of T09): the outer
    /// check reads `cty`/`typ` from the JWE Protected Header only. A
    /// flattened JWE that 0003's `decrypt_json` accepts, with `cty: JWT`
    /// in its shared unprotected header only, fails N1; so does one with a
    /// protected `cty: JWT` and an unprotected `typ`, since an unprotected
    /// `cty` or `typ` is rejected outright (the header parts are disjoint,
    /// RFC 7516 §5.2 step 4, so `cty` cannot be in both). `decrypt_nested` itself never sees it:
    /// a JWT is compact (ADR 0027 §6), so it is `InvalidFormat`.
    #[test]
    fn an_unprotected_cty_or_typ_fails_the_outer_check() {
        let clock = FixedClock(NOW);
        let policy = Policy::new(&clock, &HS256).expect("policy");
        let cases = [
            (None, r#"{"cty":"JWT"}"#),
            (Some(r#"{"typ":"JWT"}"#), r#"{"cty":"JWT"}"#),
            (Some(r#"{"cty":"JWT"}"#), r#"{"typ":"JWT"}"#),
            (Some(r#"{"cty":"JWT"}"#), r#"{"typ":"at+jwt"}"#),
        ];
        for (protected, shared) in cases {
            let jwe = encryptor(protected.map(header))
                .shared_unprotected_header(header(shared))
                .encrypt_json(inner(CLAIMS).as_bytes(), JsonForm::Flattened)
                .expect("flattened JWE");
            let d = decrypt_json(&jwe, &jwk(KEK), &decrypt_policy()).expect("0003 decrypts");
            assert!(d.shared_header().is_some());
            let empty = Header::new();
            let protected_header = d.protected_header().unwrap_or(&empty);
            assert!(
                matches!(
                    check_outer(
                        protected_header,
                        &[d.shared_header(), d.recipient_header()],
                        &policy
                    ),
                    Err(Error::InvalidHeader(_))
                ),
                "{protected:?} {shared}"
            );
            assert!(matches!(run(&jwe), Err(Error::InvalidFormat(_))));
        }
        // The protected header alone passes: the unprotected rule is what
        // failed above.
        let protected = header(r#"{"alg":"A128KW","enc":"A128GCM","cty":"JWT"}"#);
        assert_eq!(check_outer(&protected, &[None, None], &policy), Ok(()));
    }

    /// RFC 7519 §5.3, ADR 0027 §7 (N2): a replicated `iss`, `sub` or
    /// `aud` must be JSON-equal to the inner claim; the form matters, and
    /// an outer claim the inner Claims Set lacks is a mismatch.
    #[test]
    fn replicated_claims_must_be_json_equal() {
        let claims = Claims::from_json(br#"{"iss":"joe","sub":"s","aud":"a"}"#).expect("claims");
        let many = Claims::from_json(br#"{"aud":["a","b"]}"#).expect("claims");
        let ok = [
            (r#"{}"#, &claims),
            (r#"{"iss":"joe"}"#, &claims),
            (r#"{"iss":"joe","sub":"s","aud":"a"}"#, &claims),
            (r#"{"aud":["a","b"]}"#, &many),
            (r#"{"jti":"x","x-other":1}"#, &claims),
        ];
        for (h, c) in ok {
            assert_eq!(check_replicated_claims(&header(h), c), Ok(()), "{h}");
        }
        let bad = [
            (r#"{"iss":"Joe"}"#, &claims, "iss"),
            (r#"{"iss":null}"#, &claims, "iss"),
            (r#"{"iss":["joe"]}"#, &claims, "iss"),
            (r#"{"sub":"t"}"#, &claims, "sub"),
            (r#"{"iss":"joe","sub":1}"#, &claims, "sub"),
            (r#"{"aud":["a"]}"#, &claims, "aud"),
            (r#"{"aud":"a"}"#, &many, "aud"),
            (r#"{"aud":["b","a"]}"#, &many, "aud"),
            (r#"{"iss":"joe"}"#, &many, "iss"),
        ];
        for (h, c, name) in bad {
            assert_eq!(
                check_replicated_claims(&header(h), c),
                Err(Error::InvalidClaim(name)),
                "{h}"
            );
        }
    }

    /// ADR 0027 §6: a JSON serialization is `InvalidFormat`, whatever the
    /// count of `.` in it, before 0003's compact parser could call a part
    /// non-base64url.
    #[test]
    fn a_json_serialization_is_invalid_format() {
        for token in [
            "{}",
            " \t\r\n{\"protected\":\"a.b.c.d\"}",
            "{\"a\":\"x.y.z.w.v\"}",
        ] {
            assert!(
                matches!(run(token), Err(Error::InvalidFormat(_))),
                "{token:?}"
            );
        }
    }

    /// The inner plaintext must be a compact JWS: bytes that are not UTF-8
    /// cannot be one (RFC 7515 §7.1, ADR 0027 §7).
    #[test]
    fn a_non_utf8_inner_plaintext_is_invalid_format() {
        let token = encryptor(Some(header(r#"{"cty":"JWT"}"#)))
            .encrypt_compact(b"\xff.\xfe.\xfd")
            .expect("JWE");
        assert!(matches!(run(&token), Err(Error::InvalidFormat(_))));
    }
}
