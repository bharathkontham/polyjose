//! The JWE processing rules of RFC 7516 §5.1 (encrypt) and §5.2 (decrypt)
//! over [`JweParts`], independent of the serialization.
//!
//! `compact` (RFC 7516 §7.1) and `json` (§7.2) only convert between their
//! text and [`JweParts`]; both call [`parse_protected`] for the protected
//! header. Everything else lives here, so the serializations cannot drift
//! apart:
//!
//! - the JOSE Header of each recipient, the union of the protected, shared
//!   and per-recipient headers, which must be disjoint ([`jose_header`],
//!   §5.2 step 4, §7.2.1);
//! - the `crit` check (§5.2 step 5), the support check, the allow-list and
//!   key binding, in the plan.md order;
//! - recipient selection and the uniform [`Error::DecryptionFailed`] once
//!   key management starts (§5.2 steps 6–18, §11.4–§11.5);
//! - on encrypt, header placement, the RNG draw order (`jwe::random`) and
//!   the `insecure-test-vectors` protected-header hook.
//!
//! # How a key management family plugs in
//!
//! Through `keymgmt::encrypt_key` / `keymgmt::decrypt_key` only. On
//! encrypt, the family returns its header parameters (`epk`, `iv`, `tag`,
//! `p2s`, `p2c`, `apu`, `apv`) in `KeyOutput::header_params`; this file
//! places them, next to `alg`, in the protected header (compact,
//! flattened, and the direct modes in every form, ADR 0050 §1) or in the
//! recipient's header (general JSON). On decrypt the
//! family receives the recipient's JOSE Header (the union) and reads its
//! parameters there; any error it returns becomes `DecryptionFailed`.
//!
//! # `zip`
//!
//! `zip: "DEF"` is accepted only with the `deflate` feature (anything else
//! is [`Error::UnsupportedAlgorithm`] before any cryptography) and only in
//! the protected header (RFC 7516 §4.1.3). The codec is `jwe::zip`:
//! `compress` before encryption (§5.1 step 11), `decompress` after the tag
//! verified (§5.2 step 17), bounded by `max_decompressed_len`.

use std::collections::BTreeSet;

use zeroize::Zeroizing;

use super::api::{DecryptPolicy, Decrypted, Encryptor, JsonForm, Serialization};
use super::content::{self, Cek};
use super::key::{Direction, RecipientKey, kid_matches};
use super::keymgmt;
use super::random::RandomSource;
use super::zip;
use crate::header::Header;
use crate::json::{self, Object, Value};
use crate::jwa::{ContentEncAlg, KeyMgmtAlg};
use crate::jwk::Jwk;
use crate::util::{b64url_decode, b64url_encode};
use crate::{Error, Result};

/// One recipient's part of a JWE (RFC 7516 §7.2.1 `recipients`).
#[derive(Debug, Clone, Default)]
pub(crate) struct RecipientParts {
    /// The per-recipient unprotected header (`header`), if any.
    pub(crate) header: Option<Header>,
    /// The JWE Encrypted Key (`encrypted_key`), decoded; empty for `dir`
    /// and ECDH-ES.
    pub(crate) encrypted_key: Vec<u8>,
}

/// A JWE with its parts decoded, whatever its serialization (RFC 7516 §3).
#[derive(Debug, Clone, Default)]
pub(crate) struct JweParts {
    /// The JWE Protected Header exactly as received or produced, base64url
    /// encoded: the AAD is computed over these bytes, never over a
    /// re-serialization (RFC 7516 §5.2 steps 14–15, erratum 8676). Empty
    /// when a JSON JWE has no protected header.
    pub(crate) protected_b64: String,
    /// The JWE Protected Header, parsed.
    pub(crate) protected: Option<Header>,
    /// The JWE Shared Unprotected Header (`unprotected`), JSON only.
    pub(crate) shared: Option<Header>,
    /// The recipients, in order: exactly one for compact (RFC 7516 §7.1).
    pub(crate) recipients: Vec<RecipientParts>,
    /// The JWE Initialization Vector, decoded.
    pub(crate) iv: Vec<u8>,
    /// The JWE Ciphertext, decoded.
    pub(crate) ciphertext: Vec<u8>,
    /// The JWE Authentication Tag, decoded.
    pub(crate) tag: Vec<u8>,
    /// The JWE AAD (`aad`), decoded, JSON only.
    pub(crate) aad: Option<Vec<u8>>,
}

/// The only `zip` value defined (RFC 7516 §4.1.3, RFC 7518 §7.3): raw
/// DEFLATE (RFC 1951).
const ZIP_DEFLATE: &str = "DEF";

/// The header parameters polyjose sets itself on encrypt: `alg`, `enc` and
/// `zip` (RFC 7516 §4.1.1–§4.1.3) and the key management parameters
/// (RFC 7518 §4.6.1, §4.7.1, §4.8.1). A caller-supplied header holding one
/// of them is refused, so the output never carries a value polyjose did
/// not compute.
const SET_BY_POLYJOSE: &[&str] = &[
    "alg", "enc", "zip", "epk", "apu", "apv", "iv", "tag", "p2s", "p2c",
];

/// Parses a decoded JWE Protected Header (RFC 7516 §5.2 step 3: "a
/// UTF-8-encoded representation of a completely valid JSON object").
///
/// # Errors
///
/// [`Error::InvalidJson`] for bytes that are not an I-JSON object: a
/// syntax error, a duplicate member name at any depth (ADR 0041 §1), the
/// JSON limits, or valid JSON that is not an object (`[1]`, `""`), as for
/// JWS (ADR 0026 §2 step 4); [`Error::InvalidHeader`] for a registered
/// parameter of the wrong type (plan.md error contract, steps 3–4).
pub(crate) fn parse_protected(json: &[u8]) -> Result<Header> {
    let object = json::parse(json)?
        .into_object()
        .ok_or(Error::InvalidJson("protected header must be a JSON object"))?;
    Header::from_object(object)
}

/// The JOSE Header of one recipient (RFC 7516 §5.2 step 4): the union of
/// the JWE Protected Header, the JWE Shared Unprotected Header and the
/// recipient's Per-Recipient Unprotected Header, with the structural rules
/// that need to know where each member came from.
///
/// # Errors
///
/// [`Error::InvalidHeader`] if:
/// - two of the parts share a name (§5.2 step 4: the same name "MUST NOT
///   occur in distinct JSON object values"; §7.2.1: "MUST be disjoint");
/// - `crit` is outside the protected header (RFC 7516 §4.1.13, RFC 7515
///   §4.1.11: it "MUST be integrity protected");
/// - `zip` is outside the protected header (RFC 7516 §4.1.3: it "MUST be
///   integrity protected; therefore, it MUST occur only within the JWE
///   Protected Header");
/// - `crit` is malformed or lists an absent parameter
///   ([`Header::validate_crit`]).
fn jose_header(
    protected: Option<&Header>,
    shared: Option<&Header>,
    recipient: Option<&Header>,
) -> Result<Header> {
    for unprotected in [shared, recipient].into_iter().flatten() {
        if unprotected.crit.is_some() {
            return Err(Error::InvalidHeader("crit must be in the protected header"));
        }
        if unprotected.zip.is_some() {
            return Err(Error::InvalidHeader("zip must be in the protected header"));
        }
    }
    let mut names = BTreeSet::new();
    let mut members = Vec::new();
    for part in [protected, shared, recipient].into_iter().flatten() {
        for (name, value) in part.to_object()? {
            if !names.insert(name.as_str().to_owned()) {
                return Err(Error::InvalidHeader(
                    "header parameter occurs in more than one header",
                ));
            }
            members.push((name, value));
        }
    }
    // Each part's names are unique, and the parts are disjoint.
    let union = Header::from_object(Object::from_unique_members(members))?;
    union.validate_crit()?;
    Ok(union)
}

/// For a direct mode, `dir` (RFC 7518 §4.5) or `ECDH-ES` Direct Key
/// Agreement (RFC 7518 §4.6), requires `alg` **and** `enc` in the JWE
/// Protected Header (ADR 0050 §1).
///
/// RFC 7516 §5.2 step 4 lets `alg` and `enc` sit in any of the three
/// headers, but A*GCMKW wraps the CEK with AES-GCM under an **empty** AAD
/// (RFC 7518 §4.7), and a JSON JWE with no protected header and no `aad`
/// has the content AAD `""` too (RFC 7516 §5.1 step 14). A GCMKW
/// recipient's (`iv`, `encrypted_key`, `tag`) would then decrypt as a
/// `dir` ciphertext under an alg-less key, to the victim's CEK (security
/// audit B1). With `alg` and `enc` protected, a direct message's content
/// AAD is never empty, and the mode itself is integrity protected. Direct
/// modes have exactly one recipient (RFC 7516 §5.1 steps 5–6), so no
/// multi-recipient layout is lost; the non-direct modes are unaffected.
///
/// Runs in step 4, before any cryptographic operation, for compact and
/// JSON alike (a compact header is always protected, RFC 7516 §7.1).
///
/// # Errors
///
/// [`Error::InvalidHeader`] if `union`'s `alg` is a direct mode and the
/// protected header lacks `alg` or `enc`.
fn check_direct_protected(union: &Header, protected: Option<&Header>) -> Result<()> {
    let alg = KeyMgmtAlg::from(union.alg.as_deref().unwrap_or_default());
    let direct = matches!(
        keymgmt::mode(&alg),
        Some(keymgmt::Mode::DirectEncryption | keymgmt::Mode::DirectAgreement)
    );
    let protected_alg_and_enc = protected.is_some_and(|p| p.alg.is_some() && p.enc.is_some());
    if direct && !protected_alg_and_enc {
        return Err(Error::InvalidHeader(
            "dir and ECDH-ES need alg and enc in the protected header",
        ));
    }
    Ok(())
}

/// The JOSE Header of every recipient, after RFC 7516 §5.2 steps 4–5:
/// structure ([`jose_header`]), `alg` and `enc` present (§4.1.1–§4.1.2),
/// for a direct mode both protected ([`check_direct_protected`], ADR 0050
/// §1), one `enc` for the one ciphertext, and every `crit` name understood.
///
/// # Errors
///
/// [`Error::InvalidFormat`] for no recipients or more than
/// `max_recipients` (ADR 0026 §7); [`Error::InvalidHeader`] as
/// [`jose_header`], for a missing `alg` or `enc`, a direct mode whose
/// `alg` or `enc` is unprotected, or recipients that disagree on `enc`;
/// [`Error::UnknownCritical`] for a `crit` name not in the policy's
/// `understood_crit` (§4.1.13).
fn jose_headers(parts: &JweParts, policy: &DecryptPolicy) -> Result<Vec<Header>> {
    if parts.recipients.is_empty() {
        return Err(Error::InvalidFormat("JWE has no recipients"));
    }
    if parts.recipients.len() > policy.max_recipients {
        return Err(Error::InvalidFormat("JWE exceeds max_recipients"));
    }
    let mut unions = Vec::with_capacity(parts.recipients.len());
    for recipient in &parts.recipients {
        let union = jose_header(
            parts.protected.as_ref(),
            parts.shared.as_ref(),
            recipient.header.as_ref(),
        )?;
        if union.alg.is_none() {
            return Err(Error::InvalidHeader("missing alg"));
        }
        if union.enc.is_none() {
            return Err(Error::InvalidHeader("missing enc"));
        }
        check_direct_protected(&union, parts.protected.as_ref())?;
        unions.push(union);
    }
    if unions.iter().any(|u| u.enc != unions[0].enc) {
        return Err(Error::InvalidHeader("recipients disagree on enc"));
    }
    let understood: Vec<&str> = policy.understood_crit.iter().map(String::as_str).collect();
    for union in &unions {
        union.validate_crit_understood(&understood)?;
    }
    Ok(unions)
}

/// Whether `zip`, if present, can be processed (RFC 7516 §4.1.3, §5.2 step
/// 5): only `DEF`, and only with the `deflate` feature (ADR 0017).
///
/// # Errors
///
/// [`Error::UnsupportedAlgorithm`] otherwise.
fn check_zip(zip: Option<&str>) -> Result<bool> {
    match zip {
        None => Ok(false),
        Some(ZIP_DEFLATE) if cfg!(feature = "deflate") => Ok(true),
        Some(_) => Err(Error::UnsupportedAlgorithm),
    }
}

/// How a recipient that is not a candidate ranks, for the error reported
/// when no recipient is (plan.md recipient selection):
/// `AlgorithmNotAllowed` > `UnsupportedAlgorithm` > `KeyAlgorithmMismatch`
/// (and any other key binding error, and a `kid` mismatch).
fn rank(error: &Error) -> u8 {
    match error {
        Error::AlgorithmNotAllowed => 3,
        Error::UnsupportedAlgorithm => 2,
        _ => 1,
    }
}

/// Decides whether one recipient is a candidate for `key` (plan.md
/// recipient selection), in the order of the error contract:
///
/// 1. **support**: `alg` is implemented for decryption (`keymgmt::supported`:
///    not `RSA-OAEP-256`, ADR 0021; not `RSA-OAEP` or `RSA1_5`, ADRs 0021,
///    0022) → else [`Error::UnsupportedAlgorithm`];
/// 2. **allow-list**: `alg` and `enc` are in the policy (RFC 8725 §3.1,
///    RFC 7516 §5.2 last paragraph) → else [`Error::AlgorithmNotAllowed`];
/// 3. **key binding**: [`RecipientKey::from_jwk`] (RFC 7516 §5.2 step 7,
///    §11.4: "restricting the use of a key to a limited set of
///    algorithms") → else its error, [`Error::KeyAlgorithmMismatch`];
/// 4. **`kid`**: when both the header and the key carry one, they are
///    equal (RFC 7516 §4.1.6) → else [`Error::KeyAlgorithmMismatch`].
///
/// `enc` is already known to be supported.
fn candidate(
    header: &Header,
    enc: &ContentEncAlg,
    key: &Jwk,
    policy: &DecryptPolicy,
) -> Result<(KeyMgmtAlg, RecipientKey)> {
    let alg = KeyMgmtAlg::from(header.alg.as_deref().unwrap_or_default());
    if !keymgmt::supported(&alg, Direction::Decrypt) {
        return Err(Error::UnsupportedAlgorithm);
    }
    if !policy.allowed_algs.contains(&alg) || !policy.allowed_enc.contains(enc) {
        return Err(Error::AlgorithmNotAllowed);
    }
    let recipient_key = RecipientKey::from_jwk(key, &alg, enc, Direction::Decrypt)?;
    if !kid_matches(key, header.kid.as_deref()) {
        return Err(Error::KeyAlgorithmMismatch);
    }
    Ok((alg, recipient_key))
}

/// RFC 7516 §5.2 steps 6–17 for one candidate recipient: key management,
/// then content decryption over the received protected header, then
/// decompression. Every failure is [`Error::DecryptionFailed`], whatever
/// its cause (§11.4: "report all formatting errors to the CEK, Additional
/// Authenticated Data, or ciphertext as a single error"; §11.5).
#[allow(
    clippy::too_many_arguments,
    reason = "one candidate recipient and the message parts it is tried against"
)]
fn decrypt_recipient(
    alg: &KeyMgmtAlg,
    key: &RecipientKey,
    enc: &ContentEncAlg,
    header: &Header,
    encrypted_key: &[u8],
    parts: &JweParts,
    aad: &[u8],
    inflate: bool,
    policy: &DecryptPolicy,
) -> Result<Zeroizing<Vec<u8>>> {
    let failed = |_| Error::DecryptionFailed;
    let cek = keymgmt::decrypt_key(alg, key, enc, header, encrypted_key, policy).map_err(failed)?;
    let plaintext = content::decrypt(enc, &cek, &parts.iv, aad, &parts.ciphertext, &parts.tag)
        .map_err(failed)?;
    if inflate {
        zip::decompress(&plaintext, policy.max_decompressed_len).map_err(failed)
    } else {
        Ok(plaintext)
    }
}

/// Decrypts `parts` with `key` under `policy` (RFC 7516 §5.2), trying each
/// candidate recipient in order; the first that decrypts wins (§5.2 step
/// 18: at least one must).
///
/// The checks run in the plan.md order, each over every recipient before
/// the next:
///
/// 1. the recipient count (ADR 0026 §7), then steps 4–5 for every
///    recipient ([`jose_headers`]);
/// 2. `enc` and `zip` supported: they are shared by all recipients, so a
///    failure here is immediate ([`Error::UnsupportedAlgorithm`]);
/// 3. per recipient: `alg` supported, then allowed, then the key binding
///    and `kid` ([`candidate`]);
/// 4. key management and content decryption for each candidate in order
///    (steps 6–17), over the protected header **as received** (steps
///    14–15).
///
/// # Errors
///
/// The errors of the steps above. With no candidate, the best-ranked
/// recipient error: [`Error::AlgorithmNotAllowed`], then
/// [`Error::UnsupportedAlgorithm`], then [`Error::KeyAlgorithmMismatch`].
/// When every candidate fails, [`Error::DecryptionFailed`], a unit value
/// with no detail and no source, whatever the cause.
pub(crate) fn decrypt(parts: JweParts, key: &Jwk, policy: &DecryptPolicy) -> Result<Decrypted> {
    let headers = jose_headers(&parts, policy)?;
    let enc = headers[0].content_enc_alg()?;
    let inflate = check_zip(parts.protected.as_ref().and_then(|p| p.zip.as_deref()))?;

    let mut best: Option<Error> = None;
    let mut candidates = Vec::new();
    for (index, header) in headers.iter().enumerate() {
        match candidate(header, &enc, key, policy) {
            Ok((alg, recipient_key)) => candidates.push((index, alg, recipient_key)),
            Err(e) => {
                if best.as_ref().is_none_or(|b| rank(&e) > rank(b)) {
                    best = Some(e);
                }
            }
        }
    }
    if candidates.is_empty() {
        return Err(best.unwrap_or(Error::DecryptionFailed));
    }

    let aad = content::aad(&parts.protected_b64, parts.aad.as_deref());
    for (index, alg, recipient_key) in &candidates {
        let header = &headers[*index];
        let recipient = &parts.recipients[*index];
        let result = decrypt_recipient(
            alg,
            recipient_key,
            &enc,
            header,
            &recipient.encrypted_key,
            &parts,
            &aad,
            inflate,
            policy,
        );
        if let Ok(plaintext) = result {
            let index = *index;
            let mut parts = parts;
            let mut headers = headers;
            return Ok(Decrypted {
                plaintext,
                protected_header: parts.protected.take(),
                shared_header: parts.shared.take(),
                recipient_header: parts.recipients.swap_remove(index).header,
                header: headers.swap_remove(index),
                aad: parts.aad.take(),
                recipient: index,
            });
        }
    }
    Err(Error::DecryptionFailed)
}

/// Refuses a caller-supplied header that holds a parameter polyjose sets
/// itself ([`SET_BY_POLYJOSE`]).
///
/// # Errors
///
/// [`Error::InvalidHeader`].
fn check_caller_header(header: Option<&Header>) -> Result<()> {
    match header {
        Some(h) if SET_BY_POLYJOSE.iter().any(|name| h.contains(name)) => Err(
            Error::InvalidHeader("alg, enc, zip and key management parameters are set by polyjose"),
        ),
        _ => Ok(()),
    }
}

/// `header` with `alg` and a family's header parameters added (RFC 7516
/// §5.1 step 8 places them; RFC 7518 §4.6.1, §4.7.1, §4.8.1 define them).
///
/// # Errors
///
/// [`Error::InvalidHeader`] if a name is already present (a family broke
/// its contract) or a parameter has the wrong type.
fn with_key_params(header: &Header, alg: &KeyMgmtAlg, params: Object) -> Result<Header> {
    let mut object = header.to_object()?;
    for (name, value) in [(Zeroizing::new("alg".to_owned()), Value::from(alg.as_str()))]
        .into_iter()
        .chain(params)
    {
        if object.contains(&name) {
            return Err(Error::InvalidHeader(
                "header parameter occurs in more than one header",
            ));
        }
        object.insert(name.as_str(), value);
    }
    Header::from_object(object)
}

/// The `insecure-test-vectors` hook: `given` is used verbatim only if it
/// decodes to a JSON object equal to `built` (member order aside,
/// RFC 8259 §4), so a test can never make polyjose emit a header it would
/// not have produced.
///
/// # Errors
///
/// [`Error::InvalidFormat`] if `given` is not strict base64url of a JSON
/// object equal to `built`.
fn check_reproducible(given: &str, built: &Header) -> Result<()> {
    let mismatch = Error::InvalidFormat("protected header does not match the built header");
    let bytes = b64url_decode(given).map_err(|_| mismatch.clone())?;
    let value = json::parse(&bytes).map_err(|_| mismatch.clone())?;
    if value == Value::from(built.to_object()?) {
        Ok(())
    } else {
        Err(mismatch)
    }
}

/// Encrypts `plaintext` for the recipients of `encryptor` (RFC 7516 §5.1),
/// placing the header parameters as `form` requires, with the random values
/// drawn from `rng` in the documented order (`jwe::random`).
///
/// Every check runs before anything is drawn from `rng`:
///
/// 1. the request fits `form` → [`Error::InvalidFormat`]: at least one
///    recipient; compact has exactly one, no AAD and no unprotected header
///    (§7.1); flattened has exactly one (§7.2.2); `dir` and ECDH-ES have no
///    other recipient (they determine the CEK, §5.1 steps 5–6);
/// 2. the caller's headers → [`Error::InvalidHeader`]: none sets a
///    parameter polyjose sets ([`SET_BY_POLYJOSE`]), they are disjoint and
///    `crit` is well formed and protected ([`jose_header`]);
/// 3. `enc` and every `alg` implemented for encryption →
///    [`Error::UnsupportedAlgorithm`] (`RSA-OAEP` and `RSA1_5` are not,
///    ADRs 0021, 0022);
/// 4. every key bound to its `alg` ([`RecipientKey::from_jwk`]) →
///    [`Error::KeyAlgorithmMismatch`] or [`Error::InvalidKey`].
///
/// Then: the random CEK when the modes need one (§5.1 step 2), key
/// management for each recipient in order (steps 3–8), the protected header
/// and its encoding (step 13), the content IV (step 9), compression if
/// asked for (step 11), and content encryption over the encoded protected
/// header (steps 14–15).
///
/// `enc` (and `zip`) always go in the protected header. For compact and
/// flattened output each recipient's `alg` and key management parameters
/// do too; for general JSON they go in the recipient's header (as RFC 7520
/// §5.13), except for the direct modes, `dir` and ECDH-ES, whose one
/// recipient's `alg` and parameters are protected in every form (ADR 0050
/// §1), leaving its `recipients` entry without them.
///
/// `protected_b64` is the `insecure-test-vectors` hook
/// ([`check_reproducible`]).
///
/// # Errors
///
/// As listed above; [`Error::RandomnessUnavailable`] if `rng` fails;
/// [`Error::InvalidFormat`] if `protected_b64` does not match.
pub(crate) fn encrypt(
    encryptor: &Encryptor,
    plaintext: &[u8],
    form: Serialization,
    rng: &mut dyn RandomSource,
    protected_b64: Option<&str>,
) -> Result<JweParts> {
    let recipients = &encryptor.recipients;
    let enc = &encryptor.enc;
    match form {
        _ if recipients.is_empty() => {
            return Err(Error::InvalidFormat("JWE needs at least one recipient"));
        }
        Serialization::Compact => {
            if recipients.len() != 1 {
                return Err(Error::InvalidFormat(
                    "compact JWE must have exactly one recipient",
                ));
            }
            if encryptor.aad.is_some() {
                return Err(Error::InvalidFormat("compact JWE cannot carry a JWE AAD"));
            }
            if encryptor.shared.is_some() || recipients[0].header.is_some() {
                return Err(Error::InvalidFormat(
                    "compact JWE cannot carry an unprotected header",
                ));
            }
        }
        Serialization::Json(JsonForm::Flattened) if recipients.len() != 1 => {
            return Err(Error::InvalidFormat(
                "flattened JWE must have exactly one recipient",
            ));
        }
        Serialization::Json(_) => {}
    }

    // RFC 7516 §4.1.1-§4.1.2: what polyjose implements.
    enc.ensure_known()?;
    let mut modes = Vec::with_capacity(recipients.len());
    for recipient in recipients {
        if !keymgmt::supported(&recipient.alg, Direction::Encrypt) {
            return Err(Error::UnsupportedAlgorithm);
        }
        modes.push(keymgmt::mode(&recipient.alg).ok_or(Error::UnsupportedAlgorithm)?);
    }
    let random_cek = modes.iter().all(|m| m.has_random_cek());
    if !random_cek && recipients.len() > 1 {
        return Err(Error::InvalidFormat(
            "dir and ECDH-ES allow only one recipient",
        ));
    }

    // The caller's headers, with what polyjose adds to every message.
    check_caller_header(encryptor.protected.as_ref())?;
    check_caller_header(encryptor.shared.as_ref())?;
    let mut protected = encryptor.protected.clone().unwrap_or_default();
    protected.enc = Some(enc.clone());
    if encryptor.compress {
        protected.zip = Some(ZIP_DEFLATE.to_owned());
    }
    for recipient in recipients {
        check_caller_header(recipient.header.as_ref())?;
        jose_header(
            Some(&protected),
            encryptor.shared.as_ref(),
            recipient.header.as_ref(),
        )?;
    }

    let mut keys = Vec::with_capacity(recipients.len());
    for recipient in recipients {
        keys.push(RecipientKey::from_jwk(
            &recipient.key,
            &recipient.alg,
            enc,
            Direction::Encrypt,
        )?);
    }

    // Draw 1 (§5.1 step 2): the CEK, once, when the modes wrap or encrypt
    // one.
    let mut cek: Option<Cek> = if random_cek {
        Some(content::generate_cek(enc, rng)?)
    } else {
        None
    };
    // Draw 2 (§5.1 steps 3-8): each recipient's key management, in order.
    let general = form == Serialization::Json(JsonForm::General);
    let mut out_recipients = Vec::with_capacity(recipients.len());
    for ((recipient, key), mode) in recipients.iter().zip(&keys).zip(&modes) {
        let given = if random_cek { cek.as_ref() } else { None };
        let output =
            keymgmt::encrypt_key(&recipient.alg, key, enc, given, &recipient.options, rng)?;
        match (output.cek, mode.has_random_cek()) {
            (Some(determined), false) => cek = Some(determined),
            (None, true) => {}
            // A family broke the `KeyOutput` contract: fail closed.
            _ => return Err(Error::UnsupportedAlgorithm),
        }
        // A direct mode's `alg` and parameters are protected in every form
        // (ADR 0050 §1): it has the only recipient, so the general form
        // loses nothing, and decrypt requires it (`check_direct_protected`).
        let header = if general && mode.has_random_cek() {
            let base = recipient.header.clone().unwrap_or_default();
            Some(with_key_params(
                &base,
                &recipient.alg,
                output.header_params,
            )?)
        } else {
            protected = with_key_params(&protected, &recipient.alg, output.header_params)?;
            recipient.header.clone()
        };
        out_recipients.push(RecipientParts {
            header,
            encrypted_key: output.encrypted_key,
        });
    }
    let cek = cek.ok_or(Error::UnsupportedAlgorithm)?;
    for recipient in &out_recipients {
        jose_header(
            Some(&protected),
            encryptor.shared.as_ref(),
            recipient.header.as_ref(),
        )?;
    }

    // §5.1 step 13: the Encoded Protected Header, which the AAD covers.
    let protected_b64 = match protected_b64 {
        Some(given) => {
            check_reproducible(given, &protected)?;
            given.to_owned()
        }
        None => b64url_encode(protected.to_json()?.as_bytes()),
    };
    // Draw 3 (§5.1 step 9): the content IV.
    let iv = content::generate_iv(enc, rng)?;
    // §5.1 step 11: compress the plaintext if `zip` is set.
    let compressed;
    let plaintext = if encryptor.compress {
        compressed = zip::compress(plaintext)?;
        compressed.as_slice()
    } else {
        plaintext
    };
    // §5.1 steps 14-15.
    let aad = content::aad(&protected_b64, encryptor.aad.as_deref());
    let (ciphertext, tag) = content::encrypt(enc, &cek, &iv, &aad, plaintext)?;
    Ok(JweParts {
        protected_b64,
        protected: Some(protected),
        shared: encryptor.shared.clone(),
        recipients: out_recipients,
        iv,
        ciphertext,
        tag,
        aad: encryptor.aad.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwe::api::Recipient;
    use crate::jwe::random::OsRandom;
    use crate::rng::insecure_test_vectors::FixedRng;

    use KeyMgmtAlg as A;

    fn oct(bytes: &[u8], extra: &str) -> Jwk {
        let json = format!(r#"{{"kty":"oct","k":"{}"{extra}}}"#, b64url_encode(bytes));
        Jwk::from_json(json.as_bytes()).unwrap_or_else(|e| panic!("{e}"))
    }

    fn header(json: &str) -> Header {
        Header::from_json(json.as_bytes()).unwrap_or_else(|e| panic!("{json}: {e}"))
    }

    fn policy(algs: &[KeyMgmtAlg]) -> DecryptPolicy {
        DecryptPolicy::new(algs, &[ContentEncAlg::A128GCM]).unwrap_or_else(|e| panic!("{e}"))
    }

    fn code<T>(result: Result<T>) -> &'static str {
        match result {
            Ok(_) => "ok",
            Err(e) => e.code(),
        }
    }

    /// A general-form JWE (the JSON shape is T14's; `core` only needs the
    /// parts) to one A128KW recipient per key, in order.
    fn general(keys: &[&Jwk]) -> JweParts {
        let mut e = Encryptor::new(ContentEncAlg::A128GCM);
        for key in keys {
            e = e.recipient(Recipient::new(A::A128KW, key));
        }
        let form = Serialization::Json(JsonForm::General);
        encrypt(&e, b"hello", form, &mut OsRandom, None).unwrap_or_else(|e| panic!("{e}"))
    }

    fn rheader(parts: &mut JweParts, index: usize) -> &mut Header {
        parts.recipients[index]
            .header
            .as_mut()
            .unwrap_or_else(|| panic!("no header"))
    }

    fn pheader(parts: &mut JweParts) -> &mut Header {
        parts
            .protected
            .as_mut()
            .unwrap_or_else(|| panic!("no protected header"))
    }

    /// Replaces the protected header, keeping the parts consistent: the
    /// encoding (the AAD) changes with it, as it would on the wire.
    fn reprotect(parts: &mut JweParts, json: &str) {
        parts.protected = Some(header(json));
        parts.protected_b64 = b64url_encode(json.as_bytes());
    }

    fn set_alg(parts: &mut JweParts, index: usize, alg: &str) {
        rheader(parts, index).alg = Some(alg.to_owned());
    }

    #[test]
    fn protected_header_parsing_follows_the_error_contract() {
        assert_eq!(
            code(parse_protected(br#"{"alg":"dir","enc":"A128GCM"}"#)),
            "ok"
        );
        assert_eq!(code(parse_protected(b"")), "InvalidJson");
        assert_eq!(code(parse_protected(br#"{"a":1,"a":2}"#)), "InvalidJson");
        assert_eq!(
            code(parse_protected(br#"{"x":{"a":1,"a":2}}"#)),
            "InvalidJson"
        );
        assert_eq!(code(parse_protected(b"[]")), "InvalidJson");
        assert_eq!(code(parse_protected(b"\"\"")), "InvalidJson");
        assert_eq!(code(parse_protected(br#"{"enc":7}"#)), "InvalidHeader");
    }

    #[test]
    fn the_jose_header_is_the_union_of_three_disjoint_parts() {
        // RFC 7516 §5.2 step 4, §7.2.1.
        let p = header(r#"{"enc":"A128GCM"}"#);
        let s = header(r#"{"jku":"https://example.com/k"}"#);
        let r = header(r#"{"alg":"A128KW","kid":"k1"}"#);
        let union = jose_header(Some(&p), Some(&s), Some(&r)).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(union.alg.as_deref(), Some("A128KW"));
        assert_eq!(union.enc, Some(ContentEncAlg::A128GCM));
        assert_eq!(union.kid.as_deref(), Some("k1"));
        assert!(union.jku.is_some());
        assert_eq!(code(jose_header(None, None, None)), "ok");

        let dup = header(r#"{"kid":"k1"}"#);
        for (a, b, c) in [
            (Some(&r), None, Some(&dup)),
            (Some(&dup), Some(&dup), None),
            (None, Some(&r), Some(&r)),
        ] {
            assert_eq!(code(jose_header(a, b, c)), "InvalidHeader");
        }
        let private = header(r#"{"x-a":1}"#);
        assert_eq!(
            code(jose_header(Some(&private), Some(&private), None)),
            "InvalidHeader"
        );
    }

    #[test]
    fn crit_and_zip_must_be_protected() {
        // RFC 7516 §4.1.13 (RFC 7515 §4.1.11) and §4.1.3.
        let crit = header(r#"{"crit":["x-a"],"x-a":1}"#);
        let zip = header(r#"{"zip":"DEF"}"#);
        assert_eq!(code(jose_header(Some(&crit), None, None)), "ok");
        assert_eq!(code(jose_header(Some(&zip), None, None)), "ok");
        for h in [&crit, &zip] {
            assert_eq!(code(jose_header(None, Some(h), None)), "InvalidHeader");
            assert_eq!(code(jose_header(None, None, Some(h))), "InvalidHeader");
        }
        // crit naming a parameter absent from the union.
        let absent = header(r#"{"crit":["x-b"]}"#);
        assert_eq!(
            code(jose_header(Some(&absent), None, None)),
            "InvalidHeader"
        );
        // ...which may be present in another part of the union.
        let elsewhere = header(r#"{"x-b":true}"#);
        assert_eq!(
            code(jose_header(Some(&absent), Some(&elsewhere), None)),
            "ok"
        );
    }

    #[test]
    fn steps_4_and_5_run_over_every_recipient() {
        let key = oct(&[1; 16], "");
        let p = policy(&[A::A128KW]);
        let base = general(&[&key, &key]);

        let mut no_alg = base.clone();
        rheader(&mut no_alg, 1).alg = None;
        assert_eq!(code(decrypt(no_alg, &key, &p)), "InvalidHeader");

        let mut no_enc = base.clone();
        pheader(&mut no_enc).enc = None;
        assert_eq!(code(decrypt(no_enc, &key, &p)), "InvalidHeader");

        // One ciphertext, one enc (T14: "enc must be the same for all").
        let mut two_encs = base.clone();
        let moved = pheader(&mut two_encs).enc.take();
        rheader(&mut two_encs, 0).enc = moved;
        rheader(&mut two_encs, 1).enc = Some(ContentEncAlg::A256GCM);
        assert_eq!(code(decrypt(two_encs, &key, &p)), "InvalidHeader");

        // An alg in both the protected and a recipient header.
        let mut both = base.clone();
        pheader(&mut both).alg = Some("A128KW".to_owned());
        assert_eq!(code(decrypt(both, &key, &p)), "InvalidHeader");

        // Unknown crit in the protected header: UnknownCritical unless
        // understood; the second recipient's alg is unsupported but step 5
        // comes first.
        let mut crit = base.clone();
        reprotect(&mut crit, r#"{"enc":"A128GCM","crit":["x-a"],"x-a":1}"#);
        set_alg(&mut crit, 1, "RSA1_5");
        assert_eq!(code(decrypt(crit.clone(), &key, &p)), "UnknownCritical");
        let understood = p.clone().understood_crit(&["x-a"]);
        // Understood: processing goes on (and fails the tag, since the
        // protected header changed).
        assert_eq!(code(decrypt(crit, &key, &understood)), "DecryptionFailed");

        let mut empty = base.clone();
        empty.recipients.clear();
        assert_eq!(code(decrypt(empty, &key, &p)), "InvalidFormat");
        assert_eq!(
            code(decrypt(base.clone(), &key, &p.clone().max_recipients(1))),
            "InvalidFormat"
        );
        assert_eq!(code(decrypt(base, &key, &p)), "ok");
    }

    #[test]
    fn direct_modes_need_a_protected_alg_and_enc_in_step_4() {
        // ADR 0050 §1: dir and ECDH-ES with `alg` or `enc` outside the
        // protected header are InvalidHeader in step 4, so before step 5
        // (crit), the support check, the allow-list and the key binding.
        let key = oct(&[1; 16], "");
        let mut parts = general(&[&key]);
        set_alg(&mut parts, 0, "dir");
        parts.recipients[0].encrypted_key.clear();
        let not_allowed = policy(&[A::A128KW]);
        let unbound = oct(&[1; 16], r#","alg":"A128KW""#);
        assert_eq!(
            code(decrypt(parts.clone(), &key, &not_allowed)),
            "InvalidHeader"
        );
        assert_eq!(
            code(decrypt(parts.clone(), &unbound, &policy(&[A::Dir]))),
            "InvalidHeader"
        );
        let mut crit = parts.clone();
        reprotect(&mut crit, r#"{"enc":"A128GCM","crit":["x-a"],"x-a":1}"#);
        assert_eq!(
            code(decrypt(crit, &key, &policy(&[A::Dir]))),
            "InvalidHeader"
        );
        let mut unsupported_enc = parts.clone();
        reprotect(&mut unsupported_enc, r#"{"enc":"A128CTR"}"#);
        assert_eq!(
            code(decrypt(unsupported_enc, &key, &policy(&[A::Dir]))),
            "InvalidHeader"
        );
        set_alg(&mut parts, 0, "ECDH-ES");
        assert_eq!(
            code(decrypt(parts.clone(), &key, &policy(&[A::EcdhEs]))),
            "InvalidHeader"
        );

        // `alg` protected but `enc` not: still refused.
        let mut enc_unprotected = general(&[&key]);
        rheader(&mut enc_unprotected, 0).alg = None;
        rheader(&mut enc_unprotected, 0).enc = Some(ContentEncAlg::A128GCM);
        reprotect(&mut enc_unprotected, r#"{"alg":"dir"}"#);
        assert_eq!(
            code(decrypt(enc_unprotected, &key, &policy(&[A::Dir]))),
            "InvalidHeader"
        );

        // A non-direct alg may stay unprotected (RFC 7516 §7.2.1).
        assert_eq!(code(decrypt(general(&[&key]), &key, &not_allowed)), "ok");
    }

    #[test]
    fn unsupported_enc_and_zip_fail_immediately() {
        let key = oct(&[1; 16], "");
        let p = policy(&[A::A128KW]);
        let mut enc = general(&[&key]);
        reprotect(&mut enc, r#"{"enc":"A128CTR"}"#);
        assert_eq!(code(decrypt(enc, &key, &p)), "UnsupportedAlgorithm");
        for zip in ["XYZ", "def", "DEF"] {
            let mut parts = general(&[&key]);
            reprotect(&mut parts, &format!(r#"{{"enc":"A128GCM","zip":"{zip}"}}"#));
            let expected = if zip == "DEF" && cfg!(feature = "deflate") {
                "DecryptionFailed" // supported; the header changed, so the tag fails
            } else {
                "UnsupportedAlgorithm"
            };
            assert_eq!(code(decrypt(parts, &key, &p)), expected, "{zip}");
        }
    }

    #[test]
    fn the_first_candidate_that_decrypts_wins() {
        let k1 = oct(&[1; 16], "");
        let k2 = oct(&[2; 16], "");
        let k3 = oct(&[3; 16], "");
        let parts = general(&[&k1, &k2, &k3]);
        let p = policy(&[A::A128KW]);
        for (key, index) in [(&k1, 0), (&k2, 1), (&k3, 2)] {
            let d = decrypt(parts.clone(), key, &p).unwrap_or_else(|e| panic!("{e}"));
            assert_eq!(d.recipient(), index);
            assert_eq!(d.plaintext(), b"hello");
            assert_eq!(d.header().alg.as_deref(), Some("A128KW"));
            assert_eq!(d.header().enc, Some(ContentEncAlg::A128GCM));
            assert!(d.recipient_header().is_some_and(|h| h.alg.is_some()));
            assert!(d.protected_header().is_some_and(|h| h.alg.is_none()));
        }
        // No recipient's key: every candidate fails.
        let other = oct(&[9; 16], "");
        assert_eq!(code(decrypt(parts, &other, &p)), "DecryptionFailed");
    }

    #[test]
    fn non_candidates_are_skipped() {
        // plan.md: candidates are supported, allowed, of the key's family
        // and of a matching kid; the rest are skipped.
        let k = oct(&[1; 16], r#","kid":"mine""#);
        let p = policy(&[A::A128KW, A::A256KW]);
        let mut parts = general(&[&k, &k, &k, &k, &k]);
        set_alg(&mut parts, 0, "RSA1_5"); // unsupported
        set_alg(&mut parts, 1, "A192KW"); // not allowed
        set_alg(&mut parts, 2, "A256KW"); // a 16-byte key cannot serve it
        rheader(&mut parts, 3).kid = Some("theirs".to_owned());
        let d = decrypt(parts, &k, &p).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(d.recipient(), 4);
    }

    #[test]
    fn with_no_candidate_the_best_ranked_error_is_reported() {
        // plan.md: AlgorithmNotAllowed, then UnsupportedAlgorithm, then
        // KeyAlgorithmMismatch, whatever the recipient order.
        let k = oct(&[1; 16], r#","kid":"mine""#);
        let p = policy(&[A::A128KW, A::A256KW]);
        let unsupported = |parts: &mut JweParts, i: usize| set_alg(parts, i, "RSA-OAEP");
        let not_allowed = |parts: &mut JweParts, i: usize| set_alg(parts, i, "A192KW");
        let mismatch = |parts: &mut JweParts, i: usize| set_alg(parts, i, "A256KW");
        let other_kid =
            |parts: &mut JweParts, i: usize| rheader(parts, i).kid = Some("x".to_owned());
        type Make = dyn Fn(&mut JweParts, usize);
        let cases: [(&[&Make], &str); 7] = [
            (&[&unsupported], "UnsupportedAlgorithm"),
            (&[&not_allowed], "AlgorithmNotAllowed"),
            (&[&mismatch], "KeyAlgorithmMismatch"),
            (&[&other_kid], "KeyAlgorithmMismatch"),
            (
                &[&mismatch, &unsupported, &not_allowed],
                "AlgorithmNotAllowed",
            ),
            (
                &[&not_allowed, &unsupported, &mismatch],
                "AlgorithmNotAllowed",
            ),
            (
                &[&mismatch, &other_kid, &unsupported],
                "UnsupportedAlgorithm",
            ),
        ];
        for (makers, expected) in cases {
            let keys: Vec<&Jwk> = makers.iter().map(|_| &k).collect();
            let mut parts = general(&keys);
            for (i, make) in makers.iter().enumerate() {
                make(&mut parts, i);
            }
            assert_eq!(code(decrypt(parts, &k, &p)), expected, "{expected}");
        }
    }

    #[test]
    fn rsa_oaep_256_never_decrypts_even_when_allowed() {
        // ADR 0021: support comes before the allow-list.
        let k = oct(&[1; 16], "");
        let p = policy(&[A::RsaOaep256, A::from("RSA-OAEP"), A::from("RSA1_5")]);
        for alg in ["RSA-OAEP-256", "RSA-OAEP", "RSA1_5", "nope"] {
            let mut parts = general(&[&k]);
            set_alg(&mut parts, 0, alg);
            assert_eq!(
                code(decrypt(parts, &k, &p)),
                "UnsupportedAlgorithm",
                "{alg}"
            );
        }
    }

    #[test]
    fn every_post_key_management_failure_is_the_same_error() {
        let k = oct(&[1; 16], "");
        let p = policy(&[A::A128KW]);
        let base = general(&[&k]);
        let mut cases = Vec::new();
        let mut c = base.clone();
        c.tag[0] ^= 1;
        cases.push(c);
        let mut c = base.clone();
        c.ciphertext[0] ^= 1;
        cases.push(c);
        let mut c = base.clone();
        c.iv[0] ^= 1;
        cases.push(c);
        let mut c = base.clone();
        c.iv.pop();
        cases.push(c);
        let mut c = base.clone();
        c.tag.truncate(15);
        cases.push(c);
        let mut c = base.clone();
        c.recipients[0].encrypted_key[3] ^= 1;
        cases.push(c);
        let mut c = base.clone();
        c.recipients[0].encrypted_key.truncate(16);
        cases.push(c);
        let mut c = base.clone();
        c.protected_b64.push('A');
        cases.push(c);
        let mut c = base.clone();
        c.aad = Some(b"aad".to_vec());
        cases.push(c);
        for parts in cases {
            let e = decrypt(parts, &k, &p).map(|_| ()).unwrap_err();
            assert_eq!(e, Error::DecryptionFailed);
            assert_eq!(format!("{e:?}"), "DecryptionFailed");
            assert_eq!(e.to_string(), "decryption failed");
            assert!(std::error::Error::source(&e).is_none());
        }
    }

    fn compact_encryptor(alg: KeyMgmtAlg, key: &Jwk) -> Encryptor {
        Encryptor::new(ContentEncAlg::A128GCM).recipient(Recipient::new(alg, key))
    }

    fn encrypt_code(e: &Encryptor, form: Serialization) -> &'static str {
        code(encrypt(e, b"x", form, &mut OsRandom, None))
    }

    #[test]
    fn encrypt_refuses_what_the_serialization_cannot_carry() {
        // RFC 7516 §7.1 (compact), §7.2.2 (flattened), §5.1 steps 5-6.
        let k = oct(&[1; 16], "");
        let compact = Serialization::Compact;
        let flat = Serialization::Json(JsonForm::Flattened);
        let general_form = Serialization::Json(JsonForm::General);
        let one = compact_encryptor(A::A128KW, &k);
        assert_eq!(encrypt_code(&one, compact), "ok");
        let none = Encryptor::new(ContentEncAlg::A128GCM);
        for form in [compact, flat, general_form] {
            assert_eq!(encrypt_code(&none, form), "InvalidFormat");
        }
        let two = one.clone().recipient(Recipient::new(A::A128KW, &k));
        assert_eq!(encrypt_code(&two, compact), "InvalidFormat");
        assert_eq!(encrypt_code(&two, flat), "InvalidFormat");
        assert_eq!(encrypt_code(&two, general_form), "ok");
        assert_eq!(
            encrypt_code(&one.clone().aad(*b"a"), compact),
            "InvalidFormat"
        );
        assert_eq!(encrypt_code(&one.clone().aad(*b"a"), general_form), "ok");
        let shared = one
            .clone()
            .shared_unprotected_header(header(r#"{"x-a":1}"#));
        assert_eq!(encrypt_code(&shared, compact), "InvalidFormat");
        let per = Encryptor::new(ContentEncAlg::A128GCM)
            .recipient(Recipient::new(A::A128KW, &k).header(header(r#"{"kid":"a"}"#)));
        assert_eq!(encrypt_code(&per, compact), "InvalidFormat");
        assert_eq!(encrypt_code(&per, flat), "ok");
        // dir takes no other recipient (it determines the CEK).
        let d = oct(&[1; 16], "");
        let dir_and_kw = compact_encryptor(A::Dir, &d).recipient(Recipient::new(A::A128KW, &k));
        assert_eq!(encrypt_code(&dir_and_kw, general_form), "InvalidFormat");
        let dir_twice = compact_encryptor(A::Dir, &d).recipient(Recipient::new(A::Dir, &d));
        assert_eq!(encrypt_code(&dir_twice, general_form), "InvalidFormat");
    }

    #[test]
    fn encrypt_refuses_parameters_polyjose_sets() {
        let k = oct(&[1; 16], "");
        for name in SET_BY_POLYJOSE {
            let value = if *name == "p2c" {
                "1000"
            } else if *name == "epk" {
                "{}"
            } else {
                "\"A128KW\""
            };
            let h = header(&format!(r#"{{"{name}":{value}}}"#));
            let protected = compact_encryptor(A::A128KW, &k).protected_header(h.clone());
            assert_eq!(
                encrypt_code(&protected, Serialization::Compact),
                "InvalidHeader",
                "{name}"
            );
            let shared = compact_encryptor(A::A128KW, &k).shared_unprotected_header(h.clone());
            let general_form = Serialization::Json(JsonForm::General);
            assert_eq!(
                encrypt_code(&shared, general_form),
                "InvalidHeader",
                "{name}"
            );
            let per = Encryptor::new(ContentEncAlg::A128GCM)
                .recipient(Recipient::new(A::A128KW, &k).header(h));
            assert_eq!(encrypt_code(&per, general_form), "InvalidHeader", "{name}");
        }
        // The caller's headers must be disjoint, and crit protected.
        let general_form = Serialization::Json(JsonForm::General);
        let clash = compact_encryptor(A::A128KW, &k)
            .protected_header(header(r#"{"kid":"a"}"#))
            .shared_unprotected_header(header(r#"{"kid":"a"}"#));
        assert_eq!(encrypt_code(&clash, general_form), "InvalidHeader");
        let crit = compact_encryptor(A::A128KW, &k)
            .shared_unprotected_header(header(r#"{"crit":["x-a"],"x-a":1}"#));
        assert_eq!(encrypt_code(&crit, general_form), "InvalidHeader");
        let crit_absent =
            compact_encryptor(A::A128KW, &k).protected_header(header(r#"{"crit":["x-a"]}"#));
        assert_eq!(
            encrypt_code(&crit_absent, Serialization::Compact),
            "InvalidHeader"
        );
    }

    #[test]
    fn encrypt_checks_support_then_keys() {
        let k = oct(&[1; 16], "");
        let compact = Serialization::Compact;
        for alg in ["RSA-OAEP", "RSA1_5", "nope"] {
            assert_eq!(
                encrypt_code(&compact_encryptor(A::from(alg), &k), compact),
                "UnsupportedAlgorithm",
                "{alg}"
            );
        }
        let unknown_enc =
            Encryptor::new(ContentEncAlg::from("A128CTR")).recipient(Recipient::new(A::A128KW, &k));
        assert_eq!(encrypt_code(&unknown_enc, compact), "UnsupportedAlgorithm");
        // Wrong size for the alg; wrong family; JWK alg forbids it.
        assert_eq!(
            encrypt_code(&compact_encryptor(A::A256KW, &k), compact),
            "InvalidKey"
        );
        let dir_key = oct(&[1; 32], "");
        assert_eq!(
            encrypt_code(&compact_encryptor(A::Dir, &dir_key), compact),
            "InvalidKey"
        );
        let ec = Jwk::from_json(
            br#"{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}"#,
        )
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            encrypt_code(&compact_encryptor(A::A128KW, &ec), compact),
            "KeyAlgorithmMismatch"
        );
        let bound = oct(&[1; 16], r#","alg":"A192KW""#);
        assert_eq!(
            encrypt_code(&compact_encryptor(A::A128KW, &bound), compact),
            "KeyAlgorithmMismatch"
        );
    }

    #[test]
    fn rng_draw_order_is_cek_then_recipients_then_iv() {
        // jwe::random: the CEK (16 bytes for A128GCM), then nothing for
        // A128KW, then the 12-byte IV, and nothing else.
        let k = oct(&[1; 16], "");
        let bytes: Vec<u8> = (0..28).collect();
        let mut rng = FixedRng::new(bytes);
        let e = compact_encryptor(A::A128KW, &k);
        let parts = encrypt(&e, b"x", Serialization::Compact, &mut rng, None)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(rng.remaining(), 0);
        assert_eq!(parts.iv, (16..28).collect::<Vec<u8>>());
        let unwrapped = super::super::aes_kw::unwrap(&[1; 16], &parts.recipients[0].encrypted_key)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(unwrapped.as_slice(), (0..16).collect::<Vec<u8>>());
        // One byte short: fails closed, no JWE.
        let mut short = FixedRng::new((0..27).collect::<Vec<u8>>());
        assert_eq!(
            code(encrypt(&e, b"x", Serialization::Compact, &mut short, None)),
            "RandomnessUnavailable"
        );
        // dir draws only the IV.
        let mut iv_only = FixedRng::new([7u8; 12]);
        let d = compact_encryptor(A::Dir, &k);
        let parts = encrypt(&d, b"x", Serialization::Compact, &mut iv_only, None)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(iv_only.remaining(), 0);
        assert_eq!(parts.iv, [7u8; 12]);
        assert!(parts.recipients[0].encrypted_key.is_empty());
    }

    #[test]
    fn header_placement_follows_the_form() {
        let k = oct(&[1; 16], "");
        let e = compact_encryptor(A::A128KW, &k).protected_header(header(r#"{"kid":"a"}"#));
        let compact = encrypt(&e, b"x", Serialization::Compact, &mut OsRandom, None)
            .unwrap_or_else(|e| panic!("{e}"));
        let p = compact.protected.as_ref().unwrap_or_else(|| panic!("none"));
        assert_eq!(p.alg.as_deref(), Some("A128KW"));
        assert_eq!(p.kid.as_deref(), Some("a"));
        assert_eq!(
            compact.protected_b64,
            b64url_encode(br#"{"alg":"A128KW","enc":"A128GCM","kid":"a"}"#)
        );
        let general_form = Serialization::Json(JsonForm::General);
        let general =
            encrypt(&e, b"x", general_form, &mut OsRandom, None).unwrap_or_else(|e| panic!("{e}"));
        let p = general.protected.as_ref().unwrap_or_else(|| panic!("none"));
        assert!(p.alg.is_none());
        let r = general.recipients[0]
            .header
            .as_ref()
            .unwrap_or_else(|| panic!("none"));
        assert_eq!(r.alg.as_deref(), Some("A128KW"));

        // ADR 0050 §1: a direct mode is protected in the general form too;
        // a caller's per-recipient header stays where it was put.
        let d = Encryptor::new(ContentEncAlg::A128GCM)
            .recipient(Recipient::new(A::Dir, &k).header(header(r#"{"kid":"r"}"#)));
        let general =
            encrypt(&d, b"x", general_form, &mut OsRandom, None).unwrap_or_else(|e| panic!("{e}"));
        let p = general.protected.as_ref().unwrap_or_else(|| panic!("none"));
        assert_eq!(p.alg.as_deref(), Some("dir"));
        let r = general.recipients[0]
            .header
            .as_ref()
            .unwrap_or_else(|| panic!("none"));
        assert!(r.alg.is_none());
        assert_eq!(r.kid.as_deref(), Some("r"));
    }

    #[test]
    fn the_reproducible_hook_accepts_only_an_equal_header() {
        let k = oct(&[1; 16], "");
        let e = compact_encryptor(A::A128KW, &k).protected_header(header(r#"{"kid":"a"}"#));
        let run = |given: &str| {
            let mut rng = FixedRng::new([0u8; 28]);
            encrypt(&e, b"x", Serialization::Compact, &mut rng, Some(given))
        };
        // Reordered and spaced: equal as JSON, used verbatim.
        let reordered =
            b64url_encode(b"{\"kid\":\"a\",\r\n \"enc\":\"A128GCM\", \"alg\":\"A128KW\"}");
        let parts = run(&reordered).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(parts.protected_b64, reordered);
        let policy = policy(&[A::A128KW]);
        let d = decrypt(parts, &k, &policy).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(d.plaintext(), b"x");
        for bad in [
            br#"{"alg":"A128KW","enc":"A128GCM"}"#.as_slice(),
            br#"{"alg":"A128KW","enc":"A128GCM","kid":"b"}"#,
            br#"{"alg":"A128KW","enc":"A128GCM","kid":"a","x":1}"#,
            br#"{"alg":"dir","enc":"A128GCM","kid":"a"}"#,
            br#"{"alg":"A128KW","enc":"A128GCM","kid":"a","kid":"a"}"#,
            b"[]",
        ] {
            assert_eq!(code(run(&b64url_encode(bad))), "InvalidFormat");
        }
        assert_eq!(code(run("e30=")), "InvalidFormat");
    }
}
