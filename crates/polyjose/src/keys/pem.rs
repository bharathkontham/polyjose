//! Strict RFC 7468 textual encoding (§2, §3 Figure 3 `stricttextualmsg`):
//! one block, whitespace-only surroundings, matching BEGIN/END labels, no
//! headers, 64-character lines and canonical padded base64 (RFC 4648 §4,
//! §3.5), with LF, CRLF or CR line endings (ADR 0018 §2). Labels: `PRIVATE
//! KEY` (§10), `ENCRYPTED PRIVATE KEY` (§11), `PUBLIC KEY` (§13), plus
//! OpenSSL's `EC PRIVATE KEY` (RFC 5915 §4), `RSA PUBLIC KEY` and
//! `RSA PRIVATE KEY` (RFC 9500 §2.1).
//!
//! The decoder classifies the label from the BEGIN line before it reads the
//! body (ADR 0018 §2). A label that names no key structure, `ENCRYPTED
//! PRIVATE KEY` (ADR 0018 §4) and `RSA PRIVATE KEY` (ADR 0021) fail at once
//! with [`Error::UnsupportedAlgorithm`], whatever follows, so their bodies
//! are never decoded. Every other fault is [`Error::InvalidKey`] with a
//! static detail that never quotes the input.
//!
//! A private key's PEM body is secret, so the base64 text and the decoded
//! octets are held only in buffers that are wiped on every path, and the
//! body is decoded by the constant-time codec in [`crate::util`].

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use super::der;
use super::types::Label;
use crate::util::{b64_decode_into, b64_encode_append, b64_encoded_len};
use crate::{Error, Result};

/// The pre-encapsulation boundary up to the label (RFC 7468 §3 `preeb`).
const BEGIN: &[u8] = b"-----BEGIN ";
/// The post-encapsulation boundary up to the label (RFC 7468 §3 `posteb`).
const END: &[u8] = b"-----END ";
/// What closes both boundary lines: exactly five hyphen-minuses (RFC 7468 §2).
const DASHES: &[u8] = b"-----";
/// The width of every base64 line but the last (RFC 7468 §2, §3
/// `base64fullline`).
const LINE_WIDTH: usize = 64;
/// Octets per full line: 64 characters are 16 quanta of 3 octets
/// (RFC 4648 §4), so every full line ends on a quantum and needs no `=`.
const LINE_OCTETS: usize = LINE_WIDTH / 4 * 3;
/// The RFC 1421 §4.6.1.1 header that starts an encrypted legacy block
/// (`Proc-Type: 4,ENCRYPTED`, as OpenSSL writes it).
const PROC_TYPE: &[u8] = b"Proc-Type:";

/// The longest label the decoder classifies, `ENCRYPTED PRIVATE KEY`
/// (RFC 7468 §11): 21 characters. Every other known label is shorter.
const LONGEST_LABEL: usize = "ENCRYPTED PRIVATE KEY".len();
/// Room within [`MAX_INPUT_LEN`] for the whitespace around the block, which
/// the grammar does not bound (ADR 0018 §2): 8 KiB.
const SURROUNDING_WHITESPACE: usize = 8 * 1024;
/// The base64 characters of the largest DER the reader accepts (RFC 4648 §4:
/// 4 characters per started 3-octet group): 87,384 for 64 KiB.
const MAX_BODY_CHARS: usize = der::MAX_INPUT_LEN.div_ceil(3) * 4;
/// The lines of that body at 64 characters each (RFC 7468 §2): 1,366.
const MAX_BODY_LINES: usize = MAX_BODY_CHARS.div_ceil(LINE_WIDTH);

/// The largest PEM input [`decode`] reads: 98,384 octets (about 96 KiB).
///
/// It is the longest strict RFC 7468 block (§3 `stricttextualmsg`) that can
/// hold a [`der::MAX_INPUT_LEN`] (64 KiB) body, plus whitespace around it:
///
/// ```text
///   base64 body            4 * ceil(65,536 / 3)          = 87,384
/// + line endings           2 (CRLF) * (1,366 body lines
///                                      + BEGIN + END)    =  2,736
/// + armor, longest label   "-----BEGIN " 11 + 21 + 5
///                          + "-----END "  9 + 21 + 5     =     72
/// + surrounding whitespace 8 KiB                         =  8,192
///                                                          ------
///                                                          98,384
/// ```
///
/// So every block whose DER the reader could accept fits, with CRLF line
/// endings and any label, and a larger DER is still rejected by the DER cap
/// rather than by this one unless its text is also over this size. Longer
/// input is rejected before any allocation or parse (ADR 0018 §2 bounds
/// the work done on untrusted key text).
pub(crate) const MAX_INPUT_LEN: usize = MAX_BODY_CHARS
    + 2 * (MAX_BODY_LINES + 2)
    + BEGIN.len()
    + LONGEST_LABEL
    + DASHES.len()
    + END.len()
    + LONGEST_LABEL
    + DASHES.len()
    + SURROUNDING_WHITESPACE;

/// Decodes one strict RFC 7468 block into its label and DER octets.
///
/// Accepts exactly `*WS preeb eol strictbase64text posteb *WS` (RFC 7468
/// §3 Figure 3 `stricttextualmsg`, with the ADR 0018 §2 tolerances), where
/// `WS` is SP, HTAB, CR or LF:
///
/// - only whitespace before `-----BEGIN ` and after the END line's closing
///   dashes, so the final `eol` is optional and explanatory text, a second
///   block or a byte-order mark is rejected (ADR 0018 §2; RFC 7468 §2
///   permits such text, and a strict parser may refuse it);
/// - exactly five hyphen-minuses around each label (RFC 7468 §2);
/// - a label per RFC 7468 §3 (`labelchar *( ["-" / SP] labelchar )`) that is
///   upper-case (§2: labels are "formally case-sensitive, uppercase");
/// - the END label identical to the BEGIN label (§2; ADR 0018 §2 does not
///   take up §2's "MAY disregard");
/// - no headers (§2: the textual encoding "does *not* define or permit
///   headers"); an RFC 1421 `Proc-Type:` first line is legacy encryption
///   and is unsupported;
/// - base64 lines of exactly 64 characters, except the last, which holds 1
///   to 16 quanta (§2, §3 `base64fullline`, `strictbase64finl`), with
///   nothing else on any line;
/// - each line ended by CRLF, CR or LF (§3 `eol`);
/// - a non-empty body in canonical padded base64 (§2; RFC 4648 §4, §3.5).
///
/// # Errors
///
/// - [`Error::UnsupportedAlgorithm`], checked from the BEGIN line before
///   the body is read, so whatever the body holds, for a well-formed label
///   that names no supported structure (ADR 0018 §2, §4):
///   - [`Label::Other`], such as `CERTIFICATE` or `DSA PRIVATE KEY`;
///   - [`Label::EncryptedPrivateKey`]: encrypted PKCS#8 is out of scope;
///   - [`Label::RsaPrivate`]: no RSA private keys (ADR 0021), so their
///     secret body is never decoded into memory.
///
///   Also for a `Proc-Type:` header (RFC 1421 legacy encryption).
///
///   This is stricter than T03's original wording, under which these two
///   labels decoded and the caller rejected them. ADR 0018 §2 ("a
///   `CERTIFICATE` or `ENCRYPTED PRIVATE KEY` block fails with
///   `UnsupportedAlgorithm` whatever its body") and ADR 0021 take
///   precedence (lead decision, 2026-11-06). The error code at the API is
///   the same. RSA private keys inside PKCS#8 carry the generic `PRIVATE KEY`
///   label and are rejected by their AlgorithmIdentifier instead.
/// - [`Error::InvalidKey`] for everything else that breaks the grammar.
///
/// The returned octets wipe on drop; the base64 copy is wiped before
/// returning.
pub(crate) fn decode(text: &str) -> Result<(Label, Zeroizing<Vec<u8>>)> {
    let mut body = Zeroizing::new(Vec::new());
    let mut der = Zeroizing::new(Vec::new());
    let label = decode_into(text.as_bytes(), &mut body, &mut der)?;
    Ok((label, der))
}

/// [`decode`] into caller buffers: `body` receives the base64 text of the
/// block without line endings, `der` the decoded octets.
///
/// Both are wiped in place before this returns an error, and `body` is
/// wiped on success too, so a test can read them back. They keep their
/// lengths, and the caller's `Zeroizing` wipes their whole capacity on drop.
fn decode_into(text: &[u8], body: &mut Vec<u8>, der: &mut Vec<u8>) -> Result<Label> {
    // First, before any allocation or parse: the length is public, so this
    // branch leaks nothing, and nothing is collected that needs wiping.
    if text.len() > MAX_INPUT_LEN {
        return Err(Error::InvalidKey("PEM input too large"));
    }
    let result = parse(text, body).and_then(|label| {
        b64_decode_into(body, der)
            .map_err(|_| Error::InvalidKey("PEM body is not canonical padded base64"))?;
        Ok(label)
    });
    body.as_mut_slice().zeroize();
    if result.is_err() {
        der.as_mut_slice().zeroize();
    }
    result
}

/// Checks the armor and line structure of `text` and collects the base64
/// characters of the body into `body`, without decoding them.
///
/// # Constant time
///
/// The body characters are secret for a private key. They are copied and
/// compared without a branch on their values: the BEGIN/END and `Proc-Type:`
/// prefixes are compared with `subtle`, and the line split branches only on
/// CR and LF, which are not in the base64 alphabet. So for a well-formed body
/// the control flow depends only on the line lengths, which are public (they
/// follow from the DER length). Base64 validity is left to the constant-time
/// decoder. The armor and the surrounding whitespace hold no secret.
fn parse(text: &[u8], body: &mut Vec<u8>) -> Result<Label> {
    let start = text
        .iter()
        .position(|&c| !is_whitespace(c))
        .unwrap_or(text.len());
    let rest = text[start..].strip_prefix(BEGIN).ok_or(Error::InvalidKey(
        "PEM text does not start with a BEGIN line",
    ))?;
    let (line, mut rest) =
        split_line(rest).ok_or(Error::InvalidKey("PEM BEGIN line has no line ending"))?;
    let label_text = line.strip_suffix(DASHES).ok_or(Error::InvalidKey(
        "PEM BEGIN line does not end with five dashes",
    ))?;
    let label = parse_label(label_text)?;
    if is_unsupported(label) {
        // ADR 0018 §2: classified from the BEGIN line, before the body, so
        // an RSA private key (ADR 0021) or an encrypted one is never
        // base64-decoded into memory.
        return Err(Error::UnsupportedAlgorithm);
    }

    // At most `rest.len()` body characters: one allocation, never regrown.
    body.zeroize();
    body.reserve_exact(rest.len());
    let mut last_width = None;
    while !starts_with_ct(rest, END) {
        let (line, next) =
            split_line(rest).ok_or(Error::InvalidKey("PEM block has no END line"))?;
        if last_width.is_none() && starts_with_ct(line, PROC_TYPE) {
            // RFC 1421 §4.6.1.1 / OpenSSL legacy encryption (ADR 0018 §4).
            return Err(Error::UnsupportedAlgorithm);
        }
        // RFC 7468 §3: every line before the last is a full 64-character
        // line, and no line is empty or longer.
        if last_width.is_some_and(|width| width != LINE_WIDTH)
            || line.is_empty()
            || line.len() > LINE_WIDTH
        {
            return Err(Error::InvalidKey("PEM base64 lines must be 64 characters"));
        }
        body.extend_from_slice(line);
        last_width = Some(line.len());
        rest = next;
    }
    if last_width.is_none() {
        return Err(Error::InvalidKey("PEM block has an empty body"));
    }

    // posteb: the same label, five dashes, then only whitespace.
    let after = rest[END.len()..]
        .strip_prefix(label_text)
        .and_then(|r| r.strip_prefix(DASHES))
        .ok_or(Error::InvalidKey(
            "PEM END line does not match the BEGIN line",
        ))?;
    if !after.iter().all(|&c| is_whitespace(c)) {
        return Err(Error::InvalidKey("PEM text after the END line"));
    }
    Ok(label)
}

/// Labels that are unsupported whatever the block holds: any label that names
/// no key structure (RFC 7468 §5, e.g. `CERTIFICATE`), `ENCRYPTED PRIVATE
/// KEY` (RFC 7468 §11; ADR 0018 §2, §4) and `RSA PRIVATE KEY` (ADR 0021).
fn is_unsupported(label: Label) -> bool {
    matches!(
        label,
        Label::Other | Label::EncryptedPrivateKey | Label::RsaPrivate
    )
}

/// Whitespace allowed around the block (ADR 0018 §2): RFC 7468 §3 `WSP`
/// (SP, HTAB) and the `eol` characters CR and LF.
fn is_whitespace(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\r' | b'\n')
}

/// Splits off one line and its `eol` (RFC 7468 §3: CRLF, CR or LF), or
/// `None` if `text` has no line ending.
fn split_line(text: &[u8]) -> Option<(&[u8], &[u8])> {
    let end = text.iter().position(|&c| c == b'\r' || c == b'\n')?;
    let eol = if text[end..].starts_with(b"\r\n") {
        2
    } else {
        1
    };
    Some((&text[..end], &text[end + eol..]))
}

/// Whether `text` starts with `prefix`, compared without a branch on the
/// bytes (`subtle`); only the public lengths decide the early return.
fn starts_with_ct(text: &[u8], prefix: &[u8]) -> bool {
    text.len() >= prefix.len() && bool::from(text[..prefix.len()].ct_eq(prefix))
}

/// Checks a label against RFC 7468 §3 and §2 and classifies it.
///
/// `label = [ labelchar *( ["-" / SP] labelchar ) ]` with `labelchar =
/// %x21-2C / %x2E-7E`, so a label has no consecutive spaces or
/// hyphen-minuses and none at either end. §2 also says labels are
/// "formally case-sensitive, uppercase", so `a`–`z` are rejected. The empty
/// label is valid and unsupported.
fn parse_label(text: &[u8]) -> Result<Label> {
    let is_labelchar = |c: u8| matches!(c, 0x21..=0x2c | 0x2e..=0x7e) && !c.is_ascii_lowercase();
    // A separator may only follow a labelchar, and the label may not end
    // with one: start as if after a separator.
    let mut after_separator = true;
    for &c in text {
        if c == b'-' || c == b' ' {
            if after_separator {
                return Err(Error::InvalidKey("PEM label is malformed"));
            }
            after_separator = true;
        } else if is_labelchar(c) {
            after_separator = false;
        } else {
            return Err(Error::InvalidKey("PEM label is malformed"));
        }
    }
    if after_separator && !text.is_empty() {
        return Err(Error::InvalidKey("PEM label is malformed"));
    }
    // Every byte is ASCII by now.
    let text =
        core::str::from_utf8(text).map_err(|_| Error::InvalidKey("PEM label is malformed"))?;
    Ok(Label::from_text(text))
}

/// Encodes `der` as a strict RFC 7468 block with `label`, in the layout
/// OpenSSL writes: 64-character base64 lines (RFC 7468 §2: generators
/// "MUST wrap the base64-encoded lines so that each line consists of
/// exactly 64 characters except for the final line"), LF line endings, the
/// same label on the END line (§2), and a final LF.
///
/// The text is allocated once at its exact length and returned in a buffer
/// that wipes on drop, since `der` may be a private key (§10).
///
/// # Errors
///
/// - [`Error::UnsupportedAlgorithm`] for the labels [`decode`] rejects from
///   the BEGIN line: [`Label::Other`] (no text), [`Label::RsaPrivate`]
///   (ADR 0021) and [`Label::EncryptedPrivateKey`] (ADR 0018 §4). polyjose
///   never writes what it will not read.
/// - [`Error::InvalidKey`] for empty `der`: the strict grammar has at least
///   one base64 quantum (§3 `strictbase64finl`).
///
/// # Constant time
///
/// The base64 comes from the constant-time standard codec in
/// [`crate::util`]; everything else depends only on `der.len()` and the
/// label.
pub(crate) fn encode(label: Label, der: &[u8]) -> Result<Zeroizing<String>> {
    if is_unsupported(label) {
        return Err(Error::UnsupportedAlgorithm);
    }
    let text = label.as_str().ok_or(Error::UnsupportedAlgorithm)?;
    if der.is_empty() {
        return Err(Error::InvalidKey("PEM body cannot be empty"));
    }
    let lines = der.len().div_ceil(LINE_OCTETS);
    let len = BEGIN.len()
        + text.len()
        + DASHES.len()
        + 1
        + b64_encoded_len(der.len())
        + lines
        + END.len()
        + text.len()
        + DASHES.len()
        + 1;
    let mut out = Zeroizing::new(String::with_capacity(len));
    for part in ["-----BEGIN ", text, "-----\n"] {
        out.push_str(part);
    }
    for chunk in der.chunks(LINE_OCTETS) {
        b64_encode_append(chunk, &mut out);
        out.push('\n');
    }
    for part in ["-----END ", text, "-----\n"] {
        out.push_str(part);
    }
    debug_assert_eq!(out.len(), len);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use super::*;
    use crate::json;

    /// `tests/data/keys/<dir>`.
    fn data_dir(dir: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/data/keys")
            .join(dir)
    }

    fn read_text(dir: &str, name: &str) -> String {
        fs::read_to_string(data_dir(dir).join(name)).unwrap()
    }

    fn read_der(dir: &str, name: &str) -> Vec<u8> {
        fs::read(data_dir(dir).join(name)).unwrap()
    }

    /// The `.pem` files of `tests/data/keys/<dir>`, sorted by name.
    fn pem_files(dir: &str) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(data_dir(dir))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .filter(|name| name.ends_with(".pem"))
            .collect();
        names.sort();
        names
    }

    /// The decoded bytes, or the stable error code.
    fn outcome(text: &str) -> core::result::Result<(Label, Vec<u8>), &'static str> {
        decode(text)
            .map(|(label, der)| (label, der.to_vec()))
            .map_err(|e| e.code())
    }

    /// The RFC 8037 A.1 Ed25519 key, the base of the A/P vectors.
    fn ed25519_der() -> Vec<u8> {
        read_der("rfc", "rfc8037-a1-ed25519-pkcs8.der")
    }

    // ---- negative/ vectors (manifest.json) ----------------------------

    /// Every P vector in `negative/manifest.json` fails with the code the
    /// manifest gives, except P14 and P16: their armor is valid and the DER
    /// inside is what is wrong, which the container parsers reject (here the
    /// PEM layer must return the label and the decoded body).
    #[test]
    fn negative_pem_vectors_fail_with_the_manifest_code() {
        let manifest =
            json::parse(&fs::read(data_dir("negative").join("manifest.json")).unwrap()).unwrap();
        let mut checked = Vec::new();
        for row in manifest.as_array().unwrap() {
            let id = row.get("id").and_then(json::Value::as_str).unwrap();
            let file = row.get("file").and_then(json::Value::as_str).unwrap();
            let expect = row.get("expect").and_then(json::Value::as_str).unwrap();
            if !id.starts_with('P') {
                continue;
            }
            let got = outcome(&read_text("negative", file));
            match id {
                "P14" => assert_eq!(got, Ok((Label::PublicKey, ed25519_der())), "{id}"),
                "P16" => {
                    let mut der = ed25519_der();
                    der.push(0);
                    assert_eq!(got, Ok((Label::PrivateKey, der)), "{id}");
                }
                _ => assert_eq!(got.map(|_| ()), Err(expect), "{id} {file}"),
            }
            checked.push(id.to_owned());
        }
        let expected: Vec<String> = (1..=16).map(|n| format!("P{n:02}")).collect();
        assert_eq!(checked, expected);
    }

    /// A01 (CRLF), A02 (no final newline) and A03 (surrounding blank
    /// lines) decode to the RFC 8037 A.1 key, as does a CR-only copy of A01
    /// (RFC 7468 §3: `eol = CRLF / CR / LF`).
    #[test]
    fn acceptance_vectors_decode_to_the_base_key() {
        let der = ed25519_der();
        for file in [
            "A01-accept-crlf.pem",
            "A02-accept-no-final-newline.pem",
            "A03-accept-surrounding-whitespace.pem",
        ] {
            assert_eq!(
                outcome(&read_text("negative", file)),
                Ok((Label::PrivateKey, der.clone())),
                "{file}"
            );
        }
        let cr_only = read_text("negative", "A01-accept-crlf.pem").replace("\r\n", "\r");
        assert!(!cr_only.contains('\n'));
        assert_eq!(outcome(&cr_only), Ok((Label::PrivateKey, der)));
    }

    // ---- corpus -------------------------------------------------------

    /// The label of a positive fixture, from its file name.
    fn expected_label(name: &str) -> Label {
        if name.contains("-pkcs8") {
            Label::PrivateKey
        } else if name.contains("-spki") {
            Label::PublicKey
        } else if name.contains("-sec1") {
            Label::EcPrivateKey
        } else if name.contains("-pkcs1-pub") {
            Label::RsaPublic
        } else {
            panic!("no label known for {name}")
        }
    }

    /// Every positive `.pem` in `openssl/` and `rfc/` decodes with the label
    /// its structure has, to the bytes of its sibling `.der` when one exists.
    #[test]
    fn every_positive_corpus_file_decodes() {
        let mut with_der = 0;
        let mut total = 0;
        for dir in ["openssl", "rfc"] {
            for name in pem_files(dir)
                .into_iter()
                .filter(|n| !n.starts_with("reject-"))
            {
                let text = read_text(dir, &name);
                let (label, der) = decode(&text).unwrap_or_else(|e| panic!("{dir}/{name}: {e:?}"));
                assert_eq!(label, expected_label(&name), "{dir}/{name}");
                let sibling = data_dir(dir).join(name.replace(".pem", ".der"));
                if sibling.exists() {
                    assert_eq!(*der, fs::read(sibling).unwrap(), "{dir}/{name}");
                    with_der += 1;
                }
                total += 1;
            }
        }
        assert!(total >= 47, "{total} corpus files");
        assert!(with_der >= 28, "{with_der} DER siblings");
    }

    /// The `reject-*` corpus files: the PEM layer rejects what it can see
    /// from the armor (RFC 7468 §2) and returns the label of the rest, whose
    /// DER the container parsers reject (ADR 0018 §4, ADR 0021). Every
    /// `RSA PRIVATE KEY` and `ENCRYPTED PRIVATE KEY` block is unsupported
    /// from its BEGIN line. RSA private keys in PKCS#8 carry the generic
    /// `PRIVATE KEY` label, so only their AlgorithmIdentifier can reject
    /// them (ADR 0018 §2: the key type never comes from the label).
    #[test]
    fn reject_corpus_files_are_classified() {
        let mut seen = 0;
        for dir in ["openssl", "rfc"] {
            for name in pem_files(dir)
                .into_iter()
                .filter(|n| n.starts_with("reject-"))
            {
                let got = outcome(&read_text(dir, &name)).map(|(label, _)| label);
                let want = if name.contains("-cert")
                    || name.contains("-encrypted")
                    || name.contains("-private-pkcs1")
                {
                    // CERTIFICATE, ENCRYPTED PRIVATE KEY and RSA PRIVATE KEY
                    // (classified from the BEGIN line) and RFC 1421
                    // Proc-Type encryption.
                    Err("UnsupportedAlgorithm")
                } else if name.contains("six-dash") {
                    Err("InvalidKey")
                } else {
                    Ok(expected_label(&name))
                };
                assert_eq!(got, want, "{dir}/{name}");
                seen += 1;
            }
        }
        assert!(seen >= 30, "{seen} reject files");
    }

    /// `RSA PRIVATE KEY` (ADR 0021) and `ENCRYPTED PRIVATE KEY` (ADR 0018
    /// §4) blocks are unsupported from the BEGIN line, whatever the body
    /// (ADR 0018 §2): valid, corrupt, missing, or followed by junk. The body
    /// is never touched. Read back after the error, both working buffers
    /// are still unallocated, so no body character was collected and
    /// `b64_decode_into` (which allocates its output for any non-empty body)
    /// never ran: no private-key octet was ever decoded into memory.
    #[test]
    fn rsa_private_and_encrypted_blocks_are_rejected_before_the_body() {
        let mut texts = Vec::new();
        for name in [
            "reject-rsa2048-private-pkcs1.pem",
            "reject-ec-p256-pkcs8-encrypted.pem",
        ] {
            texts.push(read_text("openssl", name));
        }
        for label in ["RSA PRIVATE KEY", "ENCRYPTED PRIVATE KEY"] {
            texts.push(block(label, ED25519_BODY));
            texts.push(block(label, "not base64 at all *** QR=="));
            texts.push(block(label, &"A".repeat(65)));
            texts.push(format!("-----BEGIN {label}-----\n{ED25519_BODY}\n"));
            texts.push(format!(
                "-----BEGIN {label}-----\n{ED25519_BODY}\n-----END PUBLIC KEY-----\njunk"
            ));
        }
        for text in &texts {
            let mut body = Vec::new();
            let mut der = Vec::new();
            assert_eq!(
                decode_into(text.as_bytes(), &mut body, &mut der),
                Err(Error::UnsupportedAlgorithm),
                "{text:?}"
            );
            assert_eq!((body.capacity(), der.capacity()), (0, 0), "{text:?}");
            assert_eq!(outcome(text).map(|_| ()), Err("UnsupportedAlgorithm"));
        }
        // The same read-back is meaningful: a supported label with the same
        // body does allocate and decode.
        let mut body = Vec::new();
        let mut der = Vec::new();
        let ok = block("PRIVATE KEY", ED25519_BODY);
        assert_eq!(
            decode_into(ok.as_bytes(), &mut body, &mut der),
            Ok(Label::PrivateKey)
        );
        assert!(body.capacity() > 0 && der.capacity() > 0);
    }

    // ---- encoder ------------------------------------------------------

    /// The encoder output is byte-identical to OpenSSL's for the same DER
    /// and label: 64-column lines, LF, final LF (RFC 7468 §2).
    #[test]
    fn encoder_matches_the_openssl_fixtures() {
        let mut checked = 0;
        for dir in ["openssl", "rfc"] {
            for name in pem_files(dir)
                .into_iter()
                .filter(|n| !n.starts_with("reject-"))
            {
                let sibling = data_dir(dir).join(name.replace(".pem", ".der"));
                if !sibling.exists() {
                    continue;
                }
                let der = fs::read(sibling).unwrap();
                let pem = encode(expected_label(&name), &der).unwrap();
                assert_eq!(*pem, read_text(dir, &name), "{dir}/{name}");
                checked += 1;
            }
        }
        assert!(checked >= 28, "{checked}");
    }

    /// Lines are exactly 64 characters except the last (RFC 7468 §2), at
    /// every length around the 48-octet line boundary, and the output is
    /// allocated once at its exact length.
    #[test]
    fn encoder_wraps_at_64_and_sizes_exactly() {
        for n in 1..=200usize {
            let der: Vec<u8> = (0..n).map(|i| i as u8).collect();
            let pem = encode(Label::PublicKey, &der).unwrap();
            assert_eq!(pem.capacity(), pem.len(), "{n} octets: no reallocation");
            let lines: Vec<&str> = pem.split_terminator('\n').collect();
            assert_eq!(lines[0], "-----BEGIN PUBLIC KEY-----");
            assert_eq!(*lines.last().unwrap(), "-----END PUBLIC KEY-----");
            let body = &lines[1..lines.len() - 1];
            assert_eq!(body.len(), n.div_ceil(48), "{n} octets");
            for line in &body[..body.len() - 1] {
                assert_eq!(line.len(), 64);
            }
            assert!((4..=64).contains(&body.last().unwrap().len()));
            assert!(pem.ends_with("-----\n"));
            assert_eq!(outcome(&pem), Ok((Label::PublicKey, der)));
        }
    }

    /// No output for the unsupported labels, and no strict encoding of an
    /// empty body (RFC 7468 §3 `strictbase64finl` has at least one quantum).
    #[test]
    fn encoder_rejects_unsupported_labels_and_empty_input() {
        // The labels decode rejects from the BEGIN line are never written
        // either: RSA private keys (ADR 0021) and encrypted PKCS#8
        // (ADR 0018 §4).
        let rsa_private = read_der("openssl", "reject-rsa2048-private-pkcs1.der");
        for label in [Label::Other, Label::RsaPrivate, Label::EncryptedPrivateKey] {
            assert_eq!(
                encode(label, &rsa_private).map(|_| ()),
                Err(Error::UnsupportedAlgorithm),
                "{label:?}"
            );
        }
        assert!(matches!(
            encode(Label::PrivateKey, &[]),
            Err(Error::InvalidKey(_))
        ));
    }

    /// The encoder's return type wipes the PEM text on drop.
    #[test]
    fn encoder_returns_zeroizing_text() {
        let pem: Result<Zeroizing<String>> = encode(Label::PrivateKey, &ed25519_der());
        assert_eq!(
            *pem.unwrap(),
            read_text("rfc", "rfc8037-a1-ed25519-pkcs8.pem")
        );
    }

    // ---- grammar ------------------------------------------------------

    /// One line of the RFC 8037 A.1 key's body.
    const ED25519_BODY: &str = "MC4CAQAwBQYDK2VwBCIEIJ1hsZ3v/VpguoRK9JLsLMREScVpezJpGXA7rAMcrn9g";

    fn block(label: &str, body: &str) -> String {
        format!("-----BEGIN {label}-----\n{body}\n-----END {label}-----\n")
    }

    /// RFC 7468 §3 `label` and §2 ("formally case-sensitive, uppercase", no
    /// consecutive or end spaces/hyphen-minuses): an invalid label is
    /// malformed; a valid but unknown one is unsupported.
    #[test]
    fn label_syntax() {
        for bad in [
            "private key",
            "Private Key",
            "PRIVATE  KEY",
            "PRIVATE--KEY",
            "PRIVATE -KEY",
            " PRIVATE KEY",
            "PRIVATE KEY ",
            "-PRIVATE KEY",
            "PRIVATE KEY-",
            "PRIVATE\tKEY",
            "PRIVATE\u{e9}KEY",
        ] {
            assert_eq!(
                outcome(&block(bad, ED25519_BODY)).map(|_| ()),
                Err("InvalidKey"),
                "{bad:?}"
            );
        }
        for unknown in [
            "",
            "X",
            "DSA PRIVATE KEY",
            "X509 CRL",
            "A-B C",
            "!\"#$%&'()*+,./09:;<=>?@[\\]^_`{|}~",
        ] {
            assert_eq!(
                outcome(&block(unknown, ED25519_BODY)).map(|_| ()),
                Err("UnsupportedAlgorithm"),
                "{unknown:?}"
            );
        }
    }

    /// A non-key label is unsupported whatever its body: it is classified
    /// from the BEGIN line before the body is read (ADR 0018 §2).
    #[test]
    fn unknown_label_is_classified_before_the_body() {
        for text in [
            "-----BEGIN CERTIFICATE-----\nnot base64 at all\n",
            "-----BEGIN CERTIFICATE-----\n",
            "-----BEGIN CERTIFICATE-----\nAAAA\n-----END PUBLIC KEY-----\ntrailing\n",
        ] {
            assert_eq!(
                outcome(text).map(|_| ()),
                Err("UnsupportedAlgorithm"),
                "{text:?}"
            );
        }
        // Before the BEGIN line, only whitespace is allowed even then.
        assert_eq!(
            outcome("x\n-----BEGIN CERTIFICATE-----\n").map(|_| ()),
            Err("InvalidKey")
        );
    }

    /// RFC 1421 Proc-Type encryption (the first line after BEGIN) is
    /// unsupported (ADR 0018 §4). Any other header, or a Proc-Type line
    /// later in the body, is malformed (RFC 7468 §2: no headers).
    #[test]
    fn headers() {
        let enc = format!(
            "-----BEGIN EC PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,00\n\n{ED25519_BODY}\n-----END EC PRIVATE KEY-----\n"
        );
        assert_eq!(outcome(&enc).map(|_| ()), Err("UnsupportedAlgorithm"));
        let later = format!(
            "-----BEGIN PRIVATE KEY-----\n{ED25519_BODY}\nProc-Type: 4,ENCRYPTED\n-----END PRIVATE KEY-----\n"
        );
        assert_eq!(outcome(&later).map(|_| ()), Err("InvalidKey"));
        let other = format!(
            "-----BEGIN PRIVATE KEY-----\nComment: x\n{ED25519_BODY}\n-----END PRIVATE KEY-----\n"
        );
        assert_eq!(outcome(&other).map(|_| ()), Err("InvalidKey"));
    }

    /// The strict line structure of RFC 7468 §3 (`stricttextualmsg`), and
    /// ADR 0018 §2's whitespace-only surroundings.
    #[test]
    fn line_structure() {
        let der = ed25519_der();
        let ok = |text: &str| {
            assert_eq!(
                outcome(text),
                Ok((Label::PrivateKey, der.clone())),
                "{text:?}"
            )
        };
        let bad = |text: &str| assert_eq!(outcome(text).map(|_| ()), Err("InvalidKey"), "{text:?}");
        let b = ED25519_BODY;
        ok(&format!(
            " \t\r\n-----BEGIN PRIVATE KEY-----\n{b}\n-----END PRIVATE KEY----- \t\r\n\n"
        ));
        ok(&format!(
            "-----BEGIN PRIVATE KEY-----\r{b}\n-----END PRIVATE KEY-----\r\n"
        ));
        // Missing pieces.
        bad("");
        bad(" \n ");
        bad("-----BEGIN PRIVATE KEY-----");
        bad("-----BEGIN PRIVATE KEY-----\n");
        bad(&format!("-----BEGIN PRIVATE KEY-----\n{b}\n"));
        bad(&format!("-----BEGIN PRIVATE KEY-----\n{b}"));
        bad(&format!(
            "-----BEGIN PRIVATE KEY-----\n{b}-----END PRIVATE KEY-----\n"
        ));
        // Blank and whitespace-padded lines in the block.
        bad(&format!(
            "-----BEGIN PRIVATE KEY-----\n\n{b}\n-----END PRIVATE KEY-----\n"
        ));
        bad(&format!(
            "-----BEGIN PRIVATE KEY-----\n{b}\n\n-----END PRIVATE KEY-----\n"
        ));
        bad(&format!(
            "-----BEGIN PRIVATE KEY----- \n{b}\n-----END PRIVATE KEY-----\n"
        ));
        bad(&format!(
            "-----BEGIN PRIVATE KEY-----\n{b} \n-----END PRIVATE KEY-----\n"
        ));
        bad(&format!(
            "-----BEGIN PRIVATE KEY-----\n {b}\n-----END PRIVATE KEY-----\n"
        ));
        bad(&format!(
            "-----BEGIN PRIVATE KEY-----\n{b}\n -----END PRIVATE KEY-----\n"
        ));
        // Dashes and keywords.
        bad(&format!(
            "-----BEGIN PRIVATE KEY----\n{b}\n-----END PRIVATE KEY-----\n"
        ));
        bad(&format!(
            "------BEGIN PRIVATE KEY-----\n{b}\n-----END PRIVATE KEY-----\n"
        ));
        bad(&format!(
            "-----BEGIN PRIVATE KEY-----\n{b}\n-----END PRIVATE KEY----\n"
        ));
        bad(&format!(
            "-----BEGIN PRIVATE KEY-----\n{b}\n-----END PRIVATE KEY------\n"
        ));
        bad(&format!(
            "-----BEGIN PRIVATE KEY-----\n{b}\n-----END PRIVATE KEYS-----\n"
        ));
        bad(&format!(
            "-----BEGIN PRIVATE KEY-----\n{b}\n-----END -----\n"
        ));
        bad(&format!(
            "-----BEGIN PRIVATE KEY-----\n{b}\n-----end PRIVATE KEY-----\n"
        ));
        bad(&format!(
            "-----begin PRIVATE KEY-----\n{b}\n-----END PRIVATE KEY-----\n"
        ));
        bad(&format!(
            "-----BEGINPRIVATE KEY-----\n{b}\n-----END PRIVATE KEY-----\n"
        ));
        // Text around the block.
        bad(&format!(
            "-----BEGIN PRIVATE KEY-----\n{b}\n-----END PRIVATE KEY-----\n\0"
        ));
        bad(&format!(
            "\u{feff}-----BEGIN PRIVATE KEY-----\n{b}\n-----END PRIVATE KEY-----\n"
        ));
        bad(&format!(
            "\u{a0}-----BEGIN PRIVATE KEY-----\n{b}\n-----END PRIVATE KEY-----\n"
        ));
    }

    /// RFC 7468 §3: full lines are exactly 64 characters, and the final line
    /// holds 1 to 16 quanta (4 to 64 characters), padded.
    #[test]
    fn line_widths() {
        for n in [1usize, 47, 48, 49, 95, 96, 97, 200] {
            let der: Vec<u8> = (0..n).map(|i| (i * 7) as u8).collect();
            let mut b64 = String::new();
            crate::util::b64_encode_append(&der, &mut b64);
            let wrap = |w: usize| -> String {
                b64.as_bytes()
                    .chunks(w)
                    .map(|c| core::str::from_utf8(c).unwrap())
                    .collect::<Vec<_>>()
                    .join("\n")
            };
            assert_eq!(
                outcome(&block("PUBLIC KEY", &wrap(64))),
                Ok((Label::PublicKey, der.clone())),
                "{n}"
            );
            for w in [4usize, 60, 63, 65, 68, 76] {
                let got = outcome(&block("PUBLIC KEY", &wrap(w))).map(|_| ());
                if b64.len() <= w.min(64) {
                    // A single line is the final line; it may be 4..=64.
                    assert_eq!(got, Ok(()), "{n} octets, width {w}");
                } else {
                    assert_eq!(got, Err("InvalidKey"), "{n} octets, width {w}");
                }
            }
        }
    }

    // ---- hygiene ------------------------------------------------------

    /// Every error path wipes both working buffers: the collected base64
    /// text (a private key's encoding) and the decoded octets. Read back
    /// after the failure, both are all zeros. On success the base64 copy is
    /// wiped too and only the DER is kept.
    #[test]
    fn buffers_are_wiped_on_every_error_path() {
        let b = ED25519_BODY;
        let cases = [
            // After the body is collected: END label, trailing text.
            format!("-----BEGIN PRIVATE KEY-----\n{b}\n-----END PUBLIC KEY-----\n"),
            format!("-----BEGIN PRIVATE KEY-----\n{b}\n-----END PRIVATE KEY-----\nx\n"),
            // While collecting: a short line followed by another.
            format!(
                "-----BEGIN PRIVATE KEY-----\n{}\n{}\n-----END PRIVATE KEY-----\n",
                &b[..60],
                &b[60..]
            ),
            format!("-----BEGIN PRIVATE KEY-----\n{b}\n"),
            // While decoding: a bad symbol late in the body, bad pad bits.
            format!(
                "-----BEGIN PRIVATE KEY-----\n{}*\n-----END PRIVATE KEY-----\n",
                &b[..63]
            ),
            read_text("negative", "P15-noncanonical-pad-bits.pem"),
            read_text("negative", "P05-missing-padding.pem"),
        ];
        for text in &cases {
            let mut body = Vec::new();
            let mut der = Vec::new();
            assert!(
                decode_into(text.as_bytes(), &mut body, &mut der).is_err(),
                "{text:?}"
            );
            assert!(!body.is_empty(), "{text:?}: the body was collected");
            assert!(body.iter().all(|&x| x == 0), "{text:?}: body {body:?}");
            assert!(der.iter().all(|&x| x == 0), "{text:?}: der {der:?}");
        }
        // Bad pad bits: the DER buffer was written in full, then wiped.
        let mut body = Vec::new();
        let mut der = Vec::new();
        let p15 = read_text("negative", "P15-noncanonical-pad-bits.pem");
        assert!(decode_into(p15.as_bytes(), &mut body, &mut der).is_err());
        assert_eq!(der.len(), 91);
        assert!(der.iter().all(|&x| x == 0));
        // Success: the base64 copy is wiped, the DER is returned.
        let mut body = Vec::new();
        let mut der = Vec::new();
        let ok = block("PRIVATE KEY", b);
        assert_eq!(
            decode_into(ok.as_bytes(), &mut body, &mut der),
            Ok(Label::PrivateKey)
        );
        assert!(!body.is_empty() && body.iter().all(|&x| x == 0));
        assert_eq!(der, ed25519_der());
    }

    /// Errors carry no input text (ADR 0007, ADR 0018 §4): a marker placed in
    /// the label, the body, a header and the surrounding text never shows up
    /// in an error's `Debug` or `Display`.
    #[test]
    fn errors_never_contain_input_text() {
        const MARKER: &str = "QUJDTUFSS0VSWFla";
        let b = ED25519_BODY;
        let texts = [
            format!("{MARKER}\n{}", block("PRIVATE KEY", b)),
            format!("{}{MARKER}\n", block("PRIVATE KEY", b)),
            block(&format!("PRIVATE KEY {MARKER}"), b),
            block(&MARKER.to_ascii_lowercase(), b),
            block("PRIVATE KEY", &format!("{MARKER}{MARKER}*")),
            block("PRIVATE KEY", &format!("{MARKER}: header")),
            format!("-----BEGIN PRIVATE KEY-----\n{b}\n-----END {MARKER}-----\n"),
            format!(
                "-----BEGIN PRIVATE KEY-----\nProc-Type: {MARKER}\n\n{b}\n-----END PRIVATE KEY-----\n"
            ),
            format!("-----BEGIN {MARKER}-----\n{b}\n-----END {MARKER}-----\n"),
        ];
        let lower = MARKER.to_ascii_lowercase();
        for text in &texts {
            let err = decode(text).map(|_| ()).unwrap_err();
            for shown in [format!("{err:?}"), format!("{err}")] {
                assert!(
                    !shown.contains(MARKER) && !shown.contains(&lower),
                    "{shown}"
                );
            }
        }
    }

    // ---- size cap -----------------------------------------------------

    /// The error for input over [`MAX_INPUT_LEN`].
    const TOO_LARGE: Error = Error::InvalidKey("PEM input too large");

    /// A block of `der_len` octets under `label`, with CRLF line endings
    /// and 64-character lines, built by hand so that any label works.
    fn crlf_block(label: &str, der_len: usize) -> (String, Vec<u8>) {
        let der: Vec<u8> = (0..der_len).map(|i| (i * 31 + 7) as u8).collect();
        let mut b64 = String::new();
        b64_encode_append(&der, &mut b64);
        let mut text = format!("-----BEGIN {label}-----\r\n");
        for line in b64.as_bytes().chunks(LINE_WIDTH) {
            text.push_str(core::str::from_utf8(line).unwrap());
            text.push_str("\r\n");
        }
        text.push_str(&format!("-----END {label}-----\r\n"));
        (text, der)
    }

    /// `text` with whitespace appended until it is `len` octets long.
    fn padded(mut text: String, len: usize) -> String {
        assert!(text.len() <= len);
        let fill = len - text.len();
        text.extend(core::iter::repeat_n(' ', fill));
        text
    }

    /// The cap's formula is the size of a real block: a 64 KiB DER with CRLF
    /// line endings and the longest label is exactly the cap less the
    /// whitespace allowance, and no known label is longer (RFC 7468 §3).
    #[test]
    fn cap_is_the_largest_crlf_block_plus_whitespace() {
        assert_eq!(MAX_INPUT_LEN, 98_384);
        let (largest, _) = crlf_block("ENCRYPTED PRIVATE KEY", der::MAX_INPUT_LEN);
        assert_eq!(largest.len() + SURROUNDING_WHITESPACE, MAX_INPUT_LEN);
        for label in [
            Label::PrivateKey,
            Label::PublicKey,
            Label::EcPrivateKey,
            Label::RsaPublic,
            Label::RsaPrivate,
            Label::EncryptedPrivateKey,
        ] {
            assert!(label.as_str().unwrap().len() <= LONGEST_LABEL, "{label:?}");
        }
    }

    /// Exactly [`MAX_INPUT_LEN`] octets is read: the largest 64 KiB block
    /// with CRLF endings decodes, padded with whitespace to the cap, and the
    /// longest label is rejected for its label, not its size. One more octet
    /// is too large, whatever the block holds.
    #[test]
    fn input_at_the_cap_is_read_and_one_more_octet_is_not() {
        for label in ["EC PRIVATE KEY", "RSA PUBLIC KEY", "PRIVATE KEY"] {
            let (text, der) = crlf_block(label, der::MAX_INPUT_LEN);
            let at_cap = padded(text, MAX_INPUT_LEN);
            let (got_label, got) = decode(&at_cap).unwrap();
            assert_eq!(got_label.as_str(), Some(label));
            assert_eq!(*got, der, "{label}");
            let over = padded(at_cap, MAX_INPUT_LEN + 1);
            assert_eq!(decode(&over).map(|_| ()), Err(TOO_LARGE), "{label}");
        }
        let (text, _) = crlf_block("ENCRYPTED PRIVATE KEY", der::MAX_INPUT_LEN);
        let at_cap = padded(text, MAX_INPUT_LEN);
        assert_eq!(
            decode(&at_cap).map(|_| ()),
            Err(Error::UnsupportedAlgorithm)
        );
        let over = padded(at_cap, MAX_INPUT_LEN + 1);
        assert_eq!(decode(&over).map(|_| ()), Err(TOO_LARGE));
    }

    /// A 65 MiB input fails with the size error before any work: read back
    /// afterwards, both working buffers were never allocated, so no body was
    /// collected or decoded. The well-formed private-key block would
    /// otherwise reserve its whole body, and the `RSA PRIVATE KEY` one would
    /// be classified as unsupported (ADR 0021).
    #[test]
    fn a_65_mib_input_is_rejected_without_allocating() {
        const LEN: usize = 65 * 1024 * 1024;
        let lines = |label: &str| {
            let mut text = format!("-----BEGIN {label}-----\n");
            let line = format!("{ED25519_BODY}\n");
            while text.len() + line.len() <= LEN {
                text.push_str(&line);
            }
            padded(text, LEN)
        };
        for text in [
            lines("PRIVATE KEY"),
            lines("RSA PRIVATE KEY"),
            " ".repeat(LEN),
        ] {
            assert_eq!(text.len(), LEN);
            let mut body = Vec::new();
            let mut der = Vec::new();
            assert_eq!(
                decode_into(text.as_bytes(), &mut body, &mut der),
                Err(TOO_LARGE)
            );
            assert_eq!((body.capacity(), der.capacity()), (0, 0));
            assert_eq!(decode(&text).map(|_| ()), Err(TOO_LARGE));
        }
    }

    // ---- differential (pem-rfc7468, dev-dependency oracle) -------------

    mod properties {
        use super::super::*;
        use proptest::prelude::*;

        /// The labels of the supported key structures, which both
        /// directions of the codec handle.
        fn known_label() -> impl Strategy<Value = Label> {
            prop::sample::select(vec![
                Label::PrivateKey,
                Label::PublicKey,
                Label::EcPrivateKey,
                Label::RsaPublic,
            ])
        }

        proptest! {
            // ADR 0008 layer 2: at most 1,000 cases per property.
            #![proptest_config(ProptestConfig::with_cases(1000))]

            /// Our encoder's output decodes with `pem-rfc7468` to the same
            /// label and bytes, equals that crate's own LF encoding, and
            /// decodes with ours.
            #[test]
            fn encoder_output_decodes_with_pem_rfc7468(
                label in known_label(),
                der in proptest::collection::vec(any::<u8>(), 1..400),
            ) {
                let text = label.as_str().unwrap();
                let ours = encode(label, &der).unwrap();
                let (oracle_label, oracle_der) = pem_rfc7468::decode_vec(ours.as_bytes()).unwrap();
                prop_assert_eq!(oracle_label, text);
                prop_assert_eq!(&oracle_der, &der);
                let oracle_text =
                    pem_rfc7468::encode_string(text, pem_rfc7468::LineEnding::LF, &der).unwrap();
                prop_assert_eq!(ours.as_str(), oracle_text.as_str());
                let (back_label, back) = decode(&ours).unwrap();
                prop_assert_eq!(back_label, label);
                prop_assert_eq!(&*back, &der);
            }

            /// Our decoder is stricter than `pem-rfc7468`, never looser:
            /// whatever we accept from a mutated block, it accepts with the
            /// same label and bytes. The one deliberate difference is the
            /// whitespace around the block (ADR 0018 §2), which that crate
            /// treats differently after the END line, so the oracle gets the
            /// block with it trimmed and a final LF; everything between the
            /// boundaries is compared as is.
            #[test]
            fn accepted_input_is_accepted_by_pem_rfc7468(
                label in known_label(),
                der in proptest::collection::vec(any::<u8>(), 1..150),
                at in any::<prop::sample::Index>(),
                with in prop::sample::select(
                    "AQgw+/=-_ \t\r\n.:Pz".chars().collect::<Vec<char>>()
                ),
                insert in any::<bool>(),
            ) {
                let pem = encode(label, &der).unwrap();
                let i = at.index(pem.len());
                let mutated = if insert {
                    format!("{}{with}{}", &pem[..i], &pem[i..])
                } else {
                    format!("{}{with}{}", &pem[..i], &pem[i + 1..])
                };
                if let Ok((got_label, got)) = decode(&mutated) {
                    let trimmed = format!("{}\n", mutated.trim_matches([' ', '\t', '\r', '\n']));
                    let (oracle_label, oracle) = pem_rfc7468::decode_vec(trimmed.as_bytes())
                        .map_err(|e| TestCaseError::fail(format!("{e:?} for {mutated:?}")))?;
                    prop_assert_eq!(Some(oracle_label), got_label.as_str());
                    prop_assert_eq!(&oracle, &*got);
                }
            }
        }
    }
}
