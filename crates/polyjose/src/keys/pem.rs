//! Strict RFC 7468 textual encoding (§2, §3 Figure 3 `stricttextualmsg`):
//! one block, whitespace-only surroundings, matching BEGIN/END labels, no
//! headers, 64-character lines and canonical padded base64 (RFC 4648 §4,
//! §3.5), with LF, CRLF or CR line endings (ADR 0018 §2). Labels: `PRIVATE
//! KEY` (§10), `ENCRYPTED PRIVATE KEY` (§11), `PUBLIC KEY` (§13), plus
//! OpenSSL's `EC PRIVATE KEY` (RFC 5915 §4), `RSA PUBLIC KEY` and
//! `RSA PRIVATE KEY` (RFC 9500 §2.1).
//!
//! The decoder classifies the label from the BEGIN line before it reads the
//! body (ADR 0018 §2). A label that names no key structure fails at once
//! with [`Error::UnsupportedAlgorithm`], whatever follows. `ENCRYPTED PRIVATE
//! KEY` and `RSA PRIVATE KEY` decode normally and the caller rejects them
//! (ADR 0018 §4, ADR 0021). Every other fault is [`Error::InvalidKey`] with a
//! static detail that never quotes the input.
//!
//! A private key's PEM body is secret, so the base64 text and the decoded
//! octets are held only in buffers that are wiped on every path, and the
//! body is decoded by the constant-time codec in [`crate::util`].

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use super::types::Label;
use crate::util::b64_decode_into;
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
/// The RFC 1421 §4.6.1.1 header that starts an encrypted legacy block
/// (`Proc-Type: 4,ENCRYPTED`, as OpenSSL writes it).
const PROC_TYPE: &[u8] = b"Proc-Type:";

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
/// - [`Error::UnsupportedAlgorithm`] for a well-formed label that names no
///   supported structure, such as `CERTIFICATE` or `DSA PRIVATE KEY`
///   ([`Label::Other`]; checked before the body is read), and for a
///   `Proc-Type:` header.
/// - [`Error::InvalidKey`] for everything else that breaks the grammar.
///
/// The returned octets wipe on drop; the base64 copy is wiped before
/// returning.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "called by the PEM entry points in api.rs")
)]
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
    if label == Label::Other {
        // ADR 0018 §2: classified from the BEGIN line, before the body.
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
    /// DER the container parsers reject (ADR 0018 §4, ADR 0021).
    #[test]
    fn reject_corpus_files_are_classified() {
        let mut seen = 0;
        for dir in ["openssl", "rfc"] {
            for name in pem_files(dir)
                .into_iter()
                .filter(|n| n.starts_with("reject-"))
            {
                let got = outcome(&read_text(dir, &name)).map(|(label, _)| label);
                let want = if name.contains("-cert") || name.contains("legacy-encrypted") {
                    // CERTIFICATE (classified from the BEGIN line) and
                    // RFC 1421 Proc-Type encryption.
                    Err("UnsupportedAlgorithm")
                } else if name.contains("six-dash") {
                    Err("InvalidKey")
                } else if name.contains("pkcs8-encrypted") {
                    Ok(Label::EncryptedPrivateKey)
                } else if name.contains("private-pkcs1") {
                    Ok(Label::RsaPrivate)
                } else {
                    Ok(expected_label(&name))
                };
                assert_eq!(got, want, "{dir}/{name}");
                seen += 1;
            }
        }
        assert!(seen >= 30, "{seen} reject files");
    }

    /// An `RSA PRIVATE KEY` block decodes to its DER, which the facade
    /// rejects as unsupported (ADR 0021). (The encrypted PKCS#8 `.pem` and
    /// `.der` fixtures are two separate encryptions, so they are not a pair;
    /// `reject_corpus_files_are_classified` checks that label.)
    #[test]
    fn rsa_private_label_decodes_to_its_der() {
        assert_eq!(
            outcome(&read_text("openssl", "reject-rsa2048-private-pkcs1.pem")),
            Ok((
                Label::RsaPrivate,
                read_der("openssl", "reject-rsa2048-private-pkcs1.der")
            ))
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
}
