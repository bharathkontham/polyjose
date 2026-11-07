//! The ADR 0060 `vectors_digest` of a set of vector files, shared by the wasm-bindgen-test runner
//! (`tests/conformance.rs`, in Node and Chrome) and its host checks (`tests/vector_index.rs`).
//!
//! ADR 0060 §2–§3: one line `<id>\t<sha256 hex of the file's raw bytes>\n` per vector file read,
//! where `<id>` is the results-file id (`<path under conformance/vectors/>#0`, ADR 0034 §1 as
//! amended by ADR 0045 §4); the lines sorted by their UTF-8 bytes (not as strings and not as paths,
//! §2 "Order"); and the lowercase hex SHA-256 of their concatenation. An empty corpus has no
//! digest. SHA-256 is the `sha2` crate called directly as a test oracle, never polyjose's API
//! under test (§5).

use sha2::{Digest, Sha256};

/// The SHA-256 of the empty input: the digest of no vector at all, which parity rejects in any
/// results file (ADR 0060 §3).
pub(crate) const EMPTY_DIGEST: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The digest over `(id, raw bytes)` of every vector file read, or `None` for an empty corpus.
pub(crate) fn vectors_digest<'a>(
    files: impl IntoIterator<Item = (&'a str, &'a [u8])>,
) -> Option<String> {
    let mut lines: Vec<Vec<u8>> = files
        .into_iter()
        .map(|(id, bytes)| format!("{id}\t{}\n", hex(&Sha256::digest(bytes))).into_bytes())
        .collect();
    if lines.is_empty() {
        return None;
    }
    // ADR 0060 §2: ascending unsigned byte order of the encoded lines.
    lines.sort();
    Some(hex(&Sha256::digest(lines.concat())))
}

/// The ADR 0060 §4 worked example: `(id, bytes)` of its three vector files (its `README.md` is
/// not a vector and has no line), and the digest every implementation must give.
pub(crate) const WORKED_EXAMPLE: (&[(&str, &[u8])], &str) = (
    &[
        ("a.json#0", b"{}"),
        ("jws/b.json#0", b"{}\n"),
        ("jws-x/c.json#0", b"\xef\xbb\xbf{}"),
    ],
    "9a06f1efdd269176088cb0e6bfc6a7e4d4f74aa3d1b1b8fc6c879fdbb82ac7d1",
);
