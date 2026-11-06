//! Strict RFC 7468 textual encoding (§2, §3 Figure 3 `stricttextualmsg`):
//! one block, whitespace-only surroundings, matching BEGIN/END labels, no
//! headers, 64-character lines and canonical padded base64 (RFC 4648 §4,
//! §3.5), with LF, CRLF or CR line endings (ADR 0018 §2). Labels: `PRIVATE
//! KEY` (§10), `ENCRYPTED PRIVATE KEY` (§11), `PUBLIC KEY` (§13), plus
//! OpenSSL's `EC PRIVATE KEY` (RFC 5915 §4), `RSA PUBLIC KEY` and
//! `RSA PRIVATE KEY` (RFC 9500 §2.1).
//!
//! Filled in by task T03 of the keys feature.
