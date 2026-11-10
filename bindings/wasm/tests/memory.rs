//! Secret residue in wasm linear memory (feature 0006 F03; ADR 0030 §7, ADR 0031 §3, ADR 0058;
//! 0006 review S2, N7 and security audit L3), under `wasm-pack test --node` and
//! `wasm-pack test --headless --chrome --features browser` (`bindings/wasm/test.sh`).
//!
//! Every secret-bearing export runs with fresh random secrets: keys, payloads, plaintext, `aad`,
//! DER and PEM imports and exports, the PBES2 password, and the private JWKs that the exports
//! generate or return. Then the whole `wasm_bindgen::memory()` buffer is scanned for each secret
//! in the forms it takes there: the raw octets, and the base64url text of a JWK member or a token
//! segment (RFC 7515 §2, RFC 7517 §4). The adapter's claim (ADR 0030 §7.1–§7.3, `src/lib.rs`) is
//! **no copy on the Rust heap**. Every exception is an entry of [`KNOWN`], with its exact count
//! and its reason. Anything else fails the test, a copy on the shadow stack included, and so does
//! a known exception that no longer occurs.
//!
//! # How a scan works
//!
//! - **Secrets live in JS until an export receives them.** The test makes them in JavaScript
//!   (`crypto.getRandomValues`, in the `inline_js` module below). It hands them over the way the
//!   glue does:
//!   - `JsValue::as_string`, which is `passStringToWasm0`: an allocation of exactly the string's
//!     length that Rust then owns;
//!   - `Uint8Array::to_vec`, with exact capacity.
//!
//!   The value moves straight into the export. Results stay `JsValue`s, and the secret forms of a
//!   result (a generated `d`, a PEM text) are taken apart in JS. So the test itself never puts a
//!   copy into wasm memory. The only copies there are the ones the export, the surface, the core,
//!   the primitives and the framework make.
//! - **Snapshots.** Each call runs between two JS-side copies of the whole buffer
//!   (`memory.buffer.slice(0)`, [`measure`]):
//!   - Before the first copy, the test zeroes 192 KiB of shadow stack below its frame
//!     ([`scrub_stack`]). Earlier setup steps then leave no fragments, and a stack hit belongs to
//!     the measured call.
//!   - The call runs below a 16 KiB zeroed pad ([`padded`]). The second snapshot is then taken
//!     from frames that lie inside the pad, not over the call's own dead frames, which would
//!     overwrite the residue before it is seen. The test of the scanner checks this with a
//!     planted stack copy.
//!   - Only occurrences that are new in the second snapshot count, by address. A heap copy of an
//!     earlier step is already a failure of that step.
//! - **Full and partial copies.** A *full* copy is the whole secret at one address. A *partial*
//!   copy is one or more aligned 8-byte windows of the secret (`secret[8i..8i+8]`), all at the
//!   offsets they would have if a copy started at one address, and not inside a full copy. This is
//!   the measure of security audit L3. A freed block loses its first bytes to the allocator's
//!   free-list links, so an unwiped freed copy usually shows as partial. A partial copy on the
//!   heap fails the test like a full one. An 8-byte window matches by chance with probability
//!   about 2^-64 (raw octets) or 2^-48 (base64url text) per address. Forms with public structure
//!   are left out or cut down to their random part (a DER output holds the public point, a JWT
//!   holds its header), since a public copy would match them. The one exception is a PEM body,
//!   whose first characters encode the DER prefix, a structure only PEM keys carry.
//!
//! # Telling the shadow stack from the heap
//!
//! rustc links `wasm32-unknown-unknown` with wasm-ld `--stack-first -z stack-size=1048576`
//! (`rustc -Z unstable-options --print target-spec-json --target wasm32-unknown-unknown`,
//! `pre-link-args`). Linear memory is laid out as:
//!
//! 1. the shadow stack, `[0, 1 MiB)`, growing down from `__stack_pointer`'s initial value;
//! 2. the static data;
//! 3. the heap. dlmalloc grows memory past `__heap_base` with `memory.grow`.
//!
//! An address below the module's static data is therefore on the shadow stack. [`Layout::now`]
//! takes three addresses, with no `unsafe`: a static ([`DATA_ANCHOR`]), a local and a fresh `Box`.
//! It **asserts** local < static < heap, so a change of layout fails the test instead of
//! misclassifying. Anything at or above the static counts as heap. A random secret cannot be part
//! of the static data, and copies already present in the first snapshot don't count. The boundary
//! is conservative: rodata below `DATA_ANCHOR` would count as stack. So a heap copy never counts as
//! stack, and a stack copy never as heap.
//!
//! # Build profiles
//!
//! `test.sh` runs the dev profile. Stack fragments depend on code generation, so each stack
//! exception gives two counts. One is for the dev profile. The other is for the release profile
//! with the package's `opt-level = "z"` (`scripts/build-package.sh`, ADR 0059), the code the
//! shipped `.wasm` is made of before wasm-opt. These commands check the release counts:
//!
//! ```text
//! wasm-pack test --release --node -- --config 'profile.release.opt-level="z"' --test memory
//! wasm-pack test --release --headless --chrome --chromedriver <driver> --features browser \
//!     --config 'profile.release.opt-level="z"' --test memory
//! ```
//!
//! A plain `--release` (opt-level 3) is not one of the measured builds, and its stack counts
//! differ. Heap counts are the same in every build: the heap is what the adapter promises.
#![cfg(target_arch = "wasm32")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a panic is a failed assertion

mod common;

use std::collections::{BTreeMap, BTreeSet};

use js_sys::{Array, JsString, Object, Reflect, Uint8Array, Uint32Array};
use polyjose_wasm::{jwe, jwk, jws, jwt, keys, util};
use wasm_bindgen::prelude::*;
use wasm_bindgen_test::{console_log, wasm_bindgen_test};
use zeroize::Zeroize;

#[cfg(feature = "browser")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

// The JS half of the test: secrets are made, encoded and taken apart here, and memory is copied
// and searched here, so none of this puts a secret into wasm memory.
#[wasm_bindgen(inline_js = r#"
const utf8Encoder = new TextEncoder();
function b64(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}
function cat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
}
export function rand(n) {
  const out = new Uint8Array(n);
  globalThis.crypto.getRandomValues(out);
  return out;
}
export function b64u(bytes) {
  return b64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
export function unb64u(text) {
  const s = atob(text.replace(/-/g, "+").replace(/_/g, "/"));
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}
export function utf8(text) { return utf8Encoder.encode(text); }
export function member(json, name) { return JSON.parse(json)[name]; }
export function octJwk(k, kid) {
  const jwk = { kty: "oct", k: b64u(k) };
  if (kid !== undefined) jwk.kid = kid;
  return JSON.stringify(jwk);
}
export function withKidFirst(k, kid) { return JSON.stringify({ kid, kty: "oct", k: b64u(k) }); }
export function withKid(jwk, kid) { const o = JSON.parse(jwk); o.kid = kid; return JSON.stringify(o); }
export function jwks(...members) { return JSON.stringify({ keys: members.map((m) => JSON.parse(m)) }); }
// RFC 7519 §4.1 claims whose only random part, `sub`, starts at offset 9, a multiple of 3: the
// base64url of the claims then holds the base64url of the marker's first 30 bytes verbatim.
export function claims(marker) { return `{"sub": "${marker}","exp":4102444800}`; }
export function markerSegment(marker) { return b64u(utf8Encoder.encode(marker).subarray(0, 30)); }
// RFC 5958 OneAsymmetricKey around an RFC 5915 ECPrivateKey on P-256 (no public key).
export function p256Pkcs8(d) {
  return cat(Uint8Array.from([0x30, 0x41, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
    0x04, 0x27, 0x30, 0x25, 0x02, 0x01, 0x01, 0x04, 0x20]), d);
}
// RFC 8410 §7 OneAsymmetricKey for Ed25519.
export function ed25519Pkcs8(d) {
  return cat(Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65,
    0x70, 0x04, 0x22, 0x04, 0x20]), d);
}
// RFC 7468 §10 textual encoding, and the base64 lines between its boundaries.
export function pem(label, der) {
  const lines = b64(der).match(/.{1,64}/g).join("\n");
  return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----\n`;
}
export function pemBody(text) {
  return text.split("\n").filter((l) => l !== "" && !l.startsWith("-----")).join("\n");
}
export function bytesEqual(a, b) {
  return a instanceof Uint8Array && a.length === b.length && a.every((x, i) => x === b[i]);
}
export function snapshot(memory) { return new Uint8Array(memory.buffer.slice(0)); }
function find(mem, pat) {
  const out = [];
  const last = mem.length - pat.length;
  for (let i = mem.indexOf(pat[0]); i !== -1 && i <= last; i = mem.indexOf(pat[0], i + 1)) {
    let j = 1;
    while (j < pat.length && mem[i + j] === pat[j]) j++;
    if (j === pat.length) out.push(i);
  }
  return out;
}
// [n, n full-copy addresses, then (start, window offset) pairs of the partial windows], where
// start is the address a copy holding that window would begin at.
export function scan(mem, secret) {
  const full = find(mem, secret);
  const out = [full.length, ...full];
  for (let w = 0; w + 8 <= secret.length; w += 8) {
    for (const at of find(mem, secret.subarray(w, w + 8))) {
      if (!full.some((s) => at >= s && at < s + secret.length)) out.push(at - w, w);
    }
  }
  return Uint32Array.from(out);
}
"#)]
extern "C" {
    fn rand(n: u32) -> Uint8Array;
    fn b64u(bytes: &Uint8Array) -> JsValue;
    fn unb64u(text: &JsValue) -> Uint8Array;
    fn utf8(text: &JsValue) -> Uint8Array;
    fn member(json: &JsValue, name: &str) -> JsValue;
    #[wasm_bindgen(js_name = octJwk)]
    fn oct_jwk(k: &Uint8Array, kid: Option<&str>) -> JsValue;
    #[wasm_bindgen(js_name = withKidFirst)]
    fn with_kid_first(k: &Uint8Array, kid: &str) -> JsValue;
    #[wasm_bindgen(js_name = withKid)]
    fn with_kid(jwk: &JsValue, kid: &str) -> JsValue;
    #[wasm_bindgen(variadic)]
    fn jwks(members: &Array) -> JsValue;
    fn claims(marker: &JsValue) -> JsValue;
    #[wasm_bindgen(js_name = markerSegment)]
    fn marker_segment(marker: &JsValue) -> JsValue;
    #[wasm_bindgen(js_name = p256Pkcs8)]
    fn p256_pkcs8(d: &Uint8Array) -> Uint8Array;
    #[wasm_bindgen(js_name = ed25519Pkcs8)]
    fn ed25519_pkcs8(d: &Uint8Array) -> Uint8Array;
    fn pem(label: &str, der: &Uint8Array) -> JsValue;
    #[wasm_bindgen(js_name = pemBody)]
    fn pem_body(text: &JsValue) -> JsValue;
    #[wasm_bindgen(js_name = bytesEqual)]
    fn bytes_equal(a: &JsValue, b: &Uint8Array) -> bool;
    fn snapshot(memory: &JsValue) -> Uint8Array;
    fn scan(memory: &Uint8Array, secret: &Uint8Array) -> Uint32Array;
}

// --- Known exceptions -------------------------------------------------------------------------

/// What a call left of one secret: new full and partial copies on the shadow stack, and new
/// copies on the heap. A heap copy counts once whether it is full or partial: a freed block shows
/// as either, depending on whether the allocator has written into it yet.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Residue {
    stack_full: usize,
    stack_partial: usize,
    heap: usize,
}

/// No copy anywhere: the claim for every case and secret not in [`KNOWN`].
const NONE: Residue = r(0, 0, 0);

/// `(stack full, stack partial, heap)`.
const fn r(stack_full: usize, stack_partial: usize, heap: usize) -> Residue {
    Residue {
        stack_full,
        stack_partial,
        heap,
    }
}

/// A measured exception: `secret` in `case` leaves `dev` in the dev profile (`test.sh`) and
/// `release` in the release profile at the package's opt-level (module doc, "Build profiles"),
/// for the reason `why`.
struct Known {
    case: &'static str,
    secret: &'static str,
    dev: Residue,
    release: Residue,
    why: &'static str,
}

const fn known(
    case: &'static str,
    secret: &'static str,
    dev: Residue,
    release: Residue,
    why: &'static str,
) -> Known {
    Known {
        case,
        secret,
        dev,
        release,
        why,
    }
}

// Why a heap copy is accepted. Each is a decision on record, or a framework edge.
const JWT_CLAIMS: &str = "JWT claims are plain text, outside ADR 0030 §7 (ADR 0058 owner \
    decision 2): the core's parsed claim values and the surface's `claims` String are not wiped";
const GLUE_REALLOC: &str = "wasm-bindgen's passStringToWasm0 moved the block of a non-ASCII \
    string and freed the old one with its ASCII prefix (review N7, framework glue)";

// Not residue: a copy that is part of the call's output (orchestrator, 2026-11-07).
const JWE_JSON_AAD: &str = "output token content (RFC 7516 §7.2.1): the JWE JSON \
    serialization's `aad` member is base64url(aad) in the clear, and src/jwe.rs returns the \
    serialized JWE, a public result, as an owned String";

// Why a shadow-stack fragment occurs: a primitive's own frame, which `Zeroizing` never reaches
// and the adapter does not scrub (src/lib.rs, "Secrets"). Feature 0012 owns these (core backlog).
const HMAC_KEY: &str = "HMAC key block (hmac 0.13; review S2: HS256 `k` in full)";
const AES_KEY: &str = "AES key, or the MAC half of an A*CBC-HS* key, in the cipher's key setup";
const HASH_INPUT: &str = "SHA-2 block buffer of the hash input (the JWS signing input, the \
    RFC 7638 thumbprint input)";
const CIPHER_BLOCKS: &str = "decrypted AES-GCM or AES-CBC blocks (audit L3 measured the \
    A128CBC-HS256 case on the package)";
const EC_SCALAR: &str = "scalar temporaries of EC key generation (audit L3: P-256 `d`, 16 of \
    32 bytes)";
const X25519_SCALAR: &str = "the X25519 scalar in x25519-dalek's Diffie-Hellman frames";

/// Every exception to "no copy", measured with the commands of the module doc (dev:
/// `bindings/wasm/test.sh`; release: the package's opt-level z, without wasm-opt). Entries are
/// `known(case, secret, dev, release, why)`, with each count as `r(stack full, stack partial,
/// heap)`. A count that differs, in either direction, fails the test: a fix updates the entry,
/// and a new copy needs an entry and a reason.
///
/// For the record, the review and the audit measured the built package (opt-level z plus
/// wasm-opt -Oz): HS256 `k` 1 full stack copy (S2), P-256 `d` 16 bytes and the A128CBC-HS256
/// plaintext 32 of 64 bytes on the stack (L3). The release column reproduces the first two
/// exactly; wasm-opt rearranges the frames that held the third.
#[rustfmt::skip] // one entry per line
const KNOWN: &[Known] = &[
    // On the heap: output token content (RFC 7516 §7.2.1), not residue.
    known("jweEncryptJson(A128KW + A128CBC-HS256, aad)", "aad (base64url)", r(0, 0, 1), r(0, 0, 1), JWE_JSON_AAD),
    known("jweEncryptJson(A256GCMKW + A256GCM, aad)", "aad (base64url)", r(0, 0, 1), r(0, 0, 1), JWE_JSON_AAD),
    known("jweEncryptJson(ECDH-ES + A256GCM, aad)", "aad (base64url)", r(0, 0, 1), r(0, 0, 1), JWE_JSON_AAD),
    known("jweEncryptJson(ECDH-ES+A128KW + A128GCM, aad)", "aad (base64url)", r(0, 0, 1), r(0, 0, 1), JWE_JSON_AAD),
    known("jweEncryptJson(PBES2-HS256+A128KW + A128GCM, aad)", "aad (base64url)", r(0, 0, 1), r(0, 0, 1), JWE_JSON_AAD),
    known("jweEncryptJson(dir + A128CBC-HS256, aad)", "aad (base64url)", r(0, 0, 1), r(0, 0, 1), JWE_JSON_AAD),
    known("jweEncryptJson(dir + A128GCM, aad)", "aad (base64url)", r(0, 0, 1), r(0, 0, 1), JWE_JSON_AAD),
    // On the heap: residue.
    known("glue: a non-ASCII string whose block moved", "k (base64url)", r(0, 0, 1), r(0, 0, 1), GLUE_REALLOC),
    known("jwtDecryptNested", "claims sub", r(0, 0, 2), r(0, 0, 2), JWT_CLAIMS),
    known("jwtDecryptNestedWithJwks", "claims sub", r(0, 0, 2), r(0, 0, 2), JWT_CLAIMS),
    known("jwtSign(HS512)", "claims sub", r(0, 0, 1), r(0, 0, 1), JWT_CLAIMS),
    known("jwtVerify(HS512)", "claims sub", r(0, 0, 2), r(0, 0, 2), JWT_CLAIMS),
    known("jwtVerifyWithJwks(HS512)", "claims sub", r(0, 0, 2), r(0, 0, 2), JWT_CLAIMS),
    // On the shadow stack.
    known("jweDecryptCompact(A128KW + A128CBC-HS256)", "k", r(0, 0, 0), r(1, 1, 0), AES_KEY),
    known("jweDecryptCompact(A128KW + A128CBC-HS256)", "plaintext", r(2, 0, 0), r(0, 0, 0), CIPHER_BLOCKS),
    known("jweDecryptCompact(A256GCMKW + A256GCM)", "plaintext", r(2, 0, 0), r(0, 0, 0), CIPHER_BLOCKS),
    known("jweDecryptCompact(ECDH-ES + A256GCM)", "plaintext", r(2, 0, 0), r(0, 0, 0), CIPHER_BLOCKS),
    known("jweDecryptCompact(ECDH-ES + A256GCM)", "private key", r(3, 0, 0), r(1, 0, 0), X25519_SCALAR),
    known("jweDecryptCompact(ECDH-ES+A128KW + A128GCM)", "plaintext", r(2, 0, 0), r(0, 0, 0), CIPHER_BLOCKS),
    known("jweDecryptCompact(PBES2-HS256+A128KW + A128GCM)", "plaintext", r(2, 0, 0), r(0, 0, 0), CIPHER_BLOCKS),
    known("jweDecryptCompact(dir + A128CBC-HS256)", "k", r(0, 0, 0), r(0, 3, 0), AES_KEY),
    known("jweDecryptCompact(dir + A128CBC-HS256)", "plaintext", r(2, 0, 0), r(0, 0, 0), CIPHER_BLOCKS),
    known("jweDecryptCompact(dir + A128GCM)", "k", r(0, 0, 0), r(0, 1, 0), AES_KEY),
    known("jweDecryptCompact(dir + A128GCM)", "plaintext", r(2, 0, 0), r(0, 0, 0), CIPHER_BLOCKS),
    known("jweDecryptCompact(wrong key): DecryptionFailed", "wrong k", r(0, 0, 0), r(1, 1, 0), AES_KEY),
    known("jweDecryptJson(A128KW + A128CBC-HS256, aad)", "k", r(0, 0, 0), r(1, 1, 0), AES_KEY),
    known("jweDecryptJson(A128KW + A128CBC-HS256, aad)", "plaintext", r(2, 0, 0), r(0, 0, 0), CIPHER_BLOCKS),
    known("jweDecryptJson(A256GCMKW + A256GCM, aad)", "plaintext", r(2, 0, 0), r(0, 0, 0), CIPHER_BLOCKS),
    known("jweDecryptJson(ECDH-ES + A256GCM, aad)", "plaintext", r(2, 0, 0), r(0, 0, 0), CIPHER_BLOCKS),
    known("jweDecryptJson(ECDH-ES + A256GCM, aad)", "private key", r(3, 0, 0), r(1, 0, 0), X25519_SCALAR),
    known("jweDecryptJson(ECDH-ES+A128KW + A128GCM, aad)", "plaintext", r(2, 0, 0), r(0, 0, 0), CIPHER_BLOCKS),
    known("jweDecryptJson(PBES2-HS256+A128KW + A128GCM, aad)", "plaintext", r(2, 0, 0), r(0, 0, 0), CIPHER_BLOCKS),
    known("jweDecryptJson(dir + A128CBC-HS256, aad)", "k", r(0, 0, 0), r(0, 3, 0), AES_KEY),
    known("jweDecryptJson(dir + A128CBC-HS256, aad)", "plaintext", r(2, 0, 0), r(0, 0, 0), CIPHER_BLOCKS),
    known("jweDecryptJson(dir + A128GCM, aad)", "k", r(0, 0, 0), r(0, 1, 0), AES_KEY),
    known("jweDecryptJson(dir + A128GCM, aad)", "plaintext", r(2, 0, 0), r(0, 0, 0), CIPHER_BLOCKS),
    known("jweEncryptCompact(A128KW + A128CBC-HS256)", "k", r(0, 0, 0), r(1, 1, 0), AES_KEY),
    known("jweEncryptCompact(dir + A128CBC-HS256)", "k", r(0, 0, 0), r(0, 1, 0), AES_KEY),
    known("jweEncryptCompact(dir + A128GCM)", "k", r(0, 0, 0), r(0, 1, 0), AES_KEY),
    known("jweEncryptJson(A128KW + A128CBC-HS256, aad)", "k", r(0, 0, 0), r(1, 1, 0), AES_KEY),
    known("jweEncryptJson(dir + A128CBC-HS256, aad)", "k", r(0, 0, 0), r(0, 1, 0), AES_KEY),
    known("jweEncryptJson(dir + A128GCM, aad)", "k", r(0, 0, 0), r(0, 1, 0), AES_KEY),
    known("jwkGenerateEc(P-256)", "private key", r(0, 0, 0), r(0, 1, 0), EC_SCALAR),
    known("jwkGenerateEc(P-384)", "private key", r(0, 0, 0), r(0, 2, 0), EC_SCALAR),
    known("jwkGenerateEc(P-521)", "private key", r(0, 0, 0), r(0, 1, 0), EC_SCALAR),
    known("jwkGenerateEc(secp256k1)", "private key", r(0, 0, 0), r(1, 2, 0), EC_SCALAR),
    known("jwkGenerateForAlg(ES256)", "private key", r(0, 0, 0), r(0, 1, 0), EC_SCALAR),
    known("jwkThumbprint(oct, SHA-256)", "k (base64url)", r(0, 0, 0), r(1, 0, 0), HASH_INPUT),
    known("jwkThumbprintUri(oct, SHA-512)", "k (base64url)", r(2, 1, 0), r(2, 0, 0), HASH_INPUT),
    known("jwsSignCompact(ES256)", "payload (base64url)", r(0, 0, 0), r(0, 1, 0), HASH_INPUT),
    known("jwsSignCompact(EdDSA)", "payload (base64url)", r(1, 4, 0), r(0, 2, 0), HASH_INPUT),
    known("jwsSignCompact(HS256)", "k", r(0, 0, 0), r(1, 0, 0), HMAC_KEY),
    known("jwsSignCompact(HS256)", "payload (base64url)", r(0, 3, 0), r(0, 2, 0), HASH_INPUT),
    known("jwsSignCompact(HS384)", "k", r(0, 0, 0), r(0, 1, 0), HMAC_KEY),
    known("jwsSignCompact(HS384)", "payload (base64url)", r(3, 1, 0), r(1, 1, 0), HASH_INPUT),
    known("jwsSignCompact(HS512)", "k", r(0, 0, 0), r(0, 1, 0), HMAC_KEY),
    known("jwsSignCompact(HS512)", "payload (base64url)", r(3, 0, 0), r(1, 1, 0), HASH_INPUT),
    known("jwsSignCompact(HS512, detached)", "k", r(0, 0, 0), r(0, 1, 0), HMAC_KEY),
    known("jwsSignCompact(HS512, detached)", "payload (base64url)", r(3, 0, 0), r(1, 1, 0), HASH_INPUT),
    known("jwsSignFlattened(HS512)", "k", r(0, 0, 0), r(0, 1, 0), HMAC_KEY),
    known("jwsSignFlattened(HS512)", "payload (base64url)", r(3, 0, 0), r(1, 1, 0), HASH_INPUT),
    known("jwsSignGeneral(HS512, ES256)", "payload (base64url)", r(0, 0, 0), r(0, 1, 0), HASH_INPUT),
    known("jwsVerifyCompact(ES256)", "payload (base64url)", r(0, 2, 0), r(0, 1, 0), HASH_INPUT),
    known("jwsVerifyCompact(EdDSA)", "payload (base64url)", r(0, 4, 0), r(0, 4, 0), HASH_INPUT),
    known("jwsVerifyCompact(HS256)", "k", r(0, 0, 0), r(1, 0, 0), HMAC_KEY),
    known("jwsVerifyCompact(HS256)", "payload (base64url)", r(0, 2, 0), r(0, 3, 0), HASH_INPUT),
    known("jwsVerifyCompact(HS384)", "k", r(0, 0, 0), r(0, 1, 0), HMAC_KEY),
    known("jwsVerifyCompact(HS384)", "payload (base64url)", r(4, 1, 0), r(2, 0, 0), HASH_INPUT),
    known("jwsVerifyCompact(HS512)", "k", r(0, 0, 0), r(0, 1, 0), HMAC_KEY),
    known("jwsVerifyCompact(HS512)", "payload (base64url)", r(4, 0, 0), r(2, 0, 0), HASH_INPUT),
    known("jwsVerifyCompact(HS512, detached)", "k", r(0, 0, 0), r(0, 1, 0), HMAC_KEY),
    known("jwsVerifyCompact(HS512, detached)", "payload (base64url)", r(4, 0, 0), r(2, 0, 0), HASH_INPUT),
    known("jwsVerifyCompact(wrong key): InvalidSignature", "payload (base64url)", r(5, 0, 0), r(2, 0, 0), HASH_INPUT),
    known("jwsVerifyJson(HS512)", "k", r(0, 0, 0), r(0, 1, 0), HMAC_KEY),
    known("jwsVerifyJson(HS512)", "payload (base64url)", r(4, 0, 0), r(2, 0, 0), HASH_INPUT),
    known("jwtDecryptNested", "k", r(0, 0, 0), r(0, 1, 0), HMAC_KEY),
    known("jwtDecryptNestedWithJwks", "k", r(0, 0, 0), r(0, 1, 0), HMAC_KEY),
    known("jwtEncryptNested(A128KW + A128GCM)", "key-encryption k", r(0, 0, 0), r(1, 1, 0), AES_KEY),
    known("jwtSign(HS512)", "k", r(0, 0, 0), r(0, 1, 0), HMAC_KEY),
    known("jwtVerify(HS512)", "k", r(0, 0, 0), r(0, 1, 0), HMAC_KEY),
    known("jwtVerifyWithJwks(HS512)", "k", r(0, 0, 0), r(0, 1, 0), HMAC_KEY),
];

// --- Layout -----------------------------------------------------------------------------------

/// A static in the module's data, above the shadow stack and below the heap (`--stack-first`).
static DATA_ANCHOR: [u8; 8] = *b"F03-data";

/// How much shadow stack below the test's frame [`scrub_stack`] zeroes: more than [`PAD_BYTES`]
/// plus the deepest stack hit measured (about 70 KiB below the stack top in the dev profile).
const SCRUB_BYTES: usize = 192 * 1024;

/// The zeroed pad between the snapshots' frames and the measured call's frames ([`padded`]).
const PAD_BYTES: usize = 16 * 1024;

/// The boundary between the shadow stack and the rest of linear memory (module doc, "Telling the
/// shadow stack from the heap").
#[derive(Clone, Copy, Debug)]
struct Layout {
    /// The address of [`DATA_ANCHOR`]: everything below it is shadow stack.
    data: u32,
}

impl Layout {
    #[inline(never)]
    fn now() -> Self {
        let local = core::hint::black_box(0u8);
        let stack = core::ptr::addr_of!(local) as usize;
        let data = DATA_ANCHOR.as_ptr() as usize;
        let boxed = Box::new(core::hint::black_box(0u8));
        let heap = core::ptr::addr_of!(*boxed) as usize;
        assert!(
            stack < data && data < heap,
            "linear memory is not stack, then data, then heap (--stack-first): a local at \
             {stack:#x}, a static at {data:#x}, a heap block at {heap:#x}"
        );
        assert!(
            stack > SCRUB_BYTES,
            "the test frame at {stack:#x} is too close to the stack's end"
        );
        Self {
            data: u32::try_from(data).unwrap(),
        }
    }

    fn on_stack(self, address: u32) -> bool {
        address < self.data
    }
}

/// Zeroes the [`SCRUB_BYTES`] of dead shadow stack below the caller's frame, so fragments left by
/// earlier setup steps don't count against the next measured call. This is test hygiene, not
/// something the adapter does (`src/lib.rs`, "Secrets").
#[inline(never)]
fn scrub_stack() {
    let mut frame = [0u8; SCRUB_BYTES];
    frame.zeroize();
    core::hint::black_box(&frame);
}

/// Runs `call` [`PAD_BYTES`] deeper on the shadow stack than the caller would, so the caller's
/// next calls (the second snapshot) don't overwrite `call`'s dead frames.
#[inline(never)]
fn padded<R>(call: impl FnOnce() -> R) -> R {
    let pad = [0u8; PAD_BYTES];
    core::hint::black_box(&pad);
    call()
}

// --- Secrets and measurements -------------------------------------------------------------------

/// One form of a secret as it may sit in wasm memory. The bytes are a JS `Uint8Array`, never
/// copied into wasm memory by the test.
struct Secret {
    name: &'static str,
    bytes: Uint8Array,
}

impl Secret {
    fn new(name: &'static str, bytes: Uint8Array) -> Self {
        assert!(
            bytes.length() >= 16,
            "{name}: a secret shorter than 16 bytes could match by chance"
        );
        Self { name, bytes }
    }

    fn text(name: &'static str, text: &JsValue) -> Self {
        Self::new(name, utf8(text))
    }
}

/// A secret's raw octets and the base64url text a JWK member or a token segment carries
/// (RFC 7515 §2).
struct Octets {
    raw: Secret,
    text: Secret,
}

impl Octets {
    /// Fresh random octets.
    fn random(raw: &'static str, text: &'static str, len: u32) -> Self {
        Self::of(raw, text, rand(len))
    }

    fn of(raw: &'static str, text: &'static str, bytes: Uint8Array) -> Self {
        let encoded = b64u(&bytes);
        Self {
            raw: Secret::new(raw, bytes),
            text: Secret::text(text, &encoded),
        }
    }

    /// The member `name` (base64url) of the JSON text `json`, for example a JWK's `d`.
    fn member(raw: &'static str, text: &'static str, json: &JsValue, name: &str) -> Self {
        let encoded = member(json, name);
        assert!(encoded.is_string(), "{raw}: no member `{name}`");
        Self {
            raw: Secret::new(raw, unb64u(&encoded)),
            text: Secret::text(text, &encoded),
        }
    }
}

/// Linear memory right before and right after one call, as JS-side copies.
struct Measured {
    before: Uint8Array,
    after: Uint8Array,
}

/// Runs `call` between two snapshots of linear memory, on a scrubbed shadow stack, below a pad.
fn measure<R>(call: impl FnOnce() -> R) -> (Measured, R) {
    scrub_stack();
    let before = snapshot(&wasm_bindgen::memory());
    let out = padded(call);
    let after = snapshot(&wasm_bindgen::memory());
    (Measured { before, after }, out)
}

/// The copies of a secret in one snapshot: full copies by address, and partial copies by the
/// address they start at, with how many of the secret's 8-byte windows each holds.
struct Found {
    full: BTreeSet<u32>,
    partial: BTreeMap<u32, usize>,
}

fn find(memory: &Uint8Array, secret: &Secret) -> Found {
    let found = scan(memory, &secret.bytes).to_vec();
    let n = found[0] as usize;
    let mut partial = BTreeMap::new();
    for pair in found[n + 1..].chunks(2) {
        *partial.entry(pair[0]).or_insert(0) += 1;
    }
    Found {
        full: found[1..=n].iter().copied().collect(),
        partial,
    }
}

/// The copies `call` added, split by region, formatted for the report.
#[derive(Default)]
struct Region {
    full: Vec<String>,
    partial: Vec<String>,
}

/// The results of one test, reported together so one run shows every measured case.
struct Report {
    layout: Layout,
    lines: Vec<String>,
    failures: usize,
}

impl Report {
    fn new() -> Self {
        common::check_engine().unwrap_or_else(|e| panic!("{e}"));
        Self {
            layout: Layout::now(),
            lines: Vec::new(),
            failures: 0,
        }
    }

    /// Checks each secret against `m`: [`NONE`], or its [`KNOWN`] entry for `case`.
    fn check(&mut self, case: &str, m: &Measured, secrets: &[&Secret]) {
        for (i, secret) in secrets.iter().enumerate() {
            assert!(
                secrets[..i].iter().all(|s| s.name != secret.name),
                "{case}: two secrets named {}",
                secret.name
            );
            let before = find(&m.before, secret);
            let after = find(&m.after, secret);
            let (mut stack, mut heap) = (Region::default(), Region::default());
            for &a in after.full.difference(&before.full) {
                let region = if self.layout.on_stack(a) {
                    &mut stack
                } else {
                    &mut heap
                };
                region.full.push(format!("{a:#x}"));
            }
            let windows = secret.bytes.length() / 8;
            for (&a, &n) in after
                .partial
                .iter()
                .filter(|(a, _)| !before.partial.contains_key(a))
            {
                let region = if self.layout.on_stack(a) {
                    &mut stack
                } else {
                    &mut heap
                };
                region.partial.push(format!("{a:#x} ({n}/{windows})"));
            }
            let got = r(
                stack.full.len(),
                stack.partial.len(),
                heap.full.len() + heap.partial.len(),
            );
            let entry = KNOWN
                .iter()
                .find(|k| k.case == case && k.secret == secret.name);
            let want = entry.map_or(NONE, |k| {
                if cfg!(debug_assertions) {
                    k.dev
                } else {
                    k.release
                }
            });
            let ok = got == want;
            self.failures += usize::from(!ok);
            if !ok || got != NONE {
                self.lines.push(format!(
                    "{} {case} / {}: r({}, {}, {}) stack full {:?} partial {:?}, heap full {:?} \
                     partial {:?}{}",
                    if ok { "known" } else { "UNEXPECTED" },
                    secret.name,
                    got.stack_full,
                    got.stack_partial,
                    got.heap,
                    stack.full,
                    stack.partial,
                    heap.full,
                    heap.partial,
                    entry.map_or(String::new(), |k| format!("; expected {want:?}: {}", k.why)),
                ));
            }
        }
    }

    /// Prints the known residue, and fails on any residue that differs from [`KNOWN`].
    fn finish(self) {
        let summary = format!(
            "residue ({}; static data from {:#x}, below it is shadow stack):\n{}",
            if cfg!(debug_assertions) {
                "dev profile"
            } else {
                "release profile"
            },
            self.layout.data,
            self.lines.join("\n")
        );
        assert!(
            self.failures == 0,
            "{} residue(s) differ from KNOWN; {summary}",
            self.failures
        );
        console_log!("{summary}");
    }
}

// --- Arguments and results ----------------------------------------------------------------------

/// A string argument the way the glue passes it: Rust owns the only wasm copy, which moves into
/// the export.
fn s(value: &JsValue) -> String {
    value.as_string().expect("a string")
}

/// A byte argument the way the glue passes it (an exact-capacity `Vec<u8>`).
fn b(value: &Uint8Array) -> Vec<u8> {
    value.to_vec()
}

/// A plain object with these members (BACKEND.md, "Records").
fn object(members: &[(&str, JsValue)]) -> JsValue {
    let o = Object::new();
    for (key, value) in members {
        Reflect::set(&o, &JsValue::from_str(key), value).unwrap();
    }
    o.into()
}

fn strings(items: &[&str]) -> JsValue {
    items
        .iter()
        .map(|s| JsValue::from_str(s))
        .collect::<Array>()
        .into()
}

fn list(items: &[JsValue]) -> JsValue {
    items.iter().collect::<Array>().into()
}

fn get(object: &JsValue, key: &str) -> JsValue {
    Reflect::get(object, &JsValue::from_str(key)).unwrap()
}

fn js(value: Result<JsString, JsValue>) -> JsValue {
    value
        .map(JsValue::from)
        .unwrap_or_else(|e| panic!("the export threw {e:?}"))
}

fn ok<T>(value: Result<T, JsValue>) -> T {
    value.unwrap_or_else(|e| panic!("the export threw {e:?}"))
}

/// A random P-256 private scalar below the group order n (its top bit clear; SEC 1 §3.2.1).
fn p256_d() -> Uint8Array {
    let d = rand(32);
    d.set_index(0, d.get_index(0) & 0x7f);
    d
}

/// A new P-256 private JWK (setup: imported from PKCS #8 DER, RFC 5958).
fn p256_jwk() -> JsValue {
    js(keys::jwk_from_der(b(&p256_pkcs8(&p256_d())), "pkcs8"))
}

/// A new `oct` JWK of `len` random octets (RFC 7518 §6.4) and its `k`.
fn oct(len: u32) -> (JsValue, Octets) {
    let k = Octets::random("k", "k (base64url)", len);
    (oct_jwk(&k.raw.bytes, None), k)
}

/// A JWK's private member `name` (`d` or `k`).
fn private(jwk: &JsValue, name: &str) -> Octets {
    Octets::member("private key", "private key (base64url)", jwk, name)
}

fn protected(alg: &str) -> JsValue {
    JsValue::from_str(&format!(r#"{{"alg":"{alg}"}}"#))
}

fn verify_options(alg: &str) -> JsValue {
    object(&[("allowedAlgs", strings(&[alg]))])
}

// --- The scanner itself -------------------------------------------------------------------------

/// Plants copies of a secret and checks that the scan sees them, in the right region. So residue
/// left by an export would fail the checks below.
#[wasm_bindgen_test]
fn the_scan_finds_planted_copies_on_the_heap_and_the_stack() {
    let layout = Report::new().layout;
    let secret = Secret::new("planted", rand(32));
    let new = |m: &Measured| -> Vec<u32> {
        let (before, after) = (find(&m.before, &secret), find(&m.after, &secret));
        after.full.difference(&before.full).copied().collect()
    };

    // A live heap copy: one full copy at or above the static data.
    let (m, planted) = measure(|| b(&secret.bytes));
    let heap = new(&m);
    assert_eq!(
        heap.len(),
        1,
        "the planted heap copy was not found once: {heap:#x?}"
    );
    assert!(
        !layout.on_stack(heap[0]),
        "the heap copy at {:#x} counted as stack",
        heap[0]
    );
    drop(planted);

    // A copy in the dead frame of the measured call: below the static data, and still there
    // after the second snapshot (the pad keeps the snapshot's frames off it).
    #[inline(never)]
    fn on_stack(secret: &Uint8Array) {
        let mut frame = [0u8; 32];
        secret.copy_to(&mut frame);
        core::hint::black_box(&frame);
    }
    let (m, ()) = measure(|| on_stack(&secret.bytes));
    let stack = new(&m);
    assert_eq!(
        stack.len(),
        1,
        "the planted stack copy was not found once: {stack:#x?}"
    );
    assert!(
        layout.on_stack(stack[0]),
        "the stack copy at {:#x} counted as heap",
        stack[0]
    );

    // A freed, unwiped heap copy is residue too (full, or partial once the allocator writes its
    // links into the block), and the report counts it as a failure.
    let mut report = Report::new();
    let (m, ()) = measure(|| drop(b(&secret.bytes)));
    report.check("a planted freed copy", &m, &[&secret]);
    assert_eq!(
        report.failures, 1,
        "a freed heap copy was not reported: {:?}",
        report.lines
    );
}

/// Review N7, edge 1, the framework's and not the adapter's. The glue (`passStringToWasm0`) writes
/// a string's ASCII prefix into a block of the string's UTF-16 length, and at the first non-ASCII
/// character grows the block with realloc. If the block moves, the old one is freed unwiped with
/// the prefix in it. The export's `Zeroizing` wipes only the final block. Whether the block moves
/// depends on its heap neighbour. The test forces a move: it frees one block in the middle of a
/// run of blocks of exactly that size, so the glue's malloc gets that hole (dlmalloc's small bins
/// are last-in, first-out) and the next block is live. Nothing else allocates in between, as an
/// export's own allocations could reuse the freed block.
#[wasm_bindgen_test]
fn glue_non_ascii_string_moved_by_realloc_leaves_its_ascii_prefix() {
    let mut r = Report::new();
    let k = Octets::random("k", "k (base64url)", 32);
    let jwk = oct_jwk(&k.raw.bytes, Some("schl\u{fc}ssel-\u{1f511}"));
    let units = JsString::from(jwk.clone()).length() as usize;
    let (m, blocks) = measure(|| {
        let mut blocks: Vec<Vec<u8>> = (0..64).map(|_| Vec::with_capacity(units)).collect();
        drop(core::mem::take(&mut blocks[48]));
        drop(zeroize::Zeroizing::new(s(&jwk))); // what an export does with a `String` argument
        blocks
    });
    drop(blocks);
    r.check(
        "glue: a non-ASCII string whose block moved",
        &m,
        &[&k.raw, &k.text],
    );
    r.finish();
}

// --- Utilities ------------------------------------------------------------------------------

#[wasm_bindgen_test]
fn base64url() {
    let mut r = Report::new();
    let data = Octets::random("data", "data (base64url)", 32);
    let (m, text) = measure(|| js(Ok(util::base64url_encode(b(&data.raw.bytes)))));
    assert!(bytes_equal(&utf8(&text).into(), &data.text.bytes));
    r.check("base64urlEncode", &m, &[&data.raw, &data.text]);

    let data = Octets::random("data", "data (base64url)", 32);
    let text = b64u(&data.raw.bytes);
    let (m, out) = measure(|| ok(util::base64url_decode(s(&text))));
    assert!(bytes_equal(&out.into(), &data.raw.bytes));
    r.check("base64urlDecode", &m, &[&data.raw, &data.text]);
    r.finish();
}

// --- Key generation ---------------------------------------------------------------------------

#[wasm_bindgen_test]
fn key_generation() {
    let mut r = Report::new();
    let (m, jwk) = measure(|| js(keys::jwk_generate_oct(32)));
    let k = private(&jwk, "k");
    r.check("jwkGenerateOct(32)", &m, &[&k.raw, &k.text]);
    for crv in ["P-256", "P-384", "P-521", "secp256k1"] {
        let (m, jwk) = measure(|| js(keys::jwk_generate_ec(crv)));
        let d = private(&jwk, "d");
        r.check(&format!("jwkGenerateEc({crv})"), &m, &[&d.raw, &d.text]);
    }
    for crv in ["Ed25519", "X25519"] {
        let (m, jwk) = measure(|| js(keys::jwk_generate_okp(crv)));
        let d = private(&jwk, "d");
        r.check(&format!("jwkGenerateOkp({crv})"), &m, &[&d.raw, &d.text]);
    }
    for (alg, name) in [
        ("HS256", "k"),
        ("A128KW", "k"),
        ("A256GCM", "k"),
        ("ES256", "d"),
        ("EdDSA", "d"),
    ] {
        let (m, jwk) = measure(|| js(keys::jwk_generate_for_alg(alg)));
        let key = private(&jwk, name);
        r.check(
            &format!("jwkGenerateForAlg({alg})"),
            &m,
            &[&key.raw, &key.text],
        );
    }
    r.finish();
}

// --- PEM and DER ------------------------------------------------------------------------------

#[wasm_bindgen_test]
fn pem_and_der() {
    let mut r = Report::new();
    let d = Octets::of("d", "d (base64url)", p256_d());
    let der = p256_pkcs8(&d.raw.bytes);
    let (m, _) = measure(|| js(keys::jwk_from_der(b(&der), "pkcs8")));
    r.check("jwkFromDer(P-256, pkcs8)", &m, &[&d.raw, &d.text]);

    let d = Octets::random("d", "d (base64url)", 32);
    let der = ed25519_pkcs8(&d.raw.bytes);
    let (m, _) = measure(|| js(keys::jwk_from_der(b(&der), "pkcs8")));
    r.check("jwkFromDer(Ed25519, pkcs8)", &m, &[&d.raw, &d.text]);

    let d = Octets::of("d", "d (base64url)", p256_d());
    let text = pem("PRIVATE KEY", &p256_pkcs8(&d.raw.bytes));
    let body = Secret::text("PEM body", &pem_body(&text));
    let (m, _) = measure(|| js(keys::jwk_from_pem(s(&text))));
    r.check("jwkFromPem(P-256, pkcs8)", &m, &[&d.raw, &d.text, &body]);

    // An exported key holds `d` as raw octets (DER) and inside the PEM body's base64. The DER
    // output as a whole is not scanned: it also holds the public point, which other, public
    // copies match.
    for format in ["pkcs8", "sec1"] {
        let jwk = p256_jwk();
        let d = private(&jwk, "d");
        let (m, out) = measure(|| js(keys::jwk_to_pem(s(&jwk), format)));
        let body = Secret::text("PEM body", &pem_body(&out));
        r.check(
            &format!("jwkToPem(P-256, {format})"),
            &m,
            &[&d.raw, &d.text, &body],
        );

        let jwk = p256_jwk();
        let d = private(&jwk, "d");
        let (m, out) = measure(|| ok(keys::jwk_to_der(s(&jwk), format)));
        assert!(out.length() > 32);
        r.check(
            &format!("jwkToDer(P-256, {format})"),
            &m,
            &[&d.raw, &d.text],
        );
    }
    let jwk = js(keys::jwk_generate_okp("Ed25519"));
    let d = private(&jwk, "d");
    let (m, out) = measure(|| js(keys::jwk_to_pem(s(&jwk), "pkcs8")));
    let body = Secret::text("PEM body", &pem_body(&out));
    r.check("jwkToPem(Ed25519, pkcs8)", &m, &[&d.raw, &d.text, &body]);
    let jwk = js(keys::jwk_generate_okp("Ed25519"));
    let d = private(&jwk, "d");
    let (m, _) = measure(|| ok(keys::jwk_to_der(s(&jwk), "pkcs8")));
    r.check("jwkToDer(Ed25519, pkcs8)", &m, &[&d.raw, &d.text]);
    r.finish();
}

// --- JWK --------------------------------------------------------------------------------------

#[wasm_bindgen_test]
fn jwk_operations() {
    let mut r = Report::new();
    let (jwk, k) = oct(32);
    let (m, _) = measure(|| js(jwk::jwk_parse(s(&jwk))));
    r.check("jwkParse(oct)", &m, &[&k.raw, &k.text]);

    // A non-ASCII string goes through the glue's realloc path (review N7; see
    // `glue_non_ascii_string_moved_by_realloc_leaves_its_ascii_prefix` for what a moved block
    // leaves). The `kid` comes before `k` here, so the secret is never in the ASCII prefix.
    let k = Octets::random("k", "k (base64url)", 32);
    let jwk = with_kid_first(&k.raw.bytes, "schl\u{fc}ssel-\u{1f511}-\u{e9}t\u{e9}");
    let (m, _) = measure(|| js(jwk::jwk_parse(s(&jwk))));
    r.check(
        "jwkParse(oct, non-ASCII kid before k)",
        &m,
        &[&k.raw, &k.text],
    );

    let jwk = p256_jwk();
    let d = private(&jwk, "d");
    let (m, _) = measure(|| js(jwk::jwk_parse(s(&jwk))));
    r.check("jwkParse(P-256)", &m, &[&d.raw, &d.text]);

    let jwk = p256_jwk();
    let d = private(&jwk, "d");
    let (m, _) = measure(|| ok(jwk::jwk_to_public(s(&jwk))));
    r.check("jwkToPublic(P-256)", &m, &[&d.raw, &d.text]);

    let (jwk, k) = oct(32);
    let (m, _) = measure(|| ok(jwk::jwk_thumbprint(s(&jwk), None)));
    r.check("jwkThumbprint(oct, SHA-256)", &m, &[&k.raw, &k.text]);

    let (jwk, k) = oct(32);
    let (m, _) = measure(|| ok(jwk::jwk_thumbprint_uri(s(&jwk), Some("sha-512".to_owned()))));
    r.check("jwkThumbprintUri(oct, SHA-512)", &m, &[&k.raw, &k.text]);

    let (a, ka) = oct(32);
    let (b_jwk, kb) = oct(32);
    let kb = Octets {
        raw: Secret::new("k of b", kb.raw.bytes),
        text: Secret::new("k of b (base64url)", kb.text.bytes),
    };
    let set = jwks(
        &[with_kid(&a, "a"), with_kid(&b_jwk, "b")]
            .iter()
            .collect::<Array>(),
    );
    let selector = object(&[("kid", "b".into())]);
    let (m, _) = measure(|| js(jwk::jwks_select(s(&set), &selector)));
    r.check(
        "jwksSelect(kid)",
        &m,
        &[&ka.raw, &ka.text, &kb.raw, &kb.text],
    );
    r.finish();
}

// --- JWS --------------------------------------------------------------------------------------

fn payload() -> Octets {
    Octets::random("payload", "payload (base64url)", 48)
}

#[wasm_bindgen_test]
fn jws_sign_and_verify() {
    let mut r = Report::new();
    for (alg, len) in [("HS256", 32), ("HS384", 48), ("HS512", 64)] {
        let (key, k) = oct(len);
        let payload = payload();
        let options = object(&[("protectedHeader", protected(alg))]);
        let (m, token) = measure(|| {
            js(jws::jws_sign_compact(
                b(&payload.raw.bytes),
                s(&key),
                &options,
            ))
        });
        let all = [&payload.raw, &payload.text, &k.raw, &k.text];
        r.check(&format!("jwsSignCompact({alg})"), &m, &all);

        let policy = verify_options(alg);
        let (m, out) = measure(|| ok(jws::jws_verify_compact(s(&token), s(&key), &policy)));
        assert!(bytes_equal(&get(&out, "payload"), &payload.raw.bytes));
        r.check(&format!("jwsVerifyCompact({alg})"), &m, &all);
    }

    for (alg, key) in [
        ("ES256", p256_jwk()),
        ("EdDSA", js(keys::jwk_generate_okp("Ed25519"))),
    ] {
        let d = private(&key, "d");
        let payload = payload();
        let options = object(&[("protectedHeader", protected(alg))]);
        let (m, token) = measure(|| {
            js(jws::jws_sign_compact(
                b(&payload.raw.bytes),
                s(&key),
                &options,
            ))
        });
        r.check(
            &format!("jwsSignCompact({alg})"),
            &m,
            &[&payload.raw, &payload.text, &d.raw, &d.text],
        );

        let public = JsValue::from(ok(jwk::jwk_to_public(s(&key))));
        let policy = verify_options(alg);
        let (m, out) = measure(|| ok(jws::jws_verify_compact(s(&token), s(&public), &policy)));
        assert!(bytes_equal(&get(&out, "payload"), &payload.raw.bytes));
        r.check(
            &format!("jwsVerifyCompact({alg})"),
            &m,
            &[&payload.raw, &payload.text],
        );
    }

    // The signer record's key is read by src/read.rs (`secret_string`).
    let (key, k) = oct(64);
    let payload = payload();
    let signer = object(&[
        ("key", key.clone()),
        ("protectedHeader", protected("HS512")),
    ]);
    let (m, token) = measure(|| {
        js(jws::jws_sign_flattened(
            b(&payload.raw.bytes),
            &signer,
            false,
        ))
    });
    let all = [&payload.raw, &payload.text, &k.raw, &k.text];
    r.check("jwsSignFlattened(HS512)", &m, &all);
    let policy = verify_options("HS512");
    let (m, out) = measure(|| ok(jws::jws_verify_json(s(&token), s(&key), &policy)));
    assert!(bytes_equal(&get(&out, "payload"), &payload.raw.bytes));
    r.check("jwsVerifyJson(HS512)", &m, &all);

    let ec = p256_jwk();
    let d = private(&ec, "d");
    let signers = list(&[
        signer,
        object(&[("key", ec), ("protectedHeader", protected("ES256"))]),
    ]);
    let payload = self::payload();
    let (m, _) = measure(|| {
        js(jws::jws_sign_general(
            b(&payload.raw.bytes),
            &signers,
            false,
        ))
    });
    let all = [
        &payload.raw,
        &payload.text,
        &k.raw,
        &k.text,
        &d.raw,
        &d.text,
    ];
    r.check("jwsSignGeneral(HS512, ES256)", &m, &all);

    // A detached payload (RFC 7515 Appendix F) reaches the core as `detachedPayload` secret bytes.
    let payload = self::payload();
    let options = object(&[
        ("protectedHeader", protected("HS512")),
        ("detached", true.into()),
    ]);
    let (m, token) = measure(|| {
        js(jws::jws_sign_compact(
            b(&payload.raw.bytes),
            s(&key),
            &options,
        ))
    });
    let all = [&payload.raw, &payload.text, &k.raw, &k.text];
    r.check("jwsSignCompact(HS512, detached)", &m, &all);
    let detached = payload.raw.bytes.slice(0, payload.raw.bytes.length());
    let policy = object(&[
        ("allowedAlgs", strings(&["HS512"])),
        ("detachedPayload", detached.into()),
    ]);
    let (m, _) = measure(|| ok(jws::jws_verify_compact(s(&token), s(&key), &policy)));
    r.check("jwsVerifyCompact(HS512, detached)", &m, &all);
    r.finish();
}

// --- JWE --------------------------------------------------------------------------------------

/// One JWE recipient and the key that decrypts for it.
struct Recipient {
    alg: &'static str,
    enc: &'static str,
    /// The `JweRecipient` record (RFC 7516 §7.2.1).
    record: JsValue,
    /// The decryption key.
    key: JsValue,
    /// The decryption key's private member.
    private: Octets,
}

fn recipients() -> Vec<Recipient> {
    let symmetric = |alg: &'static str, enc: &'static str, len: u32, extra: &[(&str, JsValue)]| {
        let (key, private) = oct(len);
        let mut members = vec![("alg", JsValue::from_str(alg)), ("key", key.clone())];
        members.extend(extra.iter().cloned());
        Recipient {
            alg,
            enc,
            record: object(&members),
            key,
            private,
        }
    };
    let ecdh = |alg: &'static str, enc: &'static str, key: JsValue| {
        let private = self::private(&key, "d");
        let public = JsValue::from(ok(jwk::jwk_to_public(s(&key))));
        let record = object(&[("alg", JsValue::from_str(alg)), ("key", public)]);
        Recipient {
            alg,
            enc,
            record,
            key,
            private,
        }
    };
    vec![
        symmetric("dir", "A128GCM", 16, &[]),
        symmetric("dir", "A128CBC-HS256", 32, &[]),
        symmetric("A128KW", "A128CBC-HS256", 16, &[]),
        symmetric("A256GCMKW", "A256GCM", 32, &[]),
        // RFC 7518 §4.8.1.2: 1000 is the smallest count polyjose accepts (ADR 0023).
        symmetric("PBES2-HS256+A128KW", "A128GCM", 24, &[("p2c", 1000.into())]),
        ecdh("ECDH-ES+A128KW", "A128GCM", p256_jwk()),
        ecdh("ECDH-ES", "A256GCM", js(keys::jwk_generate_okp("X25519"))),
    ]
}

#[wasm_bindgen_test]
fn jwe_encrypt_and_decrypt() {
    let mut r = Report::new();
    for to in recipients() {
        let case = format!("{} + {}", to.alg, to.enc);
        let policy = object(&[
            ("allowedAlgs", strings(&[to.alg])),
            ("allowedEnc", strings(&[to.enc])),
        ]);

        let plaintext = Octets::random("plaintext", "plaintext (base64url)", 64);
        let options = object(&[
            ("enc", to.enc.into()),
            ("recipients", list(std::slice::from_ref(&to.record))),
        ]);
        let (m, token) =
            measure(|| ok(jwe::jwe_encrypt_compact(b(&plaintext.raw.bytes), &options)));
        let all = [
            &plaintext.raw,
            &plaintext.text,
            &to.private.raw,
            &to.private.text,
        ];
        r.check(&format!("jweEncryptCompact({case})"), &m, &all);

        let token = JsValue::from_str(&token); // ciphertext only: a public result
        let (m, out) = measure(|| ok(jwe::jwe_decrypt_compact(s(&token), s(&to.key), &policy)));
        assert!(bytes_equal(&get(&out, "plaintext"), &plaintext.raw.bytes));
        r.check(&format!("jweDecryptCompact({case})"), &m, &all);

        // The JSON serialization with an `aad` (RFC 7516 §5.1 step 14), secret by ADR 0050 §4.
        let plaintext = Octets::random("plaintext", "plaintext (base64url)", 64);
        let aad = Octets::random("aad", "aad (base64url)", 32);
        let options = object(&[
            ("enc", to.enc.into()),
            ("recipients", list(std::slice::from_ref(&to.record))),
            ("aad", aad.raw.bytes.slice(0, 32).into()),
        ]);
        let (m, token) = measure(|| {
            ok(jwe::jwe_encrypt_json(
                b(&plaintext.raw.bytes),
                &options,
                "flattened",
            ))
        });
        let all = [
            &plaintext.raw,
            &plaintext.text,
            &aad.raw,
            &aad.text,
            &to.private.raw,
            &to.private.text,
        ];
        r.check(&format!("jweEncryptJson({case}, aad)"), &m, &all);

        let token = JsValue::from_str(&token);
        let (m, out) = measure(|| ok(jwe::jwe_decrypt_json(s(&token), s(&to.key), &policy)));
        assert!(bytes_equal(&get(&out, "plaintext"), &plaintext.raw.bytes));
        assert!(bytes_equal(&get(&out, "aad"), &aad.raw.bytes));
        r.check(&format!("jweDecryptJson({case}, aad)"), &m, &all);
    }
    r.finish();
}

// --- JWT --------------------------------------------------------------------------------------

/// Fresh claims whose only random part is `sub` (RFC 7519 §4.1.2), and its two forms: the text,
/// and its base64url inside the JWT's payload segment.
struct Claims {
    text: JsValue,
    sub: Secret,
    sub_b64u: Secret,
}

fn fresh_claims() -> Claims {
    let marker = b64u(&rand(24));
    Claims {
        text: claims(&marker),
        sub: Secret::text("claims sub", &marker),
        sub_b64u: Secret::text("claims sub (base64url)", &marker_segment(&marker)),
    }
}

/// Each measured call gets claims of its own, signed in setup, so a copy of earlier claims can't
/// hide one of this call's by sitting at the same address.
#[wasm_bindgen_test]
fn jwt_operations() {
    let mut r = Report::new();
    let (key, k) = oct(64);
    let sign_options = object(&[("alg", "HS512".into())]);
    let sign = |c: &Claims| js(jwt::jwt_sign(s(&c.text), s(&key), &sign_options));

    let c = fresh_claims();
    let (m, _) = measure(|| sign(&c));
    r.check(
        "jwtSign(HS512)",
        &m,
        &[&c.sub, &c.sub_b64u, &k.raw, &k.text],
    );

    let policy = object(&[
        ("allowedAlgs", strings(&["HS512"])),
        ("now", 1_700_000_000.into()),
    ]);
    let c = fresh_claims();
    let token = sign(&c);
    let (m, out) = measure(|| ok(jwt::jwt_verify(s(&token), s(&key), &policy)));
    assert!(get(&out, "claims").is_string());
    r.check(
        "jwtVerify(HS512)",
        &m,
        &[&c.sub, &c.sub_b64u, &k.raw, &k.text],
    );

    let set = jwks(&[key.clone()].iter().collect::<Array>());
    let c = fresh_claims();
    let token = sign(&c);
    let (m, _) = measure(|| ok(jwt::jwt_verify_with_jwks(s(&token), s(&set), &policy)));
    r.check(
        "jwtVerifyWithJwks(HS512)",
        &m,
        &[&c.sub, &c.sub_b64u, &k.raw, &k.text],
    );

    // A nested JWT (RFC 7519 §5.2, §11.2): the signed JWT is the JWE plaintext.
    let (kek, kek_k) = oct(16);
    let kek_k = Octets {
        raw: Secret::new("key-encryption k", kek_k.raw.bytes),
        text: Secret::new("key-encryption k (base64url)", kek_k.text.bytes),
    };
    let recipient = object(&[("alg", "A128KW".into()), ("key", kek.clone())]);
    let options = object(&[
        ("enc", "A128GCM".into()),
        ("recipients", list(&[recipient])),
    ]);
    let decrypt = object(&[
        ("allowedAlgs", strings(&["A128KW"])),
        ("allowedEnc", strings(&["A128GCM"])),
    ]);
    let nest =
        |token: &JsValue| JsValue::from_str(&ok(jwt::jwt_encrypt_nested(s(token), &options)));

    let c = fresh_claims();
    let token = sign(&c);
    let (m, _) = measure(|| nest(&token));
    let all = [
        &c.sub,
        &c.sub_b64u,
        &k.raw,
        &k.text,
        &kek_k.raw,
        &kek_k.text,
    ];
    r.check("jwtEncryptNested(A128KW + A128GCM)", &m, &all);

    let c = fresh_claims();
    let nested = nest(&sign(&c));
    let (m, _) = measure(|| {
        ok(jwt::jwt_decrypt_nested(
            s(&nested),
            s(&kek),
            &decrypt,
            s(&key),
            &policy,
        ))
    });
    let all = [
        &c.sub,
        &c.sub_b64u,
        &k.raw,
        &k.text,
        &kek_k.raw,
        &kek_k.text,
    ];
    r.check("jwtDecryptNested", &m, &all);

    let c = fresh_claims();
    let nested = nest(&sign(&c));
    let (m, _) = measure(|| {
        ok(jwt::jwt_decrypt_nested_with_jwks(
            s(&nested),
            s(&kek),
            &decrypt,
            s(&set),
            &policy,
        ))
    });
    let all = [
        &c.sub,
        &c.sub_b64u,
        &k.raw,
        &k.text,
        &kek_k.raw,
        &kek_k.text,
    ];
    r.check("jwtDecryptNestedWithJwks", &m, &all);
    r.finish();
}

// --- Failures ---------------------------------------------------------------------------------

/// A call that throws wipes what it was given. Two cases: a core failure (`PolyjoseError`,
/// ADR 0030 §5), and a reader `TypeError` after the token and the key were passed (src/read.rs:
/// "a reader that fails half-way drops what it has read, wiping it").
#[wasm_bindgen_test]
fn failed_calls() {
    let mut r = Report::new();
    let (key, k) = oct(64);
    let payload = payload();
    let options = object(&[("protectedHeader", protected("HS512"))]);
    let token = js(jws::jws_sign_compact(
        b(&payload.raw.bytes),
        s(&key),
        &options,
    ));
    let all = [&payload.raw, &payload.text, &k.raw, &k.text];

    let (other, _) = oct(64);
    let policy = verify_options("HS512");
    let (m, failed) = measure(|| jws::jws_verify_compact(s(&token), s(&other), &policy).is_err());
    assert!(failed, "verified under the wrong key");
    r.check("jwsVerifyCompact(wrong key): InvalidSignature", &m, &all);

    let bad = object(&[("allowedAlgs", "HS512".into())]); // not an array: TypeError
    let (m, failed) = measure(|| jws::jws_verify_compact(s(&token), s(&key), &bad).is_err());
    assert!(failed, "a wrong-typed allow-list was accepted");
    r.check("jwsVerifyCompact(bad options): TypeError", &m, &all);

    // src/read.rs reads `key` into a `SecretString` before it finds `protectedHeader` wrong.
    let signer = object(&[("key", key.clone()), ("protectedHeader", 5.into())]);
    let (m, failed) =
        measure(|| jws::jws_sign_flattened(b(&payload.raw.bytes), &signer, false).is_err());
    assert!(failed, "a wrong-typed protectedHeader was accepted");
    r.check(
        "jwsSignFlattened(bad signer after key): TypeError",
        &m,
        &all,
    );

    let (kek, kek_k) = oct(16);
    let plaintext = Octets::random("plaintext", "plaintext (base64url)", 64);
    let recipient = object(&[("alg", "A128KW".into()), ("key", kek)]);
    let options = object(&[
        ("enc", "A128GCM".into()),
        ("recipients", list(&[recipient])),
    ]);
    let token = JsValue::from_str(&ok(jwe::jwe_encrypt_compact(
        b(&plaintext.raw.bytes),
        &options,
    )));
    let (wrong, wrong_k) = oct(16);
    let wrong_k = Octets {
        raw: Secret::new("wrong k", wrong_k.raw.bytes),
        text: Secret::new("wrong k (base64url)", wrong_k.text.bytes),
    };
    let policy = object(&[
        ("allowedAlgs", strings(&["A128KW"])),
        ("allowedEnc", strings(&["A128GCM"])),
    ]);
    let (m, failed) = measure(|| jwe::jwe_decrypt_compact(s(&token), s(&wrong), &policy).is_err());
    assert!(failed, "decrypted under the wrong key");
    let all = [
        &plaintext.raw,
        &plaintext.text,
        &kek_k.raw,
        &kek_k.text,
        &wrong_k.raw,
        &wrong_k.text,
    ];
    r.check("jweDecryptCompact(wrong key): DecryptionFailed", &m, &all);
    r.finish();
}
