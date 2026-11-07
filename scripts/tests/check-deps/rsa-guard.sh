#!/usr/bin/env bash
# Negative test of the ADR 0021 guard in scripts/check-deps.sh (checks 9-11), which deny.toml's
# ignore of RUSTSEC-2023-0071 depends on. Each change below is made in a copy of the tree and must
# make check-deps.sh fail with the guard's own message (and no other check's):
#   - RSA private-key and signing types and an Oaep decryption in crates/polyjose/src, and the
#     same in a binding (bindings/**);
#   - the same in a workspace member outside bindings/: the feature 0013 security audit's L1 plant
#     (a bin-only tools/evil member with an optional rsa and polyjose behind a feature, compiling
#     rsa::pkcs1v15::SigningKey), and a member whose [[bin]] path is outside its own directory
#     (the scan reads every member's directory and target directories from cargo metadata);
#   - the security audit's reproductions of ADR 0049 §1, as far as a text scan can see them: an rsa
#     alias in a brace use tree (`use {rsa as r};`), `#[path]` (also through cfg_attr) and
#     `include!` naming a file outside the scanned roots, and an out-of-line child module of
#     jws/rsa.rs or jwe/rsa_oaep.rs (`mod child;`, or a file in jws/rsa/). The macro reproduction
#     (`k!(rsa)`) is invisible to text; the compiled-symbol check catches all four
#     (scripts/check-rsa-symbols.sh, tested by rsa-symbols.sh);
#   - a sha1 dependency (also when sha1 is allowlisted and credited, so check 10 alone catches it);
#   - an rsa feature.
# Legitimate look-alikes must pass: an ECDSA SigningKey and a cbc Decryptor in files that do not
# use the rsa crate, a child module named `rsa` reached as `self::rsa::`, the typed RSA
# VerifyingKey, and inline modules (`#[cfg(test)] mod tests { .. }`) in the RSA files. The
# unchanged tree must pass.
# Usage: scripts/tests/check-deps/rsa-guard.sh
set -euo pipefail
export LC_ALL=C
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

# Every FAIL line of a source case comes from check 9.
src_fail='^FAIL: RSA private-key or signing use'
jws=crates/polyjose/src/jws.rs

new_case clean
expect_pass "unchanged tree"

# --- Check 9: sources ----------------------------------------------------------------------------
new_case private-key
append_to "$jws" 'use rsa::RsaPrivateKey;'
expect_fail "use rsa::RsaPrivateKey" "$jws:[0-9]+: RsaPrivateKey" "$src_fail"

new_case private-key-new
append_to "$jws" 'fn k() { let _ = rsa::RsaPrivateKey::new(&mut rng, 2048); }'
expect_fail "RsaPrivateKey::new" "$jws:[0-9]+: RsaPrivateKey" "$src_fail"

new_case pkcs1v15-signing-key
append_to "$jws" 'fn s(k: rsa::pkcs1v15::SigningKey<rsa::sha2::Sha256>) {}'
expect_fail "rsa::pkcs1v15::SigningKey" "$jws:[0-9]+: SigningKey in a file that uses the rsa crate" "$src_fail"

new_case pss-signing-key-import
append_to "$jws" 'use rsa::pss::{SigningKey, VerifyingKey};'
expect_fail "use rsa::pss::{SigningKey, ...}" "$jws:[0-9]+: SigningKey in a file that uses the rsa crate" "$src_fail"

new_case blinded-signing-key
append_to "$jws" 'type K = rsa::pss::BlindedSigningKey<rsa::sha2::Sha256>;'
expect_fail "BlindedSigningKey" "$jws:[0-9]+: BlindedSigningKey" "$src_fail"

new_case oaep-decrypt
append_to crates/polyjose/src/jwe.rs 'fn d<K>(k: &K, ek: &[u8]) { let _cek = k.decrypt(rsa::Oaep::<rsa::sha2::Sha256>::new(), ek); }'
expect_fail "Oaep decrypt call" "crates/polyjose/src/jwe.rs:[0-9]+: a decrypt call in a file that uses the rsa crate" "$src_fail"

new_case decrypting-key
append_to crates/polyjose/src/jwe.rs 'type D = rsa::oaep::DecryptingKey<rsa::sha2::Sha256>;'
expect_fail "oaep::DecryptingKey" "crates/polyjose/src/jwe.rs:[0-9]+: DecryptingKey" "$src_fail"

new_case decryptor-trait
append_to crates/polyjose/src/jwe.rs 'use rsa::traits::Decryptor;'
expect_fail "rsa::traits::Decryptor" "crates/polyjose/src/jwe.rs:[0-9]+: Decryptor in a file that uses the rsa crate" "$src_fail"

new_case randomized-decryptor
append_to crates/polyjose/src/jwe.rs 'use rsa::traits::RandomizedDecryptor;'
expect_fail "RandomizedDecryptor" "crates/polyjose/src/jwe.rs:[0-9]+: RandomizedDecryptor" "$src_fail"

new_case pkcs1v15-sign-scheme
append_to "$jws" 'fn v(k: &rsa::RsaPublicKey) { let _ = k.verify(rsa::Pkcs1v15Sign::new::<rsa::sha2::Sha256>(), &[], &[]); }'
expect_fail "Pkcs1v15Sign scheme" "$jws:[0-9]+: Pkcs1v15Sign" "$src_fail"

new_case pss-scheme
append_to "$jws" 'fn v(k: &rsa::RsaPublicKey) { let _ = k.verify(rsa::Pss::new::<rsa::sha2::Sha256>(), &[], &[]); }'
expect_fail "Pss scheme struct" "$jws:[0-9]+: Pss: use the typed" "$src_fail"

new_case rsa1-5
append_to crates/polyjose/src/jwe.rs 'fn e(k: &rsa::RsaPublicKey) { let _ = k.encrypt(&mut r, rsa::Pkcs1v15Encrypt, &[]); }'
expect_fail "Pkcs1v15Encrypt (RSA1_5)" "crates/polyjose/src/jwe.rs:[0-9]+: Pkcs1v15Encrypt" "$src_fail"

new_case reexport
append_to crates/polyjose/src/jwk.rs 'pub(crate) use rsa::pkcs1v15;'
expect_fail "pub(crate) use rsa::..." "crates/polyjose/src/jwk.rs:[0-9]+: pub use rsa" "$src_fail"

new_case alias
append_to crates/polyjose/src/jwk.rs 'use rsa as r;'
expect_fail "use rsa as r" "crates/polyjose/src/jwk.rs:[0-9]+: use rsa / use rsa as" "$src_fail"

new_case binding
append_to bindings/wasm/src/lib.rs 'use rsa::RsaPrivateKey;'
expect_fail "RsaPrivateKey in a binding" "bindings/wasm/src/lib.rs:[0-9]+: RsaPrivateKey" "$src_fail"

new_case binding-new-file
append_to bindings/ffi/src/sign/rsa.rs 'pub fn s(k: rsa::pkcs1v15::SigningKey<rsa::sha2::Sha256>) {}'
expect_fail "rsa SigningKey in a new binding file" "bindings/ffi/src/sign/rsa.rs:[0-9]+: SigningKey in a file that uses the rsa crate" "$src_fail"

# --- Check 9: workspace members outside bindings/ (feature 0013 security audit L1) ----------------
# The audit's plant, as written: build tooling under tools/, which no shipped library links, still
# must not compile RSA private-key code (the symbol check fails closed on it too, rsa-symbols.sh).
# The plant is a workspace member, so it takes rsa from [workspace.dependencies] (the pin of ADR
# 0055 §4, default features off) instead of a version written here, which a bump of that pin
# would make unresolvable (cargo allows one 0.10 rsa per lock file).
evil_manifest='[package]
name = "polyjose-evil-tool"
version = "0.0.0"
edition = "2024"
publish = false

[dependencies]
rsa = { workspace = true, optional = true }
polyjose = { path = "../../crates/polyjose", optional = true }

[features]
signer = ["dep:rsa", "dep:polyjose"]
'
evil_main='#[cfg(feature = "signer")]
pub fn sign(k: &rsa::RsaPrivateKey, m: &[u8]) -> Vec<u8> {
    use rsa::pkcs1v15::SigningKey;
    let _ = (SigningKey::<rsa::sha2::Sha256>::new_unprefixed(k.clone()), m); Vec::new()
}
fn main() {}'

new_case tool-member
append_to tools/evil/Cargo.toml "$evil_manifest"'[[bin]]
name = "evil"
path = "src/main.rs"'
append_to tools/evil/src/main.rs "$evil_main"
replace_in Cargo.toml 'members = [' 'members = ["tools/evil", '
expect_fail "audit L1: rsa::pkcs1v15::SigningKey in a bin-only tools/ member" \
  "^  - tools/evil/src/main\\.rs:3: SigningKey in a file that uses the rsa crate" "$src_fail"

new_case tool-member-bin-elsewhere
append_to tools/evil/Cargo.toml "$evil_manifest"'[[bin]]
name = "evil"
path = "../../misc/evil.rs"'
append_to misc/evil.rs "$evil_main"
replace_in Cargo.toml 'members = [' 'members = ["tools/evil", '
expect_fail "a tools/ member whose [[bin]] is outside its directory" \
  "^  - misc/evil\\.rs:2: RsaPrivateKey" "$src_fail"

# --- Check 9: paths split across lines, by whitespace or by a comment ------------------------------
# Rust lets whitespace and comments sit between the tokens of a path, so `rsa`, `::` and the item
# can be on different lines; none of these needs rustfmt to have run (or survives it).
new_case split-newline
append_to "$jws" $'fn s(k: rsa\n    ::pkcs1v15::SigningKey<Sha256>) {}'
expect_fail "rsa / newline / ::pkcs1v15::SigningKey" "$jws:[0-9]+: SigningKey in a file that uses the rsa crate" "$src_fail"

new_case split-spaces-private-key
append_to "$jws" 'fn k() -> rsa :: RsaPrivateKey { todo!() }'
expect_fail "rsa :: RsaPrivateKey" "$jws:[0-9]+: RsaPrivateKey" "$src_fail"

new_case split-spaces-signing-key
append_to "$jws" 'type K = rsa :: pss :: SigningKey<Sha256>;'
expect_fail "rsa :: pss :: SigningKey" "$jws:[0-9]+: SigningKey in a file that uses the rsa crate" "$src_fail"

new_case split-block-comment
append_to "$jws" 'type K = rsa /* not the crate */ ::pss::SigningKey<Sha256>;'
expect_fail "rsa /* comment */ ::pss::SigningKey" "$jws:[0-9]+: SigningKey in a file that uses the rsa crate" "$src_fail"

new_case split-line-comment
append_to "$jws" $'type K = rsa // not the crate\n    ::pss::SigningKey<Sha256>;'
expect_fail "rsa // comment / newline / ::pss::SigningKey" "$jws:[0-9]+: SigningKey in a file that uses the rsa crate" "$src_fail"

new_case split-leading-colons
append_to "$jws" $'type K = ::\n    rsa\n    ::pss::SigningKey<Sha256>;'
expect_fail ":: / rsa / ::pss::SigningKey" "$jws:[0-9]+: SigningKey in a file that uses the rsa crate" "$src_fail"

new_case split-use-alias
append_to crates/polyjose/src/jwk.rs $'use\n    rsa as r;'
expect_fail "use / newline / rsa as r" "crates/polyjose/src/jwk.rs:[0-9]+: use rsa / use rsa as" "$src_fail"

new_case split-pub-use
append_to crates/polyjose/src/jwk.rs $'pub(crate)\n    use rsa::pkcs1v15;'
expect_fail "pub(crate) / newline / use rsa::..." "crates/polyjose/src/jwk.rs:[0-9]+: pub use rsa" "$src_fail"

new_case split-extern-crate
append_to crates/polyjose/src/jwk.rs $'extern crate\n    rsa;'
expect_fail "extern crate / newline / rsa" "crates/polyjose/src/jwk.rs:[0-9]+: extern crate rsa" "$src_fail"

new_case split-decrypt-call
append_to crates/polyjose/src/jwe.rs $'fn d<K>(k: &K, ek: &[u8]) { let _cek = k.decrypt\n    (rsa::Oaep::<rsa::sha2::Sha256>::new(), ek); }'
expect_fail "decrypt / newline / (Oaep...)" "crates/polyjose/src/jwe.rs:[0-9]+: a decrypt call in a file that uses the rsa crate" "$src_fail"

new_case split-binding
append_to bindings/node/src/lib.rs $'pub fn s(k: rsa /* x */\n    :: pkcs1v15 :: SigningKey<Sha256>) {}'
expect_fail "split rsa path in a binding" "bindings/node/src/lib.rs:[0-9]+: SigningKey in a file that uses the rsa crate" "$src_fail"

# --- Check 9, hardened (ADR 0049 §1): the four audit reproductions and their neighbours -----------
# The compiled-symbol check (scripts/check-rsa-symbols.sh, tested by rsa-symbols.sh) is what these
# cannot get past; the text scan is the fast first layer and must catch every one it can see.
hmac=crates/polyjose/src/jws/hmac.rs
rsa_rs=crates/polyjose/src/jws/rsa.rs
oaep_rs=crates/polyjose/src/jwe/rsa_oaep.rs
sign_body='pub(crate) fn evil(msg: &[u8]) -> Vec<u8> {
    let k = r::pkcs1v15::SigningKey::<sha2::Sha256>::random(&mut rng(), 2048).unwrap();
    k.sign(msg).to_vec()
}'

# Audit reproduction 1: a brace use tree hides the crate name from `use rsa as`.
new_case brace-alias
append_to "$hmac" "#[allow(unused_imports)] use {rsa as r};
$sign_body"
expect_fail "use {rsa as r}; r::pkcs1v15::SigningKey" "$hmac:[0-9]+: rsa as ... in a use tree" "$src_fail"

new_case brace-alias-only
append_to "$hmac" 'use ::{rsa as r};'
expect_fail "use ::{rsa as r} on its own" "$hmac:[0-9]+: rsa as ... in a use tree" "$src_fail"

new_case brace-nested-signing-key
append_to "$hmac" $'use {self::x, rsa::{\n    pkcs1v15 as p}};\ntype K = p::SigningKey<Sha256>;'
expect_fail "use {.., rsa::{pkcs1v15 as p}}; p::SigningKey" "$hmac:[0-9]+: SigningKey in a file that uses the rsa crate" "$src_fail"

new_case brace-reexport
append_to crates/polyjose/src/jws/mod.rs 'pub(crate) use {rsa::pkcs1v15};'
expect_fail "pub(crate) use {rsa::pkcs1v15}" "crates/polyjose/src/jws/mod.rs:[0-9]+: pub use rsa" "$src_fail"

new_case raw-ident-alias
append_to "$hmac" 'use r#rsa as r;'
expect_fail "use r#rsa as r" "$hmac:[0-9]+: rsa as ... in a use tree" "$src_fail"

# Audit reproduction 2: #[path] loads a file from outside the scanned roots.
new_case path-attribute
append_to crates/polyjose/tests/fixtures/helper.rs "use rsa as r;
$sign_body"
append_to "$hmac" '#[path = "../../tests/fixtures/helper.rs"] #[allow(dead_code)] mod helper;'
expect_fail "#[path = \"../../tests/fixtures/helper.rs\"] mod helper" "$hmac:[0-9]+: #\\[path\\]" "$src_fail"

new_case path-attribute-split
append_to "$hmac" $'#\n  [ path\n  = "../../tests/fixtures/helper.rs" ] mod helper;'
expect_fail "# / [ path / = ...] over several lines" "$hmac:[0-9]+: #\\[path\\]" "$src_fail"

new_case path-cfg-attr
append_to "$hmac" '#[cfg_attr(all(), path = "../../tests/fixtures/helper.rs")] mod helper;'
expect_fail "#[cfg_attr(all(), path = ...)]" "$hmac:[0-9]+: #\\[path\\]" "$src_fail"

new_case path-attribute-binding
append_to bindings/wasm/src/lib.rs '#[path = "../../../outside.rs"] mod outside;'
expect_fail "#[path] in a binding" "bindings/wasm/src/lib.rs:[0-9]+: #\\[path\\]" "$src_fail"

new_case include-macro
append_to "$hmac" 'include!("../../tests/fixtures/helper.rs");'
expect_fail "include!(a file outside src/)" "$hmac:[0-9]+: include!" "$src_fail"

# Audit reproduction 4: an out-of-line child of jws/rsa.rs reaches the parent's private
# `use rsa::{pkcs1v15, ..}` as `super::pkcs1v15`, in a file that never writes `rsa`.
new_case child-path
append_to "$rsa_rs" '#[path = "rsa_child.rs"] mod child;'
append_to crates/polyjose/src/jws/rsa_child.rs 'use super::pkcs1v15 as p;
pub(crate) fn evil(msg: &[u8]) -> Vec<u8> {
    p::SigningKey::<sha2::Sha256>::random(&mut rng(), 2048).unwrap().sign(msg).to_vec()
}'
expect_fail "#[path = \"rsa_child.rs\"] mod child in jws/rsa.rs" "$rsa_rs:[0-9]+: (#\\[path\\]|mod child;)" "$src_fail"

new_case child-module
append_to "$rsa_rs" 'mod child;'
append_to crates/polyjose/src/jws/rsa/child.rs 'use super::pkcs1v15 as p;'
expect_fail "out-of-line mod child; in jws/rsa.rs" "$rsa_rs:[0-9]+: mod child;: an out-of-line child module of an RSA file" "$src_fail"

new_case child-module-nested
append_to "$rsa_rs" $'pub(crate) mod inline {\n    pub(crate) mod r#deep\n    ;\n}'
expect_fail "out-of-line module inside an inline one in jws/rsa.rs" "$rsa_rs:[0-9]+: mod .*: an out-of-line child module of an RSA file" "$src_fail"

new_case child-file
append_to crates/polyjose/src/jws/rsa/helper.rs 'use super::pkcs1v15 as p;'
expect_fail "a file in jws/rsa/ (a child module of jws/rsa.rs)" \
  "crates/polyjose/src/jws/rsa/helper.rs:1: a child module file of an RSA file" "$src_fail"

new_case child-module-oaep
append_to "$oaep_rs" '//! RSA-OAEP-256 encryption only (RFC 7518 §4.3).
mod child;'
expect_fail "out-of-line mod child; in jwe/rsa_oaep.rs" "$oaep_rs:[0-9]+: mod child;: an out-of-line child module of an RSA file" "$src_fail"

# Inline modules are allowed: the scan sees their text (as part of the RSA file).
new_case inline-test-modules
append_to "$rsa_rs" $'#[cfg(test)]\nmod more_tests {\n    use super::*;\n}'
append_to "$oaep_rs" $'//! RSA-OAEP-256 encryption only (RFC 7518 §4.3).\n#[cfg(test)]\nmod tests {\n    use super::*;\n    mod inner {}\n}'
expect_pass "inline #[cfg(test)] mod tests { } in jws/rsa.rs and jwe/rsa_oaep.rs"

# Look-alikes that are not RSA private-key use.
new_case look-alikes
append_to crates/polyjose/src/jws/ecdsa.rs 'fn s(k: &p256::ecdsa::SigningKey) {}'
append_to crates/polyjose/src/jwe/enc_cbc_hmac.rs 'type D = cbc::Decryptor<aes::Aes128>; fn f(c: &D) { c.decrypt(); }'
append_to crates/polyjose/src/jws/mod.rs 'mod rsa; fn v() { self::rsa::verify(); } fn s(k: &ed25519_dalek::SigningKey) {}'
append_to crates/polyjose/src/jws/rsa.rs 'use rsa::pkcs1v15::VerifyingKey; use rsa::pss::VerifyingKey as PssKey; use rsa::RsaPublicKey;'
expect_pass "ECDSA/EdDSA SigningKey, cbc Decryptor, self::rsa:: and the typed RSA VerifyingKey"

# The same legitimate code as rustfmt lays it out over several lines, one case per family, so the
# whole-file views of check 9 are exercised on it too.
new_case rsa-public-key-code
append_to crates/polyjose/src/jws/rsa.rs '//! RS256 and PS256 verification only; see [`super::ecdsa`] for signing.
use rsa::{
    BigUint, RsaPublicKey,
    pkcs1v15::{Signature, VerifyingKey},
    pss::VerifyingKey as PssVerifyingKey,
    signature::Verifier,
    traits::PublicKeyParts,
};

/// Imports n and e (RFC 7518 §6.3.1) and verifies (RFC 7518 §3.3, §3.5).
fn verify(n: &[u8], e: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let Ok(key) = RsaPublicKey::new(BigUint::from_bytes_be(n), BigUint::from_bytes_be(e)) else {
        return false;
    };
    let _bits = key.size() * 8; // "// not a comment" in a string: "/* nor this"
    let pkcs1 = rsa::pkcs1v15::VerifyingKey::<rsa::sha2::Sha256>::new(key.clone());
    let pss: PssVerifyingKey<rsa::sha2::Sha256> = rsa::pss::VerifyingKey::new(key);
    let Ok(signature) = Signature::try_from(sig) else {
        return false;
    };
    pkcs1.verify(msg, &signature).is_ok() || pss.verify(msg, &signature.into()).is_ok()
}

fn _typed(_: VerifyingKey<rsa::sha2::Sha512>) {}'
append_to crates/polyjose/src/jwe.rs 'fn wrap(key: &rsa::RsaPublicKey, rng: &mut R, cek: &[u8]) -> Vec<u8> {
    key.encrypt(
        rng,
        rsa::Oaep::<rsa::sha2::Sha256>::new(),
        cek,
    )
    .unwrap_or_default()
}'
expect_pass "rsa::RsaPublicKey, rsa::pkcs1v15::VerifyingKey, rsa::pss::VerifyingKey and an Oaep encrypt over several lines"

new_case ecdsa-signing-key
append_to crates/polyjose/src/jws/ecdsa.rs '//! ES256 signs (RFC 7518 §3.4); unlike [`super::rsa`], which only verifies.
use p256::ecdsa::{
    Signature, SigningKey, VerifyingKey,
    signature::{Signer, Verifier},
};

fn sign(d: &[u8; 32], msg: &[u8]) -> Option<Vec<u8>> {
    let key = p256::ecdsa::SigningKey::from_bytes(
        &(*d).into(),
    )
    .ok()?;
    let _p384: Option<p384::ecdsa::SigningKey> = None;
    let _k256: Option<k256::ecdsa::SigningKey> = None;
    let signature: Signature = key.sign(msg);
    VerifyingKey::from(&key).verify(msg, &signature).ok()?;
    let _ = SigningKey::verifying_key;
    Some(signature.to_bytes().to_vec())
}'
expect_pass "p256::ecdsa::SigningKey over several lines in a file that does not use rsa"

new_case eddsa-signing-key
append_to crates/polyjose/src/jws/eddsa.rs '//! EdDSA over Ed25519 (RFC 8037 §3.1).
use ed25519_dalek::{
    Signature, Signer, SigningKey,
    Verifier, VerifyingKey,
};

fn sign(seed: &[u8; 32], msg: &[u8]) -> [u8; 64] {
    let key = ed25519_dalek::SigningKey::from_bytes(
        seed,
    );
    let signature: Signature = key.sign(msg);
    let _ok = VerifyingKey::from(&key).verify(msg, &signature).is_ok();
    let _ = SigningKey::verifying_key;
    signature.to_bytes()
}'
expect_pass "ed25519_dalek::SigningKey over several lines in a file that does not use rsa"

# --- Check 9, macro rule (ADR 0049 §1): rsa as an identifier inside a macro call ----------------
# A macro can turn an `rsa` identifier into the head of a path (`$c::pkcs1v15::SigningKey`), which
# no other text rule sees. The compiled-symbol check sees it only in code that is codegened, so
# these three public but uncodegened spellings (found by the F01 tester) are this rule's alone:
# an uncalled #[inline] pub fn, an uninstantiated generic pub fn, and cfg(not(debug_assertions))
# code (the release pass of check-rsa-symbols.sh also catches the last, see rsa-symbols.sh).
lib_rs=crates/polyjose/src/lib.rs
node_rs=bindings/node/src/lib.rs
key_macro='macro_rules! k { ($c:ident) => { $c::pkcs1v15::SigningKey::<sha2::Sha256> } }'
macro_body='{
    use p256::ecdsa::signature::{SignatureEncoding, Signer as _};
    let mut rng = p256::elliptic_curve::rand_core::UnwrapErr(crate::rng::CryptoRngAdapter::os());
    let key = <k!(rsa)>::random(&mut rng, 2048).unwrap();
    key.sign(msg).to_vec()
}'
in_k='rsa as an identifier inside the macro call k!'

new_case macro-inline-pub
append_to "$lib_rs" "$key_macro
#[inline] pub fn evil(msg: &[u8]) -> Vec<u8> $macro_body"
expect_fail "uncalled #[inline] pub fn with <k!(rsa)>::random" "$lib_rs:[0-9]+: $in_k" "$src_fail"

new_case macro-generic-pub
append_to "$lib_rs" "$key_macro
pub fn evil<T>(msg: &[u8], _t: T) -> Vec<u8> $macro_body"
expect_fail "uninstantiated generic pub fn<T> with <k!(rsa)>::random" "$lib_rs:[0-9]+: $in_k" "$src_fail"

new_case macro-release-only
append_to "$lib_rs" "$key_macro
#[cfg(not(debug_assertions))] pub fn evil(msg: &[u8]) -> Vec<u8> $macro_body"
expect_fail "#[cfg(not(debug_assertions))] pub fn with <k!(rsa)>::random" "$lib_rs:[0-9]+: $in_k" "$src_fail"

new_case macro-brackets
append_to "$hmac" 'type K = k![rsa];'
expect_fail "k![rsa]" "$hmac:[0-9]+: $in_k" "$src_fail"

new_case macro-braces
append_to "$hmac" $'k! {\n    rsa\n}'
expect_fail "k! { rsa } over several lines" "$hmac:[0-9]+: $in_k" "$src_fail"

new_case macro-split-comment
append_to "$hmac" $'type K = k\n    ! /* x */ (\n    // y\n    rsa);'
expect_fail "k / ! /* x */ ( / // y / rsa)" "$hmac:[0-9]+: $in_k" "$src_fail"

new_case macro-raw-ident
append_to "$hmac" 'type K = k!(r#rsa);'
expect_fail "k!(r#rsa)" "$hmac:[0-9]+: $in_k" "$src_fail"

new_case macro-global-path
append_to "$hmac" 'type K = k!(::rsa);'
expect_fail "k!(::rsa), the crate as a global path" "$hmac:[0-9]+: $in_k" "$src_fail"

new_case macro-in-std-macro
append_to "$hmac" 'fn f() { assert!(<k!(rsa)>::random(&mut rng(), 2048).is_ok()); }'
expect_fail "assert!(<k!(rsa)>::random(..))" "$hmac:[0-9]+: $in_k" "$src_fail"

new_case macro-std-macro-in-macro
append_to "$hmac" 'k!(assert!(rsa));'
expect_fail "k!(assert!(rsa)): k! receives the tokens of assert!(..)" "$hmac:[0-9]+: $in_k" "$src_fail"

new_case macro-qualified-std-name
append_to "$hmac" 'fn f() { self::assert!(rsa); }'
expect_fail "self::assert!(rsa) is not the std assert!" "$hmac:[0-9]+: rsa as an identifier inside the macro call assert!" "$src_fail"

new_case macro-rules-body
append_to "$hmac" 'macro_rules! j { ($($t:tt)*) => { rsa $($t)* } }
type K = j!(::pkcs1v15::SigningKey<sha2::Sha256>);'
expect_fail "rsa in a macro_rules! body" "$hmac:[0-9]+: rsa as an identifier inside the macro call macro_rules! j" "$src_fail"

new_case macro-attribute
append_to "$hmac" '#[evil(rsa)] fn f() {}'
expect_fail "#[evil(rsa)]: an attribute macro gets its arguments as tokens" "$hmac:[0-9]+: rsa as an identifier inside the attribute #\\[evil" "$src_fail"

new_case macro-binding
append_to "$node_rs" "$key_macro
pub fn evil<T>(msg: &[u8], _t: T) -> Vec<u8> $macro_body"
expect_fail "<k!(rsa)>::random in a binding" "$node_rs:[0-9]+: $in_k" "$src_fail"

# The std macros whose arguments the rule trusts must not be redefined or renamed in.
new_case macro-shadow-rules
append_to "$hmac" 'macro_rules! assert_eq { ($c:ident) => { $c::pkcs1v15::SigningKey<sha2::Sha256> } }'
expect_fail "macro_rules! assert_eq" "$hmac:[0-9]+: macro_rules! assert_eq: a macro named like a std macro" "$src_fail"

new_case macro-shadow-use-as
append_to "$hmac" 'pub(crate) use k as assert;'
expect_fail "use k as assert" "$hmac:[0-9]+: as assert: a macro named like a std macro" "$src_fail"

# Must pass: polyjose paths that end in a module named rsa, literals and comments, std macros
# whose arguments are ordinary expressions, and rsa outside any macro call.
new_case macro-polyjose-paths
append_to "$node_rs" 'k!(polyjose::jws::rsa::verify);
k!(::polyjose::jws::rsa::verify);'
append_to crates/polyjose/src/jws/mod.rs 'k!(self::rsa::verify);
k!(crate::jws::rsa::verify);
macro_rules! m { () => { k!($crate::jws::rsa::verify) } }'
append_to "$hmac" 'k!(super::rsa::verify);'
expect_pass "macro calls naming polyjose::jws::rsa, ::polyjose::.., self::rsa, crate::jws::rsa, \$crate::jws::rsa and super::rsa"

new_case macro-literals-comments
append_to "$hmac" $'fn f() -> String { format!("rsa") }\nk!("rsa", r#"rsa"#, b"rsa", \'r\', c"rsa");\n// k!(rsa)\n/* k!(rsa) */\nk!(/* rsa */ x);\n/// k!(rsa)\nfn g() {}'
expect_pass "format!(\"rsa\"), rsa in string, raw string, byte string and comments inside macro calls"

new_case macro-std-arguments
append_to "$hmac" $'fn f(rsa: u8) {\n    assert!(rsa > 0, "{rsa}");\n    assert_eq!(names(&rsa), ["e"]);\n    debug_assert_ne!(rsa, 1);\n    let _ = format!("{}", rsa);\n    let _ = vec![rsa; 2];\n    let _ = matches!(rsa, 0);\n}'
expect_pass "assert!(rsa > 0), assert_eq!(names(&rsa), ..) and other std macros with a variable named rsa"

new_case macro-not-a-call
append_to crates/polyjose/src/jws/plain.rs $'use super::{hmac, rsa};\nfn f(rsa: u8) -> bool {\n    if !(rsa == 0) { return !(rsa == 1); }\n    rsa != (rsa)\n}'
expect_pass "use super::{hmac, rsa}, if !(rsa ..), return !(rsa ..) and rsa != (rsa) outside macro calls"

# --- Check 10: sha1 --------------------------------------------------------------------------------
new_case sha1
add_core_dependency 'sha1 = { version = "0.11", default-features = false }'
expect_fail "sha1 dependency" "^FAIL: sha1 is in the core's tree" \
  "^FAIL: (sha1 is in the core's tree|the core's tree \\(normal and build dependencies\\) contains crates)"

new_case sha1-allowlisted
add_core_dependency 'sha1 = { version = "0.11", default-features = false }'
replace_in deps-allowlist.txt $'\nsha2\n' $'\nsha2\nsha1\n'
printf '\n### `sha1`\n\nInjected by scripts/tests/check-deps/rsa-guard.sh.\n' >>"$case_dir/CREDITS.md"
expect_fail "sha1 dependency, allowlisted and credited" "^FAIL: sha1 is in the core's tree" "^FAIL: sha1 is in the core's tree"

# --- Check 12: rsa under another name --------------------------------------------------------------
# `foo = { package = "rsa" }` lets code write `foo::pkcs1v15::SigningKey`, which no source rule can
# tie to rsa, so the rename itself fails, in any workspace member and any dependency table.
rename_fail='^FAIL: the rsa package is a dependency under another name'
rsa_pub='rsa_pub = { package = "rsa", version = "=0.10.0-rc.21", default-features = false }'

new_case renamed-binding
replace_in bindings/wasm/Cargo.toml 'wasm-bindgen = "0.2.130"' $'wasm-bindgen = "0.2.130"\n'"$rsa_pub"
append_to bindings/wasm/src/lib.rs 'use rsa_pub::pkcs1v15::SigningKey;'
expect_fail "package = \"rsa\" renamed in a binding, used as rsa_pub::pkcs1v15::SigningKey" \
  "^  - polyjose-wasm \\(bindings/wasm/Cargo.toml\\): rsa as rsa_pub in \\[dependencies\\]$" "$rename_fail"

new_case renamed-workspace-dependency
replace_in Cargo.toml 'rsa = { version = "=0.10.0-rc.21", default-features = false }' \
  $'rsa = { version = "=0.10.0-rc.21", default-features = false }\n'"$rsa_pub"
replace_in bindings/ffi/Cargo.toml 'polyjose.workspace = true' $'polyjose.workspace = true\nrsa_pub.workspace = true'
expect_fail "package = \"rsa\" renamed in [workspace.dependencies], inherited by a binding" \
  "^  - polyjose-ffi \\(bindings/ffi/Cargo.toml\\): rsa as rsa_pub in \\[dependencies\\]$" "$rename_fail"

# cargo refuses a second name for a package a crate already depends on, so the core's own rsa
# dependency is the one renamed (each edit relocks, so the workspace keeps `rsa` too).
new_case renamed-core-dependency
replace_in Cargo.toml 'rsa = { version = "=0.10.0-rc.21", default-features = false }' \
  $'rsa = { version = "=0.10.0-rc.21", default-features = false }\n'"$rsa_pub"
replace_in crates/polyjose/Cargo.toml $'\nrsa.workspace = true\n' $'\nrsa_pub.workspace = true\n'
expect_fail "the core's rsa dependency renamed through [workspace.dependencies]" \
  "^  - polyjose \\(crates/polyjose/Cargo.toml\\): rsa as rsa_pub in \\[dependencies\\]$" "$rename_fail"

new_case renamed-dev-dependency
append_to bindings/ffi/Cargo.toml $'\n[dev-dependencies]\n'"$rsa_pub"
relock
expect_fail "package = \"rsa\" renamed in a binding's [dev-dependencies]" \
  "^  - polyjose-ffi \\(bindings/ffi/Cargo.toml\\): rsa as rsa_pub in \\[dev-dependencies\\]$" "$rename_fail"

new_case renamed-target-dependency
append_to bindings/node/Cargo.toml $'\n[target."cfg(unix)".dependencies]\nr = { package = "rsa", version = "=0.10.0-rc.21", default-features = false }'
relock
expect_fail "package = \"rsa\" renamed in a [target.*.dependencies] table" \
  "^  - polyjose-node \\(bindings/node/Cargo.toml\\): rsa as r in \\[target\\.cfg\\(unix\\)\\.dependencies\\]$" "$rename_fail"

# --- Check 11: rsa features ------------------------------------------------------------------------
new_case rsa-feature
replace_in Cargo.toml 'rsa = { version = "=0.10.0-rc.21", default-features = false }' \
  'rsa = { version = "=0.10.0-rc.21", default-features = false, features = ["hazmat"] }'
expect_fail "rsa feature" "^  - rsa 0\\.10\\.0-rc\\.21 with features: hazmat$" "^FAIL: rsa must be built with no features"

finish
