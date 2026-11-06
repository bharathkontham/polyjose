#!/usr/bin/env bash
# Negative test of the ADR 0021 guard in scripts/check-deps.sh (checks 9-11), which deny.toml's
# ignore of RUSTSEC-2023-0071 depends on. Each change below is made in a copy of the tree and must
# make check-deps.sh fail with the guard's own message (and no other check's):
#   - RSA private-key and signing types and an Oaep decryption in crates/polyjose/src, and the
#     same in a binding (bindings/**);
#   - a sha1 dependency (also when sha1 is allowlisted and credited, so check 10 alone catches it);
#   - an rsa feature.
# Legitimate look-alikes must pass: an ECDSA SigningKey and a cbc Decryptor in files that do not
# use the rsa crate, a child module named `rsa` reached as `self::rsa::`, and the typed RSA
# VerifyingKey. The unchanged tree must pass.
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

# --- Check 11: rsa features ------------------------------------------------------------------------
new_case rsa-feature
replace_in Cargo.toml 'rsa = { version = "=0.10.0-rc.20", default-features = false }' \
  'rsa = { version = "=0.10.0-rc.20", default-features = false, features = ["hazmat"] }'
expect_fail "rsa feature" "^  - rsa 0\\.10\\.0-rc\\.20 with features: hazmat$" "^FAIL: rsa must be built with no features"

finish
