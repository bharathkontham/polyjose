#!/usr/bin/env bash
# Negative test of scripts/check-rsa-symbols.sh, the compiled-symbol half of the ADR 0021 guard
# (ADR 0049 §1) that deny.toml's ignore of RUSTSEC-2023-0071 depends on. The gate builds polyjose
# and each binding and fails on any RSA private-key, signing or decryption symbol in their own
# objects. Every case runs that gate alone, never check-deps.sh, so a case that fails here is
# caught by the compiled output whatever the text scan sees.
#
# Must fail (each is reachable code, so it is compiled: unreachable private code is never codegened
# and ships nothing, which is the text scan's job):
#   1-4. the security audit's four reproductions, which each passed the old text scan:
#        `use {rsa as r};`, a `#[path]` module outside src/ with `use rsa as r;`, a macro taking
#        `rsa` as an ident (`<k!(rsa)>::random`), and a `#[path]` child of jws::rsa using
#        `super::pkcs1v15 as p`, each making a pkcs1v15::SigningKey;
#   5.   a plain `rsa::RsaPrivateKey::new` from a public function;
#   6.   OAEP decryption (`oaep::DecryptingKey` through `rsa::traits::Decryptor`);
#   7.   PSS signing (`pss::SigningKey`);
#   8.   a generic polyjose function that only a binding instantiates, so the RSA code is in the
#        binding's objects and not polyjose's.
# Must pass, with the look-alike symbols present in the scanned objects (read back from --dump,
# so a pass cannot come from scanning nothing): the unchanged tree (rsa::RsaPublicKey and the
# typed pkcs1v15/pss VerifyingKey), and a tree whose own modules are named like the forbidden
# items outside the rsa crate (a `cbc::Decryptor` as in feature 0003's A*CBC-HS*, and
# polyjose::jws::rsa::{traits::Decryptor, private_key::RsaPrivateKey}).
# Usage: scripts/tests/check-deps/rsa-symbols.sh
set -euo pipefail
export LC_ALL=C
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

# One build directory for every case, so the dependencies compile once (the cases differ only in
# workspace crates). It is inside $scratch, which lib.sh deletes on exit.
symbols_target="$scratch/target"
dump_dir=""
# A case that changes polyjose's own code needs only the all-features build to show that the
# symbol check catches it (each configuration is another full polyjose build); the clean tree,
# the binding case and the look-alikes run every configuration.
only=""
gate_name=check-rsa-symbols.sh
run_gate() {
  set -- --target-dir "$symbols_target"
  if [ -n "$dump_dir" ]; then set -- "$@" --dump "$dump_dir"; fi
  if [ -n "$only" ]; then set -- "$@" --only "$only"; fi
  scripts/check-rsa-symbols.sh "$@"
}

# expect_symbol <description> <fixed string>: the last run's dump (see run_gate) lists a symbol
# that contains the string, i.e. the gate saw it and let it pass.
expect_symbol() {
  tests_run=$((tests_run + 1))
  # grep reads the files itself: under pipefail, `cat | grep -q` fails when grep stops early.
  if [ -n "$dump_dir" ] && grep -Fqs -- "$2" "$dump_dir"/*.txt; then
    echo "ok   - $1: scanned and allowed: $2"
  else
    echo "FAIL - $1: no scanned symbol contains $2 (dump: $dump_dir)"
    tests_failed=$((tests_failed + 1))
  fi
}

sym_fail='^FAIL: compiled RSA private-key, signing or decryption code'
hmac=crates/polyjose/src/jws/hmac.rs
lib_rs=crates/polyjose/src/lib.rs
# The audit's signing body. `#[used]` keeps a pointer to it, so it is compiled although nothing
# calls it.
sign_body='pub(crate) fn evil(msg: &[u8]) -> Vec<u8> {
    use p256::ecdsa::signature::{SignatureEncoding, Signer as _};
    let mut rng = p256::elliptic_curve::rand_core::UnwrapErr(crate::rng::CryptoRngAdapter::os());
    let k = r::pkcs1v15::SigningKey::<sha2::Sha256>::random(&mut rng, 2048).unwrap();
    k.sign(msg).to_vec()
}
#[used]
static KEEP: fn(&[u8]) -> Vec<u8> = evil;'
pkcs1_sign='rsa::pkcs1v15::signing_key::SigningKey<sha2::Sha256>'

new_case clean
dump_dir="$scratch/dump-clean"
expect_pass "unchanged tree"
expect_symbol "unchanged tree" "rsa::public_key::RsaPublicKey"
expect_symbol "unchanged tree" "rsa::pkcs1v15::verifying_key::VerifyingKey<sha2::Sha256>"
expect_symbol "unchanged tree" "rsa::pss::verifying_key::VerifyingKey<sha2::Sha512>"
expect_symbol "unchanged tree" "polyjose::jws::rsa::sign"
dump_dir=""

# Cases 1-7 change polyjose itself: its all-features build is enough.
only=polyjose-all-features

# 1. `use {rsa as r};`
new_case brace-alias
append_to "$hmac" "#[allow(unused_imports)] use {rsa as r};
$sign_body"
expect_fail "audit 1: use {rsa as r}; r::pkcs1v15::SigningKey" "$pkcs1_sign" "$sym_fail"

# 2. `#[path]` to a file outside src/.
new_case path-attribute
append_to crates/polyjose/tests/fixtures/helper.rs "use rsa as r;
$sign_body"
append_to "$hmac" '#[path = "../../tests/fixtures/helper.rs"] #[allow(dead_code)] mod helper;'
expect_fail "audit 2: #[path] module outside src/" "$pkcs1_sign" "$sym_fail"

# 3. A macro takes the crate name as an ident.
new_case macro-ident
append_to "$hmac" 'macro_rules! k { ($c:ident) => { $c::pkcs1v15::SigningKey::<sha2::Sha256> } }
pub(crate) fn evil(msg: &[u8]) -> Vec<u8> {
    use p256::ecdsa::signature::{SignatureEncoding, Signer as _};
    let mut rng = p256::elliptic_curve::rand_core::UnwrapErr(crate::rng::CryptoRngAdapter::os());
    let key = <k!(rsa)>::random(&mut rng, 2048).unwrap();
    key.sign(msg).to_vec()
}
#[used]
static KEEP: fn(&[u8]) -> Vec<u8> = evil;'
expect_fail "audit 3: <k!(rsa)>::random" "$pkcs1_sign" "$sym_fail"

# 4. A child module of jws::rsa reaches its private `use rsa::{.., pkcs1v15, ..}`.
new_case child-module
append_to crates/polyjose/src/jws/rsa.rs '#[path = "rsa_child.rs"] mod child;'
append_to crates/polyjose/src/jws/rsa_child.rs "use super::pkcs1v15 as p;
$(printf '%s\n' "$sign_body" | sed 's/r::pkcs1v15::SigningKey/p::SigningKey/')"
expect_fail "audit 4: #[path] child of jws::rsa, super::pkcs1v15 as p" "$pkcs1_sign" "$sym_fail"

# 5. The plain case.
new_case private-key-new
append_to "$lib_rs" '/// Test only.
#[doc(hidden)]
pub fn evil() -> bool {
    use rsa::RsaPrivateKey;
    let mut rng = p256::elliptic_curve::rand_core::UnwrapErr(crate::rng::CryptoRngAdapter::os());
    RsaPrivateKey::new(&mut rng, 2048).is_ok()
}'
expect_fail "use rsa::RsaPrivateKey; RsaPrivateKey::new" "<rsa::private_key::RsaPrivateKey>::new" "$sym_fail"

# 6. RSA-OAEP decryption.
new_case oaep-decrypt
append_to "$lib_rs" '/// Test only.
#[doc(hidden)]
pub fn evil(key: &rsa::RsaPrivateKey, ciphertext: &[u8]) -> bool {
    use rsa::traits::Decryptor;
    rsa::oaep::DecryptingKey::<sha2::Sha256>::new(key.clone()).decrypt(ciphertext).is_ok()
}'
expect_fail "oaep::DecryptingKey through rsa::traits::Decryptor" \
  "rsa::oaep::decrypting_key::DecryptingKey<sha2::Sha256> as rsa::traits::encryption::Decryptor" "$sym_fail"

# 7. RSASSA-PSS signing.
new_case pss-sign
append_to "$lib_rs" '/// Test only.
#[doc(hidden)]
pub fn evil(key: rsa::RsaPrivateKey, msg: &[u8]) -> Vec<u8> {
    use p256::ecdsa::signature::{RandomizedSigner, SignatureEncoding};
    let mut rng = p256::elliptic_curve::rand_core::UnwrapErr(crate::rng::CryptoRngAdapter::os());
    rsa::pss::SigningKey::<sha2::Sha256>::new(key).sign_with_rng(&mut rng, msg).to_vec()
}'
expect_fail "pss::SigningKey" "rsa::pss::signing_key::SigningKey<sha2::Sha256>" "$sym_fail"

only=""

# 8. Generic in polyjose, instantiated only by a binding: polyjose's objects have no RSA code,
#    the binding's do, so only the binding's objects may be named.
new_case binding-instantiates
append_to "$lib_rs" '/// Test only.
#[doc(hidden)]
pub fn evil<T>(_: T) -> bool {
    let mut rng = p256::elliptic_curve::rand_core::UnwrapErr(crate::rng::CryptoRngAdapter::os());
    rsa::RsaPrivateKey::new(&mut rng, 2048).is_ok()
}'
append_to bindings/wasm/src/lib.rs '/// Test only.
#[doc(hidden)]
pub fn evil() -> bool {
    polyjose::evil(0u8)
}'
expect_fail "generic polyjose fn instantiated by polyjose-wasm only" \
  "<rsa::private_key::RsaPrivateKey>::new" "$sym_fail in the objects of polyjose_wasm \\("

# Look-alikes outside the rsa crate: the same item names under polyjose's own paths must pass.
new_case look-alikes
dump_dir="$scratch/dump-look-alikes"
append_to crates/polyjose/src/jws/rsa.rs '/// Test only: named like the items of rsa, under polyjose::jws::rsa.
pub mod traits {
    /// Test only.
    pub struct Decryptor(pub u8);
    impl Decryptor {
        /// Test only.
        pub fn decrypt(&self) -> u8 { self.0 }
    }
}
/// Test only.
pub mod private_key {
    /// Test only.
    pub struct RsaPrivateKey(pub u8);
    impl RsaPrivateKey {
        /// Test only.
        pub fn new(x: u8) -> Self { Self(x) }
    }
}
fn look_alikes() -> u8 {
    traits::Decryptor(2).decrypt() ^ private_key::RsaPrivateKey::new(3).0
}
#[used]
static KEEP_LOOK_ALIKES: fn() -> u8 = look_alikes;'
append_to "$lib_rs" '/// Test only: a cbc::Decryptor like the one of A*CBC-HS* in feature 0003 (RFC 7518 §5.2).
#[doc(hidden)]
pub mod cbc {
    /// Test only.
    pub struct Decryptor<T>(pub T);
    impl<T: Copy> Decryptor<T> {
        /// Test only.
        pub fn decrypt(&self) -> T { self.0 }
    }
}
/// Test only.
#[doc(hidden)]
pub fn look_alikes() -> u8 {
    cbc::Decryptor(1u8).decrypt()
}'
expect_pass "cbc::Decryptor, polyjose::jws::rsa::traits::Decryptor and ::private_key::RsaPrivateKey"
expect_symbol "look-alikes" "polyjose::cbc::Decryptor<u8>>::decrypt"
expect_symbol "look-alikes" "polyjose::jws::rsa::traits::Decryptor>::decrypt"
expect_symbol "look-alikes" "polyjose::jws::rsa::private_key::RsaPrivateKey>::new"
dump_dir=""

finish
