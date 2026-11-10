#!/usr/bin/env bash
# Negative test of scripts/check-rsa-symbols.sh, the compiled-symbol half of the RSA guard
# (ADR 0049 §1), narrowed by ADR 0067 §6: the gate builds polyjose and each binding and fails on
# any symbol of RSA key generation, RSA1_5, an unblinded, typed or scheme-based private-key path or
# hazmat in their own objects. Every case runs that gate alone, never check-deps.sh, so a case that
# fails here is caught by the compiled output whatever the text scan sees.
#
# Must fail (each is reachable code, so it is compiled: unreachable private code is never codegened
# and ships nothing, which is the text scan's job):
#   1-4. the security audit's four reproductions, which each passed the old text scan:
#        `use {rsa as r};`, a `#[path]` module outside src/ with `use rsa as r;`, a macro taking
#        `rsa` as an ident (`<k!(rsa)>::random`), and a `#[path]` child of jws::rsa using
#        `super::pkcs1v15 as p`, each making a pkcs1v15::SigningKey;
#   5.   a plain `rsa::RsaPrivateKey::new` (key generation) from a public function;
#   6.   OAEP decryption (`oaep::DecryptingKey` through `rsa::traits::Decryptor`);
#   7.   PSS signing (`pss::SigningKey`);
#   8.   a generic polyjose function that only a binding instantiates, so the RSA code is in the
#        binding's objects and not polyjose's;
#   9.   a `#[cfg(not(debug_assertions))]` public function (macro spelling), which only the
#        release configuration compiles;
#  22.   the unblinded paths ADR 0067 §6 keeps out (`PrivateKey::sign` with a scheme, and the
#        RNG-less `pkcs1v15_sign` and `oaep_decrypt`), and RSA1_5 in both directions
#        (`pkcs1v15_decrypt_with_rng`, `pkcs1v15_encrypt_with_rng`).
#  23.   must fail closed: RSA private-key code in polyjose with no blinded private-key core
#        (rsa_decrypt, rsa::algorithms::blinding) instantiated with polyjose::rng::CryptoRngAdapter (the positive sentinel; the RNG is renamed in the copy
#        and a from_components call planted, so the case holds on any tree).
# (An uncalled `#[inline] pub fn` and an uninstantiated generic `pub fn` are never codegened in
# polyjose, so they have no symbol to find: the text scan's macro rule catches those, rsa-guard.sh.)
# Extra targets (--target, feature 0013 F15):
#  20.   must fail: the 0008 security audit's L2 plant, `#[cfg(target_os = "android")]` code in
#        polyjose-ffi calling rsa::RsaPrivateKey::from_p_q (still forbidden), with rsa only under
#        [target.'cfg(target_os = "android")'.dependencies], under --target aarch64-linux-android,
#        in the dev and the release configuration; and the same plant in polyjose-surface, which
#        polyjose-ffi links, in the dev configuration. Documented residual: without --target the
#        default configurations build no Android target, so the same plant passes (asserted, so a
#        change of the default list shows up here); the callers that package or regress a target
#        pass it with --target (0008 F08 passes the four Android triples).
#  21.   must fail closed (exit 2, before any build): --target nonsense (not a triple rustc
#        knows), and a known triple whose std is not installed. Case 20 needs the Android std: if
#        it is missing, the case FAILs (rustup target add), it is never SKIPPED (pipeline rule 9;
#        `SKIPPED (host:<tool>)` is for host tools, and a rustup target is not on test-all.sh's
#        owner-accepted list).
# Must fail closed (exit 2, before any build):
#  10.   a workspace member with no library target (build tooling, like polyjose-uniffi-bindgen)
#        whose tree holds a workspace member (here polyjose), which the gate cannot read.
#  11-13. the same, whose tree holds rsa without polyjose: as a normal, a build- or a
#        dev-dependency (the tree is read with -e normal,build,dev).
#  14.   the same, with polyjose or rsa only behind an optional feature (an optional normal
#        polyjose or rsa, an optional rsa build-dependency), which the default tree does not show
#        but `--all-features` builds compile (the tree is the union of the default,
#        --no-default-features and --all-features trees; review S1 of feature 0013).
#  15.   the feature 0013 security audit's L1 plant, as written: a bin-only tools/evil member with
#        an optional rsa and polyjose behind a feature, compiling rsa::pkcs1v15::SigningKey (the
#        text scan fails on it too, rsa-guard.sh).
#  16.   the audit's I4 plant in its library-less form: a tools/ member whose only polyjose edge is
#        a dev-dependency enabling its test-RNG feature through a TOML escape (the feature itself
#        is check-test-vectors-off.sh's; here the dev tree holding polyjose is what stops the gate).
# The shipped build's extra Cargo arguments (feature 0006 F06, security audit L2): the gate builds
# polyjose-wasm for wasm32 with the one WASM_CARGO_ARGS line of bindings/wasm/scripts/wasm-cargo-args.sh
# (ADR 0059), which build-package.sh sources, so it reads the code that ships:
#  17.   the unchanged tree's wasm32 configurations are labelled with that line's arguments;
#  18.   a `#[cfg(polyjose_f06)]` RSA private-key function passes while nothing sets the cfg, and
#        fails once the line (and, in the copy, check-no-cargo-config.sh's allowlist entry, as an
#        ADR superseding ADR 0059 would) adds `build.rustflags` with that cfg;
#  19.   the gate fails closed (exit 2) when the line is missing, or holds a word it cannot read
#        as plain text (an expansion).
# Must pass, with the look-alike symbols present in the scanned objects (read back from --dump,
# so a pass cannot come from scanning nothing): the unchanged tree in every configuration, the
# release ones included (rsa::PublicKey and the typed pkcs1v15/pss VerifyingKey), and a tree
# whose own modules are named like the forbidden items outside the rsa crate (a `cbc::Decryptor`
# as in feature 0003's A*CBC-HS*, and polyjose::jws::rsa::{traits::Decryptor,
# private_key::RsaPrivateKey}).
# Usage: scripts/tests/check-deps/rsa-symbols.sh
set -euo pipefail
export LC_ALL=C
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

# Fail closed on a syntax error under bash 3.2 (feature 0013 F10; see scripts/test-all.sh): the
# EXIT trap of lib.sh again, with the sentinel, which the last line sets.
completed=""
trap 'rc=$?; rm -rf "$scratch"; [ -n "${completed:-}" ] || [ "$rc" -ne 0 ] || { echo "${0##*/}: stopped before its last line (a syntax error?): failing closed" >&2; rc=2; }; exit "$rc"' EXIT

# One build directory for every case, so the dependencies compile once (the cases differ only in
# workspace crates). It is inside $scratch, which lib.sh deletes on exit.
symbols_target="$scratch/target"
dump_dir=""
# A case that changes polyjose's own code needs only the all-features build to show that the
# symbol check catches it (each configuration is another full polyjose build); the clean tree,
# the binding case and the look-alikes run every configuration.
only=""
# Extra --target triples (cases 20 and 21), space-separated; none by default.
targets=""
gate_name=check-rsa-symbols.sh
run_gate() {
  set -- --target-dir "$symbols_target"
  if [ -n "$dump_dir" ]; then set -- "$@" --dump "$dump_dir"; fi
  for o in $only; do set -- "$@" --only "$o"; done
  for t in $targets; do set -- "$@" --target "$t"; done
  scripts/check-rsa-symbols.sh "$@"
}

# expect_closed <description> <ERE>: the copy's gate exits 2 (could not run) with a line matching
# the pattern.
expect_closed() {
  local rc=0
  tests_run=$((tests_run + 1))
  (cd "$case_dir" && run_gate) >"$scratch/out" 2>&1 || rc=$?
  if [ "$rc" -eq 2 ] && grep -Eq -- "$2" "$scratch/out"; then
    echo "ok   - $1: $gate_name fails closed"
    grep -E -- "$2" "$scratch/out" | head -1 | sed 's/^/       /'
  else
    echo "FAIL - $1: exit $rc (expected 2), wanted output matching /$2/"
    sed 's/^/       /' "$scratch/out"
    tests_failed=$((tests_failed + 1))
  fi
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

sym_fail='^FAIL: compiled RSA code that ADR 0067 does not allow'
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
tests_run=$((tests_run + 1))
if grep -Fqx '  skipped polyjose-uniffi-bindgen: no library target, and neither rsa nor a workspace member in its tree' "$scratch/out"; then
  echo "ok   - unchanged tree: the library-less polyjose-uniffi-bindgen is skipped, and says so"
else
  echo "FAIL - unchanged tree: no line saying polyjose-uniffi-bindgen was skipped"
  tests_failed=$((tests_failed + 1))
fi
# 17. The wasm32 configurations are built with wasm-cargo-args.sh's WASM_CARGO_ARGS (ADR 0059).
cfg="-""-config" # cargo's config flag, in two pieces: check-no-cargo-config.sh scans this file
wasm_args="$cfg 'profile.release.opt-level=\"z\"'"
for suffix in "" " --release"; do
  tests_run=$((tests_run + 1))
  if grep -Fqx "  polyjose-wasm $wasm_args$suffix (wasm32-unknown-unknown): polyjose, polyjose_wasm" "$scratch/out"; then
    echo "ok   - unchanged tree: polyjose-wasm$suffix (wasm32) is built with wasm-cargo-args.sh's WASM_CARGO_ARGS"
  else
    echo "FAIL - unchanged tree: no polyjose-wasm $wasm_args$suffix (wasm32-unknown-unknown) configuration"
    tests_failed=$((tests_failed + 1))
  fi
done
expect_symbol "unchanged tree" "rsa::public_key::PublicKey"
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
# shellcheck disable=SC2016 # Rust source: $c is a macro variable, not a shell expansion
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
expect_fail "use rsa::RsaPrivateKey; RsaPrivateKey::new" "<rsa::private_key::PrivateKey>::new" "$sym_fail"

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

# 22. The unblinded paths and RSA1_5, which ADR 0067 §6 keeps out next to the blinded entry points.
#     Each plant is a public, non-generic function, so it is compiled.
new_case unblinded-scheme-sign
append_to "$lib_rs" '/// Test only.
#[doc(hidden)]
pub fn evil(key: &rsa::RsaPrivateKey, digest: &[u8]) -> bool {
    key.sign(rsa::Pkcs1v15Sign::new::<sha2::Sha256>(), digest).is_ok()
}'
expect_fail "PrivateKey::sign (unblinded without an RNG)" "<rsa::private_key::PrivateKey>::sign" "$sym_fail"

new_case unblinded-pkcs1v15-sign
append_to "$lib_rs" '/// Test only.
#[doc(hidden)]
pub fn evil(key: &rsa::RsaPrivateKey, msg: &[u8]) -> bool {
    key.pkcs1v15_sign::<sha2::Sha256>(msg).is_ok()
}'
expect_fail "PrivateKey::pkcs1v15_sign (no RNG)" "<rsa::private_key::PrivateKey>::pkcs1v15_sign" "$sym_fail"

new_case unblinded-oaep-decrypt
append_to "$lib_rs" '/// Test only.
#[doc(hidden)]
pub fn evil(key: &rsa::RsaPrivateKey, ciphertext: &[u8]) -> bool {
    key.oaep_decrypt::<sha2::Sha256>(ciphertext).is_ok()
}'
expect_fail "PrivateKey::oaep_decrypt (no RNG)" "<rsa::private_key::PrivateKey>::oaep_decrypt" "$sym_fail"

new_case rsa1-5-decrypt
append_to "$lib_rs" '/// Test only.
#[doc(hidden)]
pub fn evil(key: &rsa::RsaPrivateKey, ciphertext: &[u8]) -> bool {
    let mut rng = crate::rng::CryptoRngAdapter::os();
    key.pkcs1v15_decrypt_with_rng(&mut rng, ciphertext).is_ok()
}'
expect_fail "PrivateKey::pkcs1v15_decrypt_with_rng (RSA1_5)" "<rsa::private_key::PrivateKey>::pkcs1v15_decrypt_with_rng" "$sym_fail"

new_case rsa1-5-encrypt
append_to "$lib_rs" '/// Test only.
#[doc(hidden)]
pub fn evil(key: &rsa::RsaPublicKey, msg: &[u8]) -> bool {
    let mut rng = crate::rng::CryptoRngAdapter::os();
    key.pkcs1v15_encrypt_with_rng(&mut rng, msg).is_ok()
}'
expect_fail "PublicKey::pkcs1v15_encrypt_with_rng (RSA1_5)" "<rsa::public_key::PublicKey>::pkcs1v15_encrypt_with_rng" "$sym_fail"

# 23. The positive sentinel fails closed when polyjose has RSA private-key code but no blinded
#     entry point instantiated with its RNG: the RNG type is renamed throughout the copy, and a
#     from_components call makes sure private-key code is there on any tree.
new_case sentinel-no-blinded-path
python3 -I -c '
import os, sys
for top in sys.argv[1:]:
    for dirpath, _, names in os.walk(top):
        for name in names:
            path = os.path.join(dirpath, name)
            if not name.endswith(".rs"):
                continue
            with open(path, encoding="utf-8") as f:
                text = f.read()
            if "CryptoRngAdapter" in text:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(text.replace("CryptoRngAdapter", "OsRngAdapter"))
' "$case_dir/crates/polyjose/src" "$case_dir/bindings" || lib_die "could not rename the RNG in the copy"
append_to "$lib_rs" '/// Test only.
#[doc(hidden)]
pub fn evil(n: rsa::BoxedUint, e: rsa::BoxedUint, d: rsa::BoxedUint, p: rsa::BoxedUint, q: rsa::BoxedUint) -> bool {
    rsa::RsaPrivateKey::from_components(n, e, d, vec![p, q]).is_ok()
}'
expect_closed "RSA private-key code without a blinded entry point on polyjose's RNG" \
  "has RSA private-key code but no symbol of rsa's blinded private-key core"

# 9. Code that only a release build compiles (`cfg(not(debug_assertions))`, the F01 tester's
#    finding (c)), with the macro spelling the text scan's macro rule catches (rsa-guard.sh). The
#    dev-profile configurations never compile it, so this case runs the release one alone: the
#    release pass catches it on its own.
only=polyjose-all-features-release
new_case release-only
# shellcheck disable=SC2016 # Rust source: $c is a macro variable, not a shell expansion
append_to "$lib_rs" 'macro_rules! k { ($c:ident) => { $c::pkcs1v15::SigningKey::<sha2::Sha256> } }
/// Test only.
#[doc(hidden)]
#[cfg(not(debug_assertions))]
pub fn evil(msg: &[u8]) -> Vec<u8> {
    use p256::ecdsa::signature::{SignatureEncoding, Signer as _};
    let mut rng = p256::elliptic_curve::rand_core::UnwrapErr(crate::rng::CryptoRngAdapter::os());
    let key = <k!(rsa)>::random(&mut rng, 2048).unwrap();
    key.sign(msg).to_vec()
}'
expect_fail "#[cfg(not(debug_assertions))] pub fn with <k!(rsa)>::random, release configuration" \
  "$pkcs1_sign" "$sym_fail in the objects of polyjose \\(polyjose --all-features --release \\(host\\)\\)"

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
# polyjose-wasm reaches polyjose through polyjose-surface only; the plant calls it directly.
replace_in bindings/wasm/Cargo.toml $'[dependencies]\npolyjose-surface' $'[dependencies]\npolyjose.workspace = true\npolyjose-surface'
expect_fail "generic polyjose fn instantiated by polyjose-wasm only" \
  "<rsa::private_key::PrivateKey>::new" "$sym_fail in the objects of polyjose_wasm \\("

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

# 20. The 0008 audit's L2 plant: RSA private-key code that only an Android build compiles, in
#     polyjose-ffi (the crate the Android .so is built from, ADR 0033) and in polyjose-surface,
#     which it links. rsa is reached only under a target-specific table, so no host build has it.
#     RsaPrivateKey::from_p_q (it derives d from the primes, which ADR 0067 §3 keeps out with key
#     generation) is neither generic nor #[inline], so the release profile cannot inline the call
#     away and its symbol stays in the plant's objects (a clone() would be).
android=aarch64-linux-android
android_std=$(cd "$base" && rustc --print target-libdir --target "$android" 2>/dev/null) || android_std=""
set -- "$android_std"/libstd-*.rlib
if [ -z "$android_std" ] || [ ! -f "$1" ]; then
  tests_run=$((tests_run + 1))
  echo "FAIL - Android-only plant: the $android std is not installed (rustup target add $android; rust-toolchain.toml lists it), so the case cannot run"
  tests_failed=$((tests_failed + 1))
else
  android_rsa='
[target.'"'"'cfg(target_os = "android")'"'"'.dependencies]
rsa = { workspace = true }'
  android_body='/// Test only.
#[cfg(target_os = "android")]
#[doc(hidden)]
pub fn evil(p: rsa::BoxedUint, q: rsa::BoxedUint, e: rsa::BoxedUint) -> bool {
    rsa::RsaPrivateKey::from_p_q(p, q, e).is_ok()
}
#[cfg(target_os = "android")]
#[used]
static KEEP: fn(rsa::BoxedUint, rsa::BoxedUint, rsa::BoxedUint) -> bool = evil;'
  for crate_dir in ffi surface; do
    new_case "android-only-$crate_dir"
    append_to "bindings/$crate_dir/Cargo.toml" "$android_rsa"
    append_to "bindings/$crate_dir/src/lib.rs" "$android_body"
    relock
    crate=polyjose_$crate_dir
    targets=$android
    if [ "$crate_dir" = ffi ]; then configs="polyjose-ffi-$android polyjose-ffi-$android-release"; else configs="polyjose-ffi-$android"; fi
    for config in $configs; do
      case $config in *-release) label="polyjose-ffi --release ($android)" ;; *) label="polyjose-ffi ($android)" ;; esac
      only=$config
      dump_dir="$scratch/dump-$crate_dir-$config"
      expect_fail "Android-only RsaPrivateKey in polyjose-$crate_dir, --target $android, $config" \
        "matches rsa::private_key::PrivateKey>::from_p_q: RSA key generation" \
        "$sym_fail in the objects of $crate \\($(printf '%s' "$label" | sed 's/[().]/\\&/g')\\)"
      # The target's own objects were read: polyjose's dump for the triple has its RSA verification.
      expect_symbol "Android-only plant in polyjose-$crate_dir, $config" "rsa::public_key::PublicKey"
      dump_dir=""
    done
    targets=""
    # The documented residual: without --target, no configuration compiles the plant.
    if [ "$crate_dir" = ffi ]; then
      only="polyjose-ffi polyjose-ffi-release"
      expect_pass "Android-only RsaPrivateKey in polyjose-ffi, no --target (documented residual: the caller passes the target)"
      tests_run=$((tests_run + 1))
      if grep -Eq '^ok: .* 2 configurations, ' "$scratch/out" && ! grep -q "$android" "$scratch/out"; then
        echo "ok   - no --target: the host polyjose-ffi configurations ran, and none for $android"
      else
        echo "FAIL - no --target: expected the two host polyjose-ffi configurations and no $android one"
        sed 's/^/       /' "$scratch/out"
        tests_failed=$((tests_failed + 1))
      fi
    fi
    only=""
  done
fi

# 21. A target the check cannot build fails closed before any build: a name rustc does not know,
#     and a known triple whose std is not installed (the first such one in rustc's list).
new_case target-unknown
targets=nonsense
expect_closed "--target nonsense" '^ERROR: --target: nonsense is not a target rustc knows'
missing=""
for t in $(cd "$base" && rustc --print target-list); do
  dir=$(cd "$base" && rustc --print target-libdir --target "$t" 2>/dev/null) || continue
  set -- "$dir"/libstd-*.rlib
  if [ ! -f "$1" ]; then missing=$t; break; fi
done
if [ -n "$missing" ]; then
  targets=$missing
  expect_closed "--target $missing (std not installed)" "^ERROR: --target: the std of $missing is not installed"
else
  tests_run=$((tests_run + 1))
  echo "FAIL - every target rustc knows has its std installed; no triple to test the missing-std case with"
  tests_failed=$((tests_failed + 1))
fi
targets=""

# 10. A library-less member (build tooling such as polyjose-uniffi-bindgen) is skipped only while
#     its tree holds neither rsa nor a workspace member. One that depends on polyjose could carry
#     polyjose code the gate never reads, so the gate stops.
new_case tool-with-core
append_to tools/rsa-tool/Cargo.toml '[package]
name = "rsa-tool"
version = "0.0.0"
edition = "2024"
publish = false

[dependencies]
polyjose = { path = "../../crates/polyjose" }'
append_to tools/rsa-tool/src/main.rs 'fn main() {}'
replace_in Cargo.toml 'members = [' 'members = ["tools/rsa-tool", '
tests_run=$((tests_run + 1))
rc=0
(cd "$case_dir" && run_gate) >"$scratch/out" 2>&1 || rc=$?
if [ "$rc" -eq 2 ] && grep -Eq '^ERROR: workspace member rsa-tool has no library target, and its tree contains polyjose' "$scratch/out"; then
  echo "ok   - library-less member depending on polyjose: $gate_name fails closed"
else
  echo "FAIL - library-less member depending on polyjose: exit $rc (expected 2) with the no-library-target error"
  sed 's/^/       /' "$scratch/out"
  tests_failed=$((tests_failed + 1))
fi

# 11-13. A library-less member whose tree holds rsa (and no workspace member) is not skipped either,
#        whichever kind of dependency reaches rsa.
for kind in dependencies build-dependencies dev-dependencies; do
  new_case "tool-with-rsa-$kind"
  append_to tools/rsa-tool/Cargo.toml "[package]
name = \"rsa-tool\"
version = \"0.0.0\"
edition = \"2024\"
publish = false

[$kind]
rsa = { workspace = true }"
  append_to tools/rsa-tool/src/main.rs 'fn main() {}'
  replace_in Cargo.toml 'members = [' 'members = ["tools/rsa-tool", '
  tests_run=$((tests_run + 1))
  rc=0
  (cd "$case_dir" && run_gate) >"$scratch/out" 2>&1 || rc=$?
  if [ "$rc" -eq 2 ] && grep -Eq '^ERROR: workspace member rsa-tool has no library target, and its tree contains rsa;' "$scratch/out"; then
    echo "ok   - library-less member with rsa as a $kind: $gate_name fails closed"
  else
    echo "FAIL - library-less member with rsa as a $kind: exit $rc (expected 2) with the no-library-target error"
    sed 's/^/       /' "$scratch/out"
    tests_failed=$((tests_failed + 1))
  fi
done

# 14. The same when polyjose or rsa is reached only through an optional dependency behind a
#     feature: the default tree does not show it, but `cargo build --workspace --all-features`
#     compiles it, so the skip reads every feature set (cargo has no optional dev-dependency).
for variant in "dependencies polyjose" "dependencies rsa" "build-dependencies rsa"; do
  kind=${variant% *}; dep=${variant#* }
  case $dep in
    polyjose) spec='{ path = "../../crates/polyjose", optional = true }' ;;
    *) spec='{ workspace = true, optional = true }' ;;
  esac
  new_case "tool-with-optional-$dep-$kind"
  append_to tools/rsa-tool/Cargo.toml "[package]
name = \"rsa-tool\"
version = \"0.0.0\"
edition = \"2024\"
publish = false

[features]
x = [\"dep:$dep\"]

[$kind]
$dep = $spec"
  append_to tools/rsa-tool/src/main.rs 'fn main() {}'
  replace_in Cargo.toml 'members = [' 'members = ["tools/rsa-tool", '
  tests_run=$((tests_run + 1))
  rc=0
  (cd "$case_dir" && run_gate) >"$scratch/out" 2>&1 || rc=$?
  if [ "$rc" -eq 2 ] && grep -Eq "^ERROR: workspace member rsa-tool has no library target, and its tree contains ${dep}[;,]" "$scratch/out"; then
    echo "ok   - library-less member with an optional $dep in [$kind] behind a feature: $gate_name fails closed"
  else
    echo "FAIL - library-less member with an optional $dep in [$kind] behind a feature: exit $rc (expected 2) with the no-library-target error"
    sed 's/^/       /' "$scratch/out"
    tests_failed=$((tests_failed + 1))
  fi
done

# 15. The security audit's L1 plant, as written (feature 0013 review-security.md), except that the
#     member takes rsa from [workspace.dependencies] (the pin of ADR 0055 §4, default features off)
#     instead of a version written here, which a bump of that pin would make unresolvable.
new_case tool-audit-l1
append_to tools/evil/Cargo.toml '[package]
name = "polyjose-evil-tool"
version = "0.0.0"
edition = "2024"
publish = false

[dependencies]
rsa = { workspace = true, optional = true }
polyjose = { path = "../../crates/polyjose", optional = true }

[features]
signer = ["dep:rsa", "dep:polyjose"]

[[bin]]
name = "evil"
path = "src/main.rs"'
append_to tools/evil/src/main.rs '#[cfg(feature = "signer")]
pub fn sign(k: &rsa::RsaPrivateKey, m: &[u8]) -> Vec<u8> {
    use rsa::pkcs1v15::SigningKey;
    let _ = (SigningKey::<rsa::sha2::Sha256>::new_unprefixed(k.clone()), m); Vec::new()
}
fn main() {}'
replace_in Cargo.toml 'members = [' 'members = ["tools/evil", '
tests_run=$((tests_run + 1))
rc=0
(cd "$case_dir" && run_gate) >"$scratch/out" 2>&1 || rc=$?
if [ "$rc" -eq 2 ] && grep -Eq '^ERROR: workspace member polyjose-evil-tool has no library target, and its tree contains polyjose, rsa;' "$scratch/out"; then
  echo "ok   - audit L1 plant (optional rsa and polyjose in a bin-only tools/ member): $gate_name fails closed"
else
  echo "FAIL - audit L1 plant (optional rsa and polyjose in a bin-only tools/ member): exit $rc (expected 2) with the no-library-target error"
  sed 's/^/       /' "$scratch/out"
  tests_failed=$((tests_failed + 1))
fi

# 16. The audit's I4 plant, library-less: polyjose only as a dev-dependency, with its test-RNG
#     feature spelled through a TOML escape (\u0069 is "i").
new_case tool-audit-i4
append_to tools/rsa-tool/Cargo.toml '[package]
name = "rsa-tool"
version = "0.0.0"
edition = "2024"
publish = false

[dev-dependencies]
polyjose = { path = "../../crates/polyjose", features = ["\u0069nsecure-test-vectors"] }'
append_to tools/rsa-tool/src/main.rs 'fn main() {}'
replace_in Cargo.toml 'members = [' 'members = ["tools/rsa-tool", '
tests_run=$((tests_run + 1))
rc=0
(cd "$case_dir" && run_gate) >"$scratch/out" 2>&1 || rc=$?
if [ "$rc" -eq 2 ] && grep -Eq '^ERROR: workspace member rsa-tool has no library target, and its tree contains polyjose[;,]' "$scratch/out"; then
  echo "ok   - audit I4 plant (escaped test-RNG feature on a polyjose dev-dependency, library-less): $gate_name fails closed"
else
  echo "FAIL - audit I4 plant (escaped test-RNG feature on a polyjose dev-dependency, library-less): exit $rc (expected 2) with the no-library-target error"
  sed 's/^/       /' "$scratch/out"
  tests_failed=$((tests_failed + 1))
fi

# set_line <path in the copy> <ERE of the one line to replace> <new line, or empty to delete it>
set_line() {
  python3 -I -c '
import re, sys
path, pattern, new = sys.argv[1:4]
with open(path, encoding="utf-8") as f:
    lines = f.read().splitlines(True)
hits = [i for i, l in enumerate(lines) if re.search(pattern, l)]
if len(hits) != 1:
    sys.exit("%s: %d lines match %r, expected one" % (path, len(hits), pattern))
lines[hits[0]] = new + "\n" if new else ""
with open(path, "w", encoding="utf-8") as f:
    f.write("".join(lines))
' "$case_dir/$1" "$2" "$3" || lib_die "could not edit $1 in the copy"
}

# allow_line <WASM_CARGO_ARGS line>: wasm-cargo-args.sh holds the line, and the copy's
# check-no-cargo-config.sh allows exactly it (what an ADR superseding ADR 0059 would change).
allow_line() {
  set_line bindings/wasm/scripts/wasm-cargo-args.sh '^WASM_CARGO_ARGS=' "$1"
  set_line scripts/check-no-cargo-config.sh '^allowed_line=' "allowed_line=$(printf '%s' "$1" | python3 -I -c 'import shlex, sys; print(shlex.quote(sys.stdin.read()))')"
}

# 18. A plant that only a cfg from the shipped build's arguments compiles.
only=polyjose-wasm-wasm32-unknown-unknown
cfg_plant='/// Test only.
#[doc(hidden)]
#[cfg(polyjose_f06)]
pub fn evil() -> bool {
    let mut rng = p256::elliptic_curve::rand_core::UnwrapErr(crate::rng::CryptoRngAdapter::os());
    rsa::RsaPrivateKey::new(&mut rng, 2048).is_ok()
}'
new_case wasm-args-cfg-unset
append_to "$lib_rs" "$cfg_plant"
expect_pass "a #[cfg(polyjose_f06)] RsaPrivateKey::new while nothing sets the cfg (wasm32)"

new_case wasm-args-cfg-set
append_to "$lib_rs" "$cfg_plant"
allow_line "WASM_CARGO_ARGS=($wasm_args $cfg 'build.rustflags=[\"--cfg\",\"polyjose_f06\",\"--check-cfg\",\"cfg(polyjose_f06)\"]')"
expect_fail "the same plant with build.rustflags --cfg polyjose_f06 in wasm-cargo-args.sh's WASM_CARGO_ARGS (wasm32)" \
  "<rsa::private_key::PrivateKey>::new" \
  "$sym_fail in the objects of polyjose \\(polyjose-wasm .*polyjose_f06.* \\(wasm32-unknown-unknown\\)\\)"
only=""

# 19. No line, or a word that is not plain text: the gate fails closed before any build.
for variant in missing expansion; do
  new_case "wasm-args-$variant"
  case $variant in
    missing) set_line bindings/wasm/scripts/wasm-cargo-args.sh '^WASM_CARGO_ARGS=' ""
      want='^ERROR: bindings/wasm/scripts/wasm-cargo-args\.sh has no WASM_CARGO_ARGS=\(\.\.\.\) line' ;;
    *) allow_line "WASM_CARGO_ARGS=($cfg \"\$F06_ARGS\")"
      want='^ERROR: cannot read the WASM_CARGO_ARGS line of bindings/wasm/scripts/wasm-cargo-args\.sh as plain words' ;;
  esac
  tests_run=$((tests_run + 1))
  rc=0
  (cd "$case_dir" && run_gate) >"$scratch/out" 2>&1 || rc=$?
  if [ "$rc" -eq 2 ] && grep -Eq "$want" "$scratch/out"; then
    echo "ok   - WASM_CARGO_ARGS line $variant: $gate_name fails closed"
  else
    echo "FAIL - WASM_CARGO_ARGS line $variant: exit $rc (expected 2) with output matching /$want/"
    sed 's/^/       /' "$scratch/out"
    tests_failed=$((tests_failed + 1))
  fi
done

finish_rc=0
finish || finish_rc=$?
completed=1; exit "$finish_rc"
