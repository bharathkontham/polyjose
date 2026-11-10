#!/usr/bin/env bash
# Enforces ADR 0067 §3, §6 (RSA private-key operations only through rsa 0.10's blinded entry
# points; no key generation, RSA1_5, unblinded path or hazmat) on compiled output, as ADR 0049 §1
# requires, beside check-deps.sh's text scan (checks 9-12). It keeps its ADR 0021 form, narrowed:
# the private key type and the blinded signing and OAEP-256 decryption paths are allowed, and a
# positive sentinel checks that they are the ones compiled in.
#
# A text scan cannot see every way of naming rsa: an alias in a brace use tree, a #[path] module or
# an include! from outside the scanned roots, a macro that receives `rsa` as an identifier, or a
# child module that reaches its parent's private imports through super::. Whatever the spelling,
# code that uses rsa's forbidden items leaves their symbols in the object code of the crate that
# uses them, so this check reads that object code instead.
#
# What is built (each a configuration that ships), first in the dev profile and then again with
# --release:
#   1. polyjose --lib --all-features (so feature-gated code is in);
#   2. every other workspace member (the bindings), each on its own with its own feature
#      unification, as an rlib (`cargo rustc --crate-type rlib`, so its objects are kept even when
#      it ships as a cdylib or staticlib), on the host;
#   3. polyjose-wasm the same way for wasm32-unknown-unknown, its shipping target (polyjose alone
#      does not build there: getrandom needs the binding's `wasm_js` backend), with the shipped
#      build's extra Cargo arguments: the words of the one `WASM_CARGO_ARGS=(...)` line of
#      bindings/wasm/scripts/wasm-cargo-args.sh, which build-package.sh sources (ADR 0059; feature
#      0006 F06, security audit L2), so
#      the code read is the code of the published .wasm (a cfg or a rustflag added there reaches
#      these builds too). check-no-cargo-config.sh, run first, allows that line only by its exact
#      text and fails on any other assignment of WASM_CARGO_ARGS under bindings/.
# A workspace member with no library target (build tooling such as polyjose-uniffi-bindgen) is
# skipped only when its tree, under every feature set (default, --no-default-features and
# --all-features), holds neither rsa nor another workspace member; otherwise it fails closed.
# The dev profile inlines no call away, so a reference to an rsa item stays a symbol. The release
# profile is what ships, and it compiles code the dev profile never does: anything under
# `cfg(not(debug_assertions))`. It can inline a call away, so it adds to the dev pass and never
# replaces it. Both fail and fail closed the same way.
# What is read: the object members of the rlibs of polyjose and of the binding of each build (the
# codegen-unit files `<crate>-<hash>.<cgu>.rcgu.o`, extracted with ar), never a dependency's
# rlib. Generic code is monomorphized in the crate that instantiates it, and code shared with an
# upstream instance (or not inlined) is an undefined reference, so both the defined and the
# undefined symbols of each object are listed, with nm/llvm-nm, demangled. A binding's own objects
# are read too, because a generic or inline polyjose function is compiled there.
#
# Fails, naming each symbol, its crate, configuration and object, when a demangled symbol holds a
# path of the rsa crate (anchored at the crate root, so polyjose::jws::rsa::sign, or a
# cbc::Decryptor, never matches) that ADR 0067 keeps out: see `RULES` below (rsa 0.10.0's
# defining paths: key generation, anything instantiated with rsa::dummy_rng::DummyRng, the
# unblinded PrivateKey methods, the typed keys and traits, scheme-based signing and decryption,
# RSA1_5 and hazmat, plus the re-export paths ADR 0049 names, e.g. rsa::traits::Decryptor). The same paths
# are also matched in the mangled names (`_ZN3rsa11private_key...` legacy, `C..._3rsa11private_key`
# v0), so a demangler mistake can only add findings. Legacy names are normalized after demangling
# (`$LT$` -> `<`, `..` -> `::`, ...), since llvm-nm's Itanium demangler leaves those escapes;
# rustc 1.99 emits v0 names, but the check does not depend on it.
#
# Fails closed (exit 2), with the reason, when: cargo, rustc, python3, ar or nm is missing;
# wasm-cargo-args.sh has no WASM_CARGO_ARGS line, more than one, or one whose words are not plain
# text (quoted or unquoted literals only: no expansion, glob, escape or comment); a
# workspace member has no library target and its tree holds rsa or another member; a build fails;
# a build does not report polyjose's (or the binding's) rlib; an rlib holds no object or a member
# it does not expect; the symbol tool cannot read an object or prints a line it cannot parse; or
# the symbols are not demangled (each crate must show a `<crate>::` path, and each polyjose rlib
# rsa::public_key::PublicKey, which RS*/PS* verification always uses); or a polyjose rlib holds
# rsa::private_key::PrivateKey code but no symbol of rsa's blinded private-key core
# (rsa::algorithms::rsa::rsa_decrypt(_and_check), rsa::algorithms::blinding::*) instantiated with
# polyjose::rng::CryptoRngAdapter (the positive sentinel).
#
# Tools, first found: the toolchain's own llvm-ar and llvm-nm (the llvm-tools component:
# `rustup component add llvm-tools`; the only choice that reads wasm32 objects everywhere), then
# llvm-ar/llvm-nm on PATH, then ar/nm (Xcode's are LLVM's; GNU binutils' nm reads ELF but not
# wasm). CI installs llvm-tools.
#
# Extra targets (--target TRIPLE, feature 0013 F15, the 0008 security audit's L2): code under a
# target cfg (`cfg(target_os = "android")`, ...) is compiled only for that target, so each triple
# given adds polyjose-ffi, the crate the Android and Apple libraries are built from (ADR 0032,
# ADR 0033), built for it as an rlib in the dev and the release profile like the wasm32
# configuration; the objects of polyjose, of polyjose-ffi and of each workspace member it depends
# on (polyjose-surface) are read. A triple rustc does not know, one whose std is not installed or a
# build that fails exits 2, before any build for the first two.
#
# Residual risk: code compiled only for a target that is not built here is seen by the text scan
# only. A run without --target builds the host and wasm32 alone, so the caller that packages or
# regresses a target must pass it (0008 F08 passes the four Android triples of rust-toolchain.toml;
# the Apple ones are seen only once their caller passes them). The @polyjose/node prebuild
# targets other than this Mac's (aarch64-apple-darwin) -- x86_64-apple-darwin,
# x86_64-unknown-linux-gnu, aarch64-unknown-linux-gnu, x86_64-unknown-linux-musl,
# aarch64-unknown-linux-musl, x86_64-pc-windows-msvc and aarch64-pc-windows-msvc -- are read only
# when .github/workflows/binding-node.yml runs this check with `--only polyjose-node --only
# polyjose-node-release` on each target's own runner: at the release candidate, never on a PR
# (ADR 0044; 0007 review-security.md L2). Code that is never compiled
# (unreachable private code) ships nothing and has no symbol; the text scan covers it. Public code
# that polyjose never codegens (an uncalled `#[inline] pub fn`, a generic `pub fn` it never
# instantiates) has no symbol here either, yet a downstream crate can call it and compile it
# there: the text scan covers it, its macro rule included, which catches the `k!(rsa)` spelling
# that hides the path from its other rules (ADR 0049 §1).
#
# Usage: scripts/check-rsa-symbols.sh [--target-dir DIR] [--dump DIR] [--only CONFIG]... [--target TRIPLE]...
#   --target-dir DIR  cargo's build directory (default: cargo's own, target/)
#   --dump DIR        also write every scanned symbol, demangled, to DIR/<config>.<crate>.txt
#   --only CONFIG     build and read only this configuration (repeatable): polyjose-all-features,
#                     a binding's package name, or polyjose-wasm-wasm32-unknown-unknown, each with
#                     a -release suffix for its release build. For the negative tests, which need
#                     one build per case; the gate itself (test-all.sh, CI) always runs every
#                     configuration, and the result line names a narrowed run.
#   --target TRIPLE   also build and read polyjose-ffi for this target (repeatable): the
#                     configurations polyjose-ffi-TRIPLE and polyjose-ffi-TRIPLE-release (see
#                     "Extra targets" above).
# Exit status: 0 clean, 1 a symbol ADR 0067 keeps out was found, 2 the check
# could not run (a syntax error in this script too, under bash 3.2 as well: the completion
# sentinel, F11). Runs on macOS /bin/bash 3.2 and Linux bash.
set -euo pipefail
export LC_ALL=C
cd "$(dirname "$0")/.."

die() { echo "ERROR: $*" >&2; exit 2; }

target_dir=""
dump_dir=""
only=""
targets=""
while [ $# -gt 0 ]; do
  case $1 in
    --target-dir) [ $# -ge 2 ] || die "--target-dir needs a directory"; target_dir=$2; shift 2 ;;
    --dump) [ $# -ge 2 ] || die "--dump needs a directory"; dump_dir=$2; shift 2 ;;
    --only) [ $# -ge 2 ] || die "--only needs a configuration"; only="$only $2"; shift 2 ;;
    --target) [ $# -ge 2 ] || die "--target needs a target triple"; targets="$targets $2"; shift 2 ;;
    -h | --help) sed -n '2,/^# Usage/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument: $1 (usage: scripts/check-rsa-symbols.sh [--target-dir DIR] [--dump DIR] [--only CONFIG]... [--target TRIPLE]...)" ;;
  esac
done

# Fail closed on a syntax error under bash 3.2 (feature 0013 F10, F11; see scripts/test-all.sh):
# with errexit, bash 3.2 runs an EXIT trap with $? = 0 after a parse error. Without a trap it exits
# 2, but this trap is here so that one added later for a cleanup cannot reopen that hole: an exit
# before the last line, which sets the sentinel, becomes status 2; a non-zero status (the Python
# check's 1 or 2) is kept. Installed after the arguments, so --help still exits 0.
completed=""
# shellcheck disable=SC2154 # rc is assigned by the trap itself (rc=$?)
trap 'rc=$?; [ -n "${completed:-}" ] || [ "$rc" -ne 0 ] || { echo "check-rsa-symbols.sh: stopped before its last line (a syntax error?): failing closed" >&2; rc=2; }; exit "$rc"' EXIT

# No cargo config file in the repository, checked before cargo runs at all (as in check-deps.sh):
# a planted config could swap sources or wrap rustc for the builds below.
no_config_rc=0
scripts/check-no-cargo-config.sh || no_config_rc=$?
if [ "$no_config_rc" -ne 0 ]; then
  echo "check-rsa-symbols: FAILED (scripts/check-no-cargo-config.sh)"
  exit "$no_config_rc"
fi

for tool in cargo rustc python3; do
  command -v "$tool" >/dev/null 2>&1 || die "$tool not found on PATH; cannot build and read polyjose's object code"
done

# The --target triples reach the program through its environment, always set here (so a caller's
# value is never read), in a line of their own beside the program's arguments.
export CHECK_RSA_SYMBOLS_TARGETS="$targets"

# The program is read from stdin (so it may use any quote); the builds it runs get /dev/null.
python3 -I - "$target_dir" "$dump_dir" "$only" <<'PY'
import json, os, re, shlex, shutil, subprocess, sys, tempfile

target_dir, dump_dir, only = sys.argv[1], sys.argv[2], sys.argv[3].split()
CORE = "polyjose"
WASM_BINDING, WASM_TARGET = "polyjose-wasm", "wasm32-unknown-unknown"


def die(msg):
    print("ERROR: " + msg, file=sys.stderr)
    sys.exit(2)


def run(argv, what, cwd=None):
    try:
        p = subprocess.run(argv, cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE)
    except OSError as e:
        die("%s: could not run %s: %s" % (what, argv[0], e))
    if p.returncode != 0:
        sys.stderr.write(p.stderr.decode("utf-8", "replace"))
        die("%s failed (exit %d): %s" % (what, p.returncode, " ".join(argv)))
    return p.stdout.decode("utf-8", "replace")


# --- What a forbidden symbol is ---------------------------------------------------------------------
# (path in the rsa crate, what follows it, reason). A path matches as whole segments, at the crate
# root: `rsa` must not follow an identifier character or `:`, and the last segment must not run
# on, so rsa::pss::sign does not match rsa::pss::signature. Module paths cover everything in the
# module. The second field, when set, is matched right after the path (a trait method).
GEN = "RSA key generation is not supported; keys are imported (ADR 0067 §3)"
UNBL = ("an unblinded or OS-RNG-default RSA private-key path; polyjose signs with pkcs1v15_sign_with_rng /"
        " pss_sign_with_rng and decrypts with oaep_decrypt_with_rng (ADR 0067 §2, §6)")
SIGN = "a typed or scheme-based RSA signing path; polyjose signs with pkcs1v15_sign_with_rng / pss_sign_with_rng (ADR 0067 §6)"
DEC = "a typed or scheme-based RSA decryption path; polyjose decrypts with oaep_decrypt_with_rng (ADR 0067 §6)"
R15 = "RSA1_5 is not supported in either direction (ADR 0067 §3)"
PK = "rsa::private_key::PrivateKey"
# ADR 0067 §6 allows the private key type (rsa::private_key::PrivateKey, built by from_components)
# and the blinded entry points PrivateKey::pkcs1v15_sign_with_rng, ::pss_sign_with_rng and
# ::oaep_decrypt_with_rng with polyjose's RNG, and so the rsa internals they reach:
# pkcs1v15::sign, pss::sign_digest and sign_pss_with_salt_digest, oaep::decrypt_digest,
# algorithms::rsa::rsa_decrypt(_and_check), algorithms::oaep::oaep_decrypt_digest, the PKCS#1 v1.5
# and PSS encoders and PrivateKeyParts. Everything else stays forbidden: key generation, every path
# instantiated with rsa's DummyRng (the stand-in for "no RNG", so unblinded), the unblinded and
# OS-RNG-default methods, the typed keys and traits, the scheme-based paths (a scheme can turn PSS
# blinding off), RSA1_5 and hazmat.
RULES = [
    # Key generation (and the constructors that derive d or n from primes).
    ("rsa::algorithms::generate", "", GEN),
    (PK, ">::new", GEN),
    (PK, ">::new_unchecked", GEN),
    (PK, ">::new_with_exp", GEN),
    (PK, ">::new_with_exp_unchecked", GEN),
    (PK, ">::from_p_q", GEN),
    (PK, ">::from_primes", GEN),
    (PK, " as crypto_common", GEN),
    ("rsa::algorithms::rsa::recover_primes", "", GEN),
    ("rsa::algorithms::rsa::compute_private_exponent_carmicheal", "", GEN),
    ("rsa::algorithms::rsa::compute_private_exponent_euler_totient", "", GEN),
    # Unblinded paths: anything instantiated with DummyRng, and the methods without an RNG.
    ("rsa::dummy_rng", "", UNBL),
    (PK, ">::sign", UNBL),
    (PK, ">::decrypt", UNBL),
    (PK, ">::pkcs1v15_sign", UNBL),
    (PK, ">::pkcs1v15_sign_prehash", UNBL),
    (PK, ">::pss_sign", UNBL),
    (PK, ">::pss_sign_prehash", UNBL),
    (PK, ">::oaep_decrypt", UNBL),
    ("rsa::pkcs1v15::sign_with_default_rng", "", UNBL),
    # Typed signing keys and scheme-based signing.
    ("rsa::pkcs1v15::signing_key", "", SIGN),
    ("rsa::pss::signing_key", "", SIGN),
    ("rsa::pss::blinded_signing_key", "", SIGN),
    ("rsa::traits::padding::SignatureScheme", ">::sign", SIGN),
    ("rsa::traits::SignatureScheme", ">::sign", SIGN),
    (PK, ">::sign_with_rng", SIGN),
    ("rsa::pss::sign", "", SIGN),
    ("rsa::pss::sign_pss_with_salt", "", SIGN),
    # Typed decrypting keys, the decryption traits and scheme-based decryption.
    ("rsa::oaep::decrypting_key", "", DEC),
    ("rsa::pkcs1v15::decrypting_key", "", DEC),
    ("rsa::traits::encryption::Decryptor", "", DEC),
    ("rsa::traits::Decryptor", "", DEC),
    ("rsa::traits::encryption::RandomizedDecryptor", "", DEC),
    ("rsa::traits::RandomizedDecryptor", "", DEC),
    ("rsa::traits::encryption::EncryptingKeypair", "", DEC),
    ("rsa::traits::EncryptingKeypair", "", DEC),
    ("rsa::traits::padding::PaddingScheme", ">::decrypt", DEC),
    ("rsa::traits::PaddingScheme", ">::decrypt", DEC),
    (PK, ">::decrypt_blinded", DEC),
    ("rsa::oaep::decrypt", "", DEC),
    ("rsa::algorithms::oaep::oaep_decrypt", "", DEC),
    # RSA1_5 (RSAES-PKCS1-v1_5), which ADR 0067 §3 keeps out in both directions.
    ("rsa::pkcs1v15::Pkcs1v15Encrypt", "", R15),
    ("rsa::pkcs1v15::encrypting_key", "", R15),
    ("rsa::pkcs1v15::encrypt", "", R15),
    ("rsa::pkcs1v15::decrypt", "", R15),
    (PK, ">::pkcs1v15_decrypt", R15),
    (PK, ">::pkcs1v15_decrypt_with_rng", R15),
    ("rsa::public_key::PublicKey", ">::pkcs1v15_encrypt", R15),
    ("rsa::public_key::PublicKey", ">::pkcs1v15_encrypt_with_rng", R15),
    ("rsa::algorithms::pkcs1v15::pkcs1v15_encrypt_pad", "", R15),
    ("rsa::algorithms::pkcs1v15::implicit_rejection", "", R15),
    ("rsa::algorithms::pkcs1v15::selection", "", R15),
    # Only behind the hazmat feature, which check-deps.sh check 11 rejects.
    ("rsa::hazmat", "", "the rsa hazmat module is not used (ADR 0067 §3)"),
]
IDENT_END = r"(?![A-Za-z0-9_])"
# The positive sentinel: a polyjose rlib that holds RSA private-key code must hold rsa's blinded
# private-key core instantiated with polyjose::rng::CryptoRngAdapter: rsa_decrypt(_and_check) or a
# function of rsa::algorithms::blinding. Every blinded entry point (pkcs1v15_sign_with_rng,
# pss_sign_with_rng, oaep_decrypt_with_rng) reaches it with polyjose's RNG, and it survives the
# release profile's inlining, which removes the entry points themselves (oaep_decrypt_with_rng is
# inlined into polyjose's decrypt_key). An unblinded call instantiates the same core with
# rsa::dummy_rng::DummyRng instead, which the rules above reject.
PRIVATE_KEY = re.compile(r"(?<![A-Za-z0-9_:])rsa(?:\[[0-9A-Za-z]+\])?::private_key::PrivateKey" + IDENT_END)
RNG = r"polyjose(?:\[[0-9A-Za-z]+\])?::rng::CryptoRngAdapter"
BLINDED_CORE = re.compile(r"(?<![A-Za-z0-9_:])rsa(?:\[[0-9A-Za-z]+\])?::algorithms::"
                          r"(?:rsa::rsa_decrypt(?:_and_check)?|blinding::[A-Za-z0-9_]+)::<" + RNG + IDENT_END)


def demangled_rule(path, suffix):
    segs = path.split("::")
    # A v0 demangler may print the crate's disambiguator: rsa[1bA3etlF85p]::...
    head = r"(?<![A-Za-z0-9_:])rsa(?:\[[0-9A-Za-z]+\])?"
    return re.compile(head + "".join("::" + re.escape(s) for s in segs[1:])
                      + (re.escape(suffix) + IDENT_END if suffix else IDENT_END))


def mangled_rule(path):
    # Each segment is length-prefixed, which makes it exact. The crate root follows `_ZN` (legacy)
    # or `C` and an optional `s<base62>_` disambiguator (v0).
    return re.compile(r"(?:ZN|C(?:s[0-9A-Za-z]*_)?)" + "".join("%d%s" % (len(s), s) for s in path.split("::")))


COMPILED = [(demangled_rule(p, s), None if s else mangled_rule(p), p + s, why) for p, s, why in RULES]

LEGACY_ESCAPES = [("$SP$", "@"), ("$BP$", "*"), ("$RF$", "&"), ("$LT$", "<"), ("$GT$", ">"),
                  ("$LP$", "("), ("$RP$", ")"), ("$C$", ",")]


def normalize(sym):
    """Finishes a legacy Rust name that an Itanium demangler printed with its escapes."""
    if "$" not in sym and ".." not in sym:
        return sym
    sym = re.sub(r"\$u([0-9a-fA-F]{2,6})\$", lambda m: chr(int(m.group(1), 16)), sym)
    for escape, ch in LEGACY_ESCAPES:
        sym = sym.replace(escape, ch)
    sym = sym.replace("..", "::")
    return re.sub(r"(^|[^A-Za-z0-9_])_(?=<)", r"\1", sym)


# --- Tools ------------------------------------------------------------------------------------------
sysroot = run(["rustc", "--print", "sysroot"], "rustc --print sysroot").strip()
host = None
for line in run(["rustc", "-vV"], "rustc -vV").splitlines():
    if line.startswith("host: "):
        host = line[len("host: "):].strip()
if not host:
    die("rustc -vV printed no host triple")
tool_bin = os.path.join(sysroot, "lib", "rustlib", host, "bin")


def find_tool(llvm_name, plain):
    own = os.path.join(tool_bin, llvm_name)
    if os.path.isfile(own) and os.access(own, os.X_OK):
        return own
    for name in (llvm_name, plain):
        found = shutil.which(name)
        if found:
            return found
    die("neither the toolchain's %s (rustup component add llvm-tools) nor %s or %s is on PATH;"
        " cannot read polyjose's object code" % (llvm_name, llvm_name, plain))


AR, NM = find_tool("llvm-ar", "ar"), find_tool("llvm-nm", "nm")
tool_hint = ("" if NM.startswith(tool_bin) else
             " (with %s; the toolchain's llvm-nm reads every target: rustup component add llvm-tools)" % NM)

# --- The shipped wasm build's extra Cargo arguments -------------------------------------------------
# One line of wasm-cargo-args.sh defines them (ADR 0059): `WASM_CARGO_ARGS=(<words>)`. Its words are
# read as bash would read them, and only words with one reading are accepted: runs of '...', "..."
# without $, ` or \, and unquoted characters that bash neither expands nor globs.
ARGS_FILE = "bindings/wasm/scripts/wasm-cargo-args.sh"
WORD_PART = re.compile(r"""'([^']*)'|"([^"$`\\]*)"|([A-Za-z0-9_.,:=+/@%-]+)""")


def wasm_cargo_args():
    try:
        with open(ARGS_FILE, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except (OSError, UnicodeDecodeError) as e:
        die("cannot read %s: %s" % (ARGS_FILE, e))
    defs = [l for l in lines if re.match(r"\s*WASM_CARGO_ARGS\b", l)]
    if not defs:
        die("%s has no WASM_CARGO_ARGS=(...) line (ADR 0059); the wasm32 builds read it" % ARGS_FILE)
    if len(defs) > 1:
        die("%s has %d WASM_CARGO_ARGS lines, expected one: %s" % (ARGS_FILE, len(defs), defs))
    m = re.fullmatch(r"WASM_CARGO_ARGS=\((.*)\)", defs[0])
    words, i, s = [], 0, m.group(1) if m else None
    while s is not None and i < len(s):
        if s[i] in " \t":
            i += 1
            continue
        word = ""
        while i < len(s) and s[i] not in " \t":
            part = WORD_PART.match(s, i)
            if part is None:
                s = None
                break
            word += next(g for g in part.groups() if g is not None)
            i = part.end()
        else:
            words.append(word)
    if s is None:
        die("cannot read the WASM_CARGO_ARGS line of %s as plain words: %r" % (ARGS_FILE, defs[0]))
    return words


WASM_ARGS = wasm_cargo_args()

# --- What to build ----------------------------------------------------------------------------------
meta = json.loads(run(["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"],
                      "cargo metadata"))
members = [p for p in meta["packages"] if p["id"] in set(meta["workspace_members"])]
if len(members) != len(meta["workspace_members"]):
    die("cargo metadata is missing workspace members")
LIB_KINDS = {"lib", "rlib", "cdylib", "staticlib", "dylib"}
names = sorted(p["name"] for p in members)
if CORE not in names:
    die("the workspace has no %s package" % CORE)
# A member with no library target is build tooling (polyjose-uniffi-bindgen, the UniFFI bindgen
# CLI of feature 0013 T10): no shipped library links it. It is skipped only while it cannot hold
# polyjose or rsa code at all: its whole tree (every dependency kind, every target, and the union
# of the default, --no-default-features and --all-features trees, as check-deps.sh binding_tree
# reads a binding, so an optional dependency behind a feature counts) may contain neither rsa nor
# any other workspace member. Otherwise the check fails closed, as for any member it does not know
# how to build, and so does a tree that cargo cannot print or that does not start at the member.
tools = []
for p in members:
    if any(LIB_KINDS & set(t["kind"]) for t in p["targets"]):
        continue
    reached = set()
    for flags in ([], ["--no-default-features"], ["--all-features"]):
        argv = ["cargo", "tree", "--color", "never", "--locked", "-p", p["name"], "-e", "normal,build,dev", "--target", "all",
                "--prefix", "none"] + flags
        tree = run(argv, "cargo tree -p %s%s" % (p["name"], "".join(" " + f for f in flags))).splitlines()
        if not tree or tree[0].split(" ", 1)[0] != p["name"]:
            die("%s printed no tree rooted at %s; check the script" % (" ".join(argv), p["name"]))
        reached |= set(line.split(" ", 1)[0] for line in tree[1:] if line.strip())
    holds = sorted(reached & (set(names) | {"rsa"}))
    if holds:
        die("workspace member %s has no library target, and its tree contains %s; scripts/check-rsa-symbols.sh"
            " builds every member's library, so decide how to check it and update the script"
            % (p["name"], ", ".join(holds)))
    tools.append(p["name"])
bindings = [n for n in names if n != CORE and n not in tools]
if WASM_BINDING not in bindings:
    die("the workspace has no %s package, whose %s build this check reads" % (WASM_BINDING, WASM_TARGET))

# (what, target, file-name id, cargo arguments, crates whose objects are read), each built in the
# dev profile and again in the release profile (see the top of this file).
builds = [("%s --all-features" % CORE, "host", "%s-all-features" % CORE,
           ["build", "-p", CORE, "--lib", "--all-features"], [CORE])]
for b in bindings:
    builds.append((b, "host", b, ["rustc", "-p", b, "--lib", "--crate-type", "rlib"], [CORE, b]))
builds.append((" ".join([WASM_BINDING] + [shlex.quote(a) for a in WASM_ARGS]), WASM_TARGET,
               "%s-%s" % (WASM_BINDING, WASM_TARGET),
               ["rustc", "-p", WASM_BINDING, "--lib", "--crate-type", "rlib", "--target", WASM_TARGET] + WASM_ARGS,
               [CORE, WASM_BINDING]))
# (label, file-name id, cargo arguments, crates whose objects are read)
configs = [("%s (%s)" % (what, where), file_id, args, crates) for what, where, file_id, args, crates in builds]
configs += [("%s --release (%s)" % (what, where), file_id + "-release", args + ["--release"], crates)
            for what, where, file_id, args, crates in builds]

# --- Extra targets (--target, see the top of this file) ---------------------------------------------
# Checked before any build: rustc knows the triple and its std is installed (rustup target add);
# a build that fails for it still exits 2 through run(). Read with polyjose-ffi: polyjose and every
# workspace member polyjose-ffi depends on as a normal, non-optional dependency (the code it links
# for that target); one that the build does not report fails closed below.
FFI_BINDING = "polyjose-ffi"
TARGETS = []
for t in os.environ.get("CHECK_RSA_SYMBOLS_TARGETS", "").split():
    if t not in TARGETS:
        TARGETS.append(t)
if TARGETS:
    if FFI_BINDING not in bindings:
        die("--target: the workspace has no %s package, which the --target builds are of" % FFI_BINDING)
    known_targets = set(run(["rustc", "--print", "target-list"], "rustc --print target-list").split())
    for t in TARGETS:
        if t not in known_targets:
            die("--target: %s is not a target rustc knows (rustc --print target-list)" % t)
        libdir = run(["rustc", "--print", "target-libdir", "--target", t],
                     "rustc --print target-libdir --target %s" % t).strip()
        if not os.path.isdir(libdir) or not any(re.match(r"libstd-[0-9a-f]+\.rlib$", f) for f in os.listdir(libdir)):
            die("--target: the std of %s is not installed (rustup target add %s); cannot build %s for it"
                % (t, t, FFI_BINDING))
    by_name = {p["name"]: p for p in members}
    linked, todo = [], [FFI_BINDING]
    while todo:
        name = todo.pop(0)
        if name in linked:
            continue
        linked.append(name)
        todo += sorted(d["name"] for d in by_name[name]["dependencies"]
                       if d["name"] in by_name and d.get("kind") is None and not d.get("optional"))
    ffi_crates = [CORE] + sorted(n for n in linked if n not in (CORE, FFI_BINDING)) + [FFI_BINDING]
    for t in TARGETS:
        args = ["rustc", "-p", FFI_BINDING, "--lib", "--crate-type", "rlib", "--target", t]
        configs.append(("%s (%s)" % (FFI_BINDING, t), "%s-%s" % (FFI_BINDING, t), args, ffi_crates))
        configs.append(("%s --release (%s)" % (FFI_BINDING, t), "%s-%s-release" % (FFI_BINDING, t),
                        args + ["--release"], ffi_crates))

if only:
    known = [c[1] for c in configs]
    unknown = sorted(set(only) - set(known))
    if unknown:
        die("--only: no configuration %s (there are: %s)" % (", ".join(unknown), ", ".join(known)))
    configs = [c for c in configs if c[1] in only]
narrowed = " (only %s, not every configuration)" % ", ".join(c[1] for c in configs) if only else ""

member_ids = {p["id"]: p["name"] for p in members}


def build(label, args):
    argv = ["cargo"] + args[:1] + ["--locked", "--message-format=json-render-diagnostics"] + args[1:]
    if target_dir:
        argv += ["--target-dir", target_dir]
    out = run(argv, "the %s build" % label)
    rlibs, finished = {}, False
    for line in out.splitlines():
        if not line.startswith("{"):
            continue
        msg = json.loads(line)
        if msg.get("reason") == "build-finished":
            finished = msg.get("success") is True
        if msg.get("reason") != "compiler-artifact" or msg["package_id"] not in member_ids:
            continue
        if not LIB_KINDS & set(msg["target"]["kind"]):
            continue
        crate = msg["target"]["name"].replace("-", "_")
        files = msg["filenames"]
        rlib = [f for f in files if f.endswith(".rlib")]
        hashed = [m.group(1) for f in files
                  for m in [re.match(r"lib%s-([0-9a-f]+)\.(?:rlib|rmeta)$" % re.escape(crate), os.path.basename(f))] if m]
        if len(rlib) != 1 or not hashed:
            die("the %s build reported no rlib with a metadata hash for %s: %s" % (label, crate, files))
        rlibs[member_ids[msg["package_id"]]] = (crate, rlib[0], "%s-%s." % (crate, hashed[0]))
    if not finished:
        die("the %s build did not report success" % label)
    return rlibs


# --- Reading an rlib --------------------------------------------------------------------------------
# The address column is hex for machine code, or a run of dashes for an LLVM bitcode member: the
# release profile's LTO (Cargo.toml) makes cargo build rlib roots with -C linker-plugin-lto, so
# their codegen units are bitcode, whose symbol table llvm-nm reads the same way.
NM_LINE = re.compile(r"^\s*(?:(?:[0-9A-Fa-f]+|-+)\s+)?([A-Za-z?-])\s+(\S.*)$")


def nm(path, demangle, what):
    argv = [NM] + (["-C"] if demangle else []) + [path]
    try:
        p = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as e:
        die("could not run %s: %s" % (NM, e))
    if p.returncode != 0:
        sys.stderr.write(p.stderr.decode("utf-8", "replace"))
        die("%s could not read %s%s" % (NM, what, tool_hint))
    syms = []
    for line in p.stdout.decode("utf-8", "replace").splitlines():
        if not line.strip():
            continue
        m = NM_LINE.match(line)
        if m is None:
            die("cannot parse this line of %s %s: %r" % (NM, what, line))
        syms.append((m.group(1) == "U", m.group(2)))
    return syms


def read_rlib(crate, rlib, prefix):
    """[(member, undefined, demangled, mangled)] for the rlib's own object members."""
    listing = run([AR, "t", rlib], "%s t %s" % (AR, rlib)).splitlines()
    objects = []
    for name in listing:
        if name in ("lib.rmeta", "lib.rmeta-link") or name.startswith("__.SYMDEF") or name in ("/", "//"):
            continue
        if not re.match(r"^[A-Za-z0-9._-]+$", name) or not name.startswith(prefix) or not name.endswith(".rcgu.o"):
            die("%s holds a member that is not one of %s's codegen units (%s*.rcgu.o): %r;"
                " the check reads only those, so it cannot vouch for this rlib" % (rlib, crate, prefix, name))
        objects.append(name)
    if not objects:
        die("%s holds no object file (%s*.rcgu.o); nothing to check" % (rlib, prefix))
    if len(set(objects)) != len(objects):
        die("%s holds two members with one name" % rlib)
    out = []
    with tempfile.TemporaryDirectory(prefix="check-rsa-symbols.") as tmp:
        run([AR, "x", os.path.abspath(rlib)] + objects, "%s x %s" % (AR, rlib), cwd=tmp)
        for name in objects:
            path = os.path.join(tmp, name)
            if not os.path.isfile(path):
                die("%s x did not extract %s from %s" % (AR, name, rlib))
            what = "%s in %s" % (name, rlib)
            demangled, mangled = nm(path, True, what), nm(path, False, what)
            if len(demangled) != len(mangled):
                die("%s printed %d demangled and %d mangled symbols for %s" % (NM, len(demangled), len(mangled), what))
            for (undef, dem), (_, raw) in zip(demangled, mangled):
                out.append((name, undef, normalize(dem), raw))
    return out


# --- The check --------------------------------------------------------------------------------------
if dump_dir:
    os.makedirs(dump_dir, exist_ok=True)
findings, unvouched, seen, totals = [], [], {}, [0, 0, 0]
for label, file_id, args, crates in configs:
    rlibs = build(label, args)
    for pkg in crates:
        if pkg not in rlibs:
            die("the %s build reported no rlib for %s" % (label, pkg))
        crate, rlib, prefix = rlibs[pkg]
        key = (os.path.realpath(rlib), prefix)
        if key not in seen:
            seen[key] = read_rlib(crate, rlib, prefix)
            totals[0] += 1
            totals[1] += len({m for m, _, _, _ in seen[key]})
            totals[2] += len(seen[key])
        syms = seen[key]
        demangled = [d for _, _, d, _ in syms]
        if not any(re.search(r"(?<![A-Za-z0-9_:])%s::" % re.escape(crate), d) for d in demangled):
            die("no symbol of %s (%s) demangles to a %s:: path; %s does not demangle Rust symbols%s"
                % (rlib, label, crate, NM, tool_hint))
        if pkg == CORE and not any(re.search(r"(?<![A-Za-z0-9_:])rsa::public_key::PublicKey", d) for d in demangled):
            die("no symbol of %s (%s) demangles to rsa::public_key::PublicKey, which RS*/PS*"
                " verification always uses; %s does not demangle them as expected%s" % (rlib, label, NM, tool_hint))
        # The blinded-path sentinel (ADR 0067 §6): once polyjose compiles RSA private-key code, the
        # blinded entry points must be there, instantiated with polyjose's own RNG (ADR 0005), so
        # the code read is the blinded one and the rules above can see its paths. Checked after the
        # rules, below: a forbidden symbol is the more specific finding and is reported first.
        if pkg == CORE and any(PRIVATE_KEY.search(d) for d in demangled):
            if not any(BLINDED_CORE.search(d) for d in demangled):
                unvouched.append("%s (%s) has RSA private-key code but no symbol of rsa's blinded"
                                 " private-key core with polyjose's RNG (rsa::algorithms::rsa::"
                                 "rsa_decrypt(_and_check) or rsa::algorithms::blinding::* <polyjose::"
                                 "rng::CryptoRngAdapter>); the check cannot vouch that the blinded path"
                                 " is the one compiled in (ADR 0067 §6)" % (rlib, label))
        if dump_dir:
            # One line per symbol: D (defined in some object) or U (only referenced), demangled.
            kinds = {}
            for _, undef, dem, _ in syms:
                kinds[dem] = kinds.get(dem, True) and undef
            with open(os.path.join(dump_dir, "%s.%s.txt" % (file_id, crate)), "w", encoding="utf-8") as f:
                f.write("".join("%s %s\n" % ("U" if kinds[d] else "D", d) for d in sorted(kinds)))
        hits = {}
        for member, undef, dem, raw in syms:
            for dem_re, raw_re, path, why in COMPILED:
                if dem_re.search(dem) or (raw_re is not None and raw_re.search(raw)):
                    hits.setdefault(dem, (path, why, "undefined" if undef else "defined", member))
                    break
        if hits:
            findings.append((label, crate, hits))

if findings:
    for label, crate, hits in findings:
        print("FAIL: compiled RSA code that ADR 0067 does not allow in the objects of %s (%s)"
              " (ADR 0067 §3, §6; ADR 0049 §1):" % (crate, label))
        for sym in sorted(hits):
            path, why, kind, member = hits[sym]
            print("  - %s" % sym)
            print("      matches %s: %s; %s in %s" % (path, why, kind, member))
    print("RSA private-key operations go through PrivateKey::pkcs1v15_sign_with_rng, ::pss_sign_with_rng and"
          " ::oaep_decrypt_with_rng with polyjose's RNG, in jws/rsa.rs, jwe/rsa_oaep.rs and keys/rsa.rs only;"
          " no key generation, RSA1_5, unblinded path or hazmat.")
    print("check-rsa-symbols: FAILED")
    sys.exit(1)
if unvouched:
    die("; ".join(unvouched))
print("ok: no RSA key generation, RSA1_5, unblinded, typed or scheme-based private-key or hazmat symbol in"
      " the compiled objects of polyjose or any binding (ADR 0067 §6, ADR 0049 §1): %d configurations, %d rlibs, %d objects, %d symbols"
      " (defined and undefined), read with %s%s" % (len(configs), totals[0], totals[1], totals[2], NM, narrowed))
for label, _, _, crates in configs:
    print("  %s: %s" % (label, ", ".join(c.replace("-", "_") for c in crates)))
for name in tools:
    print("  skipped %s: no library target, and neither rsa nor a workspace member in its tree" % name)
PY
completed=1; exit 0
