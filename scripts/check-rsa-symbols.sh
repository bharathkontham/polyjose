#!/usr/bin/env bash
# Enforces ADR 0021 (RSA is used for public-key operations only) on compiled output, as ADR 0049 §1
# requires: deny.toml ignores RUSTSEC-2023-0071 (Marvin, a timing leak in the rsa crate's
# private-key operations) only while this check and check-deps.sh's text scan (checks 9-12) hold.
#
# A text scan cannot see every way of naming rsa: an alias in a brace use tree, a #[path] module or
# an include! from outside the scanned roots, a macro that receives `rsa` as an identifier, or a
# child module that reaches its parent's private imports through super::. Whatever the spelling,
# code that uses rsa's private-key, signing or decryption items leaves their symbols in the object
# code of the crate that uses them, so this check reads that object code instead.
#
# What is built (each a configuration that ships), first in the dev profile and then again with
# --release:
#   1. polyjose --lib --all-features (so feature-gated code is in);
#   2. every other workspace member (the bindings), each on its own with its own feature
#      unification, as an rlib (`cargo rustc --crate-type rlib`, so its objects are kept even when
#      it ships as a cdylib or staticlib), on the host;
#   3. polyjose-wasm the same way for wasm32-unknown-unknown, its shipping target (polyjose alone
#      does not build there: getrandom needs the binding's `wasm_js` backend).
# A workspace member with no library target (build tooling such as polyjose-uniffi-bindgen) is
# skipped only when its tree holds neither rsa nor another workspace member; otherwise it fails
# closed.
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
# cbc::Decryptor, never matches) of RSA private-key, signing or decryption code: see `RULES`
# below (rsa 0.10's defining paths, e.g. rsa::private_key::RsaPrivateKey, plus the re-export
# paths ADR 0049 names, e.g. rsa::key::RsaPrivateKey and rsa::traits::Decryptor). The same paths
# are also matched in the mangled names (`_ZN3rsa11private_key...` legacy, `C..._3rsa11private_key`
# v0), so a demangler mistake can only add findings. Legacy names are normalized after demangling
# (`$LT$` -> `<`, `..` -> `::`, ...), since llvm-nm's Itanium demangler leaves those escapes;
# rustc 1.99 emits v0 names, but the check does not depend on it.
#
# Fails closed (exit 2), with the reason, when: cargo, rustc, python3, ar or nm is missing; a
# workspace member has no library target and its tree holds rsa or another member; a build fails;
# a build does not report polyjose's (or the binding's) rlib; an rlib holds no object or a member
# it does not expect; the symbol tool cannot read an object or prints a line it cannot parse; or
# the symbols are not demangled (each crate must show a `<crate>::` path, and each polyjose rlib
# rsa::public_key::RsaPublicKey, which RS*/PS* verification always uses).
#
# Tools, first found: the toolchain's own llvm-ar and llvm-nm (the llvm-tools component:
# `rustup component add llvm-tools`; the only choice that reads wasm32 objects everywhere), then
# llvm-ar/llvm-nm on PATH, then ar/nm (Xcode's are LLVM's; GNU binutils' nm reads ELF but not
# wasm). CI installs llvm-tools.
#
# Residual risk: code compiled only for a target that is not built here is seen by the text scan
# only, except where the job that builds that target runs this check too:
#   - the Android and Apple targets of rust-toolchain.toml: the text scan only, until those
#     binding jobs add their target to this check;
#   - the @polyjose/node prebuild targets other than this Mac's (aarch64-apple-darwin):
#     x86_64-apple-darwin, x86_64-unknown-linux-gnu, aarch64-unknown-linux-gnu,
#     x86_64-unknown-linux-musl, aarch64-unknown-linux-musl, x86_64-pc-windows-msvc and
#     aarch64-pc-windows-msvc. .github/workflows/binding-node.yml runs this check with `--only
#     polyjose-node --only polyjose-node-release` on each target's own runner, so their
#     target-only code is read only when that workflow runs: at the release candidate, never on a
#     PR (ADR 0044; review-security.md L2).
# Code that is never compiled (unreachable private code) ships nothing
# and has no symbol; the text scan covers it. Public code that polyjose never codegens (an uncalled
# `#[inline] pub fn`, a generic `pub fn` it never instantiates) has no symbol here either, yet a
# downstream crate can call it and compile it there: the text scan covers it, its macro rule
# included, which catches the `k!(rsa)` spelling that hides the path from its other rules (ADR 0049
# §1).
#
# Usage: scripts/check-rsa-symbols.sh [--target-dir DIR] [--dump DIR] [--only CONFIG]...
#   --target-dir DIR  cargo's build directory (default: cargo's own, target/)
#   --dump DIR        also write every scanned symbol, demangled, to DIR/<config>.<crate>.txt
#   --only CONFIG     build and read only this configuration (repeatable): polyjose-all-features,
#                     a binding's package name, or polyjose-wasm-wasm32-unknown-unknown, each with
#                     a -release suffix for its release build. For the negative tests, which need
#                     one build per case; the gate itself (test-all.sh, CI) always runs every
#                     configuration, and the result line names a narrowed run.
# Exit status: 0 clean, 1 an RSA private-key, signing or decryption symbol was found, 2 the check
# could not run. Runs on macOS /bin/bash 3.2 and Linux bash.
set -euo pipefail
export LC_ALL=C
cd "$(dirname "$0")/.."

die() { echo "ERROR: $*" >&2; exit 2; }

target_dir=""
dump_dir=""
only=""
while [ $# -gt 0 ]; do
  case $1 in
    --target-dir) [ $# -ge 2 ] || die "--target-dir needs a directory"; target_dir=$2; shift 2 ;;
    --dump) [ $# -ge 2 ] || die "--dump needs a directory"; dump_dir=$2; shift 2 ;;
    --only) [ $# -ge 2 ] || die "--only needs a configuration"; only="$only $2"; shift 2 ;;
    -h | --help) sed -n '2,/^# Usage/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument: $1 (usage: scripts/check-rsa-symbols.sh [--target-dir DIR] [--dump DIR] [--only CONFIG]...)" ;;
  esac
done

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

# The program is read from stdin (so it may use any quote); the builds it runs get /dev/null.
python3 -I - "$target_dir" "$dump_dir" "$only" <<'PY'
import json, os, re, shutil, subprocess, sys, tempfile

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
PRIV = "RSA private keys are not supported (ADR 0021)"
GEN = "RSA key generation is not supported (ADR 0021)"
SIGN = "RSA signing is not supported (ADR 0021)"
DEC = "RSA decryption is not supported (ADR 0021)"
R15 = "RSA1_5 is not supported in either direction (ADR 0021)"
RULES = [
    # Private keys. rsa 0.10 defines RsaPrivateKey in rsa::private_key; rsa::key is ADR 0049's
    # (older) path and rsa::RsaPrivateKey the re-export.
    ("rsa::private_key", "", PRIV),
    ("rsa::key::RsaPrivateKey", "", PRIV),
    ("rsa::RsaPrivateKey", "", PRIV),
    ("rsa::traits::keys::PrivateKeyParts", "", PRIV),
    ("rsa::traits::PrivateKeyParts", "", PRIV),
    ("rsa::algorithms::rsa::recover_primes", "", PRIV),
    ("rsa::algorithms::rsa::compute_private_exponent_carmicheal", "", PRIV),
    ("rsa::algorithms::rsa::compute_private_exponent_euler_totient", "", PRIV),
    ("rsa::algorithms::generate", "", GEN),
    # Signing: the typed signing keys, the Pkcs1v15Sign/Pss schemes' sign, and the helpers.
    ("rsa::pkcs1v15::signing_key", "", SIGN),
    ("rsa::pss::signing_key", "", SIGN),
    ("rsa::pss::blinded_signing_key", "", SIGN),
    ("rsa::traits::padding::SignatureScheme", ">::sign", SIGN),
    ("rsa::traits::SignatureScheme", ">::sign", SIGN),
    ("rsa::pkcs1v15::sign", "", SIGN),
    ("rsa::pkcs1v15::sign_with_default_rng", "", SIGN),
    ("rsa::pss::sign", "", SIGN),
    ("rsa::pss::sign_digest", "", SIGN),
    ("rsa::pss::sign_pss_with_salt", "", SIGN),
    ("rsa::pss::sign_pss_with_salt_digest", "", SIGN),
    ("rsa::algorithms::pkcs1v15::pkcs1v15_sign_pad", "", SIGN),
    ("rsa::algorithms::pss::emsa_pss_encode", "", SIGN),
    ("rsa::algorithms::pss::emsa_pss_encode_digest", "", SIGN),
    # Decryption: the typed decrypting keys, the traits, the schemes' decrypt, and the helpers.
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
    ("rsa::oaep::decrypt", "", DEC),
    ("rsa::oaep::decrypt_digest", "", DEC),
    ("rsa::pkcs1v15::decrypt", "", DEC),
    ("rsa::algorithms::rsa::rsa_decrypt", "", DEC),
    ("rsa::algorithms::rsa::rsa_decrypt_and_check", "", DEC),
    ("rsa::algorithms::oaep::oaep_decrypt", "", DEC),
    ("rsa::algorithms::oaep::oaep_decrypt_digest", "", DEC),
    ("rsa::algorithms::pkcs1v15::implicit_rejection", "", DEC),
    ("rsa::algorithms::pkcs1v15::selection", "", DEC),
    # RSA1_5 (RSAES-PKCS1-v1_5), which ADR 0021 drops in both directions.
    ("rsa::pkcs1v15::Pkcs1v15Encrypt", "", R15),
    ("rsa::pkcs1v15::encrypting_key", "", R15),
    ("rsa::pkcs1v15::encrypt", "", R15),
    ("rsa::algorithms::pkcs1v15::pkcs1v15_encrypt_pad", "", R15),
    # Only behind the hazmat feature, which check-deps.sh check 11 rejects.
    ("rsa::hazmat", "", "the rsa hazmat module is not used (ADR 0021)"),
]
IDENT_END = r"(?![A-Za-z0-9_])"


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
# polyjose or rsa code at all: its whole tree (every dependency kind, every target) may contain
# neither rsa nor any other workspace member. Otherwise the check fails closed, as for any member
# it does not know how to build.
tools = []
for p in members:
    if any(LIB_KINDS & set(t["kind"]) for t in p["targets"]):
        continue
    tree = run(["cargo", "tree", "--locked", "-p", p["name"], "-e", "normal,build,dev", "--target", "all",
                "--prefix", "none"], "cargo tree -p %s" % p["name"]).splitlines()
    reached = set(line.split(" ", 1)[0] for line in tree[1:] if line.strip())
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
builds.append((WASM_BINDING, WASM_TARGET, "%s-%s" % (WASM_BINDING, WASM_TARGET),
               ["rustc", "-p", WASM_BINDING, "--lib", "--crate-type", "rlib", "--target", WASM_TARGET],
               [CORE, WASM_BINDING]))
# (label, file-name id, cargo arguments, crates whose objects are read)
configs = [("%s (%s)" % (what, where), file_id, args, crates) for what, where, file_id, args, crates in builds]
configs += [("%s --release (%s)" % (what, where), file_id + "-release", args + ["--release"], crates)
            for what, where, file_id, args, crates in builds]

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
findings, seen, totals = [], {}, [0, 0, 0]
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
        if pkg == CORE and not any(re.search(r"(?<![A-Za-z0-9_:])rsa::public_key::RsaPublicKey", d) for d in demangled):
            die("no symbol of %s (%s) demangles to rsa::public_key::RsaPublicKey, which RS*/PS*"
                " verification always uses; %s does not demangle them as expected%s" % (rlib, label, NM, tool_hint))
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
        print("FAIL: compiled RSA private-key, signing or decryption code in the objects of %s (%s)"
              " (ADR 0021, ADR 0049 §1):" % (crate, label))
        for sym in sorted(hits):
            path, why, kind, member = hits[sym]
            print("  - %s" % sym)
            print("      matches %s: %s; %s in %s" % (path, why, kind, member))
    print("deny.toml ignores RUSTSEC-2023-0071 only while no RSA private-key operation is compiled in;"
          " use RS*/PS* verification and RSA-OAEP encryption only (rsa::RsaPublicKey, the typed"
          " pkcs1v15/pss VerifyingKey, Oaep encryption).")
    print("check-rsa-symbols: FAILED")
    sys.exit(1)
print("ok: no RSA private-key, signing or decryption symbol in the compiled objects of polyjose or"
      " any binding (ADR 0021, ADR 0049 §1): %d configurations, %d rlibs, %d objects, %d symbols"
      " (defined and undefined), read with %s%s" % (len(configs), totals[0], totals[1], totals[2], NM, narrowed))
for label, _, _, crates in configs:
    print("  %s: %s" % (label, ", ".join(c.replace("-", "_") for c in crates)))
for name in tools:
    print("  skipped %s: no library target, and neither rsa nor a workspace member in its tree" % name)
PY
