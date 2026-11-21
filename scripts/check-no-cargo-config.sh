#!/usr/bin/env bash
# Fails if the repository contains a cargo configuration file, or if a script or workflow sets
# cargo configuration another way.
#
# Cargo reads `.cargo/config.toml` and the legacy `.cargo/config` from its working directory and
# every parent directory (https://doc.rust-lang.org/cargo/reference/config.html). Such a file can
# replace crates.io with other sources (`[source]`, `[patch]`), add rustflags or a cfg for one
# target, and run a rustc wrapper, all outside what check-deps.sh, check-test-vectors-off.sh and
# deny.toml can see. polyjose has none, so this check keeps it that way. It runs first in both
# gates and in CI, before any cargo command, so a planted config cannot influence them.
#
#   1. No file or symlink named `config` or `config.toml` sits in a directory named `.cargo`
#      anywhere in the repository, and no `.cargo` entry is a symlink (cargo follows a symlinked
#      `.cargo` directory). Names compare case-insensitively, because macOS file systems usually
#      are. Two independent listings:
#      - git: tracked files (the index, so a staged file counts even if deleted from the working
#        tree), untracked files and ignored files, so a gitignored config fails too;
#      - find from the repository root, not following symlinks (so it cannot loop).
#      Both skip only `.git` at the root and build output: any directory named `target` (find and
#      the untracked/ignored listing; a *tracked* file under target/ still fails). Cargo reads a
#      config only from its working directory and the directories above it, and no gate, script
#      or CI step runs cargo inside a build directory.
#   2. No file under scripts/, .github/ or bindings/ (all of it; except this script) passes `--config`
#      or cargo's `-Z` (an unstable flag), writes a `.cargo/config*` or `$CARGO_HOME/config*` file, or
#      assigns an environment variable that does what a config file would: `CARGO_SOURCE_*`,
#      `CARGO_TARGET_<triple>_{RUSTFLAGS,RUSTDOCFLAGS,LINKER,RUNNER}`, `CARGO_BUILD_{RUSTFLAGS,
#      RUSTDOCFLAGS,RUSTC,RUSTC_WRAPPER,RUSTC_WORKSPACE_WRAPPER,RUSTDOC}`, `CARGO_ENCODED_RUSTFLAGS`,
#      `RUSTFLAGS`, `RUSTDOCFLAGS`, `RUSTC`, `RUSTC_WRAPPER`, `RUSTC_WORKSPACE_WRAPPER`, `RUSTDOC`,
#      `RUSTC_BOOTSTRAP`, `CARGO_UNSTABLE_*` or `CARGO_HOME`. Comment lines are skipped: those
#      starting with `#`, and in Rust, TypeScript/JavaScript, Kotlin, Java and Swift files (by
#      extension) those starting with `//` (doc comments such as bindings/wasm/tests/memory.rs's
#      manual commands; in a shell script a `//` line is a path, and is read). An
#      assignment is `NAME=`, `NAME+=`, `NAME<<` (GitHub's $GITHUB_ENV), `NAME:` (a YAML env key or a
#      JavaScript property) or `${NAME:=`. A line also fails if it holds one of these names as the
#      whole of a quoted string, `"NAME"` or `'NAME'` (also `\"NAME\"`, escaped inside a string),
#      whatever surrounds it: that is how Gradle (`environment("NAME", ...)`,
#      `environment["NAME"] = ...`, `put("NAME", ...)`, `mapOf("NAME" to ...)`) and Swift
#      (`env["NAME"] = ...`) set a child process's environment, and how a shell names a variable
#      to `printf -v` or `export`. A name inside a longer string (`"set NAME first"`) is not one.
#      check-test-vectors-off.sh separately checks *RUSTFLAGS in the environment.
#      Every git-listed file (tracked or untracked, not ignored) is read as text, binary ones too
#      (the PE fixtures of bindings/node), with its NUL bytes dropped first: one-true-awk (macOS)
#      ends a line at a NUL, which would hide the rest of it, and bash drops NULs when it runs a
#      script (a sourced file stops at its first NUL, so it runs less, not more). There is no
#      skip by content or extension. The one file not read is the Gradle wrapper
#      bindings/kotlin/gradle/wrapper/gradle-wrapper.jar, by that exact path and only while it starts
#      with a zip signature (`PK\3\4`): java runs it, not a shell, and its compressed bytes match the
#      patterns at random. Anything else at that path is read.
#      `-Z` is not matched where it is the exact command `unzip -Z1` (zipinfo's one-name-per-line
#      listing, in the Kotlin and Swift packaging checks) at the start of a line, after indentation,
#      in a shell script (*.sh), on a line that does not continue the one above it (that ends in
#      `\`). Only that command is removed from a copy of the line, and the rest is still tested for
#      `-Z`; all other patterns read the whole line. So `unzip -Z1 a && cargo -Zx`, `-Zx` at the
#      start of a line, `cargo +nightly -Zx`, `foo; unzip -Z1`, `unzip -Z1x`, and `unzip -Z1` as an
#      argument on a continuation line all fail. (`-Z1` itself is no cargo or rustc flag.)
#      bindings/ is read because the shipped @polyjose/wasm build takes extra Cargo arguments on
#      its command line (security audit L2 of feature 0006): anything added there reaches the
#      published .wasm and no other guard. The exceptions (`allowed` below) are allowed by path
#      and exact text, each at most once in its file (absent is fine):
#      - ADR 0059's line in bindings/wasm/scripts/wasm-cargo-args.sh, which build-package.sh and
#        test.sh source; no other line under bindings/ may assign `WASM_CARGO_ARGS` (reading
#        `${WASM_CARGO_ARGS[@]}` or `${#WASM_CARGO_ARGS[@]}` is fine), so that line is all of the
#        build's extra arguments. check-rsa-symbols.sh builds the wasm32 configurations with the
#        same line. Changing it needs an ADR superseding ADR 0059 and the same change here;
#      - @polyjose/node's static C runtime for the *-pc-windows-msvc prebuilds (0007 review SF-1:
#        official Node links its CRT statically and ships no VC++ redistributable): the one
#        RUSTFLAGS line of bindings/node/scripts/ci-build.sh and the regex of
#        bindings/node/test/ci.test.ts that asserts it (0006 F10; owner decision at Gate 2,
#        brain decisions.md 2026-11-08). Every other RUSTFLAGS line fails as before.
#      - ADR 0032 §1's nightly build of the tier 3 `arm64_32-apple-watchos` slice: the one
#        `-Zbuild-std=std,panic_abort` line of bindings/swift/scripts/build-xcframework.sh (its
#        continuation line, and every other line, is read as usual);
#      - the sentence of bindings/swift/README.md that documents that line (it names `-Zbuild-std`
#        in prose). An exact-line entry, not a skip of Markdown files: a skip by extension would
#        also cover a script named *.md, and an edited sentence fails until this entry follows it.
#
# Not covered (residual risk; cargo also reads these, but they are not in the repository): a config
# in a directory above the checkout (e.g. ~/.cargo/config.toml), $CARGO_HOME/config.toml, CARGO_*
# and RUST* variables from the caller's environment or the CI runner image, `--config` typed on a
# command line, and a variable name built at run time (or an env map from a `${{ }}` expression),
# which no text scan can see; also a `WASM_CARGO_ARGS` change made without assigning the name
# (`read -a`, `declare`, an array built through a nameref), and a guarded variable set without an
# assignment (`read RUSTFLAGS`, `printf -v`, then a bare `export`). Changes to scripts/, .github/,
# all of bindings/ (bindings/kotlin and bindings/swift included) and rust-toolchain.toml go through
# owner review for that reason. The script prints a note for configs and variables it finds outside
# the repository, without failing.
#
# Exit status: 0 clean, 1 a config or setting was found, 2 the check could not run (fails closed).
# Runs on macOS /bin/bash 3.2 and Linux bash.
set -euo pipefail
export LC_ALL=C
cd "$(dirname "$0")/.."
root=$(pwd -P)
self=scripts/check-no-cargo-config.sh

die() { echo "ERROR: $*" >&2; exit 2; }
status=0
fail() { echo "FAIL: $*"; status=1; }

command -v git >/dev/null 2>&1 || die "git not found on PATH; cannot list the repository's files"
command -v find >/dev/null 2>&1 || die "find not found on PATH; cannot scan the repository"
top=$(git rev-parse --show-toplevel 2>&1) || die "not a git work tree ($top)"
[ "$(cd "$top" && pwd -P)" = "$root" ] || die "git's top level $top is not this repository ($root)"

work=$(mktemp -d "${TMPDIR:-/tmp}/check-no-cargo-config.XXXXXX") || die "mktemp failed"
# Fail closed on a syntax error under bash 3.2 (feature 0013 F10; see scripts/test-all.sh).
completed=""
# shellcheck disable=SC2154 # rc is assigned by the trap itself (rc=$?)
trap 'rc=$?; rm -rf "$work"; [ -n "${completed:-}" ] || [ "$rc" -ne 0 ] || { echo "check-no-cargo-config.sh: stopped before its last line (a syntax error?): failing closed" >&2; rc=2; }; exit "$rc"' EXIT

# --- 1. No cargo config file anywhere in the repository -------------------------------------------
# NUL-separated listings become one path per line. A newline inside a name can only split a path,
# and the part after the split still ends in `.cargo/config...`, so it cannot hide a match.
git ls-files -z --cached >"$work/tracked.z" || die "git ls-files (tracked) failed"
git ls-files -z --others --exclude-standard >"$work/untracked.z" || die "git ls-files (untracked) failed"
git ls-files -z --others --ignored --exclude-standard >"$work/ignored.z" || die "git ls-files (ignored) failed"
# -prune stops the descent; without -L, find reports a symlink itself and never follows it.
find . -path ./.git -prune -o -type d -name target -prune -o \
  \( -iname config -o -iname config.toml -o \( -iname .cargo ! -type d \) \) -print0 \
  >"$work/found.z" || die "find failed while scanning the repository"

# Appends "<path>\t<source>" to $work/configs for each cargo config path (or non-directory `.cargo`)
# in a listing. The third argument, 1, skips paths inside a `target` directory (build output).
# Dynamic (string) regexes, so a `/` needs no escaping in any awk.
cargo_configs() {
  tr '\0' '\n' <"$1" | awk -v src="$2" -v skip_target="$3" '
    { p = $0; sub("^[.]/", "", p); l = tolower(p) }
    skip_target && l ~ "(^|/)target/" { next }
    l ~ "(^|/)[.]cargo/config([.]toml)?$" { print p "\t" src; next }
    l ~ "(^|/)[.]cargo$" { print p " is a symlink or file, not a directory\t" src }' >>"$work/configs" \
    || die "could not filter the $2 listing"
}
: >"$work/configs"
cargo_configs "$work/tracked.z" tracked 0
cargo_configs "$work/untracked.z" untracked 1
cargo_configs "$work/ignored.z" ignored 1
cargo_configs "$work/found.z" filesystem 1
if [ -s "$work/configs" ]; then
  fail "cargo config files in the repository (found by: tracked/untracked/ignored = git, filesystem = find):"
  sort "$work/configs" | awk -F '\t' '
    $1 != last { if (NR > 1) printf "\n"; printf "  - %s (%s", $1, $2; last = $1; next }
    { printf ", %s", $2 } END { if (NR) printf ")\n" }'
else
  echo "ok: no .cargo/config or .cargo/config.toml anywhere in the repository (git: tracked, untracked, ignored; filesystem)"
fi

# --- 2. No script, workflow or binding sets cargo configuration another way ------------------------
names='CARGO_SOURCE_[A-Za-z0-9_]+|CARGO_TARGET_[A-Za-z0-9_]+_(RUSTFLAGS|RUSTDOCFLAGS|LINKER|RUNNER)'
names="$names"'|CARGO_BUILD_(RUSTFLAGS|RUSTDOCFLAGS|RUSTC|RUSTC_WRAPPER|RUSTC_WORKSPACE_WRAPPER|RUSTDOC)'
names="$names"'|CARGO_ENCODED_RUSTFLAGS|CARGO_ENCODED_RUSTDOCFLAGS|RUSTFLAGS|RUSTDOCFLAGS'
names="$names"'|RUSTC|RUSTC_WRAPPER|RUSTC_WORKSPACE_WRAPPER|RUSTDOC|RUSTC_BOOTSTRAP|CARGO_UNSTABLE_[A-Za-z0-9_]+|CARGO_HOME'
# The exceptions, by path and exact text; each line is allowed at most once in its file.
# ADR 0059: the one command-line Cargo override of the shipped wasm build.
allowed_file=bindings/wasm/scripts/wasm-cargo-args.sh
allowed_line="WASM_CARGO_ARGS=(--config 'profile.release.opt-level=\"z\"')"
# 0007 review SF-1 (owner decision at Gate 2): the msvc prebuilds link the C runtime statically, as
# official Node does (no VC++ redistributable), and ci.test.ts asserts that line.
crt_file=bindings/node/scripts/ci-build.sh
# shellcheck disable=SC2016 # the exact text of the lines, not expansions
crt_line='  export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }-C target-feature=+crt-static"'
crt_test_file=bindings/node/test/ci.test.ts
# shellcheck disable=SC2016 # the exact text of the lines, not expansions
crt_test_line='    /^\s*export RUSTFLAGS="\$\{RUSTFLAGS:\+\$RUSTFLAGS \}-C target-feature=\+crt-static"$/,'
# ADR 0032 §1: the nightly -Zbuild-std build of the tier 3 arm64_32-apple-watchos slice, and the
# README sentence that documents it.
xcf_file=bindings/swift/scripts/build-xcframework.sh
# shellcheck disable=SC2016,SC1003 # the exact text of the line (a final backslash), not expansions
xcf_line='    cargo "+$nightly" rustc --locked -Zbuild-std=std,panic_abort -p polyjose-ffi --release \'
xcf_doc_file=bindings/swift/README.md
# shellcheck disable=SC2016 # the exact text of the lines, not expansions
xcf_doc_line='  - Every Rust target is tier 2 on the stable toolchain of `rust-toolchain.toml` (the aarch64 watchOS targets since Rust 1.95), except `arm64_32-apple-watchos` (Apple Watch Series 4–8, SE 1–2, Ultra 1). That one is tier 3 and is built with the nightly pinned in `nightly-toolchain` and `-Zbuild-std`. Install it with `rustup toolchain install "$(cat bindings/swift/nightly-toolchain)" --profile minimal --component rust-src`.'
# "<path><TAB><line>" per line, for awk.
allowed=$(printf '%s\t%s\n' "$allowed_file" "$allowed_line" "$crt_file" "$crt_line" "$crt_test_file" "$crt_test_line" \
  "$xcf_file" "$xcf_line" "$xcf_doc_file" "$xcf_doc_line")
# The Gradle wrapper (a zip that java runs), the one file not read while it is a zip (see the header).
wrapper_jar=bindings/kotlin/gradle/wrapper/gradle-wrapper.jar
git ls-files -z --cached --others --exclude-standard -- scripts .github bindings >"$work/build-files.z" \
  || die "git ls-files (scripts, .github, bindings) failed"
: >"$work/settings"
while IFS= read -r -d '' file; do
  [ "$file" = "$self" ] && continue
  [ -f "$file" ] || continue # tracked but deleted from the working tree
  if [ "$file" = "$wrapper_jar" ]; then
    sig=$(head -c 4 "$file" | od -An -tx1 | tr -d ' \n') || die "could not read $file"
    [ "$sig" = 504b0304 ] && continue
  fi
  case $file in bindings/*) binding=1 ;; *) binding=0 ;; esac
  case $file in *.rs | *.ts | *.mts | *.cts | *.js | *.mjs | *.cjs | *.kt | *.kts | *.java | *.swift) slashes=1 ;; *) slashes=0 ;; esac
  case $file in *.sh) shell=1 ;; *) shell=0 ;; esac
  # NUL bytes are dropped first (see the header). The allowed lines go through the environment:
  # awk -v would interpret their backslashes.
  tr -d '\000' <"$file" | ALLOWED=$allowed awk -v names="$names" -v file="$file" -v binding="$binding" \
    -v slashes="$slashes" -v shell="$shell" '
    BEGIN {
      q = "[\"" sprintf("%c", 39) "]?"
      eq = "(^|[^A-Za-z0-9_])(" names ")" q "[[:space:]]*([+]?=|<<)"
      colon = "(^|[^A-Za-z0-9_{])(" names ")" q "[[:space:]]*:"
      brace = "[{](" names "):="
      # A guarded name as a whole quoted string, the closing quote optionally escaped (see the header).
      sq = sprintf("%c", 39)
      quoted = "\"(" names ")(\\\\)?\"|" sq "(" names ")(\\\\)?" sq
      flag = "(^|[^A-Za-z0-9_-])--config([=[:space:]\"" sprintf("%c", 39) "]|$)"
      unstable = "(^|[^A-Za-z0-9_-])-Z"
      unzip = "^[[:space:]]*unzip -Z1([[:space:]]|$)"
      reads = "[$][{]#?WASM_CARGO_ARGS[[]@[]][}]"
      # The allowed lines of this file (the path is everything before the first tab).
      n = split(ENVIRON["ALLOWED"], entries, "\n"); nallowed = 0
      for (i = 1; i <= n; i++) {
        t = index(entries[i], "\t")
        if (t > 1 && substr(entries[i], 1, t - 1) == file) allowed_line[++nallowed] = substr(entries[i], t + 1)
      }
    }
    # A line continues the one above it if that one ends in a backslash (comment lines count too).
    { continued = prev_backslash; prev_backslash = ($0 ~ /\\$/) }
    /^[[:space:]]*#/ { next }
    slashes && /^[[:space:]]*\/\// { next }
    nallowed {
      for (i = 1; i <= nallowed; i++) if (!seen_allowed[i] && $0 == allowed_line[i]) { seen_allowed[i] = 1; next }
    }
    binding { rest = $0; gsub(reads, "", rest) }
    # The unzip carve-out (see the header): only the -Z test reads this copy.
    { z = $0; if (shell && !continued) sub(unzip, " ", z) }
    (binding && rest ~ "WASM_CARGO_ARGS") || $0 ~ flag || z ~ unstable || $0 ~ eq || $0 ~ colon || $0 ~ brace \
      || $0 ~ quoted || tolower($0) ~ "([.]cargo|cargo_home[}]?)/config" {
      printf "%s:%d: %s\n", file, FNR, $0
    }' >>"$work/settings" || die "could not scan $file"
done <"$work/build-files.z"
if [ -s "$work/settings" ]; then
  fail "scripts, workflows or bindings set cargo configuration outside a config file (--config, -Z, a .cargo/config write, a CARGO_*/RUST* variable, or WASM_CARGO_ARGS, other than the allowed lines of ADR 0059, 0007 SF-1 and ADR 0032 §1):"
  sed 's/^/  - /' "$work/settings"
else
  echo "ok: no script, workflow or binding passes --config or -Z, writes a cargo config or sets a cargo config variable (bindings/: only the allowed lines of ADR 0059, 0007 SF-1 and ADR 0032 §1)"
fi

# --- Notes: cargo configuration outside the repository (not checked, never fails) ------------------
dir=$(dirname "$root")
while :; do
  for f in "$dir/.cargo/config" "$dir/.cargo/config.toml"; do
    if [ -e "$f" ] || [ -L "$f" ]; then echo "note: cargo also reads $f (above the repository; not checked)"; fi
  done
  [ "$dir" = / ] && break
  dir=$(dirname "$dir")
done
home=${CARGO_HOME:-${HOME:-}/.cargo}
for f in "$home/config" "$home/config.toml"; do
  if [ -e "$f" ] || [ -L "$f" ]; then echo "note: cargo also reads $f (CARGO_HOME; not checked)"; fi
done
# Names only: a value (e.g. a registry token) is never printed.
set_vars=$(compgen -e | grep -E "^($names)$" || true)
if [ -n "$set_vars" ]; then
  echo "note: the environment sets $(echo "$set_vars" | tr '\n' ' ')(cargo reads these variables; not checked)"
fi

if [ $status -ne 0 ]; then
  cat <<'EOF'

A cargo config changes sources (source replacement, [patch]), rustflags, the rustc wrapper and
more for every cargo command run below it, outside the gates (check-deps.sh,
check-test-vectors-off.sh, deny.toml). polyjose has none. Adding one needs an ADR with an explicit
allowlist of keys (for example cross-compiling flags in features 0008/0009) and a change to this
check (scripts/check-no-cargo-config.sh).
EOF
fi
completed=1; exit "$status"
