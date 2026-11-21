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
#      or cargo's `-Z` (an unstable flag), passes rustc arguments after a standalone `--` of
#      `cargo rustc` or `cargo rustdoc` or in an `@` argument file (what RUSTFLAGS would do), writes
#      a `.cargo/config*` or `$CARGO_HOME/config*` file, sets the Gradle property
#      `polyjose.jniLibsDir` in a *.properties file (the key followed by `=`, `:`, whitespace, a `\`
#      or the end of the line; it packages prebuilt native libraries into the AAR instead of
#      cargo's; reading it, as bindings/kotlin/android/build.gradle.kts does, is fine), or assigns an
#      environment variable that does what a config file would: `CARGO_SOURCE_*`,
#      `CARGO_TARGET_<triple>_{RUSTFLAGS,RUSTDOCFLAGS,LINKER,RUNNER}`, `CARGO_BUILD_{RUSTFLAGS,
#      RUSTDOCFLAGS,RUSTC,RUSTC_WRAPPER,RUSTC_WORKSPACE_WRAPPER,RUSTDOC}`, `CARGO_ENCODED_RUSTFLAGS`,
#      `RUSTFLAGS`, `RUSTDOCFLAGS`, `RUSTC`, `RUSTC_WRAPPER`, `RUSTC_WORKSPACE_WRAPPER`, `RUSTDOC`,
#      `RUSTC_BOOTSTRAP`, `CARGO_UNSTABLE_*`, `CARGO_PROFILE_*`, `CARGO_ALIAS_*`, `CARGO_HOME` or
#      `RUSTUP_TOOLCHAIN` (it overrides the toolchain rust-toolchain.toml pins).
#      Lines: each LF-ended line is also split at CR, NEL, LS and PS (U+0085, U+2028, U+2029 in
#      UTF-8), which end a line in Java, Kotlin, Swift, JavaScript or YAML (bug B01: `// note<CR>`
#      then code), and every piece is tested; a hit prints the whole line, a CR shown as `<CR>`.
#      The scan stops (exit status 2) if the awk in use does not build and split at those bytes as
#      expected (an awk in a multibyte locale).
#      A line starting with `#` is skipped as a comment only in *.sh, *.yml, *.yaml, *.toml and
#      *.properties files and files without an extension (gradlew), and only its first piece, when
#      the `#` follows nothing but spaces and tabs and the line does not continue the one above it
#      (that ends in `\`): a shell ends a line at LF only, so `: <CR>#; export NAME=x`, `<FF>#; ...`
#      and a `#` line after `echo x\` are code. Elsewhere `#` starts code (a Swift raw string
#      `#"NAME"#`, a JavaScript private field, a Rust attribute). `//` lines are
#      read in every file: one can sit in a string that a shell runs, and comments name these
#      variables in prose, not as assignments (bindings/wasm/tests/memory.rs's manual commands
#      say `<args>` for the ADR 0059 words).
#      An assignment is `NAME=`, `NAME+=`, `NAME<<` (GitHub's $GITHUB_ENV), `NAME:` (a YAML env key,
#      also in a flow mapping `{NAME: x}`, or a JavaScript property) or `${NAME:=`, NAME optionally
#      followed by Xcode conditions (`NAME[sdk=iphoneos*][arch=arm64] = ...` in an .xcconfig, a
#      .pbxproj or an XcodeGen project.yml); `${NAME:-x}` and `${NAME:+x}` are reads. These rules read
#      a line's pieces joined by spaces, so a CR, NEL, LS or PS between a name and its `=` or `:`
#      (whitespace in JavaScript) still counts. A line also fails if it holds one of these names as
#      the whole of a quoted string, `"NAME"` or `'NAME'`
#      (also `\"NAME\"`, escaped inside a string), whatever surrounds it: that is how Gradle
#      (`environment("NAME", ...)`, `environment["NAME"] = ...`, `put("NAME", ...)`,
#      `mapOf("NAME" to ...)`) and Swift (`env["NAME"] = ...`) set a child process's environment,
#      and how a shell names a variable to `printf -v` or `export`. A name inside a longer string
#      (`"set NAME first"`) is not one. check-test-vectors-off.sh separately checks *RUSTFLAGS in
#      the environment.
#      The `--` rule, and with it a word starting with `@` (an argument file, which `cargo rustc`
#      hands to rustc without `--`: `cargo rustc --lib @flags.txt`, `"@flags"`), reads what follows
#      `rustc` or `rustdoc` on the line of a cargo command, on the lines that continue it (that end
#      in `\`), and, from a quoted `"cargo"` on (a Gradle commandLine, a Python argv list), on every
#      line up to the bracket that closes its list. Opening brackets are counted on the text as it
#      is; closing ones on a copy without `"..."` and `'...'` strings (backslash escapes understood)
#      and without anything from a `/*`, `//` or `#` to the end of the line (a `/* */` on one line
#      only), in every file type, so a misparse keeps the list open longer, never shorter (bug B02).
#      `--` after `cargo test`, `run`, `clippy` or `fuzz` is not matched: what follows goes to the
#      test binary, the program run, clippy's lint pass or libFuzzer, not into a built artifact.
#      Every git-listed file (tracked or untracked, not ignored) is read as text, binary ones too
#      (the PE fixtures of bindings/node), with its NUL bytes dropped first: one-true-awk (macOS)
#      ends a line at a NUL, which would hide the rest of it, and bash drops NULs when it runs a
#      script (a sourced file stops at its first NUL, so it runs less, not more). There is no
#      skip by content or extension. Besides this script, the one file not read is the Gradle
#      wrapper bindings/kotlin/gradle/wrapper/gradle-wrapper.jar, by that exact path and only while
#      it starts with a zip signature (`PK\3\4`): java runs it, not a shell, and its compressed bytes
#      match the patterns at random. Anything else at that path is read.
#      `-Z` is not matched where it is the exact command `unzip -Z1` (zipinfo's one-name-per-line
#      listing, in the Kotlin and Swift packaging checks) at the start of a line, after indentation,
#      in a shell script (*.sh), on a line that does not continue the one above it (that ends in
#      `\`, CRs after it ignored, so `\`+CR counts as continuing: fails closed), and not after a
#      CR on its line. Only that command is removed from a copy of the line, and the rest is still
#      tested for `-Z`; all other patterns read the whole line. So `unzip -Z1 a && cargo -Zx`, `-Zx`
#      at the start of a line, `cargo +nightly -Zx`, `foo; unzip -Z1`, `unzip -Z1x`, and `unzip -Z1`
#      as an argument on a continuation line all fail. (`-Z1` itself is no cargo or rustc flag.)
#      bindings/ is read because the shipped @polyjose/wasm build takes extra Cargo arguments on
#      its command line (security audit L2 of feature 0006): anything added there reaches the
#      published .wasm and no other guard. The exceptions (`allowed` below) are allowed by path
#      and exact text (a CR at the end is a change), each at most once in its file (absent is fine);
#      an allowed line is not reported, and a cargo command on it still continues to the next line:
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
#        also cover a script named *.md, and an edited sentence fails until this entry follows it;
#      - the `cargo rustc ... -- --print cfg` line of scripts/check-test-vectors-off.sh: rustc
#        prints its cfgs and stops, building nothing (that check's own probe).
#
# Not covered (residual risk; cargo also reads these, but they are not in the repository): a config
# in a directory above the checkout (e.g. ~/.cargo/config.toml), $CARGO_HOME/config.toml, CARGO_*
# and RUST* variables from the caller's environment or the CI runner image, `--config` typed on a
# command line, and a variable name built at run time (or an env map from a `${{ }}` expression),
# which no text scan can see; also a `WASM_CARGO_ARGS` change made without assigning the name
# (`read -a`, `declare`, an array built through a nameref), and a guarded variable set without an
# assignment (`read RUSTFLAGS`, `printf -v`, then a bare `export`). Further, by design or because
# a line scan cannot see them:
#   - PATH and the variables not listed above (RUSTUP_HOME, ANDROID_NDK_HOME and other toolchain
#     or NDK locations), which choose which cargo, rustc or linker runs;
#   - names, flags or property keys written with escapes or assembled at run time (`"RUST" +
#     "FLAGS"`, `\u{46}`, `$'\x46'`, a `\` inside a .properties key), cargo named through a variable
#     (`"$cargo" rustc -- ...`), and an argument list whose brackets hide in unusual quoting or
#     in a block comment over several lines;
#   - a `#` line of a heredoc or multi-line string in a *.sh or *.yml file that is handed to a
#     language where `#` is code, and an extensionless script in such a language (its lines that
#     start with `#` are skipped);
#   - `--` or `@` arguments of cargo rustc supplied through a variable (`"${extra[@]}"`), a separate
#     statement (`args("--", ...)`, `args += listOf(...)`), an unquoted shell array over several
#     lines, or a YAML folded or plain multi-line `run:` without `\`; and toolchain selection
#     without RUSTUP_TOOLCHAIN (`cargo +nightly ...`, `rustup override set`, `rustup default`);
#   - a name and its `=` or `:` on different LF lines, Dockerfile `ENV NAME value` and Makefile
#     `NAME ?= value`;
#   - files outside scripts/, .github/ and bindings/ that a scanned script sources or runs, and the
#     root Package.swift;
#   - bindings/swift/nightly-toolchain, which names the nightly beside rust-toolchain.toml;
#   - the Gradle wrapper jar's content: its control is the SHA-256 pin that
#     `ci_check_gradle_wrapper` (bindings/kotlin/scripts/ci-lib.sh) checks before every `./gradlew`
#     of bindings/kotlin/test.sh and binding-android.yml (scripts/test-all.sh's own
#     `./gradlew test`, run only when bindings/kotlin/test.sh is missing, does not call it);
#   - lower-case names on Windows runners (environment names are case-insensitive there), `.plist`
#     keys (`<key>NAME</key>`: an environment for a launched app, not a build), and
#     `polyjose.jniLibsDir` set by `-P` (bindings/kotlin/scripts/ci-assemble-jar.sh does so for the
#     release AAR, with the libraries the emulator job tested and their SHA256SUMS),
#     `ORG_GRADLE_PROJECT_*` or ~/.gradle/gradle.properties.
# The other way (fails closed): `#` comment lines of file types not listed above (.py, .rb, .gradle,
# .mk, .bash, .zsh) are read, so a commented-out assignment there fails, as does a `#` line in a
# listed type when it continues a line ending in `\`.
# Changes to scripts/, .github/, all of bindings/ (bindings/kotlin and bindings/swift included) and
# rust-toolchain.toml go through owner review for that reason. The script prints a note for configs
# and variables it finds outside the repository, without failing.
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
names="$names"'|CARGO_PROFILE_[A-Za-z0-9_]+|CARGO_ALIAS_[A-Za-z0-9_]+|RUSTUP_TOOLCHAIN'
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
# check-test-vectors-off.sh's `cargo rustc -- --print cfg`: rustc prints its cfgs and stops, building
# nothing (the check that the test-vectors cfg is off).
cfg_file=scripts/check-test-vectors-off.sh
# shellcheck disable=SC2016 # the exact text of the line, not expansions
cfg_line='if ! cfgs=$(cargo rustc --locked -q -p polyjose --lib -- --print cfg 2>&1); then'
# "<path><TAB><line>" per line, for awk.
allowed=$(printf '%s\t%s\n' "$allowed_file" "$allowed_line" "$crt_file" "$crt_line" "$crt_test_file" "$crt_test_line" \
  "$xcf_file" "$xcf_line" "$xcf_doc_file" "$xcf_doc_line" "$cfg_file" "$cfg_line")
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
  case $file in *.sh) shell=1 ;; *) shell=0 ;; esac
  case $file in *.properties) props=1 ;; *) props=0 ;; esac
  # The file types where a line starting with `#` is a comment (see the header): no other skips it.
  case $file in
    *.sh | *.yml | *.yaml | *.toml | *.properties) hash=1 ;;
    *) case ${file##*/} in *.*) hash=0 ;; *) hash=1 ;; esac ;;
  esac
  # NUL bytes are dropped first (see the header). The allowed lines go through the environment:
  # awk -v would interpret their backslashes.
  tr -d '\000' <"$file" | ALLOWED=$allowed awk -v names="$names" -v file="$file" -v binding="$binding" \
    -v shell="$shell" -v props="$props" -v hash="$hash" '
    BEGIN {
      sq = sprintf("%c", 39); cr = sprintf("%c", 13); mark = sprintf("%c", 1)
      # The line breaks other than LF of the languages read (see the header): CR, and NEL, LS and PS
      # in UTF-8. A line is tested as the pieces between them.
      nel = sprintf("%c%c", 194, 133); ls = sprintf("%c%c%c", 226, 128, 168); ps = sprintf("%c%c%c", 226, 128, 169)
      breaks = cr "|" nel "|" ls "|" ps
      # Fails closed (exit 2) on an awk that builds these as other bytes (a multibyte locale) or does
      # not split at them.
      if (cr != "\r" || nel != "\302\205" || ls != "\342\200\250" || ps != "\342\200\251" || length(mark) != 1 \
        || split("a" cr "b" nel "c" ls "d" ps "e", probe, breaks) != 5 || (probe[1] probe[2] probe[3] probe[4] probe[5]) != "abcde") {
        print "check-no-cargo-config.sh: this awk does not handle the line-break bytes as expected" >"/dev/stderr"
        exit 2
      }
      q = "[\"" sq "]?"
      # An Xcode conditional setting name, NAME[sdk=iphoneos*] (any number of conditions).
      cond = "([[][^]]*[]])*"
      eq = "(^|[^A-Za-z0-9_])(" names ")" cond q "[[:space:]]*([+]?=|<<)"
      # `{NAME:` is a YAML flow map or a JavaScript object; only `${NAME:` (a shell read) is not.
      colon = "(^|[^A-Za-z0-9_{]|(^|[^$])[{])(" names ")" cond q "[[:space:]]*:"
      brace = "[{](" names "):="
      # A guarded name as a whole quoted string, the closing quote optionally escaped (see the header).
      quoted = "\"(" names ")(\\\\)?\"|" sq "(" names ")(\\\\)?" sq
      flag = "(^|[^A-Za-z0-9_-])--config([=[:space:]\"" sq "]|$)"
      unstable = "(^|[^A-Za-z0-9_-])-Z"
      unzip = "^[[:space:]]*unzip -Z1([[:space:]]|$)"
      reads = "[$][{]#?WASM_CARGO_ARGS[[]@[]][}]"
      # cargo and rustc or rustdoc as words (a path before them is fine), a standalone `--`, cargo as
      # a quoted string (replaced by mark), and the strings that are taken out before brackets are
      # counted (never one that holds mark).
      cargo = "(^|[^A-Za-z0-9_.-])cargo([^A-Za-z0-9_/-]|$)"
      rustcw = "(^|[^A-Za-z0-9_.-])(rustc|rustdoc)([^A-Za-z0-9_/-]|$)"
      dashdash = "(^|[^A-Za-z0-9_-])--([^A-Za-z0-9_-]|$)"
      # A word starting with `@`: an argument file that cargo rustc and rustdoc hand to rustc.
      atword = "(^|[[:space:]\"" sq "\\\\])@"
      qcargo = "\"cargo\"|" sq "cargo" sq
      dstr = "\"([^\"\\\\" mark "]|\\\\.)*\""; sstr = sq "([^" sq "\\\\" mark "]|\\\\.)*" sq
      jnilibs = "^[[:space:]]*polyjose[.]jniLibsDir([=:[:space:]\\\\]|$)"
      depth = -1
      # The allowed lines of this file (the path is everything before the first tab).
      n = split(ENVIRON["ALLOWED"], entries, "\n"); nallowed = 0
      for (i = 1; i <= n; i++) {
        t = index(entries[i], "\t")
        if (t > 1 && substr(entries[i], 1, t - 1) == file) allowed_line[++nallowed] = substr(entries[i], t + 1)
      }
    }
    # A line continues the one above it if that one ends in a backslash, line breaks after it
    # ignored (comment lines count too). A cargo command stays open across such lines.
    {
      raw = $0; t = raw; sub("(" breaks ")+$", "", t)
      continued = prev_backslash; prev_backslash = (t ~ /\\$/); in_cargo = continued && cargo_open
    }
    {
      # An allowed line is tested like any other, and not reported; the cargo state goes on through it.
      allowed_now = 0
      for (i = 1; i <= nallowed; i++) if (!seen_allowed[i] && raw == allowed_line[i]) { seen_allowed[i] = 1; allowed_now = 1; break }
      n = split(raw, piece, breaks); hit = 0; live = ""
      for (p = 1; p <= n; p++) {
        line = piece[p]
        # A comment (see the header): only the first piece of a line that does not continue the one
        # above, indented by spaces and tabs only.
        if (hash && p == 1 && !continued && line ~ /^[ \t]*#/) continue
        live = live " " line
        rest = line; if (binding) gsub(reads, "", rest)
        # The unzip carve-out (see the header): only the -Z test reads this copy.
        z = line; if (shell && p == 1 && !continued) sub(unzip, " ", z)
        if ((binding && rest ~ "WASM_CARGO_ARGS") || line ~ flag || z ~ unstable \
          || line ~ brace || line ~ quoted || tolower(line) ~ "([.]cargo|cargo_home[}]?)/config" \
          || (props && line ~ jnilibs)) hit = 1
      }
      # The assignment rules read the pieces joined: a CR, NEL, LS or PS between a name and its `=`
      # or `:` (whitespace in JavaScript) still matches.
      if (live ~ eq || live ~ colon) hit = 1
      # rustc arguments after a standalone `--` of `cargo rustc` or `cargo rustdoc`, or in an `@`
      # argument file: on its line, on the lines that continue it, and inside the brackets of an
      # argument list that starts with a quoted cargo (Gradle commandLine, a Python argv list).
      after = (in_cargo || depth >= 0) ? live : ""
      if (match(live, cargo)) after = after " " substr(live, RSTART + RLENGTH - 1)
      tail = ""
      if (rustc_open) tail = after
      else if (match(after, rustcw)) tail = substr(after, RSTART + RLENGTH - 1)
      if (tail ~ dashdash || tail ~ atword) hit = 1
      seen_rustc = rustc_open || after ~ rustcw
      cargo_open = prev_backslash && (in_cargo || live ~ cargo)
      # Opening brackets are counted on the line as it is, closing ones on a copy without strings
      # and without every comment style (/* */, //, #, in any file type), from the first quoted
      # cargo on: a misparse can only keep the list open longer (bug B02).
      code = live; gsub(qcargo, mark, code)
      if (depth >= 0 || index(code, mark)) {
        shut = code; gsub(dstr, "", shut); gsub(sstr, "", shut)
        gsub("/[*]([^*]|[*]+[^*/])*[*]+/", "", shut); sub("/[*].*", "", shut); sub("//.*", "", shut); sub("#.*", "", shut)
        if (depth < 0) {
          depth = 0; code = substr(code, index(code, mark) + 1)
          shut = index(shut, mark) ? substr(shut, index(shut, mark) + 1) : ""
        }
        depth += gsub(/[([{]/, "", code) - gsub(/[])}]/, "", shut)
        if (depth < 0) depth = -1
      }
      rustc_open = seen_rustc && (cargo_open || depth >= 0)
      if (hit && !allowed_now) { gsub(cr, "<CR>", raw); printf "%s:%d: %s\n", file, FNR, raw }
    }' >>"$work/settings" || die "could not scan $file"
done <"$work/build-files.z"
if [ -s "$work/settings" ]; then
  fail "scripts, workflows or bindings set cargo configuration outside a config file (--config, -Z, rustc arguments after cargo rustc --, a .cargo/config write, a CARGO_*/RUST* variable, polyjose.jniLibsDir in a .properties file, or WASM_CARGO_ARGS, other than the allowed lines of ADR 0059, 0007 SF-1, ADR 0032 §1 and check-test-vectors-off.sh):"
  sed 's/^/  - /' "$work/settings"
else
  echo "ok: no script, workflow or binding passes --config, -Z or rustc arguments after cargo rustc --, writes a cargo config, sets a cargo config variable or polyjose.jniLibsDir (only the allowed lines of ADR 0059, 0007 SF-1, ADR 0032 §1 and check-test-vectors-off.sh)"
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
