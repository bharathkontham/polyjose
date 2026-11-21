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
#      then code), and every piece is tested (the assignment rules and part (a) of the `--` rule
#      read the pieces joined by spaces; part (b) reads the whole line, where each of these breaks
#      also counts as a line start); a hit prints the whole line, a CR shown as `<CR>`.
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
#      the whole of a quoted string, `"NAME"`, `'NAME'` or a JavaScript template literal
#      (backtick-quoted, `process.env[<backtick>NAME<backtick>] = ...`; in every file type except
#      *.md, where backticks are inline code: T07, round-4 audit L-1), also with the closing quote
#      escaped (`\"NAME\"` inside a string),
#      whatever surrounds it: that is how Gradle
#      (`environment("NAME", ...)`, `environment["NAME"] = ...`, `put("NAME", ...)`,
#      `mapOf("NAME" to ...)`) and Swift (`env["NAME"] = ...`) set a child process's environment,
#      and how a shell names a variable to `printf -v` or `export`. A name inside a longer string
#      (`"set NAME first"`) is not one. check-test-vectors-off.sh separately checks *RUSTFLAGS in
#      the environment.
#      The `--` rule, and with it a word starting with `@` (an argument file, which `cargo rustc`
#      hands to rustc without `--`: `cargo rustc --lib @flags.txt`, `"@flags"`), has two parts, in
#      every file type:
#      (a) a command line: what follows a `rustc` or `rustdoc` word on its line, and on the lines
#          that continue it (that end in `\`) once a `cargo` word (any case: `"$CARGO"`,
#          `${{ env.CARGO }}`) or a rustc or rustdoc word opened the command. No cargo word is
#          needed on the rustc line, so cargo through another name is read too (`"${CARGO_BIN}"
#          rustc -- ...`, `cross rustc -- ...`, `cargo-ndk ... rustc -- ...`; T07 round 2, audit
#          L-1). `--` after `cargo test`, `run`, `clippy` or `fuzz` is not matched there: what
#          follows goes to the test binary, the program run, clippy's lint pass or libFuzzer, not
#          into a built artifact;
#      (b) an argument list (a Gradle commandLine, a Python argv list, a JavaScript or shell array),
#          by file, with no bracket or string tracking (feature 0030 T07; four rounds of bracket
#          tracking each left a way to close a list early): if the file holds a `cargo` word and a
#          `rustc` or `rustdoc` word anywhere (any case, on any lines, comments and strings
#          included; quoted, bare, `"/usr/bin/cargo"` or `$cargo` all count, `cargo-ndk`,
#          `.cargo` and `CARGO_HOME` do not), every line of it that holds a quote, or a quote and
#          backslashes, or the start of the line or a CR, NEL, LS or PS in it, followed by `--` and
#          then anything but a letter, digit, `_` or `-`, or followed by `@`, fails, whatever else
#          is on the line: `"--"`, `'--'`, `\"--\"`, `"-- -Cx"`, `"\--"`, `"@flags"`, `"\@flags"`,
#          `"@" + path`, and the rest of a string continued on the next line (`"\` then `--",`;
#          `"""` then `--"""`) or after a CR, LS or PS on its LF line (`"\<CR>--"`, which continue a
#          string in JavaScript, CR also in Python; audit L-2 of T07 and its re-audit). A quote is
#          `"` or `'`, and a backtick (a JavaScript template literal) except in *.sh and *.md
#          files, where it is a command substitution or inline code. This fails closed: such a `--` or `@` unrelated to cargo fails too (`listOf("--")`
#          after a closed cargo rustc list, a comment, a line that starts with `-- ` or with an
#          `@` annotation or decorator), so a file that needs one either keeps the two words out
#          or has the line allowed below.
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
#        prints its cfgs and stops, building nothing (that check's own probe);
#      - three lines that part (b) of the `--` rule reads in files naming cargo and rustc, none of
#        them a cargo argument: the `"@"` of scripts/check-rsa-symbols.sh's LEGACY_ESCAPES (a
#        Python table of Rust symbol escapes), and in bindings/node/test/ci.test.ts the comment and
#        the assertion message that quote napi build's `--` in backticks.
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
#     "FLAGS"`, `\u{46}`, `$'\x46'`, a `\` inside a .properties key);
#   - a `#` line of a heredoc or multi-line string in a *.sh or *.yml file that is handed to a
#     language where `#` is code, and an extensionless script in such a language (its lines that
#     start with `#` are skipped);
#   - `--` and `@` arguments that neither part of the `--` rule reads (known limits of T07,
#     documented, not chased: a rule failing every standalone `--` in a file that names cargo and
#     rustc would fail 58 lines of the current tree):
#     - with a quoted cargo rustc list on line 1, later lines such as `/--/.source` and
#       `" --".trim()` (.mjs), `*%w[-- -Cx]` and `%w[ @flags ]` (.rb), `qw(-- -Cx)` (.pl), `/--/`
#       (.gradle), a YAML flow sequence `--, -Cx]`, an unquoted shell array `-- -Cx)` over several
#       lines, a YAML block sequence item `- --`, XML `<arg>--</arg>`;
#     - flags built at run time (`"-" + "-"`, `"\x2d-"`, `String.fromCharCode(45, 45)`,
#       `"${dd}"`), from a variable (`"${extra[@]}"`) or from another file (an imported constant,
#       a sourced script);
#     - cargo or rustc named only indirectly in a file (`process.env.CARGO`, `cargoBin`, `exe`,
#       `"car" + "go"`, `"rust" + "c"`, a path from the environment): part (b) needs both words;
#     - a backtick-quoted `--` in a *.sh file (a `node -e '...'` script) or a *.md file (the
#       Markdown exemption of the backtick), and a YAML folded or plain multi-line `run:` without
#       `\`;
#     - a YAML double-quoted scalar continued with `\`: YAML drops the next line's indentation, so
#       an indented `--"` there is not read (only a `--` at the very start of a line is);
#   - toolchain selection without RUSTUP_TOOLCHAIN (`cargo +nightly ...`, `rustup override set`,
#     `rustup default`);
#   - a name and its `=` or `:` on different LF lines, Dockerfile `ENV NAME value` and Makefile
#     `NAME ?= value`;
#   - files outside scripts/, .github/ and bindings/ that a scanned script sources or runs, and the
#     root Package.swift;
#   - bindings/swift/nightly-toolchain, which names the nightly beside rust-toolchain.toml;
#   - the Gradle wrapper jar's content: its control is the SHA-256 pin that
#     `ci_check_gradle_wrapper` (bindings/kotlin/scripts/ci-lib.sh) checks before every `./gradlew`
#     of bindings/kotlin/test.sh and binding-android.yml (scripts/test-all.sh's own
#     `./gradlew test`, run only when bindings/kotlin/test.sh is missing, does not call it);
#   - a `#` line inside a multi-line quoted string of the shell script itself (code to the shell
#     when it is run as code later, e.g. by `eval`), not only text handed to another language;
#   - a workflow step's PowerShell backtick or cmd `^` line continuation (only `\` continues a
#     cargo command), lower-case action inputs such as `with: rustflags:`, and a name split by a
#     backslash-newline in a shell script;
#   - lower-case names on Windows runners (environment names are case-insensitive there), `.plist`
#     keys (`<key>NAME</key>`: an environment for a launched app, not a build), and
#     `polyjose.jniLibsDir` set by `-P` (bindings/kotlin/scripts/ci-assemble-jar.sh does so for the
#     release AAR, with the libraries the emulator job tested and their SHA256SUMS),
#     `ORG_GRADLE_PROJECT_*` or ~/.gradle/gradle.properties.
# The other way (fails closed): `#` comment lines of file types not listed above (.py, .rb, .gradle,
# .mk, .bash, .zsh) are read, so a commented-out assignment there fails, as does a `#` line in a
# listed type when it continues a line ending in `\`; a guarded name as inline code (in backticks)
# fails outside *.md files; on a cargo rustc or rustdoc line, a trailing comment word starting with
# `@` fails; a standalone `--` or a word starting with `@` after a rustc or rustdoc word fails
# without any cargo word on the line too (a direct rustc call, prose on a code line); and in a file
# that names cargo and rustc or rustdoc, every quoted `--` or `@` fails, also one in a comment, in
# prose or in a call that has nothing to do with cargo, as does a line starting with `-- ` or `@`.
# Examples that fail for these reasons: `Built by rustc for @polyjose/node.` (any file), `rustc
# --version \` then `  && cargo test -- --nocapture`, `echo rustc; cargo doc -- x`,
# `rustc -vV | grep -- host`, and `@testable import Polyjose` at column 0 of a Swift file that
# names cargo and rustc.
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
    $1 != last { if (NR > 1) print out ")"; out = "  - " $1 " (" $2; last = $1; next }
    { out = out ", " $2 } END { if (NR) print out ")" }'
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
# Quoted `--` and `@` in files that name cargo and rustc, none a cargo argument (part (b) of the
# `--` rule): a Python table of Rust symbol escapes, and napi build's `--` in a comment and in an
# assertion message.
esc_file=scripts/check-rsa-symbols.sh
# shellcheck disable=SC2016 # the exact text of the line, not expansions
esc_line='LEGACY_ESCAPES = [("$SP$", "@"), ("$BP$", "*"), ("$RF$", "&"), ("$LT$", "<"), ("$GT$", ">"),'
# shellcheck disable=SC2016 # the exact text of the line (backticks), not expansions
napi_note_line='        // napi build passes the options after `--` on to cargo build (and to its cargo metadata).'
# shellcheck disable=SC2016 # the exact text of the line, not expansions
napi_msg_line='        assert.match(napiLine, /[ \t]--[ \t]+--locked\b/, `${name}: napi build without \`-- --locked\`: ${napiLine.trim()}`);'
# "<path><TAB><line>" per line, for awk.
allowed=$(printf '%s\t%s\n' "$allowed_file" "$allowed_line" "$crt_file" "$crt_line" "$crt_test_file" "$crt_test_line" \
  "$xcf_file" "$xcf_line" "$xcf_doc_file" "$xcf_doc_line" "$cfg_file" "$cfg_line" "$esc_file" "$esc_line" \
  "$crt_test_file" "$napi_note_line" "$crt_test_file" "$napi_msg_line")
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
  case $file in *.md) md=1 ;; *) md=0 ;; esac
  # The file types where a line starting with `#` is a comment (see the header): no other skips it.
  case $file in
    *.sh | *.yml | *.yaml | *.toml | *.properties) hash=1 ;;
    *) case ${file##*/} in *.*) hash=0 ;; *) hash=1 ;; esac ;;
  esac
  # NUL bytes are dropped first (see the header). The allowed lines go through the environment:
  # awk -v would interpret their backslashes.
  tr -d '\000' <"$file" | ALLOWED=$allowed awk -v names="$names" -v file="$file" -v binding="$binding" \
    -v shell="$shell" -v props="$props" -v hash="$hash" -v md="$md" '
    BEGIN {
      sq = sprintf("%c", 39); bt = sprintf("%c", 96); cr = sprintf("%c", 13)
      # The line breaks other than LF of the languages read (see the header): CR, and NEL, LS and PS
      # in UTF-8. A line is tested as the pieces between them.
      nel = sprintf("%c%c", 194, 133); ls = sprintf("%c%c%c", 226, 128, 168); ps = sprintf("%c%c%c", 226, 128, 169)
      breaks = cr "|" nel "|" ls "|" ps
      # Fails closed (exit 2) on an awk that builds these as other bytes (a multibyte locale) or does
      # not split at them.
      if (cr != "\r" || nel != "\302\205" || ls != "\342\200\250" || ps != "\342\200\251" \
        || split("a" cr "b" nel "c" ls "d" ps "e", probe, breaks) != 5 || (probe[1] probe[2] probe[3] probe[4] probe[5]) != "abcde") {
        print "check-no-cargo-config.sh: this awk does not handle the line-break bytes as expected" >"/dev/stderr"
        broken = 1; exit 2
      }
      q = "[\"" sq "]?"
      # An Xcode conditional setting name, NAME[sdk=iphoneos*] (any number of conditions).
      cond = "([[][^]]*[]])*"
      eq = "(^|[^A-Za-z0-9_])(" names ")" cond q "[[:space:]]*([+]?=|<<)"
      # `{NAME:` is a YAML flow map or a JavaScript object; only `${NAME:` (a shell read) is not.
      colon = "(^|[^A-Za-z0-9_{]|(^|[^$])[{])(" names ")" cond q "[[:space:]]*:"
      brace = "[{](" names "):="
      # A guarded name as a whole quoted string, the closing quote optionally escaped (see the header);
      # in a Markdown file a backtick is inline code, not a string (round-4 audit L-1).
      quoted = "\"(" names ")(\\\\)?\"|" sq "(" names ")(\\\\)?" sq
      if (!md) quoted = quoted "|" bt "(" names ")(\\\\)?" bt
      flag = "(^|[^A-Za-z0-9_-])--config([=[:space:]\"" sq "]|$)"
      unstable = "(^|[^A-Za-z0-9_-])-Z"
      unzip = "^[[:space:]]*unzip -Z1([[:space:]]|$)"
      reads = "[$][{]#?WASM_CARGO_ARGS[[]@[]][}]"
      # cargo and rustc or rustdoc as words (a path before them is fine), and a standalone `--`.
      cargo = "(^|[^A-Za-z0-9_.-])cargo([^A-Za-z0-9_/-]|$)"
      rustcw = "(^|[^A-Za-z0-9_.-])(rustc|rustdoc)([^A-Za-z0-9_/-]|$)"
      dashdash = "(^|[^A-Za-z0-9_-])--([^A-Za-z0-9_-]|$)"
      # A word starting with `@`: an argument file that cargo rustc and rustdoc hand to rustc.
      atword = "(^|[[:space:]\"" sq "\\\\])@"
      # Part (b) of the `--` rule (see the header): a quote and any backslashes, the start of the
      # line or a CR, NEL, LS or PS, then `--` that ends there, or `@`.
      quote = "[\"" sq ((shell || md) ? "" : bt) "]"
      arglist = "(^|" breaks "|" quote "\\\\*)(--([^A-Za-z0-9_-]|$)|@)"
      jnilibs = "^[[:space:]]*polyjose[.]jniLibsDir([=:[:space:]\\\\]|$)"
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
      # (a) of the `--` rule: rustc arguments after a standalone `--` of `cargo rustc` or `cargo
      # rustdoc`, or in an `@` argument file, on its line and on the lines that continue it.
      after = in_cargo ? live : ""
      if (match(tolower(live), cargo)) after = after " " substr(live, RSTART + RLENGTH - 1)
      tail = ""
      if (rustc_open) tail = after
      else if (match(after, rustcw)) tail = substr(after, RSTART + RLENGTH - 1)
      if (tail ~ dashdash || tail ~ atword) hit = 1
      # Also after a rustc or rustdoc word with no cargo word before it (cargo through a variable:
      # `"$CARGO_BIN" rustc -- ...`), and such a line opens a continued command as cargo does.
      if (match(live, rustcw)) { tail = substr(live, RSTART + RLENGTH - 1); if (tail ~ dashdash || tail ~ atword) hit = 1 }
      seen_rustc = rustc_open || live ~ rustcw
      cargo_open = prev_backslash && (in_cargo || tolower(live) ~ cargo || live ~ rustcw)
      rustc_open = seen_rustc && cargo_open
      # (b): whether the file names cargo and rustc or rustdoc is known only at its end, so a line
      # with a quoted `--` or `@` is kept until then; every other hit is kept too, to print in order.
      low = tolower(raw)
      if (low ~ cargo) has_cargo = 1
      if (low ~ rustcw) has_rustc = 1
      if (!allowed_now && (hit || raw ~ arglist)) {
        gsub(cr, "<CR>", raw); report[++nreport] = file ":" FNR ": " raw; by_file_only[nreport] = !hit
      }
    }
    END {
      if (broken) exit 2
      for (i = 1; i <= nreport; i++) if (!by_file_only[i] || (has_cargo && has_rustc)) print report[i]
    }' >>"$work/settings" || die "could not scan $file"
done <"$work/build-files.z"
if [ -s "$work/settings" ]; then
  fail "scripts, workflows or bindings set cargo configuration outside a config file (--config, -Z, rustc arguments after cargo rustc --, a .cargo/config write, a CARGO_*/RUST* variable, polyjose.jniLibsDir in a .properties file, or WASM_CARGO_ARGS, other than the allowed lines of ADR 0059, 0007 SF-1, ADR 0032 §1, check-test-vectors-off.sh and the header's three non-argument lines; in a file naming cargo and rustc or rustdoc, every quoted -- or @ fails):"
  sed 's/^/  - /' "$work/settings"
else
  echo "ok: no script, workflow or binding passes --config, -Z or rustc arguments after cargo rustc --, writes a cargo config, sets a cargo config variable or polyjose.jniLibsDir (only the allowed lines of ADR 0059, 0007 SF-1, ADR 0032 §1, check-test-vectors-off.sh and the header's three non-argument lines)"
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
