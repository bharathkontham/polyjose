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
#   2. No file under scripts/, .github/ or bindings/ (except this script) passes `--config` or
#      cargo's `-Z` (an unstable flag), writes a `.cargo/config*` or `$CARGO_HOME/config*` file, or
#      assigns an environment variable that does what a config file would: `CARGO_SOURCE_*`,
#      `CARGO_TARGET_<triple>_{RUSTFLAGS,RUSTDOCFLAGS,LINKER,RUNNER}`, `CARGO_BUILD_{RUSTFLAGS,
#      RUSTDOCFLAGS,RUSTC,RUSTC_WRAPPER,RUSTC_WORKSPACE_WRAPPER,RUSTDOC}`, `CARGO_ENCODED_RUSTFLAGS`,
#      `RUSTFLAGS`, `RUSTDOCFLAGS`, `RUSTC`, `RUSTC_WRAPPER`, `RUSTC_WORKSPACE_WRAPPER`, `RUSTDOC`,
#      `RUSTC_BOOTSTRAP`, `CARGO_UNSTABLE_*` or `CARGO_HOME`. Comment lines (`#`) are skipped. An
#      assignment is `NAME=`, `NAME<<` (GitHub's $GITHUB_ENV), `NAME:` (a YAML env key or a
#      JavaScript property) or `${NAME:=`. check-test-vectors-off.sh separately checks *RUSTFLAGS
#      in the environment.
#      bindings/ is read because the shipped @polyjose/wasm build takes extra Cargo arguments from
#      bindings/wasm/scripts/build-package.sh (security audit L2 of feature 0006): anything added
#      there reaches the published .wasm and no other guard. The one exception is ADR 0059's line,
#      allowed by path and exact text (`allowed_file`, `allowed_line` below), once; and no other
#      line under bindings/ may assign `WASM_CARGO_ARGS` (reading `${WASM_CARGO_ARGS[@]}` or
#      `${#WASM_CARGO_ARGS[@]}` is fine), so that line is all of the build's extra arguments.
#      check-rsa-symbols.sh builds the wasm32 configurations with the same line. Changing it
#      needs an ADR superseding ADR 0059 and the same change here.
#
# Not covered (residual risk; cargo also reads these, but they are not in the repository): a config
# in a directory above the checkout (e.g. ~/.cargo/config.toml), $CARGO_HOME/config.toml, CARGO_*
# and RUST* variables from the caller's environment or the CI runner image, `--config` typed on a
# command line, and a variable name built at run time (or an env map from a `${{ }}` expression),
# which no text scan can see; also a `WASM_CARGO_ARGS` change made without assigning the name
# (`read -a`, `declare`, an array built through a nameref). Changes to scripts/, .github/,
# bindings/ and rust-toolchain.toml go through owner review for that reason. The script prints a note for configs and variables it finds
# outside the repository, without failing.
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
# ADR 0059: the one command-line Cargo override of the shipped wasm build, by path and exact text.
allowed_file=bindings/wasm/scripts/build-package.sh
allowed_line="WASM_CARGO_ARGS=(--config 'profile.release.opt-level=\"z\"')"
git ls-files -z --cached --others --exclude-standard -- scripts .github bindings >"$work/build-files.z" \
  || die "git ls-files (scripts, .github, bindings) failed"
: >"$work/settings"
while IFS= read -r -d '' file; do
  [ "$file" = "$self" ] && continue
  [ -f "$file" ] || continue # tracked but deleted from the working tree
  case $file in bindings/*) binding=1 ;; *) binding=0 ;; esac
  # The allowed line goes through the environment: awk -v would interpret its backslashes.
  ALLOWED_LINE=$allowed_line awk -v names="$names" -v file="$file" -v binding="$binding" \
    -v allowed="$([ "$file" = "$allowed_file" ] && echo 1 || echo 0)" '
    BEGIN {
      q = "[\"" sprintf("%c", 39) "]?"
      eq = "(^|[^A-Za-z0-9_])(" names ")" q "[[:space:]]*(=|<<)"
      colon = "(^|[^A-Za-z0-9_{])(" names ")" q "[[:space:]]*:"
      brace = "[{](" names "):="
      flag = "(^|[^A-Za-z0-9_-])--config([=[:space:]\"" sprintf("%c", 39) "]|$)"
      unstable = "(^|[^A-Za-z0-9_-])-Z"
      reads = "[$][{]#?WASM_CARGO_ARGS[[]@[]][}]"
      allowed_line = ENVIRON["ALLOWED_LINE"]
    }
    /^[[:space:]]*#/ { next }
    allowed && !seen_allowed && $0 == allowed_line { seen_allowed = 1; next }
    binding { rest = $0; gsub(reads, "", rest) }
    (binding && rest ~ "WASM_CARGO_ARGS") || $0 ~ flag || $0 ~ unstable || $0 ~ eq || $0 ~ colon || $0 ~ brace \
      || tolower($0) ~ "([.]cargo|cargo_home[}]?)/config" {
      printf "%s:%d: %s\n", file, FNR, $0
    }' "$file" >>"$work/settings" || die "could not scan $file"
done <"$work/build-files.z"
if [ -s "$work/settings" ]; then
  fail "scripts, workflows or bindings set cargo configuration outside a config file (--config, -Z, a .cargo/config write, a CARGO_*/RUST* variable, or WASM_CARGO_ARGS other than ADR 0059's line in $allowed_file):"
  sed 's/^/  - /' "$work/settings"
else
  echo "ok: no script, workflow or binding passes --config or -Z, writes a cargo config or sets a cargo config variable (bindings/: only ADR 0059's WASM_CARGO_ARGS line in $allowed_file)"
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
