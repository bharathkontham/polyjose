# shellcheck shell=bash
# Shared helpers for the tests of scripts/third-party-notices.sh (ADR 0020 §4). Sourced, not run.
#
# The tests run the script on the real workspace (read only: it writes nothing but its -o file,
# which goes to a scratch directory) and on small fixture workspaces of path crates built in the
# scratch directory, so no case needs the network. Run `cargo fetch --locked` once beforehand if
# the local registry does not have the workspace's crates yet.
#
# Runs on macOS /bin/bash 3.2 and Linux bash.

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd -P)
notices="$repo/scripts/third-party-notices.sh"
tests_failed=0
tests_run=0

lib_die() { echo "ERROR: $*" >&2; exit 2; }

command -v cargo >/dev/null 2>&1 || lib_die "cargo not found on PATH"
command -v python3 >/dev/null 2>&1 || lib_die "python3 not found on PATH"

scratch=$(mktemp -d "${TMPDIR:-/tmp}/third-party-notices-test.XXXXXX") || lib_die "mktemp failed"
# Fail closed on a syntax error under bash 3.2 (feature 0013 F10; see scripts/test-all.sh): finish
# (each test's last statement) sets the sentinel, so a test that stops before finish never exits 0.
completed=""
trap 'rc=$?; rm -rf "$scratch"; [ -n "${completed:-}" ] || [ "$rc" -ne 0 ] || { echo "${0##*/}: stopped before finish (a syntax error?): failing closed" >&2; rc=2; }; exit "$rc"' EXIT

pass() { tests_run=$((tests_run + 1)); echo "ok   - $1"; }
fail() { tests_run=$((tests_run + 1)); tests_failed=$((tests_failed + 1)); echo "FAIL - $1"; }

# run_notices <output file> <args...>: runs the script with -o <output file> and the other
# arguments, keeping its stdout and stderr in $scratch/last.log and its exit status in $rc.
# shellcheck disable=SC2034 # rc is read by the tests that source this file
run_notices() {
  local out=$1; shift
  rc=0
  "$notices" "$@" -o "$out" >"$scratch/last.log" 2>&1 || rc=$?
}

show_log() { sed 's/^/    | /' "$scratch/last.log"; }

# The 80-character rule line that opens and closes every section heading of a notices file.
rule=$(printf '%080d' 0 | tr 0 =)

# has_crate <notices file> <crate>: the file has a section for <crate> (any version): a heading
# line "<name> <version>" right after a rule line. (The summary list repeats each name with its
# license, and license texts may hold shorter rules, so neither can match.)
has_crate() {
  awk -v rule="$rule" -v name="$2" '
    prev == rule && index($0, name " ") == 1 && substr($0, length(name) + 2) ~ /^[0-9][^ ]*$/ { found = 1 }
    { prev = $0 }
    END { exit !found }' "$1"
}

# expect_crates <label> <notices file> <present|absent> <crate...>
expect_crates() {
  local label=$1 file=$2 mode=$3 c missing=""
  shift 3
  for c in "$@"; do
    if has_crate "$file" "$c"; then [ "$mode" = absent ] && missing="$missing $c"
    else [ "$mode" = present ] && missing="$missing $c"; fi
  done
  if [ -z "$missing" ]; then pass "$label"
  else fail "$label (wrongly $([ "$mode" = present ] && echo missing || echo present):$missing)"; fi
}

# expect_text <label> <notices file> <fixed string>
expect_text() {
  if grep -qF -- "$3" "$2"; then pass "$1"; else fail "$1 (no line contains: $3)"; fi
}

# crate_section <notices file> <name> <version>: prints that crate's section, from its heading
# to the rule line that opens the next section.
crate_section() {
  awk -v rule="$rule" -v want="$2 $3" '
    prev == rule && $0 == want { on = 1 }
    on && $0 == rule && body { exit }
    on { print; if ($0 != rule && $0 != want) body = 1 }
    { prev = $0 }' "$1"
}

# headings <notices file>: the "<name> <version>" heading of every third-party crate section.
headings() {
  awk -v rule="$rule" 'prev == rule && $0 ~ /^[A-Za-z0-9_-]+ [0-9][^ ]*$/ { print } { prev = $0 }' "$1" | sort
}

# tree_crates <package> <target>: "<name> <version>" of every registry crate in the artifact's
# tree, as cargo prints it; the workspace's own path crates are covered by the polyjose section.
tree_crates() {
  (cd "$repo" && cargo tree --locked --offline -p "$1" --target "$2" -e normal,no-proc-macro \
    --prefix none -f '{p}') |
    sed 's/ (\*)$//' | grep -v ' (/' | sed 's/^\([^ ]*\) v\([^ ]*\)$/\1 \2/' | sort -u
}

# --- Fixture workspaces of local path crates ------------------------------------------------

# new_fixture <name>: an empty fixture: a workspace $fx/ws whose one member `app` (MIT, the
# workspace LICENSE is polyjose's) gets its dependencies from app_dep, and a directory
# $fx/vendor for its path dependencies, outside the workspace so they are not members.
new_fixture() {
  fx="$scratch/fixture-$1"
  rm -rf "$fx"
  mkdir -p "$fx/ws/app/src" "$fx/vendor"
  cp "$repo/LICENSE" "$fx/ws/LICENSE"
  printf '[workspace]\nresolver = "2"\nmembers = ["app"]\n' >"$fx/ws/Cargo.toml"
  : >"$fx/ws/app/src/lib.rs"
  app_license=MIT
  : >"$fx/deps"; : >"$fx/build-deps"; : >"$fx/dev-deps"; : >"$fx/android-deps"; : >"$fx/linux-deps"
}

# vendor_crate <name> <license expression | - (none) | file:<path> (license-file only)>
#              [proc-macro] [dep...]: a path crate in $fx/vendor depending on other vendor crates.
vendor_crate() {
  local name=$1 license=$2 kind="" d dir
  shift 2
  if [ "${1:-}" = proc-macro ]; then kind=proc-macro; shift; fi
  dir="$fx/vendor/$name"
  mkdir -p "$dir/src"
  : >"$dir/src/lib.rs"
  {
    printf '[package]\nname = "%s"\nversion = "0.1.0"\nedition = "2021"\n' "$name"
    printf 'repository = "https://example.invalid/%s"\n' "$name"
    case $license in
      -) ;;
      file:*) printf 'license-file = "%s"\n' "${license#file:}" ;;
      *) printf 'license = "%s"\n' "$license" ;;
    esac
    [ "$kind" = proc-macro ] && printf '\n[lib]\nproc-macro = true\n'
    printf '\n[dependencies]\n'
    for d in "$@"; do printf '%s = { path = "../%s" }\n' "$d" "$d"; done
  } >"$dir/Cargo.toml"
}

# crate_file <crate> <relative path> <text>: a file in that vendor crate's directory.
crate_file() {
  mkdir -p "$(dirname "$fx/vendor/$1/$2")"
  printf '%s\n' "$3" >"$fx/vendor/$1/$2"
}

# app_dep <deps|build-deps|dev-deps|android-deps|linux-deps> <crate>: android-deps and linux-deps are
# app's dependencies for target_os "android" and "linux" only.
app_dep() { printf '%s = { path = "../../vendor/%s" }\n' "$2" "$2" >>"$fx/$1"; }

# lock_fixture: writes app's manifest and the fixture's Cargo.lock (offline, path crates only).
lock_fixture() {
  {
    printf '[package]\nname = "app"\nversion = "0.1.0"\nedition = "2021"\nlicense = "%s"\n' "$app_license"
    printf 'repository = "https://example.invalid/app"\n'
    printf '\n[dependencies]\n'; cat "$fx/deps"
    printf '\n[build-dependencies]\n'; cat "$fx/build-deps"
    printf '\n[dev-dependencies]\n'; cat "$fx/dev-deps"
    printf '\n[target.'\''cfg(target_os = "android")'\''.dependencies]\n'; cat "$fx/android-deps"
    printf '\n[target.'\''cfg(target_os = "linux")'\''.dependencies]\n'; cat "$fx/linux-deps"
  } >"$fx/ws/app/Cargo.toml"
  cargo generate-lockfile --offline --manifest-path "$fx/ws/Cargo.toml" >"$scratch/lock.log" 2>&1 \
    || { cat "$scratch/lock.log" >&2; lib_die "could not lock fixture $fx"; }
}

# fixture_run <output file> <target>...: one --target per given target, in the given order.
fixture_run() {
  local out=$1 t n
  shift
  n=$#
  for t in "$@"; do set -- "$@" --target "$t"; done
  shift "$n"
  run_notices "$out" -p app "$@" --manifest-path "$fx/ws/Cargo.toml"
}

# expect_reject <label> <crate label...>: the last run failed with status 1, its log names every
# given "<name> <version>", and it wrote no output file ($out).
expect_reject() {
  local label=$1 c missing=""
  shift
  for c in "$@"; do grep -qF -- "$c" "$scratch/last.log" || missing="$missing [$c]"; done
  if [ "$rc" -eq 1 ] && [ -z "$missing" ] && [ ! -e "$out" ]; then pass "$label"
  else
    fail "$label (exit $rc, crates not named:${missing:- none}, output $([ -e "$out" ] && echo written || echo absent))"
    show_log
  fi
}

# finish: prints the summary, sets the sentinel and fails if any check failed.
finish() {
  echo "$tests_run checks, $tests_failed failed"
  completed=1
  [ "$tests_failed" -eq 0 ]
}
