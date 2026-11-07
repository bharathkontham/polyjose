#!/usr/bin/env bash
# Negative test of the fail-closed rule of the guard scripts (feature 0013 F10; pipeline rule 9).
# macOS /bin/bash 3.2 runs an EXIT trap with $? = 0 after a syntax error, so a script with an EXIT
# trap exited 0 when an edit broke its syntax (bash 5 exits 2). Each scripts/*.sh that installs an
# EXIT trap therefore sets `completed=1` on its last line, and its trap turns an exit without it
# into a non-zero status (keeping a non-zero status the script chose). check-deps.sh,
# check-rsa-symbols.sh and check-test-vectors-off.sh follow in F11 and are listed apart here.
#
# The cases:
#   - the rule, read from the real scripts: each trap script's trap tests the sentinel, and the
#     sentinel is set exactly once, on the last non-blank line; every scripts/*.sh is classified
#     (trap script, script without a trap, or F11), so a new script fails until it is;
#   - copies of each guard with a syntax error injected (an unexpected token, and the quote inside
#     a python3 -c string of proposals/F10-bash32-syntax-error-repro.sh) right after the trap and
#     right before the last statement exit 2 after reaching the injected line, under the bash that
#     runs this test; the same copy without the error exits 0. Also for the scripts without a trap
#     (conformance-parity.sh exits 2; a broken check-binding-api.d mode file fails its mode, exit
#     1) and for scripts/tests/test-all/lib.sh and scripts/tests/third-party-notices/lib.sh, whose
#     tests source them.
#
# Usage: /bin/bash scripts/tests/syntax/guards.sh checks bash 3.2; a Linux bash checks bash 5.
# Needs git, cargo, rustc, python3 and node.
# shellcheck disable=SC2329 # copy and the setup_* and invoke_* functions are called by name (guard)
set -euo pipefail
export LC_ALL=C

repo=$(cd "$(dirname "$0")/../../.." && pwd -P)
tests_run=0 tests_failed=0
die() { echo "ERROR: $*" >&2; exit 2; }
for tool in git cargo rustc python3 node; do
  command -v "$tool" >/dev/null 2>&1 || die "$tool not found on PATH"
done

scratch=$(mktemp -d "${TMPDIR:-/tmp}/syntax-guards-test.XXXXXX") || die "mktemp failed"
# Fail closed (F10): see scripts/test-all.sh.
completed=""
trap 'rc=$?; rm -rf "$scratch"; [ -n "${completed:-}" ] || [ "$rc" -ne 0 ] || { echo "guards.sh: stopped before its last statement (a syntax error?); failing closed" >&2; rc=2; }; exit "$rc"' EXIT

pass() { tests_run=$((tests_run + 1)); echo "ok   - $1"; }
fail() { tests_run=$((tests_run + 1)); tests_failed=$((tests_failed + 1)); echo "FAIL - $1"; }

# The scripts/*.sh that install an EXIT trap and follow the rule, the ones without a trap, and the
# ones F11 does.
trap_scripts="test-all.sh check-binding-api.sh check-no-cargo-config.sh third-party-notices.sh"
no_trap_scripts="conformance-parity.sh"
f11_scripts="check-deps.sh check-rsa-symbols.sh check-test-vectors-off.sh"

# --- The rule, read from the real scripts --------------------------------------------------------------

listed() { case " $2 " in *" $1 "*) return 0 ;; esac; return 1; }
has_exit_trap() { grep -Eq '^[[:space:]]*trap .*EXIT$' "$1"; }

for f in "$repo"/scripts/*.sh; do
  [ -e "$f" ] || continue # bash 3.2 has no nullglob by default
  name=${f##*/}
  if listed "$name" "$f11_scripts"; then continue; fi
  if has_exit_trap "$f"; then
    if listed "$name" "$trap_scripts"; then pass "$name installs an EXIT trap and is a trap script here"
    else fail "$name installs an EXIT trap but is not in trap_scripts (add the sentinel and list it)"; fi
  else
    if listed "$name" "$no_trap_scripts"; then pass "$name has no EXIT trap and is listed as such"
    else fail "$name has no EXIT trap but is not in no_trap_scripts"; fi
  fi
done

# last_line <file>: its last non-blank line.
last_line() { awk 'NF { line = $0 } END { print line }' "$1"; }

for name in $trap_scripts; do
  f=$repo/scripts/$name
  traps=$(grep -Ec '^[[:space:]]*trap .*EXIT$' "$f" || true)
  # shellcheck disable=SC2016 # a pattern for the script's text, not an expansion
  sentinel_traps=$(grep -Ec '^trap .*\[ -n "\$\{completed:-\}" \].*\[ "\$rc" -ne 0 \].*rc=2.*exit "\$rc"'"'"' EXIT$' "$f" || true)
  if [ "$traps" = 1 ] && [ "$sentinel_traps" = 1 ]; then pass "$name: its one EXIT trap fails closed without the sentinel"
  else fail "$name: $traps EXIT trap(s), $sentinel_traps of the fail-closed form"; fi
  sets=$(grep -c 'completed=1' "$f" || true)
  last=$(last_line "$f")
  case $last in
    "completed=1; exit "*)
      if [ "$sets" = 1 ]; then pass "$name: the sentinel is set once, on its last line"
      else fail "$name: the sentinel is set $sets times; only its last line may set it"; fi ;;
    *) fail "$name: its last line is not 'completed=1; exit <status>': $last" ;;
  esac
  if grep -Eq '^completed=""$' "$f"; then pass "$name: the sentinel starts unset"
  else fail "$name: no completed=\"\" line before its trap"; fi
done

# Sourced test helpers with an EXIT trap (F14): the trap fails closed without the sentinel, which
# their finish (each test's last statement) sets.
sourced_helpers="scripts/tests/third-party-notices/lib.sh"
for name in $sourced_helpers; do
  f=$repo/$name
  traps=$(grep -Ec '^[[:space:]]*trap .*EXIT$' "$f" || true)
  # shellcheck disable=SC2016 # a pattern for the script's text, not an expansion
  sentinel_traps=$(grep -Ec '^trap .*\[ -n "\$\{completed:-\}" \].*\[ "\$rc" -ne 0 \].*rc=2.*exit "\$rc"'"'"' EXIT$' "$f" || true)
  if [ "$traps" = 1 ] && [ "$sentinel_traps" = 1 ] && grep -Eq '^completed=""$' "$f"; then
    pass "$name: its one EXIT trap fails closed without the sentinel, which starts unset"
  else fail "$name: $traps EXIT trap(s), $sentinel_traps of the fail-closed form, or no completed=\"\" line"; fi
  if awk '/^finish\(\) \{$/ { on = 1 } on && /^  completed=1$/ { found = 1 } on && /^\}$/ { on = 0 } END { exit !found }' "$f" \
    && [ "$(grep -c 'completed=1' "$f")" = 1 ]; then pass "$name: finish, and only finish, sets the sentinel"
  else fail "$name: the sentinel is not set by finish alone"; fi
done

# --- Copies with an injected syntax error --------------------------------------------------------------

host=$(rustc -vV | sed -n 's/^host: //p')
[ -n "$host" ] || die "rustc -vV printed no host triple"

# A crate with no dependencies, for third-party-notices.sh.
tiny=$scratch/tiny
mkdir -p "$tiny/src"
printf '%s\n' '[package]' 'name = "f10-tiny"' 'version = "0.0.0"' 'edition = "2021"' 'license = "MIT"' \
  'publish = false' '' '[workspace]' >"$tiny/Cargo.toml"
: >"$tiny/src/lib.rs"
echo "MIT License (test fixture)" >"$tiny/LICENSE"
(cd "$tiny" && cargo generate-lockfile --offline -q) || die "could not lock the fixture crate"

# The reference results file of scripts/tests/conformance-parity/lib.sh, alone: parity holds.
reference='{"runner":"rust-core","polyjose":"0.1.0","vectors_digest":"9a06f1efdd269176088cb0e6bfc6a7e4d4f74aa3d1b1b8fc6c879fdbb82ac7d1","features":[],
"error_codes":["InvalidBase64"],
"results":[{"id":"b64url/encode.json#0","op":"b64url.encode","status":"pass","actual":{"ok":true}}]}'

# copy <path>...: copies files or directories of the repository into $case_dir, at the same paths.
copy() {
  local p
  for p in "$@"; do
    mkdir -p "$case_dir/$(dirname "$p")" || die "could not create the directory of $p"
    cp -R "$repo/$p" "$case_dir/$p" || die "could not copy $p"
  done
}

# setup_<script>: a case tree in $case_dir in which `invoke_<script>` exits 0.
setup_test_all() { copy scripts/test-all.sh; }
invoke_test_all() { "$BASH" scripts/test-all.sh android; }
setup_check_binding_api() {
  copy scripts/check-binding-api.sh scripts/check-binding-api.d bindings/api-inventory.txt crates/polyjose/src/error.rs
}
invoke_check_binding_api() { "$BASH" scripts/check-binding-api.sh surface; }
setup_check_no_cargo_config() {
  copy scripts/check-no-cargo-config.sh
  { git -C "$case_dir" init -q && git -C "$case_dir" add -A; } || die "could not make $case_dir a git work tree"
}
invoke_check_no_cargo_config() { "$BASH" scripts/check-no-cargo-config.sh; }
setup_third_party_notices() { copy scripts/third-party-notices.sh scripts/licenses; cp -R "$tiny" "$case_dir/tiny"; }
invoke_third_party_notices() {
  "$BASH" scripts/third-party-notices.sh -p f10-tiny --target "$host" -o "$case_dir/notices.txt" \
    --manifest-path "$case_dir/tiny/Cargo.toml"
}
setup_conformance_parity() {
  copy scripts/conformance-parity.sh conformance/schema/results.schema.json
  mkdir -p "$case_dir/results" && printf '%s\n' "$reference" >"$case_dir/results/rust-core.json"
}
invoke_conformance_parity() { "$BASH" scripts/conformance-parity.sh results; }
# The test helpers of scripts/tests/test-all/: a probe test that sources them and finishes.
setup_test_all_lib() {
  copy scripts/tests/check-deps/lib.sh scripts/tests/test-all/lib.sh
  # shellcheck disable=SC2016 # the probe's own text
  printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' '. "$(dirname "$0")/lib.sh"' 'echo probe ran' 'finish' \
    >"$case_dir/scripts/tests/test-all/probe.sh"
  { git -C "$case_dir" init -q && git -C "$case_dir" add -A; } || die "could not make $case_dir a git work tree"
}
invoke_test_all_lib() { "$BASH" scripts/tests/test-all/probe.sh; }
# The same for scripts/tests/third-party-notices/lib.sh (feature 0013 F14).
setup_notices_lib() {
  copy scripts/tests/third-party-notices/lib.sh
  # shellcheck disable=SC2016 # the probe's own text
  printf '%s\n' '#!/usr/bin/env bash' 'set -uo pipefail' '. "$(dirname "$0")/lib.sh"' 'echo probe ran' 'finish' \
    >"$case_dir/scripts/tests/third-party-notices/probe.sh"
}
invoke_notices_lib() { "$BASH" scripts/tests/third-party-notices/probe.sh; }

# The injected lines: what bash rejects, after a marker that shows the copy got there.
token_error='echo F10-REACHED
if then'
quote_error="echo F10-REACHED
f10_broken() {
  python3 -c '
# it's here
x = (1)
'
}
f10_broken"

# inject <file in the case> <after|before|append> <ERE anchor> <text>: inserts the text after or
# before the one line matching the anchor, or at the end; dies unless exactly one line matches.
inject() {
  python3 -I -c '
import re, sys
path, where, anchor, text = sys.argv[1:5]
with open(path, encoding="utf-8") as f:
    lines = f.read().splitlines(True)
if where == "append":
    lines.append(text + "\n")
else:
    hits = [i for i, l in enumerate(lines) if re.search(anchor, l)]
    if len(hits) != 1:
        sys.exit("%s: %d lines match %r, expected one" % (path, len(hits), anchor))
    i = hits[0] + (1 if where == "after" else 0)
    lines.insert(i, text + "\n")
with open(path, "w", encoding="utf-8") as f:
    f.write("".join(lines))
' "$case_dir/$1" "$2" "$3" "$4" || die "could not inject into $1"
}

# run_case <name> <setup/invoke suffix>: runs the case tree; sets $rc and leaves output in $out.
run_case() {
  out=$scratch/$1.out
  rc=0
  (cd "$case_dir" && "invoke_$2") </dev/null >"$out" 2>&1 || rc=$?
}

# guard <label> <suffix> <file> <want rc> <where> <anchor> [<where> <anchor>]: the baseline copy
# exits 0; each injected copy (each position, each error) exits <want rc> after the marker, with
# bash's syntax error message.
guard() {
  local label=$1 suffix=$2 file=$3 want=$4 where anchor kind text
  shift 4
  case_dir=$scratch/case-$suffix-baseline
  mkdir -p "$case_dir"; "setup_$suffix"
  run_case "$suffix-baseline" "$suffix"
  if [ "$rc" -eq 0 ]; then pass "$label: the copy without an error exits 0"
  else fail "$label: the copy without an error exited $rc"; sed 's/^/       /' "$out"; fi
  while [ $# -ge 2 ]; do
    where=$1 anchor=$2
    shift 2
    for kind in token quote; do
      if [ "$kind" = token ]; then text=$token_error; else text=$quote_error; fi
      case_dir=$scratch/case-$suffix-$where-$kind
      mkdir -p "$case_dir"; "setup_$suffix"
      inject "$file" "$where" "$anchor" "$text"
      run_case "$suffix-$where-$kind" "$suffix"
      if [ "$rc" -eq "$want" ] && grep -q '^F10-REACHED$' "$out" && grep -Eq 'syntax error|unexpected' "$out"; then
        pass "$label: a syntax error ($kind) $where /$anchor/ exits $want under bash ${BASH_VERSION%%(*}"
      else
        fail "$label: a syntax error ($kind) $where /$anchor/ exited $rc (expected $want after F10-REACHED)"
        sed 's/^/       /' "$out"
      fi
    done
  done
}

trap_anchor='^trap .* EXIT$'
end_anchor='^completed=1; exit '
guard test-all.sh test_all scripts/test-all.sh 2 after "$trap_anchor" before "$end_anchor"
guard check-binding-api.sh check_binding_api scripts/check-binding-api.sh 2 after "$trap_anchor" before "$end_anchor"
guard check-no-cargo-config.sh check_no_cargo_config scripts/check-no-cargo-config.sh 2 after "$trap_anchor" before "$end_anchor"
guard third-party-notices.sh third_party_notices scripts/third-party-notices.sh 2 after "$trap_anchor" before "$end_anchor"
# No trap: bash's own status 2, under bash 3.2 too.
guard conformance-parity.sh conformance_parity scripts/conformance-parity.sh 2 after '^set -euo pipefail$' before '^exec node '
# A mode file is sourced in a subshell: the failed source fails the mode (mode_fail, exit 1).
guard "check-binding-api.d/surface.sh (sourced mode)" check_binding_api scripts/check-binding-api.d/surface.sh 1 \
  after '^MODE_KINDS=' append ''
# The test-all tests source scripts/tests/test-all/lib.sh, which installs the EXIT trap.
guard "scripts/tests/test-all/lib.sh (sourced by its tests)" test_all_lib scripts/tests/test-all/probe.sh 2 \
  after '^echo probe ran$' before '^finish$'
guard "scripts/tests/third-party-notices/lib.sh (sourced by its tests)" notices_lib \
  scripts/tests/third-party-notices/probe.sh 2 after '^echo probe ran$' before '^finish$'

echo "$((tests_run - tests_failed))/$tests_run cases passed"
completed=1; exit "$((tests_failed > 0))"
