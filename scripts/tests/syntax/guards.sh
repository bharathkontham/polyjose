#!/usr/bin/env bash
# Negative test of the fail-closed rule of the guard scripts (feature 0013 F10; pipeline rule 9).
# macOS /bin/bash 3.2 runs an EXIT trap with $? = 0 after a syntax error, so a script with an EXIT
# trap exited 0 when an edit broke its syntax (bash 5 exits 2). Each scripts/*.sh that installs an
# EXIT trap therefore sets `completed=1` on its last line, and its trap turns an exit without it
# into a non-zero status (keeping a non-zero status the script chose). F11 brought check-deps.sh,
# check-rsa-symbols.sh and check-test-vectors-off.sh under the rule (the last two had no trap; they
# got one with the sentinel, so a trap added later cannot reopen the hole), and with them the test
# scripts and sourced test helpers that install an EXIT trap.
#
# The cases:
#   - the rule, read from the real scripts: each trap script's trap tests the sentinel, and the
#     sentinel is set exactly once, on the last non-blank line; every scripts/*.sh is classified
#     (trap script or script without a trap), and so is every other *.sh below scripts/tests,
#     bindings and platforms that installs an EXIT trap (a test trap script, or a sourced helper
#     whose finish sets the sentinel), so a new script fails until it is;
#   - copies of each guard with a syntax error injected (an unexpected token, and the quote inside
#     a python3 -c string of proposals/F10-bash32-syntax-error-repro.sh) right after the trap and
#     right before the last statement exit 2 after reaching the injected line, under the bash that
#     runs this test; the same copy without the error exits 0. Also for the scripts without a trap
#     (conformance-parity.sh exits 2; a broken check-binding-api.d mode file fails its mode, exit
#     1), for fixed-adapter-unreachable.sh, and for the sourced helpers, both in a probe test that
#     sources one and right after the helper's own trap (bash 3.2 also exits 0 from a sourced
#     file's syntax error under errexit once its trap is set). check-deps.sh,
#     check-test-vectors-off.sh, check-rsa-symbols.sh (--only polyjose-all-features) and
#     fixed-adapter-unreachable.sh run in a copy of the working tree, sharing the checkout's target
#     directory;
#   - bindings/ffi/tests/generated-names.sh and its selftest build and generate the bindings, too
#     slow to repeat for each case: their copies get the syntax errors at early positions only, and
#     the positive control there is the copy with `completed=1; exit 0` injected at the same
#     position, which must exit 0 after reaching it (their own full run is the hand-off check).
#
# Usage: /bin/bash scripts/tests/syntax/guards.sh checks bash 3.2; another bash (a Linux one, or a
# locally built bash 5: <bash5> scripts/tests/syntax/guards.sh) checks that bash.
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

# The scripts/*.sh that install an EXIT trap and follow the rule, and the ones without a trap.
trap_scripts="test-all.sh check-binding-api.sh check-no-cargo-config.sh third-party-notices.sh
  check-deps.sh check-rsa-symbols.sh check-test-vectors-off.sh"
no_trap_scripts="conformance-parity.sh"
# The other scripts with an EXIT trap (paths from the repository root): test scripts that follow the
# rule as the scripts/*.sh do, and sourced test helpers whose finish sets the sentinel (F11, F14).
test_trap_scripts="scripts/tests/syntax/guards.sh scripts/tests/check-test-vectors-off/fixed-adapter-unreachable.sh
  bindings/ffi/tests/generated-names.sh bindings/ffi/tests/generated-names-selftest.sh
  bindings/node/scripts/pack.sh
  bindings/node/scripts/pack-platform.sh
  bindings/node/test/fixtures/glibc/regen.sh
  bindings/node/test/fixtures/pe/regen.sh
  scripts/tests/check-binding-api/node.sh"
sourced_helpers="scripts/tests/check-deps/lib.sh scripts/tests/check-binding-api/lib.sh
  scripts/tests/conformance-parity/lib.sh scripts/tests/test-all/lib.sh scripts/tests/third-party-notices/lib.sh"

# --- The rule, read from the real scripts --------------------------------------------------------------

# listed <word> <list>: the list (words separated by spaces or newlines) has the word.
listed() { case " $(printf '%s' "$2" | tr '\n' ' ') " in *" $1 "*) return 0 ;; esac; return 1; }
has_exit_trap() { grep -Eq '^[[:space:]]*trap .*EXIT$' "$1"; }

for f in "$repo"/scripts/*.sh; do
  [ -e "$f" ] || continue # bash 3.2 has no nullglob by default
  name=${f##*/}
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
# sentinel_sets <file>: the number of lines that set the sentinel as a statement (not inside a quoted pattern
# or a comment of this test, which names it).
sentinel_sets() { grep -Ec '(^|[;&|[:space:]])completed=1([;&|[:space:]]|$)' "$1" || true; }

# Every other script with an EXIT trap is classified (node_modules and build output skipped).
while IFS= read -r f; do
  name=${f#"$repo"/}
  has_exit_trap "$f" || continue
  if listed "$name" "$test_trap_scripts"; then pass "$name installs an EXIT trap and is a test trap script here"
  elif listed "$name" "$sourced_helpers"; then pass "$name installs an EXIT trap and is a sourced helper here"
  else fail "$name installs an EXIT trap but is in neither test_trap_scripts nor sourced_helpers (add the sentinel and list it)"; fi
done < <(for d in scripts/tests bindings platforms; do
  [ -d "$repo/$d" ] || continue
  find "$repo/$d" \( -name node_modules -o -name target -o -name build -o -name .build -o -name .gradle \) -prune \
    -o -type f -name '*.sh' -print
done | sort)

# check_trap_script <label> <file>: one EXIT trap of the fail-closed form, the sentinel starts unset
# and is set once, on the last line.
check_trap_script() {
  local name=$1 f=$2 traps sentinel_traps sets last
  traps=$(grep -Ec '^[[:space:]]*trap .*EXIT$' "$f" || true)
  # shellcheck disable=SC2016 # a pattern for the script's text, not an expansion
  sentinel_traps=$(grep -Ec '^trap .*\[ -n "\$\{completed:-\}" \].*\[ "\$rc" -ne 0 \].*rc=2.*exit "\$rc"'"'"' EXIT$' "$f" || true)
  if [ "$traps" = 1 ] && [ "$sentinel_traps" = 1 ]; then pass "$name: its one EXIT trap fails closed without the sentinel"
  else fail "$name: $traps EXIT trap(s), $sentinel_traps of the fail-closed form"; fi
  sets=$(sentinel_sets "$f")
  last=$(last_line "$f")
  case $last in
    "completed=1; exit "*)
      if [ "$sets" = 1 ]; then pass "$name: the sentinel is set once, on its last line"
      else fail "$name: the sentinel is set $sets times; only its last line may set it"; fi ;;
    *) fail "$name: its last line is not 'completed=1; exit <status>': $last" ;;
  esac
  if grep -Eq '^completed=""$' "$f"; then pass "$name: the sentinel starts unset"
  else fail "$name: no completed=\"\" line before its trap"; fi
}
for name in $trap_scripts; do check_trap_script "$name" "$repo/scripts/$name"; done
for name in $test_trap_scripts; do check_trap_script "$name" "$repo/$name"; done

# Sourced test helpers with an EXIT trap (F11, F14): the trap fails closed without the sentinel,
# which their finish (each test's last statement) sets.
for name in $sourced_helpers; do
  f=$repo/$name
  traps=$(grep -Ec '^[[:space:]]*trap .*EXIT$' "$f" || true)
  # shellcheck disable=SC2016 # a pattern for the script's text, not an expansion
  sentinel_traps=$(grep -Ec '^trap .*\[ -n "\$\{completed:-\}" \].*\[ "\$rc" -ne 0 \].*rc=2.*exit "\$rc"'"'"' EXIT$' "$f" || true)
  if [ "$traps" = 1 ] && [ "$sentinel_traps" = 1 ] && grep -Eq '^completed=""$' "$f"; then
    pass "$name: its one EXIT trap fails closed without the sentinel, which starts unset"
  else fail "$name: $traps EXIT trap(s), $sentinel_traps of the fail-closed form, or no completed=\"\" line"; fi
  if awk '/^finish\(\) \{$/ { on = 1 } on && /^  completed=1$/ { found = 1 } on && /^\}$/ { on = 0 } END { exit !found }' "$f" \
    && [ "$(sentinel_sets "$f")" = 1 ]; then pass "$name: finish, and only finish, sets the sentinel"
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

# tree_copy: the working tree (tracked and untracked files, not ignored ones, so no target/) as a
# git work tree in $case_dir, from one copy made on first use. check-no-cargo-config.sh, which the
# three guards below run first, needs the git work tree.
tree_base=""
tree_copy() {
  if [ -z "$tree_base" ]; then
    tree_base=$scratch/tree-base
    mkdir "$tree_base" || die "could not create $tree_base"
    (cd "$repo" && git ls-files -z --cached --others --exclude-standard) >"$scratch/files.z" \
      || die "git ls-files failed in $repo"
    python3 -I -c '
import os, sys
root, listing = sys.argv[1], sys.argv[2]
with open(listing, "rb") as f:
    names = [n for n in f.read().split(b"\0") if n]
sys.stdout.buffer.write(b"".join(n + b"\0" for n in names if os.path.lexists(os.path.join(root.encode(), n))))
' "$repo" "$scratch/files.z" >"$scratch/present.z" || die "could not list the working tree"
    (cd "$repo" && tar --null -T "$scratch/present.z" -cf -) | (cd "$tree_base" && tar -xf -) \
      || die "could not copy the working tree"
    { git -C "$tree_base" init -q && git -C "$tree_base" add -A; } || die "could not make $tree_base a git work tree"
  fi
  cp -R "$tree_base/." "$case_dir/" || die "could not copy the working tree into $case_dir"
}
# The builds share the checkout's target directory, so registry dependencies are built once; each
# copy's workspace packages have another path, so their artifacts never replace the checkout's.
mkdir -p "$repo/target" || die "could not create $repo/target"
setup_check_deps() { tree_copy; }
invoke_check_deps() { "$BASH" scripts/check-deps.sh; }
setup_check_test_vectors_off() { tree_copy; }
invoke_check_test_vectors_off() { CARGO_TARGET_DIR=$repo/target "$BASH" scripts/check-test-vectors-off.sh; }
setup_check_rsa_symbols() { tree_copy; }
invoke_check_rsa_symbols() {
  "$BASH" scripts/check-rsa-symbols.sh --only polyjose-all-features --target-dir "$repo/target"
}
# fixed-adapter-unreachable.sh sets CARGO_TARGET_DIR to its tree's target/, here a link to the
# checkout's.
setup_fixed_adapter() { tree_copy; ln -s "$repo/target" "$case_dir/target" || die "could not link target/"; }
invoke_fixed_adapter() { "$BASH" scripts/tests/check-test-vectors-off/fixed-adapter-unreachable.sh; }

# probe <dir> [<path>...]: copies <dir>/lib.sh and the paths, and writes <dir>/probe.sh, a test that
# sources the helper under errexit (as their tests do) and finishes; a git work tree.
probe() {
  local dir=$1
  shift
  copy "$dir/lib.sh" "$@"
  # shellcheck disable=SC2016 # the probe's own text
  printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' '. "$(dirname "$0")/lib.sh"' 'echo probe ran' 'finish' \
    >"$case_dir/$dir/probe.sh"
  { git -C "$case_dir" init -q && git -C "$case_dir" add -A; } || die "could not make $case_dir a git work tree"
}
setup_check_deps_lib() { probe scripts/tests/check-deps; }
invoke_check_deps_lib() { "$BASH" scripts/tests/check-deps/probe.sh; }
setup_check_binding_api_lib() {
  probe scripts/tests/check-binding-api scripts/check-binding-api.sh scripts/check-binding-api.d \
    bindings/api-inventory.txt bindings/surface/src crates/polyjose/src/error.rs bindings/js/package.json
}
invoke_check_binding_api_lib() { "$BASH" scripts/tests/check-binding-api/probe.sh; }
setup_parity_lib() { probe scripts/tests/conformance-parity scripts/conformance-parity.sh; }
invoke_parity_lib() { "$BASH" scripts/tests/conformance-parity/probe.sh; }

# The bindings/ffi/tests scripts, for their early positions (guard_early).
setup_generated_names() { copy bindings/ffi/tests/generated-names.sh bindings/api-inventory.txt; }
invoke_generated_names() { "$BASH" bindings/ffi/tests/generated-names.sh; }
setup_generated_names_selftest() {
  copy bindings/ffi/tests/generated-names-selftest.sh bindings/ffi/tests/generated-names.sh bindings/api-inventory.txt
}
invoke_generated_names_selftest() { "$BASH" bindings/ffi/tests/generated-names-selftest.sh; }

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

# guard_early <label> <suffix> <file> <want rc> <where> <anchor> [<where> <anchor>]: for a script
# whose whole run is too slow to repeat for each case. At each position, the copy with the marker
# and `completed=1; exit 0` injected exits 0 after the marker (the position is reached, and the trap
# keeps the 0 of a completed run), and each injected syntax error exits <want rc> after it.
control="echo F10-REACHED"$'\n'"completed=1; exit 0"
guard_early() {
  local label=$1 suffix=$2 file=$3 want=$4 where anchor kind text
  shift 4
  while [ $# -ge 2 ]; do
    where=$1 anchor=$2
    shift 2
    case_dir=$scratch/case-$suffix-$where-control
    mkdir -p "$case_dir"; "setup_$suffix"
    inject "$file" "$where" "$anchor" "$control"
    run_case "$suffix-$where-control" "$suffix"
    if [ "$rc" -eq 0 ] && grep -q '^F10-REACHED$' "$out"; then
      pass "$label: the copy that completes $where /$anchor/ exits 0"
    else fail "$label: the copy that completes $where /$anchor/ exited $rc"; sed 's/^/       /' "$out"; fi
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

# F11: the three guards that F03 and F07 edit, in copies of the working tree.
guard check-deps.sh check_deps scripts/check-deps.sh 2 after "$trap_anchor" before "$end_anchor"
guard check-test-vectors-off.sh check_test_vectors_off scripts/check-test-vectors-off.sh 2 \
  after "$trap_anchor" before "$end_anchor"
guard "check-rsa-symbols.sh (--only polyjose-all-features)" check_rsa_symbols scripts/check-rsa-symbols.sh 2 \
  after "$trap_anchor" before "$end_anchor"
guard fixed-adapter-unreachable.sh fixed_adapter scripts/tests/check-test-vectors-off/fixed-adapter-unreachable.sh 2 \
  after "$trap_anchor" before "$end_anchor"
# The sourced helpers: an error in the test that sources one, and one in the helper itself, after
# its trap.
for helper in check_deps:check-deps check_binding_api:check-binding-api parity:conformance-parity; do
  dir=scripts/tests/${helper#*:}
  guard "$dir/lib.sh (sourced by its tests)" "${helper%%:*}_lib" "$dir/probe.sh" 2 \
    after '^echo probe ran$' before '^finish$'
  guard "$dir/lib.sh (an error in it)" "${helper%%:*}_lib" "$dir/lib.sh" 2 after "$trap_anchor"
done
# shellcheck disable=SC2016 # an ERE for the script's text, not an expansion
guard_early bindings/ffi/tests/generated-names.sh generated_names bindings/ffi/tests/generated-names.sh 2 \
  after "$trap_anchor" before '^cd "\$repo" \|\| exit 2$'
guard_early bindings/ffi/tests/generated-names-selftest.sh generated_names_selftest \
  bindings/ffi/tests/generated-names-selftest.sh 2 after "$trap_anchor" after '^failed=0$'

echo "$((tests_run - tests_failed))/$tests_run cases passed"
completed=1; exit "$((tests_failed > 0))"
