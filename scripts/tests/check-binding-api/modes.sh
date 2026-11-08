#!/usr/bin/env bash
# Tests of the mode contract of scripts/check-binding-api.sh (feature 0013 T13): each file
# scripts/check-binding-api.d/<mode>.sh is a mode, found without editing the main script; a mode
# that skips prints `SKIPPED (<mode>: <reason>)` and never counts as passing (pipeline rule 9);
# derive errors, malformed lines and code-order differences fail; unknown modes are usage errors.
# Uses fixture modes, so it needs no node and no cargo. A case that runs every mode keeps only the
# real surface and js modes of the copy, so the mode files binding features add do not change it.
#
# Usage: scripts/tests/check-binding-api/modes.sh (under /bin/bash 3.2 and bash 5).
# The fixture mode bodies below are shell code for a mode file, single-quoted on purpose.
# shellcheck disable=SC2016
set -euo pipefail
export LC_ALL=C
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

# fixture_mode <name> <body>: writes scripts/check-binding-api.d/<name>.sh in the copy.
fixture_mode() {
  printf '%s\n' "$2" >"$case_dir/scripts/check-binding-api.d/$1.sh" || lib_die "could not write mode $1"
}

# A fixture mode that derives the inventory's own operations and codes, so it passes.
echo_mode='MODE_KINDS="op code"
mode_derive() { grep -E "^(op|code) " "$repo/bindings/api-inventory.txt" >"$1"; }'

# The counts are the inventory's operations and the core's codes (lib.sh), so the case does not
# change when the API grows.
n_codes=$(core_codes | awk 'END { print NR }')
new_case new-mode-file
fixture_mode kotlin "$echo_mode"
run_check kotlin
check_last_line "a new mode file is a mode, without editing the main script" 0 \
  "check-binding-api: kotlin: PASS ($(inventory_count op) operations, 0 records, 0 fields, $n_codes codes)"

# only_modes <mode>...: removes every other mode file from the copy. The real tree gains a mode file
# per binding feature, so a case that runs every mode keeps only the real ones it controls.
only_modes() {
  local f m
  for m in "$@"; do
    [ -f "$case_dir/scripts/check-binding-api.d/$m.sh" ] || lib_die "mode $m is not in the copy"
  done
  for f in "$case_dir"/scripts/check-binding-api.d/*.sh; do
    m=${f##*/}
    case " $* " in
      *" ${m%.sh} "*) ;;
      *) rm -f "$f" || lib_die "could not remove $m from the copy" ;;
    esac
  done
}

# all_modes_case <name> [<base>]: a case whose modes are exactly the real surface (passes) and js
# (skips: bindings/js is removed) and the fixtures kotlin (passes) and swift (skips), whatever other
# modes the tree has.
all_modes_case() {
  new_case "$@"
  only_modes surface js
  fixture_mode kotlin "$echo_mode"
  fixture_mode swift 'MODE_KINDS="op"
mode_derive() { skip "swift missing"; }'
  rm -rf "$case_dir/bindings/js"
}
all_modes_lines=('^check-binding-api: kotlin: PASS ' '^check-binding-api: surface: PASS '
  '^SKIPPED \(js: bindings/js/package\.json missing\)$' '^SKIPPED \(swift: swift missing\)$')

all_modes_case all-modes
run_check
check "with no argument every mode runs, and a summary counts skips apart" 0 \
  "${all_modes_lines[@]}" '^check-binding-api: 2 passed, 0 failed, skipped: js swift$'

# Each binding feature adds its mode file to the real tree (0006 wasm.sh, then node, kotlin, swift;
# ADR 0030 §8). The all-modes case must not depend on them: here the tree has gained one that skips
# and one that passes, and the case still runs only its own modes.
cp -R "$base" "$scratch/base-grown" || lib_die "could not copy the base"
printf '%s\n' 'MODE_KINDS="op"' 'mode_derive() { skip "wasm-pack missing"; }' \
  >"$scratch/base-grown/scripts/check-binding-api.d/wasm.sh" || lib_die "could not write wasm.sh"
printf '%s\n' "$echo_mode" >"$scratch/base-grown/scripts/check-binding-api.d/node.sh" \
  || lib_die "could not write node.sh"
all_modes_case all-modes-grown-tree "$scratch/base-grown"
run_check
check "the all-modes case is unchanged by the mode files bindings add to the tree" 0 \
  "${all_modes_lines[@]}" '^check-binding-api: 2 passed, 0 failed, skipped: js swift$'
check_absent "the all-modes case runs none of the tree's other modes" \
  '^(SKIPPED \(|check-binding-api: )(wasm|node):'

# An extra mode file in the case itself is a mode like the others: it runs, a pass counts, and a
# skip is listed in the summary and never counted as passed.
all_modes_case extra-modes
fixture_mode wasm 'MODE_KINDS="op"
mode_derive() { skip "wasm-pack missing"; }'
fixture_mode node "$echo_mode"
run_check
check "an extra passing mode and an extra skipping mode are each reported" 0 \
  "${all_modes_lines[@]}" '^check-binding-api: node: PASS ' '^SKIPPED \(wasm: wasm-pack missing\)$' \
  '^check-binding-api: 3 passed, 0 failed, skipped: js swift wasm$'
check_absent "an extra mode that skips is not reported as passing" '^check-binding-api: wasm: PASS'

new_case skip
fixture_mode swift 'MODE_KINDS="op"
mode_derive() { skip "no Swift toolchain (swift missing)"; }'
run_check swift
check_last_line "a skipped mode prints SKIPPED (<mode>: <reason>) last, with exit 0" 0 \
  'SKIPPED (swift: no Swift toolchain (swift missing))'
check_absent "a skipped mode is not reported as passing" 'PASS'

new_case one-fails
fixture_mode kotlin "$echo_mode"
fixture_mode swift 'MODE_KINDS="op"
mode_derive() { echo "op version" >"$1"; }'
run_check kotlin swift surface
check "one failing mode fails the run; the others still run" 1 \
  '^check-binding-api: kotlin: PASS ' '^check-binding-api: swift: FAIL ' '^check-binding-api: surface: PASS ' \
  '^check-binding-api: 2 passed, 1 failed, skipped: none$'

new_case code-order
fixture_mode kotlin 'MODE_KINDS="op code"
mode_derive() {
  grep -E "^op " "$repo/bindings/api-inventory.txt" >"$1"
  grep -E "^code " "$repo/bindings/api-inventory.txt" | sed -n "2p" >>"$1"
  grep -E "^code " "$repo/bindings/api-inventory.txt" | sed "2d" >>"$1"
}'
run_check kotlin
check "the same codes in another order fail" 1 \
  '^  error codes of kotlin differ from the inventory.s \(same codes, same order\):$' '^check-binding-api: kotlin: FAIL '

new_case expect-filter
fixture_mode js2 'MODE_KINDS="field"
mode_expect() { sed "s/=false\$/?/"; }
# Derives every inventory field as a host would show it: a flag ("= false") as optional.
mode_derive() {
  awk "/^record / { r = \$2 } /^ *field / { print \"field \" r \".\" \$2 (\$3 == \"=\" ? \"?\" : \"\") }" \
    "$repo/bindings/api-inventory.txt" >"$1"
}'
run_check js2
check "mode_expect maps the inventory to the host idiom (flags read as optional)" 0 \
  "^check-binding-api: js2: PASS \\(0 operations, 0 records, $(inventory_count field) fields\\)\$"

new_case error-line
fixture_mode kotlin 'MODE_KINDS="op"
mode_derive() { printf "op version\nerror Polyjose.kt:3: cannot read this member\n" >"$1"; }'
run_check kotlin
check "a derived error line fails the mode with its message" 1 \
  '^check-binding-api: kotlin: Polyjose\.kt:3: cannot read this member$' '^check-binding-api: kotlin: FAIL$'

new_case malformed-line
fixture_mode kotlin 'MODE_KINDS="op"
mode_derive() { echo "op jwk_parse" >"$1"; }'
run_check kotlin
check "a derived line not in the normal form fails" 1 'derived lines not in the normal form: op jwk_parse' 'kotlin: FAIL$'

new_case derive-fails
fixture_mode kotlin 'MODE_KINDS="op"
mode_derive() { false; }'
run_check kotlin
check "a mode_derive that returns non-zero fails" 1 '^check-binding-api: kotlin: mode_derive failed$'

new_case no-kinds
fixture_mode kotlin 'mode_derive() { : >"$1"; }'
run_check kotlin
check "a mode without MODE_KINDS fails" 1 'sets no MODE_KINDS'

new_case no-derive
fixture_mode kotlin 'MODE_KINDS="op"'
run_check kotlin
check "a mode without mode_derive fails" 1 'defines no mode_derive'

new_case unknown-mode
run_check python
check "an unknown mode is a usage error" 2 '^check-binding-api: unknown mode: python '

new_case bad-mode-name
run_check ../surface
check "a mode name with a path is a usage error" 2 '^check-binding-api: bad mode name: \.\./surface$'

finish
