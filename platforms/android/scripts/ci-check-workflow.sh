#!/usr/bin/env bash
# Local check of .github/workflows/binding-android.yml (feature 0008 T05; owner decision
# 2026-11-07; ADR 0044, ADR 0037 §1). actionlint is not used: this is a line-based check of the
# subset of YAML the workflow is written in, and it fails closed on anything outside that subset.
#
#   platforms/android/scripts/ci-check-workflow.sh [<workflow>]     (default: binding-android.yml)
#
# The rules (comments are ignored, except the pin comments of `uses:` lines):
#   trigger      exactly one top-level `on:` key, in block form, whose only child is
#                `workflow_dispatch` (no pull_request, push, schedule, workflow_call or other).
#   permissions  a top-level `permissions:` of exactly `contents: read`; every other
#                `permissions:` is `{}` or `contents: read`; nothing anywhere grants `write`,
#                `write-all` or `read-all`.
#   actions      every `uses:` is `<owner>/<repo>@<40-hex commit> # v<version>` and that exact
#                action, SHA and version is one of ci.yml's own pins (the same SHAs) or one of the
#                three first-party pins below; no local, docker or unpinned action.
#   credentials  no `secrets` context or `secrets:` key, no token (github.token, GITHUB_TOKEN, a
#                `token`/`github-token` input), no deployment `environment:`, no password,
#                username or credential, no Maven Central, Sonatype, OSSRH, Nexus or Central
#                Portal name, no ORG_GRADLE_PROJECT_ property.
#   publishing   no `publish` and no signing (`sign`, `signing`, gpg, `.asc`).
#   expressions  every `${{ }}` reads only the inputs, github, matrix, steps, needs, runner, job
#                and strategy contexts and status or string functions (no vars, env or secrets),
#                and no `${{ }}` appears inside a `run:` script (values reach scripts through env:,
#                so an input cannot inject shell code).
#   structure    no YAML anchors, aliases or merge keys, no second document, no tab indentation,
#                no flow-style `uses:`.
#   scripts      the steps call each of ci-host-natives.sh, ci-android-sdk.sh, ci-emulator.sh,
#                ci-assemble-jar.sh and ci-parity.sh, and every platforms/android/scripts/ci-*.sh
#                the workflow names exists and is executable.
#
# Its negative tests are ci-check-workflow-test.sh (mutated copies of the workflow in a temp dir).
# Exit status: 0 every rule holds; 1 a rule is broken (each one printed as FAIL); 2 usage.
set -uo pipefail
# shellcheck source=ci-lib.sh source-path=SCRIPTDIR
. "$(dirname "$0")/ci-lib.sh"
export LC_ALL=C

[ $# -le 1 ] || { echo "usage: ${0##*/} [<workflow>]" >&2; exit 2; }
wf=${1:-$ci_repo/.github/workflows/binding-android.yml}
[ -f "$wf" ] || ci_die "no workflow file $wf"
ci=$ci_repo/.github/workflows/ci.yml
[ -f "$ci" ] || ci_die "no $ci (the source of the allowed action pins)"

# The first-party actions this workflow adds to ci.yml's (resolved 2026-11-07 with
# `gh api repos/actions/<repo>/commits/<tag>` and `git ls-remote`, both giving the same commit).
extra_pins="actions/setup-java@b843ebf9b913146b38da2eaa7aeddf76074ae1ad # v6.1.0
actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2
actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8.0.2"

failures=0
fail() { echo "FAIL: $*"; failures=$((failures + 1)); }

# --- actions -----------------------------------------------------------------------------------
pin_re='^[[:space:]]*(-[[:space:]]+)?uses:[[:space:]]+([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}[[:space:]]+#[[:space:]]+v[0-9][0-9A-Za-z.+-]*)[[:space:]]*$'
pin_of() { sed -E "s|$pin_re|\\2|" | sed -E 's/[[:space:]]+#[[:space:]]+/ # /'; }
pins_of() { grep -E "$pin_re" "$1" | pin_of; }
allowed=$( { pins_of "$ci"; printf '%s\n' "$extra_pins"; } | sort -u)
# Every uses key, also a quoted one ("uses" or 'uses'), which pin_re then rejects.
uses=$(grep -nE "^[[:space:]]*(-[[:space:]]+)?(uses|\"uses\"|'uses')[[:space:]]*:" "$wf")
if [ -z "$uses" ]; then fail "actions: no uses: line"; fi
while IFS= read -r line; do
  [ -n "$line" ] || continue
  n=${line%%:*}; text=${line#*:}
  if ! printf '%s\n' "$text" | grep -Eq "$pin_re"; then
    fail "actions: line $n: not <owner>/<repo>@<40-hex commit> # v<version>: ${text#"${text%%[![:space:]]*}"}"
    continue
  fi
  pin=$(printf '%s\n' "$text" | pin_of)
  printf '%s\n' "$allowed" | grep -qxF "$pin" || fail "actions: line $n: $pin is not one of the allowed pins (ci.yml's and the three first-party ones)"
done <<<"$uses"

# --- everything else: one pass over the file ---------------------------------------------------
problems=$(awk '
function fail(msg) { printf "FAIL: %s: line %d: %s\n", msg, NR, raw }
# The line without its comment: a # at the start or after a blank, outside quotes.
function strip(s,   i, c, q, out, prev) {
  q = ""; out = ""; prev = " "
  for (i = 1; i <= length(s); i++) {
    c = substr(s, i, 1)
    if (q == "") {
      if (c == "#" && (prev == " " || prev == "\t")) break
      if (c == "\"" || c == "\047") q = c
    } else if (c == q) q = ""
    out = out c; prev = c
  }
  sub(/[ \t]+$/, "", out)
  return out
}
function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }
function flat(s) { gsub(/[ \t]/, "", s); return s }
# The context names and functions an expression may use.
function allowed_word(w) {
  return (w ~ /^(inputs|github|matrix|steps|needs|runner|job|strategy)$/ ||
          w ~ /^(always|cancelled|success|failure|contains|startsWith|endsWith|format|join|toJSON|fromJSON)$/ ||
          w ~ /^(true|false|null)$/)
}
function check_expressions(s,   i, j, rest, e, k, c, q, w, prev) {
  while ((i = index(s, "${{")) > 0) {
    rest = substr(s, i + 3); j = index(rest, "}}")
    if (j == 0) { fail("expressions: unterminated ${{"); return }
    e = substr(rest, 1, j - 1); s = substr(rest, j + 2)
    q = 0; prev = ""
    for (k = 1; k <= length(e); k++) {
      c = substr(e, k, 1)
      if (q) { if (c == "\047") q = 0; continue }
      if (c == "\047") { q = 1; continue }
      if (c ~ /[A-Za-z_]/) {
        w = c
        while (k < length(e) && substr(e, k + 1, 1) ~ /[A-Za-z0-9_-]/) { k++; w = w substr(e, k, 1) }
        if (prev != "." && !allowed_word(w)) fail("expressions: ${{ }} uses \"" w "\" (only inputs, github, matrix, steps, needs, runner, job, strategy)")
        prev = "w"; continue
      }
      if (c != " ") prev = c
    }
  }
}
# Key syntax outside the subset, which the line-based rules (the uses: scan, parse_key) would not
# read as the key it is: a quoted key (YAML 1.2.2 §7.3.2, §7.3.3: `"uses":`, `'uses':`, also one
# with escapes such as `"u\x73es":`), an explicit key (§6.9 / §8.2.2: `? uses`) and a tag
# (§6.8.1: `!!str uses:`). Each is looked for at the start of a node: after the indent and any
# "- " markers, after a flow `{`, `[` or `,`, and after a `: `. A quote in the middle of a plain
# scalar is plain text, and ${{ }} expressions are skipped. Returns "" or what was found.
function key_syntax(s,   i, j, n, c, nx, q, qkey, start, t) {
  t = ""
  while ((i = index(s, "${{")) > 0 && (j = index(substr(s, i), "}}")) > 0) {
    t = t substr(s, 1, i - 1) "E"; s = substr(s, i + j + 1)
  }
  s = t s; n = length(s); q = ""; qkey = 0; start = 1
  for (i = 1; i <= n; i++) {
    c = substr(s, i, 1)
    if (q != "") {
      if (q == "\"" && c == "\\") { i++; continue }
      if (c != q) continue
      if (q == "\047" && substr(s, i + 1, 1) == "\047") { i++; continue }
      q = ""
      if (qkey) {
        for (j = i + 1; substr(s, j, 1) == " "; j++) ;
        if (substr(s, j, 1) == ":") return "a quoted key"
      }
      continue
    }
    if (c == " ") continue
    nx = substr(s, i + 1, 1)
    if (start) {
      start = 0
      if (c == "-" && (nx == " " || nx == "")) { start = 1; continue }
      if (c == "\"" || c == "\047") { q = c; qkey = 1; continue }
      if (c == "?" && (nx == " " || nx == "")) return "an explicit ? key"
      if (c == "!") return "a YAML tag"
    }
    if (c == "{" || c == "[" || c == ",") start = 1
    else if (c == ":" && (nx == " " || nx == "")) start = 1
  }
  return ""
}
# A key line: indent, an optional "- ", the key, a colon, the value.
function parse_key(s,   m, rest) {
  key = ""; value = ""; keycol = -1
  if (!match(s, /^ *(- +)?/)) return 0
  keycol = RLENGTH; rest = substr(s, RLENGTH + 1)
  if (!match(rest, /^("[^"]*"|\047[^\047]*\047|[A-Za-z_][A-Za-z0-9_.-]*)[ ]*:([ ]|$)/)) return 0
  key = substr(rest, 1, RLENGTH); sub(/[ ]*:[ ]?$/, "", key); sub(/[ ]*:[ ]$/, "", key); sub(/:$/, "", key)
  key = trim(key); gsub(/^["\047]|["\047]$/, "", key)
  value = trim(substr(rest, RLENGTH + 1))
  return 1
}
function end_permissions() {
  if (perm_open) {
    if (perm_children == 0) fail("permissions: empty permissions block")
    if (perm_top && perm_children > 0 && perm_ok) top_perm_ok = 1
  }
  perm_open = 0
}
BEGIN { on_count = 0; in_on = 0; on_child = -1; perm_open = 0; top_perm = 0; top_perm_ok = 0; run_open = 0 }
{
  raw = $0
  if (raw ~ /^\t/ || raw ~ /^ *\t/) fail("structure: tab indentation")
  code = strip(raw)
  if (code ~ /^[ ]*$/) next
  if (code ~ /^(---|\.\.\.)/ && NR > 1) fail("structure: a second YAML document")
  match(code, /^ */); indent = RLENGTH
  low = tolower(code)

  # Words that must not appear (outside comments). `persist-credentials: false` is the checkout
  # option that does not keep the token, the one allowed mention.
  w = low; gsub(/persist-credentials:[ ]*false/, "", w)
  if (w ~ /(^|[^a-z0-9_])secrets([^a-z0-9_]|$)/) fail("credentials: secrets")
  if (w ~ /token/) fail("credentials: a token")
  if (w ~ /password|username|credential/) fail("credentials: password, username or credential")
  if (w ~ /sonatype|ossrh|mavencentral|maven-central|maven_central|central[-_ ]?portal|nexus/) fail("credentials: Maven Central / Sonatype / Nexus")
  if (w ~ /org_gradle_project_/) fail("credentials: an ORG_GRADLE_PROJECT_ property")
  if (w ~ /^[ ]*(-[ ]+)?environment[ ]*:/) fail("credentials: a deployment environment")
  if (w ~ /publish/) fail("publishing: publish")
  if (w ~ /signing|(^|[^a-z])sign([^a-z]|$)|gpg|\.asc([^a-z]|$)/) fail("publishing: signing")
  if (w ~ /:[ ]*write([ ]|$|,|})|write-all|read-all/) fail("permissions: a write or read-all grant")
  check_expressions(code)

  # Inside a run: script (a block scalar): shell, not YAML; ${{ }} is forbidden.
  if (run_open && indent > run_col) {
    if (index(code, "${{")) fail("expressions: ${{ }} inside a run: script (pass it through env:)")
    next
  }
  run_open = 0
  if (code ~ /(^|[ {,[])[&*][A-Za-z0-9_]/ || code ~ /<<[ ]*:/) fail("structure: YAML anchor, alias or merge key")
  if (low ~ /[{,][ ]*["\047]?uses["\047]?[ ]*:/) fail("structure: flow-style uses:")
  if ((found = key_syntax(code)) != "") fail("structure: " found " (outside the subset)")

  # A permissions block in progress: its children.
  if (perm_open) {
    if (indent > perm_col) {
      perm_children++
      if (flat(code) != "contents:read") { perm_ok = 0; fail("permissions: only contents: read is allowed") }
      next
    }
    end_permissions()
  }

  if (!parse_key(code)) {
    if (in_on && indent > 0) fail("trigger: not a key under on:")
    next
  }

  # Top-level keys.
  if (indent == 0 && keycol == 0) {
    in_on = 0
    if (key == "on" || key == "true") {
      on_count++; in_on = 1
      if (value != "") fail("trigger: on: must be a block of keys, not a value")
    }
    if (key == "permissions") {
      top_perm++
      if (value == "") { perm_open = 1; perm_top = 1; perm_col = 0; perm_children = 0; perm_ok = 1 }
      else if (flat(value) == "{contents:read}") top_perm_ok = 1
      else fail("permissions: the top-level permissions must be contents: read")
    }
    next
  }

  if (in_on) {
    if (on_child < 0) on_child = indent
    if (indent == on_child) {
      if (keycol != indent) fail("trigger: a list under on:")
      triggers = triggers " " key
    }
    if (indent < on_child) fail("trigger: inconsistent indentation under on:")
  }

  if (key == "permissions") {
    if (value == "") { perm_open = 1; perm_top = 0; perm_col = keycol; perm_children = 0; perm_ok = 1 }
    else if (flat(value) != "{}" && flat(value) != "{contents:read}") fail("permissions: only {} or contents: read is allowed")
  }
  if (key == "run") {
    if (value ~ /^[|>]/) { run_open = 1; run_col = keycol }
    else if (index(value, "${{")) fail("expressions: ${{ }} inside a run: script (pass it through env:)")
  }
}
END {
  NR = 0; raw = "(end of file)"
  end_permissions()
  if (on_count != 1) fail("trigger: " on_count " top-level on: keys (exactly one is required)")
  t = triggers; sub(/^ /, "", t)
  if (on_count == 1 && t != "workflow_dispatch") fail("trigger: the triggers are \"" t "\", not exactly workflow_dispatch")
  if (top_perm != 1 || !top_perm_ok) fail("permissions: no top-level permissions of exactly contents: read")
}
' "$wf")
if [ -n "$problems" ]; then
  printf '%s\n' "$problems"
  failures=$((failures + $(printf '%s\n' "$problems" | wc -l)))
fi

# --- scripts -----------------------------------------------------------------------------------
named=$(grep -v '^[[:space:]]*#' "$wf" | grep -oE 'platforms/android/scripts/ci-[A-Za-z0-9_-]+\.sh' | sort -u)
for s in ci-host-natives.sh ci-android-sdk.sh ci-emulator.sh ci-assemble-jar.sh ci-parity.sh; do
  printf '%s\n' "$named" | grep -qx "platforms/android/scripts/$s" || fail "scripts: no step calls platforms/android/scripts/$s"
done
for s in $named; do
  [ -f "$ci_repo/$s" ] && [ ! -L "$ci_repo/$s" ] && [ -x "$ci_repo/$s" ] || fail "scripts: $s is not an executable regular file"
done

if [ "$failures" -eq 0 ]; then
  echo "ci-check-workflow: ${wf#"$ci_repo/"}: OK (workflow_dispatch only, contents: read, $(printf '%s\n' "$uses" | wc -l | tr -d ' ') pinned uses:, no credentials, publishing or signing)"
  exit 0
fi
echo "ci-check-workflow: ${wf#"$ci_repo/"}: $failures problem(s)"
exit 1
