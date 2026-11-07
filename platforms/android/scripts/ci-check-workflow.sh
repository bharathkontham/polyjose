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
#   with:        each step's `with:` is a block whose keys are on its action's allow-list
#                (with_allow below): actions/checkout takes only `persist-credentials: false`,
#                which every checkout must have, and a numeric `fetch-depth` (no repository, ref,
#                path, ssh-key or token: the steps would run another tree's scripts); the other
#                actions take only the inputs this workflow uses; an action not listed takes none.
#   shell        every `shell:`, also `defaults.run.shell`, is exactly `bash`.
#   guards       no `continue-on-error` anywhere (a failing step or job fails the run), and no
#                `container:` or `services:` (an image would run the steps).
#   downloads    no curl or wget output run as code in a run: script: piped into a shell or an
#                interpreter (also through sudo, env, a path, a subshell, $VAR, source or
#                tee >(sh)), or feeding a shell, eval or source through <( ), $( ) or backticks.
#                Each logical line is checked (joined at a trailing \ or |, folded as YAML folds
#                a > block or a plain scalar). A download to a file passes.
#   credentials  no `secrets` context or `secrets:` key, no token (github.token, GITHUB_TOKEN, a
#                `token`/`github-token` input), no deployment `environment:`, no password,
#                username or credential, no Maven Central, Sonatype, OSSRH, Nexus or Central
#                Portal name, no ORG_GRADLE_PROJECT_ property.
#   publishing   no `publish` and no signing (`sign`, `signing`, gpg, `.asc`).
#   expressions  every `${{ }}` reads only the inputs, github, matrix, steps, needs, runner, job
#                and strategy contexts and status or string functions (no vars, env or secrets),
#                the github context only as github.<property> (never whole, as in toJSON(github),
#                indexed or as github.*, since it holds the token), and no `${{ }}` appears inside
#                a `run:` script (values reach scripts through env:, so an input cannot inject
#                shell code).
#   structure    no YAML anchors, aliases or merge keys, no second document, no tab indentation,
#                no flow-style `uses:`, and only plain keys: no quoted ("uses": / 'uses':),
#                explicit (? uses) or tagged (!!str uses:) key; a quoted uses key also fails the
#                actions rule. No flow-style `with:` or `run:`, and no second `uses:` or `with:`
#                in one step. Keys are matched in lower case, so `Uses:` or `RUN:` meet the same
#                rules, and a case variant of a workflow keyword (on, permissions, uses, with,
#                run, shell, defaults, secrets, container, services, continue-on-error,
#                environment) fails; an env: name equal to one of them in another case (SHELL:)
#                fails too, so rename it.
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
# Every uses key, also a quoted one ("uses" or 'uses') or one in another case (Uses, USES), which
# pin_re (lower case only) then rejects.
uses=$(grep -inE "^[[:space:]]*(-[[:space:]]+)?(uses|\"uses\"|'uses')[[:space:]]*:" "$wf")
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
# A key `name` in block form (after the indent and any "- ") or in flow form (after { or ,).
function has_key(s, name) { return s ~ ("(^[ ]*(-[ ]+)*|[{,][ ]*)" name "[ ]*:([ ,}]|[]]|$)") }
function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }
function flat(s) { gsub(/[ \t]/, "", s); return s }
# The context names and functions an expression may use.
function allowed_word(w) {
  return (w ~ /^(inputs|github|matrix|steps|needs|runner|job|strategy)$/ ||
          w ~ /^(always|cancelled|success|failure|contains|startsWith|endsWith|format|join|toJSON|fromJSON)$/ ||
          w ~ /^(true|false|null)$/)
}
function check_expressions(s,   i, j, rest, e, k, c, q, w, prev, m) {
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
        # The github context holds github.token, so it is read only as github.<property>: not
        # whole (${{ github }}, toJSON(github)), not by index (github[...], also a computed
        # github[format(...)]) and not by the github.* object filter.
        if (prev != "." && w == "github") {
          for (m = k + 1; substr(e, m, 1) == " "; m++) ;
          if (substr(e, m, 1) != "." || substr(e, m + 1, 1) !~ /[A-Za-z_]/) fail("expressions: ${{ }} uses the whole github context (only github.<property>; it holds the token)")
        }
        prev = "w"; continue
      }
      if (c != " ") prev = c
    }
  }
}
# Key syntax outside the subset, which the line-based rules (the uses: scan, parse_key) would not
# read as the key it is: a quoted key (YAML 1.2.2 §7.3.1, §7.3.2: a double- or single-quoted
# uses, also one with escapes such as `"u\x73es":`), an explicit key (§8.2.2: `? uses`) and a
# tag (§6.9.1: `!!str uses:`). Each is looked for at the start of a node: after the indent and any
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
# curl or wget whose output runs as code (security audit L3): a pipe into a shell or interpreter
# (also through sudo, env, a path or flags: `curl -fsSL u | sudo -E bash -`), or a shell, eval or
# source fed by a process or command substitution (`bash <(curl u)`, `sh -c "$(wget -qO- u)"`).
# s is one logical line of a run: script, in lower case. A download to a file passes.
function is_runner(t) {
  gsub(/["\047\\]/, "", t); sub(/.*\//, "", t)
  return t ~ /^(sh|bash|zsh|dash|ksh|mksh|ash|fish|csh|tcsh|pwsh|powershell|python[0-9.]*|perl|ruby|node|php)$/
}
# A pipe segment that runs its input: its command (after assignments, a subshell ( or group {)
# is a shell, interpreter, `.`, source, eval or an expanded $VAR, or a wrapper (sudo, env, ...)
# with one of those among its arguments.
function runs_code(seg,   tok, n, i, t) {
  n = split(seg, tok, " ")
  for (i = 1; i <= n; i++) {
    t = tok[i]; gsub(/["\047]/, "", t); sub(/^[({]+/, "", t)
    if (t == "" || t ~ /^[a-z_][a-z0-9_]*=/) continue
    if (is_runner(t) || t ~ /^(\.|source|eval)$/ || t ~ /^\$/) return 1
    sub(/.*\//, "", t)
    if (t !~ /^(sudo|doas|env|command|exec|nohup|time|nice|stdbuf|xargs|busybox)$/) return 0
    for (i++; i <= n; i++) if (is_runner(tok[i])) return 1
    return 0
  }
  return 0
}
function check_download(s, n, r,   dl, rest, parts, k, i, seg, before, c2, t, m, tok, j) {
  dl = "(^|[^a-z0-9_.-])(curl|wget)([^a-z0-9_.-]|$)"
  if (s !~ dl) return
  match(s, dl); rest = substr(s, RSTART + RLENGTH - 1)
  gsub(/\|\|/, " ", rest); gsub(/\|&/, "|", rest)
  k = split(rest, parts, "|")
  for (i = 2; i <= k; i++) {
    seg = parts[i]; sub(/[;&)].*/, "", seg)
    if (runs_code(seg)) { fail_at(n, r, "downloads: curl or wget piped to a shell (download to a file, check its hash, then run it)"); return }
  }
  # An output process substitution after the download: tee >(sh).
  for (t = rest; (i = index(t, ">(")) > 0; ) {
    t = substr(t, i + 2); seg = t; sub(/[;&|)].*/, "", seg)
    if (runs_code(seg)) { fail_at(n, r, "downloads: curl or wget piped to a shell (download to a file, check its hash, then run it)"); return }
  }
  for (i = 1; i <= length(s); i++) {
    c2 = substr(s, i, 2)
    if (c2 != "<(" && c2 != "$(" && substr(s, i, 1) != "`") continue
    if (substr(s, i) !~ dl) continue
    before = substr(s, 1, i - 1); sub(/.*[;&|]/, "", before)
    m = split(before, tok, " ")
    for (j = 1; j <= m; j++) {
      t = tok[j]; gsub(/["\047]/, "", t)
      if (is_runner(t) || t == "eval" || t == "source" || t == ".") {
        fail_at(n, r, "downloads: curl or wget piped to a shell (download to a file, check its hash, then run it)"); return
      }
    }
  }
}
# A run: script is checked one logical line at a time: lines joined at a trailing \ or | in a
# literal (|) block, and all lines joined in a folded (>) block or a plain or quoted scalar, as
# YAML folds them.
function run_add(s) {
  s = trim(s)
  if (acc == "") { acc_line = NR; acc_raw = raw; acc = s } else acc = acc " " s
  if (run_fold) return
  if (acc ~ /\\$/) { sub(/\\$/, "", acc); return }
  if (acc ~ /(^|[^|])\|$/) return
  run_end()
}
function run_end() { if (acc != "") check_download(acc, acc_line, acc_raw); acc = "" }
function fail_at(n, r, msg) { printf "FAIL: %s: line %d: %s\n", msg, n, r }
# The end of a list item (a step): its with: keys against the allow-list of its action.
function end_item(   i, k, v, list, pcf) {
  if (item_action == "" && item_with) fail_at(with_line, with_raw, "actions: with: without uses: in the same step")
  if (item_action != "") {
    list = (item_action in with_allow) ? with_allow[item_action] : ""
    pcf = 0
    for (i = 1; i <= wk_n; i++) {
      k = wk_key[i]; v = wk_val[i]
      if (index(" " list " ", " " k " ") == 0)
        fail_at(wk_line[i], wk_raw[i], "actions: with: " k " is not allowed for " item_action (list == "" ? " (it takes no with: keys here)" : " (only " list ")"))
      else if (item_action == "actions/checkout" && k == "persist-credentials") {
        if (v == "false") pcf = 1
        else fail_at(wk_line[i], wk_raw[i], "actions: with: persist-credentials must be false for actions/checkout")
      } else if (item_action == "actions/checkout" && k == "fetch-depth" && v !~ /^[0-9]+$/)
        fail_at(wk_line[i], wk_raw[i], "actions: with: fetch-depth must be a number for actions/checkout")
    }
    if (item_action == "actions/checkout" && !pcf)
      fail_at(item_line, item_raw, "actions: actions/checkout without with: persist-credentials: false (it would keep the token)")
  }
  item_open = 0; item_action = ""; item_uses = 0; item_with = 0; wk_n = 0; with_open = 0
}
BEGIN {
  on_count = 0; in_on = 0; on_child = -1; perm_open = 0; top_perm = 0; top_perm_ok = 0; run_open = 0
  item_open = 0; item_action = ""; item_uses = 0; item_with = 0; wk_n = 0; with_open = 0
  run_maybe = 0; run_fold = 0; acc = ""
  # The with: keys each action may take (security audit L3): a checkout only of this repository
  # at the dispatched commit (no repository, ref, path, ssh-key or token), and no other action
  # input than the shipped workflow uses. An action not listed takes none. Add a key here only
  # with a review of what that input can fetch, run or expose.
  with_allow["actions/checkout"] = "persist-credentials fetch-depth"
  with_allow["Swatinem/rust-cache"] = "save-if"
  with_allow["actions/setup-java"] = "distribution java-version"
  with_allow["actions/upload-artifact"] = "name path if-no-files-found"
  with_allow["actions/download-artifact"] = "pattern path merge-multiple"
}
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

  # A run: with no value on its line: a mapping (defaults.run) when a key follows, else a plain
  # scalar script that starts on the next line.
  if (run_maybe) {
    run_maybe = 0
    if (indent > run_col && !parse_key(code)) { run_open = 1; run_fold = 1; acc = "" }
  }
  # Inside a run: script (a block scalar or the rest of a multi-line scalar): shell, not YAML;
  # ${{ }} is forbidden.
  if (run_open && indent > run_col) {
    if (index(code, "${{")) fail("expressions: ${{ }} inside a run: script (pass it through env:)")
    run_add(low)
    next
  }
  if (run_open) run_end()
  run_open = 0
  if (code ~ /(^|[ {,[])[&*][A-Za-z0-9_]/ || code ~ /<<[ ]*:/) fail("structure: YAML anchor, alias or merge key")
  if (low ~ /[{,][ ]*["\047]?uses["\047]?[ ]*:/) fail("structure: flow-style uses:")
  if ((found = key_syntax(code)) != "") fail("structure: " found " (outside the subset)")
  # A guard that may fail without failing its job, and a container or service image that would
  # run the steps, in any position (security audit L3).
  if (has_key(low, "continue-on-error")) fail("continue-on-error: not allowed (a failing step or job must fail the run)")
  if (has_key(low, "container") || has_key(low, "services")) fail("containers: container: or services: (an image would run the steps)")
  if (low ~ /[{,][ ]*shell[ ]*:/) fail("shell: a flow-style shell: (only a block shell: bash)")
  if (low ~ /[{,][ ]*with[ ]*:/) fail("structure: flow-style with:")
  if (low ~ /[{,][ ]*run[ ]*:/) fail("structure: flow-style run:")

  # Steps: a list item ends at the next line indented no deeper than its "-". The keys of its
  # with: block (one indentation level) are collected and checked by end_item.
  if (with_open && indent <= with_col) with_open = 0
  if (item_open && indent <= item_dash) end_item()
  if (!item_open && code ~ /^ *-( |$)/) {
    item_open = 1; item_dash = indent; item_col = -1
    if (match(code, /^ *- +[^ ]/)) item_col = RLENGTH - 1
  }
  if (with_open) {
    if (with_child < 0) with_child = indent
    if (indent == with_child) {
      if (parse_key(code) && keycol == indent) {
        wk_n++; wk_key[wk_n] = tolower(key); wk_val[wk_n] = value; wk_line[wk_n] = NR; wk_raw[wk_n] = raw
      } else fail("actions: not a key under with:")
    } else if (indent < with_child) fail("actions: inconsistent indentation under with:")
  }

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
  # Keys are matched in lower case, so that Uses:, RUN: or Permissions: cannot slip past a rule if
  # the Actions reader matches keys case-insensitively; a case variant of a workflow keyword fails.
  rawkey = key; key = tolower(key)
  if (key != rawkey && key ~ /^(on|true|permissions|uses|with|run|shell|defaults|secrets|container|services|continue-on-error|environment)$/)
    fail("structure: \"" rawkey "\" is a case variant of " key ": (keys are lower case)")

  # The uses: and with: of a step (the keys of the list item itself).
  if (item_open && item_col < 0 && indent > item_dash) item_col = keycol
  if (key == "uses" || key == "with") {
    if (item_open && keycol == item_col) {
      if (key == "uses") {
        if (item_uses++) fail("structure: a second uses: in one step")
        item_action = value; sub(/@.*/, "", item_action); item_line = NR; item_raw = raw
      } else {
        if (item_with++) fail("structure: a second with: in one step")
        with_line = NR; with_raw = raw
        if (value != "") fail("actions: with: must be a block of keys")
        else { with_open = 1; with_col = keycol; with_child = -1 }
      }
    } else if (key == "with") fail("actions: with: outside a step")
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
  # Every shell, also defaults.run.shell (which wraps every step), is plain bash.
  if (key == "shell" && value != "bash") fail("shell: only bash is allowed")
  if (key == "run") {
    run_col = keycol; acc = ""
    if (value ~ /^[|>]/) { run_open = 1; run_fold = (value ~ /^>/) }
    else if (value == "") run_maybe = 1
    else {
      if (index(value, "${{")) fail("expressions: ${{ }} inside a run: script (pass it through env:)")
      run_open = 1; run_fold = 1; acc = tolower(value); acc_line = NR; acc_raw = raw
    }
  }
}
END {
  if (run_open) run_end()
  if (item_open) end_item()
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
