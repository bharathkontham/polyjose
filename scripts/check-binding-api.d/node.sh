# shellcheck shell=bash
# shellcheck disable=SC2034,SC2154 # sourced by scripts/check-binding-api.sh, which reads MODE_KINDS
# and sets repo and mode_scratch
# Mode "node" of scripts/check-binding-api.sh: the @polyjose/node package, bindings/node (feature
# 0007 T03; ADR 0030 §2, §4, §8; ADR 0031 §2; ADR 0047). It reads the declarations the package
# build generates (bindings/node/scripts/build.sh; all git-ignored), as text:
#   1. binding.d.ts, written by `napi build --dts` from the #[napi] items of bindings/node/src/*.rs:
#      operations are the `export declare function <name>(` lines, records the
#      `export interface <Name> {` blocks with their two-space-indented members as fields
#      (`name?:` is optional). napi-rs writes a Rust `Option<bool>` flag as `name?: boolean`, so,
#      as in the js mode, mode_expect reads the inventory's `= false` fields as optional;
#   2. the package's public index.d.ts (tsc output of src/index.ts): the names it exports (the
#      `export declare const` list, `export declare function`, `export { ... } from`) must be the
#      inventory's operations plus the host idiom of NODE_INDEX_IDIOM, and it must re-export the
#      facade's records (`export type * from "./facade/api.js"`; their names are the js mode's,
#      checked on the same bindings/js sources). A difference is reported as an `error` line that
#      names index.d.ts;
#   3. the error codes, in order: the ERROR_CODES tuple of facade/error-codes.d.ts, the copy of the
#      facade the package ships and index.d.ts re-exports (ADR 0030 §5).
# The mode builds nothing (napi build is a full cargo release build). Without node, without the
# package sources or before the package is built, it is SKIPPED with the reason, never passed; so
# it is when a generated file is older than one of its sources (a stale build, which could pass or
# fail on names the sources no longer have). Rebuild with bindings/node/scripts/build.sh.
#
# NODE_BINDING_IDIOM lists binding.d.ts exports that are napi-rs loader metadata, not inventory
# entries; NODE_INDEX_IDIOM the package exports that are host idiom (ADR 0030 §5: the error class
# and the code list). Adding a name to either is a review decision, like an inventory change.

MODE_KINDS="op record field code"
NODE_BINDING_IDIOM="__napiBindingTarget"
NODE_INDEX_IDIOM="PolyjoseError ERROR_CODES"

mode_expect() { sed 's/=false$/?/'; }

# node_stale <generated> <source>...: skips when a source is newer than the generated file.
node_stale() {
  local generated=$1 src
  shift
  for src in "$@"; do
    [ -e "$src" ] || continue # an unmatched glob (bash 3.2 has no nullglob)
    if [ "$src" -nt "$generated" ]; then
      skip "bindings/node/${generated#"$repo"/bindings/node/} is older than ${src#"$repo"/} (stale build: run bindings/node/scripts/build.sh)"
    fi
  done
}

mode_derive() {
  local out=$1 pkg=$repo/bindings/node f
  [ -d "$pkg" ] || skip "bindings/node missing"
  for f in package.json src/index.ts Cargo.toml; do
    [ -f "$pkg/$f" ] || skip "bindings/node/$f missing"
  done
  command -v node >/dev/null 2>&1 || skip "node missing"
  for f in binding.d.ts index.d.ts facade/api.d.ts facade/error-codes.d.ts; do
    [ -f "$pkg/$f" ] || skip "bindings/node/$f missing (not built: run bindings/node/scripts/build.sh)"
  done
  node_stale "$pkg/binding.d.ts" "$pkg"/src/*.rs "$pkg/Cargo.toml" "$pkg/build.rs"
  node_stale "$pkg/index.d.ts" "$pkg"/src/*.ts "$pkg/binding.d.ts" "$pkg/facade/api.d.ts"
  node_stale "$pkg/facade/api.d.ts" "$repo"/bindings/js/src/*.ts
  node_stale "$pkg/facade/error-codes.d.ts" "$repo/crates/polyjose/src/error.rs" \
    "$repo/bindings/js/tools/gen-error-codes.ts"

  # 1. binding.d.ts: operations, records and fields.
  cat >"$mode_scratch/binding.awk" <<'AWK'
BEGIN { n = split(idiom, t, " "); for (i = 1; i <= n; i++) other[t[i]] = 1 }
function at() { return "binding.d.ts:" FNR }
{ sub(/\r$/, "") }
inblock && /^}/ { inblock = 0; next }
inblock {
  if ($0 ~ /^  (readonly )?[A-Za-z_$][A-Za-z0-9_$]*\??:/) {
    name = $0; sub(/^  (readonly )?/, "", name)
    opt = (name ~ /^[A-Za-z0-9_$]*\?/) ? "?" : ""
    sub(/[^A-Za-z0-9_$].*/, "", name)
    print "field " record "." name opt
  } else if ($0 !~ /^  (\/\*\*|\*|\/\/)/ && $0 !~ /^   \*/ && $0 !~ /^[ \t]*$/) {
    print "error " at() ": cannot read this member of " record ": " $0
  }
  next
}
/^export declare function [A-Za-z_$][A-Za-z0-9_$]*[(<]/ {
  name = $0; sub(/^export declare function /, "", name); sub(/[^A-Za-z0-9_$].*/, "", name)
  if (!(name in other)) print "op " name
  ops++
  next
}
/^export declare const [A-Za-z_$][A-Za-z0-9_$]*:/ {
  name = $0; sub(/^export declare const /, "", name); sub(/[^A-Za-z0-9_$].*/, "", name)
  if (!(name in other)) print "error " at() ": export " name " is neither an operation nor napi loader metadata"
  next
}
/^export interface [A-Za-z_$][A-Za-z0-9_$]* \{[ \t]*$/ {
  record = $0; sub(/^export interface /, "", record); sub(/[^A-Za-z0-9_$].*/, "", record)
  print "record " record
  inblock = 1
  next
}
/^export/ { print "error " at() ": unsupported export form: " $0 }
END { if (!ops) print "error binding.d.ts: no export declare function (has the napi-rs layout changed?)" }
AWK
  awk -v idiom="$NODE_BINDING_IDIOM" -f "$mode_scratch/binding.awk" "$pkg/binding.d.ts" >"$out" || return 1

  # 2. index.d.ts: the exported value names, one per line, and whether it re-exports the records.
  cat >"$mode_scratch/index.awk" <<'AWK'
function at() { return "index.d.ts:" FNR }
# names(list): the declarator names of `a: T, b: U, ...`, split at commas outside brackets,
# parentheses, braces, angle brackets (`=>` is not one) and string literals.
function names(s,    i, c, prev, depth, name, expect, quote) {
  depth = 0; expect = 1; name = ""; quote = ""; prev = ""
  for (i = 1; i <= length(s); i++) {
    c = substr(s, i, 1)
    if (expect) {
      if (c ~ /[A-Za-z0-9_$]/) { name = name c; prev = c; continue }
      if (c == " " && name == "") continue
      if (name == "") { print "error " at() ": cannot read the exported names: " $0; return }
      print "value " name; name = ""; expect = 0
    }
    if (quote != "") { if (c == quote && prev != "\\") quote = ""; prev = c; continue }
    if (c == "\"" || c == "'" || c == "`") quote = c
    else if (c == "(" || c == "[" || c == "{" || c == "<") depth++
    else if (c == ")" || c == "]" || c == "}") depth--
    else if (c == ">" && prev != "=") depth--
    else if (c == "," && depth == 0) expect = 1
    prev = c
  }
  if (expect && name != "") print "value " name
}
{ sub(/\r$/, "") }
/^export declare const / {
  s = $0; sub(/^export declare const /, "", s); sub(/;[ \t]*$/, "", s)
  names(s)
  next
}
/^export declare function [A-Za-z_$][A-Za-z0-9_$]*/ {
  name = $0; sub(/^export declare function /, "", name); sub(/[^A-Za-z0-9_$].*/, "", name)
  print "value " name
  next
}
/^export type \* from "\.\/facade\/api\.js";[ \t]*$/ { reexport = 1; next }
/^export \{[^}]*\} from "[^"]*";[ \t]*$/ {
  s = $0; sub(/^export \{/, "", s); sub(/\}.*/, "", s)
  n = split(s, part, ",")
  for (i = 1; i <= n; i++) {
    p = part[i]; gsub(/^[ \t]+|[ \t]+$/, "", p)
    if (p ~ /^type /) continue # a type-only re-export adds no value name
    sub(/^.* as /, "", p)
    if (p != "") print "value " p
  }
  next
}
/^export/ { print "error " at() ": unsupported export form: " $0 }
END { if (!reexport) print "error index.d.ts: does not re-export the facade's records (export type * from \"./facade/api.js\")" }
AWK
  awk -f "$mode_scratch/index.awk" "$pkg/index.d.ts" >"$mode_scratch/index" || return 1
  grep '^error ' "$mode_scratch/index" >>"$out"
  sed -n 's/^value //p' "$mode_scratch/index" | sort >"$mode_scratch/index.values"
  sort "$mode_scratch/index.values" | uniq -d | sed 's/^/error index.d.ts: exports twice: /' >>"$out"
  {
    awk '{ sub(/\r$/, "") } $1 == "op" { print $2 }' "$repo/bindings/api-inventory.txt"
    printf '%s\n' "$NODE_INDEX_IDIOM" | tr ' ' '\n'
  } | sort -u >"$mode_scratch/index.expected"
  sort -u "$mode_scratch/index.values" >"$mode_scratch/index.values.u"
  comm -23 "$mode_scratch/index.expected" "$mode_scratch/index.values.u" \
    | sed 's/^/error index.d.ts: missing export (in the inventory or the host idiom): /' >>"$out"
  comm -13 "$mode_scratch/index.expected" "$mode_scratch/index.values.u" \
    | sed 's/^/error index.d.ts: extra export (not in the inventory): /' >>"$out"

  # 3. The error codes the package ships, in order.
  awk '
    { text = text " " $0 }
    END {
      if (!match(text, /ERROR_CODES: readonly \[[^]]*\]/)) { print "error facade/error-codes.d.ts: no ERROR_CODES tuple"; exit }
      list = substr(text, RSTART, RLENGTH)
      while (match(list, /"[^"]*"/)) { print "code " substr(list, RSTART + 1, RLENGTH - 2); list = substr(list, RSTART + RLENGTH) }
    }
  ' "$pkg/facade/error-codes.d.ts" >>"$out" || return 1
}
