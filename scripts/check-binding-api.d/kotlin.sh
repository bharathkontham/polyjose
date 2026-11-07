# shellcheck shell=bash
# shellcheck disable=SC2034,SC2154 # sourced by scripts/check-binding-api.sh, which reads MODE_KINDS
# and sets repo, mode_scratch and camel_awk
# Mode "kotlin" of scripts/check-binding-api.sh: the UniFFI-generated Kotlin of the Android and JVM
# artifacts (package dev.polyjose, ADR 0033 §1), shared unchanged by :polyjose and :polyjose-jvm.
# Nothing generated is committed, so this mode generates it the way platforms/android's
# `uniffiGenerate` task does, into its scratch directory (platforms/android/build is left alone):
#   1. cargo build --release --lib -p polyjose-ffi (the host cdylib, under $CARGO_TARGET_DIR or
#      target/);
#   2. cargo run -p polyjose-uniffi-bindgen -- generate <that library> --language kotlin
#      --no-format (library mode, UniFFI 0.32).
# Without cargo, or without the bindings/ffi and bindings/uniffi-bindgen packages, the mode is
# SKIPPED, never passed. CHECK_BINDING_API_KOTLIN_SOURCE=<file> parses that generated file
# instead (no cargo needed); the mode then says so in a derived-source line on stderr.
#
# It then reads dev/polyjose/polyjose_ffi.kt as text. The generator writes it unformatted
# (--no-format), so declarations are found by brace depth, with comments, string literals and
# character literals removed first, rather than by indentation:
#   - operations: every public top-level `fun` (depth 0, not private or internal);
#   - records: every public top-level `data class`, with the `var`/`val` parameters of its
#     constructor as fields: `T? = null` is optional (`name?`), `kotlin.Boolean = false` a flag
#     (`name = false`), no default required; any other default fails the mode. Any other public
#     top-level type (`class`, `object`, `interface`, `enum class`, `typealias`, ...) is reported
#     as a record, so it cannot slip past the inventory;
#   - codes: the subclasses of `sealed class PolyjoseException`, in order (one per code, ADR 0030
#     §5), which must also declare `fun code()` (the exported accessor, ADR 0033 §3).
#
# KOTLIN_RUNTIME lists the public names of UniFFI's Kotlin runtime that are not polyjose API:
# names starting with FfiConverter, Uniffi or uniffi (converters, call-status handlers,
# uniffiEnsureInitialized), and these. PolyjoseException is the host's error type (ADR 0030 §5),
# checked through its codes. Adding a name here is a review decision, like an inventory change.

MODE_KINDS="op record field code"
KOTLIN_RUNTIME="RustBuffer InternalException Disposable NoHandle use PolyjoseException"

mode_derive() {
  local out=$1 source=${CHECK_BINDING_API_KOTLIN_SOURCE:-} lib target
  if [ -n "$source" ]; then
    [ -f "$source" ] || mode_fail "CHECK_BINDING_API_KOTLIN_SOURCE=$source is not a file"
    echo "check-binding-api: kotlin: parsing $source (CHECK_BINDING_API_KOTLIN_SOURCE)" >&2
  else
    command -v cargo >/dev/null 2>&1 || skip "cargo missing (the Kotlin is generated from the polyjose-ffi library)"
    [ -f "$repo/bindings/ffi/Cargo.toml" ] || skip "bindings/ffi missing"
    [ -f "$repo/bindings/uniffi-bindgen/Cargo.toml" ] || skip "bindings/uniffi-bindgen missing"
    case $(uname -s) in
      Darwin) lib=libpolyjose_ffi.dylib ;;
      MINGW* | MSYS* | CYGWIN*) lib=polyjose_ffi.dll ;;
      *) lib=libpolyjose_ffi.so ;;
    esac
    target=${CARGO_TARGET_DIR:-target}
    case $target in /*) ;; *) target=$repo/$target ;; esac
    (cd "$repo" && cargo build --release --lib -p polyjose-ffi) >"$mode_scratch/cargo.log" 2>&1 \
      || { cat "$mode_scratch/cargo.log"; mode_fail "cargo build --release --lib -p polyjose-ffi failed"; }
    [ -f "$target/release/$lib" ] || mode_fail "cargo built no $target/release/$lib"
    (cd "$repo" && cargo run -q -p polyjose-uniffi-bindgen -- generate "$target/release/$lib" \
      --language kotlin --no-format --out-dir "$mode_scratch/kotlin") >"$mode_scratch/bindgen.log" 2>&1 \
      || { cat "$mode_scratch/bindgen.log"; mode_fail "polyjose-uniffi-bindgen generate --language kotlin failed"; }
    source=$mode_scratch/kotlin/dev/polyjose/polyjose_ffi.kt
    [ -f "$source" ] || mode_fail "the generator wrote no dev/polyjose/polyjose_ffi.kt"
  fi
  cat >"$mode_scratch/kotlin.awk" <<'AWK'
BEGIN { n = split(runtime, t, " "); for (i = 1; i <= n; i++) other[t[i]] = 1 }
function where() { f = FILENAME; sub(/.*\//, "", f); return f ":" FNR }
# The line without comments and with string and character literals emptied, so the braces and
# parentheses left are code. Block comments and strings may span lines (incomment, instr).
function clean(s,    out, i, c, nx, n, j) {
  out = ""; n = length(s)
  for (i = 1; i <= n; i++) {
    c = substr(s, i, 1); nx = substr(s, i + 1, 1)
    if (incomment) { if (c == "*" && nx == "/") { incomment = 0; i++ } continue }
    if (instr) { if (c == "\\") { i++; continue } if (c == "\"") { instr = 0; out = out "\"" } continue }
    if (c == "/" && nx == "*") { incomment = 1; i++; continue }
    if (c == "/" && nx == "/") break
    if (c == "\"") { if (substr(s, i, 3) == "\"\"\"") { raw = 1 } instr = 1; out = out "\""; continue }
    if (c == "'") { j = index(substr(s, i + 1), "'"); if (j > 0) { out = out "''"; i += j; continue } }
    out = out c
  }
  return out
}
function name_after(s, kw,    r) {
  r = s; sub("^.*(^|[^A-Za-z0-9_])" kw "[ \t]+", "", r)
  if (r ~ /^`/) { sub(/^`/, "", r); sub(/`.*/, "", r) } else sub(/[^A-Za-z0-9_].*/, "", r)
  return r
}
function runtime_name(nm) { return (nm in other) || nm ~ /^(FfiConverter|Uniffi|uniffi)/ }
function count_braces(    o, c) {
  o = gsub(/\{/, "{", line); c = gsub(/\}/, "}", line); depth += o - c
  if (in_error && depth <= error_depth && o + c > 0) in_error = 0
}
# One constructor parameter of a data class: `T? = null` optional, `kotlin.Boolean = false` a flag.
function field_line(    field, type, dflt, suffix) {
  field = name_after(line, "(var|val)")
  type = line; sub(/^[^:]*:[ \t]*/, "", type); sub(/[ \t,]*$/, "", type)
  suffix = ""
  if (type ~ /=/) {
    dflt = type; sub(/^[^=]*=[ \t]*/, "", dflt); sub(/[ \t]*=.*$/, "", type)
    if (dflt == "null" && type ~ /\?$/) suffix = "?"
    else if (dflt == "false" && type ~ /^(kotlin\.)?Boolean$/) suffix = "=false"
    else { print "error " where() ": " record "." field " has a default the inventory cannot express: " dflt; return }
  } else if (type ~ /\?$/) {
    print "error " where() ": " record "." field " is nullable without a default"; return
  }
  print "field " record "." field suffix
}
{
  line = clean($0)
  if (raw) { print "error " where() ": a raw string literal (\"\"\"); this parse does not read them"; raw = 0 }
  # The fields of a data class: its constructor's parameter lines, up to the closing parenthesis.
  if (record != "") {
    if (line ~ /^[ \t]*\)/) record = ""
    else if (line ~ /(^|[ \t])(var|val)[ \t]+`?[A-Za-z_]/ && line !~ /(^|[ \t])(private|internal|protected)[ \t]/) field_line()
    count_braces()
    next
  }
  # The subclasses of PolyjoseException (its direct body, one level in), one per code in order.
  if (in_error && depth == error_depth + 1) {
    if (line ~ /(^|[ \t])class[ \t]+[A-Z]/) print "code " name_after(line, "class")
    if (line ~ /(^|[ \t])fun[ \t]+`?code`?[ \t]*\(/) has_code = 1
  }
  if (depth == 0 && line !~ /(^|[ \t])(private|internal)[ \t]/ && line !~ /^[ \t]*(package|import)[ \t]/) {
    if (line ~ /(^|[ \t)])fun[ \t]/) {
      nm = line; sub(/^.*(^|[ \t)])fun[ \t]+(<[^>]*>[ \t]*)?/, "", nm)
      if (nm ~ /^[A-Za-z_][A-Za-z0-9_<>?, ]*\./) { sub(/^[^.]*\./, "", nm) } # an extension receiver
      if (nm ~ /^`/) { sub(/^`/, "", nm); sub(/`.*/, "", nm) } else sub(/[^A-Za-z0-9_].*/, "", nm)
      if (!runtime_name(nm)) print "op " nm
      ops++
    } else if (line ~ /(^|[ \t])data[ \t]+class[ \t]/) {
      nm = name_after(line, "class")
      if (!runtime_name(nm)) { print "record " nm; record = nm }
    } else if (line ~ /(^|[ \t])(class|object|interface|typealias)[ \t]/) {
      nm = line
      if (match(line, /(^|[ \t])(class|object|interface|typealias)[ \t]+`?[A-Za-z_][A-Za-z0-9_]*/)) {
        nm = substr(line, RSTART, RLENGTH); sub(/^.*[ \t]`?/, "", nm)
      }
      if (nm == "PolyjoseException" && line ~ /sealed[ \t]+class/) { in_error = 1; error_depth = depth; found_error = 1 }
      if (!runtime_name(nm)) print "record " nm
    } else if (line ~ /(^|[ \t])(val|var)[ \t]/) {
      print "error " where() ": a public top-level property: " $0
    }
  }
  count_braces()
}
END {
  if (!found_error) print "error no sealed class PolyjoseException (ADR 0030 §5)"
  else if (!has_code) print "error PolyjoseException declares no fun code() (ADR 0033 §3)"
  if (depth != 0) print "error unbalanced braces at the end of the file (has the generator's layout changed?)"
  if (!ops) print "error no top-level fun found (has the generator's layout changed?)"
}
AWK
  awk -v runtime="$KOTLIN_RUNTIME" -f "$mode_scratch/kotlin.awk" "$source" >"$out" || return 1
}
