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
# (--no-format), so declarations are found by brace and parenthesis depth (a constructor's
# parameter lines are not top-level declarations), with comments, string literals and character
# literals removed first, rather than by indentation:
#   - operations: every public top-level `fun` (depth 0, not private or internal);
#   - interfaces: every public top-level `interface` that is not UniFFI's own, with the `fun`s of
#     its body as methods (ADR 0071 §5: a foreign interface host code implements). The
#     `open class <Name>Impl` UniFFI generates beside each such interface, the wrapper of a
#     Rust-side implementation that polyjose never returns, belongs to the interface and is not
#     reported;
#   - enums: every `sealed class <Name>Exception` but PolyjoseException, reported under its Rust and
#     Swift name `<Name>Error` (UniFFI renames an error type's Error suffix to Exception), with its
#     direct subclasses as cases (the error an interface throws, ADR 0071 §5);
#   - records: every public top-level `data class`, with the `var`/`val` parameters of its
#     constructor as fields: `T? = null` is optional (`name?`), `kotlin.Boolean = false` a flag
#     (`name = false`), no default required; any other default fails the mode. Any other public
#     top-level type (`class`, `object`, `interface`, `enum class`, `typealias`, ...) is reported
#     as a record, so it cannot slip past the inventory;
#   - codes: the subclasses of `sealed class PolyjoseException`, in order (one per code, ADR 0030
#     §5), which must also declare `fun code()` (the exported accessor, ADR 0033 §3).
#
# Hand-written Kotlin (MODE_HOST_TYPES): the sources the artifacts compile besides the generated
# file, platforms/android/src/shared/kotlin, platforms/android/polyjose/src/main/kotlin and
# platforms/android/polyjose-jvm/src/main/kotlin (*.kt, by the same parse). Each public top-level
# declaration (not private or internal) must be a type listed in kotlin.host-types; it is then a
# `hosttype`, and its public members (not private, internal or protected) are `hostmember`s:
#   - the `fun`, `val`, `var` and `constructor` declarations of its body (depth 1), and those of
#     its `companion object` (depth 2);
#   - its nested `class`, `object`, `interface` and `typealias` declarations, by name (their own
#     members are not listed);
#   - the `val`/`var` parameters of its primary constructor, and `constructor` for a public primary
#     constructor, written or implicit (a class that is not abstract, sealed or an enum, and has
#     no private, internal or protected `constructor` keyword in its header).
# Any other public top-level declaration there fails the mode.
# KOTLIN_RUNTIME lists the public names of UniFFI's Kotlin runtime that are not polyjose API:
# names starting with FfiConverter, Uniffi or uniffi (converters, call-status handlers,
# uniffiEnsureInitialized), and these. PolyjoseException is the host's error type (ADR 0030 §5),
# checked through its codes. Adding a name here is a review decision, like an inventory change.

MODE_KINDS="op record field code interface method enum case"
MODE_HOST_TYPES=1
KOTLIN_RUNTIME="RustBuffer InternalException Disposable NoHandle use PolyjoseException"
# The hand-written Kotlin source directories (see the header), relative to the repository root.
KOTLIN_HAND_WRITTEN="platforms/android/src/shared/kotlin platforms/android/polyjose/src/main/kotlin platforms/android/polyjose-jvm/src/main/kotlin"

mode_derive() {
  local out=$1 source=${CHECK_BINDING_API_KOTLIN_SOURCE:-} lib target dir f
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
  cat >"$mode_scratch/common.awk" <<'AWK'
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
# (A space is put in front, as BSD awk does not match `^` inside a group after `.*`.)
function name_after(s, kw,    r) {
  r = " " s; sub("^.*[^A-Za-z0-9_]" kw "[ \t]+", "", r)
  if (r ~ /^`/) { sub(/^`/, "", r); sub(/`.*/, "", r) } else sub(/[^A-Za-z0-9_].*/, "", r)
  return r
}
# The name of a `fun` declaration, after any type parameters and extension receiver.
function fun_name(s,    nm) {
  nm = " " s; sub(/^.*[ \t)]fun[ \t]+(<[^>]*>[ \t]*)?/, "", nm)
  if (nm ~ /^[A-Za-z_][A-Za-z0-9_<>?, ]*\./) { sub(/^[^.]*\./, "", nm) } # an extension receiver
  if (nm ~ /^`/) { sub(/^`/, "", nm); sub(/`.*/, "", nm) } else sub(/[^A-Za-z0-9_].*/, "", nm)
  return nm
}
# The declared name after the first type keyword of the line.
function type_name(s,    nm) {
  nm = ""
  if (match(s, /(^|[ \t])(class|object|interface|typealias)[ \t]+`?[A-Za-z_][A-Za-z0-9_]*/)) {
    nm = substr(s, RSTART, RLENGTH); sub(/^.*[ \t]`?/, "", nm)
  }
  return nm
}
function count_braces(    o, c) {
  o = gsub(/\{/, "{", line); c = gsub(/\}/, "}", line); depth += o - c
  pdepth += gsub(/\(/, "(", line) - gsub(/\)/, ")", line)
  if (pdepth < 0) pdepth = 0
  return o + c
}
function hidden(s) { return s ~ /(^|[ \t])(private|internal)[ \t]/ }
# The modifiers of a declaration: the text before its first declaration keyword, so that
# `class X private constructor(` is public and `private class X` is not.
function modifiers(s,    m) {
  m = " " s
  if (match(m, /[ \t)](class|object|interface|typealias|fun|val|var)[ \t]/)) m = substr(m, 1, RSTART)
  return m
}
AWK
  cat >"$mode_scratch/kotlin.awk" <<'AWK'
BEGIN { n = split(runtime, t, " "); for (i = 1; i <= n; i++) other[t[i]] = 1 }
function runtime_name(nm) { return (nm in other) || nm ~ /^(FfiConverter|Uniffi|uniffi)/ }
function braces(    moved) {
  moved = count_braces()
  if (in_error && depth <= error_depth && moved > 0) in_error = 0
  if (iface != "" && depth <= iface_depth && moved > 0) iface = ""
  if (enum != "" && depth <= enum_depth && moved > 0) enum = ""
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
    braces()
    next
  }
  # The subclasses of PolyjoseException (its direct body, one level in), one per code in order.
  if (in_error && depth == error_depth + 1 && pdepth == 0) {
    if (line ~ /(^|[ \t])class[ \t]+[A-Z]/) print "code " name_after(line, "class")
    if (line ~ /(^|[ \t])fun[ \t]+`?code`?[ \t]*\(/) has_code = 1
  }
  # The cases of another error type, and the methods of an interface (their direct bodies).
  if (enum != "" && depth == enum_depth + 1 && pdepth == 0 && line ~ /(^|[ \t])class[ \t]+[A-Z]/) print "case " enum "." name_after(line, "class")
  if (iface != "" && depth == iface_depth + 1 && pdepth == 0 && line ~ /(^|[ \t)])fun[ \t]/) print "method " iface "." fun_name(line)
  if (depth == 0 && pdepth == 0 && !hidden(line) && line !~ /^[ \t]*(package|import)[ \t]/) {
    if (line ~ /(^|[ \t)])fun[ \t]/) {
      nm = fun_name(line)
      if (!runtime_name(nm)) print "op " nm
      ops++
    } else if (line ~ /(^|[ \t])data[ \t]+class[ \t]/) {
      nm = name_after(line, "class")
      if (!runtime_name(nm)) { print "record " nm; record = nm }
    } else if (line ~ /(^|[ \t])(class|object|interface|typealias)[ \t]/) {
      nm = type_name(line)
      if (nm == "") nm = line
      if (nm == "PolyjoseException" && line ~ /sealed[ \t]+class/) { in_error = 1; error_depth = depth; found_error = 1 }
      else if (runtime_name(nm)) { }
      else if (line ~ /(^|[ \t])interface[ \t]/ && line !~ /(^|[ \t])fun[ \t]+interface/) { print "interface " nm; ifaces[nm] = 1; iface = nm; iface_depth = depth }
      else if (line ~ /sealed[ \t]+class/ && nm ~ /.Exception$/) { e = substr(nm, 1, length(nm) - 9) "Error"; print "enum " e; enum = e; enum_depth = depth }
      else if (line ~ /(^|[ \t])class[ \t]/ && nm ~ /.Impl$/ && (substr(nm, 1, length(nm) - 4) in ifaces)) { }
      else print "record " nm
    } else if (line ~ /(^|[ \t])(val|var)[ \t]/) {
      print "error " where() ": a public top-level property: " $0
    }
  }
  braces()
}
END {
  if (!found_error) print "error no sealed class PolyjoseException (ADR 0030 §5)"
  else if (!has_code) print "error PolyjoseException declares no fun code() (ADR 0033 §3)"
  if (depth != 0 || pdepth != 0) print "error unbalanced braces or parentheses at the end of the file (has the generator's layout changed?)"
  if (!ops) print "error no top-level fun found (has the generator's layout changed?)"
}
AWK
  # The hand-written sources: public top-level declarations must be listed host types.
  cat >"$mode_scratch/hand.awk" <<'AWK'
BEGIN { n = split(listed, t, " "); for (i = 1; i <= n; i++) host[t[i]] = 1 }
FNR == 1 {
  if (depth != 0 || pdepth != 0) print "error " prev ": unbalanced braces or parentheses at the end of the file"
  depth = 0; pdepth = 0; incomment = 0; instr = 0; type = ""; header = 0; companion = 0; companion_at = 0
}
function member(nm) { if (nm != "") print "hostmember " type "." nm }
function closed(s) { return s ~ /(^|[ \t])(private|internal|protected)[ \t]/ }
{
  prev = where()
  line = clean($0)
  if (raw) { print "error " where() ": a raw string literal (\"\"\"); this parse does not read them"; raw = 0 }
  # The declaration without its leading annotations (`@Suppress("x") class Foo` is `class Foo`).
  decl = line
  while (match(decl, /^[ \t]*@[A-Za-z_][A-Za-z0-9_.:]*[ \t]*/)) {
    decl = substr(decl, RLENGTH + 1)
    if (decl ~ /^\(/ && match(decl, /^\([^()]*\)[ \t]*/)) decl = substr(decl, RLENGTH + 1)
  }
  # The primary constructor's parameter lines of a host type (its header, up to the parentheses'
  # close): each public val/var is a member, and a private, internal or protected `constructor`
  # keyword makes the constructor non-public.
  if (type != "" && header && pdepth > 0 && decl ~ /(^|[ \t(])(val|var)[ \t]+`?[A-Za-z_]/ && !closed(modifiers(decl))) member(name_after(decl, "(val|var)"))
  if (type != "" && header && decl ~ /(private|internal|protected)[ \t]+constructor/) public_ctor = 0
  # The body of a host type: depth 1, and depth 2 inside its companion object.
  if (type != "" && !header && pdepth == 0 && !closed(modifiers(decl)) && (depth == 1 || (depth == 2 && companion))) {
    if (decl ~ /(^|[ \t])companion[ \t]+object/) { if (depth == 1) companion_at = 1 }
    else if (decl ~ /(^|[ \t)])fun[ \t]/) member(fun_name(decl))
    else if (decl ~ /(^|[ \t])(val|var)[ \t]/) member(name_after(decl, "(val|var)"))
    else if (decl ~ /(^|[ \t])constructor[ \t]*\(/) member("constructor")
    else if (decl ~ /(^|[ \t])(class|object|interface|typealias)[ \t]/) member(type_name(decl))
  }
  # Top-level declarations: a listed host type, or a failure.
  if (depth == 0 && pdepth == 0 && decl ~ /[^ \t]/ && decl !~ /^[ \t]*(package|import)[ \t]/ && !hidden(modifiers(decl))) {
    if (decl ~ /(^|[ \t])(class|object|interface|typealias)[ \t]/ && (type_name(decl) in host)) {
      type = type_name(decl); header = 1; print "hosttype " type
      public_ctor = (decl ~ /(^|[ \t])class[ \t]/ && decl !~ /(^|[ \t])(abstract|sealed|enum|annotation)[ \t]/)
      if (decl ~ /(private|internal|protected)[ \t]+constructor/) public_ctor = 0
    } else if (decl ~ /(^|[ \t)])(class|object|interface|typealias|fun|val|var)[ \t]/) {
      print "error " where() ": a public top-level declaration that is not a listed host type (scripts/check-binding-api.d/kotlin.host-types): " $0
    }
  }
  count_braces()
  # The header ends with the first line on which its parentheses are closed.
  if (type != "" && header && pdepth == 0) {
    header = 0
    if (public_ctor) member("constructor")
  }
  if (companion_at && depth == 2) { companion = 1; companion_at = 0 }
  if (companion && depth < 2) companion = 0
  if (type != "" && !header && depth == 0) type = ""
}
END { if (depth != 0 || pdepth != 0) print "error " prev ": unbalanced braces or parentheses at the end of the file" }
AWK
  awk -v runtime="$KOTLIN_RUNTIME" -f "$mode_scratch/common.awk" -f "$mode_scratch/kotlin.awk" "$source" >"$out" || return 1
  set --
  for dir in $KOTLIN_HAND_WRITTEN; do
    [ -d "$repo/$dir" ] || continue
    while IFS= read -r f; do set -- "$@" "$f"; done < <(find "$repo/$dir" -name '*.kt' -type f | sort)
  done
  [ $# -eq 0 ] && return 0
  awk -v listed="$(sed -n 's/^hosttype //p' "$host_types" | tr '\n' ' ')" \
    -f "$mode_scratch/common.awk" -f "$mode_scratch/hand.awk" "$@" >>"$out" || return 1
}
