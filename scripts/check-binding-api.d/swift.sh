# shellcheck shell=bash
# shellcheck disable=SC2034,SC2154 # sourced by scripts/check-binding-api.sh, which reads MODE_KINDS
# and sets repo, mode_scratch and camel_awk
# Mode "swift" of scripts/check-binding-api.sh: the Swift (iOS) binding's public API, the Swift
# module Polyjose of the root Package.swift (ADR 0032 §3-§4). Its sources are
# platforms/swift/Sources/Polyjose/*.swift: the committed UniFFI-generated Polyjose.swift (kept
# fresh by platforms/swift/scripts/check-generated.sh) and any hand-written extension (ADR 0030 §1
# allows "a few", and each one is public API, so it must be in the inventory too). A text parse,
# so no build is needed:
#   1. comments (`//`, `/* */`, nested) and string literals are blanked, keeping the line breaks;
#   2. the declarations are read by brace depth, each line in pieces that end after a `{`, `}` or
#      `;`, so declarations sharing a line with an extension, a brace or each other count too,
#      and without leading attributes (`@available(iOS 16, *) public func f()` is `public func f()`,
#      also when the arguments span lines and the declaration follows the closing `)`)
#      or modifiers before the access keyword (`@MainActor final public class Y` is `public class Y`);
#      `open` (public, and also subclassable or overridable outside the module) counts as `public`:
#      - an operation is a `public func <name>(` at depth 0;
#      - a record is a `public struct <Name>` at depth 0, and its fields are the parameters of its
#        `public init(` (depth 1): no default is a required field, `= nil` an optional one (`?`)
#        and `= false` a flag (`=false`, ADR 0030 §3); any other default fails the mode. Each
#        parameter must also be a `public var` of the struct, and each `public var` a parameter;
#      - the codes are the `case <Code>(` lines of `public enum PolyjoseError` (depth 1), in order,
#        and the enum must have the exported `public func code() -> String` (ADR 0030 §5);
#      - a `public` member of an extension (depth 1) of any type but UniFFI's converters fails the
#        mode: the inventory has no form for hand-written members yet, so adding one is a review
#        decision that extends the inventory and this mode together. The one exception is the
#        printing members of the redaction extensions (below);
#      - an extension's header is read up to its `{`, over several lines if need be, and every
#        protocol of its conformance list (before any `where`) must be allowed, since a conformance
#        is public API as well: `Sendable` (SWIFT_GENERATED_CONFORMANCES) only in the generated
#        Polyjose.swift, and the printing protocols (SWIFT_REDACTION_PROTOCOLS) only in
#        Redaction.swift (SWIFT_REDACTION_FILE), only on the records whose secret fields ADR 0065
#        redacts (SWIFT_REDACTED_RECORDS). Such an extension may have exactly the public members
#        `public var description: String`, `public var debugDescription: String` and
#        `public var customMirror: Mirror`, as written here, with no attribute or modifier;
#      - any other public declaration at depth 0 (class, protocol, enum, typealias, var, let,
#        extension) fails the mode, so nothing public escapes the comparison.
# The derived set must equal the inventory exactly (ADR 0030 §8), codes also in order.
#
# SWIFT_FRAMEWORK lists what is UniFFI's own public plumbing, not polyjose API: the converter
# structs and their lift/lower functions (`FfiConverter*`, used by the generated code itself), and
# the initialization check `uniffiEnsurePolyjoseFfiInitialized`. SWIFT_ERROR is the error type
# (ADR 0030 §5: Swift's is PolyjoseError), whose cases are the codes. Adding a name here is a review
# decision, like an inventory change.

MODE_KINDS="op record field code"
SWIFT_FRAMEWORK_PREFIX="FfiConverter"
SWIFT_FRAMEWORK="uniffiEnsurePolyjoseFfiInitialized"
SWIFT_ERROR="PolyjoseError"
# ADR 0065: the records whose secret fields are redacted when printed, and how (feature 0009 F05).
SWIFT_GENERATED_FILE="Polyjose.swift"
SWIFT_GENERATED_CONFORMANCES="Sendable"
SWIFT_REDACTION_FILE="Redaction.swift"
SWIFT_REDACTED_RECORDS="JweDecrypted JweEncryptOptions JweRecipient JwsSigner JwsVerified JwsVerifyOptions"
SWIFT_REDACTION_PROTOCOLS="CustomStringConvertible CustomDebugStringConvertible CustomReflectable"
SWIFT_REDACTION_MEMBERS="description:String debugDescription:String customMirror:Mirror"

mode_derive() {
  local out=$1 src=$repo/platforms/swift/Sources/Polyjose f
  [ -d "$src" ] || skip "platforms/swift/Sources/Polyjose missing"
  set -- "$src"/*.swift
  [ -e "$1" ] || skip "no .swift files in platforms/swift/Sources/Polyjose"
  [ -f "$src/Polyjose.swift" ] || mode_fail "platforms/swift/Sources/Polyjose/Polyjose.swift (the generated API) is missing"

  # 1. Blank comments and string literals, keeping every line (and so the brace structure).
  cat >"$mode_scratch/strip.awk" <<'AWK'
FNR == 1 { block = 0; str = 0 }
{
  line = $0; out = ""; n = length(line); i = 1
  while (i <= n) {
    c = substr(line, i, 1); two = substr(line, i, 2)
    if (block > 0) {
      if (two == "*/") { block--; i += 2 } else if (two == "/*") { block++; i += 2 } else i++
      out = out " "; continue
    }
    if (str) {
      if (c == "\\") { i += 2; out = out "  "; continue }
      if (c == "\"") str = 0
      out = out " "; i++; continue
    }
    if (two == "//") break
    if (two == "/*") { block = 1; i += 2; out = out "  "; continue }
    if (c == "\"") { str = 1; out = out " "; i++; continue }
    out = out c; i++
  }
  str = 0 # Swift single-line strings end at the line end
  print out
}
AWK
  for f in "$@"; do
    awk -f "$mode_scratch/strip.awk" "$f" >"$mode_scratch/${f##*/}.stripped" || return 1
  done

  # 2. Declarations by brace depth.
  cat >"$mode_scratch/swift.awk" <<'AWK'
BEGIN {
  n = split(framework, t, " "); for (i = 1; i <= n; i++) plumbing[t[i]] = 1
  n = split(gen_conformances, t, " "); for (i = 1; i <= n; i++) gen_conf[t[i]] = 1
  n = split(redacted_records, t, " "); for (i = 1; i <= n; i++) redacted[t[i]] = 1
  n = split(redaction_protocols, t, " "); for (i = 1; i <= n; i++) redaction_proto[t[i]] = 1
  n = split(redaction_members, t, " "); for (i = 1; i <= n; i++) { split(t[i], kv, ":"); redaction_member[kv[1]] = kv[2] }
}
function file() { f = FILENAME; sub(/\.stripped$/, "", f); sub(/.*\//, "", f); return f }
function where() { return file() ":" FNR }
function trim(s) { gsub(/^[ \t]+|[ \t]+$/, "", s); return s }
function count(s, ch,    k, m) { m = 0; for (k = 1; k <= length(s); k++) if (substr(s, k, 1) == ch) m++; return m }
# A declaration without its leading attributes (`@discardableResult`, `@available(iOS 16, *)`, any
# number, each with an optional parenthesized argument clause), so `@inlinable public func f()` is
# read as `public func f()`. String literals and comments are already blank, so their parentheses
# do not count. An argument clause still open at the end of the piece (`@available(iOS 16,`) is
# left open in attr_open, its depth, and the pieces after it are read by attr_close. One still open
# at the end of its file fails the mode, so a parse gone wrong cannot hide the rest of the file.
function noattrs(s,    i, d, c) {
  while (match(s, /^@[A-Za-z_][A-Za-z0-9_]*/)) {
    s = substr(s, RLENGTH + 1)
    if (s ~ /^[ \t]*\(/) {
      sub(/^[ \t]*/, "", s); d = 0
      for (i = 1; i <= length(s); i++) {
        c = substr(s, i, 1)
        if (c == "(") d++
        else if (c == ")" && --d == 0) break
      }
      if (d > 0) { attr_open = d; attr_at = where(); return "" }
      s = substr(s, i + 1)
    }
    s = trim(s)
  }
  return s
}
# The rest of a piece after the `)` that closes an attribute's argument clause left open by an
# earlier piece or line (attr_open), or "" while it is still open. The rest is then read as the
# start of a declaration: `@available(iOS 16,` then `*) public func f() {}` is `public func f()`.
function attr_close(s,    i, c) {
  for (i = 1; i <= length(s); i++) {
    c = substr(s, i, 1)
    if (c == "(") attr_open++
    else if (c == ")" && --attr_open == 0) return trim(substr(s, i + 1))
  }
  return ""
}
# A declaration from its access keyword on, when declaration modifiers (any number, each with an
# optional argument such as `nonisolated(unsafe)`, mixed with attributes) come before `public` or
# `open`: `@MainActor final public class Y` is read as `public class Y`. Without `public` or `open`
# after them, the modifiers stay (`final class Z` is not public), only the attributes go.
function lead(s,    t) {
  s = noattrs(s); t = s
  while (match(t, /^(final|nonisolated|override|static|class|convenience|required|dynamic|lazy|mutating|nonmutating|indirect|prefix|postfix|infix|unowned|weak|optional|distributed)([ \t]*\([^()]*\))?[ \t]+/))
    t = noattrs(substr(t, RLENGTH + 1))
  if (t != s && t ~ /^(public|open)([ \t]|$)/) return t
  return s
}
# The parameters of a collected `public init(...)`: name and the default's form.
function params(text, record,    i, c, d, p, cur, name, list, k) {
  sub(/^[ \t]*public[ \t]+init[ \t]*\(/, "", text); sub(/\)[ \t]*(throws[ \t]*)?\{.*$/, "", text)
  d = 0; cur = ""; k = 0
  for (i = 1; i <= length(text); i++) {
    c = substr(text, i, 1)
    if (c == "(" || c == "[" || c == "<") d++
    if (c == ")" || c == "]" || c == ">") d--
    if (c == "," && d == 0) { list[++k] = cur; cur = "" } else cur = cur c
  }
  list[++k] = cur
  for (i = 1; i <= k; i++) {
    p = trim(list[i]); if (p == "") continue
    name = p; sub(/[ \t]*:.*/, "", name)
    initparam[record "." name] = 1
    if (p ~ /=[ \t]*nil$/) name = name "?"
    else if (p ~ /=[ \t]*false$/) name = name "=false"
    else if (p ~ /=/) { print "error " record "." name " has a default other than nil or false (ADR 0030 §3): " p; continue }
    print "field " record "." name
  }
}
# A whole extension header, `extension <Type>[: <protocols>] [where ...] {`, read from its line
# (at) on: sets the block and checks each protocol of the conformance list (ADR 0065).
function extension_header(h, at,    t, list, n, i, p) {
  t = h; sub(/^(public[ \t]+)?extension[ \t]+/, "", t); sub(/[ \t]*\{$/, "", t)
  block_kind = "extension"; block_name = t; sub(/[^A-Za-z0-9_].*/, "", block_name)
  redaction_ext = 0
  sub(/[ \t]+where([ \t].*)?$/, "", t)
  if (index(t, ":") == 0) return
  n = split(substr(t, index(t, ":") + 1), list, ",")
  for (i = 1; i <= n; i++) {
    p = trim(list[i]); gsub(/[ \t]+/, " ", p)
    if (file() == gen_file && (p in gen_conf)) continue
    if (file() == redaction_file && (block_name in redacted) && (p in redaction_proto)) {
      conformance[block_name SUBSEP p]++; redaction_ext = 1; continue
    }
    print "error " at ": conformance " block_name ": " p " is not allowed (only " gen_conformances " in " gen_file ", and " redaction_protocols " on " redacted_records " in " redaction_file ", ADR 0065)"
  }
}
# One piece of a line: the text up to and including its first `{`, `}` or `;`, or the rest of the
# line (see the main rule below).
function piece(line) {
  text = trim(line)
  if (collecting) {
    init = init " " text
    if (text ~ /\)[ \t]*(throws[ \t]*)?\{/) { params(init, block_name); inits[block_name]++; collecting = 0 }
    depth += count(line, "{") - count(line, "}")
    return
  }
  if (header_open) {
    header = header " " text
    if (text ~ /\{$/) { header_open = 0; extension_header(header, header_at) }
    else if (text ~ /[};]$/) { header_open = 0; print "error " header_at ": extension header without {" }
    depth += count(line, "{") - count(line, "}")
    return
  }
  if (attr_open > 0) text = attr_close(text)
  written = text
  text = lead(text)
  if (depth == 0 && (text == "public" || text == "open")) { pending = text; return }
  decl = text
  if (pending != "" && text != "") { decl = pending " " text; pending = "" }
  if (depth == 0 && decl ~ /^(public|open)[ \t]/) {
    access = decl; sub(/[ \t].*/, "", access)
    rest = decl; sub(/^(public|open)[ \t]+/, "", rest)
    kind = rest; sub(/[ \t].*/, "", kind)
    name = rest; sub(/^[a-z]+[ \t]+/, "", name); sub(/[^A-Za-z0-9_].*/, "", name)
    framework_item = (index(name, prefix) == 1 || (name in plumbing))
    if (kind == "func") {
      if (!framework_item) print "op " name
    } else if (kind == "struct") {
      if (!framework_item) { print "record " name; records[name] = 1 }
    } else if (kind == "enum" && name == error_type) {
      seen_error = 1
    } else if (!framework_item) {
      print "error " where() ": " access " " kind " " name " is neither an operation, a record nor the error type"
    }
  }
  if (depth == 0) {
    block_kind = ""; block_name = ""; redaction_ext = 0
    if (decl ~ /^public[ \t]+struct[ \t]/ || decl ~ /^public[ \t]+enum[ \t]/) { block_kind = "type"; block_name = name }
    if (decl ~ /^(public[ \t]+)?extension[ \t]/) {
      if (decl ~ /\{$/) extension_header(decl, where())
      else { header_open = 1; header = decl; header_at = where() }
    }
  }
  if (depth == 1 && block_name != "") {
    if (block_kind == "type" && block_name == error_type && text ~ /^case[ \t]+[A-Za-z0-9_]+/) {
      code = text; sub(/^case[ \t]+/, "", code); sub(/[^A-Za-z0-9_].*/, "", code); print "code " code
    }
    if (block_kind == "type" && block_name == error_type && text ~ /^public[ \t]+func[ \t]+code\(\)[ \t]*->[ \t]*String/) has_code = 1
    if (block_kind == "type" && (block_name in records)) {
      if (text ~ /^public[ \t]+var[ \t]/) { v = text; sub(/^public[ \t]+var[ \t]+/, "", v); sub(/[^A-Za-z0-9_].*/, "", v); vars[block_name "." v] = 1 }
      if (text ~ /^public[ \t]+init[ \t]*\(/) {
        init = text
        if (text ~ /\)[ \t]*(throws[ \t]*)?\{/) { params(init, block_name); inits[block_name]++ } else collecting = 1
      }
    }
    if (block_kind == "extension" && redaction_ext && match(written, /^public var [A-Za-z]+: [A-Za-z]+[ \t]*\{?$/)) {
      m = written; sub(/^public var /, "", m); ty = m; sub(/:.*/, "", m); sub(/^[^:]*: /, "", ty); sub(/[ \t]*\{?$/, "", ty)
      if ((m in redaction_member) && redaction_member[m] == ty) { member[block_name SUBSEP m]++; text = "" }
    }
    if (block_kind == "extension" && index(block_name, prefix) != 1 && text ~ /^(public|open)[ \t]/) {
      access = text; sub(/[ \t].*/, "", access)
      m = text; sub(/^(public|open)[ \t]+((static|class|final|override|mutating|convenience)[ \t]+)*(var|let|func|init|subscript)[ \t]*/, "", m); sub(/[^A-Za-z0-9_].*/, "", m)
      print "error " where() ": " access " member " (m == "" ? "init" : m) " in an extension of " block_name " (a hand-written member is public API: add it to the inventory and to this mode)"
    }
  }
  depth += count(line, "{") - count(line, "}")
  if (depth < 0) { print "error " where() ": unbalanced braces"; depth = 0 }
}
function attr_unclosed() { if (attr_open > 0) print "error " attr_at ": attribute argument list never closed" }
function header_unclosed() { if (header_open) print "error " header_at ": extension header without {" }
FNR == 1 { attr_unclosed(); header_unclosed(); depth = 0; pending = ""; collecting = 0; attr_open = 0; header_open = 0; redaction_ext = 0 }
# Each line is read in pieces that end after a `{`, `}` or `;`, so a declaration that shares its
# line with a brace or another declaration (`extension T { public func f() {} }`, `} public func
# g() {}`, `public func a() {}; public func b() {}`) is read at its own depth like one on a line of
# its own. A line with at most one brace, at its end, is one piece.
{
  rest_of_line = $0
  do {
    if (match(rest_of_line, /[{};]/)) {
      chunk = substr(rest_of_line, 1, RSTART); rest_of_line = substr(rest_of_line, RSTART + 1)
    } else { chunk = rest_of_line; rest_of_line = "" }
    piece(chunk)
  } while (rest_of_line != "")
}
END {
  attr_unclosed(); header_unclosed()
  if (!seen_error) print "error no public enum " error_type " (ADR 0030 §5)"
  else if (!has_code) print "error " error_type " has no public func code() -> String (ADR 0030 §5)"
  for (r in records) if (inits[r] != 1) print "error record " r " has " (inits[r] + 0) " public init(...), not 1"
  for (k in vars) if (!(k in initparam)) print "error public var " k " is not a parameter of its init"
  for (k in initparam) if (!(k in vars)) print "error init parameter " k " is not a public var"
}
AWK
  awk -v framework="$SWIFT_FRAMEWORK" -v prefix="$SWIFT_FRAMEWORK_PREFIX" -v error_type="$SWIFT_ERROR" \
    -v gen_file="$SWIFT_GENERATED_FILE" -v gen_conformances="$SWIFT_GENERATED_CONFORMANCES" \
    -v redaction_file="$SWIFT_REDACTION_FILE" -v redacted_records="$SWIFT_REDACTED_RECORDS" \
    -v redaction_protocols="$SWIFT_REDACTION_PROTOCOLS" -v redaction_members="$SWIFT_REDACTION_MEMBERS" \
    -f "$mode_scratch/swift.awk" "$mode_scratch"/*.stripped >"$out" || return 1
  grep -q '^op ' "$out" || mode_fail "no public func found in platforms/swift/Sources/Polyjose (has the layout changed?)"
}
