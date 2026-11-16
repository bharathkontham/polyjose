# shellcheck shell=bash
# shellcheck disable=SC2034,SC2154 # sourced by scripts/check-binding-api.sh, which reads MODE_KINDS
# and sets repo, mode_scratch and camel_awk
# Mode "surface" of scripts/check-binding-api.sh: the Rust surface crate, bindings/surface
# (polyjose-surface, ADR 0030 §1), which defines every operation and record once.
#
# A text parse of the T01 layout of bindings/surface/src/*.rs, so no cargo build is needed. It
# relies on rustfmt's layout (cargo fmt --check gates every change):
#   - an operation is a top-level `pub fn <snake_name>` at column 0 (optionally `pub const fn`);
#     methods (`impl` blocks, indented), `pub(crate)` items and the indented contents of the
#     `#[cfg(test)] mod tests` blocks are not operations;
#   - a record is a top-level `pub struct <Name>`, and its fields are the `    pub <snake_name>:`
#     lines up to the closing `}` at column 0; `Option<...>` marks an optional field (`name?`) and
#     `bool` a flag (`name = false`: every surface flag defaults to false, ADR 0030 §3, §4);
#   - an interface is a top-level `pub trait <Name>`, and its methods are the `    fn <snake_name>`
#     lines up to the closing `}` at column 0 (ADR 0071 §5);
#   - an enum is a top-level `pub enum <Name>`, and its cases are the `    <Variant>,` lines up to
#     the closing `}` at column 0; a variant with a payload fails the mode (the inventory's enums
#     have none, ADR 0071 §1);
#   - any other top-level public type (`pub type`, `pub union`) is reported as a record, so it
#     cannot slip past the inventory;
#   - an inline `pub mod <name> {` would hide its items from this parse and fails the mode; the
#     surface has one file per module (lib.rs declares them as `pub mod <name>;`).
# Names are converted to camelCase as the frameworks do (ADR 0030 §2).
#
# SURFACE_TYPES are the surface's public types that are not inventory records: the error type and
# its result alias (ADR 0030 §5; each host has its own error type: PolyjoseError,
# PolyjoseException), and the zeroizing secret owners (ADR 0030 §7), which hosts see as plain
# strings and bytes. Adding a public type to this list is a review decision, like an inventory
# change.

MODE_KINDS="op record field interface method enum case"
SURFACE_TYPES="SurfaceError SurfaceResult SecretString SecretBytes"

mode_derive() {
  local out=$1 src=$repo/bindings/surface/src
  [ -d "$src" ] || skip "bindings/surface/src missing"
  set -- "$src"/*.rs
  [ -e "$1" ] || skip "no .rs files in bindings/surface/src"
  cat >"$mode_scratch/surface.awk" <<'AWK'
BEGIN { n = split(types, t, " "); for (i = 1; i <= n; i++) other[t[i]] = 1 }
function where() { f = FILENAME; sub(/.*\//, "", f); return f ":" FNR }
FNR == 1 { block = 0; trait = ""; enum = "" }
# Inside a top-level trait body: its methods, until the closing brace at column 0.
trait != "" && /^}/ { trait = ""; next }
trait != "" {
  if ($0 ~ /^    fn [a-z_][a-z0-9_]*/) {
    name = $0; sub(/^    fn /, "", name); sub(/[^a-z0-9_].*/, "", name)
    print "method " trait "." camel(name)
  }
  next
}
# Inside a top-level enum body: its variants, until the closing brace at column 0.
enum != "" && /^}/ { enum = ""; next }
enum != "" {
  if ($0 ~ /^    [A-Z][A-Za-z0-9]*,?[ \t]*$/) {
    name = $0; sub(/^    /, "", name); sub(/[^A-Za-z0-9].*/, "", name)
    print "case " enum "." name
  } else if ($0 ~ /^    [A-Z][A-Za-z0-9]*[ \t]*[({=]/) {
    print "error " where() ": enum variant with a payload or value (the inventory cannot express it): " $0
  }
  next
}
# Inside a top-level struct body: its public fields, until the closing brace at column 0.
block && /^}/ { block = 0; next }
block {
  if ($0 ~ /^    pub [a-z_][a-z0-9_]*:/) {
    line = $0; sub(/^    pub /, "", line)
    name = line; sub(/:.*/, "", name)
    type = line; sub(/^[^:]*:[ \t]*/, "", type)
    if (type == "") { print "error " where() ": cannot read the type of " record "." name " (one line per field)"; next }
    suffix = ""
    if (type ~ /^Option</) suffix = "?"
    else if (type ~ /^bool,?$/) suffix = "=false"
    if (record != "") print "field " record "." camel(name) suffix
  }
  next
}
/^pub (const )?fn [a-z_][a-z0-9_]*/ {
  name = $0; sub(/^pub (const )?fn /, "", name); sub(/[^a-z0-9_].*/, "", name)
  print "op " camel(name); next
}
/^pub (async |unsafe |extern )/ { print "error " where() ": unsupported item form: " $0; next }
/^pub mod [a-z_][a-z0-9_]*[ \t]*\{/ { print "error " where() ": inline module (its items are not parsed): " $0; next }
/^pub (trait|enum) / {
  name = $3; sub(/[^A-Za-z0-9_].*/, "", name)
  if (name in other) next
  if ($2 == "trait") { print "interface " name; if ($0 ~ /\{[ \t]*$/) trait = name }
  else { print "enum " name; if ($0 ~ /\{[ \t]*$/) enum = name }
  next
}
/^pub (struct|type|union) / {
  name = $3; sub(/[^A-Za-z0-9_].*/, "", name)
  record = (name in other) ? "" : name
  if (record != "") print "record " name
  if ($2 == "struct" && $0 ~ /\{[ \t]*$/) block = 1
  next
}
AWK
  awk -v types="$SURFACE_TYPES" -f "$camel_awk" -f "$mode_scratch/surface.awk" "$@" >"$out" || return 1
  [ -s "$out" ] || mode_fail "no pub fn or pub struct found in bindings/surface/src/*.rs (has the layout changed?)"
}
