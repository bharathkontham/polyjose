#!/usr/bin/env bash
# Regenerates the two PE fixtures of the CRT import check (feature 0007 F03; review-code.md SF-1),
# which test/ci.test.ts runs scripts/pe-imports.py on:
#   crt-dynamic-x64.dll   PE32+ x86-64 DLL importing KERNEL32.dll, VCRUNTIME140.dll and
#                         MSVCP140.dll, the shape of an addon linked against the dynamic VC++ runtime
#                         (/MD, Rust's msvc default);
#   crt-static-arm64.dll  PE32+ ARM64 DLL importing KERNEL32.dll only, the shape of a +crt-static
#                         addon.
# Each is 2560 bytes. They are committed; the tests never run this script, which needs only the
# pinned toolchain's own llvm-tools component (llc, llvm-ar, rust-lld: `rustup component add
# llvm-tools`), so no Windows SDK, MSVC or Windows Rust target. A tiny LLVM IR module per DLL
# calls the imported functions (dllimport), llvm-ar in its dlltool mode writes an import library
# per DLL name from a .def file, and rust-lld links with /noentry /nodefaultlib (no CRT at all)
# and /Brepro (a zero timestamp), so the output is reproducible: re-running this script must leave
# `git status` clean.
# Usage: test/fixtures/pe/regen.sh (from bindings/node or anywhere). Runs on macOS and Linux bash.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd -P)
sysroot=$(rustc --print sysroot)
host=$(rustc -vV | sed -n 's/^host: //p')
bin=$sysroot/lib/rustlib/$host/bin
for tool in llc llvm-ar rust-lld; do
  [ -x "$bin/$tool" ] || { echo "regen.sh: $bin/$tool missing (rustup component add llvm-tools)" >&2; exit 1; }
done

work=$(mktemp -d "${TMPDIR:-/tmp}/polyjose-pe-fixtures.XXXXXX")
trap 'rm -rf "$work"' EXIT
# llvm-ar runs as dlltool when it is invoked under that name.
ln -s "$bin/llvm-ar" "$work/llvm-dlltool"

def() { # def <dll> <export>: a module-definition file naming one export of <dll>
  printf 'LIBRARY %s\nEXPORTS\n%s\n' "$1" "$2"
}
def KERNEL32.dll GetLastError >"$work/kernel32.def"
def VCRUNTIME140.dll memcpy >"$work/vcruntime140.def"
def MSVCP140.dll '?_Xlength_error@std@@YAXPEBD@Z' >"$work/msvcp140.def"

cat >"$work/dynamic.ll" <<'EOF'
target triple = "x86_64-pc-windows-msvc"
declare dllimport i32 @GetLastError()
declare dllimport ptr @memcpy(ptr, ptr, i64)
declare dllimport void @"?_Xlength_error@std@@YAXPEBD@Z"(ptr)
define dllexport i32 @f(ptr %a, ptr %b) {
  %r = call i32 @GetLastError()
  %p = call ptr @memcpy(ptr %a, ptr %b, i64 1)
  call void @"?_Xlength_error@std@@YAXPEBD@Z"(ptr %a)
  ret i32 %r
}
EOF
cat >"$work/static.ll" <<'EOF'
target triple = "aarch64-pc-windows-msvc"
declare dllimport i32 @GetLastError()
define dllexport i32 @f() {
  %r = call i32 @GetLastError()
  ret i32 %r
}
EOF

"$bin/llc" -filetype=obj -o "$work/dynamic.obj" "$work/dynamic.ll"
"$bin/llc" -filetype=obj -o "$work/static.obj" "$work/static.ll"
for lib in kernel32 vcruntime140 msvcp140; do
  "$work/llvm-dlltool" -m i386:x86-64 -d "$work/$lib.def" -l "$work/$lib-x64.lib"
done
"$work/llvm-dlltool" -m arm64 -d "$work/kernel32.def" -l "$work/kernel32-arm64.lib"

lld_link() { "$bin/rust-lld" -flavor link /dll /noentry /nodefaultlib /Brepro "$@"; }
lld_link /machine:x64 "/out:$work/crt-dynamic-x64.dll" "$work/dynamic.obj" \
  "$work/kernel32-x64.lib" "$work/vcruntime140-x64.lib" "$work/msvcp140-x64.lib"
lld_link /machine:arm64 "/out:$work/crt-static-arm64.dll" "$work/static.obj" "$work/kernel32-arm64.lib"

cp "$work/crt-dynamic-x64.dll" "$work/crt-static-arm64.dll" "$here/"
echo "regen.sh: wrote $here/crt-dynamic-x64.dll and $here/crt-static-arm64.dll"
