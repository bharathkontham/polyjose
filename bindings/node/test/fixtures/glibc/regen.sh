#!/usr/bin/env bash
# Regenerates the text fixtures of the glibc floor check (feature 0007 F04; review-code.md SF-2),
# which test/ci.test.ts runs scripts/glibc-floor.sh on (`--output`, a recorded tool output):
#   floor-2.28-arm64.readelf.txt / .objdump.txt
#       `readelf --version-info --wide` and `objdump -T` of an aarch64 shared object shaped like
#       the addon built in manylinux_2_28 (measured in Phase A, F04's Log): NEEDED libdl.so.2,
#       libpthread.so.0, libgcc_s.so.1 and libc.so.6; GLIBC_2.17 (the aarch64 base version),
#       GLIBC_2.28 (statx) and GCC_3.0. The highest glibc version is 2.28: it passes at floor 2.28.
#   above-2.34-x64.readelf.txt / .objdump.txt
#       the same for an x86-64 object shaped like a build on a newer glibc (the runner, or the
#       Phase A trixie measurement): NEEDED libgcc_s.so.1 and libc.so.6; GLIBC_2.2.5 (the x86-64
#       base version, three components), GLIBC_2.3.4, GLIBC_2.28 and GLIBC_2.34 (dlsym and
#       pthread_key_create after the libdl/libpthread merge) and GCC_3.0. It fails at floor 2.28.
# These are synthetic objects, not the addon: no glibc, Linux or Docker is needed, only the pinned
# toolchain's llvm-tools component (`rustup component add llvm-tools`): llc compiles a tiny LLVM
# IR module per object, rust-lld links stub libc/libdl/libpthread/libgcc_s shared objects whose
# version scripts give each symbol the version glibc gives it, then the "addon" against them, so
# its version-needs section is the one a real link writes. The outputs come from llvm-readobj run
# as llvm-readelf (GNU-style output) and llvm-objdump; on the build images, GNU binutils prints
# the same `Name: GLIBC_x.y` and `(GLIBC_x.y)` fields that the check reads. The objects are
# written to a temporary directory and only the text is committed; the tools run there on a
# relative file name, so the output is reproducible: re-running this script must leave
# `git status` clean. The tests never run it.
# Usage: test/fixtures/glibc/regen.sh (from bindings/node or anywhere). Runs on macOS and Linux bash.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd -P)
sysroot=$(rustc --print sysroot)
host=$(rustc -vV | sed -n 's/^host: //p')
bin=$sysroot/lib/rustlib/$host/bin
for tool in llc llvm-readobj llvm-objdump rust-lld; do
  [ -x "$bin/$tool" ] || { echo "regen.sh: $bin/$tool missing (rustup component add llvm-tools)" >&2; exit 1; }
done

work=$(mktemp -d "${TMPDIR:-/tmp}/polyjose-glibc-fixtures.XXXXXX")
trap 'rm -rf "$work"' EXIT
# llvm-readobj prints GNU readelf's format when it is invoked under that name.
ln -s "$bin/llvm-readobj" "$work/llvm-readelf"

# stub <dir> <triple> <soname> <version script> <symbol>...: a shared object <dir>/<soname> that
# defines each <symbol> as an empty function, versioned by the script.
stub() {
  local dir=$1 triple=$2 soname=$3 script=$4 name
  shift 4
  mkdir -p "$dir"
  {
    printf 'target triple = "%s"\n' "$triple"
    for name in "$@"; do printf 'define void @%s() {\n  ret void\n}\n' "$name"; done
  } >"$dir/$soname.ll"
  printf '%s\n' "$script" >"$dir/$soname.map"
  "$bin/llc" -filetype=obj -relocation-model=pic -o "$dir/$soname.o" "$dir/$soname.ll"
  "$bin/rust-lld" -flavor gnu -shared --build-id=none -soname "$soname" \
    --version-script "$dir/$soname.map" -o "$dir/$soname" "$dir/$soname.o"
}

# addon <dir> <triple> <name> <symbol>... <-- <lib>...: <dir>/<name>, a shared object exporting
# napi_register_module_v1, which calls each <symbol>, linked against the stub <lib>s in order.
addon() {
  local dir=$1 triple=$2 name=$3 sym libs=() calls=()
  shift 3
  while [ "$1" != "--" ]; do calls+=("$1"); shift; done
  shift
  for sym in "$@"; do libs+=("$dir/$sym"); done
  {
    printf 'target triple = "%s"\n' "$triple"
    for sym in "${calls[@]}"; do printf 'declare void @%s()\n' "$sym"; done
    printf 'define void @napi_register_module_v1() {\n'
    for sym in "${calls[@]}"; do printf '  call void @%s()\n' "$sym"; done
    printf '  ret void\n}\n'
  } >"$dir/addon.ll"
  "$bin/llc" -filetype=obj -relocation-model=pic -o "$dir/addon.o" "$dir/addon.ll"
  "$bin/rust-lld" -flavor gnu -shared --build-id=none --hash-style=gnu -soname "$name" \
    -o "$dir/$name" "$dir/addon.o" "${libs[@]}"
}

# record <dir> <name> <fixture prefix>: both tool outputs, run in <dir> on the relative <name>.
record() {
  (cd "$1" && "$work/llvm-readelf" --version-info --wide "$2") >"$here/$3.readelf.txt"
  (cd "$1" && "$bin/llvm-objdump" -T "$2") >"$here/$3.objdump.txt"
}

a=$work/arm64
stub "$a" aarch64-unknown-linux-gnu libc.so.6 \
  'GLIBC_2.17 { global: malloc; free; memcpy; local: *; }; GLIBC_2.28 { global: statx; };' \
  malloc free memcpy statx
stub "$a" aarch64-unknown-linux-gnu libdl.so.2 'GLIBC_2.17 { global: dlsym; local: *; };' dlsym
stub "$a" aarch64-unknown-linux-gnu libpthread.so.0 'GLIBC_2.17 { global: pthread_key_create; local: *; };' pthread_key_create
stub "$a" aarch64-unknown-linux-gnu libgcc_s.so.1 'GCC_3.0 { global: _Unwind_Resume; local: *; };' _Unwind_Resume
addon "$a" aarch64-unknown-linux-gnu polyjose.linux-arm64-gnu.node \
  malloc free memcpy statx dlsym pthread_key_create _Unwind_Resume \
  -- libdl.so.2 libpthread.so.0 libgcc_s.so.1 libc.so.6
record "$a" polyjose.linux-arm64-gnu.node floor-2.28-arm64

x=$work/x64
stub "$x" x86_64-unknown-linux-gnu libc.so.6 \
  'GLIBC_2.2.5 { global: malloc; free; local: *; }; GLIBC_2.3.4 { global: __memcpy_chk; }; GLIBC_2.28 { global: statx; }; GLIBC_2.34 { global: dlsym; pthread_key_create; };' \
  malloc free __memcpy_chk statx dlsym pthread_key_create
stub "$x" x86_64-unknown-linux-gnu libgcc_s.so.1 'GCC_3.0 { global: _Unwind_Resume; local: *; };' _Unwind_Resume
addon "$x" x86_64-unknown-linux-gnu polyjose.linux-x64-gnu.node \
  malloc free __memcpy_chk statx dlsym pthread_key_create _Unwind_Resume \
  -- libgcc_s.so.1 libc.so.6
record "$x" polyjose.linux-x64-gnu.node above-2.34-x64

echo "regen.sh: wrote $here/{floor-2.28-arm64,above-2.34-x64}.{readelf,objdump}.txt"
