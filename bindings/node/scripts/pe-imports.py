"""Lists the DLLs a PE file imports, and with --deny-crt fails on the dynamic VC++ runtime.

Feature 0007 F03 (review-code.md SF-1). Rust's *-pc-windows-msvc targets link the C runtime
dynamically by default (/MD), so the addon would import VCRUNTIME140.dll, which comes from the
VC++ Redistributable, not from Windows, and would fail to load on a clean machine. ci-build.sh
builds the two msvc prebuilds with -C target-feature=+crt-static and then runs

    python3 -I scripts/pe-imports.py --deny-crt polyjose.<platform>.node

Usage: pe-imports.py [--deny-crt] <file>
  Prints each DLL name of the import directory, one per line, in table order.
  --deny-crt  exit 1 when a name matches VCRUNTIME*.dll or MSVCP*.dll, case-insensitively
              (Windows file names are), naming each on stderr.
Exit status: 0 listed (and, with --deny-crt, none forbidden), 1 a forbidden import, 2 the file is
not a well-formed PE file or cannot be read, or a usage error. It fails closed: nothing that it
cannot parse passes.

Format: the Microsoft "PE Format" specification (learn.microsoft.com/windows/win32/debug/pe-format):
the MS-DOS stub's e_lfanew at 0x3c, the "PE\\0\\0" signature, the COFF file header, the optional
header (PE32 0x10b or PE32+ 0x20b) and its data directory 1 (the import table), the section table
to map an RVA to a file offset, and the import directory table (20-byte entries, the name RVA at
+12, ended by an all-zero entry). Delay-load imports (data directory 13) are not read: a linker
adds them only on /DELAYLOAD, which the Rust build never passes.

Python 3 standard library only (no dependency), run with -I as every polyjose script does.
"""

import re
import struct
import sys

FORBIDDEN = re.compile(r"^(vcruntime|msvcp)[^\\/]*\.dll$", re.IGNORECASE)
MAX_IMPORTS = 4096  # a bound on the import directory, so a corrupt one cannot loop for long


class Malformed(Exception):
    pass


def unpack(fmt, data, offset):
    size = struct.calcsize(fmt)
    if offset < 0 or offset + size > len(data):
        raise Malformed("truncated at offset %#x" % offset)
    return struct.unpack_from(fmt, data, offset)


def imports(data):
    """The DLL names of the import directory of the PE image `data`, in table order."""
    if unpack("<2s", data, 0)[0] != b"MZ":
        raise Malformed("no MZ header")
    pe = unpack("<I", data, 0x3C)[0]
    if unpack("<4s", data, pe)[0] != b"PE\0\0":
        raise Malformed("no PE signature at e_lfanew %#x" % pe)
    _machine, sections, _, _, _, opt_size, _ = unpack("<HHIIIHH", data, pe + 4)
    opt = pe + 24
    magic = unpack("<H", data, opt)[0]
    if magic == 0x10B:
        count_at, dirs_at = 92, 96
    elif magic == 0x20B:
        count_at, dirs_at = 108, 112
    else:
        raise Malformed("unknown optional header magic %#x" % magic)
    if opt_size < dirs_at:
        raise Malformed("optional header too small")
    count = unpack("<I", data, opt + count_at)[0]
    if count < 2 or dirs_at + 8 * 2 > opt_size:
        return []  # no import directory entry at all
    import_rva, import_size = unpack("<II", data, opt + dirs_at + 8)
    if import_rva == 0 and import_size == 0:
        return []

    table = opt + opt_size
    spans = []
    for i in range(sections):
        _, vsize, va, raw_size, raw_ptr = unpack("<8sIIII", data, table + 40 * i)
        spans.append((va, max(vsize, raw_size), raw_ptr, raw_size))

    def offset(rva):
        for va, span, raw_ptr, raw_size in spans:
            if va <= rva < va + span:
                if rva - va >= raw_size:
                    raise Malformed("RVA %#x is not backed by file data" % rva)
                return raw_ptr + (rva - va)
        raise Malformed("RVA %#x is in no section" % rva)

    def name(rva):
        start = offset(rva)
        end = data.find(b"\0", start, start + 256)
        if end < 0:
            raise Malformed("unterminated DLL name at RVA %#x" % rva)
        raw = data[start:end]
        if not raw or any(b < 0x20 or b > 0x7E for b in raw):
            raise Malformed("DLL name at RVA %#x is not printable ASCII" % rva)
        return raw.decode("ascii")

    names = []
    at = offset(import_rva)
    for i in range(MAX_IMPORTS + 1):
        entry = unpack("<IIIII", data, at + 20 * i)
        if entry == (0, 0, 0, 0, 0):
            return names
        if i == MAX_IMPORTS:
            break
        names.append(name(entry[3]))
    raise Malformed("more than %d import entries" % MAX_IMPORTS)


def main(argv):
    deny = bool(argv) and argv[0] == "--deny-crt"
    files = argv[1:] if deny else argv
    if len(files) != 1 or files[0].startswith("-"):
        print("usage: pe-imports.py [--deny-crt] <file>", file=sys.stderr)
        return 2
    path = files[0]
    try:
        with open(path, "rb") as f:
            data = f.read()
        names = imports(data)
    except (OSError, Malformed) as err:
        print("pe-imports.py: %s: not a readable PE file: %s" % (path, err), file=sys.stderr)
        return 2
    for n in names:
        print(n)
    if deny:
        bad = [n for n in names if FORBIDDEN.match(n)]
        if bad:
            print("pe-imports.py: %s imports the dynamic VC++ runtime: %s (build with -C target-feature=+crt-static)"
                  % (path, ", ".join(bad)), file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
