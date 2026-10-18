#!/usr/bin/env python3

'''
ELF packer for static non-PIE x86 binaries (32- and 64-bit), concept after
@gynvael's packer. XOR-encrypts .text, appends a position-independent stub
(load.nasm) + config blob at EOF, extends the last PT_LOAD to map them, and
repoints e_entry at the stub. The stub mprotects .text RWX, decrypts it, and
jumps to the original entry point.

Usage: packer.py <elf>  ->  writes <elf>.packed
'''

import os
import struct
import subprocess
import sys

PAGE = 0x1000
KEY = 0xA5

ET_EXEC = 2
PT_LOAD = 1
PT_INTERP = 3
PF_X = 1

# e_ident + the rest of the Elf{32,64}_Ehdr. Field order is identical for
# both classes; only e_entry/e_phoff/e_shoff widen from I to Q.
EHDR = {
    1: ("<16sHHIIIIIHHHHHH", 52),
    2: ("<16sHHIQQQIHHHHHH", 64),
}
# NOTE: Elf32_Phdr and Elf64_Phdr differ in field order (p_flags moves from
# index 6 to 1). Parsed into dicts below so the rest of the code is uniform.
PHDR = {
    1: ("<IIIIIIII", 32),   # type, offset, vaddr, paddr, filesz, memsz, flags, align
    2: ("<IIQQQQQQ", 56),   # type, flags, offset, vaddr, paddr, filesz, memsz, align
}
SHDR = {
    1: ("<IIIIIIIIII", 40),  # name, type, flags, addr, offset, size, link, info, addralign, entsize
    2: ("<IIQQQQIIQQ", 64),
}


def die(msg):
    sys.exit("packer: " + msg)


def parse_elf(data):
    if len(data) < 64 or data[:4] != b"\x7fELF":
        die("not an ELF file")
    ei_class, ei_data = data[4], data[5]
    if ei_class not in EHDR:
        die("unsupported EI_CLASS %d" % ei_class)
    if ei_data != 1:
        die("only little-endian ELF is supported")

    fmt, _ = EHDR[ei_class]
    (_, e_type, _, _, e_entry, e_phoff, e_shoff, _,
     _, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = \
        struct.unpack_from(fmt, data, 0)

    if e_type != ET_EXEC:
        die("only ET_EXEC (static non-PIE) binaries are supported")
    if e_shnum == 0:
        die("no section headers -- can't locate .text (stripped file?)")

    phdrs = []
    for i in range(e_phnum):
        v = struct.unpack_from(PHDR[ei_class][0], data, e_phoff + i * e_phentsize)
        if ei_class == 2:
            p = dict(zip(("type", "flags", "offset", "vaddr",
                          "paddr", "filesz", "memsz", "align"), v))
        else:
            p = dict(zip(("type", "offset", "vaddr", "paddr",
                          "filesz", "memsz", "flags", "align"), v))
        p["_off"] = e_phoff + i * e_phentsize
        phdrs.append(p)
    if any(p["type"] == PT_INTERP for p in phdrs):
        die("dynamically linked binary (PT_INTERP) -- ld.so would relocate "
            "against encrypted .text; static non-PIE only")
    loads = [p for p in phdrs if p["type"] == PT_LOAD]
    if not loads:
        die("no PT_LOAD segments")

    shdrs = []
    for i in range(e_shnum):
        v = struct.unpack_from(SHDR[ei_class][0], data, e_shoff + i * e_shentsize)
        shdrs.append(dict(zip(("name", "type", "flags", "addr",
                               "offset", "size", "link", "info",
                               "addralign", "entsize"), v)))

    return ei_class, e_entry, phdrs, shdrs, e_shstrndx


def find_text(data, ei_class, shdrs, e_shstrndx):
    # The .text names live in the string table pointed to by e_shstrndx --
    # not "the first SHT_STRTAB", which can be .dynstr.
    shstr = shdrs[e_shstrndx]
    for sh in shdrs:
        if sh["addr"] == 0 or not (sh["flags"] & 0x4):  # SHF_EXECINSTR
            continue
        end = data.index(b"\x00", shstr["offset"] + sh["name"])
        name = data[shstr["offset"] + sh["name"]:end]
        if name == b".text":
            return sh
    die("no allocated executable .text section found")


def build_stub(is64):
    # Assembled once per class and cached; rebuilt only when load.nasm
    # changes. The committed loader*.bin is used as-is if nasm is absent.
    here = os.path.dirname(os.path.abspath(__file__))
    out = os.path.join(here, "loader%d.bin" % (64 if is64 else 32))
    src = os.path.join(here, "load.nasm")
    if not os.path.exists(out) or os.path.getmtime(src) > os.path.getmtime(out):
        if not os.path.exists(src) and os.path.exists(out):
            return open(out, "rb").read()
        try:
            subprocess.check_output(["nasm", "-f", "bin", "-DELF64=%d" % is64,
                                    src, "-o", out])
        except FileNotFoundError:
            die("nasm not installed and no cached %s" % os.path.basename(out))
    return open(out, "rb").read()


def pack(data):
    ei_class, oep, phdrs, shdrs, e_shstrndx = parse_elf(data)
    is64 = ei_class == 2

    text = find_text(data, ei_class, shdrs, e_shstrndx)
    print(".text @ vaddr 0x%x, file offset 0x%x, %u bytes"
          % (text["addr"], text["offset"], text["size"]))

    packed = bytearray(data)

    # "encrypt" .text
    for i in range(text["offset"], text["offset"] + text["size"]):
        packed[i] ^= KEY

    # mprotect range: page-aligned window covering .text
    mp_addr = text["addr"] & ~(PAGE - 1)
    mp_len = ((text["addr"] + text["size"] + PAGE - 1) & ~(PAGE - 1)) - mp_addr

    # lo = last PT_LOAD by vaddr; our stub lives at its tail.
    lo = max((p for p in phdrs if p["type"] == PT_LOAD),
             key=lambda p: p["vaddr"] + p["filesz"])

    # bss-safety: pages below p_filesz come from the FILE, pages in
    # [p_filesz, p_memsz) are anonymous zeros. Growing p_filesz would turn
    # former .bss pages into file-backed ones -- so the file bytes backing
    # .bss must be zeroed, and the file padded out if .bss extends past EOF.
    bss_lo = lo["offset"] + lo["filesz"]
    bss_hi = lo["offset"] + lo["memsz"]
    for i in range(bss_lo, min(bss_hi, len(packed))):
        packed[i] = 0
    if bss_hi > len(packed):
        packed += b"\x00" * (bss_hi - len(packed))

    # append stub + config blob (little-endian u64 fields; the 32-bit stub
    # reads the low dword of each -- see load.nasm)
    stub_off = len(packed)
    stub = build_stub(is64)
    packed += stub
    packed += struct.pack("<QQQQQB7x", text["addr"], text["size"],
                          mp_addr, mp_len, oep, KEY)

    # grow the segment over the appended data and make it executable
    lo["flags"] |= PF_X
    lo["filesz"] = len(packed) - lo["offset"]
    lo["memsz"] = max(lo["memsz"], lo["filesz"])
    write_phdr(packed, ei_class, lo)

    # repoint e_entry at the stub (e_entry is at file offset 0x18 in both
    # classes; 4 bytes in ELF32, 8 in ELF64)
    stub_vaddr = lo["vaddr"] + (stub_off - lo["offset"])
    struct.pack_into("<Q" if is64 else "<I", packed, 0x18, stub_vaddr)

    print("stub @ file 0x%x / vaddr 0x%x, e_entry 0x%x -> stub (OEP 0x%x)"
          % (stub_off, stub_vaddr, stub_vaddr, oep))
    return packed


def write_phdr(buf, ei_class, p):
    if ei_class == 2:
        struct.pack_into(PHDR[2][0], buf, p["_off"], p["type"], p["flags"],
                         p["offset"], p["vaddr"], p["paddr"], p["filesz"],
                         p["memsz"], p["align"])
    else:
        struct.pack_into(PHDR[1][0], buf, p["_off"], p["type"], p["offset"],
                         p["vaddr"], p["paddr"], p["filesz"], p["memsz"],
                         p["flags"], p["align"])


def main(argv):
    if len(argv) != 2:
        print("Usage: packer.py <filename>")
        return 1
    with open(argv[1], "rb") as f:
        data = f.read()
    with open(argv[1] + ".packed", "wb") as f:
        f.write(pack(data))
    os.chmod(argv[1] + ".packed", os.stat(argv[1]).st_mode)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))