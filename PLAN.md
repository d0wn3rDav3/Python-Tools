# Packer rework — reliable 32/64-bit ELF packer

## Goal

Make `packer.py` + `load.nasm` work on any static non-PIE x86 ELF (32- and
64-bit) by deriving every constant from the file being packed. Replace the
per-binary hardcodes (`MAGIC_OFFSET = 0x75254`, text vaddr, sizes, OEP) and
the Python 2 code.

## Design

Generic loader + appended config blob (option C):

- `packer.py` (Python 3) parses both ELF classes, XOR-encrypts `.text`,
  appends a position-independent stub + config blob at EOF, grows the last
  `PT_LOAD` to map them, ORs in `PF_X`, and repoints `e_entry` at the stub.
- `load.nasm` is assembled once per class (`nasm -f bin -DELF64=0|1`), cached
  as `loader32.bin`/`loader64.bin`. The stub self-locates (call/pop on 32,
  `lea rel` on 64), mprotects the `.text` range RWX, decrypts, jumps to OEP.
- Config blob (little-endian, 8-byte fields, 32-bit stub reads low dwords):
  `+0x00 text_addr, +0x08 text_size, +0x10 mprot_addr, +0x18 mprot_len,
  +0x20 oep, +0x28 key`.

## Scope ceiling

Static `ET_EXEC` without `PT_INTERP` only, enforced with a clear error.
Dynamic/PIE targets break by design: `ld.so` runs before our entry code, so
relocations are applied against encrypted `.text`. Extending the RW data
segment to RWX can trip W^X enforcement (SELinux/grsec).

## Placement math (critical, see DEVLOG)

Growing the last `PT_LOAD`'s `p_filesz` naively corrupts `.bss` (pages below
`p_filesz` become file-backed with symtab garbage). Recipe:

```
bss_lo = p_offset + p_filesz;  bss_hi = p_offset + p_memsz
1. zero file bytes [bss_lo, min(bss_hi, EOF))
2. zero-pad file to bss_hi if bss_hi > EOF
3. append stub + blob; 4. p_filesz = newEOF - p_offset;
   p_memsz = max(old, new p_filesz); 5. p_flags |= PF_X;
6. e_entry = p_vaddr + (stub_off - p_offset)
```

## Milestones

- [x] Design agreed (config-blob loader)
- [x] `load.nasm` rewritten, both classes assemble (56 bytes each)
- [x] `packer.py` rewritten in Python 3
- [x] Smoke check: 64-bit static target packs and runs identically
- [x] 32-bit target (multilib present; verified natively and under qemu-i386)
- [x] Clean refusal of dynamic/PIE inputs
- [x] README + DEVLOG committed