# DEVLOG

## 2026-10-18 — Packer rework (branch `packer-rework`)

### Findings

- Old code worked on exactly one binary: five hardcoded per-target constants
  (`packer.py:142` MAGIC_OFFSET, `load.nasm` text addr/size, mprotect range,
  OEP). Entry patch assumed base 0x8048000. Python 2, ELF32 only.
- Old `.text` lookup bug: it grabbed the first `SHT_STRTAB` and exited when a
  binary had both `.dynstr` and `.shstrtab`. Correct source is
  `sections[e_shstrndx]`.
- **Placement pitfall (design-stage catch):** growing the last `PT_LOAD`'s
  `p_filesz` without prep corrupts `.bss`. Kernel maps pages below `p_filesz`
  from the file; `[p_filesz, p_memsz)` are anonymous zeros. Extending
  `p_filesz` turns former `.bss` pages into file-backed pages holding
  symtab/strtab garbage. Fix: zero the file bytes backing the `.bss` range and
  zero-pad the file to `p_offset+p_memsz` before appending the stub. Runtime
  never reads symtab, so zeroing it is harmless. Recipe in PLAN.md.
- Section headers do not exist at runtime (kernel maps only `PT_LOAD` ranges),
  so a runtime "read the sections" loader is impossible as stated; the viable
  runtime variant (auxv `AT_PHDR` walk) was considered and rejected — ~3x the
  asm, hardest to debug, and `AT_PHDR` can be absent in odd ELFs. Config-blob
  design chosen instead.

### Decisions

- Static non-PIE only, enforced with an error. Dynamic/PIE break by design
  (`ld.so` relocates against encrypted `.text` before our stub runs).
- 64-bit stub runs first (native test target), 32-bit second (needs
  gcc-multilib; falls back to qemu-i386).

### Results (same day)

- Both stub classes assemble to 56 bytes; verified instruction-by-instruction
  with ndisasm before first use (self-location deltas `cfg - .next` resolve
  to 0x32/0x08 as expected).
- 64-bit: two static targets (one with a 64KB `.bss` touched at its far end)
  pack and run identically natively and under qemu-x86_64. The far-`.bss`
  target confirms the bss-safety recipe works.
- 32-bit: gcc-multilib was already installed; two targets verified natively
  and under qemu-i386.
- `gcc -static -pie` on this toolchain (gcc 12, Debian 13) links as plain
  ET_EXEC static and packs fine — not a real PIE; genuine ET_DYN/PT_INTERP
  inputs are refused with a clear error.
- First smoke-check catch: `.packed` output wasn't executable (umask); the
  packer now copies the input's mode with `os.chmod`.
- `test_packer.sh` is the committed regression check: builds both classes,
  packs, compares stdout + exit code.

### Open questions / next steps (optional)

- Stripped inputs (no section headers) are currently rejected; a phdr-based
  fallback (encrypt the PF_X LOAD's file range) would cover them.
- Other ISAs need new stubs; qemu-user is already on the box for testing.