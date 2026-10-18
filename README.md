# Python-Tools

Assorted Python tooling for RE/VR work. Currently three tools:

| Tool | What it does |
|---|---|
| `packer.py` + `load.nasm` | ELF packer for static non-PIE x86 binaries (32/64-bit) |
| `adbWebView.py` | Open a URL in a WebView on an ADB-connected Android device and capture logcat |
| `pe_parse.py` | Dump PE headers, sections, and imports to a text file |

---

## ELF packer (`packer.py` + `load.nasm`)

Packs static non-PIE x86 ELF executables (32- and 64-bit). XOR-encrypts the
`.text` section, appends a position-independent unpacker stub plus a config
blob at EOF, grows the last `PT_LOAD` to map them, and repoints `e_entry` at
the stub. At runtime the stub mprotects `.text` RWX, decrypts it in place,
and jumps to the original entry point.

```
$ ./packer.py ./target
.text @ vaddr 0x401100, file offset 0x1100, 479097 bytes
stub @ file 0xba2e8 / vaddr 0x4bb2e8, e_entry 0x4bb2e8 -> stub (OEP 0x401600)
$ ./target.packed
```

Requires Python 3 and nasm (or the committed `loader32.bin`/`loader64.bin`
caches; the stubs are only rebuilt when `load.nasm` changes).

### Constraints

- **Static `ET_EXEC` only** (no `PT_INTERP`, not PIE). Dynamic/PIE binaries
  are rejected with an error: `ld.so` would apply relocations against the
  encrypted `.text` before the stub runs.
- The section header table must be present (the packer locates `.text` by
  name via `e_shstrndx`). Stripped-with-`strip -s` files fail loudly.
- Linux only. The extended data segment is RWX, which W^X-enforcing setups
  (SELinux, grsec) may refuse.

### Design notes

- Every per-target constant is derived from the ELF being packed; nothing is
  hardcoded (the config blob layout is documented in `load.nasm`).
- The stub is position-independent and identical for every target of its
  class; the packer appends a 0x30-byte config blob (text addr/size, mprotect
  range, original entry, key) immediately after the stub code.
- The last `PT_LOAD` extension zeroes/pads the file bytes that back `.bss`
  first — otherwise growing `p_filesz` would seed `.bss` with symtab garbage
  (see DEVLOG.md).

### Testing

```
$ ./test_packer.sh   # builds static targets (64-bit, 32-bit if multilib),
                     # packs, and compares stdout + exit codes
```

---

## adbWebView.py

Opens a URL in a WebView context on a device connected over ADB and captures
the surrounding logcat output — used to verify that websites are handled
appropriately within a WebView.

```
$ adb start-server
$ python3 adbWebView.py
```

Prompts for the device (if several are attached) and the URL, prints the
target's make/model/serial/OS version (via `getprop`), force-stops any
running Chrome, launches the URL as a VIEW intent, and writes the last 1000
logcat lines to `logcat_output_<timestamp>.txt` in the current directory.

Requires: the `adb` binary on PATH, a running ADB server, USB/network-debug
enabled on the device, and `pure-python-adb` (`pip install pure-python-adb`).

---

## pe_parse.py

Dumps PE metadata to `binary_summary.txt`: DOS header, the first 9 section
headers (with VA/virtual size/raw size), and the import table (DLL name,
function name, IAT address per entry).

```
$ pip install --user --break-system-packages pefile   # Debian 13 and later
$ python3 pe_parse.py ./target.exe
$ cat binary_summary.txt
```

Requires: Python 3 and the `pefile` module.

---

## Repo docs

- `PLAN.md` — active plan / design record for the packer rework
- `DEVLOG.md` — chronological findings trail (dead ends included)
- `test_packer.sh` — packer regression check (see above)