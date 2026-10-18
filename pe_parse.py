#!/usr/bin/env python3

import mmap
import sys

import pefile

if len(sys.argv) != 2:
    sys.exit("Usage: pe_parse.py <pe-file>")

with open(sys.argv[1], "rb") as fd:
    pe_data = mmap.mmap(fd.fileno(), 0, access=mmap.ACCESS_READ)
    pe = pefile.PE(data=pe_data)

    with open("binary_summary.txt", "wt") as f:
        print("PE Metadata for %s\n" % sys.argv[1], file=f)

        print(pe.DOS_HEADER, file=f)
        print("\n", file=f)

        for section in pe.sections[:9]:
            print(section, file=f)
            print("\t" + section.Name.decode("utf-8", "replace").rstrip("\x00"), file=f)
            print("\tVirtual Address: " + hex(section.VirtualAddress), file=f)
            print("\tVirtual Size: " + hex(section.Misc_VirtualSize), file=f)
            print("\tRaw Size: " + hex(section.SizeOfRawData), file=f)
            print("\n", file=f)

        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            dll = entry.dll.decode("utf-8")
            print("[*] %s imports" % dll, file=f)
            for func in entry.imports:
                name = func.name.decode("utf-8") if func.name \
                    else "<ordinal %d>" % func.ordinal
                print("\t%s at 0x%08x" % (name, func.address), file=f)