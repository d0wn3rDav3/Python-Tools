#!/usr/bin/python2

import pefile
import mmap
import sys

exe = sys.argv[1]

fd = open(exe,'rb')

pe_data = mmap.mmap(fd.fileno(), 0, access=mmap.ACCESS_READ)

pe = pefile.PE(data=pe_data)

with open('binary_summary.txt', 'wt') as f:
    sys.stdout = f
    
    print 'PE Metadata for %s\r\n' % sys.argv[1]
    print pe.DOS_HEADER
    print '\r\n'
    
    for section in pe.sections[:9]:
        print section
        print "\t" + section.Name.decode('utf-8')
        print "\tVirtual Address: " + hex(section.VirtualAddress)
        print "\tVirtual Size: " + hex(section.Misc_VirtualSize)
        print "\tRaw Size: " + hex(section.SizeOfRawData)
        print '\r\n'

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll_names = entry.dll.decode('utf-8')

        for dll_name in dll_names:
            print "[*] %s imports" % dll_names
            for func in entry.imports:
                print '\t%s at 0x%08x' % (func.name.decode('utf-8'), func.address)
f.close()
