#!/usr/bin/env python2

'''
ELF32 packer concept from 64-bit
packer written by @gynvael
'''

import sys
from struct import unpack, pack
import os
import time
import subprocess

def get_c_string(data, offset):
    out = []
    i = offset
    while data[i] != "\x00":
        out.append(data[i])
        i += 1
    return ''.join(out)

def parse_section(data):
    return unpack("IIIIIIIIII", data[:40])

def main(argv):
    if len(argv) != 2:
        print "Usage: packer <filename>"
        return 1

    with open(argv[1], "rb") as f:
        elf = f.read()

    '''
    ELF Header
    #define EI_NIDENT 16
    typedef struct {
        unsigned char   e_ident[EI_NIDENT]; #16s
        Elf32_Half      e_type;             #H
        Elf32_Half      e_machine;          #H
        Elf32_W0rd      e_version;          #I
        Elf_32Addr      e_entry;            #I
        Elf32_Off       e_phoff;            #I
        Elf32_Off       e_shoff;            #I
        Elf32_Word      e_flags;            #I
        Elf32_Half      e_ehsize;           #H
        Elf32_Half      e_phentsize;        #H
        Elf32_Half      e_phnum;            #H
        Elf32_Half      e_shentsize;        #H
        Elf32_Half      e_shnum;            #H
        Elf32_Half      e_shstrndx;         #H
    } Elf32_Ehdr;                           # -> 52 bytes
    '''

    ( e_ident,
      e_type,
      e_machine,
      e_version,
      e_entry,
      e_phoff,
      e_shoff,
      e_flags,
      e_ehsize,
      e_phentsize,
      e_phnum,
      e_shentsize,
      e_shnum,
      e_shstrndx ) = unpack("16sHHIIIIIHHHHHH", elf[:52])
    
    oep = e_entry
    
    '''
    Section Header
    typedef struct {
        Elf32_Word      sh_name;        #I
        Elf32_Word      sh_type;        #I
        Elf32_Word      sh_flags;       #I
        Elf32_Addr      sh_addr;        #I
        Elf32_Off       sh_offset;      #I
        Elf32_Word      sh_size;        #I
        Elf32_Word      sh_link;        #I
        Elf32_Word      sh_info;        #I
        Elf32_Word      sh_addralign;   #I
        Elf32_Word      sh_entsize;     #I
    } Elf32_Shdr;                       # -> 40 bytes
    '''

    sections = []
    strtab_section = -1
    strtab_offset = None
    for i in xrange(e_shnum):
        offset = i * 40
        s = parse_section(elf[e_shoff + offset:e_shoff + offset + 40])
        (sh_name,
         sh_type,
         sh_flags,
         sh_addr,
         sh_offset,
         sh_size,
         sh_link,
         sh_info,
         sh_addralign,
         sh_entsize) = s
        sections.append(s)
        
        # sh_type of 3 is the string table
        if sh_type == 3:
           strtab_section = i
           if strtab_section != e_shstrndx:
               sys.exit("strtab_section != e_shstrndx")
           strtab_offset = sh_offset

    text_offset = None
    text_size = None
    for i in xrange(e_shnum):
        (sh_name,
         sh_type,
         sh_flags,
         sh_addr,
         sh_offset,
         sh_size,
         sh_link,
         sh_info,
         sh_addralign,
         sh_entsize
        ) = sections[i]
        
        name = get_c_string(elf, strtab_offset + sh_name)
        if name == ".text":
            text_section = i
            text_offset = sh_offset
            text_size = sh_size
            print ".text section @ %x of size %u bytes" % (text_offset, text_size)

    packed = bytearray(elf)
    
    #"encrypt" -> Big Air Quotes
    for i in xrange(text_size):
        packed[text_offset + i] ^= 0xa5

    #for i in xrange(0x100):
    #    packed[0x75254 + i] = 0xcc 
    MAGIC_OFFSET = 0x75254
    subprocess.check_output(["nasm", "load.nasm"])

    with open("load", "rb") as f:
        loader = bytearray(f.read())

    packed[MAGIC_OFFSET:MAGIC_OFFSET+len(loader)] = loader


    #This will probably not be right.
    packed[24:24+4] = bytearray(pack("I", MAGIC_OFFSET + 0x8048000))
    #.text size + shellcode = 0x30547

    with open(argv[1] + ".packed", "wb") as f:
        f.write(packed)

if __name__ == "__main__":
    sys.exit(main(sys.argv))
