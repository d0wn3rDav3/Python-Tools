; load.nasm -- position-independent unpacker stub for the ELF packer.
;
; Assembled once per ELF class (the packer caches and reuses the blobs):
;   nasm -f bin -DELF64=0 load.nasm -o loader32.bin
;   nasm -f bin -DELF64=1 load.nasm -o loader64.bin
;
; The packer appends a 0x30-byte config blob directly after this code:
;   +0x00 text_addr   +0x08 text_size   +0x10 mprot_addr   (page-aligned)
;   +0x18 mprot_len   +0x20 oep         +0x28 key byte + 7 pad
; All fields are little-endian u64; the 32-bit stub reads the low dword.
;
; No [org] and no absolute references: the stub may sit anywhere the packer
; maps it. cfg-relative addressing keeps it position-independent.

%ifndef ELF64
%define ELF64 0
%endif

%if ELF64
[bits 64]
%else
[bits 32]
%endif

entry:
%if ELF64
    ; _start only relies on rsp and rdx (kernel passes rtld_fini in rdx);
    ; rbx is our cfg base. syscall also clobbers rcx/r11 -- not needed at
    ; process entry, but saving what we touch is cheap insurance.
    push rdx
    push rbx

    lea rbx, [rel cfg]

    ; mprotect(mprot_addr, mprot_len, PROT_READ|PROT_WRITE|PROT_EXEC)
    mov rdi, [rbx + 0x10]
    mov rsi, [rbx + 0x18]
    mov edx, 7
    mov eax, 10                       ; SYS_mprotect
    syscall

    ; decrypt .text: for i in [0, text_size): text_addr[i] ^= key
    mov rdi, [rbx + 0x00]
    mov rcx, [rbx + 0x08]
    movzx esi, byte [rbx + 0x28]
.decrypt:
    xor byte [rdi], sil
    inc rdi
    loop .decrypt

    mov rax, [rbx + 0x20]             ; original entry point
    pop rbx
    pop rdx
    push rax
    ret                               ; -> original _start
%else
    pusha

    ; locate the config blob: call pushes the address of the next insn
    call .next
.next:
    pop esi                           ; esi = address of .next
    add esi, cfg - .next              ; esi = address of cfg

    ; mprotect(mprot_addr, mprot_len, PROT_READ|PROT_WRITE|PROT_EXEC)
    mov ebx, [esi + 0x10]
    mov ecx, [esi + 0x18]
    mov edx, 7
    mov eax, 125                      ; SYS_mprotect (int 0x80)
    int 0x80

    ; decrypt .text: for i in [0, text_size): text_addr[i] ^= key
    mov edi, [esi + 0x00]
    mov ecx, [esi + 0x08]
    movzx edx, byte [esi + 0x28]
.decrypt:
    xor byte [edi], dl
    inc edi
    loop .decrypt

    popa                              ; would destroy esi/eax, so re-locate

    call .next2
.next2:
    pop eax                           ; eax = address of .next2
    add eax, cfg - .next2             ; eax = address of cfg
    push dword [eax + 0x20]           ; original entry point
    ret                               ; -> original _start
%endif

cfg:                                  ; packer appends the config blob here