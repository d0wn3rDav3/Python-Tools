[bits 32]
[org 0x80BD254] ;start of function to be overwritten

push eax
push ebx
push edi
push esi
push ecx
push edx

mov edx, 7 ;permission for rwx
mov ecx, 0x76254 ;size of from baddr to start of shellcode
mov ebx, 0x8048000 ;baddr
mov eax, 0x7d ;required param in eax
int 0x80

mov edi, 0x8048250 ;start of .text section
mov esi, edi
mov ecx, 0x75004 ;size of from start of .text to shellcode

cld
decrypt:
    lodsb
    xor al, 0xa5
    stosb
    loop decrypt


pop edx
pop ecx
pop esi
pop edi
pop ebx
pop eax

push 0x804881F ;public start
ret
