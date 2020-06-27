# OneByteLdr
Bypass for CS:GO's LoadLibrary injection prevention mechanism, achieved by patching one byte of game memory. 

## How it works
The game hooks [NtOpenFile](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntopenfile) function from `ntdll.dll`. The disassembly of the replacement function is listed below:

```asm
push    ebp
mov     ebp, esp
push    esi
mov     esi, [ebp+arg_8]
mov     eax, [esi+8]
mov     eax, [eax+4]
test    eax, eax
jz      short loc_4095BB ; we patch this to skip loc_4095A1

loc_4095A1:

test    byte ptr [ebp+arg_4], 20h
jz      short loc_4095BB
push    eax
call    sub_40D460
test    al, al
jnz     short loc_4095BB
mov     eax, 0C0000034h
pop     esi
pop     ebp
retn    18h

loc_4095BB:

push    [ebp+arg_14]
push    [ebp+arg_10]
push    [ebp+arg_C]
push    esi
push    [ebp+arg_4]
push    [ebp+arg_0]
call    originalNtOpenFile
pop     esi
pop     ebp
retn    18h
```
