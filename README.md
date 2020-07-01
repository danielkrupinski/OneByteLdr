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
test    eax, eax ; is ObjectAttributes->ObjectName->Buffer not null
jz      short loc_4095BB ; we patch this with 'jmp' to skip loc_4095A1

loc_4095A1:

test    byte ptr [ebp+arg_4], 20h ; check if DesiredAccess has FILE_EXECUTE flag set (whether we're loading a dll)
jz      short loc_4095BB ; if it's not a dll, call original
push    eax ; ObjectAttributes->ObjectName->Buffer
call    sub_40D460 ; verify the dll
test    al, al ; check if dll is allowed to load
jnz     short loc_4095BB ; if the dll passed verification call original
mov     eax, 0C0000034h ; return STATUS_OBJECT_NAME_NOT_FOUND
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

## Alternative approach
An alternative approach which also bypasses anti-loadlibrary protection is to restore `5` first bytes of original [NtOpenFile](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntopenfile). Below is an example of that coded in C:
```c
// Restore original NtOpenFile from external process
LPVOID ntOpenFile = GetProcAddress(LoadLibraryW(L"ntdll"), "NtOpenFile");
if (ntOpenFile) {
    char originalBytes[5];
    memcpy(originalBytes, ntOpenFile, 5);
    WriteProcessMemory(csgoProcessHandle, ntOpenFile, originalBytes, 5, NULL);
}
```

## Thread creation detection
Many dll injectors (both LoadLibrary and Manual Mapping) creates thread in target process to load dll or perform initialization. This is what CS:GO devs seem to target in addition to LoadLibrary detection.

`DllMain` of `client.dll` contains code that calls **NtQueryInformationThread** function from `ntdll.dll`.

TODO: bypass this