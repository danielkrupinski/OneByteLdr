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
Many Manual Mapping dll injectors create thread in target process to load dll or perform initialization. This is what CS:GO devs target in addition to LoadLibrary detection. **Thread detection doesn't affect LoadLibrary injectors**.

`DllMain` function of `client.dll` contains code that calls **NtQueryInformationThread** function from `ntdll.dll` to get **start address of current thread**:

```asm
push    ebp
mov     ebp, esp
mov     eax, [ebp+fdwReason]
sub     esp, 20h
cmp     eax, 1
jz      loc_106390D3 ; if fdwReason is DLL_PROCESS_ATTACH, skip
test    eax, eax
jz      loc_106390D3 ; if fdwReason is DLL_PROCESS_DETACH, skip
cmp     eax, 2
jnz     loc_106390D3 ; if fdwReason is not DLL_THREAD_ATTACH, skip
push    esi
push    edi
mov     [ebp+phModule], 0
call    ds:GetCurrentThreadId
push    offset aNtqueryinforma ; "NtQueryInformationThread"
push    offset aNtdllDll ; "ntdll.dll"
mov     edi, eax
call    ds:GetModuleHandleA
push    eax
call    ds:GetProcAddress
mov     esi, eax
test    esi, esi
jz      short loc_106390C6 ; we patch this with 'jmp' to skip loc_106390B2
push    0
push    4
lea     eax, [ebp+fdwReason]
push    eax
push    9 ; ThreadQuerySetWin32StartAddress
call    ds:GetCurrentThread
push    eax
call    esi ; get thread start address from NtQueryInformationThread
test    eax, eax
jnz     short loc_106390C6
push    1Ch
lea     eax, [ebp+Buffer]
push    eax
push    [ebp+fdwReason]
call    ds:VirtualQuery
lea     eax, [ebp+phModule]
push    eax
push    [ebp+fdwReason]
push    6
call    ds:GetModuleHandleExA
mov     ecx, [ebp+Buffer.Protect]
test    eax, eax ; check if the address leads to a valid module
jz      short loc_106390B2 ; if the code's been manually mapped save thread's characteristics
cmp     ecx, 40h
jnz     short loc_106390C6

loc_106390B2:
mov     eax, [ebp+fdwReason]
mov     dword_1528625C, eax
mov     dword_15286260, edi
mov     dword_15286264, ecx

loc_106390C6:
pop     edi
mov     eax, 1
pop     esi
mov     esp, ebp
pop     ebp
retn    0Ch

loc_106390D3:
mov     eax, 1
mov     esp, ebp
pop     ebp
retn    0Ch
```