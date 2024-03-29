#include "syscalls_common.h"
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
        // if we are a WoW64 process, jump to WOW32Reserved
        SyscallAddress = (PVOID)__readfsdword(0xc0);
        return SyscallAddress;
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

__declspec(naked) NTSTATUS VAVNtCreateProcess(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN HANDLE ParentProcess,
	IN BOOLEAN InheritObjectTable,
	IN HANDLE SectionHandle OPTIONAL,
	IN HANDLE DebugPort OPTIONAL,
	IN HANDLE ExceptionPort OPTIONAL)
{
	asm(
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x55E575B8 \n"
		"call _VAV_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x55E575B8 \n"
		"call _VAV_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x8 \n"
	"push_argument_55E575B8: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_55E575B8 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_55E575B8] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_55E575B8 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_55E575B8: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_55E575B8: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
	);
}

__declspec(naked) NTSTATUS VAVNtCreateThreadEx(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN HANDLE ProcessHandle,
	IN PVOID StartRoutine,
	IN PVOID Argument OPTIONAL,
	IN ULONG CreateFlags,
	IN SIZE_T ZeroBits,
	IN SIZE_T StackSize,
	IN SIZE_T MaximumStackSize,
	IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL)
{
	asm(
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x72A2B0F8 \n"
		"call _VAV_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x72A2B0F8 \n"
		"call _VAV_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xb \n"
	"push_argument_72A2B0F8: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_72A2B0F8 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_72A2B0F8] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_72A2B0F8 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_72A2B0F8: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_72A2B0F8: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
	);
}

__declspec(naked) NTSTATUS VAVNtOpenProcess(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId OPTIONAL)
{
	asm(
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x011F72D0 \n"
		"call _VAV_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x011F72D0 \n"
		"call _VAV_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_011F72D0: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_011F72D0 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_011F72D0] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_011F72D0 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_011F72D0: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_011F72D0: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
	);
}

__declspec(naked) NTSTATUS VAVNtOpenProcessToken(
	IN HANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	OUT PHANDLE TokenHandle)
{
	asm(
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x9C83B019 \n"
		"call _VAV_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x9C83B019 \n"
		"call _VAV_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_9C83B019: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_9C83B019 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_9C83B019] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_9C83B019 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_9C83B019: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_9C83B019: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
	);
}

__declspec(naked) NTSTATUS VAVNtTestAlert()
{
	asm(
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xAA386D6A \n"
		"call _VAV_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xAA386D6A \n"
		"call _VAV_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_AA386D6A: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_AA386D6A \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_AA386D6A] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_AA386D6A \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_AA386D6A: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_AA386D6A: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
	);
}

__declspec(naked) NTSTATUS VAVNtOpenThread(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId OPTIONAL)
{
	asm(
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xB4AC3887 \n"
		"call _VAV_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xB4AC3887 \n"
		"call _VAV_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_B4AC3887: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_B4AC3887 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_B4AC3887] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_B4AC3887 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_B4AC3887: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_B4AC3887: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
	);
}

__declspec(naked) NTSTATUS VAVNtSuspendProcess(
	IN HANDLE ProcessHandle)
{
	asm(
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xE1BF13D3 \n"
		"call _VAV_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xE1BF13D3 \n"
		"call _VAV_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_E1BF13D3: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_E1BF13D3 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_E1BF13D3] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_E1BF13D3 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_E1BF13D3: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_E1BF13D3: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
	);
}

__declspec(naked) NTSTATUS VAVNtSuspendThread(
	IN HANDLE ThreadHandle,
	OUT PULONG PreviousSuspendCount)
{
	asm(
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x16CB4871 \n"
		"call _VAV_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x16CB4871 \n"
		"call _VAV_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_16CB4871: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_16CB4871 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_16CB4871] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_16CB4871 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_16CB4871: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_16CB4871: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
	);
}

__declspec(naked) NTSTATUS VAVNtResumeProcess(
	IN HANDLE ProcessHandle)
{
	asm(
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xDF3C306E \n"
		"call _VAV_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xDF3C306E \n"
		"call _VAV_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_DF3C306E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_DF3C306E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_DF3C306E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_DF3C306E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_DF3C306E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_DF3C306E: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
	);
}

__declspec(naked) NTSTATUS VAVNtResumeThread(
	IN HANDLE ThreadHandle,
	IN OUT PULONG PreviousSuspendCount OPTIONAL)
{
	asm(
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x3C9BE6A5 \n"
		"call _VAV_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x3C9BE6A5 \n"
		"call _VAV_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_3C9BE6A5: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_3C9BE6A5 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_3C9BE6A5] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_3C9BE6A5 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_3C9BE6A5: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_3C9BE6A5: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
	);
}

__declspec(naked) NTSTATUS VAVNtGetContextThread(
	IN HANDLE ThreadHandle,
	IN OUT PCONTEXT ThreadContext)
{
	asm(
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x16FD2C2B \n"
		"call _VAV_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x16FD2C2B \n"
		"call _VAV_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_16FD2C2B: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_16FD2C2B \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_16FD2C2B] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_16FD2C2B \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_16FD2C2B: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_16FD2C2B: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
	);
}

__declspec(naked) NTSTATUS VAVNtSetContextThread(
	IN HANDLE ThreadHandle,
	IN PCONTEXT Context)
{
	asm(
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x14304A81 \n"
		"call _VAV_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x14304A81 \n"
		"call _VAV_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_14304A81: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_14304A81 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_14304A81] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_14304A81 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_14304A81: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_14304A81: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
	);
}

__declspec(naked) NTSTATUS VAVNtClose(
	IN HANDLE Handle)
{
	asm(
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1681FD01 \n"
		"call _VAV_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1681FD01 \n"
		"call _VAV_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_1681FD01: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1681FD01 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1681FD01] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1681FD01 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1681FD01: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1681FD01: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
	);
}

__declspec(naked) NTSTATUS VAVNtReadVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress OPTIONAL,
	OUT PVOID Buffer,
	IN SIZE_T BufferSize,
	OUT PSIZE_T NumberOfBytesRead OPTIONAL)
{
	asm(
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x05952B03 \n"
		"call _VAV_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x05952B03 \n"
		"call _VAV_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_05952B03: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_05952B03 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_05952B03] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_05952B03 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_05952B03: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_05952B03: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
	);
}

__declspec(naked) NTSTATUS VAVNtWriteVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN PVOID Buffer,
	IN SIZE_T NumberOfBytesToWrite,
	OUT PSIZE_T NumberOfBytesWritten OPTIONAL)
{
	asm(
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x8E1E9A80 \n"
		"call _VAV_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x8E1E9A80 \n"
		"call _VAV_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_8E1E9A80: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_8E1E9A80 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_8E1E9A80] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_8E1E9A80 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_8E1E9A80: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_8E1E9A80: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
	);
}

__declspec(naked) NTSTATUS VAVNtAllocateVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID * BaseAddress,
	IN ULONG ZeroBits,
	IN OUT PSIZE_T RegionSize,
	IN ULONG AllocationType,
	IN ULONG Protect)
{
	asm(
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xCB5EE985 \n"
		"call _VAV_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xCB5EE985 \n"
		"call _VAV_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_CB5EE985: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_CB5EE985 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_CB5EE985] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_CB5EE985 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_CB5EE985: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_CB5EE985: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
	);
}

__declspec(naked) NTSTATUS VAVNtProtectVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID * BaseAddress,
	IN OUT PSIZE_T RegionSize,
	IN ULONG NewProtect,
	OUT PULONG OldProtect)
{
	asm(
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x05962905 \n"
		"call _VAV_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x05962905 \n"
		"call _VAV_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_05962905: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_05962905 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_05962905] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_05962905 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_05962905: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_05962905: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
	);
}

__declspec(naked) NTSTATUS VAVNtFreeVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID * BaseAddress,
	IN OUT PSIZE_T RegionSize,
	IN ULONG FreeType)
{
	asm(
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x07974D69 \n"
		"call _VAV_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x07974D69 \n"
		"call _VAV_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_07974D69: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_07974D69 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_07974D69] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_07974D69 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_07974D69: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_07974D69: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
	);
}

__declspec(naked) NTSTATUS VAVNtQuerySystemInformation(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	IN OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL)
{
	asm(
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xFEA4FA4E \n"
		"call _VAV_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xFEA4FA4E \n"
		"call _VAV_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_FEA4FA4E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_FEA4FA4E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_FEA4FA4E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_FEA4FA4E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_FEA4FA4E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_FEA4FA4E: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
	);
}

__declspec(naked) NTSTATUS VAVNtQueryDirectoryFile(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass,
	IN BOOLEAN ReturnSingleEntry,
	IN PUNICODE_STRING FileName OPTIONAL,
	IN BOOLEAN RestartScan)
{
	asm(
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x3E904206 \n"
		"call _VAV_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x3E904206 \n"
		"call _VAV_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xb \n"
	"push_argument_3E904206: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_3E904206 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_3E904206] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_3E904206 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_3E904206: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_3E904206: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
	);
}

__declspec(naked) NTSTATUS VAVNtQueryInformationFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass)
{
	asm(
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xD9C3D163 \n"
		"call _VAV_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xD9C3D163 \n"
		"call _VAV_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_D9C3D163: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_D9C3D163 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_D9C3D163] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_D9C3D163 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_D9C3D163: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_D9C3D163: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
	);
}

__declspec(naked) NTSTATUS VAVNtQueryInformationProcess(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL)
{
	asm(
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x5D867214 \n"
		"call _VAV_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x5D867214 \n"
		"call _VAV_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_5D867214: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_5D867214 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_5D867214] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_5D867214 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_5D867214: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_5D867214: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
	);
}

__declspec(naked) NTSTATUS VAVNtQueryInformationThread(
	IN HANDLE ThreadHandle,
	IN THREADINFOCLASS ThreadInformationClass,
	OUT PVOID ThreadInformation,
	IN ULONG ThreadInformationLength,
	OUT PULONG ReturnLength OPTIONAL)
{
	asm(
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x8696C037 \n"
		"call _VAV_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x8696C037 \n"
		"call _VAV_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_8696C037: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_8696C037 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_8696C037] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_8696C037 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_8696C037: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_8696C037: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
	);
}

__declspec(naked) NTSTATUS VAVNtCreateSection(
	OUT PHANDLE SectionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PLARGE_INTEGER MaximumSize OPTIONAL,
	IN ULONG SectionPageProtection,
	IN ULONG AllocationAttributes,
	IN HANDLE FileHandle OPTIONAL)
{
	asm(
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x12CD321F \n"
		"call _VAV_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x12CD321F \n"
		"call _VAV_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x7 \n"
	"push_argument_12CD321F: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_12CD321F \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_12CD321F] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_12CD321F \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_12CD321F: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_12CD321F: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
	);
}

__declspec(naked) NTSTATUS VAVNtOpenSection(
	OUT PHANDLE SectionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes)
{
	asm(
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x4A82702F \n"
		"call _VAV_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x4A82702F \n"
		"call _VAV_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_4A82702F: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_4A82702F \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_4A82702F] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_4A82702F \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_4A82702F: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_4A82702F: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
	);
}

__declspec(naked) NTSTATUS VAVNtMapViewOfSection(
	IN HANDLE SectionHandle,
	IN HANDLE ProcessHandle,
	IN OUT PVOID BaseAddress,
	IN ULONG ZeroBits,
	IN SIZE_T CommitSize,
	IN OUT PLARGE_INTEGER SectionOffset OPTIONAL,
	IN OUT PSIZE_T ViewSize,
	IN SECTION_INHERIT InheritDisposition,
	IN ULONG AllocationType,
	IN ULONG Win32Protect)
{
	asm(
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xB2ADD637 \n"
		"call _VAV_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xB2ADD637 \n"
		"call _VAV_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xa \n"
	"push_argument_B2ADD637: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_B2ADD637 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_B2ADD637] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_B2ADD637 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_B2ADD637: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_B2ADD637: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
	);
}

__declspec(naked) NTSTATUS VAVNtUnmapViewOfSection(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress)
{
	asm(
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xF7E70F8D \n"
		"call _VAV_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xF7E70F8D \n"
		"call _VAV_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_F7E70F8D: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_F7E70F8D \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_F7E70F8D] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_F7E70F8D \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_F7E70F8D: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_F7E70F8D: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
	);
}

__declspec(naked) NTSTATUS VAVNtAdjustPrivilegesToken(
	IN HANDLE TokenHandle,
	IN BOOLEAN DisableAllPrivileges,
	IN PTOKEN_PRIVILEGES NewState OPTIONAL,
	IN ULONG BufferLength,
	OUT PTOKEN_PRIVILEGES PreviousState OPTIONAL,
	OUT PULONG ReturnLength OPTIONAL)
{
	asm(
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x63D45554 \n"
		"call _VAV_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x63D45554 \n"
		"call _VAV_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_63D45554: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_63D45554 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_63D45554] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_63D45554 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_63D45554: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_63D45554: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
	);
}

__declspec(naked) NTSTATUS VAVNtDeviceIoControlFile(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG IoControlCode,
	IN PVOID InputBuffer OPTIONAL,
	IN ULONG InputBufferLength,
	OUT PVOID OutputBuffer OPTIONAL,
	IN ULONG OutputBufferLength)
{
	asm(
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x24BE1818 \n"
		"call _VAV_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x24BE1818 \n"
		"call _VAV_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xa \n"
	"push_argument_24BE1818: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_24BE1818 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_24BE1818] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_24BE1818 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_24BE1818: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_24BE1818: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
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
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xA48F38B7 \n"
		"call _VAV_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xA48F38B7 \n"
		"call _VAV_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_A48F38B7: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_A48F38B7 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_A48F38B7] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_A48F38B7 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_A48F38B7: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_A48F38B7: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
	);
}

__declspec(naked) NTSTATUS VAVNtWaitForMultipleObjects(
	IN ULONG Count,
	IN PHANDLE Handles,
	IN WAIT_TYPE WaitType,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER Timeout OPTIONAL)
{
	asm(
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x41DD7973 \n"
		"call _VAV_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x41DD7973 \n"
		"call _VAV_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_41DD7973: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_41DD7973 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_41DD7973] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_41DD7973 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_41DD7973: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_41DD7973: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
	);
}

#endif
