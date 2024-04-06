#pragma once

// Code below is adapted from @modexpblog. Read linked article for more details.
// https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams

#ifndef VAV_HEADER_H_
#define VAV_HEADER_H_

#include <windows.h>

#ifndef _NTDEF_
typedef _Return_type_success_(return >= 0) LONG NTSTATUS;
typedef NTSTATUS* PNTSTATUS;
#endif

#define VAV_SEED 0x6D8D5A5A
#define VAV_ROL8(v) (v << 8 | v >> 24)
#define VAV_ROR8(v) (v >> 8 | v << 24)
#define VAV_ROX8(v) ((VAV_SEED % 2) ? VAV_ROL8(v) : VAV_ROR8(v))
#define VAV_MAX_ENTRIES 600
#define VAV_RVA2VA(Type, DllBase, Rva) (Type)((ULONG_PTR) DllBase + Rva)

// Typedefs are prefixed to avoid pollution.

typedef struct _VAV_SYSCALL_ENTRY
{
    DWORD Hash;
    DWORD Address;
	PVOID SyscallAddress;
} VAV_SYSCALL_ENTRY, *PVAV_SYSCALL_ENTRY;

typedef struct _VAV_SYSCALL_LIST
{
    DWORD Count;
    VAV_SYSCALL_ENTRY Entries[VAV_MAX_ENTRIES];
} VAV_SYSCALL_LIST, *PVAV_SYSCALL_LIST;

typedef struct _VAV_PEB_LDR_DATA {
	BYTE Reserved1[8];
	PVOID Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} VAV_PEB_LDR_DATA, *PVAV_PEB_LDR_DATA;

typedef struct _VAV_LDR_DATA_TABLE_ENTRY {
	PVOID Reserved1[2];
	LIST_ENTRY InMemoryOrderLinks;
	PVOID Reserved2[2];
	PVOID DllBase;
} VAV_LDR_DATA_TABLE_ENTRY, *PVAV_LDR_DATA_TABLE_ENTRY;

typedef struct _VAV_PEB {
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[2];
	PVAV_PEB_LDR_DATA Ldr;
} VAV_PEB, *PVAV_PEB;

DWORD VAV_HashSyscall(PCSTR FunctionName);
BOOL VAV_PopulateSyscallList();
EXTERN_C DWORD VAV_GetSyscallNumber(DWORD FunctionHash);
EXTERN_C PVOID VAV_GetSyscallAddress(DWORD FunctionHash);
EXTERN_C PVOID internal_cleancall_wow64_gate(VOID);
typedef VOID(KNORMAL_ROUTINE) (
	IN PVOID NormalContext,
	IN PVOID SystemArgument1,
	IN PVOID SystemArgument2);

typedef KNORMAL_ROUTINE* PKNORMAL_ROUTINE;

EXTERN_C NTSTATUS VAV_NtWriteVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN PVOID Buffer,
	IN SIZE_T NumberOfBytesToWrite,
	OUT PSIZE_T NumberOfBytesWritten OPTIONAL);

EXTERN_C NTSTATUS VAV_NtAllocateVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID * BaseAddress,
	IN ULONG ZeroBits,
	IN OUT PSIZE_T RegionSize,
	IN ULONG AllocationType,
	IN ULONG Protect);

EXTERN_C NTSTATUS VAVNtQueueApcThread(
	IN HANDLE ThreadHandle,
	IN PKNORMAL_ROUTINE ApcRoutine,
	IN PVOID ApcArgument1 OPTIONAL,
	IN PVOID ApcArgument2 OPTIONAL,
	IN PVOID ApcArgument3 OPTIONAL);

EXTERN_C NTSTATUS VAVNtTestAlert();

EXTERN_C NTSTATUS VAV_NtProtectVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID * BaseAddress,
	IN OUT PSIZE_T RegionSize,
	IN ULONG NewProtect,
	OUT PULONG OldProtect);

#endif
