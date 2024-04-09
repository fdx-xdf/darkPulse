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

#define VAV_SEED 0x1764C2B3
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
typedef struct _SYSTEM_HANDLE
{
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _IO_STATUS_BLOCK
{
	union
	{
		NTSTATUS Status;
		VOID*    Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG HandleCount;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef VOID(KNORMAL_ROUTINE) (
	IN PVOID NormalContext,
	IN PVOID SystemArgument1,
	IN PVOID SystemArgument2);

typedef struct _PS_ATTRIBUTE
{
	ULONG  Attribute;
	SIZE_T Size;
	union
	{
		ULONG Value;
		PVOID ValuePtr;
	} u1;
	PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) { \
	(p)->Length = sizeof( OBJECT_ATTRIBUTES );        \
	(p)->RootDirectory = r;                           \
	(p)->Attributes = a;                              \
	(p)->ObjectName = n;                              \
	(p)->SecurityDescriptor = s;                      \
	(p)->SecurityQualityOfService = NULL;             \
}
#endif

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation = 0,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemProcessInformation = 5,
	SystemProcessorPerformanceInformation = 8,
	SystemHandleInformation = 16,
	SystemInterruptInformation = 23,
	SystemExceptionInformation = 33,
	SystemRegistryQuotaInformation = 37,
	SystemLookasideInformation = 45,
	SystemCodeIntegrityInformation = 103,
	SystemPolicyInformation = 134,
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

typedef enum _PROCESSINFOCLASS
{
	ProcessBasicInformation = 0,
	ProcessDebugPort = 7,
	ProcessWow64Information = 26,
	ProcessImageFileName = 27,
	ProcessBreakOnTermination = 29
} PROCESSINFOCLASS, *PPROCESSINFOCLASS;

typedef enum _WAIT_TYPE
{
	WaitAll = 0,
	WaitAny = 1
} WAIT_TYPE, *PWAIT_TYPE;

typedef VOID(NTAPI* PIO_APC_ROUTINE) (
	IN PVOID            ApcContext,
	IN PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG            Reserved);

typedef KNORMAL_ROUTINE* PKNORMAL_ROUTINE;

typedef enum _THREADINFOCLASS
{
	ThreadBasicInformation,
	ThreadTimes,
	ThreadPriority,
	ThreadBasePriority,
	ThreadAffinityMask,
	ThreadImpersonationToken,
	ThreadDescriptorTableEntry,
	ThreadEnableAlignmentFaultFixup,
	ThreadEventPair_Reusable,
	ThreadQuerySetWin32StartAddress,
	ThreadZeroTlsCell,
	ThreadPerformanceCount,
	ThreadAmILastThread,
	ThreadIdealProcessor,
	ThreadPriorityBoost,
	ThreadSetTlsArrayAddress,
	ThreadIsIoPending,
	ThreadHideFromDebugger,
	ThreadBreakOnTermination,
	MaxThreadInfoClass
} THREADINFOCLASS, *PTHREADINFOCLASS;

typedef enum _SECTION_INHERIT
{
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT, *PSECTION_INHERIT;

typedef enum _FILE_INFORMATION_CLASS
{
	FileDirectoryInformation = 1,
	FileFullDirectoryInformation = 2,
	FileBothDirectoryInformation = 3,
	FileBasicInformation = 4,
	FileStandardInformation = 5,
	FileInternalInformation = 6,
	FileEaInformation = 7,
	FileAccessInformation = 8,
	FileNameInformation = 9,
	FileRenameInformation = 10,
	FileLinkInformation = 11,
	FileNamesInformation = 12,
	FileDispositionInformation = 13,
	FilePositionInformation = 14,
	FileFullEaInformation = 15,
	FileModeInformation = 16,
	FileAlignmentInformation = 17,
	FileAllInformation = 18,
	FileAllocationInformation = 19,
	FileEndOfFileInformation = 20,
	FileAlternateNameInformation = 21,
	FileStreamInformation = 22,
	FilePipeInformation = 23,
	FilePipeLocalInformation = 24,
	FilePipeRemoteInformation = 25,
	FileMailslotQueryInformation = 26,
	FileMailslotSetInformation = 27,
	FileCompressionInformation = 28,
	FileObjectIdInformation = 29,
	FileCompletionInformation = 30,
	FileMoveClusterInformation = 31,
	FileQuotaInformation = 32,
	FileReparsePointInformation = 33,
	FileNetworkOpenInformation = 34,
	FileAttributeTagInformation = 35,
	FileTrackingInformation = 36,
	FileIdBothDirectoryInformation = 37,
	FileIdFullDirectoryInformation = 38,
	FileValidDataLengthInformation = 39,
	FileShortNameInformation = 40,
	FileIoCompletionNotificationInformation = 41,
	FileIoStatusBlockRangeInformation = 42,
	FileIoPriorityHintInformation = 43,
	FileSfioReserveInformation = 44,
	FileSfioVolumeInformation = 45,
	FileHardLinkInformation = 46,
	FileProcessIdsUsingFileInformation = 47,
	FileNormalizedNameInformation = 48,
	FileNetworkPhysicalNameInformation = 49,
	FileIdGlobalTxDirectoryInformation = 50,
	FileIsRemoteDeviceInformation = 51,
	FileUnusedInformation = 52,
	FileNumaNodeInformation = 53,
	FileStandardLinkInformation = 54,
	FileRemoteProtocolInformation = 55,
	FileRenameInformationBypassAccessCheck = 56,
	FileLinkInformationBypassAccessCheck = 57,
	FileVolumeNameInformation = 58,
	FileIdInformation = 59,
	FileIdExtdDirectoryInformation = 60,
	FileReplaceCompletionInformation = 61,
	FileHardLinkFullIdInformation = 62,
	FileIdExtdBothDirectoryInformation = 63,
	FileDispositionInformationEx = 64,
	FileRenameInformationEx = 65,
	FileRenameInformationExBypassAccessCheck = 66,
	FileMaximumInformation = 67,
} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;

typedef struct _PS_ATTRIBUTE_LIST
{
	SIZE_T       TotalLength;
	PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;


EXTERN_C NTSTATUS VAVNtTestAlert();


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

EXTERN_C NTSTATUS VAV_NtProtectVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID * BaseAddress,
	IN OUT PSIZE_T RegionSize,
	IN ULONG NewProtect,
	OUT PULONG OldProtect);

EXTERN_C NTSTATUS VAVNtQueueApcThread(
	IN HANDLE ThreadHandle,
	IN PKNORMAL_ROUTINE ApcRoutine,
	IN PVOID ApcArgument1 OPTIONAL,
	IN PVOID ApcArgument2 OPTIONAL,
	IN PVOID ApcArgument3 OPTIONAL);





#endif
