// Ror13Calc.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <windows.h>
DWORD HashROR13A(_In_ LPCSTR sz)
{
	DWORD dwVal, dwHash = 0;
	while (*sz) {
		dwVal = (DWORD)*sz++;
		dwHash = (dwHash >> 13) | (dwHash << 19);
		dwHash += dwVal;
	}
	return dwHash;
}
LPCSTR szGenTable[] = {
    "CloseHandle",
    "CreatePipe",
    "CreateProcessA",
    "CreateThread",
    "GetExitCodeProcess",
    "GetLastError",
    "LocalAlloc",
    "LocalFree",
    "ReadFile",
    "Sleep",
    "WriteFile",
	"GetProcAddress",
	"GetModuleHandleA",
	"VirtualAlloc",
	"VirtualProtect",
	"CreateFileW",
	"CloseHandle",
	"VirtualFree",
};
int main(_In_ unsigned int argc, _In_ char* argv[])
{
	if (argc!=2)
	{
		printf("usage:ror13calc <string>\r\n");
		
		for (auto i=0;i<ARRAYSIZE(szGenTable);i++)
		{
			auto hash = HashROR13A(szGenTable[i]);
			printf("#define H_%s 0x%x\r\n", szGenTable[i], hash);
		}
		return 1;
	}
	
	auto hash = HashROR13A(argv[1]);
	printf("#define H_%s 0x%x\r\n", argv[1], hash);
    return 0;
}

