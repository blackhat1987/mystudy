#include <windows.h>
#pragma warning(disable:4152)


typedef unsigned __int64		QWORD, *PQWORD;

#define H_CloseHandle				0x0ffd97fb
#define H_CreatePipe				0x170c8f80
#define H_CreateProcessA			0x16b3fe72
#define H_CreateThread				0xca2bd06b
#define H_GetExitCodeProcess		0xac30ab74
#define H_GetLastError				0x75da1966
#define H_LocalAlloc				0x4c0297fa
#define H_LocalFree					0x5cbaeaf6
#define H_ReadFile					0x10fa6516
#define H_Sleep						0xdb2d49b0
#define H_WriteFile					0xe80a791f
//////////////////////////////////////////////////////////////////////////
#define H_GetProcAddress 0x7c0dfcaa
#define H_GetModuleHandleA 0xd3324904
#define H_VirtualAlloc 0x91afca54
#define H_VirtualProtect 0x7946c61b
#define H_CreateFileW 0x7c0017bb
#define H_VirtualFree 0x30633ac
//////////////////////////////////////////////////////////////////////////
typedef struct tdArgs
{
	DWORD64 r9;
	DWORD64 r8;
	DWORD64 rdx;
	DWORD64 rcx;
	DWORD64 rsp;
}HOOKARGS,*PHOOKARGS;
void jmp_old_hook();
//////////////////////////////////////////////////////////////////////////
typedef struct tdUserShellFunctions {
	BOOL(WINAPI*CloseHandle)(
		_In_ HANDLE hObject
		);
	BOOL(WINAPI*CreatePipe)(
		_Out_    PHANDLE               hReadPipe,
		_Out_    PHANDLE               hWritePipe,
		_In_opt_ LPSECURITY_ATTRIBUTES lpPipeAttributes,
		_In_     DWORD                 nSize
		);
	BOOL(WINAPI*CreateProcessA)(
		_In_opt_    LPCSTR                lpApplicationName,
		_Inout_opt_ LPSTR                 lpCommandLine,
		_In_opt_    LPSECURITY_ATTRIBUTES lpProcessAttributes,
		_In_opt_    LPSECURITY_ATTRIBUTES lpThreadAttributes,
		_In_        BOOL                  bInheritHandles,
		_In_        DWORD                 dwCreationFlags,
		_In_opt_    LPVOID                lpEnvironment,
		_In_opt_    LPCSTR                lpCurrentDirectory,
		_In_        LPSTARTUPINFO         lpStartupInfo,
		_Out_       LPPROCESS_INFORMATION lpProcessInformation
		);
	HANDLE(WINAPI*CreateThread)(
		_In_opt_  LPSECURITY_ATTRIBUTES  lpThreadAttributes,
		_In_      SIZE_T                 dwStackSize,
		_In_      LPTHREAD_START_ROUTINE lpStartAddress,
		_In_opt_  LPVOID                 lpParameter,
		_In_      DWORD                  dwCreationFlags,
		_Out_opt_ LPDWORD                lpThreadId
		);
	BOOL(WINAPI*GetExitCodeProcess)(
		_In_  HANDLE  hProcess,
		_Out_ LPDWORD lpExitCode
		);
	DWORD(WINAPI*GetLastError)(void);
	HLOCAL(WINAPI*LocalAlloc)(
		_In_ UINT   uFlags,
		_In_ SIZE_T uBytes
		);
	HLOCAL(WINAPI*LocalFree)(
		_In_ HLOCAL hMem
		);
	BOOL(WINAPI*ReadFile)(
		_In_        HANDLE       hFile,
		_Out_       LPVOID       lpBuffer,
		_In_        DWORD        nNumberOfBytesToRead,
		_Out_opt_   LPDWORD      lpNumberOfBytesRead,
		_Inout_opt_ LPOVERLAPPED lpOverlapped
		);
	VOID(WINAPI*Sleep)(
		_In_ DWORD dwMilliseconds
		);
	BOOL(WINAPI*WriteFile)(
		_In_        HANDLE       hFile,
		_In_        LPCVOID      lpBuffer,
		_In_        DWORD        nNumberOfBytesToWrite,
		_Out_opt_   LPDWORD      lpNumberOfBytesWritten,
		_Inout_opt_ LPOVERLAPPED lpOverlapped
		);
	FARPROC
	(WINAPI*GetProcAddress)(
			_In_ HMODULE hModule,
			_In_ LPCSTR lpProcName
		);
	HMODULE
		(WINAPI*GetModuleHandleA)(
			_In_opt_ LPCSTR lpModuleName
		);
	LPVOID
	(WINAPI*VirtualAlloc)(
		_In_opt_ LPVOID lpAddress,
		_In_     SIZE_T dwSize,
		_In_     DWORD flAllocationType,
		_In_     DWORD flProtect
		);
	BOOL
	(WINAPI *VirtualProtect)(
		_In_ LPVOID lpAddress,
		_In_ SIZE_T dwSize,
		_In_ DWORD flNewProtect,
		_Out_ PDWORD lpflOldProtect
		);
	BOOL
	(WINAPI*VirtualFree)(
		_In_ LPVOID lpAddress,
		_In_ SIZE_T dwSize,
		_In_ DWORD dwFreeType
		);
	HANDLE
	(WINAPI*CreateFileW)(
		_In_ LPCWSTR lpFileName,
		_In_ DWORD dwDesiredAccess,
		_In_ DWORD dwShareMode,
		_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
		_In_ DWORD dwCreationDisposition,
		_In_ DWORD dwFlagsAndAttributes,
		_In_opt_ HANDLE hTemplateFile
		);
} USERSHELL_FUNCTIONS, *PUSERSHELL_FUNCTIONS;

DWORD HashROR13A(_In_ LPCSTR sz)
{
	DWORD dwVal, dwHash = 0;
	while(*sz) {
		dwVal = (DWORD)*sz++;
		dwHash = (dwHash >> 13) | (dwHash << 19);
		dwHash += dwVal;
	}
	return dwHash;
}

PVOID PEGetProcAddressH(_In_ HMODULE hModuleIn, _In_ DWORD dwProcNameH)
{
	ULONG_PTR hModule = (ULONG_PTR)hModuleIn;
	PDWORD pdwRVAAddrNames, pdwRVAAddrFunctions;
	PWORD pwNameOrdinals;
	DWORD i, dwFnIdx, dwHash;
	LPSTR sz;
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule; // dos header.
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(hModule + dosHeader->e_lfanew); // nt header
	PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)(ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + hModule);
	pdwRVAAddrNames = (PDWORD)(hModule + exp->AddressOfNames);
	pwNameOrdinals = (PWORD)(hModule + exp->AddressOfNameOrdinals);
	pdwRVAAddrFunctions = (PDWORD)(hModule + exp->AddressOfFunctions);
	for(i = 0; i < exp->NumberOfNames; i++) {
		sz = (LPSTR)(hModule + pdwRVAAddrNames[i]);
		dwHash = HashROR13A(sz);
		if(dwHash == dwProcNameH) {
			dwFnIdx = pwNameOrdinals[i];
			return (PVOID)(hModule + pdwRVAAddrFunctions[dwFnIdx]);
		}
	}
	return 0;
}

VOID UserShellInitializeFunctions(_In_ HMODULE hModuleKernel32, _Out_ PUSERSHELL_FUNCTIONS fnu)
{

	fnu->CloseHandle = PEGetProcAddressH(hModuleKernel32, H_CloseHandle);
	fnu->CreatePipe = PEGetProcAddressH(hModuleKernel32, H_CreatePipe);
	fnu->CreateProcessA = PEGetProcAddressH(hModuleKernel32, H_CreateProcessA);
	fnu->CreateThread = PEGetProcAddressH(hModuleKernel32, H_CreateThread);
	fnu->GetExitCodeProcess = PEGetProcAddressH(hModuleKernel32, H_GetExitCodeProcess);
	fnu->GetLastError = PEGetProcAddressH(hModuleKernel32, H_GetLastError);
	fnu->LocalAlloc = PEGetProcAddressH(hModuleKernel32, H_LocalAlloc);
	fnu->LocalFree = PEGetProcAddressH(hModuleKernel32, H_LocalFree);
	fnu->ReadFile = PEGetProcAddressH(hModuleKernel32, H_ReadFile);
	fnu->Sleep = PEGetProcAddressH(hModuleKernel32, H_Sleep);
	fnu->WriteFile = PEGetProcAddressH(hModuleKernel32, H_WriteFile);
	fnu->GetModuleHandleA = PEGetProcAddressH(hModuleKernel32, H_GetModuleHandleA);
	fnu->GetProcAddress = PEGetProcAddressH(hModuleKernel32, H_GetProcAddress);
	fnu->VirtualAlloc = PEGetProcAddressH(hModuleKernel32, H_VirtualAlloc);
	fnu->VirtualProtect = PEGetProcAddressH(hModuleKernel32, H_VirtualProtect);
	fnu->VirtualFree = PEGetProcAddressH(hModuleKernel32, H_VirtualFree);
	fnu->CreateFileW = PEGetProcAddressH(hModuleKernel32, H_CreateFileW);
}

/*
  1.要用到哪个函数，先算hash
  2.在PUSERSHELL_FUNCTIONS添加函数指针
  3.在UserShellInitializeFunctions给结构体赋真实值
*/
VOID hookcode(PHOOKARGS arg1, ULONG_PTR lpBaseKernel32)
{
    //arg1是r9,  r8, rdx, rcx, rsp，此内容与my_hook开头push的函数有关。
    UNREFERENCED_PARAMETER(arg1);
	HLOCAL(WINAPI*fnLocalAlloc)(UINT, SIZE_T);
	PUSERSHELL_FUNCTIONS funSets;       //shellcode需要函数的集合的结构体
	fnLocalAlloc = PEGetProcAddressH((HMODULE)lpBaseKernel32, H_LocalAlloc);//获得LocalAlloc地址
	funSets = (PUSERSHELL_FUNCTIONS)fnLocalAlloc(LMEM_ZEROINIT, sizeof(USERSHELL_FUNCTIONS));
	UserShellInitializeFunctions((HMODULE)lpBaseKernel32, funSets);

	//下面只是shellcode的一个测试用例
    HANDLE hFile;
    WCHAR szFile[MAX_PATH];
	szFile[0] = L'e';
	szFile[1] = L':';
	szFile[2] = L'\\';
	szFile[3] = L'S';
	szFile[4] = L'.';
	szFile[5] = L't';
	szFile[6] = L'x';
	szFile[7] = L't';
	szFile[8] = L'\0';
	if (funSets->CreateFileW)
	{
		DWORD dwWrite;
		dwWrite = 0;
		hFile = funSets->CreateFileW(szFile, GENERIC_ALL, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		funSets->WriteFile(hFile, szFile, sizeof(szFile), &dwWrite, NULL);
		funSets->CloseHandle(hFile);
	}

    /*如果你使用了hook，
      则要调用原始函数也就是entry.asm中的jmp_old_hook
	  定义fn类型，然后强制转化调用就行了,如*/

	//VOID(WINAPI*ff)(UINT);
	//ff = jmp_old_hook;
	//ff(999);
}
