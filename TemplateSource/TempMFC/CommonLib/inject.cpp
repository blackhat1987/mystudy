#include "stdafx.h"

namespace usr::util::inject {
	BOOL ThreadInjection(const WCHAR *dll_name, const WCHAR *processname)
	{
		TCHAR lpdllpath[MAX_PATH];
		GetFullPathName(dll_name, MAX_PATH, lpdllpath, nullptr);

		usr::util::snapshot::process_item item;
		item.process_name = std::wstring(processname);
		usr::util::snapshot::FindProcessByName(item);
		auto size = wcslen(lpdllpath) * sizeof(TCHAR);

		// open selected process
		auto hVictimProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, item.ProcessId);
		if (hVictimProcess == NULL) // check if process open failed
		{
			DbgPrintMsg("[!]Failed to open process");
			return FALSE;
		}
		// allocate memory in the remote process
		auto pNameInVictimProcess = VirtualAllocEx(hVictimProcess,
			nullptr,
			size,
			MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (pNameInVictimProcess == NULL) //Check if allocation failed
		{
			DbgPrintMsg("[!] allocation of memory failed, WFT?");
			return FALSE;
		}
		auto bStatus = WriteProcessMemory(hVictimProcess,
			pNameInVictimProcess,
			lpdllpath,
			size,
			nullptr);
		if (bStatus == 0)
		{
			DbgPrintMsg("[!] failed to write memory to the process");
			return FALSE;
		}

		auto hKernel32 = GetModuleHandle(L"kernel32.dll");
		if (hKernel32 == NULL)
		{
			DbgPrintMsg("[!] Unable to find Kernel32 in process, what the fuck did you do?");
			return FALSE;
		}

		auto LoadLibraryAddress = GetProcAddress(hKernel32, "LoadLibraryW");
		if (LoadLibraryAddress == NULL) //Check if GetProcAddress works; if not try some ugly as sin correction code
		{
			DbgPrintMsg("[-] Unable to find LoadLibraryW, What is this: Windows 2000?");
			DbgPrintMsg("[-] Trying LoadLibraryA");
			if ((LoadLibraryAddress = GetProcAddress(hKernel32, "LoadLibraryA")) == NULL)
			{
				DbgPrintMsg("[!] LoadLibraryA failed as well. You're on your own.");
				return FALSE;
			}
		}

		auto hThreadId = CreateRemoteThread(hVictimProcess,
			nullptr,
			0,
			reinterpret_cast<LPTHREAD_START_ROUTINE>(LoadLibraryAddress),
			pNameInVictimProcess,
			NULL,
			nullptr);
		if (hThreadId == NULL)
		{
			DbgPrintMsg("[!] failed to create remote process");
			return FALSE;
		}

		DbgPrintMsg("[+] waiting for thread to execute");
		WaitForSingleObject(hThreadId, INFINITE);
		DbgPrintMsg("[+] Done!!!! Closing handle\n");

		CloseHandle(hVictimProcess);
		VirtualFreeEx(hVictimProcess, pNameInVictimProcess, size, MEM_RELEASE);

		DbgPrintMsg("Injected Successfully");
		return TRUE;
	}
	
}