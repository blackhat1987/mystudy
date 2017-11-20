#include "stdafx.h"

namespace usr::util::snapshot
{
	void get_snapshot_process(std::vector<process_item> &_process)
	{
		get_all_privilege();
		unsigned long cbBuffer = 0x5000;  //Initial Buffer Size
		void* Buffer = (void*)malloc(cbBuffer);
		auto exit1 = std::experimental::make_scope_exit([&]() {
			if (Buffer)
				free(Buffer);
		});
		if (Buffer == 0) return;
		bool x = false;
		bool error = false;
		while (x == false)
		{
			int ret = ntdll::NtQuerySystemInformation(ntdll::SystemExtendedProcessInformation, Buffer, cbBuffer, 0);
			if (ret < 0)
			{
				if (ret == STATUS_INFO_LENGTH_MISMATCH)
				{
					cbBuffer = cbBuffer + cbBuffer;
					free(Buffer);
					Buffer = (void*)malloc(cbBuffer);
					if (Buffer == 0) return;
					x = false;
				}
				else
				{
					x = true;
					error = true;
				}
			}
			else x = true;
		}
		if (error == false)
		{
			ntdll::SYSTEM_PROCESS_INFORMATION* p = (ntdll::SYSTEM_PROCESS_INFORMATION*)Buffer;
			while (1)
			{
				auto min = [](auto a, auto b) {
					return (((a) < (b)) ? (a) : (b)); };

				WCHAR szName[MAX_PATH] = { 0 };
				RtlCopyMemory(szName, p->ImageName.Buffer, min(p->ImageName.MaximumLength, 512));
				process_item item = {};
				item.ProcessId = (DWORD_PTR)p->UniqueProcessId;
				item.process_name = _tstring(szName);
				_process.push_back(item);
				if (p->NextEntryOffset == 0) break;
				p = (ntdll::SYSTEM_PROCESS_INFORMATION*)((unsigned char*)p + (p->NextEntryOffset));
			}
		}
	}
	BOOL FindProcessByName(process_item &item)
	{
		auto hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
		if (hSnapshot == INVALID_HANDLE_VALUE)
			return FALSE;

		item.ProcessId = 0;

		PROCESSENTRY32 pe = { sizeof(pe) };
		if (::Process32First(hSnapshot, &pe)) {
			do {
				if (_wcsicmp(pe.szExeFile, item.process_name.c_str()) == 0) {
					item.ProcessId = pe.th32ProcessID;
					THREADENTRY32 te = { sizeof(te) };
					if (Thread32First(hSnapshot, &te)) {
						do {
							if (te.th32OwnerProcessID == item.ProcessId) {
								item.tids.push_back(te.th32ThreadID);
							}
						} while (Thread32Next(hSnapshot, &te));
					}
					break;
				}
			} while (Process32Next(hSnapshot, &pe));
		}
		CloseHandle(hSnapshot);
		return item.ProcessId > 0 && !item.tids.empty();
	}
}

	

