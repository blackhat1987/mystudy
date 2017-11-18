#include "stdafx.h"
#include <commdlg.h>
namespace usr::util
{
	void get_all_privilege()
	{
		using namespace ntdll;
		for (USHORT i = 0; i < 0x100; i++)
		{
			BOOLEAN Old;
			RtlAdjustPrivilege(i, TRUE, FALSE, &Old);
		}
	}
	void alloc_cmd_window()
	{
		AllocConsole();
		//SetConsoleTitle(_T("Êä³ö"));
		AttachConsole(GetCurrentProcessId());

		FILE* pFile = nullptr;
		freopen_s(&pFile, "CON", "r", stdin);
		freopen_s(&pFile, "CON", "w", stdout);
		freopen_s(&pFile, "CON", "w", stderr);
	}
	VOID DbgPrintMsg(char *msg)
	{
#ifdef _DEBUG
		setlocale(LC_CTYPE, "");
		DWORD eMsgLen, errNum = GetLastError();
		LPTSTR lpvSysMsg;

		if (msg)
			printf("%s: ", msg);
		eMsgLen = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
			FORMAT_MESSAGE_FROM_SYSTEM,
			NULL, errNum, MAKELANGID(0x00, 0x01),
			(LPTSTR)&lpvSysMsg, 0, NULL);
		if (eMsgLen > 0)
			_ftprintf(stderr, _T("%d %s\n"), errNum, lpvSysMsg);
		else
			_ftprintf(stderr, _T("Error %d\n"), errNum);
		if (lpvSysMsg != NULL)
			LocalFree(lpvSysMsg);
#endif
	}

	void hex2string(_tstring &string_, LPVOID data_, std::size_t size_)
	{
		string_ = _T("");
		const TCHAR IntegerToChar[] = _T("0123456789abcdef"); /*0-16*/
		auto buffer_ = reinterpret_cast<PUCHAR>(data_);
		for (SIZE_T i = 0; i < size_; i++)
		{
			TCHAR szString[3] = {};
			szString[0] = IntegerToChar[buffer_[i] >> 4];
			szString[1] = IntegerToChar[buffer_[i] & 0xf];
			string_ += szString;
		}
		return;
	}
	void string2hex(_tstring string_, std::vector<BYTE> &data_)
	{
		const int CharToInteger[256] =
		{
			-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 0 - 15 */
			-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 16 - 31 */
			36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, /* ' ' - '/' */
			0, 1, 2, 3, 4, 5, 6, 7, 8, 9, /* '0' - '9' */
			52, 53, 54, 55, 56, 57, 58, /* ':' - '@' */
			10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, /* 'A' - 'Z' */
			59, 60, 61, 62, 63, 64, /* '[' - '`' */
			10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, /* 'a' - 'z' */
			65, 66, 67, 68, -1, /* '{' - 127 */
			-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 128 - 143 */
			-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 144 - 159 */
			-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 160 - 175 */
			-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 176 - 191 */
			-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 192 - 207 */
			-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 208 - 223 */
			-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 224 - 239 */
			-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 /* 240 - 255 */
		};
		auto length = string_.length() / 2;
		data_.resize(length);
		for (SIZE_T i = 0; i < length; i++)
		{
			data_[i] =
				(UCHAR)(CharToInteger[(UCHAR)string_[i * 2]] << 4) +
				(UCHAR)CharToInteger[(UCHAR)string_[i * 2 + 1]];
		}
		return;
	}
	DWORD GetOpenName(HINSTANCE hInstance, TCHAR* outbuf, const TCHAR* filter, const TCHAR* title)
	{
		OPENFILENAME ofn;
		memset(&ofn, 0, sizeof(OPENFILENAME));

		TCHAR buf[MAX_PATH + 2] = {};
		GetModuleFileName(hInstance, buf, MAX_PATH);

		TCHAR* tmp = StrRChr(buf, NULL, L'\\');
		if (tmp != 0)
		{
			*tmp = 0;
			ofn.lpstrInitialDir = buf;
		}

		ofn.hInstance = hInstance;
		ofn.hwndOwner = NULL;
		ofn.lStructSize = sizeof(OPENFILENAME);
		ofn.lpstrFilter = filter;
		ofn.nFilterIndex = 1;
		ofn.lpstrFile = outbuf;
		ofn.lpstrFile[0] = 0;
		ofn.lpstrFile[1] = 0;
		ofn.nMaxFile = MAX_PATH;
		ofn.lpstrTitle = title;
		ofn.Flags = OFN_EXPLORER | OFN_DONTADDTORECENT | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY | OFN_LONGNAMES | OFN_NONETWORKBUTTON | OFN_PATHMUSTEXIST;

		return GetOpenFileName(&ofn);
	}
	DWORD GetSaveName(HINSTANCE hInstance, TCHAR* outbuf, const TCHAR* filter, const TCHAR* title)
	{
		OPENFILENAME ofn;
		memset(&ofn, 0, sizeof(OPENFILENAME));

		TCHAR buf[MAX_PATH + 2] = {};
		GetModuleFileName(hInstance, buf, MAX_PATH);

		TCHAR* tmp = StrRChr(buf, NULL, L'\\');
		if (tmp != 0)
		{
			*tmp = 0;
			ofn.lpstrInitialDir = buf;
		}

		ofn.hInstance = hInstance;
		ofn.hwndOwner = NULL;
		ofn.lStructSize = sizeof(OPENFILENAME);
		ofn.lpstrFilter = filter;
		ofn.nFilterIndex = 1;
		ofn.lpstrFile = outbuf;
		ofn.lpstrFile[0] = 0;
		ofn.lpstrFile[1] = 0;
		ofn.nMaxFile = MAX_PATH;
		ofn.lpstrTitle = title;
		ofn.Flags = OFN_EXPLORER | OFN_DONTADDTORECENT |OFN_LONGNAMES | OFN_NONETWORKBUTTON ;

		return GetSaveFileName(&ofn);
	}

	void loadfile2vec(_tstring file_name, std::vector<BYTE> &data_)
	{
		auto file = std::experimental::make_unique_resource(
			CreateFile(file_name.c_str(), GENERIC_READ, FILE_SHARE_READ,
				nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr),
			&CloseHandle
		);
		auto _handle = file.get();
		if (_handle)
		{
			auto file_size = GetFileSize(_handle, nullptr);
			data_.resize(file_size);
			std::uninitialized_fill_n(&data_[0], file_size, 0);
			DWORD read_size = 0;
			auto bRet= ReadFile(_handle, &data_[0], file_size, &read_size, nullptr);
		}
	}
	void vec2savefile(_tstring file_name, const std::vector<BYTE> _data)
	{
		auto file = std::experimental::make_unique_resource(
			CreateFile(file_name.c_str(), GENERIC_WRITE, FILE_SHARE_READ,
				nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr),
			&CloseHandle
		);
		auto _handle = file.get();
		if (_handle)
		{
			DWORD write_size = 0;
			auto bRet = WriteFile(_handle, &_data[0], _data.size(), &write_size, nullptr);
		}
	}
	bool is_process_bit64(DWORD process_id)
	{
		bool isX86 = false;
#ifndef _WIN64  
		isX86 = GetProcAddress(GetModuleHandle(TEXT("ntdll")), "NtWow64DebuggerCall") == nullptr ? true : false;
#endif  
		if (isX86)
			return false;
		auto _process = std::experimental::make_unique_resource(
			OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)process_id),
			&CloseHandle
		);
		if (!_process.get())
		{
			return false;
		}
		using ISWOW64PROCESS = decltype(&IsWow64Process);
		ISWOW64PROCESS fnIsWow64Process;
		BOOL isWow64 = TRUE;
		fnIsWow64Process = (ISWOW64PROCESS)GetProcAddress(GetModuleHandle(TEXT("kernel32")), "IsWow64Process");
		if (fnIsWow64Process != nullptr)
			fnIsWow64Process(_process.get(), &isWow64);
		return !isWow64;
	}

	PVOID get_sys_info(DWORD32 sysinfo)
	{
		PVOID p_ret = nullptr;
		auto cbBuffer = 0x5000UL;
		auto x = false;
		auto error = false;
		p_ret = malloc(cbBuffer);
		if (!p_ret)
		{
			return nullptr;
		}
		while (x == false)
		{
			int ret = ntdll::ZwQuerySystemInformation(
				(ntdll::SYSTEM_INFORMATION_CLASS)sysinfo,
				p_ret, 
				cbBuffer,
				0);
			if (ret < 0)
			{
				if (ret == STATUS_INFO_LENGTH_MISMATCH)
				{
					cbBuffer = cbBuffer + cbBuffer;
					free(p_ret);
					p_ret = malloc(cbBuffer);
					if (!p_ret) return nullptr;
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
		if (error==false)
		{
			return p_ret;
		}
		if (p_ret)
		{
			free(p_ret);
		}
		return nullptr;
	}
	DWORD get_main_tid(DWORD process_id)
	{
		auto sysinfo = get_sys_info(DWORD32(ntdll::SystemExtendedProcessInformation));
		if (!sysinfo)
		{
			return 0;
		}
		auto exit1 = std::experimental::make_scope_exit([&]() {
			if (sysinfo)
				free(sysinfo);
		});
		auto p = reinterpret_cast<ntdll::PSYSTEM_PROCESS_INFORMATION>(sysinfo);
		while (1)
		{
			if (p->UniqueProcessId == (HANDLE)process_id)
			{
				auto ThreadId = (DWORD)p->Threads[0].ClientId.UniqueThread;
				return ThreadId;
			}
			if (p->NextEntryOffset == 0) break;
			p = reinterpret_cast<ntdll::PSYSTEM_PROCESS_INFORMATION>((uint8_t*)p + (p->NextEntryOffset));
		}
		return 0;
	}

	DWORD32 crc32(LPVOID data_, std::size_t size_)
	{
		return ntdll::RtlComputeCrc32(0, data_, size_);
	}

	VOID Util_SHA256(_In_ PBYTE pb, _In_ DWORD cb, _Out_ __bcount(32) PBYTE pbHash)
	{
		BCRYPT_ALG_HANDLE hAlg = NULL;
		BCRYPT_HASH_HANDLE hHash = NULL;
		BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
		BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
		BCryptHashData(hHash, pb, cb, 0);
		BCryptFinishHash(hHash, pbHash, 32, 0);
		BCryptDestroyHash(hHash);
		BCryptCloseAlgorithmProvider(hAlg, 0);
	}
}