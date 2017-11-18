#pragma once
//#include "stdafx.h"

namespace usr::util
{
	void get_all_privilege();
	void alloc_cmd_window();
	VOID DbgPrintMsg(char *msg);
	void hex2string(_tstring &string_, LPVOID data_, std::size_t size_);
	void string2hex(_tstring string_, std::vector<BYTE> &data_);
	//DWORD32 rot13
	DWORD32 crc32(LPVOID data_, std::size_t size_);
	VOID Util_SHA256(_In_ PBYTE pb, _In_ DWORD cb, _Out_ __bcount(32) PBYTE pbHash);
	//
	bool is_process_bit64(DWORD process_id);
	//
	DWORD get_main_tid(DWORD process_id);
	//bool crack_crc32_for_dwordptr
	void loadfile2vec(_tstring file_name, std::vector<BYTE> &data_);
	void vec2savefile(_tstring file_name, const std::vector<BYTE> _data);
	DWORD GetSaveName(HINSTANCE hInstance, TCHAR* outbuf, const TCHAR* filter, const TCHAR* title);
	DWORD GetOpenName(HINSTANCE hInstance, TCHAR* outbuf, const TCHAR* filter, const TCHAR* title);
}