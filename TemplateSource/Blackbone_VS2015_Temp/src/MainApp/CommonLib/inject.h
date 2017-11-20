#pragma once
//#include "stdafx.h"

namespace usr::util::inject
{
	//static const BYTE x86shellcode[] = {};
	//static const BYTE x64shellcode[] = {};
	BOOL ThreadInjection(const WCHAR *dll_name, const WCHAR *processname);
	
}