#pragma once
//#include "stdafx.h"
#include "util.h"
#include "snapshot_process.h"
#include "Process.h"
#include "Memory.h"
#include "inject.h"
#include "Services.h"

///git clone https://github.com/Microsoft/vcpkg.git
///pushd vcpkg
///.\bootstrap-vcpkg.bat
///.\vcpkg integrate install

//网络
#define ASIO_STANDALONE
#include "asio.hpp"
#include "pkg_msg.h"
#include "client.h"
#include "server.h"

#include "lsp_helper.h"

//vcpkg install msgpack msgpack:x64-windows
#include <msgpack.hpp>
//https http
//vcpkg install cpr cpr:x64-windows
//需要把头文件copy一下
//#include <cpr\cpr.h>

//PE文件库
//LIEF
//popd
//git clone https://github.com/lief-project/LIEF.git
//cd LIEF
//cmake -G"Visual Studio 14 2015"
//devenv LIEF.sln
#include <iso646.h>
#include <LIEF\LIEF.hpp>
#if defined(_WIN64)
#pragma comment(lib,"../LIEF-0.7.0-win64/lib/LIEF.lib")
#else
#pragma comment(lib,"../LIEF-0.7.0-win32/lib/LIEF.lib")
#endif

//LDR
#include "ldr_tools.h"
#include "ldr_patch_loader.h"
#include "ldr_module.h"

//hijack
#include "dll_hijack.h"