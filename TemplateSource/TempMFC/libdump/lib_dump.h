#pragma once
#include "stdafx.h"

namespace usr
{
	namespace libdump
	{
#pragma warning(push)
#pragma warning(disable:4307)
#ifdef _AMD64_
		static const auto dump_header_magic = hash_string::hash_const<hash_string::hash("dump_header64")>::value;
#else
		static const auto dump_header_magic = hash_string::hash_const<hash_string::hash("dump_header32")>::value;
#endif
		static const auto dump_block_magic = hash_string::hash_const<hash_string::hash("dump_block")>::value;
#pragma warning(pop)
#pragma pack(1)
		using dump_file_header = struct
		{
			DWORD64 magic_dump_header;
#ifdef _AMD64_
			BOOL _is64;
			WOW64_CONTEXT _ctx86;
			CONTEXT _ctx64;
#else
			CONTEXT _ctx86;
#endif
			DWORD64 StackBase;
			DWORD64 StackSize;
			DWORD64 FSBase;
			DWORD64 GSBase;
			DWORD64 GdtBase;
			UINT _dump_block_count;
		};
		using dump_block = struct
		{
			DWORD64 _magic_block_header;
			DWORD64 _virtual_address;
			DWORD64 _size;
		};
#pragma pack()
		using dump_blockex = struct
		{
			dump_block _dmp_block;
			std::vector<BYTE> _save_data;
		};
		class dump_file
		{
		public:
			dump_file()
			{
				_dmp = {};
			};
			~dump_file()
			{

			};
		public:
			bool load_file(_tstring file_name)
			{
				std::vector<BYTE> _data;
				usr::util::loadfile2vec(file_name, _data);
				if (_data.size() < sizeof(dump_file_header))
				{
					return false;
				}
				auto p_dump_buffer = reinterpret_cast<uint8_t*>(_data.data());
				auto p_dmp_header = reinterpret_cast<dump_file_header*>(p_dump_buffer);
				if (p_dmp_header->magic_dump_header != dump_header_magic)
				{
					return false;
				}
				_dmp = *p_dmp_header;
				p_dump_buffer += sizeof(dump_file_header);

				for (auto i = 0UL; i < p_dmp_header->_dump_block_count; i++)
				{
					auto p_dump_block = reinterpret_cast<dump_block*>(p_dump_buffer);
					if (p_dump_block->_magic_block_header != dump_block_magic)
					{
						return false;
					}
					p_dump_buffer += sizeof(dump_block);

					dump_blockex block_ext = {};
					auto _block_size = p_dump_block->_size;
					block_ext._save_data.resize(p_dump_block->_size);
					std::uninitialized_fill_n(&block_ext._save_data[0], _block_size, 0);
					block_ext._dmp_block = *p_dump_block;
					RtlCopyMemory(&block_ext._save_data[0], p_dump_buffer, _block_size);
					p_dump_buffer += _block_size;
					_dmpblock.push_back(block_ext);
				}

				return true;
			}
			bool save_file(_tstring file_name)
			{
				std::vector<BYTE> _file_data;
				auto _file_size = 0ULL;
				_file_size += sizeof(dump_file_header);
				if (_dmp._dump_block_count < 1)
				{
					return false;
				}
				_file_size += sizeof(dump_block)*_dmp._dump_block_count;

				for (auto _block : _dmpblock)
				{
					_file_size += _block._dmp_block._size;
				}
				_file_data.resize(_file_size);
				std::uninitialized_fill_n(&_file_data[0], _file_size, 0);
				auto _data_offset = 0ULL;
				RtlCopyMemory(&_file_data[_data_offset], &_dmp, sizeof(dump_file_header));
				_data_offset += sizeof(dump_file_header);
				for (auto i = 0UL; i < _dmp._dump_block_count; i++)
				{
					auto _copy_size = _dmpblock[i]._dmp_block._size;
					RtlCopyMemory(&_file_data[_data_offset], &_dmpblock[i]._dmp_block, sizeof(dump_block));
					_data_offset += sizeof(dump_block);
					RtlCopyMemory(&_file_data[_data_offset], &_dmpblock[i]._save_data[0], _copy_size);
					_data_offset += _copy_size;
				}
				usr::util::vec2savefile(file_name, _file_data);
				return true;
			}
			bool dump_process(DWORD process_id)
			{
				_dmp.magic_dump_header = dump_header_magic;
				auto _process = std::experimental::make_unique_resource(
					OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)process_id),
					&CloseHandle
				);
				auto _handle = _process.get();
				if (!_handle
					|| _handle == INVALID_HANDLE_VALUE)
				{
					return false;
				}
				///暂停进程
				auto ns = ntdll::ZwSuspendProcess(_handle);
				if (!NT_SUCCESS(ns))
				{
					return false;
				}
				{
					auto exit1 = std::experimental::make_scope_exit(
						[&]() {ntdll::ZwResumeProcess(_handle); });
					///获取进程是否64
					auto is_bit_64 = usr::util::is_process_bit64(process_id);
					if (is_bit_64)
					{
						_dmp._is64 = TRUE;
					}
					///获得主线程id
					auto main_tid = usr::util::get_main_tid(process_id);
					if (!main_tid)
					{
						return false;
					}
					///获得主线程wow64context和context
					auto _thread = std::experimental::make_unique_resource(
						OpenThread(THREAD_ALL_ACCESS, FALSE, main_tid),
						&CloseHandle
					);
					auto _h_thread = _thread.get();
					if (!_h_thread
						|| _h_thread == INVALID_HANDLE_VALUE)
					{
						return false;
					}
#ifdef _AMD64_
					_dmp._ctx64.ContextFlags = CONTEXT_ALL;
					if (!GetThreadContext(_h_thread, &_dmp._ctx64))
					{
						return false;
					}
					std::cout << std::hex << _dmp._ctx64.SegFs << " " << _dmp._ctx64.SegGs << "\r\n";
					if (!is_bit_64)
					{
						_dmp._ctx86.ContextFlags = WOW64_CONTEXT_ALL;
						if (!Wow64GetThreadContext(_h_thread, &_dmp._ctx86))
						{
							return false;
						}
						std::cout << std::hex << _dmp._ctx86.SegFs << " " << _dmp._ctx86.SegGs << "\r\n";
					}

#else
					_dmp._ctx86.ContextFlags = CONTEXT_ALL;
					if (!GetThreadContext(_h_thread, &_dmp._ctx86))
					{
						return false;
					}

#endif
					///获得FS和GS的Base
#ifdef _AMD64_
					_dmp.GdtBase = 0xC0000000UL;
					{
						//差TIB的地址然后读出来
						ntdll::THREAD_BASIC_INFORMATION threadinfo = {};
						ULONG dwRet = 0;
						auto ns = ntdll::ZwQueryInformationThread(_h_thread, ntdll::ThreadBasicInformation, &threadinfo, sizeof(threadinfo), &dwRet);
						if (!NT_SUCCESS(ns))
						{
							std::cout << "what ns=0x" << std::hex << ns << "\r\n";
						}
						NT_TIB64 tib = {};
						SIZE_T dwRead = 0;
						std::cout << std::hex << "TEB=0x" << DWORD64(threadinfo.TebBaseAddress) << "\r\n";
						ReadProcessMemory(_handle, threadinfo.TebBaseAddress, &tib, sizeof(tib), &dwRead);
						auto fsbase = tib.ExceptionList;
						auto gsbase = tib.Self;
						std::cout << std::hex << "FSBASE=0x" << fsbase << "\r\n";
						std::cout << std::hex << "GSBASE=0x" << gsbase << "\r\n";
						_dmp.FSBase = fsbase;
						_dmp.GSBase = gsbase;
					}
#else
					auto SegFS = _dmp._ctx86.SegFs;
					auto SegGS = _dmp._ctx86.SegGs;

					LDT_ENTRY selector_entry_fs = {};
					LDT_ENTRY selector_entry_gs = {};

					auto getfs_ok = GetThreadSelectorEntry(_h_thread, SegFS, &selector_entry_fs);
					auto getgs_ok = GetThreadSelectorEntry(_h_thread, SegGS, &selector_entry_gs);
					if (!getgs_ok ||
						!getfs_ok)
					{
						std::cout << "fuck" << "\r\n";
						return false;
					}
					auto fsbase = get_base(selector_entry_fs);
					auto gsbase = get_base(selector_entry_gs);
					std::cout << std::hex << "FSBASE=0x" << fsbase << "\r\n";
					std::cout << std::hex << "GSBASE=0x" << gsbase << "\r\n";
					_dmp.FSBase = fsbase;
					_dmp.GSBase = gsbase;
					_dmp.GdtBase = 0xc0000000UL;
#endif
					///获得内存分布
					SYSTEM_INFO si = {};
					GetSystemInfo(&si);
					PUCHAR addr = 0;
					auto max_addr = reinterpret_cast<PUCHAR>(si.lpMaximumApplicationAddress);
					std::cout << "max_address =0x" << std::hex << DWORD_PTR(max_addr) << "\r\n";
					while (addr < max_addr)
					{
						MEMORY_BASIC_INFORMATION meminfo = {};
						if (VirtualQueryEx(_handle, addr, &meminfo, sizeof(meminfo)) == 0)
						{
							addr += si.dwPageSize;
							std::cout << "BadAccess==0x" << std::hex << DWORD_PTR(addr) << "\r\n";
							break;
						}
						if (meminfo.State == MEM_COMMIT)
						{
							dump_blockex _newblock = {};
							_newblock._save_data.resize(meminfo.RegionSize);
							std::uninitialized_fill_n(&_newblock._save_data[0], meminfo.RegionSize, 0);
							_newblock._dmp_block._magic_block_header = dump_block_magic;
							_newblock._dmp_block._size = meminfo.RegionSize;
#ifdef _AMD64_
							_newblock._dmp_block._virtual_address = DWORD64(meminfo.BaseAddress);
#else
							_newblock._dmp_block._virtual_address = DWORD64(PtrToPtr64(meminfo.BaseAddress));
#endif
							SIZE_T dwRet = 0;
							ReadProcessMemory(_handle,
								meminfo.BaseAddress,
								&_newblock._save_data[0],
								meminfo.RegionSize,
								&dwRet);
							_dmpblock.push_back(_newblock);
						}
						addr = (PUCHAR)meminfo.BaseAddress + meminfo.RegionSize;
					}
					
					///获得Stack信息
					auto now_stack_address = 0ULL;
					if (!is_bit_64)
					{
						now_stack_address = _dmp._ctx86.Esp;
					}
					else
					{
						now_stack_address = _dmp._ctx64.Rsp;
					}
					for (auto _block : _dmpblock)
					{
						if (now_stack_address >= _block._dmp_block._virtual_address
							&&now_stack_address <= _block._dmp_block._virtual_address +
							_block._dmp_block._size)
						{
							///找到了Stack的地址
							_dmp.StackBase = _block._dmp_block._virtual_address;
							_dmp.StackSize = _block._dmp_block._size;
						}
					}
				}
				_dmp._dump_block_count = (UINT)_dmpblock.size();
				return true;
			}
		private:
			dump_file_header _dmp;
			std::vector<dump_blockex> _dmpblock;
		public:
			dump_file_header & get_header() {
				return _dmp;
			}
			dump_blockex & operator[](std::size_t _Pos)
			{
				return _dmpblock[_Pos];
			}
		};
	};
};