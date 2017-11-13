#pragma once
#include "stdafx.h"
#include "../libdump/lib_dump.h"
namespace usr
{
	namespace ucengine
	{
#include "../hook_engine/distorm/mnemonics.h"
#include <unicorn/unicorn.h>
#if defined(_WIN64)
//#include "./unicorn/include/x64/unicorn/unicorn.h"
#pragma comment(lib,"../uc_engine/unicorn/lib/x64/unicorn.lib")
#else
//#include "./unicorn/include/x86/unicorn/unicorn.h"
#pragma comment(lib,"../uc_engine/unicorn/lib/x86/unicorn.lib")
#endif
#define DISTORM_TO_UC_REGS \
UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RBX, UC_X86_REG_RSP, UC_X86_REG_RBP, UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11, UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15,\
UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_EBX, UC_X86_REG_ESP, UC_X86_REG_EBP, UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_R8D, UC_X86_REG_R9D, UC_X86_REG_R10D, UC_X86_REG_R11D, UC_X86_REG_R12D, UC_X86_REG_R13D, UC_X86_REG_R14D, UC_X86_REG_R15D,\
UC_X86_REG_AX, UC_X86_REG_CX, UC_X86_REG_DX, UC_X86_REG_BX, UC_X86_REG_SP, UC_X86_REG_BP, UC_X86_REG_SI, UC_X86_REG_DI, UC_X86_REG_R8W, UC_X86_REG_R9W, UC_X86_REG_R10W, UC_X86_REG_R11W, UC_X86_REG_R12W, UC_X86_REG_R13W, UC_X86_REG_R14W, UC_X86_REG_R15W,\
UC_X86_REG_AL, UC_X86_REG_CL, UC_X86_REG_DL, UC_X86_REG_BL, UC_X86_REG_AH, UC_X86_REG_CH, UC_X86_REG_DH, UC_X86_REG_BH, UC_X86_REG_R8B, UC_X86_REG_R9B, UC_X86_REG_R10B, UC_X86_REG_R11B, UC_X86_REG_R12B, UC_X86_REG_R13B, UC_X86_REG_R14B, UC_X86_REG_R15B,\
UC_X86_REG_SPL, UC_X86_REG_BPL, UC_X86_REG_SIL, UC_X86_REG_DIL,\
UC_X86_REG_ES, UC_X86_REG_CS, UC_X86_REG_SS, UC_X86_REG_DS, UC_X86_REG_FS, UC_X86_REG_GS,\
UC_X86_REG_RIP,\
UC_X86_REG_ST0, UC_X86_REG_ST1, UC_X86_REG_ST2, UC_X86_REG_ST3, UC_X86_REG_ST4, UC_X86_REG_ST5, UC_X86_REG_ST6, UC_X86_REG_ST7,\
UC_X86_REG_MM0, UC_X86_REG_MM1, UC_X86_REG_MM2, UC_X86_REG_MM3, UC_X86_REG_MM4, UC_X86_REG_MM5, UC_X86_REG_MM6, UC_X86_REG_MM7,\
UC_X86_REG_XMM0, UC_X86_REG_XMM1, UC_X86_REG_XMM2, UC_X86_REG_XMM3, UC_X86_REG_XMM4, UC_X86_REG_XMM5, UC_X86_REG_XMM6, UC_X86_REG_XMM7, UC_X86_REG_XMM8, UC_X86_REG_XMM9, UC_X86_REG_XMM10, UC_X86_REG_XMM11, UC_X86_REG_XMM12, UC_X86_REG_XMM13, UC_X86_REG_XMM14, UC_X86_REG_XMM15,\
UC_X86_REG_YMM0, UC_X86_REG_YMM1, UC_X86_REG_YMM2, UC_X86_REG_YMM3, UC_X86_REG_YMM4, UC_X86_REG_YMM5, UC_X86_REG_YMM6, UC_X86_REG_YMM7, UC_X86_REG_YMM8, UC_X86_REG_YMM9, UC_X86_REG_YMM10, UC_X86_REG_YMM11, UC_X86_REG_YMM12, UC_X86_REG_YMM13, UC_X86_REG_YMM14, UC_X86_REG_YMM15,\
UC_X86_REG_CR0, UC_X86_REG_CR2, UC_X86_REG_CR3, UC_X86_REG_CR4, UC_X86_REG_CR8,\
UC_X86_REG_DR0, UC_X86_REG_DR1, UC_X86_REG_DR2, UC_X86_REG_DR3, UC_X86_REG_DR6, UC_X86_REG_DR7

		typedef enum pegasus_regs
		{
			PR_RAX, PR_RCX, PR_RDX, PR_RBX, PR_RSP, PR_RBP, PR_RSI, PR_RDI, PR_RIP, PR_R8, PR_R9, PR_R10, PR_R11, PR_R12, PR_R13, PR_R14, PR_R15, PR_EFLAGS,
			PR_XMM0, PR_XMM1, PR_XMM2, PR_XMM3, PR_XMM4, PR_XMM5, PR_XMM6, PR_XMM7, PR_XMM8, PR_XMM9, PR_XMM10, PR_XMM11, PR_XMM12, PR_XMM13, PR_XMM14, PR_XMM15,
			PR_YMM0, PR_YMM1, PR_YMM2, PR_YMM3, PR_YMM4, PR_YMM5, PR_YMM6, PR_YMM7, PR_YMM8, PR_YMM9, PR_YMM10, PR_YMM11, PR_YMM12, PR_YMM13, PR_YMM14, PR_YMM15,
			PR_REG_ES, PR_REG_CS, PR_REG_SS, PR_REG_DS, PR_REG_FS, PR_REG_GS
		}pegasus_regs;

#define UC_X86_REGISTER_SET \
UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_EBX, UC_X86_REG_ESP, UC_X86_REG_EBP, UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EIP, UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11, UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15, UC_X86_REG_EFLAGS,\
UC_X86_REG_XMM0, UC_X86_REG_XMM1, UC_X86_REG_XMM2, UC_X86_REG_XMM3, UC_X86_REG_XMM4, UC_X86_REG_XMM5, UC_X86_REG_XMM6, UC_X86_REG_XMM7, UC_X86_REG_XMM8, UC_X86_REG_XMM9, UC_X86_REG_XMM10, UC_X86_REG_XMM11, UC_X86_REG_XMM12, UC_X86_REG_XMM13, UC_X86_REG_XMM14, UC_X86_REG_XMM15,\
UC_X86_REG_YMM0, UC_X86_REG_YMM1, UC_X86_REG_YMM2, UC_X86_REG_YMM3, UC_X86_REG_YMM4, UC_X86_REG_YMM5, UC_X86_REG_YMM6, UC_X86_REG_YMM7, UC_X86_REG_YMM8, UC_X86_REG_YMM9, UC_X86_REG_YMM10, UC_X86_REG_YMM11, UC_X86_REG_YMM12, UC_X86_REG_YMM13, UC_X86_REG_YMM14, UC_X86_REG_YMM15,\
UC_X86_REG_ES, UC_X86_REG_CS, UC_X86_REG_SS, UC_X86_REG_DS, UC_X86_REG_FS, UC_X86_REG_GS

#define UC_X64_REGISTER_SET \
UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RBX, UC_X86_REG_RSP, UC_X86_REG_RBP, UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RIP, UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11, UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15, UC_X86_REG_EFLAGS,\
UC_X86_REG_XMM0, UC_X86_REG_XMM1, UC_X86_REG_XMM2, UC_X86_REG_XMM3, UC_X86_REG_XMM4, UC_X86_REG_XMM5, UC_X86_REG_XMM6, UC_X86_REG_XMM7, UC_X86_REG_XMM8, UC_X86_REG_XMM9, UC_X86_REG_XMM10, UC_X86_REG_XMM11, UC_X86_REG_XMM12, UC_X86_REG_XMM13, UC_X86_REG_XMM14, UC_X86_REG_XMM15,\
UC_X86_REG_YMM0, UC_X86_REG_YMM1, UC_X86_REG_YMM2, UC_X86_REG_YMM3, UC_X86_REG_YMM4, UC_X86_REG_YMM5, UC_X86_REG_YMM6, UC_X86_REG_YMM7, UC_X86_REG_YMM8, UC_X86_REG_YMM9, UC_X86_REG_YMM10, UC_X86_REG_YMM11, UC_X86_REG_YMM12, UC_X86_REG_YMM13, UC_X86_REG_YMM14, UC_X86_REG_YMM15,\
UC_X86_REG_ES, UC_X86_REG_CS, UC_X86_REG_SS, UC_X86_REG_DS, UC_X86_REG_FS, UC_X86_REG_GS
#pragma pack(push, 1)
		typedef struct _SegmentDescriptor {
			union {
				struct {
					unsigned short limit_low;
					unsigned short base_low;
					unsigned char base_mid;
					unsigned char type : 4;
					unsigned char system : 1;
					unsigned char dpl : 2;
					unsigned char present : 1;
					unsigned char limit_hi : 4;
					unsigned char available : 1;
					unsigned char is_64_code : 1;
					unsigned char db : 1;
					unsigned char granularity : 1;
					unsigned char base_hi;
				};
				unsigned long long descriptor; // resize 8byte.
			};
		}SegmentDescriptor, *PSegmentDescriptor;
		struct SegmentDesctiptorX64 {
			SegmentDescriptor descriptor;
			ULONG32 base_upper32;
			ULONG32 reserved;
		};
#pragma pack(pop)
		void hook_fetch_memory(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data);
		void hook_unmap_memory(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data);
		class uc_engine_base
		{
		public:
			virtual bool load_dump(_tstring file_name) = 0;
			//异常处理
			virtual void on_fetch(uc_mem_type type, uint64_t address, int size, int64_t value) = 0;
			virtual void on_umap(uc_mem_type type, uint64_t address, int size, int64_t value) = 0;
			
#ifdef _AMD64_
			virtual bool get_context32(WOW64_CONTEXT &context_) = 0;
			virtual bool get_context64(CONTEXT &context_) = 0;
			virtual bool set_context32(WOW64_CONTEXT context_) = 0;
			virtual bool set_context64(CONTEXT context_) = 0;
#else
			virtual bool get_context32(CONTEXT &context_) = 0;
			virtual bool set_context32(CONTEXT context_) = 0;
#endif
			virtual bool read_memory(uint64_t address, void *buffer, size_t size) = 0;
			virtual bool write_memory(uint64_t address, void *buffer, size_t size) = 0;

			//每次执行一条指令的execute
			virtual bool execute_code(uint64_t address) = 0;
		};
		class unicorn_engine :public uc_engine_base
		{
		public:
			unicorn_engine() {
				engine = nullptr;
				gdt_base = 0;
				_code_64 = false;
			};
			~unicorn_engine() {
				if (engine)
				{
					uc_close((uc_engine *)engine);
				}
			};
		private:
			void *engine;
			bool _code_64;
			DWORD64 gdt_base;
			DWORD64 fs_base;
			DWORD64 gs_base;
		private:
			bool create_engine(bool is64)
			{
				uc_err err = UC_ERR_OK;
				if (!is64)
				{
					err = uc_open(UC_ARCH_X86, UC_MODE_32, (uc_engine **)&engine);
				}
				else
				{
					///这里有很多事儿
					err = uc_open(UC_ARCH_X86, UC_MODE_64, (uc_engine **)&engine);
					_code_64 = true;
				}

				if (err != 0)
				{
					std::cout << "error in init uc engine code=" << err << "\r\n";
					return false;
				}
				return true;
			}
		private:
			bool load_context_64(CONTEXT context_)
			{
#ifdef _WIN64
				if (context_.SegDs == context_.SegSs)
					context_.SegSs = 0x88; // rpl = 0

				context_.SegGs = 0x63;

				int x86_register[] = { UC_X64_REGISTER_SET };
				int size = sizeof(x86_register) / sizeof(int);
				unsigned long long *write_register = nullptr;
				void **write_ptr = nullptr;

				write_register = (unsigned long long *)malloc(sizeof(unsigned long long)*size);
				if (!write_register)
					return false;
				std::cout << "load_context_64 1\r\n";
				std::shared_ptr<void> write_register_closer(write_register, free);
				memset(write_register, 0, sizeof(unsigned long long)*size);

				write_ptr = (void **)malloc(sizeof(void **)*size);
				if (!write_ptr)
					return false;
				std::shared_ptr<void> write_ptr_closer(write_ptr, free);
				memset(write_ptr, 0, sizeof(void **)*size);
				//std::cout << "load_context_64 2\r\n";
				for (int i = 0; i < size; ++i)
					write_ptr[i] = &write_register[i];
				//std::cout << "load_context_64 3\r\n";
				write_register[PR_RAX] = context_.Rax;
				write_register[PR_RBX] = context_.Rbx;
				write_register[PR_RCX] = context_.Rcx;
				write_register[PR_RDX] = context_.Rdx;
				write_register[PR_RSI] = context_.Rsi;
				write_register[PR_RDI] = context_.Rdi;
				write_register[PR_RSP] = context_.Rsp;
				write_register[PR_RBP] = context_.Rbp;
				write_register[PR_R8] = context_.R8;
				write_register[PR_R9] = context_.R9;
				write_register[PR_R10] = context_.R10;
				write_register[PR_R11] = context_.R11;
				write_register[PR_R12] = context_.R12;
				write_register[PR_R13] = context_.R13;
				write_register[PR_R14] = context_.R14;
				write_register[PR_R15] = context_.R15;
				write_register[PR_EFLAGS] = (unsigned long)context_.EFlags;
				write_register[PR_REG_CS] = context_.SegCs;
				write_register[PR_REG_DS] = context_.SegDs;
				write_register[PR_REG_ES] = context_.SegEs;
				write_register[PR_REG_FS] = context_.SegFs;
				write_register[PR_REG_GS] = context_.SegGs;
				write_register[PR_REG_SS] = context_.SegSs;
				write_register[PR_RIP] = context_.Rip;
				//std::cout << "load_context_64 4\r\n";
				//std::cout << size << "\r\n";
				auto uc = (uc_engine *)engine;
				for (auto i=0;i<size;i++)
				{
					if (uc_reg_write(uc, x86_register[i], &write_register[i])!=0)
					{
						return false;
					}
				}
				/*if (uc_reg_write_batch(uc, x86_register, write_ptr, size) != 0)
					return false;*/
				//std::cout << "load_context_64 5\r\n";
#endif
				return true;
			}
#ifdef _AMD64_
			bool load_context_86(WOW64_CONTEXT context_)

#else
			bool load_context_86(CONTEXT context_)
#endif
			{
				if (context_.SegDs == context_.SegSs)
					context_.SegSs = 0x88; // rpl = 0

				context_.SegGs = 0x63;

				int x86_register[] = { UC_X86_REGISTER_SET };
				int size = sizeof(x86_register) / sizeof(int);
				unsigned long *write_register = nullptr;
				void **write_ptr = nullptr;

				write_register = (unsigned long *)malloc(sizeof(unsigned long)*size);
				if (!write_register)
					return false;
				std::shared_ptr<void> write_register_closer(write_register, free);
				memset(write_register, 0, sizeof(unsigned long)*size);
				//std::cout << "load_context_86 1\r\n";
				write_ptr = (void **)malloc(sizeof(void **)*size);
				if (!write_ptr)
					return false;
				std::shared_ptr<void> write_ptr_closer(write_ptr, free);
				memset(write_ptr, 0, sizeof(void **)*size);
				//std::cout << "load_context_86 2\r\n";
				for (int i = 0; i < size; ++i)
					write_ptr[i] = &write_register[i];
				//std::cout << "load_context_86 3\r\n";

				write_register[PR_RAX] = (unsigned long)context_.Eax;
				write_register[PR_RBX] = (unsigned long)context_.Ebx;
				write_register[PR_RCX] = (unsigned long)context_.Ecx;
				write_register[PR_RDX] = (unsigned long)context_.Edx;
				write_register[PR_RSI] = (unsigned long)context_.Esi;
				write_register[PR_RDI] = (unsigned long)context_.Edi;
				write_register[PR_RSP] = (unsigned long)context_.Esp;
				write_register[PR_RBP] = (unsigned long)context_.Ebp;
				write_register[PR_RIP] = (unsigned long)context_.Eip;
				write_register[PR_EFLAGS] = (unsigned long)context_.EFlags;
				write_register[PR_REG_CS] = context_.SegCs;
				write_register[PR_REG_DS] = context_.SegDs;
				write_register[PR_REG_ES] = context_.SegEs;
				write_register[PR_REG_FS] = context_.SegFs;
				write_register[PR_REG_GS] = context_.SegGs;
				write_register[PR_REG_SS] = context_.SegSs;

				//std::cout << "load_context_86 4\r\n";
				std::cout << size << "\r\n";
				auto uc = (uc_engine *)engine;
				for (auto i = 0; i < size; i++)
				{
					/*std::cout << std::dec << "i="<<i<<" reg=" << x86_register[i] << " value="
						<<std::hex<<write_register[i] << "\r\n";*/
					if(i!=PR_REG_CS)
						uc_reg_write(uc, x86_register[i], &write_register[i]);
					else
					{
						std::cout << "what happend to my CS\r\n" << "\r\n";
					}
				}
				/*if (uc_reg_write_batch(uc, x86_register, write_ptr, size) != 0)
					return false;
*/
				//std::cout << "load_context_86 5\r\n";
				return true;
			}
		private:
			void set_global_descriptor(SegmentDescriptor *desc, uint64_t base, uint32_t limit, uint8_t is_code)
			{
				desc->descriptor = 0;
				desc->base_low = base & 0xffff;
				desc->base_mid = (base >> 16) & 0xff;
				desc->base_hi = base >> 24;

				if (limit > 0xfffff)
				{
					limit >>= 12;
					desc->granularity = 1;
				}
				desc->limit_low = limit & 0xffff;
				desc->limit_hi = limit >> 16;

				desc->dpl = 3;
				desc->present = 1;
				desc->db = 1;
				desc->type = is_code ? 0xb : 3;
				desc->system = 1;
			}
			bool load_gdt()
			{
				uc_x86_mmr gdtr;
				gdtr.base = gdt_base;
				gdtr.limit = (sizeof(SegmentDescriptor) * 31) - 1;

				if (uc_mem_map((uc_engine*)engine, gdt_base, 0x10000, UC_PROT_ALL) != 0)
					return false;
				if (uc_reg_write((uc_engine *)engine, UC_X86_REG_GDTR, &gdtr) != 0)
					return false;

				return true;
			}
			void load_segment(CONTEXT context_)
			{
				SegmentDescriptor global_descriptor[31];
				memset(global_descriptor, 0, sizeof(global_descriptor));
				if (context_.SegDs == context_.SegSs)
					context_.SegSs = 0x88; // rpl = 0

				context_.SegGs = 0x63;

				set_global_descriptor(&global_descriptor[0x33 >> 3], 0, 0xfffff000, 1); // 64 code
				set_global_descriptor(&global_descriptor[context_.SegCs >> 3], 0, 0xfffff000, 1);
				set_global_descriptor(&global_descriptor[context_.SegDs >> 3], 0, 0xfffff000, 0);
				set_global_descriptor(&global_descriptor[context_.SegFs >> 3], fs_base, 0xfff, 0);
				set_global_descriptor(&global_descriptor[context_.SegGs >> 3], gs_base, 0xfffff000, 0);
				set_global_descriptor(&global_descriptor[context_.SegSs >> 3], 0, 0xfffff000, 0);
				global_descriptor[context_.SegSs >> 3].dpl = 0; // dpl = 0, cpl = 0

				uc_mem_write((uc_engine *)engine, gdt_base, global_descriptor, sizeof(global_descriptor));
			}
		public:
			bool load_dump(_tstring file_name)
			{
				auto GetFlagBit = [](DWORD eflags, DWORD i) {
					return (eflags >> i) & 1;
				};
				if (engine)
				{
					std::cout << "重複使用" << "\r\n";
					return false;
				}
				usr::libdump::dump_file _dumpfile;
				if (_dumpfile.load_file(file_name))
				{
					std::cout << "load file ok" << "\r\n";
					///load成功可以開始構建偉大力量了
					auto dmpheader = _dumpfile.get_header();
					gdt_base = dmpheader.GdtBase;
					fs_base = dmpheader.FSBase;
					gs_base = dmpheader.GSBase;

					if (dmpheader._is64)
					{
						auto context = dmpheader._ctx64;
						printf("	rax=%0*I64x rbx=%0*I64x rcx=%0*I64x rdx=%0*I64x\n", 16, context.Rax, 16, context.Rbx, 16, context.Rcx, 16, context.Rdx);
						printf("	rsi=%0*I64x rdi=%0*I64x\n", 16, context.Rsi, 16, context.Rdi);
						printf("	rsp=%0*I64x rbp=%0*I64x\n", 16, context.Rsp, 16, context.Rbp);
						printf("	rip=%0*I64x\n", 16, context.Rip);
						printf("\n");
						printf("	r8=%0*I64x r9=%0*I64x r10=%0*I64x\n", 16, context.R8, 16, context.R9, 16, context.R10);
						printf("	r11=%0*I64x r12=%0*I64x r13=%0*I64x\n", 16, context.R11, 16, context.R12, 16, context.R13);
						printf("	r14=%0*I64x r15=%0*I64x\n", 16, context.R14, 16, context.R15);
						printf("	efl=%08x\n", context.EFlags);
						printf("	CF=%d PF=%d AF=%d ZF=%d SF=%d TF=%d IF=%d DF=%d OF=%d IOPL=%d IOPL2=%d NT=%d RF=%d VM=%d AC=%d VIF=%d VIP=%d ID=%d\n"
							, GetFlagBit(context.EFlags, 0), GetFlagBit(context.EFlags, 2)
							, GetFlagBit(context.EFlags, 4), GetFlagBit(context.EFlags, 6)
							, GetFlagBit(context.EFlags, 7), GetFlagBit(context.EFlags, 8)
							, GetFlagBit(context.EFlags, 9), GetFlagBit(context.EFlags, 10)
							, GetFlagBit(context.EFlags, 11), GetFlagBit(context.EFlags, 12)
							, GetFlagBit(context.EFlags, 13), GetFlagBit(context.EFlags, 14)
							, GetFlagBit(context.EFlags, 16), GetFlagBit(context.EFlags, 17)
							, GetFlagBit(context.EFlags, 18), GetFlagBit(context.EFlags, 19)
							, GetFlagBit(context.EFlags, 20), GetFlagBit(context.EFlags, 21));
						printf("	cs=%02x ds=%02x es=%02x fs=%02x gs=%02x ss=%02x\n", context.SegCs, context.SegDs, context.SegEs, context.SegFs, context.SegGs, context.SegSs);
					}
#ifdef _AMD64_
					if (!create_engine(dmpheader._is64 ? true : false))
					{
						return false;
					}

#else 
					if (!create_engine(false))
					{
						return false;
					}
#endif
					std::cout << "create engine ok" << "\r\n";
					auto uc = (uc_engine *)engine;
					uc_hook write_unmap_hook;
					uc_hook read_unmap_hook;
					uc_hook fetch_hook;
					uc_hook_add(uc, &write_unmap_hook, UC_HOOK_MEM_WRITE_UNMAPPED, hook_unmap_memory, this, (uint64_t)1, (uint64_t)0);
					uc_hook_add(uc, &read_unmap_hook, UC_HOOK_MEM_READ_UNMAPPED, hook_unmap_memory, this, (uint64_t)1, (uint64_t)0);
					uc_hook_add(uc, &fetch_hook, UC_HOOK_MEM_FETCH_UNMAPPED, hook_fetch_memory, this, (uint64_t)1, (uint64_t)0);

					///偉大力量之map內存

					for (auto i = 0UL; i < dmpheader._dump_block_count; i++)
					{
						auto dmpblockex = _dumpfile[i];
						auto dmpblock = dmpblockex._dmp_block;
					//	std::cout << "VA=0x" << dmpblock._virtual_address << "\r\n";
					//	std::cout << "Size=0x" << dmpblock._size << "\r\n";
						auto err = uc_mem_map(uc, dmpblock._virtual_address, dmpblock._size, UC_PROT_ALL);
						if (err != 0)
						{
							std::cout << "map failed\r\n";
							std::cout << std::hex << "VA=0x" << dmpblock._virtual_address << "\r\n";
							std::cout << "Size=0x" << dmpblock._size << "\r\n";
							return false;
						}


						err = uc_mem_write(uc, dmpblock._virtual_address, &dmpblockex._save_data[0], dmpblock._size);
						if (err != 0)
						{
							std::cout << "write failed\r\n";
							std::cout << std::hex << "VA=0x" << dmpblock._virtual_address << "\r\n";
							std::cout << "Size=0x" << dmpblock._size << "\r\n";
							return false;
						}

					}

					std::cout << "load mem ok" << "\r\n";
					///修复Segment段映射
					if (!load_gdt())
					{
						return false;
					}

					std::cout << "load gdt ok" << "\r\n";
#ifdef _AMD64_
					load_segment(dmpheader._ctx64);
#else
					load_segment(dmpheader._ctx86);
#endif
					std::cout << "load segment ok" << "\r\n";
					///修理context
#ifdef _AMD64_
					if (dmpheader._is64)
					{
						//64位context的Load
						if (!load_context_64(dmpheader._ctx64))
						{
							return false;
						}
					}
					else
					{
						//32位Context的Load
						if (!load_context_86(dmpheader._ctx86))
						{
							return false;
						}
					}
#else
					//32的处理
					if (!load_context_86(dmpheader._ctx86))
					{
						return false;
					}
#endif

					std::cout << "load context ok" << "\r\n";

					return true;
				}
				return false;
			}
		public:
			void on_fetch(uc_mem_type type, uint64_t address, int size, int64_t value)
			{
				if (type == UC_MEM_FETCH_UNMAPPED)
				{
					std::cout << std::hex << "UC_MEM_FETCH_UNMAPPED:" <<
						"address=0x" << address
					<< " size=0x" << size << " " << "\r\n";
					return;
				}
			}
			void on_umap(uc_mem_type type, uint64_t address, int size, int64_t value)
			{
				if (type == UC_MEM_WRITE_UNMAPPED )
				{
					std::cout << std::hex << "UC_MEM_WRITE_UNMAPPED:" <<
						"address=0x" << address
					<< " size=0x" << size << " " << "\r\n";
					return;
				}
				if (type == UC_MEM_READ_UNMAPPED)
				{
					std::cout << std::hex << "UC_MEM_READ_UNMAPPED:" <<
						"address=0x" << address
						<< " size=0x" << size << " " << "\r\n";
					return;
				}
			}
		public:
			bool read_memory(uint64_t address, void *buffer, size_t size)
			{
				auto err = uc_mem_read((uc_engine*)engine, address, buffer, size);
				if (err==0)
				{
					return true;
				}
				return false;
			}
			bool write_memory(uint64_t address, void *buffer, size_t size)
			{
				auto err = uc_mem_write((uc_engine*)engine, address, buffer, size);
				if (err == 0)
				{
					return true;
				}
				return false;
			}
		public:
#ifdef _AMD64_
			bool get_context64(CONTEXT &context_)
			{
				int x86_register[] = { UC_X64_REGISTER_SET };
				int size = sizeof(x86_register) / sizeof(int);
				unsigned long long *read_register = nullptr;
				void **read_ptr = nullptr;

				read_register = (unsigned long long *)malloc(sizeof(unsigned long long)*size);
				if (!read_register)
					return false;
				std::shared_ptr<void> read_register_closer(read_register, free);
				memset(read_register, 0, sizeof(unsigned long long)*size);

				read_ptr = (void **)malloc(sizeof(void **)*size);
				if (!read_ptr)
					return false;
				std::shared_ptr<void> read_ptr_closer(read_ptr, free);
				memset(read_ptr, 0, sizeof(void **)*size);

				for (int i = 0; i < size; ++i)
					read_ptr[i] = &read_register[i];

				auto uc = (uc_engine *)engine;
				for (auto i=0;i<size;i++)
				{
					if (uc_reg_read(uc, x86_register[i], &read_register[i]) != 0)
					{
						std::cout << "read reg failed\r\n";
						return false;
					}
				}
				context_.Rax = read_register[PR_RAX];
				context_.Rbx = read_register[PR_RBX];
				context_.Rcx = read_register[PR_RCX];
				context_.Rdx = read_register[PR_RDX];
				context_.Rsi = read_register[PR_RSI];
				context_.Rdi = read_register[PR_RDI];
				context_.Rsp = read_register[PR_RSP];
				context_.Rbp = read_register[PR_RBP];
				context_.Rip = read_register[PR_RIP];
				context_.R8 = read_register[PR_R8];
				context_.R9 = read_register[PR_R9];
				context_.R10 = read_register[PR_R10];
				context_.R11 = read_register[PR_R11];
				context_.R12 = read_register[PR_R12];
				context_.R13 = read_register[PR_R13];
				context_.R14 = read_register[PR_R14];
				context_.R15 = read_register[PR_R15];
				context_.EFlags = (unsigned long)read_register[PR_EFLAGS];
				context_.SegCs = (unsigned short)read_register[PR_REG_CS];
				context_.SegDs = (unsigned short)read_register[PR_REG_DS];
				context_.SegEs = (unsigned short)read_register[PR_REG_ES];
				context_.SegFs = (unsigned short)read_register[PR_REG_FS];
				context_.SegGs = (unsigned short)read_register[PR_REG_GS];
				context_.SegSs = (unsigned short)read_register[PR_REG_SS];
				return true;
			}
			bool set_context64(CONTEXT context_)
			{
				int x86_register[] = { UC_X64_REGISTER_SET };
				int size = sizeof(x86_register) / sizeof(int);
				unsigned long long *write_register = nullptr;
				void **write_ptr = nullptr;

				write_register = (unsigned long long *)malloc(sizeof(unsigned long long)*size);
				if (!write_register)
					return false;
				std::shared_ptr<void> write_register_closer(write_register, free);
				memset(write_register, 0, sizeof(unsigned long long)*size);

				write_ptr = (void **)malloc(sizeof(void **)*size);
				if (!write_ptr)
					return false;
				std::shared_ptr<void> write_ptr_closer(write_ptr, free);
				memset(write_ptr, 0, sizeof(void **)*size);

				for (int i = 0; i < size; ++i)
					write_ptr[i] = &write_register[i];

				write_register[PR_RAX] = context_.Rax;
				write_register[PR_RBX] = context_.Rbx;
				write_register[PR_RCX] = context_.Rcx;
				write_register[PR_RDX] = context_.Rdx;
				write_register[PR_RSI] = context_.Rsi;
				write_register[PR_RDI] = context_.Rdi;
				write_register[PR_RSP] = context_.Rsp;
				write_register[PR_RBP] = context_.Rbp;
				write_register[PR_R8] = context_.R8;
				write_register[PR_R9] = context_.R9;
				write_register[PR_R10] = context_.R10;
				write_register[PR_R11] = context_.R11;
				write_register[PR_R12] = context_.R12;
				write_register[PR_R13] = context_.R13;
				write_register[PR_R14] = context_.R14;
				write_register[PR_R15] = context_.R15;
				write_register[PR_EFLAGS] = (unsigned long)context_.EFlags;
				write_register[PR_REG_CS] = context_.SegCs;
				write_register[PR_REG_DS] = context_.SegDs;
				write_register[PR_REG_ES] = context_.SegEs;
				write_register[PR_REG_FS] = context_.SegFs;
				write_register[PR_REG_GS] = context_.SegGs;
				write_register[PR_REG_SS] = context_.SegSs;

				auto uc = (uc_engine *)engine;
				for (auto i = 0; i < size; i++)
				{
					uc_reg_write(uc, x86_register[i], &write_register[i]);
				}

				/*uc_engine *uc = (uc_engine *)engine;
				if (uc_reg_write_batch(uc, x86_register, write_ptr, size) != 0)
					return false;*/
				return true;
			}
#endif
#ifdef _AMD64_
			bool get_context32(WOW64_CONTEXT &context_)
#else
			bool get_context32(CONTEXT &context_)
#endif
			{
				int x86_register[] = { UC_X86_REGISTER_SET };
				int size = sizeof(x86_register) / sizeof(int);
				unsigned long *read_register = nullptr;
				void **read_ptr = nullptr;

				read_register = (unsigned long *)malloc(sizeof(unsigned long)*size);
				if (!read_register)
					return false;
				std::shared_ptr<void> read_register_closer(read_register, free);
				memset(read_register, 0, sizeof(unsigned long)*size);

				read_ptr = (void **)malloc(sizeof(void **)*size);
				if (!read_ptr)
					return false;
				std::shared_ptr<void> read_ptr_closer(read_ptr, free);
				memset(read_ptr, 0, sizeof(void **)*size);

				for (int i = 0; i < size; ++i)
					read_ptr[i] = &read_register[i];

				uc_engine *uc = (uc_engine *)engine;
				if (uc_reg_read_batch(uc, x86_register, read_ptr, size) != 0)
					return false;

				context_.Eax = read_register[PR_RAX];
				context_.Ebx = read_register[PR_RBX];
				context_.Ecx = read_register[PR_RCX];
				context_.Edx = read_register[PR_RDX];
				context_.Esi = read_register[PR_RSI];
				context_.Edi = read_register[PR_RDI];
				context_.Esp = read_register[PR_RSP];
				context_.Ebp = read_register[PR_RBP];
				context_.Eip = read_register[PR_RIP];

				context_.EFlags = read_register[PR_EFLAGS];
				context_.SegCs = (unsigned short)read_register[PR_REG_CS];
				context_.SegDs = (unsigned short)read_register[PR_REG_DS];
				context_.SegEs = (unsigned short)read_register[PR_REG_ES];
				context_.SegFs = (unsigned short)read_register[PR_REG_FS];
				context_.SegGs = (unsigned short)read_register[PR_REG_GS];
				context_.SegSs = (unsigned short)read_register[PR_REG_SS];

				return true;
			}
#ifdef _AMD64_
			bool set_context32(WOW64_CONTEXT context_)
#else
			bool set_context32(CONTEXT context_)
#endif
			{
				int x86_register[] = { UC_X86_REGISTER_SET };
				int size = sizeof(x86_register) / sizeof(int);
				unsigned long *write_register = nullptr;
				void **write_ptr = nullptr;

				write_register = (unsigned long *)malloc(sizeof(unsigned long)*size);
				if (!write_register)
					return false;
				std::shared_ptr<void> write_register_closer(write_register, free);
				memset(write_register, 0, sizeof(unsigned long)*size);

				write_ptr = (void **)malloc(sizeof(void **)*size);
				if (!write_ptr)
					return false;
				std::shared_ptr<void> write_ptr_closer(write_ptr, free);
				memset(write_ptr, 0, sizeof(void **)*size);

				for (int i = 0; i < size; ++i)
					write_ptr[i] = &write_register[i];

				write_register[PR_RAX] = (unsigned long)context_.Eax;
				write_register[PR_RBX] = (unsigned long)context_.Ebx;
				write_register[PR_RCX] = (unsigned long)context_.Ecx;
				write_register[PR_RDX] = (unsigned long)context_.Edx;
				write_register[PR_RSI] = (unsigned long)context_.Esi;
				write_register[PR_RDI] = (unsigned long)context_.Edi;
				write_register[PR_RSP] = (unsigned long)context_.Esp;
				write_register[PR_RBP] = (unsigned long)context_.Ebp;
				write_register[PR_RIP] = (unsigned long)context_.Eip;

				write_register[PR_EFLAGS] = (unsigned long)context_.EFlags;
				write_register[PR_REG_CS] = context_.SegCs;
				write_register[PR_REG_DS] = context_.SegDs;
				write_register[PR_REG_ES] = context_.SegEs;
				write_register[PR_REG_FS] = context_.SegFs;
				write_register[PR_REG_GS] = context_.SegGs;
				write_register[PR_REG_SS] = context_.SegSs;

				auto uc = (uc_engine *)engine;
				for (auto i = 0; i < size; i++)
				{
					/*std::cout << std::dec << "i=" << i << " reg=" << x86_register[i] << " value="
						<< std::hex << write_register[i] << "\r\n";*/
					if (i != PR_REG_CS)
						uc_reg_write(uc, x86_register[i], &write_register[i]);
					else
					{
						/*std::cout << "what happend to my CS\r\n" << "\r\n";*/
					}
				}
				
				/*if (uc_reg_write_batch(uc, x86_register, write_ptr, size) != 0)
					return false;*/

				return true;
			}
		private:
			bool disasm(void *code, size_t size, uint32_t dt, void *out)
			{
				unsigned int dc;
				_CodeInfo ci;
				_DInst *di = (_DInst *)out;

				ci.code = (unsigned char *)code;
				ci.codeLen = (int)size;
				ci.codeOffset = (_OffsetType)(unsigned long long *)code;
				ci.dt = (_DecodeType)dt;
				ci.features = DF_NONE;

				if (distorm_decompose(&ci, di, 1, &dc) == DECRES_INPUTERR)
					return false;

				if (dc < 1)
					return false;

				return true;
			}
		private:
			bool handle_mov_ss(uint64_t &_rip)
			{
				BYTE dump[1024];
				_DInst di;
				auto uc = (uc_engine *)engine;

				if (uc_mem_read(uc,_rip, dump, 1024) != 0)
					return false;

				if (!disasm((PVOID)dump, 64, Decode64Bits, &di))
					return false;

				if (di.opcode != I_MOV || di.ops[0].type != O_REG || di.ops[0].index != R_SS || di.size != 3)
					return false;

				unsigned int distorm_to_uc[] = { DISTORM_TO_UC_REGS };
				DWORD ss = 0x88;
				if (uc_reg_write(uc, distorm_to_uc[di.ops[1].index], &ss) != 0)
					return false;

				return true;
			}
			bool handle_mov_gs(uint64_t &_rip)
			{
				BYTE dump[1024];
				_DInst di;
				auto uc = (uc_engine *)engine;

				if (uc_mem_read(uc,_rip, dump, 1024) != 0)
					return false;

				if (!disasm((PVOID)dump, 64, Decode64Bits, &di))
					return false;

				if (di.opcode != I_MOV || di.ops[0].type != O_REG || di.ops[1].type != O_DISP || di.size != 9 || di.disp != 0x30)
					return false;

				unsigned int distorm_to_uc[] = { DISTORM_TO_UC_REGS };

				if (uc_reg_write(uc, distorm_to_uc[di.ops[0].index], &gs_base) != 0)
					return false;

				_rip += di.size;
				return true;
			}
			bool handle_into_wow(uint64_t &rip)
			{
				auto uc = (uc_engine *)engine;
				unsigned char dump[16] = { 0, };

				if (uc_mem_read(uc,rip, dump, 16) == 0 && dump[0] == 0xea && dump[5] == 0x33 && dump[6] == 0)
				{
					unsigned long *syscall_ptr = (unsigned long *)(&dump[1]);
					unsigned long syscall = *syscall_ptr;
					_code_64 = true;
					rip = syscall;
					return true;
				}
				return false;
			}
			bool handle_ret_wow(uint64_t &rip)
			{
				BYTE dump[1024];
				_DInst di;
				auto uc = (uc_engine *)engine;
				if (uc_mem_read(uc, rip, dump, 1024) != 0)
					return false;

				if (!disasm((PVOID)dump, 64, Decode64Bits, &di))
					return false;

				if (di.opcode != I_JMP_FAR || di.ops[0].type != O_SMEM || di.size != 3)
					return false;

				unsigned int distorm_to_uc[] = { DISTORM_TO_UC_REGS };

				unsigned long long return_register = 0;
				if (uc_reg_read(uc, distorm_to_uc[di.ops[0].index], &return_register) != 0)
					return false;

				unsigned long value = 0;
				if (uc_mem_read(uc, return_register, &value, sizeof(value)) != 0)
					return false;

				rip = value;
				_code_64 = false;

				return true;
			}
		public:
			bool execute_code(uint64_t address)
			{
				auto rip = address;
				auto uc = (uc_engine*)engine;
				do 
				{
					auto err = uc_emu_start(uc, rip, rip + 0x1000, 0, 1);
					if (err != 0)
					{

						//是不是mov ss引發
						if (_code_64 && handle_mov_ss(rip))
							continue;
						//是不是mov gs引發
						if (_code_64 && handle_mov_gs(rip))
							continue;

						//syscall進入引發
						auto backup_rip = rip;
						if (handle_into_wow(rip))
						{
							//進了wow的世界，模擬強行結束
							std::cout << "wow call into rip=0x" << std::hex << rip
								<< " from address = " << backup_rip << "\r\n";
							return false;
						}
						//syscall結束
						if (handle_ret_wow(rip))
						{
							//因為不能改變世界，所以模擬到這裏結束了
							std::cout << "wow call ret rip=0x" << std::hex << rip << "\r\n";
							return false;
						}
						//是不是syscall進出進出引發——如果進入這個流程
						//ntapi之外的api執行沒有壓力，但進ntapi的地方肯定會炸啊
						//呵呵
						///有個問題是SEH這裏模擬不起來——
						///還好VMP和SE以及TMD的VM不使用SEH,正常情況下...
						///seh處理的需要遍歷SEH鏈條，然後還要腦洞更大
						if ((err == UC_ERR_WRITE_UNMAPPED || err == UC_ERR_READ_UNMAPPED || err == UC_ERR_FETCH_UNMAPPED))
						{
							//這SEH啊
							std::cout << "need seh support rip = 0x" << std::hex << rip << "\r\n";
							return false;
						}
						std::cout << "unknown error = " << std::dec << err
							<< " rip=0x" << std::hex << rip
							<< "\r\n";
						return false;
					}
					//成功執行一條指令,退出
					break;
				} while (1);
				
				return true;
			}
		public:
			bool is_bit64()
			{
				return _code_64;
			}
			void print_context()
			{

				auto GetFlagBit = [](DWORD eflags,DWORD i) {
					return (eflags>>i)&1;
				};

				if (_code_64)
				{
					printf("\n");	
#ifdef _AMD64_
					CONTEXT context = {};
					get_context64(context);
					printf("	rax=%0*I64x rbx=%0*I64x rcx=%0*I64x rdx=%0*I64x\n", 16, context.Rax, 16, context.Rbx, 16, context.Rcx, 16, context.Rdx);
					printf("	rsi=%0*I64x rdi=%0*I64x\n", 16, context.Rsi, 16, context.Rdi);
					printf("	rsp=%0*I64x rbp=%0*I64x\n", 16, context.Rsp, 16, context.Rbp);
					printf("	rip=%0*I64x\n", 16, context.Rip);
					printf("\n");
					printf("	r8=%0*I64x r9=%0*I64x r10=%0*I64x\n", 16, context.R8, 16, context.R9, 16, context.R10);
					printf("	r11=%0*I64x r12=%0*I64x r13=%0*I64x\n", 16, context.R11, 16, context.R12, 16, context.R13);
					printf("	r14=%0*I64x r15=%0*I64x\n", 16, context.R14, 16, context.R15);
					printf("	efl=%08x\n", context.EFlags);
					printf("	CF=%d PF=%d AF=%d ZF=%d SF=%d TF=%d IF=%d DF=%d OF=%d IOPL=%d IOPL2=%d NT=%d RF=%d VM=%d AC=%d VIF=%d VIP=%d ID=%d\n"
						, GetFlagBit(context.EFlags, 0), GetFlagBit(context.EFlags, 2)
						, GetFlagBit(context.EFlags, 4), GetFlagBit(context.EFlags, 6)
						, GetFlagBit(context.EFlags, 7), GetFlagBit(context.EFlags, 8)
						, GetFlagBit(context.EFlags, 9), GetFlagBit(context.EFlags, 10)
						, GetFlagBit(context.EFlags, 11), GetFlagBit(context.EFlags, 12)
						, GetFlagBit(context.EFlags, 13), GetFlagBit(context.EFlags, 14)
						, GetFlagBit(context.EFlags, 16), GetFlagBit(context.EFlags, 17)
						, GetFlagBit(context.EFlags, 18), GetFlagBit(context.EFlags, 19)
						, GetFlagBit(context.EFlags, 20), GetFlagBit(context.EFlags, 21));
					printf("	cs=%02x ds=%02x es=%02x fs=%02x gs=%02x ss=%02x\n", context.SegCs, context.SegDs, context.SegEs, context.SegFs, context.SegGs, context.SegSs);
#endif
				}
				else
				{
#ifdef _AMD64_
					WOW64_CONTEXT context = {};
#else
					CONTEXT context = {};
#endif
					get_context32(context);
					printf("eax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x\n", context.Eax, context.Ebx, context.Ecx, context.Edx, context.Esi, context.Edi);
					printf("eip=%08x esp=%08x ebp=%08x efl=%08x\n", context.Eip, context.Esp, context.Ebp, context.EFlags);
					printf("	CF=%d PF=%d AF=%d ZF=%d SF=%d TF=%d IF=%d DF=%d OF=%d IOPL1=%d IOPL2=%d NT=%d RF=%d VM=%d AC=%d VIF=%d VIP=%d ID=%d\n"
						, GetFlagBit(context.EFlags, 0), GetFlagBit(context.EFlags, 2)
						, GetFlagBit(context.EFlags, 4), GetFlagBit(context.EFlags, 6)
						, GetFlagBit(context.EFlags, 7), GetFlagBit(context.EFlags, 8)
						, GetFlagBit(context.EFlags, 9), GetFlagBit(context.EFlags, 10)
						, GetFlagBit(context.EFlags, 11), GetFlagBit(context.EFlags, 12)
						, GetFlagBit(context.EFlags, 13), GetFlagBit(context.EFlags, 14)
						, GetFlagBit(context.EFlags, 16), GetFlagBit(context.EFlags, 17)
						, GetFlagBit(context.EFlags, 18), GetFlagBit(context.EFlags, 19)
						, GetFlagBit(context.EFlags, 20), GetFlagBit(context.EFlags, 21));
					printf("	cs=%02x ss=%02x ds=%02x es=%02x fs=%02x gs=%02x\n", context.SegCs, context.SegSs, context.SegDs, context.SegEs, context.SegFs, context.SegGs);
				}
			}
		};
	};
};