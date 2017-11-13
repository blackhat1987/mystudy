// From llvm/Support/MachO.h - The MachO file format
#ifndef LIEF_MACHO_STRUCTURES_H_
#define LIEF_MACHO_STRUCTURES_H_

#include <cstdint>

#include "LIEF/types.hpp"

#include "LIEF/MachO/enums.hpp"


// Swap 2 byte, 16 bit values:
#define Swap2Bytes(val) \
 ( (((val) >> 8) & 0x00FF) | (((val) << 8) & 0xFF00) )


// Swap 4 byte, 32 bit values:
#define Swap4Bytes(val) \
 ( (((val) >> 24) & 0x000000FF) | (((val) >>  8) & 0x0000FF00) | \
   (((val) <<  8) & 0x00FF0000) | (((val) << 24) & 0xFF000000) )



// Swap 8 byte, 64 bit values:
#define Swap8Bytes(val) \
 ( (((val) >> 56) & 0x00000000000000FF) | (((val) >> 40) & 0x000000000000FF00) | \
   (((val) >> 24) & 0x0000000000FF0000) | (((val) >>  8) & 0x00000000FF000000) | \
   (((val) <<  8) & 0x000000FF00000000) | (((val) << 24) & 0x0000FF0000000000) | \
   (((val) << 40) & 0x00FF000000000000) | (((val) << 56) & 0xFF00000000000000) )

namespace LIEF {
//! Namespace related to the LIEF's MachO module
namespace MachO {

  
struct mach_header {
  uint32_t magic;
  uint32_t cputype;
  uint32_t cpusubtype;
  uint32_t filetype;
  uint32_t ncmds;
  uint32_t sizeofcmds;
  uint32_t flags;
  //uint32_t reserved; not for 32 bits
};

struct mach_header_64 {
  uint32_t magic;
  uint32_t cputype;
  uint32_t cpusubtype;
  uint32_t filetype;
  uint32_t ncmds;
  uint32_t sizeofcmds;
  uint32_t flags;
  uint32_t reserved;
};

struct load_command {
  uint32_t cmd;
  uint32_t cmdsize;
};

struct segment_command_32 {
  uint32_t cmd;
  uint32_t cmdsize;
  char     segname[16];
  uint32_t vmaddr;
  uint32_t vmsize;
  uint32_t fileoff;
  uint32_t filesize;
  uint32_t maxprot;
  uint32_t initprot;
  uint32_t nsects;
  uint32_t flags;
};

struct segment_command_64 {
  uint32_t cmd;
  uint32_t cmdsize;
  char     segname[16];
  uint64_t vmaddr;
  uint64_t vmsize;
  uint64_t fileoff;
  uint64_t filesize;
  uint32_t maxprot;
  uint32_t initprot;
  uint32_t nsects;
  uint32_t flags;
};

struct section_32 {
  char sectname[16];
  char segname[16];
  uint32_t addr;
  uint32_t size;
  uint32_t offset;
  uint32_t align;
  uint32_t reloff;
  uint32_t nreloc;
  uint32_t flags;
  uint32_t reserved1;
  uint32_t reserved2;
};

struct section_64 {
  char sectname[16];
  char segname[16];
  uint64_t addr;
  uint64_t size;
  uint32_t offset;
  uint32_t align;
  uint32_t reloff;
  uint32_t nreloc;
  uint32_t flags;
  uint32_t reserved1;
  uint32_t reserved2;
  uint32_t reserved3;
};

struct fvmlib {
  uint32_t name;
  uint32_t minor_version;
  uint32_t header_addr;
};

struct fvmlib_command {
  uint32_t  cmd;
  uint32_t cmdsize;
  struct fvmlib fvmlib;
};

struct dylib {
  uint32_t name;
  uint32_t timestamp;
  uint32_t current_version;
  uint32_t compatibility_version;
};

struct dylib_command {
  uint32_t cmd;
  uint32_t cmdsize;
  struct dylib dylib;
};

struct sub_framework_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t umbrella;
};

struct sub_client_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t client;
};

struct sub_umbrella_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t sub_umbrella;
};

struct sub_library_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t sub_library;
};

struct prebound_dylib_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t name;
  uint32_t nmodules;
  uint32_t linked_modules;
};

struct dylinker_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t name;
};

struct thread_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t flavor;
  uint32_t count;
};

struct routines_command_32 {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t init_address;
  uint32_t init_module;
  uint32_t reserved1;
  uint32_t reserved2;
  uint32_t reserved3;
  uint32_t reserved4;
  uint32_t reserved5;
  uint32_t reserved6;
};

struct routines_command_64 {
  uint32_t cmd;
  uint32_t cmdsize;
  uint64_t init_address;
  uint64_t init_module;
  uint64_t reserved1;
  uint64_t reserved2;
  uint64_t reserved3;
  uint64_t reserved4;
  uint64_t reserved5;
  uint64_t reserved6;
};

struct symtab_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t symoff;
  uint32_t nsyms;
  uint32_t stroff;
  uint32_t strsize;
};

struct dysymtab_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t ilocalsym;
  uint32_t nlocalsym;
  uint32_t iextdefsym;
  uint32_t nextdefsym;
  uint32_t iundefsym;
  uint32_t nundefsym;
  uint32_t tocoff;
  uint32_t ntoc;
  uint32_t modtaboff;
  uint32_t nmodtab;
  uint32_t extrefsymoff;
  uint32_t nextrefsyms;
  uint32_t indirectsymoff;
  uint32_t nindirectsyms;
  uint32_t extreloff;
  uint32_t nextrel;
  uint32_t locreloff;
  uint32_t nlocrel;
};

struct dylib_table_of_contents {
  uint32_t symbol_index;
  uint32_t module_index;
};

struct dylib_module_32 {
  uint32_t module_name;
  uint32_t iextdefsym;
  uint32_t nextdefsym;
  uint32_t irefsym;
  uint32_t nrefsym;
  uint32_t ilocalsym;
  uint32_t nlocalsym;
  uint32_t iextrel;
  uint32_t nextrel;
  uint32_t iinit_iterm;
  uint32_t ninit_nterm;
  uint32_t objc_module_info_addr;
  uint32_t objc_module_info_size;
};

struct dylib_module_64 {
  uint32_t module_name;
  uint32_t iextdefsym;
  uint32_t nextdefsym;
  uint32_t irefsym;
  uint32_t nrefsym;
  uint32_t ilocalsym;
  uint32_t nlocalsym;
  uint32_t iextrel;
  uint32_t nextrel;
  uint32_t iinit_iterm;
  uint32_t ninit_nterm;
  uint32_t objc_module_info_size;
  uint64_t objc_module_info_addr;
};

struct dylib_reference {
  uint32_t isym:24,
           flags:8;
};

struct twolevel_hints_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t offset;
  uint32_t nhints;
};

struct twolevel_hint {
  uint32_t isub_image:8,
           itoc:24;
};

struct prebind_cksum_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t cksum;
};

struct uuid_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint8_t uuid[16];
};

struct rpath_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t path;
};

struct linkedit_data_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t dataoff;
  uint32_t datasize;
};

struct data_in_code_entry {
  uint32_t offset;
  uint16_t length;
  uint16_t kind;
};

struct source_version_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint64_t version;
};

struct encryption_info_command_32 {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t cryptoff;
  uint32_t cryptsize;
  uint32_t cryptid;
};

struct encryption_info_command_64 {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t cryptoff;
  uint32_t cryptsize;
  uint32_t cryptid;
  uint32_t pad;
};

struct version_min_command {
  uint32_t cmd;       // LC_VERSION_MIN_MACOSX or
                      // LC_VERSION_MIN_IPHONEOS
  uint32_t cmdsize;   // sizeof(struct version_min_command)
  uint32_t version;   // X.Y.Z is encoded in nibbles xxxx.yy.zz
  uint32_t sdk;       // X.Y.Z is encoded in nibbles xxxx.yy.zz
};

struct dyld_info_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t rebase_off;
  uint32_t rebase_size;
  uint32_t bind_off;
  uint32_t bind_size;
  uint32_t weak_bind_off;
  uint32_t weak_bind_size;
  uint32_t lazy_bind_off;
  uint32_t lazy_bind_size;
  uint32_t export_off;
  uint32_t export_size;
};

struct linker_option_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t count;
};

struct symseg_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t offset;
  uint32_t size;
};

struct ident_command {
  uint32_t cmd;
  uint32_t cmdsize;
};

struct fvmfile_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t name;
  uint32_t header_addr;
};

struct tlv_descriptor_32 {
  uint32_t thunk;
  uint32_t key;
  uint32_t offset;
};

struct tlv_descriptor_64 {
  uint64_t thunk;
  uint64_t key;
  uint64_t offset;
};

struct tlv_descriptor {
  uintptr_t thunk;
  uintptr_t key;
  uintptr_t offset;
};

struct entry_point_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint64_t entryoff;
  uint64_t stacksize;
};

// Structs from <mach-o/fat.h>
struct fat_header {
  uint32_t magic;
  uint32_t nfat_arch;
};

struct fat_arch {
  uint32_t cputype;
  uint32_t cpusubtype;
  uint32_t offset;
  uint32_t size;
  uint32_t align;
};

// Structs from <mach-o/reloc.h>
struct relocation_info {
  int32_t r_address;
  uint32_t r_symbolnum:24,
           r_pcrel:1,
           r_length:2,
           r_extern:1,
           r_type:4;
};


struct scattered_relocation_info {
  #if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && (BYTE_ORDER == BIG_ENDIAN)
  uint32_t r_scattered:1,
           r_pcrel:1,
           r_length:2,
           r_type:4,
           r_address:24;
  #else
  uint32_t r_address:24,
           r_type:4,
           r_length:2,
           r_pcrel:1,
           r_scattered:1;
  #endif
  int32_t r_value;
};


// Structs NOT from <mach-o/reloc.h>, but that make LLVM's life easier
struct any_relocation_info {
  uint32_t r_word0, r_word1;
};

// Structs from <mach-o/nlist.h>
struct nlist_base {
  uint32_t n_strx;
  uint8_t n_type;
  uint8_t n_sect;
  uint16_t n_desc;
};

struct nlist_32 {
  uint32_t n_strx;
  uint8_t n_type;
  uint8_t n_sect;
  int16_t n_desc;
  uint32_t n_value;
};

struct nlist_64 {
  uint32_t n_strx;
  uint8_t n_type;
  uint8_t n_sect;
  uint16_t n_desc;
  uint64_t n_value;
};


struct x86hread_state64 {
  uint64_t rax;
  uint64_t rbx;
  uint64_t rcx;
  uint64_t rdx;
  uint64_t rdi;
  uint64_t rsi;
  uint64_t rbp;
  uint64_t rsp;
  uint64_t r8;
  uint64_t r9;
  uint64_t r10;
  uint64_t r11;
  uint64_t r12;
  uint64_t r13;
  uint64_t r14;
  uint64_t r15;
  uint64_t rip;
  uint64_t rflags;
  uint64_t cs;
  uint64_t fs;
  uint64_t gs;
};


struct fp_control_t {
  unsigned short
   invalid :1,
   denorm  :1,
   zdiv    :1,
   ovrfl   :1,
   undfl   :1,
   precis  :1,
           :2,
   pc      :2,
   rc      :2,
           :1,
           :3;
};

struct fp_status_t {
  unsigned short
    invalid :1,
    denorm  :1,
    zdiv    :1,
    ovrfl   :1,
    undfl   :1,
    precis  :1,
    stkflt  :1,
    errsumm :1,
    c0      :1,
    c1      :1,
    c2      :1,
    tos     :3,
    c3      :1,
    busy    :1;
};


struct mmst_reg_t {
  char mmst_reg[10];
  char mmst_rsrv[6];
};

struct xmm_reg_t {
  char xmm_reg[16];
};

struct x86_float_state64 {
  int32_t fpu_reserved[2];
  fp_control_t fpu_fcw;
  fp_status_t fpu_fsw;
  uint8_t fpu_ftw;
  uint8_t fpu_rsrv1;
  uint16_t fpu_fop;
  uint32_t fpu_ip;
  uint16_t fpu_cs;
  uint16_t fpu_rsrv2;
  uint32_t fpu_dp;
  uint16_t fpu_ds;
  uint16_t fpu_rsrv3;
  uint32_t fpu_mxcsr;
  uint32_t fpu_mxcsrmask;
  mmst_reg_t fpu_stmm0;
  mmst_reg_t fpu_stmm1;
  mmst_reg_t fpu_stmm2;
  mmst_reg_t fpu_stmm3;
  mmst_reg_t fpu_stmm4;
  mmst_reg_t fpu_stmm5;
  mmst_reg_t fpu_stmm6;
  mmst_reg_t fpu_stmm7;
  xmm_reg_t fpu_xmm0;
  xmm_reg_t fpu_xmm1;
  xmm_reg_t fpu_xmm2;
  xmm_reg_t fpu_xmm3;
  xmm_reg_t fpu_xmm4;
  xmm_reg_t fpu_xmm5;
  xmm_reg_t fpu_xmm6;
  xmm_reg_t fpu_xmm7;
  xmm_reg_t fpu_xmm8;
  xmm_reg_t fpu_xmm9;
  xmm_reg_t fpu_xmm10;
  xmm_reg_t fpu_xmm11;
  xmm_reg_t fpu_xmm12;
  xmm_reg_t fpu_xmm13;
  xmm_reg_t fpu_xmm14;
  xmm_reg_t fpu_xmm15;
  char fpu_rsrv4[6*16];
  uint32_t fpu_reserved1;
};

struct x86_exception_state64 {
  uint16_t trapno;
  uint16_t cpu;
  uint32_t err;
  uint64_t faultvaddr;
};


struct x86_state_hdr_t {
  uint32_t flavor;
  uint32_t count;
};

struct x86hread_state_t {
  x86_state_hdr_t tsh;
  union {
    x86hread_state64 ts64;
  } uts;
};

struct x86_float_state_t {
  x86_state_hdr_t fsh;
  union {
    x86_float_state64 fs64;
  } ufs;
};

struct x86_exception_state_t {
  x86_state_hdr_t esh;
  union {
    x86_exception_state64 es64;
  } ues;
};



  static const HEADER_FLAGS header_flags_array[] = {
    HEADER_FLAGS::MH_NOUNDEFS,              HEADER_FLAGS::MH_INCRLINK,
    HEADER_FLAGS::MH_DYLDLINK,              HEADER_FLAGS::MH_BINDATLOAD,
    HEADER_FLAGS::MH_PREBOUND,              HEADER_FLAGS::MH_SPLIT_SEGS,
    HEADER_FLAGS::MH_LAZY_INIT,             HEADER_FLAGS::MH_TWOLEVEL,
    HEADER_FLAGS::MH_FORCE_FLAT,            HEADER_FLAGS::MH_NOMULTIDEFS,
    HEADER_FLAGS::MH_NOFIXPREBINDING,       HEADER_FLAGS::MH_PREBINDABLE,
    HEADER_FLAGS::MH_ALLMODSBOUND,          HEADER_FLAGS::MH_SUBSECTIONS_VIA_SYMBOLS,
    HEADER_FLAGS::MH_CANONICAL,             HEADER_FLAGS::MH_WEAK_DEFINES,
    HEADER_FLAGS::MH_BINDS_TO_WEAK,         HEADER_FLAGS::MH_ALLOW_STACK_EXECUTION,
    HEADER_FLAGS::MH_ROOT_SAFE,             HEADER_FLAGS::MH_SETUID_SAFE,
    HEADER_FLAGS::MH_NO_REEXPORTED_DYLIBS,  HEADER_FLAGS::MH_PIE,
    HEADER_FLAGS::MH_DEAD_STRIPPABLE_DYLIB, HEADER_FLAGS::MH_HAS_TLV_DESCRIPTORS,
    HEADER_FLAGS::MH_NO_HEAP_EXECUTION,     HEADER_FLAGS::MH_APP_EXTENSION_SAFE
  };


  static const SECTION_FLAGS section_flags_array[] = {
    SECTION_FLAGS::S_ATTR_PURE_INSTRUCTIONS, SECTION_FLAGS::S_ATTR_NO_TOC,
    SECTION_FLAGS::S_ATTR_STRIP_STATIC_SYMS, SECTION_FLAGS::S_ATTR_NO_DEAD_STRIP,
    SECTION_FLAGS::S_ATTR_LIVE_SUPPORT,      SECTION_FLAGS::S_ATTR_SELF_MODIFYING_CODE,
    SECTION_FLAGS::S_ATTR_DEBUG,             SECTION_FLAGS::S_ATTR_SOME_INSTRUCTIONS,
    SECTION_FLAGS::S_ATTR_EXT_RELOC,         SECTION_FLAGS::S_ATTR_LOC_RELOC
  };



  // Structs from <mach-o/loader.h>




  // Byte order swapping functions for MachO structs

  //inline void swapStruct(mach_header &mh) {
  //  sys::swapByteOrder(mh.magic);
  //  sys::swapByteOrder(mh.cputype);
  //  sys::swapByteOrder(mh.cpusubtype);
  //  sys::swapByteOrder(mh.filetype);
  //  sys::swapByteOrder(mh.ncmds);
  //  sys::swapByteOrder(mh.sizeofcmds);
  //  sys::swapByteOrder(mh.flags);
  //}

  //inline void swapStruct(mach_header_64 &H) {
  //  sys::swapByteOrder(H.magic);
  //  sys::swapByteOrder(H.cputype);
  //  sys::swapByteOrder(H.cpusubtype);
  //  sys::swapByteOrder(H.filetype);
  //  sys::swapByteOrder(H.ncmds);
  //  sys::swapByteOrder(H.sizeofcmds);
  //  sys::swapByteOrder(H.flags);
  //  sys::swapByteOrder(H.reserved);
  //}

  //inline void swapStruct(load_command &lc) {
  //  sys::swapByteOrder(lc.cmd);
  //  sys::swapByteOrder(lc.cmdsize);
  //}

  //inline void swapStruct(symtab_command &lc) {
  //  sys::swapByteOrder(lc.cmd);
  //  sys::swapByteOrder(lc.cmdsize);
  //  sys::swapByteOrder(lc.symoff);
  //  sys::swapByteOrder(lc.nsyms);
  //  sys::swapByteOrder(lc.stroff);
  //  sys::swapByteOrder(lc.strsize);
  //}

  //inline void swapStruct(segment_command_64 &seg) {
  //  sys::swapByteOrder(seg.cmd);
  //  sys::swapByteOrder(seg.cmdsize);
  //  sys::swapByteOrder(seg.vmaddr);
  //  sys::swapByteOrder(seg.vmsize);
  //  sys::swapByteOrder(seg.fileoff);
  //  sys::swapByteOrder(seg.filesize);
  //  sys::swapByteOrder(seg.maxprot);
  //  sys::swapByteOrder(seg.initprot);
  //  sys::swapByteOrder(seg.nsects);
  //  sys::swapByteOrder(seg.flags);
  //}

  //inline void swapStruct(segment_command &seg) {
  //  sys::swapByteOrder(seg.cmd);
  //  sys::swapByteOrder(seg.cmdsize);
  //  sys::swapByteOrder(seg.vmaddr);
  //  sys::swapByteOrder(seg.vmsize);
  //  sys::swapByteOrder(seg.fileoff);
  //  sys::swapByteOrder(seg.filesize);
  //  sys::swapByteOrder(seg.maxprot);
  //  sys::swapByteOrder(seg.initprot);
  //  sys::swapByteOrder(seg.nsects);
  //  sys::swapByteOrder(seg.flags);
  //}

  //inline void swapStruct(section_64 &sect) {
  //  sys::swapByteOrder(sect.addr);
  //  sys::swapByteOrder(sect.size);
  //  sys::swapByteOrder(sect.offset);
  //  sys::swapByteOrder(sect.align);
  //  sys::swapByteOrder(sect.reloff);
  //  sys::swapByteOrder(sect.nreloc);
  //  sys::swapByteOrder(sect.flags);
  //  sys::swapByteOrder(sect.reserved1);
  //  sys::swapByteOrder(sect.reserved2);
  //}

  //inline void swapStruct(section &sect) {
  //  sys::swapByteOrder(sect.addr);
  //  sys::swapByteOrder(sect.size);
  //  sys::swapByteOrder(sect.offset);
  //  sys::swapByteOrder(sect.align);
  //  sys::swapByteOrder(sect.reloff);
  //  sys::swapByteOrder(sect.nreloc);
  //  sys::swapByteOrder(sect.flags);
  //  sys::swapByteOrder(sect.reserved1);
  //  sys::swapByteOrder(sect.reserved2);
  //}

  //inline void swapStruct(dyld_info_command &info) {
  //  sys::swapByteOrder(info.cmd);
  //  sys::swapByteOrder(info.cmdsize);
  //  sys::swapByteOrder(info.rebase_off);
  //  sys::swapByteOrder(info.rebase_size);
  //  sys::swapByteOrder(info.bind_off);
  //  sys::swapByteOrder(info.bind_size);
  //  sys::swapByteOrder(info.weak_bind_off);
  //  sys::swapByteOrder(info.weak_bind_size);
  //  sys::swapByteOrder(info.lazy_bind_off);
  //  sys::swapByteOrder(info.lazy_bind_size);
  //  sys::swapByteOrder(info.export_off);
  //  sys::swapByteOrder(info.export_size);
  //}

  //inline void swapStruct(dylib_command &d) {
  //  sys::swapByteOrder(d.cmd);
  //  sys::swapByteOrder(d.cmdsize);
  //  sys::swapByteOrder(d.dylib.name);
  //  sys::swapByteOrder(d.dylib.timestamp);
  //  sys::swapByteOrder(d.dylib.current_version);
  //  sys::swapByteOrder(d.dylib.compatibility_version);
  //}

  //inline void swapStruct(sub_framework_command &s) {
  //  sys::swapByteOrder(s.cmd);
  //  sys::swapByteOrder(s.cmdsize);
  //  sys::swapByteOrder(s.umbrella);
  //}

  //inline void swapStruct(sub_umbrella_command &s) {
  //  sys::swapByteOrder(s.cmd);
  //  sys::swapByteOrder(s.cmdsize);
  //  sys::swapByteOrder(s.sub_umbrella);
  //}

  //inline void swapStruct(sub_library_command &s) {
  //  sys::swapByteOrder(s.cmd);
  //  sys::swapByteOrder(s.cmdsize);
  //  sys::swapByteOrder(s.sub_library);
  //}

  //inline void swapStruct(sub_client_command &s) {
  //  sys::swapByteOrder(s.cmd);
  //  sys::swapByteOrder(s.cmdsize);
  //  sys::swapByteOrder(s.client);
  //}

  //inline void swapStruct(routines_command &r) {
  //  sys::swapByteOrder(r.cmd);
  //  sys::swapByteOrder(r.cmdsize);
  //  sys::swapByteOrder(r.init_address);
  //  sys::swapByteOrder(r.init_module);
  //  sys::swapByteOrder(r.reserved1);
  //  sys::swapByteOrder(r.reserved2);
  //  sys::swapByteOrder(r.reserved3);
  //  sys::swapByteOrder(r.reserved4);
  //  sys::swapByteOrder(r.reserved5);
  //  sys::swapByteOrder(r.reserved6);
  //}

  //inline void swapStruct(routines_command_64 &r) {
  //  sys::swapByteOrder(r.cmd);
  //  sys::swapByteOrder(r.cmdsize);
  //  sys::swapByteOrder(r.init_address);
  //  sys::swapByteOrder(r.init_module);
  //  sys::swapByteOrder(r.reserved1);
  //  sys::swapByteOrder(r.reserved2);
  //  sys::swapByteOrder(r.reserved3);
  //  sys::swapByteOrder(r.reserved4);
  //  sys::swapByteOrder(r.reserved5);
  //  sys::swapByteOrder(r.reserved6);
  //}

  //inline void swapStruct(thread_command &t) {
  //  sys::swapByteOrder(t.cmd);
  //  sys::swapByteOrder(t.cmdsize);
  //}

  //inline void swapStruct(dylinker_command &d) {
  //  sys::swapByteOrder(d.cmd);
  //  sys::swapByteOrder(d.cmdsize);
  //  sys::swapByteOrder(d.name);
  //}

  //inline void swapStruct(uuid_command &u) {
  //  sys::swapByteOrder(u.cmd);
  //  sys::swapByteOrder(u.cmdsize);
  //}

  //inline void swapStruct(rpath_command &r) {
  //  sys::swapByteOrder(r.cmd);
  //  sys::swapByteOrder(r.cmdsize);
  //  sys::swapByteOrder(r.path);
  //}

  //inline void swapStruct(source_version_command &s) {
  //  sys::swapByteOrder(s.cmd);
  //  sys::swapByteOrder(s.cmdsize);
  //  sys::swapByteOrder(s.version);
  //}

  //inline void swapStruct(entry_point_command &e) {
  //  sys::swapByteOrder(e.cmd);
  //  sys::swapByteOrder(e.cmdsize);
  //  sys::swapByteOrder(e.entryoff);
  //  sys::swapByteOrder(e.stacksize);
  //}

  //inline void swapStruct(encryption_info_command &e) {
  //  sys::swapByteOrder(e.cmd);
  //  sys::swapByteOrder(e.cmdsize);
  //  sys::swapByteOrder(e.cryptoff);
  //  sys::swapByteOrder(e.cryptsize);
  //  sys::swapByteOrder(e.cryptid);
  //}

  //inline void swapStruct(encryption_info_command_64 &e) {
  //  sys::swapByteOrder(e.cmd);
  //  sys::swapByteOrder(e.cmdsize);
  //  sys::swapByteOrder(e.cryptoff);
  //  sys::swapByteOrder(e.cryptsize);
  //  sys::swapByteOrder(e.cryptid);
  //  sys::swapByteOrder(e.pad);
  //}

  //inline void swapStruct(dysymtab_command &dst) {
  //  sys::swapByteOrder(dst.cmd);
  //  sys::swapByteOrder(dst.cmdsize);
  //  sys::swapByteOrder(dst.ilocalsym);
  //  sys::swapByteOrder(dst.nlocalsym);
  //  sys::swapByteOrder(dst.iextdefsym);
  //  sys::swapByteOrder(dst.nextdefsym);
  //  sys::swapByteOrder(dst.iundefsym);
  //  sys::swapByteOrder(dst.nundefsym);
  //  sys::swapByteOrder(dst.tocoff);
  //  sys::swapByteOrder(dst.ntoc);
  //  sys::swapByteOrder(dst.modtaboff);
  //  sys::swapByteOrder(dst.nmodtab);
  //  sys::swapByteOrder(dst.extrefsymoff);
  //  sys::swapByteOrder(dst.nextrefsyms);
  //  sys::swapByteOrder(dst.indirectsymoff);
  //  sys::swapByteOrder(dst.nindirectsyms);
  //  sys::swapByteOrder(dst.extreloff);
  //  sys::swapByteOrder(dst.nextrel);
  //  sys::swapByteOrder(dst.locreloff);
  //  sys::swapByteOrder(dst.nlocrel);
  //}

  //inline void swapStruct(any_relocation_info &reloc) {
  //  sys::swapByteOrder(reloc.r_word0);
  //  sys::swapByteOrder(reloc.r_word1);
  //}

  //inline void swapStruct(nlist_base &S) {
  //  sys::swapByteOrder(S.n_strx);
  //  sys::swapByteOrder(S.n_desc);
  //}

  //inline void swapStruct(nlist &sym) {
  //  sys::swapByteOrder(sym.n_strx);
  //  sys::swapByteOrder(sym.n_desc);
  //  sys::swapByteOrder(sym.n_value);
  //}

  //inline void swapStruct(nlist_64 &sym) {
  //  sys::swapByteOrder(sym.n_strx);
  //  sys::swapByteOrder(sym.n_desc);
  //  sys::swapByteOrder(sym.n_value);
  //}

  //inline void swapStruct(linkedit_data_command &C) {
  //  sys::swapByteOrder(C.cmd);
  //  sys::swapByteOrder(C.cmdsize);
  //  sys::swapByteOrder(C.dataoff);
  //  sys::swapByteOrder(C.datasize);
  //}

  //inline void swapStruct(linker_option_command &C) {
  //  sys::swapByteOrder(C.cmd);
  //  sys::swapByteOrder(C.cmdsize);
  //  sys::swapByteOrder(C.count);
  //}

  //inline void swapStruct(version_min_command&C) {
  //  sys::swapByteOrder(C.cmd);
  //  sys::swapByteOrder(C.cmdsize);
  //  sys::swapByteOrder(C.version);
  //  sys::swapByteOrder(C.sdk);
  //}

  //inline void swapStruct(data_in_code_entry &C) {
  //  sys::swapByteOrder(C.offset);
  //  sys::swapByteOrder(C.length);
  //  sys::swapByteOrder(C.kind);
  //}

  //inline void swapStruct(uint32_t &C) {
  //  sys::swapByteOrder(C);
  //}

  // Get/Set functions from <mach-o/nlist.h>

  //static inline uint16_t GET_LIBRARY_ORDINAL(uint16_t n_desc) {
  //  return (((n_desc) >> 8u) & 0xffu);
  //}

  //static inline void SET_LIBRARY_ORDINAL(uint16_t &n_desc, uint8_t ordinal) {
  //  n_desc = (((n_desc) & 0x00ff) | (((ordinal) & 0xff) << 8));
  //}

  //static inline uint8_t GET_COMM_ALIGN (uint16_t n_desc) {
  //  return (n_desc >> 8u) & 0x0fu;
  //}

  //static inline void SET_COMM_ALIGN (uint16_t &n_desc, uint8_t align) {
  //  n_desc = ((n_desc & 0xf0ffu) | ((align & 0x0fu) << 8u));
  //}

  //static inline int CPU_SUBTYPE_INTEL(int Family, int Model) {
  //  return Family | (Model << 4);
  //}
  //static inline int CPU_SUBTYPE_INTEL_FAMILY(CPUSubTypeX86 ST) {
  //  return ((int)ST) & 0x0f;
  //}
  //static inline int CPU_SUBTYPE_INTEL_MODEL(CPUSubTypeX86 ST) {
  //  return ((int)ST) >> 4;
  //}





  //inline void swapStruct(x86hread_state64 &x) {
  //  sys::swapByteOrder(x.rax);
  //  sys::swapByteOrder(x.rbx);
  //  sys::swapByteOrder(x.rcx);
  //  sys::swapByteOrder(x.rdx);
  //  sys::swapByteOrder(x.rdi);
  //  sys::swapByteOrder(x.rsi);
  //  sys::swapByteOrder(x.rbp);
  //  sys::swapByteOrder(x.rsp);
  //  sys::swapByteOrder(x.r8);
  //  sys::swapByteOrder(x.r9);
  //  sys::swapByteOrder(x.r10);
  //  sys::swapByteOrder(x.r11);
  //  sys::swapByteOrder(x.r12);
  //  sys::swapByteOrder(x.r13);
  //  sys::swapByteOrder(x.r14);
  //  sys::swapByteOrder(x.r15);
  //  sys::swapByteOrder(x.rip);
  //  sys::swapByteOrder(x.rflags);
  //  sys::swapByteOrder(x.cs);
  //  sys::swapByteOrder(x.fs);
  //  sys::swapByteOrder(x.gs);
  //}

  //inline void swapStruct(x86_float_state64 &x) {
  //  sys::swapByteOrder(x.fpu_reserved[0]);
  //  sys::swapByteOrder(x.fpu_reserved[1]);
  //  // TODO swap: fp_control_t fpu_fcw;
  //  // TODO swap: fp_status_t fpu_fsw;
  //  sys::swapByteOrder(x.fpu_fop);
  //  sys::swapByteOrder(x.fpu_ip);
  //  sys::swapByteOrder(x.fpu_cs);
  //  sys::swapByteOrder(x.fpu_rsrv2);
  //  sys::swapByteOrder(x.fpu_dp);
  //  sys::swapByteOrder(x.fpu_ds);
  //  sys::swapByteOrder(x.fpu_rsrv3);
  //  sys::swapByteOrder(x.fpu_mxcsr);
  //  sys::swapByteOrder(x.fpu_mxcsrmask);
  //  sys::swapByteOrder(x.fpu_reserved1);
  //}

  //inline void swapStruct(x86_exception_state64 &x) {
  //  sys::swapByteOrder(x.trapno);
  //  sys::swapByteOrder(x.cpu);
  //  sys::swapByteOrder(x.err);
  //  sys::swapByteOrder(x.faultvaddr);
  //}


  //inline void swapStruct(x86_state_hdr_t &x) {
  //  sys::swapByteOrder(x.flavor);
  //  sys::swapByteOrder(x.count);
  //}


  //inline void swapStruct(x86hread_state_t &x) {
  //  swapStruct(x.tsh);
  //  if (x.tsh.flavor == x86HREAD_STATE64)
  //    swapStruct(x.uts.ts64);
  //}

  //inline void swapStruct(x86_float_state_t &x) {
  //  swapStruct(x.fsh);
  //  if (x.fsh.flavor == x86_FLOAT_STATE64)
  //    swapStruct(x.ufs.fs64);
  //}

  //inline void swapStruct(x86_exception_state_t &x) {
  //  swapStruct(x.esh);
  //  if (x.esh.flavor == x86_EXCEPTION_STATE64)
  //    swapStruct(x.ues.es64);
  //}

  const uint32_t x86HREAD_STATE64_COUNT =
    sizeof(x86hread_state64) / sizeof(uint32_t);
  const uint32_t x86_FLOAT_STATE64_COUNT =
    sizeof(x86_float_state64) / sizeof(uint32_t);
  const uint32_t x86_EXCEPTION_STATE64_COUNT =
    sizeof(x86_exception_state64) / sizeof(uint32_t);

  const uint32_t x86HREAD_STATE_COUNT =
    sizeof(x86hread_state_t) / sizeof(uint32_t);
  const uint32_t x86_FLOAT_STATE_COUNT =
    sizeof(x86_float_state_t) / sizeof(uint32_t);
  const uint32_t x86_EXCEPTION_STATE_COUNT =
    sizeof(x86_exception_state_t) / sizeof(uint32_t);

  class MachO32 {
    public:
    using header                  = mach_header;
    using segment_command         = segment_command_32;
    using section                 = section_32;
    using routines_command        = routines_command_32;
    using dylib_module            = dylib_module_32;
    using encryption_info_command = encryption_info_command_32;
    using nlist                   = nlist_32;

    using uint                    = uint32_t;
  };

  class MachO64 {
    public:
    using header                  = mach_header_64;
    using segment_command         = segment_command_64;
    using section                 = section_64;
    using routines_command        = routines_command_64;
    using dylib_module            = dylib_module_64;
    using encryption_info_command = encryption_info_command_64;
    using nlist                   = nlist_64;

    using uint                    = uint64_t;
  };

} // end namespace MachO
}
#endif
