typedef unsigned char   undefined;

typedef unsigned char    byte;
typedef unsigned char    dwfenc;
typedef unsigned int    dword;
typedef unsigned long    ulong;
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
typedef unsigned int    undefined4;
typedef unsigned short    word;
typedef struct eh_frame_hdr eh_frame_hdr, *Peh_frame_hdr;

struct eh_frame_hdr {
    byte eh_frame_hdr_version; // Exception Handler Frame Header Version
    dwfenc eh_frame_pointer_encoding; // Exception Handler Frame Pointer Encoding
    dwfenc eh_frame_desc_entry_count_encoding; // Encoding of # of Exception Handler FDEs
    dwfenc eh_frame_table_encoding; // Exception Handler Table Encoding
};

typedef struct fde_table_entry fde_table_entry, *Pfde_table_entry;

struct fde_table_entry {
    dword initial_loc; // Initial Location
    dword data_loc; // Data location
};

typedef ulong size_t;

typedef struct Elf32_Rel Elf32_Rel, *PElf32_Rel;

struct Elf32_Rel {
    dword r_offset; // location to apply the relocation action
    dword r_info; // the symbol table index and the type of relocation
};

typedef enum Elf32_DynTag_x86 {
    DT_AUDIT=1879047932,
    DT_AUXILIARY=2147483645,
    DT_BIND_NOW=24,
    DT_CHECKSUM=1879047672,
    DT_CONFIG=1879047930,
    DT_DEBUG=21,
    DT_DEPAUDIT=1879047931,
    DT_ENCODING=32,
    DT_FEATURE_1=1879047676,
    DT_FILTER=2147483647,
    DT_FINI=13,
    DT_FINI_ARRAY=26,
    DT_FINI_ARRAYSZ=28,
    DT_FLAGS=30,
    DT_FLAGS_1=1879048187,
    DT_GNU_CONFLICT=1879047928,
    DT_GNU_CONFLICTSZ=1879047670,
    DT_GNU_HASH=1879047925,
    DT_GNU_LIBLIST=1879047929,
    DT_GNU_LIBLISTSZ=1879047671,
    DT_GNU_PRELINKED=1879047669,
    DT_HASH=4,
    DT_INIT=12,
    DT_INIT_ARRAY=25,
    DT_INIT_ARRAYSZ=27,
    DT_JMPREL=23,
    DT_MOVEENT=1879047674,
    DT_MOVESZ=1879047675,
    DT_MOVETAB=1879047934,
    DT_NEEDED=1,
    DT_NULL=0,
    DT_PLTGOT=3,
    DT_PLTPAD=1879047933,
    DT_PLTPADSZ=1879047673,
    DT_PLTREL=20,
    DT_PLTRELSZ=2,
    DT_POSFLAG_1=1879047677,
    DT_PREINIT_ARRAYSZ=33,
    DT_REL=17,
    DT_RELA=7,
    DT_RELACOUNT=1879048185,
    DT_RELAENT=9,
    DT_RELASZ=8,
    DT_RELCOUNT=1879048186,
    DT_RELENT=19,
    DT_RELSZ=18,
    DT_RPATH=15,
    DT_RUNPATH=29,
    DT_SONAME=14,
    DT_STRSZ=10,
    DT_STRTAB=5,
    DT_SYMBOLIC=16,
    DT_SYMENT=11,
    DT_SYMINENT=1879047679,
    DT_SYMINFO=1879047935,
    DT_SYMINSZ=1879047678,
    DT_SYMTAB=6,
    DT_TEXTREL=22,
    DT_TLSDESC_GOT=1879047927,
    DT_TLSDESC_PLT=1879047926,
    DT_VERDEF=1879048188,
    DT_VERDEFNUM=1879048189,
    DT_VERNEED=1879048190,
    DT_VERNEEDNUM=1879048191,
    DT_VERSYM=1879048176
} Elf32_DynTag_x86;

typedef struct Elf32_Dyn_x86 Elf32_Dyn_x86, *PElf32_Dyn_x86;

struct Elf32_Dyn_x86 {
    enum Elf32_DynTag_x86 d_tag;
    dword d_val;
};

typedef struct Elf32_Phdr Elf32_Phdr, *PElf32_Phdr;

typedef enum Elf_ProgramHeaderType_x86 {
    PT_DYNAMIC=2,
    PT_GNU_EH_FRAME=1685382480,
    PT_GNU_RELRO=1685382482,
    PT_GNU_STACK=1685382481,
    PT_INTERP=3,
    PT_LOAD=1,
    PT_NOTE=4,
    PT_NULL=0,
    PT_PHDR=6,
    PT_SHLIB=5,
    PT_TLS=7
} Elf_ProgramHeaderType_x86;

struct Elf32_Phdr {
    enum Elf_ProgramHeaderType_x86 p_type;
    dword p_offset;
    dword p_vaddr;
    dword p_paddr;
    dword p_filesz;
    dword p_memsz;
    dword p_flags;
    dword p_align;
};

typedef struct Elf32_Shdr Elf32_Shdr, *PElf32_Shdr;

typedef enum Elf_SectionHeaderType_x86 {
    SHT_CHECKSUM=1879048184,
    SHT_DYNAMIC=6,
    SHT_DYNSYM=11,
    SHT_FINI_ARRAY=15,
    SHT_GNU_ATTRIBUTES=1879048181,
    SHT_GNU_HASH=1879048182,
    SHT_GNU_LIBLIST=1879048183,
    SHT_GNU_verdef=1879048189,
    SHT_GNU_verneed=1879048190,
    SHT_GNU_versym=1879048191,
    SHT_GROUP=17,
    SHT_HASH=5,
    SHT_INIT_ARRAY=14,
    SHT_NOBITS=8,
    SHT_NOTE=7,
    SHT_NULL=0,
    SHT_PREINIT_ARRAY=16,
    SHT_PROGBITS=1,
    SHT_REL=9,
    SHT_RELA=4,
    SHT_SHLIB=10,
    SHT_STRTAB=3,
    SHT_SUNW_COMDAT=1879048187,
    SHT_SUNW_move=1879048186,
    SHT_SUNW_syminfo=1879048188,
    SHT_SYMTAB=2,
    SHT_SYMTAB_SHNDX=18
} Elf_SectionHeaderType_x86;

struct Elf32_Shdr {
    dword sh_name;
    enum Elf_SectionHeaderType_x86 sh_type;
    dword sh_flags;
    dword sh_addr;
    dword sh_offset;
    dword sh_size;
    dword sh_link;
    dword sh_info;
    dword sh_addralign;
    dword sh_entsize;
};

typedef struct Elf32_Sym Elf32_Sym, *PElf32_Sym;

struct Elf32_Sym {
    dword st_name;
    dword st_value;
    dword st_size;
    byte st_info;
    byte st_other;
    word st_shndx;
};

typedef struct Elf32_Ehdr Elf32_Ehdr, *PElf32_Ehdr;

struct Elf32_Ehdr {
    byte e_ident_magic_num;
    char e_ident_magic_str[3];
    byte e_ident_class;
    byte e_ident_data;
    byte e_ident_version;
    byte e_ident_pad[9];
    word e_type;
    word e_machine;
    dword e_version;
    dword e_entry;
    dword e_phoff;
    dword e_shoff;
    dword e_flags;
    word e_ehsize;
    word e_phentsize;
    word e_phnum;
    word e_shentsize;
    word e_shnum;
    word e_shstrndx;
};

typedef struct evp_pkey_ctx_st evp_pkey_ctx_st, *Pevp_pkey_ctx_st;

struct evp_pkey_ctx_st {
};

typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;

typedef void * __gnuc_va_list;




int _init(EVP_PKEY_CTX *ctx)

{
  int iVar1;
  int unaff_EBX;
  
  entry();
  iVar1 = *(int *)(unaff_EBX + 0xec3f);
  if (iVar1 != 0) {
    iVar1 = __gmon_start__();
  }
  return iVar1;
}



void FUN_00012520(void)

{
                    // WARNING: Treating indirect jump as call
  (*(code *)(undefined *)0x0)();
  return;
}



void __cxa_finalize(void)

{
  __cxa_finalize();
  return;
}



void __gmon_start__(void)

{
  __gmon_start__();
  return;
}



void entry(void)

{
  return;
}



void FUN_00012560(void)

{
  int unaff_EBX;
  
  entry();
  if ((6 < (uint)((unaff_EBX + 0xec0a) - (unaff_EBX + 0xec07))) &&
     (*(code **)(unaff_EBX + 0xebcf) != (code *)0x0)) {
    (**(code **)(unaff_EBX + 0xebcf))(unaff_EBX + 0xec07);
  }
  return;
}



void _FINI_0(void)

{
  int unaff_EBX;
  
  entry();
  if (*(char *)(unaff_EBX + 0xeb87) == '\0') {
    if (*(int *)(unaff_EBX + 0xeb43) != 0) {
      __cxa_finalize(*(undefined4 *)(unaff_EBX + 0xeb67));
    }
    FUN_00012560();
    *(undefined *)(unaff_EBX + 0xeb87) = 1;
  }
  return;
}



void _INIT_0(void)

{
  int iVar1;
  int unaff_EBX;
  undefined4 unaff_EBP;
  int local_8;
  
  local_8 = unaff_EBX;
  entry();
  if ((*(int *)(unaff_EBX + 0xea03) != 0) && (*(code **)(unaff_EBX + 0xeafb) != (code *)0x0)) {
    (**(code **)(unaff_EBX + 0xeafb))((int *)(unaff_EBX + 0xea03));
  }
  entry(local_8,unaff_EBP);
  iVar1 = (local_8 + 0xebc7) - (local_8 + 0xebc7);
  iVar1 = (iVar1 >> 2) - (iVar1 >> 0x1f) >> 1;
  if ((iVar1 != 0) && (*(code **)(local_8 + 0xeb9f) != (code *)0x0)) {
    (**(code **)(local_8 + 0xeb9f))(local_8 + 0xebc7,iVar1);
  }
  return;
}



uint FUN_00012690(uint param_1,byte *param_2,uint param_3)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  byte *pbVar6;
  int iVar7;
  int iVar8;
  byte *pbVar9;
  uint uVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  int iVar14;
  int iVar15;
  int iVar16;
  int iVar17;
  int iVar18;
  uint local_48;
  uint local_1c;
  byte *local_18;
  
  local_1c = param_1 >> 0x10;
  param_1 = param_1 & 0xffff;
  if (param_3 == 1) {
    param_1 = *param_2 + param_1;
    if (0xfff0 < param_1) {
      param_1 = param_1 - 0xfff1;
    }
    local_1c = local_1c + param_1;
    if (0xfff0 < local_1c) {
      local_1c = local_1c - 0xfff1;
    }
    return param_1 | local_1c << 0x10;
  }
  if (param_2 == (byte *)0x0) {
    return 1;
  }
  if (param_3 < 0x10) {
    if (param_3 != 0) {
      pbVar9 = param_2;
      do {
        pbVar6 = pbVar9 + 1;
        param_1 = param_1 + *pbVar9;
        local_1c = local_1c + param_1;
        pbVar9 = pbVar6;
      } while (pbVar6 != param_2 + param_3);
    }
    if (0xfff0 < param_1) {
      param_1 = param_1 - 0xfff1;
    }
    return (local_1c % 0xfff1) * 0x10000 | param_1;
  }
  if (param_3 < 0x15b0) {
    if (param_3 == 0) goto LAB_00012a35;
    local_18 = param_2;
LAB_000128c6:
    local_48 = param_3;
    pbVar9 = local_18;
    do {
      local_48 = local_48 - 0x10;
      iVar15 = param_1 + *pbVar9;
      iVar1 = (uint)pbVar9[1] + iVar15;
      iVar17 = (uint)pbVar9[2] + iVar1;
      iVar11 = (uint)pbVar9[3] + iVar17;
      iVar7 = (uint)pbVar9[4] + iVar11;
      iVar13 = (uint)pbVar9[5] + iVar7;
      iVar16 = (uint)pbVar9[6] + iVar13;
      iVar2 = (uint)pbVar9[7] + iVar16;
      iVar14 = (uint)pbVar9[8] + iVar2;
      iVar18 = (uint)pbVar9[9] + iVar14;
      iVar12 = (uint)pbVar9[10] + iVar18;
      iVar8 = (uint)pbVar9[0xb] + iVar12;
      iVar3 = (uint)pbVar9[0xc] + iVar8;
      iVar4 = (uint)pbVar9[0xd] + iVar3;
      iVar5 = (uint)pbVar9[0xe] + iVar4;
      param_1 = (uint)pbVar9[0xf] + iVar5;
      local_1c = local_1c +
                 iVar1 + iVar15 + iVar17 + iVar11 + iVar7 + iVar13 + iVar16 + iVar2 + iVar14 +
                 iVar18 + iVar12 + iVar8 + iVar3 + iVar4 + iVar5 + param_1;
      pbVar9 = pbVar9 + 0x10;
    } while (0xf < local_48);
    uVar10 = param_3 & 0xf;
    local_18 = local_18 + (param_3 - 0x10 & 0xfffffff0) + 0x10;
    if (uVar10 != 0) goto LAB_000129db;
  }
  else {
    do {
      uVar10 = param_3 - 0x15b0;
      local_18 = param_2 + 0x15b0;
      do {
        iVar1 = param_1 + *param_2;
        iVar4 = (uint)param_2[1] + iVar1;
        iVar16 = (uint)param_2[2] + iVar4;
        iVar13 = (uint)param_2[3] + iVar16;
        iVar2 = (uint)param_2[4] + iVar13;
        iVar15 = (uint)param_2[5] + iVar2;
        iVar5 = (uint)param_2[6] + iVar15;
        iVar7 = (uint)param_2[7] + iVar5;
        iVar8 = (uint)param_2[8] + iVar7;
        iVar11 = (uint)param_2[9] + iVar8;
        iVar12 = (uint)param_2[10] + iVar11;
        iVar18 = (uint)param_2[0xb] + iVar12;
        iVar17 = (uint)param_2[0xc] + iVar18;
        iVar14 = (uint)param_2[0xd] + iVar17;
        iVar3 = (uint)param_2[0xe] + iVar14;
        param_1 = (uint)param_2[0xf] + iVar3;
        local_1c = local_1c +
                   iVar3 + iVar14 + iVar4 + iVar1 + iVar16 + iVar13 + iVar2 + iVar15 + iVar5 + iVar7
                                    + iVar8 + iVar11 + iVar12 + iVar18 + iVar17 + param_1;
        param_2 = param_2 + 0x10;
      } while (param_2 != local_18);
      param_1 = param_1 % 0xfff1;
      local_1c = local_1c % 0xfff1;
      param_2 = local_18;
      param_3 = uVar10;
    } while (0x15af < uVar10);
    if (uVar10 == 0) goto LAB_00012a35;
    if (0xf < uVar10) goto LAB_000128c6;
LAB_000129db:
    pbVar9 = local_18;
    do {
      pbVar6 = pbVar9 + 1;
      param_1 = param_1 + *pbVar9;
      local_1c = local_1c + param_1;
      pbVar9 = pbVar6;
    } while (pbVar6 != local_18 + uVar10);
  }
  param_1 = param_1 % 0xfff1;
  local_1c = local_1c % 0xfff1;
LAB_00012a35:
  return local_1c << 0x10 | param_1;
}



uint FUN_00012a61(uint param_1,uint param_2,uint param_3)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  
  iVar4 = (param_2 & 0xffff) + (param_1 & 0xffff);
  uVar3 = iVar4 + 0xfff0;
  iVar2 = (((param_1 >> 0x10) + (param_2 >> 0x10)) - param_3 % 0xfff1) +
          ((param_3 % 0xfff1) * (param_1 & 0xffff)) % 0xfff1;
  uVar1 = iVar2 + 0xfff1;
  if ((0xfff1 < uVar3) && (uVar3 = iVar4 - 1, 0xfff1 < uVar3)) {
    uVar3 = iVar4 - 0xfff2;
  }
  if (0x1ffe2 < uVar1) {
    uVar1 = iVar2 - 0xfff1;
  }
  if (0xfff1 < uVar1) {
    uVar1 = uVar1 - 0xfff1;
  }
  return uVar1 << 0x10 | uVar3;
}



uint __regparm3 FUN_00012b0a(uint *param_1,uint param_2)

{
  uint uVar1;
  
  if (param_2 != 0) {
    uVar1 = 0;
    do {
      if ((param_2 & 1) != 0) {
        uVar1 = uVar1 ^ *param_1;
      }
      param_1 = param_1 + 1;
      param_2 = param_2 >> 1;
    } while (param_2 != 0);
    return uVar1;
  }
  return 0;
}



void __regparm3 FUN_00012b2a(int param_1)

{
  undefined4 uVar1;
  int iVar2;
  
  iVar2 = 0;
  do {
    uVar1 = FUN_00012b0a();
    *(undefined4 *)(param_1 + iVar2 * 4) = uVar1;
    iVar2 = iVar2 + 1;
  } while (iVar2 != 0x20);
  return;
}



undefined * FUN_00012b4f(void)

{
  return &DAT_0001b000;
}



uint FUN_00012b55(uint param_1,uint *param_2,uint param_3)

{
  uint uVar1;
  uint *puVar2;
  uint *puVar3;
  uint uVar4;
  
  if (param_2 == (uint *)0x0) {
    param_1 = 0;
  }
  else {
    param_1 = ~param_1;
    if (param_3 == 0) {
LAB_00012e02:
      param_3 = 0;
    }
    else {
      uVar4 = (uint)param_2 & 3;
      while (uVar4 != 0) {
        puVar2 = (uint *)((int)param_2 + 1);
        param_1 = param_1 >> 8 ^
                  *(uint *)(&DAT_0001b000 + (uint)(byte)((byte)param_1 ^ *(byte *)param_2) * 4);
        param_3 = param_3 - 1;
        param_2 = puVar2;
        if (param_3 == 0) goto LAB_00012e02;
        uVar4 = (uint)puVar2 & 3;
      }
      puVar2 = param_2;
      uVar4 = param_3;
      if (0x1f < param_3) {
        do {
          param_1 = param_1 ^ *puVar2;
          uVar1 = *(uint *)(&DAT_0001bc00 + (param_1 & 0xff) * 4) ^
                  *(uint *)(&DAT_0001b000 + (param_1 >> 0x18) * 4) ^ puVar2[1] ^
                  *(uint *)(&DAT_0001b800 + (param_1 >> 8 & 0xff) * 4) ^
                  *(uint *)(&DAT_0001b400 + (param_1 >> 0x10 & 0xff) * 4);
          uVar1 = *(uint *)(&DAT_0001bc00 + (uVar1 & 0xff) * 4) ^
                  *(uint *)(&DAT_0001b000 + (uVar1 >> 0x18) * 4) ^ puVar2[2] ^
                  *(uint *)(&DAT_0001b800 + (uVar1 >> 8 & 0xff) * 4) ^
                  *(uint *)(&DAT_0001b400 + (uVar1 >> 0x10 & 0xff) * 4);
          uVar1 = *(uint *)(&DAT_0001bc00 + (uVar1 & 0xff) * 4) ^
                  *(uint *)(&DAT_0001b000 + (uVar1 >> 0x18) * 4) ^ puVar2[3] ^
                  *(uint *)(&DAT_0001b800 + (uVar1 >> 8 & 0xff) * 4) ^
                  *(uint *)(&DAT_0001b400 + (uVar1 >> 0x10 & 0xff) * 4);
          uVar1 = *(uint *)(&DAT_0001bc00 + (uVar1 & 0xff) * 4) ^
                  *(uint *)(&DAT_0001b000 + (uVar1 >> 0x18) * 4) ^ puVar2[4] ^
                  *(uint *)(&DAT_0001b800 + (uVar1 >> 8 & 0xff) * 4) ^
                  *(uint *)(&DAT_0001b400 + (uVar1 >> 0x10 & 0xff) * 4);
          uVar1 = *(uint *)(&DAT_0001bc00 + (uVar1 & 0xff) * 4) ^
                  *(uint *)(&DAT_0001b000 + (uVar1 >> 0x18) * 4) ^ puVar2[5] ^
                  *(uint *)(&DAT_0001b800 + (uVar1 >> 8 & 0xff) * 4) ^
                  *(uint *)(&DAT_0001b400 + (uVar1 >> 0x10 & 0xff) * 4);
          uVar1 = *(uint *)(&DAT_0001bc00 + (uVar1 & 0xff) * 4) ^
                  *(uint *)(&DAT_0001b000 + (uVar1 >> 0x18) * 4) ^ puVar2[6] ^
                  *(uint *)(&DAT_0001b800 + (uVar1 >> 8 & 0xff) * 4) ^
                  *(uint *)(&DAT_0001b400 + (uVar1 >> 0x10 & 0xff) * 4);
          uVar1 = *(uint *)(&DAT_0001bc00 + (uVar1 & 0xff) * 4) ^
                  *(uint *)(&DAT_0001b000 + (uVar1 >> 0x18) * 4) ^ puVar2[7] ^
                  *(uint *)(&DAT_0001b800 + (uVar1 >> 8 & 0xff) * 4) ^
                  *(uint *)(&DAT_0001b400 + (uVar1 >> 0x10 & 0xff) * 4);
          param_1 = *(uint *)(&DAT_0001b000 + (uVar1 >> 0x18) * 4) ^
                    *(uint *)(&DAT_0001bc00 + (uVar1 & 0xff) * 4) ^
                    *(uint *)(&DAT_0001b800 + (uVar1 >> 8 & 0xff) * 4) ^
                    *(uint *)(&DAT_0001b400 + (uVar1 >> 0x10 & 0xff) * 4);
          uVar4 = uVar4 - 0x20;
          puVar2 = puVar2 + 8;
        } while (0x1f < uVar4);
        param_2 = (uint *)((int)param_2 + (param_3 - 0x20 & 0xffffffe0) + 0x20);
        param_3 = param_3 & 0x1f;
      }
      if (3 < param_3) {
        puVar2 = (uint *)((param_3 - 4 & 0xfffffffc) + 4 + (int)param_2);
        do {
          puVar3 = param_2 + 1;
          param_1 = param_1 ^ *param_2;
          param_1 = *(uint *)(&DAT_0001b000 + (param_1 >> 0x18) * 4) ^
                    *(uint *)(&DAT_0001bc00 + (param_1 & 0xff) * 4) ^
                    *(uint *)(&DAT_0001b800 + (param_1 >> 8 & 0xff) * 4) ^
                    *(uint *)(&DAT_0001b400 + (param_1 >> 0x10 & 0xff) * 4);
          param_2 = puVar3;
        } while (puVar3 != puVar2);
        param_3 = param_3 & 3;
        param_2 = puVar2;
      }
    }
    if (param_3 != 0) {
      puVar2 = param_2;
      do {
        puVar3 = (uint *)((int)puVar2 + 1);
        param_1 = param_1 >> 8 ^
                  *(uint *)(&DAT_0001b000 + (uint)(byte)((byte)param_1 ^ *(byte *)puVar2) * 4);
        puVar2 = puVar3;
      } while (puVar3 != (uint *)((int)param_2 + param_3));
    }
    param_1 = ~param_1;
  }
  return param_1;
}



uint FUN_00012e11(uint param_1,uint param_2,uint param_3)

{
  int *piVar1;
  int iVar2;
  int local_108 [31];
  int local_8c [32];
  
  if (param_3 != 0) {
    piVar1 = local_108;
    iVar2 = 1;
    do {
      *piVar1 = iVar2;
      iVar2 = iVar2 * 2;
      piVar1 = piVar1 + 1;
    } while (piVar1 != local_8c);
    FUN_00012b2a(0xedb88320);
    FUN_00012b2a();
    do {
      FUN_00012b2a();
      if ((param_3 & 1) != 0) {
        param_1 = FUN_00012b0a();
      }
      if ((int)param_3 >> 1 == 0) break;
      FUN_00012b2a();
      if (((int)param_3 >> 1 & 1U) != 0) {
        param_1 = FUN_00012b0a();
      }
      param_3 = (int)param_3 >> 2;
    } while (param_3 != 0);
    param_1 = param_1 ^ param_2;
  }
  return param_1;
}



void FUN_00012ee0(void)

{
  Plugin_TcpCloseConnectionMT(DAT_000412c4,0);
  DAT_00041300 = 0;
  return;
}



void FUN_00012f06(void)

{
  int iVar1;
  char *__nptr;
  
  iVar1 = Plugin_Cmd_Argc();
  if (iVar1 == 2) {
    __nptr = (char *)Plugin_Cmd_Argv(1);
    DAT_000413b0 = strtol(__nptr,(char **)0x0,10);
  }
  else {
    Plugin_Printf("usage: grsayto <grid>");
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00012f4e(int param_1,int param_2)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  
  if (param_2 != 0) {
    Plugin_EnterCriticalSection();
    _DAT_0004139c = *(int *)(param_1 + 0x14) + -8;
    FUN_0001a8bf(param_1,(uint)(byte)((byte)DAT_00041398 ^ DAT_0004139c ^ DAT_000413a0));
    _DAT_000413a0 = _DAT_000413a0 + 1;
    DAT_00041398 = FUN_0001ac33(**(undefined4 **)(param_1 + 8));
    Plugin_LeaveCriticalSection();
  }
  iVar2 = *(int *)(param_1 + 8);
  uVar1 = FUN_0001ac33(*(int *)(param_1 + 0x14) + -8);
  *(undefined4 *)(iVar2 + 4) = uVar1;
  Plugin_EnterCriticalSection();
  iVar2 = Plugin_Milliseconds();
  iVar4 = 0;
  while( true ) {
    if ((*(int *)(param_1 + 0x14) <= iVar4) || (_DAT_000412c8 != 0)) {
      Plugin_LeaveCriticalSection();
      return;
    }
    iVar4 = Plugin_TcpSendDataMT
                      (DAT_000412c4,0,iVar4 + *(int *)(param_1 + 8),*(int *)(param_1 + 0x14) - iVar4
                      );
    if (iVar4 < 0) {
      Plugin_LeaveCriticalSection();
      Plugin_Printf("Connection to Gameranger backend closed\n");
      FUN_00012ee0();
      return;
    }
    iVar3 = Plugin_Milliseconds();
    if (iVar2 + 120000 < iVar3) break;
    if (iVar4 < *(int *)(param_1 + 0x14)) {
      Plugin_SleepMSec(5);
    }
  }
  Plugin_LeaveCriticalSection();
  Plugin_Printf("Connection to Gameranger backend timed out\n");
  FUN_00012ee0();
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00013072(void)

{
  undefined local_434 [8];
  undefined4 local_42c;
  undefined4 local_420;
  undefined local_40c [1028];
  
  if ((_DAT_000413b8 < DAT_0004130c) && (4 < DAT_00041300)) {
    _DAT_000413b8 = DAT_0004130c + 15000;
    FUN_0001a849(local_434,local_40c,0x400);
    FUN_0001a926(local_434,0x79);
    FUN_0001a926(local_434,0);
    FUN_00012f4e(local_434,0);
    FUN_0001a849(local_434,local_40c,0x400);
    FUN_0001a8bf(local_434,3);
    FUN_0001a926(local_434,DAT_00041308);
    FUN_0001a926(local_434,DAT_00041408);
    if (_DAT_000413e8 != 0) {
      Plugin_UdpSendData(&DAT_000413e8,local_42c,local_420);
    }
    Plugin_Printf("Sending heartbeat to connect.gameranger.com\n");
  }
  return;
}



void FUN_0001316e(void)

{
  int iVar1;
  undefined4 uVar2;
  undefined local_5f4 [1024];
  undefined local_1f4 [40];
  undefined local_1cc [64];
  char local_18c [5];
  undefined local_187 [59];
  undefined local_14c [256];
  undefined local_4c [64];
  
  if (DAT_00041300 < 5) {
    Plugin_Printf("You have to be logged into GameRanger 1st to use this feature\n");
  }
  else {
    if (DAT_00041300 < 7) {
      iVar1 = Plugin_GetSlotCount();
      Plugin_Cvar_VariableStringBuffer("fs_game",local_18c,0x40);
      if (local_18c[0] == '\0') {
        uVar2 = Plugin_Cvar_GetString(DAT_00041230,local_1cc,0x40);
        FUN_0001ac96(local_4c,0x40,0x1d046,uVar2);
      }
      else {
        uVar2 = Plugin_Cvar_GetString(DAT_00041230,local_1cc,0x40);
        FUN_0001ac96(local_4c,0x40,"[Mod: %s] %s",local_187,uVar2);
      }
      Plugin_Cvar_GetString(DAT_0004122c,local_14c,0x100);
      FUN_0001a849(local_1f4,local_5f4,0x400);
      FUN_0001a926(local_1f4,0x3b);
      FUN_0001a926(local_1f4,0);
      FUN_0001a926(local_1f4,0x239);
      FUN_0001a926(local_1f4,iVar1 + 1);
      FUN_0001a926(local_1f4,0);
      FUN_0001a8bf(local_1f4,1);
      FUN_0001a998(local_1f4,local_4c);
      FUN_0001a998(local_1f4,local_14c);
      FUN_0001a8bf(local_1f4,0);
      FUN_0001a8bf(local_1f4,0);
      FUN_0001a8bf(local_1f4,0);
      FUN_0001a8bf(local_1f4,1);
      FUN_0001a8bf(local_1f4,0);
      FUN_0001a8bf(local_1f4,0);
      FUN_0001a8bf(local_1f4,0);
      FUN_0001a8bf(local_1f4,0);
      FUN_0001a8bf(local_1f4,0);
      FUN_00012f4e(local_1f4,1);
      DAT_00041300 = 6;
      Plugin_Printf("Attempting to host a room\n");
      DAT_0004140c = 0;
    }
    else {
      Plugin_Printf("You have already a room open\n");
    }
  }
  return;
}



void FUN_000133f2(void)

{
  undefined local_434 [1024];
  undefined local_34 [48];
  
  if (6 < DAT_00041300) {
    FUN_0001a849(local_34,local_434,0x400);
    FUN_0001a926(local_34,0xe);
    FUN_0001a926(local_34,0);
    FUN_00012f4e(local_34,1);
    Plugin_Printf("Closing hosted room\n");
    DAT_00041300 = 5;
    DAT_0004140c = 0;
  }
  return;
}



void FUN_00013479(void)

{
  int iVar1;
  char *__nptr;
  long lVar2;
  undefined local_434 [1024];
  undefined local_34 [44];
  
  if (DAT_00041300 < 5) {
    Plugin_Printf("You have to be logged into GameRanger 1st to use this feature\n");
  }
  else {
    iVar1 = Plugin_Cmd_Argc();
    if (1 < iVar1) {
      __nptr = (char *)Plugin_Cmd_Argv(1);
      lVar2 = strtol(__nptr,(char **)0x0,10);
      if (0 < lVar2) {
        FUN_0001a849(local_34,local_434,0x400);
        FUN_0001a926(local_34,0x57);
        FUN_0001a926(local_34,0);
        FUN_0001a926(local_34,lVar2);
        FUN_00012f4e(local_34,1);
        return;
      }
    }
    Plugin_Printf("usage: GrUserinfo <GameRanger-ID>\n");
  }
  return;
}



void FUN_00013541(void)

{
  int iVar1;
  undefined4 uVar2;
  undefined local_434 [1024];
  undefined local_34 [48];
  
  if (DAT_00041300 < 5) {
    Plugin_Printf("You have to be logged into GameRanger 1st to use this feature\n");
  }
  else {
    iVar1 = Plugin_Cmd_Argc();
    if (iVar1 < 2) {
      Plugin_Printf("usage: GrChangeRealname <\"newname\">\n");
    }
    else {
      FUN_0001a849(local_34,local_434,0x400);
      FUN_0001a926(local_34,0x3f);
      FUN_0001a926(local_34,0);
      uVar2 = Plugin_Cmd_Argv(1);
      FUN_0001a998(local_34,uVar2);
      FUN_00012f4e(local_34,1);
    }
  }
  return;
}



void FUN_000135e6(void)

{
  char cVar1;
  int iVar2;
  undefined4 uVar3;
  uint uVar4;
  char *pcVar5;
  byte bVar6;
  undefined local_434 [1024];
  undefined local_34 [48];
  
  bVar6 = 0;
  if (DAT_00041300 < 5) {
    Plugin_Printf("You have to be logged into GameRanger 1st to use this feature\n");
  }
  else {
    iVar2 = Plugin_Cmd_Argc();
    if (1 < iVar2) {
      pcVar5 = (char *)Plugin_Cmd_Argv(1);
      uVar4 = 0xffffffff;
      do {
        if (uVar4 == 0) break;
        uVar4 = uVar4 - 1;
        cVar1 = *pcVar5;
        pcVar5 = pcVar5 + (uint)bVar6 * -2 + 1;
      } while (cVar1 != '\0');
      if (1 < ~uVar4 - 1) {
        FUN_0001a849(local_34,local_434,0x400);
        FUN_0001a926(local_34,0x115);
        FUN_0001a926(local_34,0);
        uVar3 = Plugin_Cmd_Argv(1);
        FUN_0001a998(local_34,uVar3);
        FUN_00012f4e(local_34,1);
        return;
      }
    }
    Plugin_Printf("usage: GrChangeNick <\"newname\">\n");
  }
  return;
}



void FUN_000136b5(void)

{
  int iVar1;
  undefined local_834 [1024];
  undefined local_434 [40];
  undefined local_40c [1028];
  
  if (DAT_00041300 < 5) {
    Plugin_Printf("You have to be logged into GameRanger 1st to use this feature\n");
  }
  else {
    iVar1 = Plugin_Cmd_Argc();
    if (iVar1 < 2) {
      Plugin_Printf("usage: grsay <message>\n");
    }
    else {
      if (DAT_000413b0 == 0) {
        Plugin_Printf(
                     "You have to specify an user-id who should receive your messages first: grsayto grid\n"
                     );
      }
      else {
        Plugin_Cmd_Args(local_40c,0x400);
        FUN_0001a849(local_434,local_834,0x400);
        FUN_0001a926(local_434,0xb6);
        FUN_0001a926(local_434,0);
        FUN_0001a926(local_434,DAT_000413b0);
        FUN_0001a998(local_434,local_40c);
        FUN_00012f4e(local_434,1);
        Plugin_Printf("\r^4Me: ^7%s\n",local_40c);
      }
    }
  }
  return;
}



// WARNING: Removing unreachable block (ram,0x000137d4)
// WARNING: Removing unreachable block (ram,0x000137df)
// WARNING: Removing unreachable block (ram,0x000137f7)
// WARNING: Removing unreachable block (ram,0x000137f0)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_000137a9(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,undefined4 param_6,undefined4 param_7,undefined4 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11)

{
  undefined4 uVar1;
  int iVar2;
  undefined4 *puVar3;
  byte bVar4;
  undefined4 local_838;
  undefined local_834 [1024];
  undefined local_434 [1024];
  undefined local_34 [48];
  
  bVar4 = 0;
  local_838 = 0;
  Plugin_EnterCriticalSection();
  iVar2 = 0xa46;
  puVar3 = &DAT_00041300;
  while (iVar2 != 0) {
    iVar2 = iVar2 + -1;
    *puVar3 = 0;
    puVar3 = puVar3 + (uint)bVar4 * 0x3ffffffe + 1;
  }
  Plugin_LeaveCriticalSection();
  Plugin_Printf("GR_SetupConnection...\n");
  Plugin_RandomBytes(&DAT_00041304,4);
  if (_DAT_000211e0 == 0) {
    iVar2 = Plugin_TcpConnectMT(DAT_000412c4,0,"connect.gameranger.com:16000");
  }
  else {
    uVar1 = Plugin_NET_AdrToStringMT(&DAT_000211e0,local_834,0x400);
    iVar2 = Plugin_TcpConnectMT(DAT_000412c4,0,uVar1);
  }
  if (iVar2 == 0) {
    DAT_00041300 = 0;
    Plugin_PrintError("Connecting to: connect.gameranger.com:16000 failed\n");
  }
  else {
    Plugin_Printf("Connected to GameRanger\n");
    DAT_00041300 = 2;
    DAT_00041308 = param_2;
    FUN_0001ac5b(&DAT_00041314,param_1,0x40);
    DAT_00041354 = param_3;
    _DAT_00041358 = param_4;
    _DAT_0004135c = param_5;
    _DAT_00041360 = param_6;
    _DAT_00041364 = param_7;
    _DAT_00041368 = param_8;
    _DAT_0004136c = param_9;
    _DAT_00041370 = param_10;
    _DAT_00041374 = param_11;
    FUN_0001a849(local_34,local_434,0x400);
    FUN_0001a926(local_34,0xb4);
    FUN_0001a926(local_34,0);
    FUN_0001a926(local_34,2);
    FUN_0001a926(local_34,0xa2);
    Plugin_RandomBytes(&local_838,4);
    FUN_0001a926(local_34,local_838);
    FUN_0001a926(local_34,0x299);
    FUN_00012f4e(local_34,0);
  }
  return;
}



void FUN_000139f4(void)

{
  char cVar1;
  uint uVar2;
  int iVar3;
  undefined4 uVar4;
  char *pcVar5;
  byte bVar6;
  undefined4 local_86c;
  undefined4 local_868;
  undefined4 local_864;
  undefined4 local_860;
  undefined4 local_85c;
  undefined4 local_858;
  undefined4 local_854;
  undefined4 local_850;
  undefined local_84c [64];
  undefined local_80c [1024];
  char local_40c [1028];
  
  bVar6 = 0;
  if (DAT_00041300 == 0) {
    Plugin_Printf("GR_Connect_f\n");
    uVar2 = Plugin_Cvar_VariableIntegerValue("net_port");
    Plugin_Cvar_VariableStringBuffer("net_ip",local_80c,0x400);
    FUN_0001ac96(local_84c,0x40,"%s:%d",local_80c,uVar2 & 0xffff);
    Plugin_NET_StringToAdr(local_84c,&local_86c,6);
    Plugin_Cvar_GetString(DAT_00041238,local_40c,0x400);
    iVar3 = Plugin_Cvar_GetInteger(DAT_0004123c);
    uVar2 = 0xffffffff;
    pcVar5 = local_40c;
    do {
      if (uVar2 == 0) break;
      uVar2 = uVar2 - 1;
      cVar1 = *pcVar5;
      pcVar5 = pcVar5 + (uint)bVar6 * -2 + 1;
    } while (cVar1 != '\0');
    if ((~uVar2 - 1 < 3) || (iVar3 < 2)) {
      Plugin_PrintError(
                       "GameRanger: No password or user id has been set!\nPlease add to your server.cfg:\nset grloginpassword password\nset gruserid numericID\n"
                       );
      DAT_00041300 = 0;
    }
    else {
      DAT_00041300 = 1;
      uVar4 = Plugin_Cvar_GetInteger(DAT_00041234);
      FUN_000137a9(local_40c,iVar3,uVar4,local_86c,local_868,local_864,local_860,local_85c,local_858
                   ,local_854,local_850);
    }
  }
  else {
    Plugin_Printf("Already connected to GameRanger\n");
  }
  return;
}



void FUN_00013b67(undefined4 param_1)

{
  FUN_00012f4e(param_1,0);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00013b82(void)

{
  char cVar1;
  int iVar2;
  undefined4 uVar3;
  uint uVar4;
  char *pcVar5;
  byte bVar6;
  undefined local_80c [1024];
  char local_40c;
  undefined local_40b;
  undefined local_40a;
  undefined local_409;
  undefined local_408 [1024];
  
  bVar6 = 0;
  if (DAT_00041300 != 3) {
    return;
  }
  if (_DAT_000413c8 == 0) {
    Plugin_Printf("Resolving %s\n","grangercod4xplugin.ddns.net");
    iVar2 = Plugin_NET_StringToAdr("grangercod4xplugin.ddns.net",&DAT_000413c8,4);
    if (iVar2 == 0) {
      Plugin_Printf("Couldn\'t resolve address\n");
      return;
    }
    _DAT_000413d0 = FUN_0001ac20(0x411a);
    uVar3 = Plugin_NET_AdrToStringMT(&DAT_000413c8,local_80c,0x400);
    Plugin_Printf("%s resolved to %s\n","grangercod4xplugin.ddns.net",uVar3);
    if (_DAT_000413c8 == 0) {
      return;
    }
  }
  local_40c = -1;
  local_40b = 0xff;
  local_40a = 0xff;
  local_409 = 0xff;
  local_408[0] = 0;
  Plugin_Printf("Requesting login data from remote server for GameRanger login...\n");
  uVar3 = Plugin_NET_AdrToStringShortMT(&DAT_00041358,local_80c,0x400);
  FUN_0001ac96(local_408,0x3fc,
                              
               "getlogin \"\\cl_challenge\\%d\\challenge\\%d\\grid\\%d\\tz\\%d\\netadr\\%s\\passwd\\%s\\data\\%s\""
               ,DAT_00041304,DAT_000413c4,DAT_00041308,DAT_00041354,uVar3,&DAT_00041314,
               &DAT_00041410);
  uVar4 = 0xffffffff;
  pcVar5 = &local_40c;
  do {
    if (uVar4 == 0) break;
    uVar4 = uVar4 - 1;
    cVar1 = *pcVar5;
    pcVar5 = pcVar5 + (uint)bVar6 * -2 + 1;
  } while (cVar1 != '\0');
  Plugin_UdpSendData(&DAT_000413c8,&local_40c,~uVar4 - 1);
  return;
}



void FUN_00013d1c(undefined4 param_1,undefined4 param_2,uint param_3)

{
  int iVar1;
  int iVar2;
  long lVar3;
  undefined4 uVar4;
  undefined local_82c [1024];
  char local_42c [32];
  undefined local_40c [1028];
  
  if (DAT_00041300 == 3) {
    FUN_0001ac5b(local_82c,param_2,param_3 & 0x3ff);
    FUN_0001ace4();
    iVar1 = FUN_0001acf9(local_82c);
    if (iVar1 == 0) {
      Plugin_Printf("GR_AuthChallengeResponse: Unexpected end of serverdata\n");
    }
    else {
      iVar1 = FUN_0001acf9(iVar1);
      if (iVar1 == 0) {
        Plugin_Printf("GR_AuthChallengeResponse: Unexpected end of serverdata\n");
      }
      else {
        iVar2 = FUN_0001adcc(iVar1);
        FUN_0001ac5b(local_42c,iVar1,iVar2 + 1U & 0x1f);
        lVar3 = strtol(local_42c,(char **)0x0,10);
        if (lVar3 == DAT_00041304) {
          iVar1 = FUN_0001acf9(iVar1);
          if (iVar1 == 0) {
            Plugin_Printf("GR_AuthChallengeResponse: Unexpected end of serverdata\n");
          }
          else {
            iVar2 = FUN_0001adcc(iVar1);
            FUN_0001ac5b(local_42c,iVar1,iVar2 + 1U & 0x1f);
            DAT_000413c4 = strtol(local_42c,(char **)0x0,10);
          }
        }
        else {
          uVar4 = Plugin_NET_AdrToStringMT(param_1,local_40c,0x400);
          Plugin_Printf("GR_AuthChallengeResponse: Bad challenge from %s\n",uVar4);
          Plugin_DPrintf("Expected challenge: %d but got: %d\n",DAT_00041304,lVar3);
        }
      }
    }
  }
  return;
}



// WARNING: Removing unreachable block (ram,0x00013ed3)
// WARNING: Removing unreachable block (ram,0x00013eef)

void FUN_00013e94(undefined4 param_1,undefined4 *param_2,uint param_3)

{
  uint uVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  
  if (DAT_00041300 == 3) {
    if (param_3 < 0x579) {
      puVar3 = (undefined4 *)&DAT_00041810;
      if (3 < param_3) {
        uVar1 = param_3 >> 2;
        puVar3 = (undefined4 *)&DAT_00041810;
        while (uVar1 != 0) {
          uVar1 = uVar1 - 1;
          *puVar3 = *param_2;
          param_2 = param_2 + 1;
          puVar3 = puVar3 + 1;
        }
      }
      puVar2 = param_2;
      puVar4 = puVar3;
      if ((param_3 & 2) != 0) {
        puVar4 = (undefined4 *)((int)puVar3 + 2);
        puVar2 = (undefined4 *)((int)param_2 + 2);
        *(undefined2 *)puVar3 = *(undefined2 *)param_2;
      }
      if ((param_3 & 1) != 0) {
        *(undefined *)puVar4 = *(undefined *)puVar2;
      }
      DAT_00041d88 = param_3;
    }
  }
  else {
    Plugin_Printf("Received login data when it was not requested or within invalid state\n");
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00013f1d(void)

{
  undefined4 uVar1;
  int iVar2;
  byte *pbVar3;
  byte *pbVar4;
  byte *pbVar5;
  bool bVar6;
  bool bVar7;
  byte bVar8;
  undefined local_45c [16];
  int local_44c;
  int local_448;
  undefined4 local_434;
  undefined4 local_430;
  undefined *local_42c;
  int local_424;
  int local_420;
  uint local_418;
  undefined4 local_414;
  undefined local_40c [1024];
  
  bVar8 = 0;
  if ((0 < DAT_00041d88) && (DAT_00041300 < 4)) {
    local_42c = &DAT_00041810;
    local_420 = DAT_00041d88;
    local_424 = DAT_00041d88;
    local_418 = 0;
    local_414 = 0;
    local_430 = 1;
    local_434 = 0;
    DAT_00041d88 = 0;
    FUN_0001aa97(&local_434);
    FUN_0001aae8(&local_434,local_40c,0x400);
    uVar1 = FUN_0001aa97(&local_434);
    iVar2 = FUN_0001ac33(uVar1);
    if (iVar2 == DAT_00041304) {
      bVar6 = CARRY4(local_418,(uint)local_42c);
      pbVar3 = local_42c + local_418;
      bVar7 = pbVar3 == (byte *)0x0;
      iVar2 = 6;
      pbVar4 = pbVar3;
      pbVar5 = (byte *)"Error:";
      do {
        if (iVar2 == 0) break;
        iVar2 = iVar2 + -1;
        bVar6 = *pbVar4 < *pbVar5;
        bVar7 = *pbVar4 == *pbVar5;
        pbVar4 = pbVar4 + (uint)bVar8 * -2 + 1;
        pbVar5 = pbVar5 + (uint)bVar8 * -2 + 1;
      } while (bVar7);
      if ((!bVar6 && !bVar7) == bVar6) {
        Plugin_Printf("^1%s\n",pbVar3);
        Plugin_ChatPrintf(0xffffffff,&DAT_0001d173,local_42c + local_418);
      }
      else {
        _DAT_00043c10 = FUN_0001aac7(&local_434);
        local_448 = local_420 - local_418;
        FUN_0001a849(local_45c,local_40c,0x400);
        FUN_0001ab2b(&local_434,local_40c,0x400);
        if (local_44c < local_448) {
          Plugin_Printf("GameRanger: Login message overflow\n");
        }
        else {
          FUN_00013b67(local_45c);
          Plugin_Printf("Logging in to GameRanger...\n");
          DAT_00041300 = 4;
        }
      }
    }
    else {
      Plugin_Printf("GR_AuthLoginPacket: Bad challenge\n");
      Plugin_DPrintf("Expected challenge: %d but got: %d\n",DAT_00041304,iVar2);
    }
  }
  return;
}



void FUN_000140c4(undefined4 param_1)

{
  FUN_0001ab5d(param_1,&DAT_00041410,0x400);
  DAT_00041300 = 3;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_000140f1(undefined4 param_1)

{
  undefined4 uVar1;
  undefined local_40c [1032];
  
  FUN_0001aa97(param_1);
  FUN_0001aa97(param_1);
  DAT_000211f0 = FUN_0001aa43(param_1);
  DAT_000211f1 = FUN_0001aa43(param_1);
  DAT_000211f2 = FUN_0001aa43(param_1);
  DAT_000211f3 = FUN_0001aa43(param_1);
  _DAT_000211e0 = 4;
  _DAT_000211e8 = FUN_0001ac20(16000);
  uVar1 = Plugin_NET_AdrToStringMT(&DAT_000211e0,local_40c,0x400);
  Plugin_Printf("GameRanger said: Redirecting to new address: %s\n",uVar1);
  DAT_00041300 = 0;
  Plugin_TcpCloseConnectionMT(DAT_000412c4,0);
  return;
}



void FUN_000141b2(undefined4 param_1)

{
  undefined4 uVar1;
  undefined local_45c [1024];
  undefined local_5c [76];
  
  uVar1 = FUN_0001aa97(param_1);
  FUN_0001aae8(param_1,local_5c,0x40);
  FUN_0001aae8(param_1,local_45c,0x400);
  Plugin_Printf("^1%s (%d): ^7%s\n",local_5c,uVar1,local_45c);
  DAT_000413b0 = uVar1;
  return;
}



// WARNING: Removing unreachable block (ram,0x00014d36)
// WARNING: Removing unreachable block (ram,0x00014d59)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00014229(void)

{
  size_t __size;
  int iVar1;
  int iVar2;
  int iVar3;
  undefined4 uVar4;
  char *pcVar5;
  int iVar6;
  uint uVar7;
  uint uVar8;
  int iVar9;
  int *piVar10;
  int *piVar11;
  undefined4 *puVar12;
  undefined4 *puVar13;
  undefined4 *puVar14;
  undefined4 *puVar15;
  undefined4 *puVar16;
  int *piVar17;
  bool bVar18;
  byte bVar19;
  undefined auStack132460 [20];
  int iStack132440;
  undefined auStack132420 [128];
  undefined auStack132292 [8];
  undefined4 uStack132284;
  undefined4 uStack132272;
  undefined auStack132164 [1024];
  undefined4 auStack131140 [32768];
  undefined local_44 [8];
  undefined4 *local_3c;
  size_t local_34;
  uint local_30;
  int local_28;
  
  bVar19 = 0;
  FUN_0001a849(local_44,auStack131140,0x20000);
  iVar1 = Plugin_Milliseconds();
LAB_00014e00:
  do {
    while( true ) {
      do {
        uVar8 = local_30;
        if (_DAT_000412c8 != 0) {
          if (local_3c != auStack131140) {
            free(local_3c);
          }
          return;
        }
        puVar14 = local_3c;
        __size = local_34;
        if (local_30 == local_34) {
          __size = local_30 * 4;
          puVar14 = (undefined4 *)malloc(__size);
          if (puVar14 == (undefined4 *)0x0) {
            Plugin_PrintWarning("GameRanger-Server malloc() failed!\n");
            DAT_00041300 = 0;
            if (local_3c == auStack131140) {
              DAT_00041300 = 0;
              return;
            }
            free(local_3c);
            return;
          }
          puVar12 = local_3c;
          puVar15 = puVar14;
          if (3 < uVar8) {
            uVar7 = uVar8 >> 2;
            while (uVar7 != 0) {
              uVar7 = uVar7 - 1;
              *puVar15 = *puVar12;
              puVar12 = puVar12 + (uint)bVar19 * 0x3ffffffe + 1;
              puVar15 = puVar15 + (uint)bVar19 * 0x3ffffffe + 1;
            }
          }
          puVar13 = puVar12;
          puVar16 = puVar15;
          if ((uVar8 & 2) != 0) {
            puVar16 = (undefined4 *)((int)puVar15 + (uint)bVar19 * -4 + 2);
            puVar13 = (undefined4 *)((int)puVar12 + (uint)bVar19 * -4 + 2);
            *(undefined2 *)puVar15 = *(undefined2 *)puVar12;
          }
          if ((uVar8 & 1) != 0) {
            *(undefined *)puVar16 = *(undefined *)puVar13;
          }
          if (local_3c != auStack131140) {
            free(local_3c);
          }
        }
        local_34 = __size;
        local_3c = puVar14;
        if ((local_3c != auStack131140) && (local_30 < 0x20000)) {
          puVar14 = local_3c;
          puVar12 = auStack131140;
          if (3 < local_30) {
            uVar8 = local_30 >> 2;
            while (uVar8 != 0) {
              uVar8 = uVar8 - 1;
              *puVar12 = *puVar14;
              puVar14 = puVar14 + (uint)bVar19 * 0x3ffffffe + 1;
              puVar12 = puVar12 + (uint)bVar19 * 0x3ffffffe + 1;
            }
          }
          puVar15 = puVar14;
          puVar13 = puVar12;
          if ((local_30 & 2) != 0) {
            puVar13 = (undefined4 *)((int)puVar12 + (uint)bVar19 * -4 + 2);
            puVar15 = (undefined4 *)((int)puVar14 + (uint)bVar19 * -4 + 2);
            *(undefined2 *)puVar12 = *(undefined2 *)puVar14;
          }
          if ((local_30 & 1) != 0) {
            *(undefined *)puVar13 = *(undefined *)puVar15;
          }
          local_34 = 0x20000;
          free(local_3c);
          local_3c = auStack131140;
        }
        iVar2 = Plugin_TcpGetDataMT(DAT_000412c4,0,local_30 + (int)local_3c,local_34 - local_30);
        if (iVar2 < 1) {
          if (iVar2 == -1) {
            Plugin_PrintWarning("GameRanger-Server closed connection!\n");
            DAT_00041300 = 0;
            DAT_000413bc = Plugin_Milliseconds();
            DAT_000413bc = DAT_000413bc + 60000;
            if ((int)local_30 < 1) {
              Plugin_Printf("No more commands to read\n");
            }
            if (local_3c == auStack131140) {
              return;
            }
            free(local_3c);
            return;
          }
          iVar2 = Plugin_Milliseconds();
          if (iVar1 + 120000 < iVar2) {
            Plugin_PrintWarning(
                               "Waiting for more than 120 seconds for GameRanger-Server to send complete message! Aborting...\n"
                               );
            FUN_00012ee0();
            DAT_000413bc = Plugin_Milliseconds();
            DAT_000413bc = DAT_000413bc + 60000;
            if (local_3c == auStack131140) {
              return;
            }
            free(local_3c);
            return;
          }
          if ((int)local_30 < 1) {
            if (local_3c == auStack131140) {
              return;
            }
            free(local_3c);
            return;
          }
          Plugin_SleepMSec(5);
        }
        else {
          local_30 = local_30 + iVar2;
        }
        FUN_0001abe7(local_44);
      } while (local_30 < 8);
      iVar2 = FUN_0001aa97(local_44);
      iVar3 = FUN_0001aa97(local_44);
      if (iVar3 <= (int)(local_30 - local_28)) break;
      local_28 = 0;
    }
    FUN_0001a849(auStack132460,local_28 + (int)local_3c,iVar3);
    local_28 = local_28 + iVar3;
    iStack132440 = iVar3;
    Plugin_EnterCriticalSection();
    _DAT_000413ac = _DAT_000413ac + 1;
    _DAT_000413a4 = iVar2;
    _DAT_000413a8 = iVar3;
    Plugin_LeaveCriticalSection();
  } while (iVar2 == 0x95);
  if (iVar2 < 0x96) {
    if (iVar2 == 0x34) {
      iVar2 = FUN_0001aa97(auStack132460);
      if (iVar2 != DAT_00041308) {
        Plugin_EnterCriticalSection();
        if (iVar2 == DAT_00041d90) {
          piVar11 = &DAT_00041d90;
LAB_000147bf:
          *(undefined4 *)((int)piVar11 + 0x72) = 1;
          Plugin_LeaveCriticalSection();
        }
        else {
          piVar11 = &DAT_00041e0a;
          iVar3 = 1;
          do {
            if (iVar2 == *piVar11) {
              if (iVar3 != 0x40) goto LAB_000147bf;
              break;
            }
            iVar3 = iVar3 + 1;
            piVar11 = (int *)((int)piVar11 + 0x7a);
          } while (iVar3 != 0x40);
          Plugin_LeaveCriticalSection();
        }
      }
      goto LAB_00014e00;
    }
    if (iVar2 < 0x35) {
      if (iVar2 == 9) {
        iVar2 = FUN_0001aa97(auStack132460);
        pcVar5 = (char *)FUN_0001aae8(auStack132460,auStack132164,0x400);
        if (iVar2 == DAT_00041308) {
          if ((pcVar5 == (char *)0x0) || (*pcVar5 == '\0')) {
            Plugin_Printf("^1GameRanger has disconnected you for an unknown reason\n");
          }
          else {
            Plugin_Printf("^1GameRanger has disconnected you for: %s\n",pcVar5);
          }
          FUN_00012ee0();
        }
        else {
          if ((pcVar5 == (char *)0x0) || (*pcVar5 == '\0')) {
            Plugin_Printf("^2Player: %d left GameRanger\n",iVar2);
          }
          else {
            Plugin_Printf("^2Player: %d has been disconnected: %s\n",iVar2,pcVar5);
          }
        }
        goto LAB_00014e00;
      }
      if (iVar2 < 10) {
        if (iVar2 == 3) {
          FUN_000140f1(auStack132460);
LAB_00014673:
          uVar4 = FUN_0001aa97(auStack132460);
          FUN_0001aa97(auStack132460);
          FUN_0001aa97(auStack132460);
          FUN_0001aa97(auStack132460);
          FUN_0001aa97(auStack132460);
          FUN_0001aa97(auStack132460);
          FUN_0001aa97(auStack132460);
          FUN_0001aa97(auStack132460);
          FUN_0001aae8(auStack132460,auStack132292,0x80);
          FUN_0001aae8(auStack132460,auStack132164,0x80);
          Plugin_Printf("Account ID: %d\n",uVar4);
          Plugin_Printf("Nickname: %s\n",auStack132292);
          Plugin_Printf("Realname: %s\n",auStack132164);
          goto LAB_00014e00;
        }
      }
      else {
        if (iVar2 == 0x1d) goto LAB_00014673;
        if (iVar2 == 0x22) {
          iVar2 = FUN_0001aa97(auStack132460);
          iVar3 = FUN_0001aa97(auStack132460);
          Plugin_EnterCriticalSection();
          if (iVar2 == DAT_00041d90) {
            piVar11 = &DAT_00041d90;
          }
          else {
            piVar17 = (int *)0x0;
            iVar9 = 0;
            piVar10 = &DAT_00041d90;
            iVar6 = DAT_00041d90;
            do {
              if (iVar6 == 0) {
                piVar17 = piVar10;
              }
              iVar9 = iVar9 + 1;
              piVar10 = (int *)((int)piVar10 + 0x7a);
              piVar11 = piVar17;
            } while ((iVar9 != 0x40) && (iVar6 = *piVar10, piVar11 = piVar10, iVar2 != iVar6));
            if (piVar11 == (int *)0x0) {
              Plugin_LeaveCriticalSection();
              Plugin_PrintError("Room exceeded the maximum size of 64\n");
              goto LAB_00014e00;
            }
          }
          *piVar11 = iVar2;
          piVar11[1] = iVar3;
          Plugin_Printf("^2Player: %d Challenge: %d\n",iVar2,iVar3);
          Plugin_LeaveCriticalSection();
          goto LAB_00014e00;
        }
      }
    }
    else {
      if (iVar2 == 0x54) {
        FUN_000140c4(auStack132460);
        goto LAB_00014e00;
      }
      if (iVar2 < 0x55) {
        if (iVar2 != 0x37) goto LAB_00014df0;
        Plugin_Printf("^1Invalid user account: %d\n",DAT_00041308);
        goto LAB_00014e00;
      }
      if (iVar2 == 100) goto LAB_00014e00;
      if (iVar2 == 0x90) {
        uVar4 = FUN_0001aa97(auStack132460);
        Plugin_Printf("^1User %d is currently playing a game\n",uVar4);
        goto LAB_00014e00;
      }
    }
  }
  else {
    if (iVar2 == 0xc4) {
      iVar2 = FUN_0001aa97(auStack132460);
      if (iVar2 != DAT_00041308) {
        Plugin_EnterCriticalSection();
        if (iVar2 == DAT_00041d90) {
          piVar11 = &DAT_00041d90;
LAB_0001482a:
          *(undefined4 *)((int)piVar11 + 0x72) = 0;
          Plugin_LeaveCriticalSection();
        }
        else {
          piVar11 = &DAT_00041e0a;
          iVar3 = 1;
          do {
            if (iVar2 == *piVar11) {
              if (iVar3 != 0x40) goto LAB_0001482a;
              break;
            }
            iVar3 = iVar3 + 1;
            piVar11 = (int *)((int)piVar11 + 0x7a);
          } while (iVar3 != 0x40);
          Plugin_LeaveCriticalSection();
        }
      }
      goto LAB_00014e00;
    }
    if (iVar2 < 0xc5) {
      if (iVar2 == 0xb1) {
        uVar4 = FUN_0001aa97(auStack132460);
        Plugin_Printf("^1User %d is currently not online\n",uVar4);
        goto LAB_00014e00;
      }
      if (iVar2 < 0xb2) {
        if (iVar2 != 0xa6) goto LAB_00014df0;
        iVar2 = FUN_0001aa97(auStack132460);
        Plugin_EnterCriticalSection();
        if (iVar2 == DAT_00041d90) {
          piVar11 = &DAT_00041d90;
LAB_00014d13:
          Plugin_Printf("^2Player: %d left room\n",*piVar11);
          uVar8 = 0x7a;
          bVar18 = ((uint)piVar11 & 2) != 0;
          piVar17 = piVar11;
          if (bVar18) {
            piVar17 = (int *)((int)piVar11 + (uint)bVar19 * -4 + 2);
            *(undefined2 *)piVar11 = 0;
            uVar8 = 0x78;
          }
          uVar8 = uVar8 >> 2;
          while (uVar8 != 0) {
            uVar8 = uVar8 - 1;
            *piVar17 = 0;
            piVar17 = piVar17 + (uint)bVar19 * 0x3ffffffe + 1;
          }
          if (!bVar18) {
            *(undefined2 *)piVar17 = 0;
          }
          Plugin_LeaveCriticalSection();
        }
        else {
          piVar11 = &DAT_00041e0a;
          iVar3 = 1;
          do {
            if (iVar2 == *piVar11) {
              if (iVar3 != 0x40) goto LAB_00014d13;
              break;
            }
            iVar3 = iVar3 + 1;
            piVar11 = (int *)((int)piVar11 + 0x7a);
          } while (iVar3 != 0x40);
          Plugin_PrintError("Player left who was not inside room\n");
          Plugin_LeaveCriticalSection();
        }
        goto LAB_00014e00;
      }
      if (iVar2 == 0xb2) {
        uVar4 = FUN_0001aa97(auStack132460);
        FUN_0001aae8(auStack132460,auStack132164,0x80);
        Plugin_Printf("Nickname for (%d) has been changed to %s\n",uVar4,auStack132164);
        goto LAB_00014e00;
      }
      if (iVar2 == 0xba) {
        uVar8 = Plugin_Cvar_VariableIntegerValue("net_port");
        DAT_00041408 = FUN_0001aa97(auStack132460);
        FUN_0001aa97(auStack132460);
        FUN_0001aa97(auStack132460);
        FUN_0001aa97(auStack132460);
        DAT_00041300 = 7;
        iVar2 = Plugin_NET_StringToAdr("208.43.2.243",&DAT_000413e8,4);
        if (iVar2 == 0) {
          Plugin_Error(1,"Couldn\'t resolve %s\n","208.43.2.243");
        }
        else {
          _DAT_000413f0 = FUN_0001ac20(16000);
          FUN_0001a849(auStack132292,auStack132164,0x400);
          FUN_0001a8bf(auStack132292,3);
          FUN_0001a926(auStack132292,DAT_00041308);
          FUN_0001a926(auStack132292,DAT_00041408);
          uVar8 = uVar8 & 0xffff;
          FUN_0001a8e9(auStack132292,uVar8);
          Plugin_UdpSendData(&DAT_000413e8,uStack132284,uStack132272);
          FUN_0001a849(auStack132292,auStack132164,0x400);
          FUN_0001a926(auStack132292,0x11f);
          FUN_0001a926(auStack132292,0);
          FUN_0001a8e9(auStack132292,uVar8);
          FUN_0001a8e9(auStack132292,uVar8);
          FUN_0001a8bf(auStack132292,0);
          FUN_00012f4e(auStack132292,1);
          Plugin_Printf("Room sucessfully opened\n");
          FUN_0001a849(auStack132292,auStack132164,0x400);
          FUN_0001a926(auStack132292,0x41);
          FUN_0001a926(auStack132292,0);
          FUN_00012f4e(auStack132292,1);
          DAT_00041300 = 8;
        }
        goto LAB_00014e00;
      }
    }
    else {
      if (iVar2 == 0xd2) {
        FUN_0001aa97(auStack132460);
        iVar2 = FUN_0001aa97(auStack132460);
        FUN_0001aae8(auStack132460,auStack132420,0x80);
        FUN_0001aae8(auStack132460,auStack132292,0x80);
        FUN_0001aae8(auStack132460,auStack132164,0x80);
        Plugin_Printf("Logged in to GameRanger as:\n");
        Plugin_Printf("Account ID: %d\n",iVar2);
        Plugin_Printf("Email: %s\n",auStack132420);
        Plugin_Printf("Nickname: %s\n",auStack132292);
        Plugin_Printf("Realname: %s\n",auStack132164);
        if (iVar2 == DAT_00041308) {
          DAT_00041300 = 5;
          DAT_0004140c = 0;
          iVar2 = Plugin_Cvar_GetBoolean(DAT_00041228);
          if (iVar2 != 0) {
            _DAT_00043c14 = 1;
          }
        }
        else {
          Plugin_PrintError("Account id missmatch\nExpected id: %d got id %d\nDisconnecting...\n",
                            DAT_00041308,iVar2);
          FUN_00012ee0();
        }
        goto LAB_00014e00;
      }
      if (iVar2 < 0xd3) {
        if (iVar2 == 0xcc) {
          Plugin_Printf("^1Invalid password: %s for account: %d\n",&DAT_00041314,DAT_00041308);
          goto LAB_00014e00;
        }
      }
      else {
        if (iVar2 == 0xfe) {
          FUN_000141b2(auStack132460);
          goto LAB_00014e00;
        }
        if (iVar2 == 0x103) {
          iVar2 = FUN_0001aa97(auStack132460);
          Plugin_Printf("^1Account banned for another %d minutes\n",iVar2 / 0x3c);
          Plugin_SleepSec(0xf);
          goto LAB_00014e00;
        }
      }
    }
  }
LAB_00014df0:
  Plugin_DPrintf("Command: %d\n",iVar2);
  goto LAB_00014e00;
}



void FUN_00014e40(undefined4 param_1)

{
  undefined local_434 [1024];
  undefined local_34 [48];
  
  FUN_0001a849(local_34,local_434,0x400);
  FUN_0001a926(local_34,0x4c);
  FUN_0001a926(local_34,0);
  FUN_0001a926(local_34,param_1);
  FUN_00012f4e(local_34,1);
  return;
}



void FUN_00014eb1(void)

{
  int iVar1;
  char *__nptr;
  long lVar2;
  
  iVar1 = Plugin_Cmd_Argc();
  if (iVar1 == 2) {
    __nptr = (char *)Plugin_Cmd_Argv(1);
    lVar2 = strtol(__nptr,(char **)0x0,10);
    FUN_00014e40(lVar2);
  }
  else {
    Plugin_Printf("usage: grkick <grid>");
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00014efc(void)

{
  int iVar1;
  undefined4 *puVar2;
  
  iVar1 = DAT_0004130c;
  if (_DAT_000413b4 <= DAT_0004130c) {
    _DAT_000413b4 = DAT_0004130c + 120000;
    Plugin_EnterCriticalSection();
    puVar2 = &DAT_00041d90;
    do {
      if (*(int *)((int)puVar2 + 0x72) != 0) {
        if ((*(int *)((int)puVar2 + 0x76) == 0) || (iVar1 <= puVar2[2] + 120000)) {
          *(undefined4 *)((int)puVar2 + 0x76) = 0;
          if (puVar2[2] + 120000 < iVar1) {
            *(undefined4 *)((int)puVar2 + 0x76) = 1;
          }
        }
        else {
          FUN_00014e40(*puVar2);
        }
      }
      puVar2 = (undefined4 *)((int)puVar2 + 0x7a);
    } while (puVar2 != (undefined4 *)&DAT_00043c10);
    Plugin_LeaveCriticalSection();
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_00014f78(void)

{
  undefined *puVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  
  _DAT_000412cc = 0;
  if (_DAT_000412c8 != 0) {
    _DAT_000412cc = 1;
    return 0;
  }
  do {
    uVar2 = Plugin_Milliseconds();
    if (DAT_00041310 != 0) {
      if (uVar2 < DAT_00041310) {
        DAT_0004130c = DAT_0004130c + 0x32;
      }
      else {
        DAT_0004130c = DAT_0004130c + (uVar2 - DAT_00041310);
      }
    }
    DAT_00041310 = uVar2;
    if (DAT_00041300 < 5) {
LAB_00014fe8:
      if (DAT_00041300 < 4) {
        if (DAT_00041300 == 3) {
          FUN_00013f1d();
          iVar3 = DAT_000413c0;
          if ((DAT_00041300 == 3) && (iVar4 = Plugin_Milliseconds(), iVar3 < iVar4)) {
            FUN_00013b82();
            DAT_000413c0 = Plugin_Milliseconds();
            DAT_000413c0 = DAT_000413c0 + 1000;
          }
        }
        else {
          if ((DAT_00041300 == 2) && (iVar3 = Plugin_IsSvRunning(), iVar3 != 0)) {
            FUN_00014229();
            FUN_00014efc();
          }
          else {
            iVar3 = Plugin_IsSvRunning();
            puVar1 = DAT_000413bc;
            if ((iVar3 != 0) && (iVar3 = Plugin_Milliseconds(), (int)puVar1 < iVar3)) {
              DAT_00041300 = 0;
              FUN_000139f4();
              iVar3 = Plugin_Milliseconds();
              DAT_000413bc = &DAT_0002bf20 + iVar3;
            }
          }
        }
      }
      else {
        FUN_00014229();
        iVar3 = Plugin_IsSvRunning();
        if (iVar3 == 0) {
          if (6 < DAT_00041300) {
            FUN_000133f2();
          }
        }
        else {
          if (DAT_00041300 == 5) {
            if (DAT_0004140c == 0) {
              DAT_0004140c = DAT_0004130c + 12000;
            }
            if (DAT_0004140c < DAT_0004130c) {
              FUN_0001316e();
            }
          }
        }
      }
    }
    else {
      FUN_00013072();
      FUN_00014efc();
      if (DAT_0004130c <= _DAT_00043c10) goto LAB_00014fe8;
      FUN_00012ee0();
    }
    Plugin_SleepSec(1);
    if (_DAT_000412c8 != 0) {
      _DAT_000412cc = 1;
      return 0;
    }
  } while( true );
}



void FUN_00015130(void)

{
  Plugin_Cvar_RegisterString("Running GameRanger plugin","by IceOps",0x44,0x1d0b4);
  return;
}



void FUN_0001515b(void)

{
  undefined local_33;
  undefined local_32;
  undefined local_31;
  undefined local_30;
  undefined local_2f;
  undefined local_2e;
  undefined local_2d;
  undefined local_2c;
  undefined local_2b;
  undefined local_2a;
  undefined local_29;
  undefined local_28;
  undefined local_27;
  undefined local_26;
  undefined local_25;
  undefined local_24;
  undefined local_23;
  undefined local_22;
  undefined local_21;
  undefined local_20;
  undefined local_1f;
  undefined local_1e;
  undefined local_1d;
  undefined local_1c;
  
  local_31 = 0x75;
  local_2d = 0x20;
  local_2a = 0x20;
  local_22 = 0x69;
  local_1e = 0x6e;
  local_29 = 0x49;
  local_33 = 0x50;
  local_2b = 0x79;
  local_1d = 0x67;
  local_25 = 0x70;
  local_2f = 0x69;
  local_21 = 0x6e;
  if (DAT_000211c0 != 0) {
    FUN_0001688e(DAT_000211c0);
  }
  local_28 = 99;
  DAT_000211c0 = FUN_00016570(0x3ff);
  local_32 = 0x6c;
  local_30 = 0x67;
  local_26 = 0x4f;
  local_23 = 0x2e;
  local_2e = 0x6e;
  local_1f = 0x69;
  local_1c = 0;
  local_20 = 0;
  if (DAT_000211c0 != 0) {
    local_2c = 0x62;
    local_27 = 0x65;
    local_24 = 0x73;
    FUN_0001680f(DAT_000211c0,&local_33);
    FUN_00016741(DAT_000211c0,0x3fb33333,3);
    FUN_00016718(DAT_000211c0,0,0xc1800000,0x11,2,4,1);
    FUN_00016702(DAT_000211c0,0xa0000000,0xffffff);
  }
  return;
}



void FUN_00015290(void)

{
  if (DAT_000211c0 != 0) {
    FUN_0001688e(DAT_000211c0);
    DAT_000211c0 = 0;
    return;
  }
  DAT_000211c0 = 0;
  return;
}



void OnPreFastRestart(void)

{
  FUN_00015290();
  return;
}



void OnExitLevel(void)

{
  FUN_00015290();
  return;
}



void OnPostFastRestart(void)

{
  return;
}



void OnSpawnServer(void)

{
  return;
}



void OnFrame(void)

{
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 OnInit(void)

{
  char cVar1;
  int iVar2;
  undefined4 uVar3;
  uint uVar4;
  char *pcVar5;
  byte bVar6;
  char local_1c [20];
  
  bVar6 = 0;
  if (_DAT_00041224 != 0) {
    return 0;
  }
  _DAT_000412cc = 1;
  DAT_0004123c = Plugin_Cvar_RegisterInt
                           ("gruserid",1,1,0x7fffffff,1,
                            "GameRanger Account ID of the account we want to signin to GameRanger");
  DAT_00041238 = Plugin_Cvar_RegisterString
                           ("grloginpassword",0x1d0b4,1,
                                                        
                            "GameRanger Account Password of the account we want to signin to GameRanger"
                           );
  DAT_00041234 = Plugin_Cvar_RegisterInt
                           ("grtimezone",0,0xffff5740,0xa8c0,1,
                            "GameRanger Timezone-Delta in seconds shown on profilepage");
  DAT_00041230 = Plugin_Cvar_RegisterString
                           ("grRoomDescription","Another GameRanger host",1,
                            "GameRanger-Room description");
  DAT_0004122c = Plugin_Cvar_RegisterString("grRoomPassword",0x1d0b4,1,"GameRanger-Room password");
  DAT_00041228 = Plugin_Cvar_RegisterBool
                           ("grallowpublicplayers",0,1,"Allow external players to connect");
  _DAT_00041224 = 1;
  Plugin_Cvar_GetString(DAT_00041238,local_1c,0x10);
  iVar2 = Plugin_Cvar_GetInteger(DAT_0004123c);
  uVar4 = 0xffffffff;
  pcVar5 = local_1c;
  do {
    if (uVar4 == 0) break;
    uVar4 = uVar4 - 1;
    cVar1 = *pcVar5;
    pcVar5 = pcVar5 + (uint)bVar6 * -2 + 1;
  } while (cVar1 != '\0');
  if ((~uVar4 - 1 < 3) || (iVar2 < 2)) {
    Plugin_PrintError(
                     "GameRanger: No password or user id has been set!\nPlease add to your server.cfg:\nset grloginpassword password\nset gruserid numericID\nThis has to be before the plugin load command\n"
                     );
    uVar3 = 0xffffffff;
  }
  else {
    DAT_000412c4 = Plugin_GetPluginID();
    iVar2 = Plugin_CreateNewThread(FUN_00014f78,&DAT_00041220,0);
    if (iVar2 == 0) {
      Plugin_Printf("Failure creating thread for GameRanger plugin\n");
      uVar3 = 0xffffffff;
    }
    else {
      Plugin_AddCommand("grkick",FUN_00014eb1,100);
      Plugin_AddCommand("grconnect",FUN_000139f4,100);
      Plugin_AddCommand("grsay",FUN_000136b5,100);
      Plugin_AddCommand("grsayto",FUN_00012f06,100);
      Plugin_AddCommand("gropenroom",FUN_0001316e,100);
      Plugin_AddCommand("grcloseroom",FUN_000133f2,100);
      Plugin_AddCommand("grchangenick",FUN_000135e6,0x5f);
      Plugin_AddCommand("grchangerealname",FUN_00013541,100);
      Plugin_AddCommand("gruserinfo",FUN_00013479,0x28);
      uVar3 = 0;
    }
  }
  return uVar3;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void OnTerminate(void)

{
  int iVar1;
  int iVar2;
  
  iVar1 = Plugin_Milliseconds();
  _DAT_000412c8 = 1;
  Plugin_Printf("Waiting for GameRanger plugin to terminate\n");
  iVar2 = 0;
  do {
    if (_DAT_000412cc != 0) {
      Plugin_Printf("GameRanger plugin has terminated after %d msec\n",iVar2);
      return;
    }
    Plugin_SleepSec(0);
    iVar2 = Plugin_Milliseconds();
    iVar2 = iVar2 - iVar1;
  } while (iVar2 < 0x3a99);
  Plugin_Printf("GameRanger plugin couldn\'t terminate within 15000 msec\n");
  return;
}



void OnInfoRequest(undefined4 *param_1)

{
  *param_1 = 3;
  param_1[1] = 100;
  param_1[4] = 0x656d6147;
  param_1[5] = 0x676e6152;
  param_1[6] = 0x432d7265;
  param_1[7] = 0x2d34446f;
  param_1[8] = 0x76726553;
  param_1[9] = 0x482d7265;
  param_1[10] = 0x6974736f;
  param_1[0xb] = 0x502d676e;
  param_1[0xc] = 0x6967756c;
  param_1[0xd] = 0x7962206e;
  param_1[0xe] = 0x626f4e20;
  param_1[0xf] = 0x79646f;
  param_1[0x10] = 0;
  param_1[0x11] = 0;
  param_1[0x12] = 0;
  param_1[0x13] = 0;
  strncpy((char *)(param_1 + 0x14),
          "This plugin is used to host CoD4 servers inside of the program GameRanger.",0x80);
  strncpy((char *)(param_1 + 0x34),
                    
          "This plugin is used to host CoD4 servers inside of the program GameRanger.\nIt can automatically login, open a room and hosting CoD4 inside it\nCopyright (c) 2015 Nobody.\n"
          ,0x400);
  return;
}



// WARNING: Removing unreachable block (ram,0x00016203)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void OnUdpNetEvent(int *param_1,int *param_2,int param_3,undefined4 *param_4)

{
  char cVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined4 uVar6;
  uint uVar7;
  int *piVar8;
  int iVar9;
  undefined4 *puVar10;
  undefined4 *puVar11;
  char *pcVar12;
  bool bVar13;
  byte bVar14;
  undefined4 local_940;
  int local_938;
  int local_934;
  int local_930;
  int local_92c;
  int local_928;
  int local_924;
  int local_920;
  int local_91c;
  int local_918;
  int local_914;
  int local_910;
  int local_90c;
  int local_908;
  int local_904;
  int local_900;
  int local_8fc;
  int local_8f8;
  int local_8f4;
  int local_8f0;
  int local_8ec;
  int local_8e8;
  int local_8e4;
  int local_8e0;
  int local_8dc;
  int local_8d8;
  int local_8d4;
  int local_8d0;
  int local_8cc;
  int local_8c8;
  int local_8c4;
  int local_8c0;
  int local_8bc;
  int local_8b7;
  int local_8b3;
  int local_8af;
  int local_8ab;
  int local_8a7;
  int local_8a3;
  int local_89f;
  int local_89b;
  undefined local_897 [8];
  int local_88f;
  int local_887;
  int local_883 [5];
  char local_86f;
  undefined2 local_86e;
  undefined local_86c [2045];
  undefined4 local_6f;
  undefined4 local_6b;
  undefined4 local_67;
  undefined4 local_63;
  undefined4 local_5f;
  undefined4 local_5b;
  undefined4 local_57;
  undefined4 local_53;
  undefined4 local_4f;
  undefined4 local_4b;
  undefined2 local_47;
  undefined local_45;
  undefined4 local_44;
  undefined4 local_40;
  int *local_3c;
  int local_34;
  int local_30;
  int local_28;
  undefined4 local_24;
  
  bVar14 = 0;
  local_3c = param_2;
  local_30 = param_3;
  local_34 = param_3;
  local_28 = 0;
  local_24 = 0;
  local_40 = 1;
  local_44 = 0;
  FUN_0001a8a6(&local_44);
  iVar2 = FUN_0001aa43(&local_44);
  iVar3 = FUN_0001aa97(&local_44);
  iVar4 = FUN_0001aa97(&local_44);
  if (*param_1 == 0) {
    *param_4 = 1;
    return;
  }
  Plugin_EnterCriticalSection();
  piVar8 = &DAT_00041d90;
  iVar9 = 0;
  do {
    if ((((*piVar8 == iVar3) && (piVar8[1] == iVar4)) && (iVar3 != 0)) && (iVar4 != 0)) {
      iVar5 = Plugin_NET_CompareBaseAdr(piVar8 + 0x13,param_1);
      if (iVar5 == 0) {
        if (iVar2 != 1) goto LAB_0001603d;
        piVar8[2] = DAT_0004130c;
        local_938 = *param_1;
        local_934 = param_1[1];
        local_930 = param_1[2];
        local_92c = param_1[3];
        local_928 = param_1[4];
        local_924 = param_1[5];
        local_920 = param_1[6];
        local_91c = param_1[7];
        Plugin_EnterCriticalSection();
        local_940 = FUN_0001aa65(&local_44);
      }
      else {
        piVar8[2] = DAT_0004130c;
        switch(iVar2) {
        default:
          goto switchD_000163b0_caseD_0;
        case 1:
          local_938 = *param_1;
          local_934 = param_1[1];
          local_930 = param_1[2];
          local_92c = param_1[3];
          local_928 = param_1[4];
          local_924 = param_1[5];
          local_920 = param_1[6];
          local_91c = param_1[7];
          Plugin_EnterCriticalSection();
          local_940 = FUN_0001aa65(&local_44);
          break;
        case 2:
          local_918 = *param_1;
          local_914 = param_1[1];
          local_910 = param_1[2];
          local_90c = param_1[3];
          local_908 = param_1[4];
          local_904 = param_1[5];
          local_900 = param_1[6];
          local_8fc = param_1[7];
          iVar9 = FUN_0001aa65(&local_44);
          Plugin_EnterCriticalSection();
          iVar5 = 0;
          piVar8 = &DAT_00041d90;
          goto LAB_00015a43;
        case 10:
          local_8f8 = *param_1;
          local_8f4 = param_1[1];
          local_8f0 = param_1[2];
          local_8ec = param_1[3];
          local_8e8 = param_1[4];
          local_8e4 = param_1[5];
          local_8e0 = param_1[6];
          local_8dc = param_1[7];
          FUN_0001aa65(&local_44);
          FUN_0001aa65(&local_44);
          _DAT_00041d8c = iVar9;
          FUN_0001a849(local_897,&local_86f,0x800);
          local_88f = local_28 + (int)local_3c;
          local_887 = local_30 - local_28;
          local_883[0] = local_887;
          Plugin_ServerPacketEvent(&local_8f8,local_88f,local_887);
          goto LAB_00016026;
        case 0xb:
          local_8d8 = *param_1;
          local_8d4 = param_1[1];
          local_8d0 = param_1[2];
          local_8cc = param_1[3];
          local_8c8 = param_1[4];
          local_8c4 = param_1[5];
          local_8c0 = param_1[6];
          local_8bc = param_1[7];
          FUN_0001aa65(&local_44);
          FUN_0001aa65(&local_44);
          _DAT_00041d8c = iVar9;
          FUN_0001a849(local_897,&local_86f,0x800);
          FUN_0001ae70(local_88f,local_887,local_883,local_28 + (int)local_3c,local_30 - local_28);
          Plugin_ServerPacketEvent(&local_8d8,local_88f,local_883[0]);
          goto LAB_00016026;
        case 0x16:
          local_8b7 = *param_1;
          local_8b3 = param_1[1];
          local_8af = param_1[2];
          local_8ab = param_1[3];
          local_8a7 = param_1[4];
          local_8a3 = param_1[5];
          local_89f = param_1[6];
          local_89b = param_1[7];
          uVar6 = FUN_0001aa97(&local_44);
          Plugin_EnterCriticalSection();
          iVar9 = 0;
          piVar8 = &DAT_00041d90;
          goto LAB_00015e2c;
        }
      }
      iVar9 = 0;
      piVar8 = &DAT_00041d90;
      goto LAB_00015801;
    }
LAB_0001603d:
    iVar9 = iVar9 + 1;
    piVar8 = (int *)((int)piVar8 + 0x7a);
  } while (piVar8 != (int *)&DAT_00043c10);
  Plugin_LeaveCriticalSection();
  local_4f = 0x75417267;
  local_4b = 0x61446874;
  local_47 = 0x6174;
  local_45 = 0;
  local_67 = 0x75417267;
  local_63 = 0x68436874;
  local_5f = 0x656c6c61;
  local_5b = 0x5265676e;
  local_57 = 0x6f707365;
  local_53 = 0x65736e;
  local_6f = 0x6e6e6f63;
  local_6b = 0x746365;
  if (*param_2 == -1) {
    iVar2 = strncmp((char *)(param_2 + 1),(char *)&local_67,0x17);
    if (iVar2 == 0) {
      FUN_00013d1c(param_1,param_2,param_3);
      *param_4 = 1;
      return;
    }
    iVar2 = strncmp((char *)(param_2 + 1),(char *)&local_4f,10);
    if (iVar2 == 0) {
      FUN_00013e94(param_1,param_2,param_3);
      *param_4 = 1;
      return;
    }
  }
  if ((_DAT_00043c14 != 0) ||
     (iVar2 = strncmp((char *)(param_2 + 1),(char *)&local_6f,7), iVar2 != 0)) {
    *param_4 = 0;
    return;
  }
  puVar11 = (undefined4 *)&local_86e;
  puVar10 = (undefined4 *)0x1df05;
  uVar7 = 0x70;
  bVar13 = ((uint)puVar11 & 2) != 0;
  if (bVar13) {
    puVar11 = (undefined4 *)local_86c;
    puVar10 = (undefined4 *)0x1df07;
    uVar7 = 0x6e;
  }
  uVar7 = uVar7 >> 2;
  while (uVar7 != 0) {
    uVar7 = uVar7 - 1;
    *puVar11 = *puVar10;
    puVar10 = puVar10 + (uint)bVar14 * 0x3ffffffe + 1;
    puVar11 = puVar11 + (uint)bVar14 * 0x3ffffffe + 1;
  }
  if (bVar13) {
    *(undefined2 *)puVar11 = *(undefined2 *)puVar10;
  }
  local_86f = -1;
  local_86e = 0xffff;
  local_86c[0] = 0xff;
  uVar7 = 0xffffffff;
  pcVar12 = &local_86f;
  do {
    if (uVar7 == 0) break;
    uVar7 = uVar7 - 1;
    cVar1 = *pcVar12;
    pcVar12 = pcVar12 + (uint)bVar14 * -2 + 1;
  } while (cVar1 != '\0');
  Plugin_UdpSendData(param_1,&local_86f,~uVar7 - 1);
  *param_4 = 1;
  return;
  while( true ) {
    iVar9 = iVar9 + 1;
    piVar8 = (int *)((int)piVar8 + 0x7a);
    if (iVar9 == 0x40) break;
LAB_00015e2c:
    if ((iVar3 == *piVar8) && (iVar4 == piVar8[1])) {
      if (iVar9 != 0x40) {
        piVar8[0x13] = local_8b7;
        piVar8[0x14] = local_8b3;
        piVar8[0x15] = local_8af;
        piVar8[0x16] = local_8ab;
        piVar8[0x17] = local_8a7;
        piVar8[0x18] = local_8a3;
        piVar8[0x19] = local_89f;
        piVar8[0x1a] = local_89b;
        Plugin_LeaveCriticalSection();
        FUN_0001a849(local_897,&local_86f,0x400);
        FUN_0001a8bf(local_897,0x17);
        FUN_0001a926(local_897,DAT_00041308);
        FUN_0001a926(local_897,iVar4);
        FUN_0001a926(local_897,uVar6);
        Plugin_UdpSendData(&local_8b7,local_88f,local_883[0]);
        local_8d8 = 1;
        Plugin_RandomBytes(&local_8d8,4);
        FUN_0001a849(local_897,&local_86f,0x400);
        FUN_0001a8bf(local_897,0x16);
        FUN_0001a926(local_897,DAT_00041308);
        FUN_0001a926(local_897,iVar4);
        FUN_0001a926(local_897,local_8d8);
        Plugin_UdpSendData(&local_8b7,local_88f,local_883[0]);
        goto switchD_000163b0_caseD_0;
      }
      break;
    }
  }
  uVar6 = Plugin_NET_AdrToStringMT(&local_8b7,&local_86f,0x400);
  Plugin_Printf("Invalid GRID/Challenge from: %s\n",uVar6);
  Plugin_LeaveCriticalSection();
  goto switchD_000163b0_caseD_0;
  while( true ) {
    iVar5 = iVar5 + 1;
    piVar8 = (int *)((int)piVar8 + 0x7a);
    if (iVar5 == 0x40) break;
LAB_00015a43:
    if ((iVar3 == *piVar8) && (iVar4 == piVar8[1])) {
      if (iVar5 != 0x40) {
        if (iVar9 == (int)*(short *)(piVar8 + 0x1b)) {
          if (*(int *)((int)piVar8 + 0x6e) == 1) {
            Plugin_LeaveCriticalSection();
          }
          else {
            *(undefined4 *)((int)piVar8 + 0x6e) = 1;
            Plugin_Printf("^5GameRanger: UDP-Connection good for client: %d\n",*piVar8);
            Plugin_LeaveCriticalSection();
            FUN_0001a849(local_897,&local_86f,0x400);
            FUN_0001a926(local_897,0x8b);
            FUN_0001a926(local_897,0);
            FUN_0001a926(local_897,iVar3);
            FUN_0001a8bf(local_897,1);
            FUN_00012f4e(local_897,1);
          }
        }
        else {
          Plugin_LeaveCriticalSection();
        }
        goto switchD_000163b0_caseD_0;
      }
      break;
    }
  }
  uVar6 = Plugin_NET_AdrToStringMT(&local_918,&local_86f,0x400);
  Plugin_Printf("Invalid GRID/Challenge from: %s\n",uVar6);
  Plugin_LeaveCriticalSection();
  goto switchD_000163b0_caseD_0;
  while( true ) {
    iVar9 = iVar9 + 1;
    piVar8 = (int *)((int)piVar8 + 0x7a);
    if (iVar9 == 0x40) break;
LAB_00015801:
    if ((iVar3 == *piVar8) && (iVar4 == piVar8[1])) {
      if (iVar9 != 0x40) {
        piVar8[0x13] = local_938;
        piVar8[0x14] = local_934;
        piVar8[0x15] = local_930;
        piVar8[0x16] = local_92c;
        piVar8[0x17] = local_928;
        piVar8[0x18] = local_924;
        piVar8[0x19] = local_920;
        piVar8[0x1a] = local_91c;
        FUN_0001a849(local_897,&local_86f,0x400);
        FUN_0001a8bf(local_897,2);
        FUN_0001a926(local_897,DAT_00041308);
        FUN_0001a926(local_897,iVar4);
        FUN_0001a8e9(local_897,local_940);
        Plugin_UdpSendData(&local_938,local_88f,local_883[0]);
        Plugin_RandomBytes(piVar8 + 0x1b,2);
        *(undefined2 *)(piVar8 + 0x1b) = 1;
        FUN_0001a849(local_897,&local_86f,0x400);
        FUN_0001a8bf(local_897,1);
        FUN_0001a926(local_897,DAT_00041308);
        FUN_0001a926(local_897,iVar4);
        FUN_0001a8e9(local_897,(int)*(short *)(piVar8 + 0x1b));
        FUN_0001a8bf(local_897,1);
        Plugin_UdpSendData(&local_938,local_88f,local_883[0]);
        Plugin_LeaveCriticalSection();
        goto switchD_000163b0_caseD_0;
      }
      break;
    }
  }
  uVar6 = Plugin_NET_AdrToStringMT(&local_938,&local_86f,0x400);
  Plugin_Printf("^5GameRanger: Invalid GRID/Challenge from: %s\n",uVar6);
  Plugin_LeaveCriticalSection();
switchD_000163b0_caseD_0:
  uVar6 = Plugin_NET_AdrToStringMT(param_1,&local_86f,0x400);
  Plugin_DPrintf("Udp-Cmd: %d from: %s\n",iVar2,uVar6);
LAB_00016026:
  *param_4 = 1;
  Plugin_LeaveCriticalSection();
  return;
}



void OnUdpNetSend(int *param_1,undefined4 param_2,undefined4 param_3,undefined4 *param_4)

{
  undefined4 uVar1;
  int iVar2;
  undefined4 *puVar3;
  int iVar4;
  undefined local_34 [8];
  undefined4 local_2c;
  undefined4 local_20;
  
  if (*param_1 == 0) {
    *param_4 = 1;
  }
  else {
    Plugin_EnterCriticalSection();
    puVar3 = &DAT_00041d90;
    iVar4 = 0;
    do {
      iVar2 = Plugin_NET_CompareAdr(puVar3 + 0x13,param_1);
      if (iVar2 != 0) {
        if (iVar4 != 0x40) {
          uVar1 = puVar3[1];
          FUN_0001a849(local_34,&DAT_00021200,&uleb128_00020020);
          FUN_0001a8bf(local_34,10);
          FUN_0001a926(local_34,DAT_00041308);
          Plugin_LeaveCriticalSection();
          FUN_0001a926(local_34,uVar1);
          FUN_0001a8e9(local_34,0x7120);
          FUN_0001a8e9(local_34,0x7120);
          FUN_0001a961(local_34,param_2,param_3);
          Plugin_UdpSendData(param_1,local_2c,local_20);
          *param_4 = 1;
          return;
        }
        break;
      }
      iVar4 = iVar4 + 1;
      puVar3 = (undefined4 *)((int)puVar3 + 0x7a);
    } while (iVar4 != 0x40);
    *param_4 = 0;
    Plugin_LeaveCriticalSection();
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void OnPlayerConnect(int param_1,undefined4 param_2)

{
  int iVar1;
  undefined4 *puVar2;
  int iVar3;
  undefined2 *param_6;
  
  Plugin_EnterCriticalSection();
  puVar2 = &DAT_00041d90;
  iVar3 = 0;
  do {
    iVar1 = Plugin_NET_CompareAdr(puVar2 + 0x13,param_2);
    if (iVar1 != 0) {
      if (iVar3 != 0x40) {
        Plugin_LeaveCriticalSection();
        *(undefined4 *)(&DAT_090b5338 + param_1 * 0xa563c) = *puVar2;
        *(undefined4 *)(&DAT_090b533c + param_1 * 0xa563c) = 0x24100001;
        return;
      }
      break;
    }
    iVar3 = iVar3 + 1;
    puVar2 = (undefined4 *)((int)puVar2 + 0x7a);
  } while (iVar3 != 0x40);
  if (_DAT_00043c14 == 0) {
    *param_6 = 0x6b;
  }
  Plugin_LeaveCriticalSection();
  return;
}



int * FUN_00016570(uint param_1)

{
  int *piVar1;
  
  piVar1 = DAT_00021164;
  if (*DAT_00021164 != 0) {
    piVar1 = DAT_00021164 + 0x2b;
    while (*piVar1 != 0) {
      piVar1 = piVar1 + 0x2b;
      if (piVar1 == DAT_00021164 + 0xac00) {
        return (int *)0;
      }
    }
  }
  *piVar1 = 1;
  piVar1[1] = 0;
  piVar1[2] = 0;
  piVar1[3] = 0;
  piVar1[4] = 0x3ff;
  piVar1[6] = 0;
  piVar1[7] = 0;
  piVar1[8] = 0;
  *(undefined *)(piVar1 + 9) = 0xff;
  *(undefined *)((int)piVar1 + 0x25) = 0xff;
  *(undefined *)((int)piVar1 + 0x26) = 0xff;
  *(undefined *)((int)piVar1 + 0x27) = 0xff;
  *(undefined *)(piVar1 + 0x21) = 0;
  *(undefined *)((int)piVar1 + 0x85) = 0;
  *(undefined *)((int)piVar1 + 0x86) = 0;
  *(undefined *)((int)piVar1 + 0x87) = 0;
  *(undefined *)(piVar1 + 10) = 0;
  *(undefined *)((int)piVar1 + 0x29) = 0;
  *(undefined *)((int)piVar1 + 0x2a) = 0;
  *(undefined *)((int)piVar1 + 0x2b) = 0;
  piVar1[0xb] = 0;
  piVar1[0xc] = 0;
  piVar1[0xd] = 0;
  piVar1[0x20] = 0;
  piVar1[0x27] = 0;
  piVar1[0x22] = 0;
  piVar1[0x23] = 0;
  piVar1[0x24] = 0;
  piVar1[0x25] = 0;
  piVar1[0x26] = 0;
  piVar1[0x1a] = 0;
  piVar1[0x1b] = 0;
  piVar1[5] = 0x3fb33333;
  piVar1[0x2a] = 0;
  piVar1[0xe] = 0;
  piVar1[0xf] = 0;
  piVar1[0x16] = 0;
  piVar1[0x17] = 0;
  piVar1[0x18] = 0;
  piVar1[0x19] = 0;
  piVar1[0x12] = 0;
  piVar1[0x13] = 0;
  piVar1[0x14] = 0;
  piVar1[0x15] = 0;
  piVar1[0x1c] = 0;
  piVar1[0x1d] = 0;
  piVar1[0x1e] = 0;
  piVar1[0x1f] = 0;
  if (0x3f < param_1) {
    param_1 = 0x3ff;
  }
  piVar1[0x28] = param_1;
  piVar1[0x29] = 0;
  return piVar1;
}



void FUN_00016702(int param_1,undefined4 param_2,undefined4 param_3)

{
  *(undefined4 *)(param_1 + 0x24) = param_2;
  *(undefined4 *)(param_1 + 0x84) = param_3;
  return;
}



void FUN_00016718(int param_1,undefined4 param_2,undefined4 param_3,int param_4,int param_5,
                 uint param_6,uint param_7)

{
  *(undefined4 *)(param_1 + 4) = param_2;
  *(undefined4 *)(param_1 + 8) = param_3;
  *(uint *)(param_1 + 0x1c) = param_7 | param_6;
  *(int *)(param_1 + 0x20) = param_5 + param_4;
  return;
}



void FUN_00016741(int param_1,float param_2,undefined4 param_3)

{
  float fVar1;
  
  if (4.59999990 < param_2) {
    fVar1 = 1.39999998;
  }
  else {
    fVar1 = 1.39999998;
    if (1.39999890 <= param_2) {
      fVar1 = param_2;
    }
  }
  *(float *)(param_1 + 0x14) = fVar1;
  *(undefined4 *)(param_1 + 0x18) = param_3;
  return;
}



unkbyte10 FUN_00016784(int param_1,uint param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 uVar1;
  unkbyte10 extraout_ST0;
  
  if (60000 < param_2) {
    param_2 = 0;
  }
  uVar1 = Plugin_GetLevelTime();
  *(undefined4 *)(param_1 + 0x68) = uVar1;
  *(undefined4 *)(param_1 + 0x58) = *(undefined4 *)(param_1 + 4);
  *(undefined4 *)(param_1 + 0x5c) = *(undefined4 *)(param_1 + 8);
  *(undefined4 *)(param_1 + 4) = param_3;
  *(undefined4 *)(param_1 + 8) = param_4;
  *(undefined4 *)(param_1 + 0x60) = *(undefined4 *)(param_1 + 0x1c);
  *(undefined4 *)(param_1 + 100) = *(undefined4 *)(param_1 + 0x20);
  *(uint *)(param_1 + 0x6c) = param_2;
  return extraout_ST0;
}



void FUN_000167d6(int param_1,uint param_2,undefined4 param_3)

{
  undefined4 uVar1;
  
  if (60000 < param_2) {
    param_2 = 0;
  }
  uVar1 = Plugin_GetLevelTime();
  *(undefined4 *)(param_1 + 0x2c) = uVar1;
  *(undefined4 *)(param_1 + 0x28) = *(undefined4 *)(param_1 + 0x24);
  *(uint *)(param_1 + 0x30) = param_2;
  *(undefined4 *)(param_1 + 0x24) = param_3;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0001680f(undefined4 *param_1,undefined4 param_2)

{
  undefined4 uVar1;
  
  param_1[0xe] = 0;
  param_1[0xf] = 0;
  param_1[0x10] = 0;
  param_1[0x16] = 0;
  param_1[0x17] = 0;
  param_1[0x18] = 0;
  param_1[0x19] = 0;
  param_1[0x12] = 0;
  param_1[0x13] = 0;
  param_1[0x14] = 0;
  param_1[0x15] = 0;
  param_1[0x1c] = 0;
  param_1[0x1d] = 0;
  param_1[0x1e] = 0;
  uVar1 = (*_DAT_0002116c)(param_2);
  param_1[0x1f] = uVar1;
  *param_1 = 1;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0001688e(undefined4 *param_1)

{
  (*_DAT_00021168)(param_1);
  *param_1 = 0;
  return;
}



void FUN_000168b0(int *param_1,int param_2)

{
  undefined *puVar1;
  byte *pbVar2;
  uint uVar3;
  undefined *puVar4;
  ushort uVar5;
  undefined4 *puVar6;
  undefined *puVar7;
  undefined *puVar8;
  int iVar9;
  int iVar10;
  undefined4 uVar11;
  undefined4 uVar12;
  undefined uVar13;
  undefined *puVar14;
  undefined *puVar15;
  int iVar16;
  undefined *puVar17;
  undefined *puVar18;
  uint uVar19;
  byte bVar20;
  uint uVar21;
  uint uVar22;
  int iVar23;
  uint uVar24;
  undefined *puVar25;
  undefined *local_50;
  uint local_4c;
  
  puVar6 = (undefined4 *)param_1[7];
  local_4c = *param_1 - 1;
  uVar3 = *param_1 + -6 + param_1[1];
  local_50 = (undefined *)(param_1[3] + -1);
  puVar18 = local_50 + (param_1[4] - param_2);
  puVar4 = (undefined *)(param_1[3] + -0x102 + param_1[4]);
  iVar16 = puVar6[10];
  puVar7 = (undefined *)puVar6[0xb];
  puVar8 = (undefined *)puVar6[0xc];
  iVar23 = puVar6[0xd];
  uVar19 = puVar6[0xe];
  uVar22 = puVar6[0xf];
  iVar9 = puVar6[0x13];
  iVar10 = puVar6[0x14];
  uVar11 = puVar6[0x15];
  uVar12 = puVar6[0x16];
  puVar1 = (undefined *)(iVar23 + -1);
  do {
    if (uVar22 < 0xf) {
      uVar19 = uVar19 + ((uint)*(byte *)(local_4c + 1) << ((byte)uVar22 & 0x1f)) +
                        ((uint)*(byte *)(local_4c + 2) << ((byte)uVar22 + 8 & 0x1f));
      uVar22 = uVar22 + 0x10;
      local_4c = local_4c + 2;
    }
    pbVar2 = (byte *)(iVar9 + ((1 << ((byte)uVar11 & 0x1f)) - 1U & uVar19) * 4);
    bVar20 = *pbVar2;
    uVar21 = (uint)bVar20;
    puVar25 = (undefined *)(uint)*(ushort *)(pbVar2 + 2);
    uVar13 = (undefined)*(ushort *)(pbVar2 + 2);
    uVar19 = uVar19 >> (pbVar2[1] & 0x1f);
    uVar22 = uVar22 - pbVar2[1];
    if (bVar20 == 0) {
LAB_000169d8:
      local_50[1] = uVar13;
      local_50 = local_50 + 1;
    }
    else {
      if ((bVar20 & 0x10) == 0) {
        if ((bVar20 & 0x40) == 0) {
          while( true ) {
            pbVar2 = (byte *)(iVar9 + (int)(puVar25 + ((1 << ((byte)uVar21 & 0x1f)) - 1U & uVar19))
                                      * 4);
            bVar20 = *pbVar2;
            uVar21 = (uint)bVar20;
            puVar25 = (undefined *)(uint)*(ushort *)(pbVar2 + 2);
            uVar13 = (undefined)*(ushort *)(pbVar2 + 2);
            uVar19 = uVar19 >> (pbVar2[1] & 0x1f);
            uVar22 = uVar22 - pbVar2[1];
            if (bVar20 == 0) break;
            if ((bVar20 & 0x10) != 0) goto LAB_000169f4;
            if ((bVar20 & 0x40) != 0) goto LAB_00016da9;
          }
          goto LAB_000169d8;
        }
LAB_00016da9:
        if ((uVar21 & 0x20) == 0) {
          param_1[6] = 0x1e01c;
          *puVar6 = 0x1b;
        }
        else {
          *puVar6 = 0xb;
        }
LAB_00016df0:
        iVar16 = local_4c - (uVar22 >> 3);
        iVar23 = uVar22 - (uVar22 & 0xfffffff8);
        *param_1 = iVar16 + 1;
        *(undefined **)(param_1 + 3) = local_50 + 1;
        param_1[1] = (uVar3 - iVar16) + 5;
        *(undefined **)(param_1 + 4) = puVar4 + (0x101 - (int)local_50);
        puVar6[0xe] = uVar19 & (1 << ((byte)iVar23 & 0x1f)) - 1U;
        puVar6[0xf] = iVar23;
        return;
      }
LAB_000169f4:
      uVar21 = uVar21 & 0xf;
      if (uVar21 != 0) {
        if (uVar22 < uVar21) {
          uVar19 = uVar19 + ((uint)*(byte *)(local_4c + 1) << ((byte)uVar22 & 0x1f));
          uVar22 = uVar22 + 8;
          local_4c = local_4c + 1;
        }
        puVar25 = puVar25 + ((1 << (sbyte)uVar21) - 1U & uVar19);
        uVar19 = uVar19 >> (sbyte)uVar21;
        uVar22 = uVar22 - uVar21;
      }
      if (uVar22 < 0xf) {
        uVar19 = uVar19 + ((uint)*(byte *)(local_4c + 1) << ((byte)uVar22 & 0x1f)) +
                          ((uint)*(byte *)(local_4c + 2) << ((byte)uVar22 + 8 & 0x1f));
        uVar22 = uVar22 + 0x10;
        local_4c = local_4c + 2;
      }
      pbVar2 = (byte *)(iVar10 + ((1 << ((byte)uVar12 & 0x1f)) - 1U & uVar19) * 4);
      bVar20 = *pbVar2;
      uVar5 = *(ushort *)(pbVar2 + 2);
      uVar19 = uVar19 >> (pbVar2[1] & 0x1f);
      uVar22 = uVar22 - pbVar2[1];
      while ((bVar20 & 0x10) == 0) {
        if ((bVar20 & 0x40) != 0) {
          param_1[6] = 0x1e006;
          *puVar6 = 0x1b;
          goto LAB_00016df0;
        }
        pbVar2 = (byte *)(iVar10 + (((1 << (bVar20 & 0x1f)) - 1U & uVar19) + (uint)uVar5) * 4);
        bVar20 = *pbVar2;
        uVar5 = *(ushort *)(pbVar2 + 2);
        uVar19 = uVar19 >> (pbVar2[1] & 0x1f);
        uVar22 = uVar22 - pbVar2[1];
      }
      bVar20 = bVar20 & 0xf;
      uVar24 = (uint)bVar20;
      uVar21 = uVar22;
      if (uVar22 < uVar24) {
        uVar19 = uVar19 + ((uint)*(byte *)(local_4c + 1) << ((byte)uVar22 & 0x1f));
        uVar21 = uVar22 + 8;
        if (uVar21 < uVar24) {
          uVar19 = uVar19 + ((uint)*(byte *)(local_4c + 2) << ((byte)uVar21 & 0x1f));
          uVar21 = uVar22 + 0x10;
          local_4c = local_4c + 2;
        }
        else {
          local_4c = local_4c + 1;
        }
      }
      puVar14 = (undefined *)(((1 << bVar20) - 1U & uVar19) + (uint)uVar5);
      uVar19 = uVar19 >> bVar20;
      uVar22 = uVar21 - uVar24;
      if (local_50 + -(int)puVar18 < puVar14) {
        puVar17 = puVar14 + -(int)(local_50 + -(int)puVar18);
        if (puVar7 < puVar17) {
          param_1[6] = 0x1dfe8;
          *puVar6 = 0x1b;
          goto LAB_00016df0;
        }
        if (puVar8 == (undefined *)0x0) {
          puVar15 = puVar1 + (iVar16 - (int)puVar17);
          if (puVar17 < puVar25) {
            puVar25 = puVar25 + -(int)puVar17;
            puVar17 = puVar17 + (int)local_50;
            do {
              local_50 = local_50 + 1;
              puVar15 = puVar15 + 1;
              *local_50 = *puVar15;
            } while (local_50 != puVar17);
            puVar15 = puVar17 + -(int)puVar14;
            local_50 = puVar17;
          }
        }
        else {
          if (puVar8 < puVar17) {
            puVar15 = puVar1 + (int)(puVar8 + (iVar16 - (int)puVar17));
            puVar17 = puVar17 + -(int)puVar8;
            if (puVar17 < puVar25) {
              puVar25 = puVar25 + -(int)puVar17;
              puVar17 = puVar17 + (int)local_50;
              do {
                local_50 = local_50 + 1;
                puVar15 = puVar15 + 1;
                *local_50 = *puVar15;
              } while (local_50 != puVar17);
              puVar15 = puVar1;
              local_50 = puVar17;
              if (puVar8 < puVar25) {
                puVar25 = puVar25 + -(int)puVar8;
                puVar15 = (undefined *)0x0;
                do {
                  (puVar17 + 1)[(int)puVar15] = puVar15[iVar23];
                  puVar15 = puVar15 + 1;
                } while (puVar15 != puVar8);
                puVar15 = puVar17 + (int)puVar8 + -(int)puVar14;
                local_50 = puVar17 + (int)puVar8;
              }
            }
          }
          else {
            puVar15 = puVar8 + -(int)puVar17 + (int)puVar1;
            if (puVar17 < puVar25) {
              puVar25 = puVar25 + -(int)puVar17;
              puVar17 = puVar17 + (int)local_50;
              do {
                local_50 = local_50 + 1;
                puVar15 = puVar15 + 1;
                *local_50 = *puVar15;
              } while (local_50 != puVar17);
              puVar15 = puVar17 + -(int)puVar14;
              local_50 = puVar17;
            }
          }
        }
        while ((undefined *)0x2 < puVar25) {
          local_50[1] = puVar15[1];
          local_50[2] = puVar15[2];
          local_50[3] = puVar15[3];
          puVar25 = puVar25 + -3;
          puVar15 = puVar15 + 3;
          local_50 = local_50 + 3;
        }
        if (puVar25 != (undefined *)0x0) {
          local_50[1] = puVar15[1];
          if (puVar25 < (undefined *)0x2) {
            local_50 = local_50 + 1;
          }
          else {
            local_50[2] = puVar15[2];
            local_50 = local_50 + 2;
          }
        }
      }
      else {
        puVar14 = local_50 + -(int)puVar14;
        do {
          puVar15 = local_50;
          puVar17 = puVar14;
          puVar15[1] = puVar17[1];
          puVar15[2] = puVar17[2];
          local_50 = puVar15 + 3;
          puVar15[3] = puVar17[3];
          puVar25 = puVar25 + -3;
          puVar14 = puVar17 + 3;
        } while ((undefined *)0x2 < puVar25);
        if (puVar25 != (undefined *)0x0) {
          puVar15[4] = puVar17[4];
          if (puVar25 < (undefined *)0x2) {
            local_50 = puVar15 + 4;
          }
          else {
            puVar15[5] = puVar17[5];
            local_50 = puVar15 + 5;
          }
        }
      }
    }
    if ((uVar3 <= local_4c) || (puVar4 <= local_50)) goto LAB_00016df0;
  } while( true );
}



uint __regparm3 FUN_00016e90(uint *param_1,int param_2,uint param_3)

{
  byte bVar1;
  uint uVar2;
  uint uVar3;
  
  uVar3 = *param_1;
  if (param_3 == 0) {
    uVar2 = 0;
  }
  else {
    uVar2 = 1;
    if (uVar3 < 4) {
      do {
        bVar1 = *(byte *)(param_2 + -1 + uVar2);
        if (bVar1 == (byte)~-(uVar3 < 2)) {
          uVar3 = uVar3 + 1;
LAB_00016ee0:
          if ((param_3 <= uVar2) || (3 < uVar3)) goto LAB_00016efb;
        }
        else {
          if (bVar1 == 0) {
            uVar3 = 4 - uVar3;
            goto LAB_00016ee0;
          }
          if (param_3 <= uVar2) {
            uVar3 = 0;
            goto LAB_00016efb;
          }
          uVar3 = 0;
        }
        uVar2 = uVar2 + 1;
      } while( true );
    }
    uVar2 = 0;
  }
LAB_00016efb:
  *param_1 = uVar3;
  return uVar2;
}



undefined4 __regparm3 FUN_00016f08(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  undefined4 *puVar6;
  undefined4 *puVar7;
  undefined4 *puVar8;
  undefined4 *puVar9;
  byte bVar10;
  uint local_24;
  
  bVar10 = 0;
  iVar1 = *(int *)(param_1 + 0x1c);
  if (*(int *)(iVar1 + 0x34) == 0) {
    iVar2 = (**(code **)(param_1 + 0x20))
                      (*(undefined4 *)(param_1 + 0x28),
                       1 << ((byte)*(undefined4 *)(iVar1 + 0x24) & 0x1f),1);
    *(int *)(iVar1 + 0x34) = iVar2;
    if (iVar2 == 0) {
      return 1;
    }
  }
  if (*(int *)(iVar1 + 0x28) == 0) {
    *(int *)(iVar1 + 0x28) = 1 << ((byte)*(undefined4 *)(iVar1 + 0x24) & 0x1f);
    *(undefined4 *)(iVar1 + 0x30) = 0;
    *(undefined4 *)(iVar1 + 0x2c) = 0;
  }
  uVar5 = param_2 - *(int *)(param_1 + 0x10);
  uVar4 = *(uint *)(iVar1 + 0x28);
  if (uVar5 < uVar4) {
    uVar4 = uVar4 - *(int *)(iVar1 + 0x30);
    if (uVar5 <= uVar4) {
      uVar4 = uVar5;
    }
    puVar8 = (undefined4 *)(*(int *)(iVar1 + 0x30) + *(int *)(iVar1 + 0x34));
    puVar6 = (undefined4 *)(*(int *)(param_1 + 0xc) - uVar5);
    local_24 = uVar4;
    if (3 < uVar4) {
      if (((uint)puVar8 & 1) != 0) {
        *(undefined *)puVar8 = *(undefined *)puVar6;
        puVar8 = (undefined4 *)((int)puVar8 + 1);
        puVar6 = (undefined4 *)((int)puVar6 + 1);
        local_24 = uVar4 - 1;
      }
      if (((uint)puVar8 & 2) != 0) {
        *(undefined2 *)puVar8 = *(undefined2 *)puVar6;
        puVar8 = (undefined4 *)((int)puVar8 + 2);
        puVar6 = (undefined4 *)((int)puVar6 + 2);
        local_24 = local_24 - 2;
      }
      uVar3 = local_24 >> 2;
      while (uVar3 != 0) {
        uVar3 = uVar3 - 1;
        *puVar8 = *puVar6;
        puVar6 = puVar6 + (uint)bVar10 * 0x3ffffffe + 1;
        puVar8 = puVar8 + (uint)bVar10 * 0x3ffffffe + 1;
      }
    }
    puVar7 = puVar6;
    puVar9 = puVar8;
    if ((local_24 & 2) != 0) {
      puVar9 = (undefined4 *)((int)puVar8 + (uint)bVar10 * -4 + 2);
      puVar7 = (undefined4 *)((int)puVar6 + (uint)bVar10 * -4 + 2);
      *(undefined2 *)puVar8 = *(undefined2 *)puVar6;
    }
    if ((local_24 & 1) != 0) {
      *(undefined *)puVar9 = *(undefined *)puVar7;
    }
    uVar5 = uVar5 - uVar4;
    if (uVar5 == 0) {
      uVar5 = uVar4 + *(int *)(iVar1 + 0x30);
      *(uint *)(iVar1 + 0x30) = uVar5;
      if (uVar5 == *(uint *)(iVar1 + 0x28)) {
        *(undefined4 *)(iVar1 + 0x30) = 0;
      }
      if (*(uint *)(iVar1 + 0x2c) < *(uint *)(iVar1 + 0x28)) {
        *(int *)(iVar1 + 0x2c) = uVar4 + *(uint *)(iVar1 + 0x2c);
      }
    }
    else {
      puVar8 = *(undefined4 **)(iVar1 + 0x34);
      puVar6 = (undefined4 *)(*(int *)(param_1 + 0xc) - uVar5);
      uVar4 = uVar5;
      if (3 < uVar5) {
        if (((uint)puVar8 & 1) != 0) {
          *(undefined *)puVar8 = *(undefined *)puVar6;
          puVar8 = (undefined4 *)((int)puVar8 + 1);
          puVar6 = (undefined4 *)((int)puVar6 + 1);
          uVar4 = uVar5 - 1;
        }
        if (((uint)puVar8 & 2) != 0) {
          *(undefined2 *)puVar8 = *(undefined2 *)puVar6;
          puVar8 = (undefined4 *)((int)puVar8 + 2);
          puVar6 = (undefined4 *)((int)puVar6 + 2);
          uVar4 = uVar4 - 2;
        }
        uVar3 = uVar4 >> 2;
        while (uVar3 != 0) {
          uVar3 = uVar3 - 1;
          *puVar8 = *puVar6;
          puVar6 = puVar6 + (uint)bVar10 * 0x3ffffffe + 1;
          puVar8 = puVar8 + (uint)bVar10 * 0x3ffffffe + 1;
        }
      }
      puVar7 = puVar6;
      puVar9 = puVar8;
      if ((uVar4 & 2) != 0) {
        puVar9 = (undefined4 *)((int)puVar8 + (uint)bVar10 * -4 + 2);
        puVar7 = (undefined4 *)((int)puVar6 + (uint)bVar10 * -4 + 2);
        *(undefined2 *)puVar8 = *(undefined2 *)puVar6;
      }
      if ((uVar4 & 1) != 0) {
        *(undefined *)puVar9 = *(undefined *)puVar7;
      }
      *(uint *)(iVar1 + 0x30) = uVar5;
      *(undefined4 *)(iVar1 + 0x2c) = *(undefined4 *)(iVar1 + 0x28);
    }
  }
  else {
    puVar8 = *(undefined4 **)(iVar1 + 0x34);
    puVar6 = (undefined4 *)(*(int *)(param_1 + 0xc) - uVar4);
    if (3 < uVar4) {
      if (((uint)puVar8 & 1) != 0) {
        *(undefined *)puVar8 = *(undefined *)puVar6;
        puVar8 = (undefined4 *)((int)puVar8 + 1);
        puVar6 = (undefined4 *)((int)puVar6 + 1);
        uVar4 = uVar4 - 1;
      }
      if (((uint)puVar8 & 2) != 0) {
        *(undefined2 *)puVar8 = *(undefined2 *)puVar6;
        puVar8 = (undefined4 *)((int)puVar8 + 2);
        puVar6 = (undefined4 *)((int)puVar6 + 2);
        uVar4 = uVar4 - 2;
      }
      uVar5 = uVar4 >> 2;
      while (uVar5 != 0) {
        uVar5 = uVar5 - 1;
        *puVar8 = *puVar6;
        puVar6 = puVar6 + (uint)bVar10 * 0x3ffffffe + 1;
        puVar8 = puVar8 + (uint)bVar10 * 0x3ffffffe + 1;
      }
    }
    puVar7 = puVar6;
    puVar9 = puVar8;
    if ((uVar4 & 2) != 0) {
      puVar9 = (undefined4 *)((int)puVar8 + (uint)bVar10 * -4 + 2);
      puVar7 = (undefined4 *)((int)puVar6 + (uint)bVar10 * -4 + 2);
      *(undefined2 *)puVar8 = *(undefined2 *)puVar6;
    }
    if ((uVar4 & 1) != 0) {
      *(undefined *)puVar9 = *(undefined *)puVar7;
    }
    *(undefined4 *)(iVar1 + 0x30) = 0;
    *(undefined4 *)(iVar1 + 0x2c) = *(undefined4 *)(iVar1 + 0x28);
  }
  return 0;
}



undefined4 FUN_000170f3(int param_1)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  
  if (param_1 == 0) {
    return 0xfffffffe;
  }
  puVar2 = *(undefined4 **)(param_1 + 0x1c);
  if (puVar2 != (undefined4 *)0x0) {
    puVar2[7] = 0;
    *(undefined4 *)(param_1 + 0x14) = 0;
    *(undefined4 *)(param_1 + 8) = 0;
    *(undefined4 *)(param_1 + 0x18) = 0;
    *(undefined4 *)(param_1 + 0x30) = 1;
    *puVar2 = 0;
    puVar2[1] = 0;
    puVar2[3] = 0;
    puVar2[5] = 0x8000;
    puVar2[8] = 0;
    puVar2[10] = 0;
    puVar2[0xb] = 0;
    puVar2[0xc] = 0;
    puVar2[0xe] = 0;
    puVar2[0xf] = 0;
    puVar1 = puVar2 + 0x14c;
    *(undefined4 **)(puVar2 + 0x1b) = puVar1;
    *(undefined4 **)(puVar2 + 0x14) = puVar1;
    *(undefined4 **)(puVar2 + 0x13) = puVar1;
    return 0;
  }
  return 0xfffffffe;
}



undefined4 FUN_00017193(int param_1,int param_2,uint param_3)

{
  uint uVar1;
  int iVar2;
  undefined4 uVar3;
  
  if (param_1 == 0) {
    uVar3 = 0xfffffffe;
  }
  else {
    iVar2 = *(int *)(param_1 + 0x1c);
    if (iVar2 == 0) {
      uVar3 = 0xfffffffe;
    }
    else {
      if (param_2 < 0x11) {
        uVar1 = param_2 + *(int *)(iVar2 + 0x3c);
        if (uVar1 < 0x21) {
          *(int *)(iVar2 + 0x38) =
               *(int *)(iVar2 + 0x38) +
               (((1 << ((byte)param_2 & 0x1f)) - 1U & param_3) <<
               ((byte)*(int *)(iVar2 + 0x3c) & 0x1f));
          *(uint *)(iVar2 + 0x3c) = uVar1;
          uVar3 = 0;
        }
        else {
          uVar3 = 0xfffffffe;
        }
      }
      else {
        uVar3 = 0xfffffffe;
      }
    }
  }
  return uVar3;
}



undefined4 FUN_000171f4(int param_1,uint param_2,char *param_3,int param_4)

{
  int iVar1;
  undefined4 uVar2;
  
  if (param_3 == (char *)0x0) {
    uVar2 = 0xfffffffa;
  }
  else {
    if (*param_3 == '1') {
      if (param_4 == 0x38) {
        if (param_1 == 0) {
          uVar2 = 0xfffffffe;
        }
        else {
          *(undefined4 *)(param_1 + 0x18) = 0;
          if (*(int *)(param_1 + 0x20) == 0) {
            *(undefined4 *)(param_1 + 0x20) = 0x1afb7;
            *(undefined4 *)(param_1 + 0x28) = 0;
          }
          if (*(int *)(param_1 + 0x24) == 0) {
            *(undefined4 *)(param_1 + 0x24) = 0x1afcf;
          }
          iVar1 = (**(code **)(param_1 + 0x20))(*(undefined4 *)(param_1 + 0x28),1,0x2530);
          if (iVar1 == 0) {
            uVar2 = 0xfffffffc;
          }
          else {
            *(int *)(param_1 + 0x1c) = iVar1;
            if ((int)param_2 < 0) {
              *(undefined4 *)(iVar1 + 8) = 0;
              param_2 = -param_2;
            }
            else {
              *(int *)(iVar1 + 8) = ((int)param_2 >> 4) + 1;
              if ((int)param_2 < 0x30) {
                param_2 = param_2 & 0xf;
              }
            }
            if (param_2 - 8 < 8) {
              *(uint *)(iVar1 + 0x24) = param_2;
              *(undefined4 *)(iVar1 + 0x34) = 0;
              uVar2 = FUN_000170f3(param_1);
            }
            else {
              (**(code **)(param_1 + 0x24))(*(undefined4 *)(param_1 + 0x28),iVar1);
              *(undefined4 *)(param_1 + 0x1c) = 0;
              uVar2 = 0xfffffffe;
            }
          }
        }
      }
      else {
        uVar2 = 0xfffffffa;
      }
    }
    else {
      uVar2 = 0xfffffffa;
    }
  }
  return uVar2;
}



void FUN_000172f4(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  FUN_000171f4(param_1,0xf,param_2,param_3);
  return;
}



int FUN_0001731f(int *param_1,int param_2)

{
  uint *puVar1;
  byte *pbVar2;
  char cVar3;
  byte bVar4;
  uint *puVar5;
  uint uVar6;
  byte bVar7;
  uint *puVar8;
  ushort *puVar9;
  uint *puVar10;
  uint uVar11;
  undefined4 *puVar12;
  uint uVar13;
  int iVar14;
  uint uVar15;
  int iVar16;
  byte bVar17;
  undefined2 uVar18;
  ushort uVar19;
  uint uVar20;
  undefined4 *puVar21;
  undefined4 *puVar22;
  int iVar23;
  undefined4 *puVar24;
  uint uVar25;
  uint uVar26;
  byte bVar27;
  uint local_74;
  uint local_70;
  uint local_6c;
  uint local_68;
  undefined4 *local_64;
  int local_60;
  undefined4 *local_5c;
  char local_20;
  undefined local_1f;
  undefined local_1e;
  undefined local_1d;
  
  bVar27 = 0;
  if ((((param_1 == (int *)0x0) || (puVar5 = (uint *)param_1[7], puVar5 == (uint *)0x0)) ||
      (param_1[3] == 0)) || ((*param_1 == 0 && (param_1[1] != 0)))) {
    return 0xfffffffe;
  }
  if (*puVar5 == 0xb) {
    *puVar5 = 0xc;
  }
  local_6c = param_1[4];
  uVar6 = param_1[1];
  local_70 = puVar5[0xe];
  uVar15 = puVar5[0xf];
  local_60 = 0;
  puVar1 = puVar5 + 0x14c;
  puVar8 = puVar5 + 0xbc;
  local_5c = (undefined4 *)*param_1;
  local_74 = uVar6;
  local_68 = local_6c;
  local_64 = (undefined4 *)param_1[3];
LAB_000173e3:
  if (0x1c < *puVar5) {
    return 0xfffffffe;
  }
  puVar12 = local_5c;
  switch(*puVar5) {
  case 0:
    if (puVar5[2] == 0) {
      *puVar5 = 0xc;
    }
    else {
      while (uVar15 < 0x10) {
        if (local_74 == 0) goto LAB_00018f18;
        local_74 = local_74 - 1;
        local_70 = local_70 + ((uint)*(byte *)local_5c << ((byte)uVar15 & 0x1f));
        uVar15 = uVar15 + 8;
        local_5c = (undefined4 *)((int)local_5c + 1);
      }
      if (((puVar5[2] & 2) == 0) || (local_70 != 0x8b1f)) {
        puVar5[4] = 0;
        if (puVar5[8] != 0) {
          *(undefined4 *)(puVar5[8] + 0x30) = 0xffffffff;
        }
        if (((*(byte *)(puVar5 + 2) & 1) == 0) ||
           (uVar13 = (local_70 >> 8) + (local_70 & 0xff) * 0x100, uVar13 != (uVar13 / 0x1f) * 0x1f))
        {
          param_1[6] = 0x1e038;
          *puVar5 = 0x1b;
        }
        else {
          if ((local_70 & 0xf) == 8) {
            local_70 = local_70 >> 4;
            uVar13 = (local_70 & 0xf) + 8;
            if (uVar13 < puVar5[9] || uVar13 == puVar5[9]) {
              puVar5[5] = 1 << (sbyte)uVar13;
              uVar15 = FUN_00012690(0,0,0);
              puVar5[6] = uVar15;
              param_1[0xc] = uVar15;
              *puVar5 = (-(uint)((local_70 & 0x200) == 0) & 2) + 9;
              uVar15 = 0;
              local_70 = 0;
            }
            else {
              uVar15 = uVar15 - 4;
              param_1[6] = 0x1e06a;
              *puVar5 = 0x1b;
            }
          }
          else {
            param_1[6] = 0x1e04f;
            *puVar5 = 0x1b;
          }
        }
      }
      else {
        uVar15 = FUN_00012b55(0,0,0);
        puVar5[6] = uVar15;
        local_20 = '\x1f';
        local_1f = 0x8b;
        uVar15 = FUN_00012b55(uVar15,&local_20,2);
        puVar5[6] = uVar15;
        *puVar5 = 1;
        uVar15 = 0;
        local_70 = 0;
      }
    }
    goto LAB_000173e3;
  case 1:
    while (uVar15 < 0x10) {
      if (local_74 == 0) goto LAB_00018f18;
      local_74 = local_74 - 1;
      local_70 = local_70 + ((uint)*(byte *)local_5c << ((byte)uVar15 & 0x1f));
      uVar15 = uVar15 + 8;
      local_5c = (undefined4 *)((int)local_5c + 1);
    }
    puVar5[4] = local_70;
    if ((char)local_70 != '\b') {
      param_1[6] = 0x1e04f;
      *puVar5 = 0x1b;
      goto LAB_000173e3;
    }
    if ((local_70 & 0xe000) != 0) {
      param_1[6] = 0x1e07e;
      *puVar5 = 0x1b;
      goto LAB_000173e3;
    }
    if ((uint *)puVar5[8] != (uint *)0x0) {
      *(uint *)puVar5[8] = local_70 >> 8 & 1;
    }
    if ((*(byte *)((int)puVar5 + 0x11) & 2) != 0) {
      local_1f = (undefined)(local_70 >> 8);
      local_20 = (char)local_70;
      uVar15 = FUN_00012b55(puVar5[6],&local_20,2);
      puVar5[6] = uVar15;
    }
    *puVar5 = 2;
    uVar15 = 0;
    local_70 = 0;
LAB_0001774c:
    puVar12 = local_5c;
    if (local_74 != 0) {
      while( true ) {
        local_74 = local_74 - 1;
        local_5c = (undefined4 *)((int)puVar12 + 1);
        local_70 = local_70 + ((uint)*(byte *)puVar12 << ((byte)uVar15 & 0x1f));
        uVar15 = uVar15 + 8;
        if (0x1f < uVar15) break;
        puVar12 = local_5c;
        if (local_74 == 0) goto LAB_00018f18;
      }
      goto LAB_0001778a;
    }
    break;
  case 2:
    if (uVar15 < 0x20) goto LAB_0001774c;
LAB_0001778a:
    if (puVar5[8] != 0) {
      *(uint *)(puVar5[8] + 4) = local_70;
    }
    if ((*(byte *)((int)puVar5 + 0x11) & 2) != 0) {
      local_20 = (char)local_70;
      local_1f = (undefined)(local_70 >> 8);
      local_1e = (undefined)(local_70 >> 0x10);
      local_1d = (undefined)(local_70 >> 0x18);
      uVar15 = FUN_00012b55(puVar5[6],&local_20,4);
      puVar5[6] = uVar15;
    }
    *puVar5 = 3;
    local_70 = 0;
    uVar15 = 0;
LAB_0001780b:
    puVar12 = local_5c;
    if (local_74 != 0) {
      while( true ) {
        local_74 = local_74 - 1;
        local_5c = (undefined4 *)((int)puVar12 + 1);
        local_70 = local_70 + ((uint)*(byte *)puVar12 << ((byte)uVar15 & 0x1f));
        uVar15 = uVar15 + 8;
        if (0xf < uVar15) break;
        puVar12 = local_5c;
        if (local_74 == 0) goto LAB_00018f18;
      }
      goto LAB_0001784a;
    }
    break;
  case 3:
    if (uVar15 < 0x10) goto LAB_0001780b;
LAB_0001784a:
    if (puVar5[8] != 0) {
      *(uint *)(puVar5[8] + 8) = local_70 & 0xff;
      *(uint *)(puVar5[8] + 0xc) = local_70 >> 8;
    }
    if ((*(byte *)((int)puVar5 + 0x11) & 2) != 0) {
      local_20 = (char)local_70;
      local_1f = (undefined)(local_70 >> 8);
      uVar15 = FUN_00012b55(puVar5[6],&local_20,2);
      puVar5[6] = uVar15;
    }
    *puVar5 = 4;
    if ((*(byte *)((int)puVar5 + 0x11) & 4) == 0) {
      uVar15 = 0;
      local_70 = 0;
LAB_0001798d:
      if (puVar5[8] != 0) {
        *(undefined4 *)(puVar5[8] + 0x10) = 0;
      }
      goto LAB_000179ae;
    }
    uVar15 = 0;
    local_70 = 0;
LAB_000178eb:
    puVar12 = local_5c;
    if (local_74 != 0) {
      while( true ) {
        local_74 = local_74 - 1;
        local_5c = (undefined4 *)((int)puVar12 + 1);
        local_70 = local_70 + ((uint)*(byte *)puVar12 << ((byte)uVar15 & 0x1f));
        uVar15 = uVar15 + 8;
        if (0xf < uVar15) break;
        puVar12 = local_5c;
        if (local_74 == 0) goto LAB_00018f18;
      }
      goto LAB_0001792a;
    }
    break;
  case 4:
    if ((*(byte *)((int)puVar5 + 0x11) & 4) == 0) goto LAB_0001798d;
    if (uVar15 < 0x10) goto LAB_000178eb;
LAB_0001792a:
    puVar5[0x10] = local_70;
    if (puVar5[8] != 0) {
      *(uint *)(puVar5[8] + 0x14) = local_70;
    }
    if ((*(byte *)((int)puVar5 + 0x11) & 2) == 0) {
      uVar15 = 0;
      local_70 = 0;
    }
    else {
      local_20 = (char)local_70;
      local_1f = (undefined)(local_70 >> 8);
      uVar15 = FUN_00012b55(puVar5[6],&local_20,2);
      puVar5[6] = uVar15;
      uVar15 = 0;
      local_70 = 0;
    }
LAB_000179ae:
    *puVar5 = 5;
  case 5:
    if ((*(byte *)((int)puVar5 + 0x11) & 4) != 0) {
      uVar13 = puVar5[0x10];
      uVar20 = local_74;
      if (uVar13 < local_74) {
        uVar20 = uVar13;
      }
      if (uVar20 != 0) {
        uVar25 = puVar5[8];
        if ((uVar25 != 0) && (*(int *)(uVar25 + 0x10) != 0)) {
          iVar14 = *(int *)(uVar25 + 0x14) - uVar13;
          uVar13 = uVar20;
          if (*(uint *)(uVar25 + 0x18) < uVar20 + iVar14) {
            uVar13 = *(uint *)(uVar25 + 0x18) - iVar14;
          }
          puVar12 = (undefined4 *)(*(int *)(uVar25 + 0x10) + iVar14);
          puVar21 = local_5c;
          if (3 < uVar13) {
            if (((uint)puVar12 & 1) != 0) {
              *(undefined *)puVar12 = *(undefined *)local_5c;
              puVar12 = (undefined4 *)((int)puVar12 + 1);
              puVar21 = (undefined4 *)((int)local_5c + 1);
              uVar13 = uVar13 - 1;
            }
            if (((uint)puVar12 & 2) != 0) {
              *(undefined2 *)puVar12 = *(undefined2 *)puVar21;
              puVar12 = (undefined4 *)((int)puVar12 + 2);
              puVar21 = (undefined4 *)((int)puVar21 + 2);
              uVar13 = uVar13 - 2;
            }
            uVar25 = uVar13 >> 2;
            while (uVar25 != 0) {
              uVar25 = uVar25 - 1;
              *puVar12 = *puVar21;
              puVar21 = puVar21 + (uint)bVar27 * 0x3ffffffe + 1;
              puVar12 = puVar12 + (uint)bVar27 * 0x3ffffffe + 1;
            }
          }
          puVar22 = puVar21;
          puVar24 = puVar12;
          if ((uVar13 & 2) != 0) {
            puVar24 = (undefined4 *)((int)puVar12 + (uint)bVar27 * -4 + 2);
            puVar22 = (undefined4 *)((int)puVar21 + (uint)bVar27 * -4 + 2);
            *(undefined2 *)puVar12 = *(undefined2 *)puVar21;
          }
          if ((uVar13 & 1) != 0) {
            *(undefined *)puVar24 = *(undefined *)puVar22;
          }
        }
        if ((*(byte *)((int)puVar5 + 0x11) & 2) != 0) {
          uVar13 = FUN_00012b55(puVar5[6],local_5c,uVar20);
          puVar5[6] = uVar13;
        }
        local_74 = local_74 - uVar20;
        local_5c = (undefined4 *)((int)local_5c + uVar20);
        puVar5[0x10] = puVar5[0x10] - uVar20;
      }
      if (puVar5[0x10] != 0) break;
    }
    puVar5[0x10] = 0;
    *puVar5 = 6;
switchD_000173ee_caseD_6:
    uVar13 = local_74;
    if ((*(byte *)((int)puVar5 + 0x11) & 8) == 0) {
      if (puVar5[8] != 0) {
        *(undefined4 *)(puVar5[8] + 0x1c) = 0;
      }
    }
    else {
      if (local_74 == 0) break;
      uVar20 = 0;
      while( true ) {
        uVar25 = uVar20 + 1;
        cVar3 = *(char *)((int)local_5c + uVar20);
        uVar20 = puVar5[8];
        if (((uVar20 != 0) && (iVar14 = *(int *)(uVar20 + 0x1c), iVar14 != 0)) &&
           (uVar26 = puVar5[0x10], uVar26 < *(uint *)(uVar20 + 0x20))) {
          puVar5[0x10] = uVar26 + 1;
          *(char *)(iVar14 + uVar26) = cVar3;
        }
        if (cVar3 == '\0') break;
        uVar20 = uVar25;
        if (uVar25 == local_74) {
          if ((*(byte *)((int)puVar5 + 0x11) & 2) == 0) {
            local_74 = 0;
            local_5c = (undefined4 *)((int)local_5c + uVar13);
          }
          else {
            uVar20 = FUN_00012b55(puVar5[6],local_5c,local_74);
            puVar5[6] = uVar20;
            local_74 = 0;
            local_5c = (undefined4 *)((int)local_5c + uVar13);
          }
          goto LAB_00018f18;
        }
      }
      if ((*(byte *)((int)puVar5 + 0x11) & 2) == 0) {
        local_74 = local_74 - uVar25;
        local_5c = (undefined4 *)((int)local_5c + uVar25);
      }
      else {
        uVar13 = FUN_00012b55(puVar5[6],local_5c,uVar25);
        puVar5[6] = uVar13;
        local_74 = local_74 - uVar25;
        local_5c = (undefined4 *)((int)local_5c + uVar25);
      }
    }
    puVar5[0x10] = 0;
    *puVar5 = 7;
switchD_000173ee_caseD_7:
    uVar13 = local_74;
    if ((*(byte *)((int)puVar5 + 0x11) & 0x10) == 0) {
      if (puVar5[8] != 0) {
        *(undefined4 *)(puVar5[8] + 0x24) = 0;
      }
    }
    else {
      if (local_74 == 0) break;
      uVar20 = 0;
      while( true ) {
        uVar25 = uVar20 + 1;
        cVar3 = *(char *)((int)local_5c + uVar20);
        uVar20 = puVar5[8];
        if (((uVar20 != 0) && (iVar14 = *(int *)(uVar20 + 0x24), iVar14 != 0)) &&
           (uVar26 = puVar5[0x10], uVar26 < *(uint *)(uVar20 + 0x28))) {
          puVar5[0x10] = uVar26 + 1;
          *(char *)(iVar14 + uVar26) = cVar3;
        }
        if (cVar3 == '\0') break;
        uVar20 = uVar25;
        if (uVar25 == local_74) {
          if ((*(byte *)((int)puVar5 + 0x11) & 2) == 0) {
            local_74 = 0;
            local_5c = (undefined4 *)((int)local_5c + uVar13);
          }
          else {
            uVar20 = FUN_00012b55(puVar5[6],local_5c,local_74);
            puVar5[6] = uVar20;
            local_74 = 0;
            local_5c = (undefined4 *)((int)local_5c + uVar13);
          }
          goto LAB_00018f18;
        }
      }
      if ((*(byte *)((int)puVar5 + 0x11) & 2) == 0) {
        local_74 = local_74 - uVar25;
        local_5c = (undefined4 *)((int)local_5c + uVar25);
      }
      else {
        uVar13 = FUN_00012b55(puVar5[6],local_5c,uVar25);
        puVar5[6] = uVar13;
        local_74 = local_74 - uVar25;
        local_5c = (undefined4 *)((int)local_5c + uVar25);
      }
    }
    *puVar5 = 8;
switchD_000173ee_caseD_8:
    if ((puVar5[4] & 0x200) != 0) {
      while (uVar15 < 0x10) {
        if (local_74 == 0) goto LAB_00018f18;
        local_74 = local_74 - 1;
        local_70 = local_70 + ((uint)*(byte *)local_5c << ((byte)uVar15 & 0x1f));
        uVar15 = uVar15 + 8;
        local_5c = (undefined4 *)((int)local_5c + 1);
      }
      if ((uint)*(ushort *)(puVar5 + 6) != local_70) {
        param_1[6] = 0x1e097;
        *puVar5 = 0x1b;
        goto LAB_000173e3;
      }
      uVar15 = 0;
      local_70 = 0;
    }
    if (puVar5[8] != 0) {
      *(uint *)(puVar5[8] + 0x2c) = (int)puVar5[4] >> 9 & 1;
      *(undefined4 *)(puVar5[8] + 0x30) = 1;
    }
    uVar13 = FUN_00012b55(0,0,0);
    puVar5[6] = uVar13;
    param_1[0xc] = uVar13;
    *puVar5 = 0xb;
    goto LAB_000173e3;
  case 6:
    goto switchD_000173ee_caseD_6;
  case 7:
    goto switchD_000173ee_caseD_7;
  case 8:
    goto switchD_000173ee_caseD_8;
  case 9:
    while (uVar15 < 0x20) {
      if (local_74 == 0) goto LAB_00018f18;
      local_74 = local_74 - 1;
      local_70 = local_70 + ((uint)*(byte *)local_5c << ((byte)uVar15 & 0x1f));
      uVar15 = uVar15 + 8;
      local_5c = (undefined4 *)((int)local_5c + 1);
    }
    uVar15 = (local_70 & 0xff00) * 0x100 +
             local_70 * 0x1000000 + (local_70 >> 0x18) + (local_70 >> 8 & 0xff00);
    puVar5[6] = uVar15;
    param_1[0xc] = uVar15;
    *puVar5 = 10;
    uVar15 = 0;
    local_70 = 0;
  case 10:
    if (puVar5[3] == 0) {
      *(undefined4 **)(param_1 + 3) = local_64;
      param_1[4] = local_68;
      *(undefined4 **)param_1 = local_5c;
      param_1[1] = local_74;
      puVar5[0xe] = local_70;
      puVar5[0xf] = uVar15;
      return 2;
    }
    uVar13 = FUN_00012690(0,0,0);
    puVar5[6] = uVar13;
    param_1[0xc] = uVar13;
    *puVar5 = 0xb;
switchD_000173ee_caseD_b:
    if (param_2 != 5) {
switchD_000173ee_caseD_c:
      if (puVar5[1] == 0) {
        while (uVar15 < 3) {
          if (local_74 == 0) goto LAB_00018f18;
          local_74 = local_74 - 1;
          local_70 = local_70 + ((uint)*(byte *)local_5c << ((byte)uVar15 & 0x1f));
          uVar15 = uVar15 + 8;
          local_5c = (undefined4 *)((int)local_5c + 1);
        }
        puVar5[1] = local_70 & 1;
        uVar13 = local_70 >> 1 & 3;
        if (uVar13 == 1) {
          puVar5[0x13] = 0x1e2c0;
          puVar5[0x15] = 9;
          puVar5[0x14] = 0x1e240;
          puVar5[0x16] = 5;
          *puVar5 = 0x12;
        }
        else {
          if (uVar13 == 0) {
            *puVar5 = 0xd;
          }
          else {
            if (uVar13 == 2) {
              *puVar5 = 0xf;
            }
            else {
              if (uVar13 == 3) {
                param_1[6] = 0x1e0ab;
                *puVar5 = 0x1b;
              }
            }
          }
        }
        local_70 = local_70 >> 3;
        uVar15 = uVar15 - 3;
      }
      else {
        local_70 = local_70 >> ((byte)uVar15 & 7);
        uVar15 = uVar15 & 0xfffffff8;
        *puVar5 = 0x18;
      }
      goto LAB_000173e3;
    }
    break;
  case 0xb:
    goto switchD_000173ee_caseD_b;
  case 0xc:
    goto switchD_000173ee_caseD_c;
  case 0xd:
    local_70 = local_70 >> ((byte)uVar15 & 7);
    uVar15 = uVar15 & 0xfffffff8;
    while (uVar15 < 0x20) {
      if (local_74 == 0) goto LAB_00018f18;
      local_74 = local_74 - 1;
      local_70 = local_70 + ((uint)*(byte *)local_5c << ((byte)uVar15 & 0x1f));
      uVar15 = uVar15 + 8;
      local_5c = (undefined4 *)((int)local_5c + 1);
    }
    if ((local_70 & 0xffff) == (local_70 >> 0x10 ^ 0xffff)) {
      puVar5[0x10] = local_70 & 0xffff;
      *puVar5 = 0xe;
      uVar15 = 0;
      local_70 = 0;
      goto switchD_000173ee_caseD_e;
    }
    param_1[6] = 0x1e0be;
    *puVar5 = 0x1b;
    goto LAB_000173e3;
  case 0xe:
switchD_000173ee_caseD_e:
    uVar13 = puVar5[0x10];
    if (uVar13 == 0) {
      *puVar5 = 0xb;
      goto LAB_000173e3;
    }
    if (local_68 <= uVar13) {
      uVar13 = local_68;
    }
    if (local_74 < uVar13) {
      uVar13 = local_74;
    }
    if (uVar13 != 0) {
      uVar20 = uVar13;
      puVar21 = local_5c;
      puVar12 = local_64;
      if (3 < uVar13) {
        if (((uint)local_64 & 1) != 0) {
          *(undefined *)local_64 = *(undefined *)local_5c;
          puVar12 = (undefined4 *)((int)local_64 + 1);
          puVar21 = (undefined4 *)((int)local_5c + 1);
          uVar20 = uVar13 - 1;
        }
        if (((uint)puVar12 & 2) != 0) {
          *(undefined2 *)puVar12 = *(undefined2 *)puVar21;
          puVar12 = (undefined4 *)((int)puVar12 + 2);
          puVar21 = (undefined4 *)((int)puVar21 + 2);
          uVar20 = uVar20 - 2;
        }
        uVar25 = uVar20 >> 2;
        while (uVar25 != 0) {
          uVar25 = uVar25 - 1;
          *puVar12 = *puVar21;
          puVar21 = puVar21 + (uint)bVar27 * 0x3ffffffe + 1;
          puVar12 = puVar12 + (uint)bVar27 * 0x3ffffffe + 1;
        }
      }
      puVar22 = puVar21;
      puVar24 = puVar12;
      if ((uVar20 & 2) != 0) {
        puVar24 = (undefined4 *)((int)puVar12 + (uint)bVar27 * -4 + 2);
        puVar22 = (undefined4 *)((int)puVar21 + (uint)bVar27 * -4 + 2);
        *(undefined2 *)puVar12 = *(undefined2 *)puVar21;
      }
      if ((uVar20 & 1) != 0) {
        *(undefined *)puVar24 = *(undefined *)puVar22;
      }
      local_74 = local_74 - uVar13;
      local_5c = (undefined4 *)((int)local_5c + uVar13);
      local_68 = local_68 - uVar13;
      puVar5[0x10] = puVar5[0x10] - uVar13;
      local_64 = (undefined4 *)((int)local_64 + uVar13);
      goto LAB_000173e3;
    }
    break;
  case 0xf:
    while (uVar15 < 0xe) {
      if (local_74 == 0) goto LAB_00018f18;
      local_74 = local_74 - 1;
      local_70 = local_70 + ((uint)*(byte *)local_5c << ((byte)uVar15 & 0x1f));
      uVar15 = uVar15 + 8;
      local_5c = (undefined4 *)((int)local_5c + 1);
    }
    uVar20 = (local_70 & 0x1f) + 0x101;
    puVar5[0x18] = uVar20;
    uVar13 = (local_70 >> 5 & 0x1f) + 1;
    puVar5[0x19] = uVar13;
    puVar5[0x17] = (local_70 >> 10 & 0xf) + 4;
    local_70 = local_70 >> 0xe;
    uVar15 = uVar15 - 0xe;
    if ((uVar20 < 0x11f) && (uVar13 < 0x1f)) {
      puVar5[0x1a] = 0;
      *puVar5 = 0x10;
      goto switchD_000173ee_caseD_10;
    }
    param_1[6] = 0x1e16c;
    *puVar5 = 0x1b;
    goto LAB_000173e3;
  case 0x10:
switchD_000173ee_caseD_10:
    uVar13 = puVar5[0x1a];
    if (uVar13 < puVar5[0x17]) {
      do {
        while (uVar15 < 3) {
          if (local_74 == 0) goto LAB_00018f18;
          local_74 = local_74 - 1;
          local_70 = local_70 + ((uint)*(byte *)local_5c << ((byte)uVar15 & 0x1f));
          uVar15 = uVar15 + 8;
          local_5c = (undefined4 *)((int)local_5c + 1);
        }
        puVar5[0x1a] = uVar13 + 1;
        *(ushort *)((int)puVar5 + (uint)*(ushort *)(&DAT_0001eac0 + uVar13 * 2) * 2 + 0x70) =
             (ushort)local_70 & 7;
        local_70 = local_70 >> 3;
        uVar15 = uVar15 - 3;
        uVar13 = puVar5[0x1a];
      } while (uVar13 < puVar5[0x17]);
    }
    if (puVar5[0x1a] < 0x13) {
      puVar9 = (ushort *)(&DAT_0001eac0 + puVar5[0x1a] * 2);
      do {
        *(undefined2 *)((int)puVar5 + (uint)*puVar9 * 2 + 0x70) = 0;
        puVar9 = puVar9 + 1;
      } while (puVar9 != (ushort *)&DAT_0001eae6);
      puVar5[0x1a] = 0x13;
    }
    *(uint **)(puVar5 + 0x1b) = puVar1;
    *(uint **)(puVar5 + 0x13) = puVar1;
    puVar5[0x15] = 7;
    local_60 = FUN_000197f0(0,puVar5 + 0x1c,0x13,puVar5 + 0x1b,puVar5 + 0x15,puVar8);
    if (local_60 != 0) {
      param_1[6] = 0x1e0db;
      *puVar5 = 0x1b;
      goto LAB_000173e3;
    }
    puVar5[0x1a] = 0;
    *puVar5 = 0x11;
switchD_000173ee_caseD_11:
    uVar13 = puVar5[0x18];
    uVar20 = puVar5[0x19];
    while (uVar25 = puVar5[0x1a], uVar25 < uVar13 + uVar20) {
      uVar26 = (1 << ((byte)puVar5[0x15] & 0x1f)) - 1;
      iVar14 = puVar5[0x13] + (uVar26 & local_70) * 4;
      bVar17 = *(byte *)(iVar14 + 1);
      uVar19 = *(ushort *)(iVar14 + 2);
      uVar11 = (uint)bVar17;
      if (uVar15 < uVar11) {
        do {
          if (local_74 == 0) goto LAB_00018f18;
          local_74 = local_74 - 1;
          puVar12 = (undefined4 *)((int)local_5c + 1);
          local_70 = local_70 + ((uint)*(byte *)local_5c << ((byte)uVar15 & 0x1f));
          uVar15 = uVar15 + 8;
          iVar14 = puVar5[0x13] + (uVar26 & local_70) * 4;
          bVar17 = *(byte *)(iVar14 + 1);
          uVar19 = *(ushort *)(iVar14 + 2);
          uVar11 = (uint)bVar17;
          local_5c = puVar12;
        } while (uVar15 < uVar11);
      }
      if (uVar19 < 0x10) {
        local_70 = local_70 >> (bVar17 & 0x1f);
        uVar15 = uVar15 - uVar11;
        puVar5[0x1a] = uVar25 + 1;
        *(ushort *)((int)puVar5 + uVar25 * 2 + 0x70) = uVar19;
      }
      else {
        if (uVar19 == 0x10) {
          while (uVar15 < (uint)bVar17 + 2) {
            if (local_74 == 0) goto LAB_00018f18;
            local_74 = local_74 - 1;
            local_70 = local_70 + ((uint)*(byte *)local_5c << ((byte)uVar15 & 0x1f));
            uVar15 = uVar15 + 8;
            local_5c = (undefined4 *)((int)local_5c + 1);
          }
          local_70 = local_70 >> (bVar17 & 0x1f);
          uVar15 = uVar15 - uVar11;
          if (uVar25 == 0) {
            param_1[6] = 0x1e0f4;
            *puVar5 = 0x1b;
            goto LAB_000173e3;
          }
          uVar18 = *(undefined2 *)((int)puVar5 + (uVar25 + 0x37) * 2);
          iVar14 = (local_70 & 3) + 3;
          local_70 = local_70 >> 2;
          uVar15 = uVar15 - 2;
        }
        else {
          if (uVar19 == 0x11) {
            while (uVar15 < (uint)bVar17 + 3) {
              if (local_74 == 0) goto LAB_00018f18;
              local_74 = local_74 - 1;
              local_70 = local_70 + ((uint)*(byte *)local_5c << ((byte)uVar15 & 0x1f));
              uVar15 = uVar15 + 8;
              local_5c = (undefined4 *)((int)local_5c + 1);
            }
            local_70 = local_70 >> (bVar17 & 0x1f);
            iVar14 = (local_70 & 7) + 3;
            local_70 = local_70 >> 3;
            uVar15 = uVar15 + (-3 - uVar11);
            uVar18 = 0;
          }
          else {
            while (uVar15 < (uint)bVar17 + 7) {
              if (local_74 == 0) goto LAB_00018f18;
              local_74 = local_74 - 1;
              local_70 = local_70 + ((uint)*(byte *)local_5c << ((byte)uVar15 & 0x1f));
              uVar15 = uVar15 + 8;
              local_5c = (undefined4 *)((int)local_5c + 1);
            }
            local_70 = local_70 >> (bVar17 & 0x1f);
            iVar14 = (local_70 & 0x7f) + 0xb;
            local_70 = local_70 >> 7;
            uVar15 = (uVar15 - uVar11) - 7;
            uVar18 = 0;
          }
        }
        if (uVar13 + uVar20 < uVar25 + iVar14) {
          param_1[6] = 0x1e0f4;
          *puVar5 = 0x1b;
          goto LAB_000173e3;
        }
        if (iVar14 != 0) {
          puVar10 = (uint *)((int)puVar5 + (uVar25 + 0x38) * 2);
          do {
            *(undefined2 *)puVar10 = uVar18;
            puVar10 = (uint *)((int)puVar10 + 2);
          } while (puVar10 != (uint *)((int)puVar5 + (iVar14 + uVar25 + 0x38) * 2));
          puVar5[0x1a] = uVar25 + iVar14;
        }
      }
    }
    if (*puVar5 == 0x1b) goto LAB_000173e3;
    *(uint **)(puVar5 + 0x1b) = puVar1;
    *(uint **)(puVar5 + 0x13) = puVar1;
    puVar5[0x15] = 9;
    local_60 = FUN_000197f0(1,puVar5 + 0x1c,puVar5[0x18],puVar5 + 0x1b,puVar5 + 0x15,puVar8);
    if (local_60 != 0) {
      param_1[6] = 0x1e10e;
      *puVar5 = 0x1b;
      goto LAB_000173e3;
    }
    puVar5[0x14] = puVar5[0x1b];
    puVar5[0x16] = 6;
    local_60 = FUN_000197f0(2,puVar5[0x18] * 2 + 0x70 + (int)puVar5,puVar5[0x19],puVar5 + 0x1b,
                            puVar5 + 0x16,puVar8);
    if (local_60 != 0) {
      param_1[6] = 0x1e12a;
      *puVar5 = 0x1b;
      goto LAB_000173e3;
    }
    *puVar5 = 0x12;
    puVar12 = local_5c;
switchD_000173ee_caseD_12:
    if ((5 < local_74) && (0x101 < local_68)) {
      *(undefined4 **)(param_1 + 3) = local_64;
      param_1[4] = local_68;
      *(undefined4 **)param_1 = puVar12;
      param_1[1] = local_74;
      puVar5[0xe] = local_70;
      puVar5[0xf] = uVar15;
      FUN_000168b0(param_1,local_6c);
      local_68 = param_1[4];
      local_5c = (undefined4 *)*param_1;
      local_74 = param_1[1];
      local_70 = puVar5[0xe];
      uVar15 = puVar5[0xf];
      local_64 = (undefined4 *)param_1[3];
      goto LAB_000173e3;
    }
    uVar13 = puVar5[0x13];
    uVar25 = (1 << ((byte)puVar5[0x15] & 0x1f)) - 1;
    pbVar2 = (byte *)(uVar13 + (local_70 & uVar25) * 4);
    bVar4 = *pbVar2;
    bVar17 = pbVar2[1];
    uVar19 = *(ushort *)(pbVar2 + 2);
    uVar20 = (uint)bVar17;
    local_5c = puVar12;
    if (uVar15 < uVar20) {
      do {
        if (local_74 == 0) goto LAB_00018f18;
        local_74 = local_74 - 1;
        puVar12 = (undefined4 *)((int)local_5c + 1);
        local_70 = local_70 + ((uint)*(byte *)local_5c << ((byte)uVar15 & 0x1f));
        uVar15 = uVar15 + 8;
        pbVar2 = (byte *)(uVar13 + (uVar25 & local_70) * 4);
        bVar4 = *pbVar2;
        bVar17 = pbVar2[1];
        uVar19 = *(ushort *)(pbVar2 + 2);
        uVar20 = (uint)bVar17;
        local_5c = puVar12;
      } while (uVar15 < uVar20);
    }
    uVar25 = (uint)uVar19;
    if (bVar4 == 0) {
      local_70 = local_70 >> (bVar17 & 0x1f);
      uVar15 = uVar15 - bVar17;
      puVar5[0x10] = uVar25;
LAB_000187d0:
      *puVar5 = 0x17;
      local_5c = puVar12;
      goto LAB_000173e3;
    }
    if ((bVar4 & 0xf0) == 0) {
      uVar26 = (1 << (bVar4 + bVar17 & 0x1f)) - 1;
      pbVar2 = (byte *)(uVar13 + (uVar25 + ((uVar26 & local_70) >> (bVar17 & 0x1f))) * 4);
      bVar4 = *pbVar2;
      bVar7 = pbVar2[1];
      uVar19 = *(ushort *)(pbVar2 + 2);
      local_5c = puVar12;
      if (uVar15 < (uint)bVar7 + (uint)bVar17) {
        do {
          if (local_74 == 0) goto LAB_00018f18;
          local_74 = local_74 - 1;
          puVar12 = (undefined4 *)((int)local_5c + 1);
          local_70 = local_70 + ((uint)*(byte *)local_5c << ((byte)uVar15 & 0x1f));
          uVar15 = uVar15 + 8;
          pbVar2 = (byte *)(uVar13 + (((uVar26 & local_70) >> (bVar17 & 0x1f)) + uVar25) * 4);
          bVar4 = *pbVar2;
          bVar7 = pbVar2[1];
          uVar19 = *(ushort *)(pbVar2 + 2);
          local_5c = puVar12;
        } while (uVar15 < (uint)bVar7 + (uint)bVar17);
      }
      local_70 = (local_70 >> (bVar17 & 0x1f)) >> (bVar7 & 0x1f);
      uVar15 = (uVar15 - uVar20) - (uint)bVar7;
      puVar5[0x10] = (uint)uVar19;
      if (bVar4 == 0) goto LAB_000187d0;
    }
    else {
      local_70 = local_70 >> (bVar17 & 0x1f);
      uVar15 = uVar15 - bVar17;
      puVar5[0x10] = uVar25;
    }
    local_5c = (undefined4 *)(uint)bVar4;
    if ((bVar4 & 0x20) != 0) {
      *puVar5 = 0xb;
      local_5c = puVar12;
      goto LAB_000173e3;
    }
    if ((bVar4 & 0x40) != 0) {
      param_1[6] = 0x1e01c;
      *puVar5 = 0x1b;
      local_5c = puVar12;
      goto LAB_000173e3;
    }
    puVar5[0x12] = (uint)local_5c & 0xf;
    *puVar5 = 0x13;
switchD_000173ee_caseD_13:
    uVar13 = puVar5[0x12];
    local_5c = puVar12;
    if (uVar13 != 0) {
      while (uVar15 < uVar13) {
        if (local_74 == 0) goto LAB_00018f18;
        local_74 = local_74 - 1;
        local_70 = local_70 + ((uint)*(byte *)local_5c << ((byte)uVar15 & 0x1f));
        uVar15 = uVar15 + 8;
        local_5c = (undefined4 *)((int)local_5c + 1);
      }
      puVar5[0x10] = puVar5[0x10] + ((1 << ((byte)uVar13 & 0x1f)) - 1U & local_70);
      local_70 = local_70 >> ((byte)uVar13 & 0x1f);
      uVar15 = uVar15 - uVar13;
    }
    *puVar5 = 0x14;
    puVar12 = local_5c;
switchD_000173ee_caseD_14:
    uVar13 = puVar5[0x14];
    uVar25 = (1 << ((byte)puVar5[0x16] & 0x1f)) - 1;
    pbVar2 = (byte *)(uVar13 + (local_70 & uVar25) * 4);
    bVar4 = *pbVar2;
    bVar17 = pbVar2[1];
    uVar19 = *(ushort *)(pbVar2 + 2);
    uVar20 = (uint)bVar17;
    local_5c = puVar12;
    if (uVar15 < uVar20) {
      do {
        if (local_74 == 0) goto LAB_00018f18;
        local_74 = local_74 - 1;
        puVar12 = (undefined4 *)((int)local_5c + 1);
        local_70 = local_70 + ((uint)*(byte *)local_5c << ((byte)uVar15 & 0x1f));
        uVar15 = uVar15 + 8;
        pbVar2 = (byte *)(uVar13 + (uVar25 & local_70) * 4);
        bVar4 = *pbVar2;
        bVar17 = pbVar2[1];
        uVar19 = *(ushort *)(pbVar2 + 2);
        uVar20 = (uint)bVar17;
        local_5c = puVar12;
      } while (uVar15 < uVar20);
    }
    bVar7 = bVar17;
    if ((bVar4 & 0xf0) == 0) {
      uVar26 = (uint)uVar19;
      uVar25 = (1 << (bVar4 + bVar17 & 0x1f)) - 1;
      pbVar2 = (byte *)(uVar13 + (uVar26 + ((uVar25 & local_70) >> (bVar17 & 0x1f))) * 4);
      bVar4 = *pbVar2;
      bVar7 = pbVar2[1];
      uVar19 = *(ushort *)(pbVar2 + 2);
      local_5c = puVar12;
      if (uVar15 < (uint)bVar7 + (uint)bVar17) {
        do {
          if (local_74 == 0) goto LAB_00018f18;
          local_74 = local_74 - 1;
          puVar12 = (undefined4 *)((int)local_5c + 1);
          local_70 = local_70 + ((uint)*(byte *)local_5c << ((byte)uVar15 & 0x1f));
          uVar15 = uVar15 + 8;
          pbVar2 = (byte *)(uVar13 + (((uVar25 & local_70) >> (bVar17 & 0x1f)) + uVar26) * 4);
          bVar4 = *pbVar2;
          bVar7 = pbVar2[1];
          uVar19 = *(ushort *)(pbVar2 + 2);
          local_5c = puVar12;
        } while (uVar15 < (uint)bVar7 + (uint)bVar17);
      }
      local_70 = local_70 >> (bVar17 & 0x1f);
      uVar15 = uVar15 - uVar20;
    }
    local_5c = (undefined4 *)(uint)bVar4;
    local_70 = local_70 >> (bVar7 & 0x1f);
    uVar15 = uVar15 - bVar7;
    if ((bVar4 & 0x40) != 0) {
      param_1[6] = 0x1e006;
      *puVar5 = 0x1b;
      local_5c = puVar12;
      goto LAB_000173e3;
    }
    puVar5[0x11] = (uint)uVar19;
    puVar5[0x12] = (uint)local_5c & 0xf;
    *puVar5 = 0x15;
switchD_000173ee_caseD_15:
    uVar13 = puVar5[0x12];
    local_5c = puVar12;
    if (uVar13 != 0) {
      while (uVar15 < uVar13) {
        if (local_74 == 0) goto LAB_00018f18;
        local_74 = local_74 - 1;
        local_70 = local_70 + ((uint)*(byte *)local_5c << ((byte)uVar15 & 0x1f));
        uVar15 = uVar15 + 8;
        local_5c = (undefined4 *)((int)local_5c + 1);
      }
      puVar5[0x11] = puVar5[0x11] + ((1 << ((byte)uVar13 & 0x1f)) - 1U & local_70);
      local_70 = local_70 >> ((byte)uVar13 & 0x1f);
      uVar15 = uVar15 - uVar13;
    }
    uVar13 = (local_6c + puVar5[0xb]) - local_68;
    if (uVar13 <= puVar5[0x11] && puVar5[0x11] != uVar13) {
      param_1[6] = 0x1dfe8;
      *puVar5 = 0x1b;
      goto LAB_000173e3;
    }
    *puVar5 = 0x16;
switchD_000173ee_caseD_16:
    if (local_68 != 0) {
      uVar13 = puVar5[0x11];
      if (local_6c - local_68 < uVar13) {
        uVar13 = uVar13 - (local_6c - local_68);
        uVar20 = puVar5[0xc];
        if (uVar20 < uVar13) {
          uVar13 = uVar13 - uVar20;
          puVar12 = (undefined4 *)((puVar5[10] - uVar13) + puVar5[0xd]);
        }
        else {
          puVar12 = (undefined4 *)((uVar20 - uVar13) + puVar5[0xd]);
        }
        if (puVar5[0x10] < uVar13) {
          uVar13 = puVar5[0x10];
        }
      }
      else {
        puVar12 = (undefined4 *)((int)local_64 - uVar13);
        uVar13 = puVar5[0x10];
      }
      if (local_68 < uVar13) {
        uVar13 = local_68;
      }
      local_68 = local_68 - uVar13;
      puVar5[0x10] = puVar5[0x10] - uVar13;
      puVar21 = (undefined4 *)(uVar13 + (int)local_64);
      do {
        puVar22 = (undefined4 *)((int)local_64 + 1);
        *(undefined *)local_64 = *(undefined *)puVar12;
        puVar12 = (undefined4 *)((int)puVar12 + 1);
        local_64 = puVar22;
      } while (puVar22 != puVar21);
      local_64 = puVar21;
      if (puVar5[0x10] == 0) {
        *puVar5 = 0x12;
      }
      goto LAB_000173e3;
    }
    break;
  case 0x11:
    goto switchD_000173ee_caseD_11;
  case 0x12:
    goto switchD_000173ee_caseD_12;
  case 0x13:
    goto switchD_000173ee_caseD_13;
  case 0x14:
    goto switchD_000173ee_caseD_14;
  case 0x15:
    goto switchD_000173ee_caseD_15;
  case 0x16:
    goto switchD_000173ee_caseD_16;
  case 0x17:
    if (local_68 != 0) {
      *(char *)local_64 = (char)puVar5[0x10];
      local_68 = local_68 - 1;
      *puVar5 = 0x12;
      local_64 = (undefined4 *)((int)local_64 + 1);
      goto LAB_000173e3;
    }
    break;
  case 0x18:
    if (puVar5[2] == 0) {
LAB_00018d2f:
      *puVar5 = 0x19;
      goto switchD_000173ee_caseD_19;
    }
    while (uVar15 < 0x20) {
      if (local_74 == 0) goto LAB_00018f18;
      local_74 = local_74 - 1;
      local_70 = local_70 + ((uint)*(byte *)local_5c << ((byte)uVar15 & 0x1f));
      uVar15 = uVar15 + 8;
      local_5c = (undefined4 *)((int)local_5c + 1);
    }
    iVar14 = local_6c - local_68;
    param_1[5] = param_1[5] + iVar14;
    puVar5[7] = puVar5[7] + iVar14;
    if (iVar14 != 0) {
      if (puVar5[4] == 0) {
        uVar13 = FUN_00012690(puVar5[6],(undefined4 *)((int)local_64 - iVar14),iVar14);
      }
      else {
        uVar13 = FUN_00012b55(puVar5[6],(undefined4 *)((int)local_64 - iVar14),iVar14);
      }
      puVar5[6] = uVar13;
      param_1[0xc] = uVar13;
    }
    uVar13 = local_70;
    if (puVar5[4] == 0) {
      uVar13 = (local_70 & 0xff00) * 0x100 +
               local_70 * 0x1000000 + (local_70 >> 0x18) + (local_70 >> 8 & 0xff00);
    }
    if (uVar13 == puVar5[6]) {
      local_6c = local_68;
      uVar15 = 0;
      local_70 = 0;
      goto LAB_00018d2f;
    }
    param_1[6] = 0x1e140;
    *puVar5 = 0x1b;
    local_6c = local_68;
    goto LAB_000173e3;
  case 0x19:
switchD_000173ee_caseD_19:
    if ((puVar5[2] != 0) && (puVar5[4] != 0)) {
      while (uVar15 < 0x20) {
        if (local_74 == 0) goto LAB_00018f18;
        local_74 = local_74 - 1;
        local_70 = local_70 + ((uint)*(byte *)local_5c << ((byte)uVar15 & 0x1f));
        uVar15 = uVar15 + 8;
        local_5c = (undefined4 *)((int)local_5c + 1);
      }
      if (puVar5[7] != local_70) {
        param_1[6] = 0x1e155;
        *puVar5 = 0x1b;
        goto LAB_000173e3;
      }
      uVar15 = 0;
      local_70 = 0;
    }
    *puVar5 = 0x1a;
    local_60 = 1;
    break;
  case 0x1a:
    local_60 = 1;
    break;
  case 0x1b:
    local_60 = -3;
    break;
  case 0x1c:
    return 0xfffffffc;
  }
LAB_00018f18:
  *(undefined4 **)(param_1 + 3) = local_64;
  param_1[4] = local_68;
  *(undefined4 **)param_1 = local_5c;
  param_1[1] = local_74;
  puVar5[0xe] = local_70;
  puVar5[0xf] = uVar15;
  if (puVar5[10] == 0) {
    if (*puVar5 < 0x18) {
      if (param_1[4] == local_6c) {
        iVar23 = uVar6 - param_1[1];
        param_1[2] = param_1[2] + iVar23;
        iVar14 = 0;
        goto LAB_0001901e;
      }
      goto LAB_00018f63;
    }
  }
  else {
LAB_00018f63:
    iVar14 = FUN_00016f08();
    if (iVar14 != 0) {
      *puVar5 = 0x1c;
      return 0xfffffffc;
    }
  }
  iVar23 = uVar6 - param_1[1];
  iVar14 = local_6c - param_1[4];
  param_1[2] = param_1[2] + iVar23;
  param_1[5] = param_1[5] + iVar14;
  puVar5[7] = puVar5[7] + iVar14;
  if ((puVar5[2] != 0) && (iVar14 != 0)) {
    if (puVar5[4] == 0) {
      uVar15 = FUN_00012690(puVar5[6],param_1[3] - iVar14,iVar14);
    }
    else {
      uVar15 = FUN_00012b55(puVar5[6],param_1[3] - iVar14,iVar14);
    }
    puVar5[6] = uVar15;
    param_1[0xc] = uVar15;
  }
LAB_0001901e:
  iVar16 = 0;
  if (*puVar5 == 0xb) {
    iVar16 = 0x80;
  }
  param_1[0xb] = iVar16 + (~-(uint)(puVar5[1] == 0) & 0x40) + puVar5[0xf];
  if (((iVar23 != 0) || (iVar14 != 0)) && (param_2 != 4)) {
    return local_60;
  }
  if (local_60 != 0) {
    return local_60;
  }
  return 0xfffffffb;
}



undefined4 FUN_00019263(int param_1)

{
  int iVar1;
  undefined4 uVar2;
  
  if (param_1 == 0) {
    uVar2 = 0xfffffffe;
  }
  else {
    if (*(int *)(param_1 + 0x1c) == 0) {
      uVar2 = 0xfffffffe;
    }
    else {
      if (*(code **)(param_1 + 0x24) == (code *)0x0) {
        uVar2 = 0xfffffffe;
      }
      else {
        iVar1 = *(int *)(*(int *)(param_1 + 0x1c) + 0x34);
        if (iVar1 != 0) {
          (**(code **)(param_1 + 0x24))(*(undefined4 *)(param_1 + 0x28),iVar1);
        }
        (**(code **)(param_1 + 0x24))
                  (*(undefined4 *)(param_1 + 0x28),*(undefined4 *)(param_1 + 0x1c));
        *(undefined4 *)(param_1 + 0x1c) = 0;
        uVar2 = 0;
      }
    }
  }
  return uVar2;
}



int FUN_000192c6(int param_1,undefined4 *param_2,uint param_3)

{
  int *piVar1;
  undefined4 uVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  undefined4 *puVar6;
  undefined4 *puVar7;
  undefined4 *puVar8;
  byte bVar9;
  
  bVar9 = 0;
  if (param_1 == 0) {
    return 0xfffffffe;
  }
  piVar1 = *(int **)(param_1 + 0x1c);
  if (piVar1 == (int *)0x0) {
    return 0xfffffffe;
  }
  if (piVar1[2] == 0) {
    if (*piVar1 != 10) goto LAB_0001933b;
  }
  else {
    if (*piVar1 != 10) {
      return 0xfffffffe;
    }
  }
  uVar2 = FUN_00012690(0,0,0);
  iVar3 = FUN_00012690(uVar2,param_2,param_3);
  if (piVar1[6] != iVar3) {
    return 0xfffffffd;
  }
LAB_0001933b:
  iVar3 = FUN_00016f08();
  if (iVar3 == 0) {
    uVar4 = piVar1[10];
    if (uVar4 < param_3) {
      puVar7 = (undefined4 *)piVar1[0xd];
      param_2 = (undefined4 *)((param_3 - uVar4) + (int)param_2);
      if (3 < uVar4) {
        if (((uint)puVar7 & 1) != 0) {
          *(undefined *)puVar7 = *(undefined *)param_2;
          puVar7 = (undefined4 *)((int)puVar7 + 1);
          param_2 = (undefined4 *)((int)param_2 + 1);
          uVar4 = uVar4 - 1;
        }
        if (((uint)puVar7 & 2) != 0) {
          *(undefined2 *)puVar7 = *(undefined2 *)param_2;
          puVar7 = (undefined4 *)((int)puVar7 + 2);
          param_2 = (undefined4 *)((int)param_2 + 2);
          uVar4 = uVar4 - 2;
        }
        uVar5 = uVar4 >> 2;
        while (uVar5 != 0) {
          uVar5 = uVar5 - 1;
          *puVar7 = *param_2;
          param_2 = param_2 + (uint)bVar9 * 0x3ffffffe + 1;
          puVar7 = puVar7 + (uint)bVar9 * 0x3ffffffe + 1;
        }
      }
      puVar6 = param_2;
      puVar8 = puVar7;
      if ((uVar4 & 2) != 0) {
        puVar8 = (undefined4 *)((int)puVar7 + (uint)bVar9 * -4 + 2);
        puVar6 = (undefined4 *)((int)param_2 + (uint)bVar9 * -4 + 2);
        *(undefined2 *)puVar7 = *(undefined2 *)param_2;
      }
      if ((uVar4 & 1) != 0) {
        *(undefined *)puVar8 = *(undefined *)puVar6;
      }
      piVar1[0xb] = piVar1[10];
    }
    else {
      puVar7 = (undefined4 *)((uVar4 - param_3) + piVar1[0xd]);
      uVar4 = param_3;
      if (3 < param_3) {
        if (((uint)puVar7 & 1) != 0) {
          *(undefined *)puVar7 = *(undefined *)param_2;
          puVar7 = (undefined4 *)((int)puVar7 + 1);
          param_2 = (undefined4 *)((int)param_2 + 1);
          uVar4 = param_3 - 1;
        }
        if (((uint)puVar7 & 2) != 0) {
          *(undefined2 *)puVar7 = *(undefined2 *)param_2;
          puVar7 = (undefined4 *)((int)puVar7 + 2);
          param_2 = (undefined4 *)((int)param_2 + 2);
          uVar4 = uVar4 - 2;
        }
        uVar5 = uVar4 >> 2;
        while (uVar5 != 0) {
          uVar5 = uVar5 - 1;
          *puVar7 = *param_2;
          param_2 = param_2 + (uint)bVar9 * 0x3ffffffe + 1;
          puVar7 = puVar7 + (uint)bVar9 * 0x3ffffffe + 1;
        }
      }
      puVar6 = param_2;
      puVar8 = puVar7;
      if ((uVar4 & 2) != 0) {
        puVar8 = (undefined4 *)((int)puVar7 + (uint)bVar9 * -4 + 2);
        puVar6 = (undefined4 *)((int)param_2 + (uint)bVar9 * -4 + 2);
        *(undefined2 *)puVar7 = *(undefined2 *)param_2;
      }
      if ((uVar4 & 1) != 0) {
        *(undefined *)puVar8 = *(undefined *)puVar6;
      }
      piVar1[0xb] = param_3;
    }
    piVar1[3] = 1;
  }
  else {
    *piVar1 = 0x1c;
    iVar3 = -4;
  }
  return iVar3;
}



undefined4 FUN_00019444(int param_1,int param_2)

{
  int iVar1;
  
  if (param_1 == 0) {
    return 0xfffffffe;
  }
  iVar1 = *(int *)(param_1 + 0x1c);
  if (iVar1 != 0) {
    if ((*(byte *)(iVar1 + 8) & 2) != 0) {
      *(int *)(iVar1 + 0x20) = param_2;
      *(undefined4 *)(param_2 + 0x30) = 0;
      return 0;
    }
    return 0xfffffffe;
  }
  return 0xfffffffe;
}



undefined4 FUN_0001947f(int *param_1)

{
  undefined *puVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  undefined *puVar6;
  int iVar7;
  undefined4 uVar8;
  uint uVar9;
  undefined local_14 [4];
  
  if (param_1 == (int *)0x0) {
    uVar8 = 0xfffffffe;
  }
  else {
    piVar2 = (int *)param_1[7];
    if (piVar2 == (int *)0x0) {
      uVar8 = 0xfffffffe;
    }
    else {
      if ((param_1[1] == 0) && ((uint)piVar2[0xf] < 8)) {
        uVar8 = 0xfffffffb;
      }
      else {
        if (*piVar2 != 0x1d) {
          *piVar2 = 0x1d;
          piVar2[0xe] = piVar2[0xe] << ((byte)piVar2[0xf] & 7);
          uVar5 = piVar2[0xf] & 0xfffffff8;
          piVar2[0xf] = uVar5;
          if (7 < uVar5) {
            uVar9 = piVar2[0xe];
            puVar6 = local_14;
            puVar1 = puVar6 + (uVar5 - 8 >> 3) + 1;
            do {
              *puVar6 = (char)uVar9;
              uVar9 = uVar9 >> 8;
              puVar6 = puVar6 + 1;
            } while (puVar6 != puVar1);
            piVar2[0xe] = uVar9;
            piVar2[0xf] = 0;
          }
          piVar2[0x1a] = 0;
          FUN_00016e90();
        }
        iVar7 = FUN_00016e90();
        param_1[1] = param_1[1] - iVar7;
        *param_1 = *param_1 + iVar7;
        iVar3 = param_1[2];
        param_1[2] = iVar7 + iVar3;
        if (piVar2[0x1a] == 4) {
          iVar4 = param_1[5];
          FUN_000170f3(param_1);
          param_1[2] = iVar7 + iVar3;
          param_1[5] = iVar4;
          *piVar2 = 0xb;
          uVar8 = 0;
        }
        else {
          uVar8 = 0xfffffffd;
        }
      }
    }
  }
  return uVar8;
}



uint FUN_00019573(int param_1)

{
  int *piVar1;
  
  if (param_1 == 0) {
    return 0xfffffffe;
  }
  piVar1 = *(int **)(param_1 + 0x1c);
  if (piVar1 != (int *)0x0) {
    if (*piVar1 == 0xd) {
      return (uint)(piVar1[0xf] == 0);
    }
    return 0;
  }
  return 0xfffffffe;
}



undefined4 FUN_000195a4(undefined4 *param_1,undefined4 *param_2)

{
  undefined4 *puVar1;
  uint uVar2;
  undefined4 uVar3;
  uint uVar4;
  undefined4 *puVar5;
  undefined4 *puVar6;
  undefined4 *puVar7;
  undefined4 *puVar8;
  undefined4 *puVar9;
  undefined4 *puVar10;
  bool bVar11;
  byte bVar12;
  
  bVar12 = 0;
  if (param_1 == (undefined4 *)0x0) {
    uVar3 = 0xfffffffe;
  }
  else {
    if (param_2 == (undefined4 *)0x0) {
      uVar3 = 0xfffffffe;
    }
    else {
      puVar10 = (undefined4 *)param_2[7];
      if (puVar10 == (undefined4 *)0x0) {
        uVar3 = 0xfffffffe;
      }
      else {
        if ((code *)param_2[8] == (code *)0x0) {
          uVar3 = 0xfffffffe;
        }
        else {
          if (param_2[9] == 0) {
            uVar3 = 0xfffffffe;
          }
          else {
            puVar1 = (undefined4 *)(*(code *)param_2[8])(param_2[10],1,0x2530);
            if (puVar1 == (undefined4 *)0x0) {
              uVar3 = 0xfffffffc;
            }
            else {
              if (puVar10[0xd] == 0) {
                puVar5 = (undefined4 *)0x0;
              }
              else {
                puVar5 = (undefined4 *)
                         (*(code *)param_2[8])(param_2[10],1 << ((byte)puVar10[9] & 0x1f),1);
                if (puVar5 == (undefined4 *)0x0) {
                  (*(code *)param_2[9])(param_2[10],puVar1);
                  return 0xfffffffc;
                }
              }
              *param_1 = *param_2;
              param_1[1] = param_2[1];
              param_1[2] = param_2[2];
              param_1[3] = param_2[3];
              param_1[4] = param_2[4];
              param_1[5] = param_2[5];
              param_1[6] = param_2[6];
              param_1[7] = param_2[7];
              param_1[8] = param_2[8];
              param_1[9] = param_2[9];
              param_1[10] = param_2[10];
              param_1[0xb] = param_2[0xb];
              param_1[0xc] = param_2[0xc];
              param_1[0xd] = param_2[0xd];
              uVar2 = 0x2530;
              bVar11 = ((uint)puVar1 & 1) != 0;
              puVar8 = puVar10;
              puVar7 = puVar1;
              if (bVar11) {
                *(undefined *)puVar1 = *(undefined *)puVar10;
                puVar7 = (undefined4 *)((int)puVar1 + 1);
                puVar8 = (undefined4 *)((int)puVar10 + 1);
                uVar2 = 0x252f;
              }
              if (((uint)puVar7 & 2) != 0) {
                *(undefined2 *)puVar7 = *(undefined2 *)puVar8;
                puVar7 = (undefined4 *)((int)puVar7 + 2);
                puVar8 = (undefined4 *)((int)puVar8 + 2);
                uVar2 = uVar2 - 2;
              }
              uVar4 = uVar2 >> 2;
              while (uVar4 != 0) {
                uVar4 = uVar4 - 1;
                *puVar7 = *puVar8;
                puVar8 = puVar8 + (uint)bVar12 * 0x3ffffffe + 1;
                puVar7 = puVar7 + (uint)bVar12 * 0x3ffffffe + 1;
              }
              puVar6 = puVar8;
              puVar9 = puVar7;
              if ((uVar2 & 2) != 0) {
                puVar9 = (undefined4 *)((int)puVar7 + (uint)bVar12 * -4 + 2);
                puVar6 = (undefined4 *)((int)puVar8 + (uint)bVar12 * -4 + 2);
                *(undefined2 *)puVar7 = *(undefined2 *)puVar8;
              }
              if (bVar11) {
                *(undefined *)puVar9 = *(undefined *)puVar6;
              }
              puVar8 = (undefined4 *)puVar10[0x13];
              puVar7 = puVar10 + 0x14c;
              if ((puVar7 <= puVar8) && (puVar8 <= puVar10 + 0x94b)) {
                puVar1[0x13] = ((uint)((int)puVar8 - (int)puVar7) & 0xfffffffc) + 0x530 +
                               (int)puVar1;
                puVar1[0x14] = (puVar10[0x14] - (int)puVar7 & 0xfffffffcU) + 0x530 + (int)puVar1;
              }
              puVar1[0x1b] = (puVar10[0x1b] - (int)puVar7 & 0xfffffffcU) + 0x530 + (int)puVar1;
              if (puVar5 != (undefined4 *)0x0) {
                uVar2 = 1 << ((byte)puVar10[9] & 0x1f);
                puVar7 = (undefined4 *)puVar10[0xd];
                puVar10 = puVar5;
                if (3 < uVar2) {
                  if (((uint)puVar5 & 1) != 0) {
                    *(undefined *)puVar5 = *(undefined *)puVar7;
                    puVar10 = (undefined4 *)((int)puVar5 + 1);
                    puVar7 = (undefined4 *)((int)puVar7 + 1);
                    uVar2 = uVar2 - 1;
                  }
                  if (((uint)puVar10 & 2) != 0) {
                    *(undefined2 *)puVar10 = *(undefined2 *)puVar7;
                    puVar10 = (undefined4 *)((int)puVar10 + 2);
                    puVar7 = (undefined4 *)((int)puVar7 + 2);
                    uVar2 = uVar2 - 2;
                  }
                  uVar4 = uVar2 >> 2;
                  while (uVar4 != 0) {
                    uVar4 = uVar4 - 1;
                    *puVar10 = *puVar7;
                    puVar7 = puVar7 + (uint)bVar12 * 0x3ffffffe + 1;
                    puVar10 = puVar10 + (uint)bVar12 * 0x3ffffffe + 1;
                  }
                }
                puVar8 = puVar7;
                puVar6 = puVar10;
                if ((uVar2 & 2) != 0) {
                  puVar6 = (undefined4 *)((int)puVar10 + (uint)bVar12 * -4 + 2);
                  puVar8 = (undefined4 *)((int)puVar7 + (uint)bVar12 * -4 + 2);
                  *(undefined2 *)puVar10 = *(undefined2 *)puVar7;
                }
                if ((uVar2 & 1) != 0) {
                  *(undefined *)puVar6 = *(undefined *)puVar8;
                }
              }
              *(undefined4 **)(puVar1 + 0xd) = puVar5;
              *(undefined4 **)(param_1 + 7) = puVar1;
              uVar3 = 0;
            }
          }
        }
      }
    }
  }
  return uVar3;
}



// WARNING: Could not reconcile some variable overlaps

undefined4
FUN_000197f0(int param_1,ushort *param_2,int param_3,int *param_4,uint *param_5,ushort *param_6)

{
  ushort uVar1;
  uint uVar2;
  ushort *puVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  undefined *puVar7;
  undefined uVar8;
  ushort uVar9;
  uint uVar10;
  int iVar11;
  uint uVar12;
  uint local_98;
  uint local_90;
  uint local_8c;
  uint local_80;
  int local_7c;
  ushort *local_74;
  uint local_70;
  int local_6c;
  uint local_64;
  uint local_60;
  uint local_5c;
  ushort *local_58;
  ushort *local_54;
  ushort auStack80 [16];
  ushort local_30 [16];
  
  local_58 = param_6;
  puVar3 = auStack80 + 0x10;
  do {
    *puVar3 = 0;
    puVar3 = puVar3 + 1;
  } while (puVar3 != (ushort *)&stack0xfffffff0);
  if (param_3 != 0) {
    puVar3 = param_2;
    do {
      auStack80[(uint)*puVar3 + 0x10] = auStack80[(uint)*puVar3 + 0x10] + 1;
      puVar3 = puVar3 + 1;
    } while (puVar3 != param_2 + param_3);
  }
  local_80 = *param_5;
  if (local_30[15] == 0) {
    local_70 = 0xe;
    do {
      if (auStack80[local_70 + 0x10] != 0) goto LAB_00019d81;
      local_70 = local_70 - 1;
    } while (local_70 != 0);
LAB_0001988e:
    puVar7 = (undefined *)*param_4;
    *(undefined **)param_4 = puVar7 + 4;
    *puVar7 = 0x40;
    puVar7[1] = 1;
    *(undefined2 *)(puVar7 + 2) = 0;
    puVar7 = (undefined *)*param_4;
    *(undefined **)param_4 = puVar7 + 4;
    *puVar7 = 0x40;
    puVar7[1] = 1;
    *(undefined2 *)(puVar7 + 2) = 0;
    *param_5 = 1;
    return 0;
  }
  local_70 = 0xf;
LAB_00019d81:
  if (local_70 < local_80) {
    if (local_70 == 0) goto LAB_0001988e;
    if (local_30[1] == 0) {
      local_80 = local_70;
      goto LAB_000198db;
    }
    local_80 = local_70;
    local_90 = 1;
LAB_00019930:
    iVar4 = 2 - (uint)local_30[1];
    if (iVar4 < 0) {
      return 0xffffffff;
    }
  }
  else {
    if (local_30[1] != 0) {
      if (local_80 != 0) {
        local_90 = 1;
        goto LAB_00019930;
      }
      local_90 = 1;
LAB_0001990c:
      local_80 = local_90;
      goto LAB_00019930;
    }
LAB_000198db:
    local_90 = 2;
    do {
      if (auStack80[local_90 + 0x10] != 0) break;
      local_90 = local_90 + 1;
    } while (local_90 != 0x10);
    if (local_80 < local_90) goto LAB_0001990c;
    iVar4 = 2;
  }
  puVar3 = auStack80 + 0x12;
  do {
    iVar4 = iVar4 * 2 - (uint)*puVar3;
    if (iVar4 < 0) {
      return 0xffffffff;
    }
    puVar3 = puVar3 + 1;
  } while ((ushort *)&stack0xfffffff0 != puVar3);
  if (0 < iVar4) {
    if (param_1 == 0) {
      return 0xffffffff;
    }
    if (local_70 != 1) {
      return 0xffffffff;
    }
  }
  auStack80[1] = 0;
  iVar4 = 1;
  do {
    iVar5 = iVar4 + 1;
    auStack80[iVar5] = *(short *)((int)&local_54 + iVar5 * 2 + 2) + auStack80[iVar4 + 0x10];
    iVar4 = iVar5;
  } while (iVar5 != 0xf);
  if (param_3 != 0) {
    iVar4 = 0;
    do {
      uVar9 = param_2[iVar4];
      if (uVar9 != 0) {
        uVar1 = auStack80[uVar9];
        auStack80[uVar9] = uVar1 + 1;
        param_6[uVar1] = (ushort)iVar4;
      }
      iVar4 = iVar4 + 1;
    } while (iVar4 != param_3);
  }
  if (param_1 == 0) {
    local_7c = *param_4;
    local_5c = 1 << ((byte)local_80 & 0x1f);
    local_60 = local_5c - 1;
    local_6c = 0x13;
    local_54 = local_58;
  }
  else {
    if (param_1 == 1) {
      local_7c = *param_4;
      local_5c = 1 << ((byte)local_80 & 0x1f);
      local_60 = local_5c - 1;
      local_6c = 0x100;
      local_58 = (ushort *)&DAT_0001e97e;
      local_54 = (ushort *)&DAT_0001e9be;
    }
    else {
      local_7c = *param_4;
      local_5c = 1 << ((byte)local_80 & 0x1f);
      local_60 = local_5c - 1;
      if (param_1 != 1) {
        local_6c = -1;
        local_58 = (ushort *)&DAT_0001eb00;
        local_54 = (ushort *)&DAT_0001eb40;
        goto LAB_00019a59;
      }
      local_6c = -1;
      local_58 = (ushort *)&DAT_0001eb00;
      local_54 = (ushort *)&DAT_0001eb40;
    }
    if (0x5af < local_5c) {
      return 1;
    }
  }
LAB_00019a59:
  local_74 = param_6;
  local_64 = 0xffffffff;
  local_8c = 0;
  uVar10 = 0;
  uVar12 = local_80;
  do {
    local_98 = (uint)(byte)((char)local_90 - (byte)local_8c);
    uVar9 = *local_74;
    uVar6 = (uint)uVar9;
    if ((int)uVar6 < local_6c) {
      uVar8 = 0;
    }
    else {
      if (local_6c < (int)uVar6) {
        uVar8 = *(undefined *)(local_58 + uVar6);
        uVar9 = local_54[uVar6];
      }
      else {
        uVar9 = 0;
        uVar8 = 0x60;
      }
    }
    iVar5 = 1 << ((char)local_90 - (byte)local_8c & 0x1f);
    iVar11 = 1 << ((byte)uVar12 & 0x1f);
    puVar7 = (undefined *)(local_7c + (((uVar10 >> ((byte)local_8c & 0x1f)) + iVar11) - iVar5) * 4);
    iVar4 = iVar11;
    do {
      *puVar7 = uVar8;
      puVar7[1] = (char)local_90 - (byte)local_8c;
      *(ushort *)(puVar7 + 2) = uVar9;
      puVar7 = puVar7 + iVar5 * -4;
      iVar4 = iVar4 - iVar5;
    } while (iVar4 != 0);
    uVar6 = 1 << ((char)local_90 - 1U & 0x1f);
    while ((uVar6 & uVar10) != 0) {
      uVar6 = uVar6 >> 1;
    }
    if (uVar6 == 0) {
      uVar10 = 0;
    }
    else {
      uVar10 = (uVar6 - 1 & uVar10) + uVar6;
    }
    uVar9 = auStack80[local_90 + 0x10];
    auStack80[local_90 + 0x10] = uVar9 - 1;
    if ((ushort)(uVar9 - 1) == 0) {
      if (local_90 == local_70) break;
      local_90 = (uint)param_2[local_74[1]];
    }
    if ((local_80 < local_90) && (uVar6 = local_60 & uVar10, uVar6 != local_64)) {
      if (local_8c == 0) {
        local_8c = local_80;
      }
      local_7c = local_7c + iVar11 * 4;
      uVar12 = local_90 - local_8c;
      if (local_90 < local_70) {
        iVar4 = (1 << ((byte)uVar12 & 0x1f)) - (uint)auStack80[local_90 + 0x10];
        uVar2 = uVar12;
        while (uVar12 = uVar2, 0 < iVar4) {
          uVar12 = uVar2 + 1;
          if (local_70 <= local_8c + uVar12) break;
          iVar4 = iVar4 * 2 - (uint)auStack80[local_8c + uVar2 + 0x11];
          uVar2 = uVar12;
        }
      }
      local_5c = local_5c + (1 << ((byte)uVar12 & 0x1f));
      if ((param_1 == 1) && (0x5af < local_5c)) {
        return 1;
      }
      iVar4 = uVar6 * 4;
      *(byte *)(*param_4 + iVar4) = (byte)uVar12;
      *(byte *)(*param_4 + 1 + iVar4) = (byte)local_80;
      *(undefined2 *)(*param_4 + 2 + iVar4) = (short)(local_7c - *param_4 >> 2);
      local_64 = uVar6;
    }
    local_74 = local_74 + 1;
  } while( true );
joined_r0x00019c95:
  if (uVar10 == 0) {
LAB_00019d10:
    *param_4 = *param_4 + local_5c * 4;
    *param_5 = local_80;
    return 0;
  }
  if ((local_8c != 0) && ((local_60 & uVar10) != local_64)) {
    local_7c = *param_4;
    local_98 = local_80 & 0xff;
    local_70 = local_80;
    local_8c = 0;
  }
  puVar7 = (undefined *)(local_7c + (uVar10 >> ((byte)local_8c & 0x1f)) * 4);
  *puVar7 = 0x40;
  puVar7[1] = (undefined)local_98;
  *(undefined2 *)(puVar7 + 2) = 0;
  uVar12 = 1 << ((char)local_70 - 1U & 0x1f);
  while ((uVar12 & uVar10) != 0) {
    uVar12 = uVar12 >> 1;
  }
  if (uVar12 == 0) goto LAB_00019d10;
  uVar10 = (uVar10 & uVar12 - 1) + uVar12;
  goto joined_r0x00019c95;
}



void __regparm3 FUN_00019e50(int *param_1,int *param_2)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  int iVar14;
  int iVar15;
  int iVar16;
  uint uVar17;
  uint uVar18;
  uint uVar19;
  uint uVar20;
  uint uVar21;
  
  iVar1 = *param_2;
  uVar18 = ((param_1[3] ^ param_1[2]) & param_1[1] ^ param_1[3]) + *param_1 + -0x28955b88 + iVar1;
  uVar19 = (uVar18 * 0x80 | uVar18 >> 0x19) + param_1[1];
  iVar2 = param_2[1];
  uVar18 = ((param_1[2] ^ param_1[1]) & uVar19 ^ param_1[2]) + param_1[3] + -0x173848aa + iVar2;
  uVar20 = (uVar18 * 0x1000 | uVar18 >> 0x14) + uVar19;
  iVar3 = param_2[2];
  uVar18 = ((uVar19 ^ param_1[1]) & uVar20 ^ param_1[1]) + param_1[2] + 0x242070db + iVar3;
  uVar17 = (uVar18 >> 0xf | uVar18 * 0x20000) + uVar20;
  iVar4 = param_2[3];
  uVar18 = ((uVar20 ^ uVar19) & uVar17 ^ uVar19) + param_1[1] + -0x3e423112 + iVar4;
  uVar18 = (uVar18 >> 10 | uVar18 * 0x400000) + uVar17;
  iVar5 = param_2[4];
  uVar19 = ((uVar17 ^ uVar20) & uVar18 ^ uVar20) + uVar19 + 0xf57c0faf + iVar5;
  uVar19 = (uVar19 * 0x80 | uVar19 >> 0x19) + uVar18;
  iVar6 = param_2[5];
  uVar20 = ((uVar18 ^ uVar17) & uVar19 ^ uVar17) + uVar20 + 0x4787c62a + iVar6;
  uVar20 = (uVar20 * 0x1000 | uVar20 >> 0x14) + uVar19;
  iVar7 = param_2[6];
  uVar17 = ((uVar19 ^ uVar18) & uVar20 ^ uVar18) + uVar17 + 0xa8304613 + iVar7;
  uVar17 = (uVar17 >> 0xf | uVar17 * 0x20000) + uVar20;
  iVar8 = param_2[7];
  uVar18 = ((uVar20 ^ uVar19) & uVar17 ^ uVar19) + uVar18 + 0xfd469501 + iVar8;
  uVar18 = (uVar18 >> 10 | uVar18 * 0x400000) + uVar17;
  iVar9 = param_2[8];
  uVar19 = ((uVar17 ^ uVar20) & uVar18 ^ uVar20) + uVar19 + 0x698098d8 + iVar9;
  uVar19 = (uVar19 * 0x80 | uVar19 >> 0x19) + uVar18;
  iVar10 = param_2[9];
  uVar20 = ((uVar18 ^ uVar17) & uVar19 ^ uVar17) + uVar20 + 0x8b44f7af + iVar10;
  uVar21 = (uVar20 * 0x1000 | uVar20 >> 0x14) + uVar19;
  iVar11 = param_2[10];
  uVar17 = ((uVar19 ^ uVar18) & uVar21 ^ uVar18) + (uVar17 - 0xa44f) + iVar11;
  uVar17 = (uVar17 >> 0xf | uVar17 * 0x20000) + uVar21;
  iVar12 = param_2[0xb];
  uVar18 = ((uVar21 ^ uVar19) & uVar17 ^ uVar19) + uVar18 + 0x895cd7be + iVar12;
  uVar18 = (uVar18 >> 10 | uVar18 * 0x400000) + uVar17;
  iVar13 = param_2[0xc];
  uVar19 = ((uVar17 ^ uVar21) & uVar18 ^ uVar21) + uVar19 + 0x6b901122 + iVar13;
  uVar20 = (uVar19 * 0x80 | uVar19 >> 0x19) + uVar18;
  iVar14 = param_2[0xd];
  uVar19 = ((uVar18 ^ uVar17) & uVar20 ^ uVar17) + uVar21 + 0xfd987193 + iVar14;
  uVar21 = (uVar19 * 0x1000 | uVar19 >> 0x14) + uVar20;
  iVar15 = param_2[0xe];
  uVar17 = ((uVar20 ^ uVar18) & uVar21 ^ uVar18) + uVar17 + 0xa679438e + iVar15;
  uVar19 = (uVar17 >> 0xf | uVar17 * 0x20000) + uVar21;
  iVar16 = param_2[0xf];
  uVar18 = ((uVar21 ^ uVar20) & uVar19 ^ uVar20) + uVar18 + 0x49b40821 + iVar16;
  uVar18 = (uVar18 >> 10 | uVar18 * 0x400000) + uVar19;
  uVar17 = ((uVar18 ^ uVar19) & uVar21 ^ uVar19) + iVar2 + -0x9e1da9e + uVar20;
  uVar17 = (uVar17 * 0x20 | uVar17 >> 0x1b) + uVar18;
  uVar20 = ((uVar17 ^ uVar18) & uVar19 ^ uVar18) + iVar7 + -0x3fbf4cc0 + uVar21;
  uVar20 = (uVar20 * 0x200 | uVar20 >> 0x17) + uVar17;
  uVar19 = ((uVar20 ^ uVar17) & uVar18 ^ uVar17) + iVar12 + 0x265e5a51 + uVar19;
  uVar19 = (uVar19 * 0x4000 | uVar19 >> 0x12) + uVar20;
  uVar18 = ((uVar19 ^ uVar20) & uVar17 ^ uVar20) + iVar1 + -0x16493856 + uVar18;
  uVar18 = (uVar18 >> 0xc | uVar18 * 0x100000) + uVar19;
  uVar17 = ((uVar18 ^ uVar19) & uVar20 ^ uVar19) + iVar6 + -0x29d0efa3 + uVar17;
  uVar17 = (uVar17 * 0x20 | uVar17 >> 0x1b) + uVar18;
  uVar20 = ((uVar17 ^ uVar18) & uVar19 ^ uVar18) + iVar11 + 0x2441453 + uVar20;
  uVar20 = (uVar20 * 0x200 | uVar20 >> 0x17) + uVar17;
  uVar19 = ((uVar20 ^ uVar17) & uVar18 ^ uVar17) + iVar16 + -0x275e197f + uVar19;
  uVar19 = (uVar19 * 0x4000 | uVar19 >> 0x12) + uVar20;
  uVar18 = ((uVar19 ^ uVar20) & uVar17 ^ uVar20) + iVar5 + -0x182c0438 + uVar18;
  uVar18 = (uVar18 >> 0xc | uVar18 * 0x100000) + uVar19;
  uVar17 = ((uVar18 ^ uVar19) & uVar20 ^ uVar19) + iVar10 + 0x21e1cde6 + uVar17;
  uVar17 = (uVar17 * 0x20 | uVar17 >> 0x1b) + uVar18;
  uVar20 = ((uVar17 ^ uVar18) & uVar19 ^ uVar18) + iVar15 + -0x3cc8f82a + uVar20;
  uVar20 = (uVar20 * 0x200 | uVar20 >> 0x17) + uVar17;
  uVar19 = ((uVar20 ^ uVar17) & uVar18 ^ uVar17) + iVar4 + -0xb2af279 + uVar19;
  uVar19 = (uVar19 * 0x4000 | uVar19 >> 0x12) + uVar20;
  uVar18 = ((uVar19 ^ uVar20) & uVar17 ^ uVar20) + iVar9 + 0x455a14ed + uVar18;
  uVar18 = (uVar18 >> 0xc | uVar18 * 0x100000) + uVar19;
  uVar17 = ((uVar18 ^ uVar19) & uVar20 ^ uVar19) + iVar14 + -0x561c16fb + uVar17;
  uVar17 = (uVar17 * 0x20 | uVar17 >> 0x1b) + uVar18;
  uVar20 = ((uVar17 ^ uVar18) & uVar19 ^ uVar18) + iVar3 + -0x3105c08 + uVar20;
  uVar20 = (uVar20 * 0x200 | uVar20 >> 0x17) + uVar17;
  uVar19 = ((uVar20 ^ uVar17) & uVar18 ^ uVar17) + iVar8 + 0x676f02d9 + uVar19;
  uVar21 = (uVar19 * 0x4000 | uVar19 >> 0x12) + uVar20;
  uVar18 = ((uVar21 ^ uVar20) & uVar17 ^ uVar20) + iVar13 + -0x72d5b376 + uVar18;
  uVar18 = (uVar18 >> 0xc | uVar18 * 0x100000) + uVar21;
  uVar17 = (uVar21 ^ uVar20 ^ uVar18) + iVar6 + -0x5c6be + uVar17;
  uVar19 = (uVar17 * 0x10 | uVar17 >> 0x1c) + uVar18;
  uVar17 = (uVar18 ^ uVar21 ^ uVar19) + iVar9 + -0x788e097f + uVar20;
  uVar17 = (uVar17 * 0x800 | uVar17 >> 0x15) + uVar19;
  uVar20 = (uVar19 ^ uVar18 ^ uVar17) + iVar12 + 0x6d9d6122 + uVar21;
  uVar20 = (uVar20 * 0x10000 | uVar20 >> 0x10) + uVar17;
  uVar18 = (uVar17 ^ uVar19 ^ uVar20) + iVar15 + -0x21ac7f4 + uVar18;
  uVar18 = (uVar18 >> 9 | uVar18 * 0x800000) + uVar20;
  uVar19 = (uVar20 ^ uVar17 ^ uVar18) + iVar2 + -0x5b4115bc + uVar19;
  uVar19 = (uVar19 * 0x10 | uVar19 >> 0x1c) + uVar18;
  uVar17 = (uVar18 ^ uVar20 ^ uVar19) + iVar5 + 0x4bdecfa9 + uVar17;
  uVar17 = (uVar17 * 0x800 | uVar17 >> 0x15) + uVar19;
  uVar20 = (uVar19 ^ uVar18 ^ uVar17) + iVar8 + -0x944b4a0 + uVar20;
  uVar20 = (uVar20 * 0x10000 | uVar20 >> 0x10) + uVar17;
  uVar18 = (uVar17 ^ uVar19 ^ uVar20) + iVar11 + -0x41404390 + uVar18;
  uVar21 = (uVar18 >> 9 | uVar18 * 0x800000) + uVar20;
  uVar18 = (uVar20 ^ uVar17 ^ uVar21) + iVar14 + 0x289b7ec6 + uVar19;
  uVar18 = (uVar18 * 0x10 | uVar18 >> 0x1c) + uVar21;
  uVar17 = (uVar21 ^ uVar20 ^ uVar18) + iVar1 + -0x155ed806 + uVar17;
  uVar19 = (uVar17 * 0x800 | uVar17 >> 0x15) + uVar18;
  uVar17 = (uVar18 ^ uVar21 ^ uVar19) + iVar4 + -0x2b10cf7b + uVar20;
  uVar20 = (uVar17 * 0x10000 | uVar17 >> 0x10) + uVar19;
  uVar17 = (uVar19 ^ uVar18 ^ uVar20) + iVar7 + 0x4881d05 + uVar21;
  uVar17 = (uVar17 >> 9 | uVar17 * 0x800000) + uVar20;
  uVar18 = (uVar20 ^ uVar19 ^ uVar17) + iVar10 + -0x262b2fc7 + uVar18;
  uVar21 = (uVar18 * 0x10 | uVar18 >> 0x1c) + uVar17;
  uVar18 = (uVar17 ^ uVar20 ^ uVar21) + iVar13 + -0x1924661b + uVar19;
  uVar19 = (uVar18 * 0x800 | uVar18 >> 0x15) + uVar21;
  uVar18 = (uVar21 ^ uVar17 ^ uVar19) + iVar16 + 0x1fa27cf8 + uVar20;
  uVar18 = (uVar18 * 0x10000 | uVar18 >> 0x10) + uVar19;
  uVar17 = (uVar19 ^ uVar21 ^ uVar18) + iVar3 + -0x3b53a99b + uVar17;
  uVar20 = (uVar17 >> 9 | uVar17 * 0x800000) + uVar18;
  uVar17 = ((~uVar19 | uVar20) ^ uVar18) + iVar1 + -0xbd6ddbc + uVar21;
  uVar21 = (uVar17 * 0x40 | uVar17 >> 0x1a) + uVar20;
  uVar17 = ((~uVar18 | uVar21) ^ uVar20) + iVar8 + 0x432aff97 + uVar19;
  uVar17 = (uVar17 * 0x400 | uVar17 >> 0x16) + uVar21;
  uVar18 = ((~uVar20 | uVar17) ^ uVar21) + iVar15 + -0x546bdc59 + uVar18;
  uVar19 = (uVar18 * 0x8000 | uVar18 >> 0x11) + uVar17;
  uVar18 = ((~uVar21 | uVar19) ^ uVar17) + iVar6 + -0x36c5fc7 + uVar20;
  uVar18 = (uVar18 >> 0xb | uVar18 * 0x200000) + uVar19;
  uVar20 = ((~uVar17 | uVar18) ^ uVar19) + iVar13 + 0x655b59c3 + uVar21;
  uVar20 = (uVar20 * 0x40 | uVar20 >> 0x1a) + uVar18;
  uVar17 = ((~uVar19 | uVar20) ^ uVar18) + iVar4 + -0x70f3336e + uVar17;
  uVar17 = (uVar17 * 0x400 | uVar17 >> 0x16) + uVar20;
  uVar19 = ((~uVar18 | uVar17) ^ uVar20) + iVar11 + -0x100b83 + uVar19;
  uVar19 = (uVar19 * 0x8000 | uVar19 >> 0x11) + uVar17;
  uVar18 = ((~uVar20 | uVar19) ^ uVar17) + iVar2 + -0x7a7ba22f + uVar18;
  uVar21 = (uVar18 >> 0xb | uVar18 * 0x200000) + uVar19;
  uVar18 = ((~uVar17 | uVar21) ^ uVar19) + iVar9 + 0x6fa87e4f + uVar20;
  uVar18 = (uVar18 * 0x40 | uVar18 >> 0x1a) + uVar21;
  uVar17 = ((~uVar19 | uVar18) ^ uVar21) + iVar16 + -0x1d31920 + uVar17;
  uVar20 = (uVar17 * 0x400 | uVar17 >> 0x16) + uVar18;
  uVar17 = ((~uVar21 | uVar20) ^ uVar18) + iVar7 + -0x5cfebcec + uVar19;
  uVar17 = (uVar17 * 0x8000 | uVar17 >> 0x11) + uVar20;
  uVar19 = ((~uVar18 | uVar17) ^ uVar20) + iVar14 + 0x4e0811a1 + uVar21;
  uVar19 = (uVar19 >> 0xb | uVar19 * 0x200000) + uVar17;
  uVar18 = ((~uVar20 | uVar19) ^ uVar17) + iVar5 + -0x8ac817e + uVar18;
  uVar18 = (uVar18 * 0x40 | uVar18 >> 0x1a) + uVar19;
  uVar20 = ((~uVar17 | uVar18) ^ uVar19) + iVar12 + -0x42c50dcb + uVar20;
  uVar20 = (uVar20 * 0x400 | uVar20 >> 0x16) + uVar18;
  uVar17 = ((~uVar19 | uVar20) ^ uVar18) + iVar3 + 0x2ad7d2bb + uVar17;
  uVar17 = (uVar17 * 0x8000 | uVar17 >> 0x11) + uVar20;
  uVar19 = ((~uVar18 | uVar17) ^ uVar20) + iVar10 + -0x14792c6f + uVar19;
  *param_1 = uVar18 + *param_1;
  param_1[1] = (uVar19 >> 0xb | uVar19 * 0x200000) + uVar17 + param_1[1];
  param_1[2] = uVar17 + param_1[2];
  param_1[3] = uVar20 + param_1[3];
  return;
}



void FUN_0001a519(undefined4 *param_1)

{
  *param_1 = 0x67452301;
  param_1[1] = 0xefcdab89;
  param_1[2] = 0x98badcfe;
  param_1[3] = 0x10325476;
  param_1[4] = 0;
  param_1[5] = 0;
  return;
}



void FUN_0001a547(int param_1,undefined4 *param_2,uint param_3)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  undefined4 *puVar5;
  undefined4 *puVar6;
  undefined4 *puVar7;
  undefined4 *puVar8;
  byte bVar9;
  
  bVar9 = 0;
  uVar4 = *(uint *)(param_1 + 0x10);
  uVar2 = uVar4 + param_3 * 8;
  *(uint *)(param_1 + 0x10) = uVar2;
  if (uVar2 < uVar4) {
    *(int *)(param_1 + 0x14) = *(int *)(param_1 + 0x14) + 1;
  }
  *(int *)(param_1 + 0x14) = *(int *)(param_1 + 0x14) + (param_3 >> 0x1d);
  uVar2 = uVar4 >> 3 & 0x3f;
  if (uVar2 != 0) {
    iVar1 = param_1 + 0x10 + uVar2;
    puVar5 = (undefined4 *)(iVar1 + 8);
    uVar4 = -uVar2 + 0x40;
    if (param_3 < uVar4) {
      if (3 < param_3) {
        if (((uint)puVar5 & 1) != 0) {
          *(undefined *)(iVar1 + 8) = *(undefined *)param_2;
          puVar5 = (undefined4 *)(iVar1 + 9);
          param_2 = (undefined4 *)((int)param_2 + 1);
          param_3 = param_3 - 1;
        }
        if (((uint)puVar5 & 2) != 0) {
          *(undefined2 *)puVar5 = *(undefined2 *)param_2;
          puVar5 = (undefined4 *)((int)puVar5 + 2);
          param_2 = (undefined4 *)((int)param_2 + 2);
          param_3 = param_3 - 2;
        }
        uVar2 = param_3 >> 2;
        while (uVar2 != 0) {
          uVar2 = uVar2 - 1;
          *puVar5 = *param_2;
          param_2 = param_2 + 1;
          puVar5 = puVar5 + 1;
        }
      }
      puVar6 = param_2;
      puVar7 = puVar5;
      if ((param_3 & 2) != 0) {
        puVar7 = (undefined4 *)((int)puVar5 + 2);
        puVar6 = (undefined4 *)((int)param_2 + 2);
        *(undefined2 *)puVar5 = *(undefined2 *)param_2;
      }
      if ((param_3 & 1) == 0) {
        return;
      }
      *(undefined *)puVar7 = *(undefined *)puVar6;
      return;
    }
    uVar3 = uVar4;
    puVar6 = param_2;
    if (3 < uVar4) {
      if (((uint)puVar5 & 1) != 0) {
        *(undefined *)(iVar1 + 8) = *(undefined *)param_2;
        puVar5 = (undefined4 *)(iVar1 + 9);
        puVar6 = (undefined4 *)((int)param_2 + 1);
        uVar3 = -uVar2 + 0x3f;
      }
      if (((uint)puVar5 & 2) != 0) {
        *(undefined2 *)puVar5 = *(undefined2 *)puVar6;
        puVar5 = (undefined4 *)((int)puVar5 + 2);
        puVar6 = (undefined4 *)((int)puVar6 + 2);
        uVar3 = uVar3 - 2;
      }
      uVar2 = uVar3 >> 2;
      while (uVar2 != 0) {
        uVar2 = uVar2 - 1;
        *puVar5 = *puVar6;
        puVar6 = puVar6 + 1;
        puVar5 = puVar5 + 1;
      }
    }
    puVar7 = puVar6;
    puVar8 = puVar5;
    if ((uVar3 & 2) != 0) {
      puVar8 = (undefined4 *)((int)puVar5 + 2);
      puVar7 = (undefined4 *)((int)puVar6 + 2);
      *(undefined2 *)puVar5 = *(undefined2 *)puVar6;
    }
    if ((uVar3 & 1) != 0) {
      *(undefined *)puVar8 = *(undefined *)puVar7;
    }
    FUN_00019e50();
    param_2 = (undefined4 *)((int)param_2 + uVar4);
    param_3 = param_3 - uVar4;
  }
  if (0x3f < param_3) {
    puVar5 = param_2;
    uVar2 = param_3;
    do {
      *(undefined4 *)(param_1 + 0x18) = *puVar5;
      *(undefined4 *)(param_1 + 0x1c) = puVar5[1];
      *(undefined4 *)(param_1 + 0x20) = puVar5[2];
      *(undefined4 *)(param_1 + 0x24) = puVar5[3];
      *(undefined4 *)(param_1 + 0x28) = puVar5[4];
      *(undefined4 *)(param_1 + 0x2c) = puVar5[5];
      *(undefined4 *)(param_1 + 0x30) = puVar5[6];
      *(undefined4 *)(param_1 + 0x34) = puVar5[7];
      *(undefined4 *)(param_1 + 0x38) = puVar5[8];
      *(undefined4 *)(param_1 + 0x3c) = puVar5[9];
      *(undefined4 *)(param_1 + 0x40) = puVar5[10];
      *(undefined4 *)(param_1 + 0x44) = puVar5[0xb];
      *(undefined4 *)(param_1 + 0x48) = puVar5[0xc];
      *(undefined4 *)(param_1 + 0x4c) = puVar5[0xd];
      *(undefined4 *)(param_1 + 0x50) = puVar5[0xe];
      *(undefined4 *)(param_1 + 0x54) = puVar5[0xf];
      FUN_00019e50();
      puVar5 = puVar5 + 0x10;
      uVar2 = uVar2 - 0x40;
    } while (0x3f < uVar2);
    param_2 = (undefined4 *)((int)param_2 + (param_3 - 0x40 & 0xffffffc0) + 0x40);
    param_3 = param_3 & 0x3f;
  }
  puVar5 = (undefined4 *)(param_1 + 0x18);
  if (3 < param_3) {
    if (((uint)puVar5 & 1) != 0) {
      *(undefined *)(param_1 + 0x18) = *(undefined *)param_2;
      puVar5 = (undefined4 *)(param_1 + 0x19);
      param_2 = (undefined4 *)((int)param_2 + 1);
      param_3 = param_3 - 1;
    }
    if (((uint)puVar5 & 2) != 0) {
      *(undefined2 *)puVar5 = *(undefined2 *)param_2;
      puVar5 = (undefined4 *)((int)puVar5 + 2);
      param_2 = (undefined4 *)((int)param_2 + 2);
      param_3 = param_3 - 2;
    }
    uVar2 = param_3 >> 2;
    while (uVar2 != 0) {
      uVar2 = uVar2 - 1;
      *puVar5 = *param_2;
      param_2 = param_2 + (uint)bVar9 * 0x3ffffffe + 1;
      puVar5 = puVar5 + (uint)bVar9 * 0x3ffffffe + 1;
    }
  }
  puVar6 = param_2;
  puVar7 = puVar5;
  if ((param_3 & 2) != 0) {
    puVar7 = (undefined4 *)((int)puVar5 + (uint)bVar9 * -4 + 2);
    puVar6 = (undefined4 *)((int)param_2 + (uint)bVar9 * -4 + 2);
    *(undefined2 *)puVar5 = *(undefined2 *)param_2;
  }
  if ((param_3 & 1) != 0) {
    *(undefined *)puVar7 = *(undefined *)puVar6;
  }
  return;
}



void FUN_0001a73a(undefined4 *param_1,undefined4 *param_2)

{
  void *__s;
  uint uVar1;
  uint uVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  bool bVar5;
  byte bVar6;
  
  bVar6 = 0;
  uVar1 = (uint)param_1[4] >> 3 & 0x3f;
  __s = (void *)((int)param_1 + uVar1 + 0x19);
  *(undefined *)((int)param_1 + uVar1 + 0x18) = 0x80;
  if (0x3f - uVar1 < 8) {
    memset(__s,0,0x3f - uVar1);
    puVar4 = param_1 + 6;
    FUN_00019e50();
    uVar1 = 0x38;
    bVar5 = ((uint)puVar4 & 1) != 0;
    puVar3 = puVar4;
    if (bVar5) {
      puVar3 = (undefined4 *)((int)param_1 + (uint)bVar6 * -2 + 0x19);
      *(undefined *)puVar4 = 0;
      uVar1 = 0x37;
    }
    puVar4 = puVar3;
    if (((uint)puVar3 & 2) != 0) {
      puVar4 = (undefined4 *)((int)puVar3 + (uint)bVar6 * -4 + 2);
      *(undefined2 *)puVar3 = 0;
      uVar1 = uVar1 - 2;
    }
    uVar2 = uVar1 >> 2;
    while (uVar2 != 0) {
      uVar2 = uVar2 - 1;
      *puVar4 = 0;
      puVar4 = puVar4 + (uint)bVar6 * 0x3ffffffe + 1;
    }
    puVar3 = puVar4;
    if ((uVar1 & 2) != 0) {
      puVar3 = (undefined4 *)((int)puVar4 + (uint)bVar6 * -4 + 2);
      *(undefined2 *)puVar4 = 0;
    }
    if (bVar5) {
      *(undefined *)puVar3 = 0;
    }
  }
  else {
    memset(__s,0,0x37 - uVar1);
  }
  param_1[0x14] = param_1[4];
  param_1[0x15] = param_1[5];
  FUN_00019e50();
  if (param_2 != (undefined4 *)0x0) {
    *param_2 = *param_1;
    param_2[1] = param_1[1];
    param_2[2] = param_1[2];
    param_2[3] = param_1[3];
  }
  uVar1 = 0x58;
  bVar5 = ((uint)param_1 & 1) != 0;
  puVar4 = param_1;
  if (bVar5) {
    puVar4 = (undefined4 *)((int)param_1 + (uint)bVar6 * -2 + 1);
    *(undefined *)param_1 = 0;
    uVar1 = 0x57;
  }
  puVar3 = puVar4;
  if (((uint)puVar4 & 2) != 0) {
    puVar3 = (undefined4 *)((int)puVar4 + (uint)bVar6 * -4 + 2);
    *(undefined2 *)puVar4 = 0;
    uVar1 = uVar1 - 2;
  }
  uVar2 = uVar1 >> 2;
  while (uVar2 != 0) {
    uVar2 = uVar2 - 1;
    *puVar3 = 0;
    puVar3 = puVar3 + (uint)bVar6 * 0x3ffffffe + 1;
  }
  puVar4 = puVar3;
  if ((uVar1 & 2) != 0) {
    puVar4 = (undefined4 *)((int)puVar3 + (uint)bVar6 * -4 + 2);
    *(undefined2 *)puVar3 = 0;
  }
  if (bVar5) {
    *(undefined *)puVar4 = 0;
  }
  return;
}



void FUN_0001a849(undefined2 *param_1,undefined4 param_2,undefined4 param_3)

{
  uint uVar1;
  uint uVar2;
  undefined2 *puVar3;
  undefined2 *puVar4;
  bool bVar5;
  
  uVar2 = 0x28;
  bVar5 = ((uint)param_1 & 1) != 0;
  puVar4 = param_1;
  if (bVar5) {
    puVar4 = (undefined2 *)((int)param_1 + 1);
    *(undefined *)param_1 = 0;
    uVar2 = 0x27;
  }
  puVar3 = puVar4;
  if (((uint)puVar4 & 2) != 0) {
    puVar3 = puVar4 + 1;
    *puVar4 = 0;
    uVar2 = uVar2 - 2;
  }
  uVar1 = 0;
  do {
    *(undefined4 *)((int)puVar3 + uVar1) = 0;
    uVar1 = uVar1 + 4;
  } while (uVar1 < (uVar2 & 0xfffffffc));
  puVar3 = (undefined2 *)((int)puVar3 + uVar1);
  puVar4 = puVar3;
  if ((uVar2 & 2) != 0) {
    puVar4 = puVar3 + 1;
    *puVar3 = 0;
  }
  if (bVar5) {
    *(undefined *)puVar4 = 0;
  }
  *(undefined4 *)(param_1 + 4) = param_2;
  *(undefined4 *)(param_1 + 8) = param_3;
  return;
}



void FUN_0001a8a6(undefined4 *param_1)

{
  *param_1 = 0;
  param_1[7] = 0;
  param_1[8] = 0;
  return;
}



void FUN_0001a8bf(undefined4 *param_1,undefined param_2)

{
  int iVar1;
  
  iVar1 = param_1[5];
  if (param_1[4] == iVar1 || param_1[4] - iVar1 < 0) {
    *param_1 = 1;
  }
  else {
    *(undefined *)(param_1[2] + iVar1) = param_2;
    param_1[5] = param_1[5] + 1;
  }
  return;
}



void FUN_0001a8e9(undefined4 *param_1,short param_2)

{
  int iVar1;
  int iVar2;
  undefined2 uVar3;
  
  iVar1 = param_1[5];
  if (param_1[4] - iVar1 < 2) {
    *param_1 = 1;
  }
  else {
    iVar2 = param_1[2];
    uVar3 = FUN_0001ac20((int)param_2);
    *(undefined2 *)(iVar1 + iVar2) = uVar3;
    param_1[5] = param_1[5] + 2;
  }
  return;
}



void FUN_0001a926(undefined4 *param_1,undefined4 param_2)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  
  iVar1 = param_1[5];
  if (param_1[4] - iVar1 < 4) {
    *param_1 = 1;
  }
  else {
    iVar2 = param_1[2];
    uVar3 = FUN_0001ac33(param_2);
    *(undefined4 *)(iVar1 + iVar2) = uVar3;
    param_1[5] = param_1[5] + 4;
  }
  return;
}



void FUN_0001a961(undefined4 param_1,byte *param_2,int param_3)

{
  byte *pbVar1;
  
  if (0 < param_3) {
    pbVar1 = param_2 + param_3;
    do {
      FUN_0001a8bf(param_1,(uint)*param_2);
      param_2 = param_2 + 1;
    } while (param_2 != pbVar1);
  }
  return;
}



void FUN_0001a998(undefined4 param_1,char *param_2)

{
  char cVar1;
  uint uVar2;
  char *pcVar3;
  undefined local_40c [1028];
  
  if (param_2 == (char *)0x0) {
    FUN_0001a961(param_1,0x1d0b4,1);
  }
  else {
    uVar2 = 0xffffffff;
    pcVar3 = param_2;
    do {
      if (uVar2 == 0) break;
      uVar2 = uVar2 - 1;
      cVar1 = *pcVar3;
      pcVar3 = pcVar3 + 1;
    } while (cVar1 != '\0');
    if ((int)(~uVar2 - 1) < 0x400) {
      FUN_0001ac5b(local_40c,param_2,0x400);
      FUN_0001a961(param_1,local_40c,~uVar2);
    }
    else {
      FUN_0001a961(param_1,0x1d0b4,1);
    }
  }
  return;
}



uint FUN_0001aa43(int param_1)

{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x1c);
  uVar1 = iVar2 + 1;
  if (*(uint *)(param_1 + 0x14) <= uVar1 && uVar1 != *(uint *)(param_1 + 0x14)) {
    *(uint *)(param_1 + 0x1c) = uVar1;
    return 0xffffffff;
  }
  *(uint *)(param_1 + 0x1c) = uVar1;
  return (uint)*(byte *)(iVar2 + *(int *)(param_1 + 8));
}



int FUN_0001aa65(int param_1)

{
  uint uVar1;
  short sVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0x1c);
  uVar1 = iVar3 + 2;
  if (uVar1 < *(uint *)(param_1 + 0x14) || uVar1 == *(uint *)(param_1 + 0x14)) {
    *(uint *)(param_1 + 0x1c) = uVar1;
    sVar2 = FUN_0001ac20((int)*(short *)(iVar3 + *(int *)(param_1 + 8)));
    iVar3 = (int)sVar2;
  }
  else {
    *(uint *)(param_1 + 0x1c) = uVar1;
    iVar3 = -1;
  }
  return iVar3;
}



undefined4 FUN_0001aa97(int param_1)

{
  uint uVar1;
  int iVar2;
  undefined4 uVar3;
  
  iVar2 = *(int *)(param_1 + 0x1c);
  uVar1 = iVar2 + 4;
  if (uVar1 < *(uint *)(param_1 + 0x14) || uVar1 == *(uint *)(param_1 + 0x14)) {
    *(uint *)(param_1 + 0x1c) = uVar1;
    uVar3 = FUN_0001ac33(*(undefined4 *)(iVar2 + *(int *)(param_1 + 8)));
  }
  else {
    *(uint *)(param_1 + 0x1c) = uVar1;
    uVar3 = 0xffffffff;
  }
  return uVar3;
}



undefined4 FUN_0001aac7(int param_1)

{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x1c);
  uVar1 = iVar2 + 4;
  if (*(uint *)(param_1 + 0x14) <= uVar1 && uVar1 != *(uint *)(param_1 + 0x14)) {
    *(uint *)(param_1 + 0x1c) = uVar1;
    return 0xffffffff;
  }
  *(uint *)(param_1 + 0x1c) = uVar1;
  return *(undefined4 *)(iVar2 + *(int *)(param_1 + 8));
}



int FUN_0001aae8(undefined4 param_1,int param_2,int param_3)

{
  int iVar1;
  int iVar2;
  
  iVar2 = 0;
  do {
    iVar1 = FUN_0001aa43(param_1);
    if (iVar1 + 1U < 2) break;
    *(undefined *)(param_2 + iVar2) = (char)iVar1;
    iVar2 = iVar2 + 1;
  } while (iVar2 < param_3 + -1);
  *(undefined *)(param_2 + iVar2) = 0;
  return param_2;
}



void FUN_0001ab2b(undefined4 param_1,undefined *param_2,int param_3)

{
  undefined uVar1;
  undefined *puVar2;
  
  if (0 < param_3) {
    puVar2 = param_2 + param_3;
    do {
      uVar1 = FUN_0001aa43(param_1);
      *param_2 = uVar1;
      param_2 = param_2 + 1;
    } while (param_2 != puVar2);
  }
  return;
}



int FUN_0001ab5d(int param_1,undefined *param_2,int param_3)

{
  uint uVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  
  if (param_3 < 1) {
LAB_0001abcd:
    *param_2 = 0;
    iVar4 = 0;
  }
  else {
    uVar1 = *(int *)(param_1 + 0x1c) + 1;
    if (uVar1 < *(uint *)(param_1 + 0x14) || uVar1 == *(uint *)(param_1 + 0x14)) {
      iVar3 = 0;
      do {
        uVar2 = FUN_0001aa43(param_1);
        sprintf(param_2 + iVar3,"%02x",uVar2);
        iVar4 = iVar3 + 2;
        if (param_3 <= iVar4 * 2) {
          if (iVar4 != 0) {
            param_2[iVar3] = 0;
            return iVar4;
          }
          goto LAB_0001abcd;
        }
        uVar1 = *(int *)(param_1 + 0x1c) + 1;
        iVar3 = iVar4;
      } while (uVar1 < *(uint *)(param_1 + 0x14) || uVar1 == *(uint *)(param_1 + 0x14));
    }
    else {
      iVar4 = 0;
    }
    param_2[iVar4] = 0;
  }
  return iVar4;
}



void FUN_0001abe7(int param_1)

{
  int iVar1;
  size_t __n;
  
  iVar1 = *(int *)(param_1 + 0x1c);
  if (0 < iVar1) {
    __n = *(int *)(param_1 + 0x14) - iVar1;
    *(size_t *)(param_1 + 0x14) = __n;
    memmove(*(void **)(param_1 + 8),(void *)(iVar1 + (int)*(void **)(param_1 + 8)),__n);
    *(undefined4 *)(param_1 + 0x1c) = 0;
  }
  return;
}



int FUN_0001ac20(uint param_1)

{
  return param_1 * 0x100 + (param_1 >> 8 & 0xff);
}



uint FUN_0001ac2d(ushort param_1)

{
  return (uint)param_1;
}



int FUN_0001ac33(uint param_1)

{
  return (param_1 >> 8 & 0xff00) + param_1 * 0x1000000 + (param_1 >> 8 & 0xff) * 0x10000 +
         (param_1 >> 0x18);
}



undefined4 FUN_0001ac56(undefined4 param_1)

{
  return param_1;
}



void FUN_0001ac5b(char *param_1,char *param_2,int param_3)

{
  if (((param_1 != (char *)0x0) && (param_2 != (char *)0x0)) && (0 < param_3)) {
    strncpy(param_1,param_2,param_3 - 1);
    param_1[param_3 + -1] = '\0';
  }
  return;
}



void FUN_0001ac96(char *param_1,size_t param_2,char *param_3)

{
  vsnprintf(param_1,param_2,param_3,&stack0x00000010);
  return;
}



void FUN_0001acc1(char *param_1,char *param_2)

{
  char cVar1;
  
  cVar1 = *param_2;
  while (cVar1 != '\0') {
    param_2 = param_2 + 1;
    *param_1 = cVar1;
    cVar1 = *param_2;
    param_1 = param_1 + 1;
  }
  *param_1 = '\0';
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0001ace4(void)

{
  DAT_00041240 = 0;
  _DAT_00041244 = 0;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

char * FUN_0001acf9(char *param_1)

{
  char cVar1;
  
  if (DAT_00041240 == param_1) {
    if (_DAT_00041244 != 0) {
      do {
        DAT_00041240 = DAT_00041240 + 1;
        cVar1 = *DAT_00041240;
        if (((cVar1 == '\"') || (cVar1 == ';')) || (cVar1 == '\n')) break;
      } while (cVar1 != '\0');
      _DAT_00041244 = 0;
    }
    cVar1 = *DAT_00041240;
    param_1 = DAT_00041240;
    while (cVar1 != ' ') {
      if ((cVar1 == '\0') || (cVar1 == '\n')) {
        DAT_00041240 = (char *)0x0;
        _DAT_00041244 = 0;
        return (char *)0;
      }
      param_1 = param_1 + 1;
      cVar1 = *param_1;
    }
  }
  while ((cVar1 = *param_1, cVar1 == ' ' || (cVar1 == ';'))) {
    param_1 = param_1 + 1;
  }
  if (cVar1 == '\"') {
    _DAT_00041244 = 1;
    param_1 = param_1 + 1;
  }
  if ((*param_1 != '\0') && (*param_1 != '\n')) {
    DAT_00041240 = param_1;
    return param_1;
  }
  DAT_00041240 = (char *)0x0;
  _DAT_00041244 = 0;
  return (char *)0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_0001adcc(byte *param_1)

{
  byte bVar1;
  int iVar2;
  
  if (param_1 == (byte *)0x0) {
    return 0;
  }
  if (_DAT_00041244 == 0) {
    bVar1 = *param_1;
    if (bVar1 == 0x3b) {
      return 0;
    }
    if (bVar1 == 10) {
      return 0;
    }
    iVar2 = 0;
    if ((bVar1 & 0xdf) == 0) {
      return iVar2;
    }
    while( true ) {
      iVar2 = iVar2 + 1;
      bVar1 = param_1[iVar2];
      if ((bVar1 == 0x3b) || (bVar1 == 10)) break;
      if ((bVar1 & 0xdf) == 0) {
        return iVar2;
      }
    }
  }
  else {
    bVar1 = *param_1;
    if (bVar1 == 0x22) {
      return 0;
    }
    if (bVar1 == 0x3b) {
      return 0;
    }
    if (bVar1 == 10) {
      return 0;
    }
    if (bVar1 == 0) {
      iVar2 = 0;
    }
    else {
      iVar2 = 0;
      while( true ) {
        iVar2 = iVar2 + 1;
        bVar1 = param_1[iVar2];
        if (((bVar1 == 0x22) || (bVar1 == 0x3b)) || (bVar1 == 10)) break;
        if (bVar1 == 0) {
          return iVar2;
        }
      }
    }
  }
  return iVar2;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_0001ae70(undefined4 param_1,undefined4 param_2,undefined4 *param_3,undefined4 param_4,
                undefined4 param_5)

{
  int iVar1;
  
  *param_3 = 0;
  _DAT_000412a0 = 0;
  _DAT_000412a4 = 0;
  _DAT_000412a8 = 0;
  if (_DAT_00041260 == 0) {
    iVar1 = FUN_000171f4(&DAT_00041280,0xfffffff1,"1.2.3",0x38);
    _DAT_00041260 = 1;
  }
  else {
    iVar1 = FUN_000170f3(&DAT_00041280);
  }
  if (iVar1 == 0) {
    _DAT_00041280 = param_4;
    _DAT_00041284 = param_5;
    _DAT_0004128c = param_1;
    _DAT_00041290 = param_2;
    iVar1 = FUN_0001731f(&DAT_00041280,4);
    if (iVar1 == -3) {
      Plugin_PrintError("zlib: inflate: Error: Data\n");
      iVar1 = -3;
    }
    else {
      if (iVar1 == 2) {
        Plugin_PrintError("zlib: inflate: Error: Need Dictionary\n");
        iVar1 = -3;
      }
      else {
        if (iVar1 == -4) {
          Plugin_PrintError("zlib: inflate: Error: Memory\n");
          iVar1 = -4;
        }
        else {
          *param_3 = DAT_00041294;
          iVar1 = (uint)(iVar1 == 1) * 3 + -3;
        }
      }
    }
  }
  else {
    Plugin_PrintError("zlib: inflateInit failed\n");
  }
  return iVar1;
}



char * FUN_0001af9a(void)

{
  return "1.2.3";
}



undefined4 FUN_0001afa0(void)

{
  return 0x55;
}



undefined * FUN_0001afa6(int param_1)

{
  return (&PTR_s_need_dictionary_0001ed40)[2 - param_1];
}



void FUN_0001afb7(undefined4 param_1,int param_2,int param_3)

{
  Plugin_Malloc(param_3 * param_2);
  return;
}



void FUN_0001afcf(undefined4 param_1,undefined4 param_2)

{
  Plugin_Free(param_2);
  return;
}



void _fini(void)

{
  entry();
  return;
}


