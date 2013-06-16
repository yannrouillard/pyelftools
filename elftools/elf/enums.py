#-------------------------------------------------------------------------------
# elftools: elf/enums.py
#
# Mappings of enum names to values
#
# Eli Bendersky (eliben@gmail.com)
# This code is in the public domain
#-------------------------------------------------------------------------------
from ..construct import Pass


# e_ident[EI_CLASS] in the ELF header
ENUM_EI_CLASS = dict(
    ELFCLASSNONE=0,
    ELFCLASS32=1,
    ELFCLASS64=2
)

# e_ident[EI_DATA] in the ELF header
ENUM_EI_DATA = dict(
    ELFDATANONE=0,
    ELFDATA2LSB=1,
    ELFDATA2MSB=2
)

# e_version in the ELF header
ENUM_E_VERSION = dict(
    EV_NONE=0,
    EV_CURRENT=1,
    _default_=Pass,
)

# e_ident[EI_OSABI] in the ELF header
ENUM_EI_OSABI = dict(
    ELFOSABI_SYSV=0,
    ELFOSABI_HPUX=1,
    ELFOSABI_NETBSD=2,
    ELFOSABI_LINUX=3,
    ELFOSABI_HURD=4,
    ELFOSABI_SOLARIS=6,
    ELFOSABI_AIX=7,
    ELFOSABI_IRIX=8,
    ELFOSABI_FREEBSD=9,
    ELFOSABI_TRU64=10,
    ELFOSABI_MODESTO=11,
    ELFOSABI_OPENBSD=12,
    ELFOSABI_OPENVMS=13,
    ELFOSABI_NSK=14,
    ELFOSABI_AROS=15,
    ELFOSABI_ARM_AEABI=64,
    ELFOSABI_ARM=97,
    ELFOSABI_STANDALONE=255,
    _default_=Pass,
)

# e_type in the ELF header
ENUM_E_TYPE = dict(
    ET_NONE=0,
    ET_REL=1,
    ET_EXEC=2,
    ET_DYN=3,
    ET_CORE=4,
    ET_LOPROC=0xff00,
    ET_HIPROC=0xffff,
    _default_=Pass,
)

# e_machine in the ELF header
ENUM_E_MACHINE = dict(
    EM_NONE=0,
    EM_M32=1,
    EM_SPARC=2,
    EM_386=3,
    EM_68K=4,
    EM_88K=5,
    EM_860=7,
    EM_MIPS=8,
    EM_S370=9,
    EM_MIPS_RS3_LE=10,
    EM_PARISC=15,
    EM_VPP500=17,
    EM_SPARC32PLUS=18,
    EM_960=19,
    EM_PPC=20,
    EM_PPC64=21,
    EM_S390=22,
    EM_V800=36,
    EM_FR20=37,
    EM_RH32=38,
    EM_RCE=39,
    EM_ARM=40,
    EM_ALPHA=41,
    EM_SH=42,
    EM_SPARCV9=43,
    EM_TRICORE=44,
    EM_ARC=45,
    EM_H8_300=46,
    EM_H8_300H=47,
    EM_H8S=48,
    EM_H8_500=49,
    EM_IA_64=50,
    EM_MIPS_X=51,
    EM_COLDFIRE=52,
    EM_68HC12=53,
    EM_MMA=54,
    EM_PCP=55,
    EM_NCPU=56,
    EM_NDR1=57,
    EM_STARCORE=58,
    EM_ME16=59,
    EM_ST100=60,
    EM_TINYJ=61,
    EM_X86_64=62,
    EM_PDSP=63,
    EM_PDP10=64,
    EM_PDP11=65,
    EM_FX66=66,
    EM_ST9PLUS=67,
    EM_ST7=68,
    EM_68HC16=69,
    EM_68HC11=70,
    EM_68HC08=71,
    EM_68HC05=72,
    EM_SVX=73,
    EM_ST19=74,
    EM_VAX=75,
    EM_CRIS=76,
    EM_JAVELIN=77,
    EM_FIREPATH=78,
    EM_ZSP=79,
    EM_MMIX=80,
    EM_HUANY=81,
    EM_PRISM=82,
    EM_AVR=83,
    EM_FR30=84,
    EM_D10V=85,
    EM_D30V=86,
    EM_V850=87,
    EM_M32R=88,
    EM_MN10300=89,
    EM_MN10200=90,
    EM_PJ=91,
    EM_OPENRISC=92,
    EM_ARC_A5=93,
    EM_XTENSA=94,
    EM_VIDEOCORE=95,
    EM_TMM_GPP=96,
    EM_NS32K=97,
    EM_TPC=98,
    EM_SNP1K=99,
    EM_ST200=100,
    EM_IP2K=101,
    EM_MAX=102,
    EM_CR=103,
    EM_F2MC16=104,
    EM_MSP430=105,
    EM_BLACKFIN=106,
    EM_SE_C33=107,
    EM_SEP=108,
    EM_ARCA=109,
    EM_UNICORE=110,
    EM_L10M=180,
    EM_AARCH64=183,
    _default_=Pass,
)

# sh_type in the section header
ENUM_SH_TYPE = dict(
    SHT_NULL=0,
    SHT_PROGBITS=1,
    SHT_SYMTAB=2,
    SHT_STRTAB=3,
    SHT_RELA=4,
    SHT_HASH=5,
    SHT_DYNAMIC=6,
    SHT_NOTE=7,
    SHT_NOBITS=8,
    SHT_REL=9,
    SHT_SHLIB=10,
    SHT_DYNSYM=11,
    SHT_INIT_ARRAY=14,
    SHT_FINI_ARRAY=15,
    SHT_PREINIT_ARRAY=16,
    SHT_GROUP=17,
    SHT_SYMTAB_SHNDX=18,
    SHT_NUM=19,
    SHT_LOOS=0x60000000,
    SHT_GNU_HASH=0x6ffffff6,
    SHT_GNU_verdef=0x6ffffffd,  # also SHT_SUNW_verdef
    SHT_GNU_verneed=0x6ffffffe, # also SHT_SUNW_verneed
    SHT_GNU_versym=0x6fffffff,  # also SHT_SUNW_versym
    SHT_LOPROC=0x70000000,
    SHT_HIPROC=0x7fffffff,
    SHT_LOUSER=0x80000000,
    SHT_HIUSER=0xffffffff,
    SHT_AMD64_UNWIND=0x70000001,
    SHT_SUNW_LDYNSYM=0x6ffffff3,
    SHT_SUNW_syminfo=0x6ffffffc,
    SHT_ARM_EXIDX=0x70000001,
    SHT_ARM_PREEMPTMAP=0x70000002,
    SHT_ARM_ATTRIBUTES=0x70000003,
    SHT_ARM_DEBUGOVERLAY=0x70000004,
    _default_=Pass,
)

# p_type in the program header
# some values scavenged from the ELF headers in binutils-2.21
ENUM_P_TYPE = dict(
    PT_NULL=0,
    PT_LOAD=1,
    PT_DYNAMIC=2,
    PT_INTERP=3,
    PT_NOTE=4,
    PT_SHLIB=5,
    PT_PHDR=6,
    PT_TLS=7,
    PT_LOPROC=0x70000000,
    PT_HIPROC=0x7fffffff,
    PT_GNU_EH_FRAME=0x6474e550,
    PT_GNU_STACK=0x6474e551,
    PT_GNU_RELRO=0x6474e552,
    PT_ARM_ARCHEXT=0x70000000,
    PT_ARM_EXIDX=0x70000001,
    PT_ARM_UNWIND=0x70000001,
    PT_AARCH64_ARCHEXT=0x70000000,
    PT_AARCH64_UNWIND=0x70000001,
    _default_=Pass,
)

# st_info bindings in the symbol header
ENUM_ST_INFO_BIND = dict(
    STB_LOCAL=0,
    STB_GLOBAL=1,
    STB_WEAK=2,
    STB_NUM=3,
    STB_LOOS=10,
    STB_HIOS=12,
    STB_LOPROC=13,
    STB_HIPROC=15,
    _default_=Pass,
)

# st_info type in the symbol header
ENUM_ST_INFO_TYPE = dict(
    STT_NOTYPE=0,
    STT_OBJECT=1,
    STT_FUNC=2,
    STT_SECTION=3,
    STT_FILE=4,
    STT_COMMON=5,
    STT_TLS=6,
    STT_NUM=7,
    STT_RELC=8,
    STT_SRELC=9,
    STT_LOOS=10,
    STT_HIOS=12,
    STT_LOPROC=13,
    STT_HIPROC=15,
    _default_=Pass,
)

# visibility from st_other
ENUM_ST_VISIBILITY = dict(
    STV_DEFAULT=0,
    STV_INTERNAL=1,
    STV_HIDDEN=2,
    STV_PROTECTED=3,
    STV_EXPORTED=4,
    STV_SINGLETON=5,
    STV_ELIMINATE=6,
    _default_=Pass,
)

# st_shndx
ENUM_ST_SHNDX = dict(
    SHN_UNDEF=0,
    SHN_ABS=0xfff1,
    SHN_COMMON=0xfff2,
    _default_=Pass,
)

# d_tag
ENUM_D_TAG = dict(
    DT_NULL=0,
    DT_NEEDED=1,
    DT_PLTRELSZ=2,
    DT_PLTGOT=3,
    DT_HASH=4,
    DT_STRTAB=5,
    DT_SYMTAB=6,
    DT_RELA=7,
    DT_RELASZ=8,
    DT_RELAENT=9,
    DT_STRSZ=10,
    DT_SYMENT=11,
    DT_INIT=12,
    DT_FINI=13,
    DT_SONAME=14,
    DT_RPATH=15,
    DT_SYMBOLIC=16,
    DT_REL=17,
    DT_RELSZ=18,
    DT_RELENT=19,
    DT_PLTREL=20,
    DT_DEBUG=21,
    DT_TEXTREL=22,
    DT_JMPREL=23,
    DT_BIND_NOW=24,
    DT_INIT_ARRAY=25,
    DT_FINI_ARRAY=26,
    DT_INIT_ARRAYSZ=27,
    DT_FINI_ARRAYSZ=28,
    DT_RUNPATH=29,
    DT_FLAGS=30,
    DT_ENCODING=32,
    DT_PREINIT_ARRAY=32,
    DT_PREINIT_ARRAYSZ=33,
    DT_NUM=34,
    DT_LOOS=0x6000000d,
    DT_SUNW_AUXILIARY=0x6000000d,
    DT_SUNW_RTLDINF=0x6000000e,
    DT_SUNW_FILTER=0x6000000f,
    DT_SUNW_CAP=0x60000010,
    DT_SUNW_SYMTAB=0x60000011,
    DT_SUNW_SYMSZ=0x60000012,
    DT_SUNW_ENCODING=0x60000013,
    DT_SUNW_SORTENT=0x60000013,
    DT_SUNW_SYMSORT=0x60000014,
    DT_SUNW_SYMSORTSZ=0x60000015,
    DT_SUNW_TLSSORT=0x60000016,
    DT_SUNW_TLSSORTSZ=0x60000017,
    DT_SUNW_CAPINFO=0x60000018,
    DT_SUNW_STRPAD=0x60000019,
    DT_SUNW_CAPCHAIN=0x6000001a,
    DT_SUNW_LDMACH=0x6000001b,
    DT_SUNW_CAPCHAINENT=0x6000001d,
    DT_SUNW_CAPCHAINSZ=0x6000001f,
    DT_HIOS=0x6ffff000,
    DT_LOPROC=0x70000000,
    DT_HIPROC=0x7fffffff,
    DT_PROCNUM=0x35,
    DT_VALRNGLO=0x6ffffd00,
    DT_GNU_PRELINKED=0x6ffffdf5,
    DT_GNU_CONFLICTSZ=0x6ffffdf6,
    DT_GNU_LIBLISTSZ=0x6ffffdf7,
    DT_CHECKSUM=0x6ffffdf8,
    DT_PLTPADSZ=0x6ffffdf9,
    DT_MOVEENT=0x6ffffdfa,
    DT_MOVESZ=0x6ffffdfb,
    DT_SYMINSZ=0x6ffffdfe,
    DT_SYMINENT=0x6ffffdff,
    DT_GNU_HASH=0x6ffffef5,
    DT_TLSDESC_PLT=0x6ffffef6,
    DT_TLSDESC_GOT=0x6ffffef7,
    DT_GNU_CONFLICT=0x6ffffef8,
    DT_GNU_LIBLIST=0x6ffffef9,
    DT_CONFIG=0x6ffffefa,
    DT_DEPAUDIT=0x6ffffefb,
    DT_AUDIT=0x6ffffefc,
    DT_PLTPAD=0x6ffffefd,
    DT_MOVETAB=0x6ffffefe,
    DT_SYMINFO=0x6ffffeff,
    DT_VERSYM=0x6ffffff0,
    DT_RELACOUNT=0x6ffffff9,
    DT_RELCOUNT=0x6ffffffa,
    DT_FLAGS_1=0x6ffffffb,
    DT_VERDEF=0x6ffffffc,
    DT_VERDEFNUM=0x6ffffffd,
    DT_VERNEED=0x6ffffffe,
    DT_VERNEEDNUM=0x6fffffff,
    DT_AUXILIARY=0x7ffffffd,
    DT_FILTER=0x7fffffff,
    _default_=Pass,
)

ENUM_RELOC_TYPE_i386 = dict(
    R_386_NONE=0,
    R_386_32=1,
    R_386_PC32=2,
    R_386_GOT32=3,
    R_386_PLT32=4,
    R_386_COPY=5,
    R_386_GLOB_DAT=6,
    R_386_JUMP_SLOT=7,
    R_386_RELATIVE=8,
    R_386_GOTOFF=9,
    R_386_GOTPC=10,
    R_386_32PLT=11,
    R_386_TLS_TPOFF=14,
    R_386_TLS_IE=15,
    R_386_TLS_GOTIE=16,
    R_386_TLS_LE=17,
    R_386_TLS_GD=18,
    R_386_TLS_LDM=19,
    R_386_16=20,
    R_386_PC16=21,
    R_386_8=22,
    R_386_PC8=23,
    R_386_TLS_GD_32=24,
    R_386_TLS_GD_PUSH=25,
    R_386_TLS_GD_CALL=26,
    R_386_TLS_GD_POP=27,
    R_386_TLS_LDM_32=28,
    R_386_TLS_LDM_PUSH=29,
    R_386_TLS_LDM_CALL=30,
    R_386_TLS_LDM_POP=31,
    R_386_TLS_LDO_32=32,
    R_386_TLS_IE_32=33,
    R_386_TLS_LE_32=34,
    R_386_TLS_DTPMOD32=35,
    R_386_TLS_DTPOFF32=36,
    R_386_TLS_TPOFF32=37,
    R_386_TLS_GOTDESC=39,
    R_386_TLS_DESC_CALL=40,
    R_386_TLS_DESC=41,
    R_386_IRELATIVE=42,
    R_386_USED_BY_INTEL_200=200,
    R_386_GNU_VTINHERIT=250,
    R_386_GNU_VTENTRY=251,
    _default_=Pass,
)

ENUM_RELOC_TYPE_x64 = dict(
    R_X86_64_NONE=0,
    R_X86_64_64=1,
    R_X86_64_PC32=2,
    R_X86_64_GOT32=3,
    R_X86_64_PLT32=4,
    R_X86_64_COPY=5,
    R_X86_64_GLOB_DAT=6,
    R_X86_64_JUMP_SLOT=7,
    R_X86_64_RELATIVE=8,
    R_X86_64_GOTPCREL=9,
    R_X86_64_32=10,
    R_X86_64_32S=11,
    R_X86_64_16=12,
    R_X86_64_PC16=13,
    R_X86_64_8=14,
    R_X86_64_PC8=15,
    R_X86_64_DTPMOD64=16,
    R_X86_64_DTPOFF64=17,
    R_X86_64_TPOFF64=18,
    R_X86_64_TLSGD=19,
    R_X86_64_TLSLD=20,
    R_X86_64_DTPOFF32=21,
    R_X86_64_GOTTPOFF=22,
    R_X86_64_TPOFF32=23,
    R_X86_64_PC64=24,
    R_X86_64_GOTOFF64=25,
    R_X86_64_GOTPC32=26,
    R_X86_64_GOT64=27,
    R_X86_64_GOTPCREL64=28,
    R_X86_64_GOTPC64=29,
    R_X86_64_GOTPLT64=30,
    R_X86_64_PLTOFF64=31,
    R_X86_64_GOTPC32_TLSDESC=34,
    R_X86_64_TLSDESC_CALL=35,
    R_X86_64_TLSDESC=36,
    R_X86_64_IRELATIVE=37,
    R_X86_64_GNU_VTINHERIT=250,
    R_X86_64_GNU_VTENTRY=251,
    _default_=Pass,
)

# Sunw Syminfo Bound To special values
ENUM_SUNW_SYMINFO_BOUNDTO = dict(
    SYMINFO_BT_SELF=0xffff,
    SYMINFO_BT_PARENT=0xfffe,
    SYMINFO_BT_NONE=0xfffd,
    SYMINFO_BT_EXTERN=0xfffc,
    _default_=Pass,
)

# Versym section, version dependency index 
ENUM_VERSYM = dict(
    VER_NDX_LOCAL=0,
    VER_NDX_GLOBAL=1,
    VER_NDX_LORESERVE=0xff00,
    VER_NDX_ELIMINATE=0xff01,
    _default_=Pass,
)
# Sunw Syminfo Bound To special values
ENUM_SUNW_SYMINFO_BOUNDTO = dict(
    SYMINFO_BT_SELF=0xffff,
    SYMINFO_BT_PARENT=0xfffe,
    SYMINFO_BT_NONE=0xfffd,
    SYMINFO_BT_EXTERN=0xfffc,
    _default_=Pass,
)

ENUM_RELOC_TYPE_ARM = dict(
    R_ARM_NONE=0,
    R_ARM_PC24=1,
    R_ARM_ABS32=2,
    R_ARM_REL32=3,
    R_ARM_LDR_PC_G0=4,
    R_ARM_ABS16=5,
    R_ARM_ABS12=6,
    R_ARM_THM_ABS5=7,
    R_ARM_ABS8=8,
    R_ARM_SBREL32=9,
    R_ARM_THM_CALL=10,
    R_ARM_THM_PC8=11,
    R_ARM_BREL_ADJ=12,
    R_ARM_SWI24=13,
    R_ARM_THM_SWI8=14,
    R_ARM_XPC25=15,
    R_ARM_THM_XPC22=16,
    R_ARM_TLS_DTPMOD32=17,
    R_ARM_TLS_DTPOFF32=18,
    R_ARM_TLS_TPOFF32=19,
    R_ARM_COPY=20,
    R_ARM_GLOB_DAT=21,
    R_ARM_JUMP_SLOT=22,
    R_ARM_RELATIVE=23,
    R_ARM_GOTOFF32=24,
    R_ARM_BASE_PREL=25,
    R_ARM_GOT_BREL=26,
    R_ARM_PLT32=27,
    R_ARM_CALL=28,
    R_ARM_JUMP24=29,
    R_ARM_THM_JUMP24=30,
    R_ARM_BASE_ABS=31,
    R_ARM_ALU_PCREL_7_0=32,
    R_ARM_ALU_PCREL_15_8=33,
    R_ARM_ALU_PCREL_23_15=34,
    R_ARM_LDR_SBREL_11_0_NC=35,
    R_ARM_ALU_SBREL_19_12_NC=36,
    R_ARM_ALU_SBREL_27_20_CK=37,
    R_ARM_TARGET1=38,
    R_ARM_SBREL31=39,
    R_ARM_V4BX=40,
    R_ARM_TARGET2=41,
    R_ARM_PREL31=42,
    R_ARM_MOVW_ABS_NC=43,
    R_ARM_MOVT_ABS=44,
    R_ARM_MOVW_PREL_NC=45,
    R_ARM_MOVT_PREL=46,
    R_ARM_THM_MOVW_ABS_NC=47,
    R_ARM_THM_MOVT_ABS=48,
    R_ARM_THM_MOVW_PREL_NC=49,
    R_ARM_THM_MOVT_PREL=50,
    R_ARM_THM_JUMP19=51,
    R_ARM_THM_JUMP6=52,
    R_ARM_THM_ALU_PREL_11_0=53,
    R_ARM_THM_PC12=54,
    R_ARM_ABS32_NOI=55,
    R_ARM_REL32_NOI=56,
    R_ARM_ALU_PC_G0_NC=57,
    R_ARM_ALU_PC_G0=58,
    R_ARM_ALU_PC_G1_NC=59,
    R_ARM_ALU_PC_G1=60,
    R_ARM_ALU_PC_G2=61,
    R_ARM_LDR_PC_G1=62,
    R_ARM_LDR_PC_G2=63,
    R_ARM_LDRS_PC_G0=64,
    R_ARM_LDRS_PC_G1=65,
    R_ARM_LDRS_PC_G2=66,
    R_ARM_LDC_PC_G0=67,
    R_ARM_LDC_PC_G1=68,
    R_ARM_LDC_PC_G2=69,
    R_ARM_ALU_SB_G0_NC=70,
    R_ARM_ALU_SB_G0=71,
    R_ARM_ALU_SB_G1_NC=72,
    R_ARM_ALU_SB_G1=73,
    R_ARM_ALU_SB_G2=74,
    R_ARM_LDR_SB_G0=75,
    R_ARM_LDR_SB_G1=76,
    R_ARM_LDR_SB_G2=77,
    R_ARM_LDRS_SB_G0=78,
    R_ARM_LDRS_SB_G1=79,
    R_ARM_LDRS_SB_G2=80,
    R_ARM_LDC_SB_G0=81,
    R_ARM_LDC_SB_G1=82,
    R_ARM_LDC_SB_G2=83,
    R_ARM_MOVW_BREL_NC=84,
    R_ARM_MOVT_BREL=85,
    R_ARM_MOVW_BREL=86,
    R_ARM_THM_MOVW_BREL_NC=87,
    R_ARM_THM_MOVT_BREL=88,
    R_ARM_THM_MOVW_BREL=89,
    R_ARM_PLT32_ABS=94,
    R_ARM_GOT_ABS=95,
    R_ARM_GOT_PREL=96,
    R_ARM_GOT_BREL12=97,
    R_ARM_GOTOFF12=98,
    R_ARM_GOTRELAX=99,
    R_ARM_GNU_VTENTRY=100,
    R_ARM_GNU_VTINHERIT=101,
    R_ARM_THM_JUMP11=102,
    R_ARM_THM_JUMP8=103,
    R_ARM_TLS_GD32=104,
    R_ARM_TLS_LDM32=105,
    R_ARM_TLS_LDO32=106,
    R_ARM_TLS_IE32=107,
    R_ARM_TLS_LE32=108,
    R_ARM_TLS_LDO12=109,
    R_ARM_TLS_LE12=110,
    R_ARM_TLS_IE12GP=111,
    R_ARM_PRIVATE_0=112,
    R_ARM_PRIVATE_1=113,
    R_ARM_PRIVATE_2=114,
    R_ARM_PRIVATE_3=115,
    R_ARM_PRIVATE_4=116,
    R_ARM_PRIVATE_5=117,
    R_ARM_PRIVATE_6=118,
    R_ARM_PRIVATE_7=119,
    R_ARM_PRIVATE_8=120,
    R_ARM_PRIVATE_9=121,
    R_ARM_PRIVATE_10=122,
    R_ARM_PRIVATE_11=123,
    R_ARM_PRIVATE_12=124,
    R_ARM_PRIVATE_13=125,
    R_ARM_PRIVATE_14=126,
    R_ARM_PRIVATE_15=127,
    R_ARM_ME_TOO=128,
    R_ARM_THM_TLS_DESCSEQ16=129,
    R_ARM_THM_TLS_DESCSEQ32=130,
    R_ARM_THM_GOT_BREL12=131,
    R_ARM_IRELATIVE=140,
)

ENUM_RELOC_TYPE_AARCH64 = dict(
    R_AARCH64_NONE=256,
    R_AARCH64_ABS64=257,
    R_AARCH64_ABS32=258,
    R_AARCH64_ABS16=259,
    R_AARCH64_PREL64=260,
    R_AARCH64_PREL32=261,
    R_AARCH64_PREL16=262,
    R_AARCH64_MOVW_UABS_G0=263,
    R_AARCH64_MOVW_UABS_G0_NC=264,
    R_AARCH64_MOVW_UABS_G1=265,
    R_AARCH64_MOVW_UABS_G1_NC=266,
    R_AARCH64_MOVW_UABS_G2=267,
    R_AARCH64_MOVW_UABS_G2_NC=268,
    R_AARCH64_MOVW_UABS_G3=269,
    R_AARCH64_MOVW_SABS_G0=270,
    R_AARCH64_MOVW_SABS_G1=271,
    R_AARCH64_MOVW_SABS_G2=272,
    R_AARCH64_LD_PREL_LO19=273,
    R_AARCH64_ADR_PREL_LO21=274,
    R_AARCH64_ADR_PREL_PG_HI21=275,
    R_AARCH64_ADR_PREL_PG_HI21_NC=276,
    R_AARCH64_ADD_ABS_LO12_NC=277,
    R_AARCH64_LDST8_ABS_LO12_NC=278,
    R_AARCH64_TSTBR14=279,
    R_AARCH64_CONDBR19=280,
    R_AARCH64_JUMP26=282,
    R_AARCH64_CALL26=283,
    R_AARCH64_LDST16_ABS_LO12_NC=284,
    R_AARCH64_LDST32_ABS_LO12_NC=285,
    R_AARCH64_LDST64_ABS_LO12_NC=286,
    R_AARCH64_MOVW_PREL_G0=287,
    R_AARCH64_MOVW_PREL_G0_NC=288,
    R_AARCH64_MOVW_PREL_G1=289,
    R_AARCH64_MOVW_PREL_G1_NC=290,
    R_AARCH64_MOVW_PREL_G2=291,
    R_AARCH64_MOVW_PREL_G2_NC=292,
    R_AARCH64_MOVW_PREL_G3=293,
    R_AARCH64_MOVW_GOTOFF_G0=300,
    R_AARCH64_MOVW_GOTOFF_G0_NC=301,
    R_AARCH64_MOVW_GOTOFF_G1=302,
    R_AARCH64_MOVW_GOTOFF_G1_NC=303,
    R_AARCH64_MOVW_GOTOFF_G2=304,
    R_AARCH64_MOVW_GOTOFF_G2_NC=305,
    R_AARCH64_MOVW_GOTOFF_G3=306,
    R_AARCH64_GOTREL64=307,
    R_AARCH64_GOTREL32=308,
    R_AARCH64_GOT_LD_PREL19=309,
    R_AARCH64_LD64_GOTOFF_LO15=310,
    R_AARCH64_ADR_GOT_PAGE=311,
    R_AARCH64_LD64_GOT_LO12_NC=312,
    R_AARCH64_TLSGD_ADR_PREL21=512,
    R_AARCH64_TLSGD_ADR_PAGE21=513,
    R_AARCH64_TLSGD_ADD_LO12_NC=514,
    R_AARCH64_TLSGD_MOVW_G1=515,
    R_AARCH64_TLSGD_MOVW_G0_NC=516,
    R_AARCH64_TLSLD_ADR_PREL21=517,
    R_AARCH64_TLSLD_ADR_PAGE21=518,
    R_AARCH64_TLSLD_ADD_LO12_NC=519,
    R_AARCH64_TLSLD_MOVW_G1=520,
    R_AARCH64_TLSLD_MOVW_G0_NC=521,
    R_AARCH64_TLSLD_LD_PREL19=522,
    R_AARCH64_TLSLD_MOVW_DTPREL_G2=523,
    R_AARCH64_TLSLD_MOVW_DTPREL_G1=524,
    R_AARCH64_TLSLD_MOVW_DTPREL_G1_NC=525,
    R_AARCH64_TLSLD_MOVW_DTPREL_G0=526,
    R_AARCH64_TLSLD_MOVW_DTPREL_G0_NC=527,
    R_AARCH64_TLSLD_ADD_DTPREL_HI12=528,
    R_AARCH64_TLSLD_ADD_DTPREL_LO12=529,
    R_AARCH64_TLSLD_ADD_DTPREL_LO12_NC=530,
    R_AARCH64_TLSLD_LDST8_DTPREL_LO12=531,
    R_AARCH64_TLSLD_LDST8_DTPREL_LO12_NC=532,
    R_AARCH64_TLSLD_LDST16_DTPREL_LO12=533,
    R_AARCH64_TLSLD_LDST16_DTPREL_LO12_NC=534,
    R_AARCH64_TLSLD_LDST32_DTPREL_LO12=535,
    R_AARCH64_TLSLD_LDST32_DTPREL_LO12_NC=536,
    R_AARCH64_TLSLD_LDST64_DTPREL_LO12=537,
    R_AARCH64_TLSLD_LDST64_DTPREL_LO12_NC=538,
    R_AARCH64_TLSIE_MOVW_GOTTPREL_G1=539,
    R_AARCH64_TLSIE_MOVW_GOTTPREL_G0_NC=540,
    R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21=541,
    R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC=542,
    R_AARCH64_TLSIE_LD_GOTTPREL_PREL19=543,
    R_AARCH64_TLSLE_MOVW_TPREL_G2=544,
    R_AARCH64_TLSLE_MOVW_TPREL_G1=545,
    R_AARCH64_TLSLE_MOVW_TPREL_G1_NC=546,
    R_AARCH64_TLSLE_MOVW_TPREL_G0=547,
    R_AARCH64_TLSLE_MOVW_TPREL_G0_NC=548,
    R_AARCH64_TLSLE_ADD_TPREL_HI12=549,
    R_AARCH64_TLSLE_ADD_TPREL_LO12=550,
    R_AARCH64_TLSLE_ADD_TPREL_LO12_NC=551,
    R_AARCH64_TLSLE_LDST8_TPREL_LO12=552,
    R_AARCH64_TLSLE_LDST8_TPREL_LO12_NC=553,
    R_AARCH64_TLSLE_LDST16_TPREL_LO12=554,
    R_AARCH64_TLSLE_LDST16_TPREL_LO12_NC=555,
    R_AARCH64_TLSLE_LDST32_TPREL_LO12=556,
    R_AARCH64_TLSLE_LDST32_TPREL_LO12_NC=557,
    R_AARCH64_TLSLE_LDST64_TPREL_LO12=558,
    R_AARCH64_TLSLE_LDST64_TPREL_LO12_NC=559,
    R_AARCH64_COPY=1024,
    R_AARCH64_GLOB_DAT=1025,
    R_AARCH64_JUMP_SLOT=1026,
    R_AARCH64_RELATIVE=1027,
    R_AARCH64_TLS_DTPREL64=1028,
    R_AARCH64_TLS_DTPMOD64=1029,
    R_AARCH64_TLS_TPREL64=1030,
    R_AARCH64_TLS_DTPREL32=1031,
    R_AARCH64_TLS_DTPMOD32=1032,
    R_AARCH64_TLS_TPREL32=1033,
)
