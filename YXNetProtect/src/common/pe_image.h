// BanJiu-Guard - 可移植 PE（Portable Executable）结构定义
// 仅在非 Windows 平台使用：提供启发式引擎 / ML 特征提取所需的最小 PE 结构与常量，
// 布局与 Windows SDK winnt.h 严格一致（x64 视角，与 Windows 版 IMAGE_NT_HEADERS 保持等价，
// 确保同一文件在两个平台上提取的特征完全相同）。
#pragma once

#ifndef _WIN32

#include <cstdint>
#include "yx_win_compat.h"

// ---- 签名 / 魔数 ----
#define IMAGE_DOS_SIGNATURE             0x5A4D      // "MZ"
#define IMAGE_NT_SIGNATURE              0x00004550  // "PE\0\0"
#define IMAGE_NT_OPTIONAL_HDR32_MAGIC   0x10b
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC   0x20b

// ---- 目录索引 ----
#define IMAGE_DIRECTORY_ENTRY_EXPORT      0
#define IMAGE_DIRECTORY_ENTRY_IMPORT      1
#define IMAGE_DIRECTORY_ENTRY_RESOURCE    2
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION   3
#define IMAGE_DIRECTORY_ENTRY_SECURITY    4
#define IMAGE_DIRECTORY_ENTRY_BASERELOC   5
#define IMAGE_DIRECTORY_ENTRY_DEBUG       6
#define IMAGE_DIRECTORY_ENTRY_TLS         9

// ---- 节区特征 ----
#define IMAGE_SCN_MEM_EXECUTE  0x20000000
#define IMAGE_SCN_MEM_READ     0x40000000
#define IMAGE_SCN_MEM_WRITE    0x80000000

// ---- 导入序号标记 ----
#define IMAGE_ORDINAL_FLAG32   0x80000000u
#define IMAGE_ORDINAL_FLAG64   0x8000000000000000ull

// ---- 资源树 ----
#define IMAGE_RESOURCE_DATA_IS_DIRECTORY 0x80000000u

#pragma pack(push, 1)

typedef struct _IMAGE_DOS_HEADER {
    WORD   e_magic;
    WORD   e_cblp, e_cp, e_crlc, e_cparhdr, e_minalloc, e_maxalloc;
    WORD   e_ss, e_sp, e_csum, e_ip, e_cs, e_lfarlc, e_ovno;
    WORD   e_res[4];
    WORD   e_oemid, e_oeminfo;
    WORD   e_res2[10];
    LONG   e_lfanew;
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
    WORD   Machine;
    WORD   NumberOfSections;
    DWORD  TimeDateStamp;
    DWORD  PointerToSymbolTable;
    DWORD  NumberOfSymbols;
    WORD   SizeOfOptionalHeader;
    WORD   Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD  VirtualAddress;
    DWORD  Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    WORD   Magic;
    BYTE   MajorLinkerVersion;
    BYTE   MinorLinkerVersion;
    DWORD  SizeOfCode;
    DWORD  SizeOfInitializedData;
    DWORD  SizeOfUninitializedData;
    DWORD  AddressOfEntryPoint;
    DWORD  BaseOfCode;
    ULONGLONG ImageBase;
    DWORD  SectionAlignment;
    DWORD  FileAlignment;
    WORD   MajorOperatingSystemVersion;
    WORD   MinorOperatingSystemVersion;
    WORD   MajorImageVersion;
    WORD   MinorImageVersion;
    WORD   MajorSubsystemVersion;
    WORD   MinorSubsystemVersion;
    DWORD  Win32VersionValue;
    DWORD  SizeOfImage;
    DWORD  SizeOfHeaders;
    DWORD  CheckSum;
    WORD   Subsystem;
    WORD   DllCharacteristics;
    ULONGLONG SizeOfStackReserve;
    ULONGLONG SizeOfStackCommit;
    ULONGLONG SizeOfHeapReserve;
    ULONGLONG SizeOfHeapCommit;
    DWORD  LoaderFlags;
    DWORD  NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64 {
    DWORD                Signature;
    IMAGE_FILE_HEADER    FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

// 与 Windows x64 下 PIMAGE_NT_HEADERS 等价（均为 64 位视角）
typedef IMAGE_NT_HEADERS64        IMAGE_NT_HEADERS;
typedef IMAGE_NT_HEADERS64*       PIMAGE_NT_HEADERS;

typedef struct _IMAGE_SECTION_HEADER {
    BYTE   Name[8];
    union {
        DWORD PhysicalAddress;
        DWORD VirtualSize;
    } Misc;
    DWORD  VirtualAddress;
    DWORD  SizeOfRawData;
    DWORD  PointerToRawData;
    DWORD  PointerToRelocations;
    DWORD  PointerToLinenumbers;
    WORD   NumberOfRelocations;
    WORD   NumberOfLinenumbers;
    DWORD  Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        DWORD Characteristics;
        DWORD OriginalFirstThunk;
    };
    DWORD  TimeDateStamp;
    DWORD  ForwarderChain;
    DWORD  Name;
    DWORD  FirstThunk;
} IMAGE_IMPORT_DESCRIPTOR, *PIMAGE_IMPORT_DESCRIPTOR;

typedef struct _IMAGE_IMPORT_BY_NAME {
    WORD   Hint;
    char   Name[1];
} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;

typedef struct _IMAGE_THUNK_DATA32 {
    union {
        DWORD ForwarderString;
        DWORD Function;
        DWORD Ordinal;
        DWORD AddressOfData;
    } u1;
} IMAGE_THUNK_DATA32, *PIMAGE_THUNK_DATA32;

typedef struct _IMAGE_THUNK_DATA64 {
    union {
        ULONGLONG ForwarderString;
        ULONGLONG Function;
        ULONGLONG Ordinal;
        ULONGLONG AddressOfData;
    } u1;
} IMAGE_THUNK_DATA64, *PIMAGE_THUNK_DATA64;

typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD  Characteristics;
    DWORD  TimeDateStamp;
    WORD   MajorVersion;
    WORD   MinorVersion;
    DWORD  Name;
    DWORD  Base;
    DWORD  NumberOfFunctions;
    DWORD  NumberOfNames;
    DWORD  AddressOfFunctions;
    DWORD  AddressOfNames;
    DWORD  AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

typedef struct _IMAGE_RESOURCE_DIRECTORY {
    WORD   Characteristics;
    WORD   TimeDateStamp;
    WORD   MajorVersion;
    WORD   MinorVersion;
    WORD   NumberOfNamedEntries;
    WORD   NumberOfIdEntries;
} IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;

typedef struct _IMAGE_RESOURCE_DIRECTORY_ENTRY {
    union {
        struct {
            DWORD NameOffset : 31;
            DWORD NameIsString : 1;
        };
        DWORD Name;
        WORD   Id;
    };
    union {
        DWORD OffsetToData;
        struct {
            DWORD OffsetToDirectory : 31;
            DWORD DataIsDirectory : 1;
        };
    };
} IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;

typedef struct _IMAGE_DEBUG_DIRECTORY {
    DWORD  Characteristics;
    DWORD  TimeDateStamp;
    WORD   MajorVersion;
    WORD   MinorVersion;
    DWORD  Type;
    DWORD  SizeOfData;
    DWORD  AddressOfRawData;
    DWORD  PointerToRawData;
} IMAGE_DEBUG_DIRECTORY, *PIMAGE_DEBUG_DIRECTORY;

#pragma pack(pop)

// 可选头之后紧跟节区表（与 winnt.h 宏等价）
#ifndef IMAGE_FIRST_SECTION
#define IMAGE_FIRST_SECTION(ntheader) \
    ((PIMAGE_SECTION_HEADER)((uint8_t*)(ntheader) + \
     offsetof(IMAGE_NT_HEADERS, OptionalHeader) + \
     ((PIMAGE_NT_HEADERS)(ntheader))->FileHeader.SizeOfOptionalHeader))
#endif

#endif // !_WIN32
