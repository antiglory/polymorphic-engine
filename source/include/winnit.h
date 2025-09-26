#ifndef WINNIT_H
#define WINNIT_H

// PE structure definitions (subset of winnt.h adapted for linux)
#define IMAGE_DOS_SIGNATURE 0x5A4D      // MZ
#define IMAGE_NT_SIGNATURE  0x00004550  // PE00

typedef struct _IMAGE_DOS_HEADER
{
    uint16_t e_magic;       // magic number
    uint16_t e_cblp;        // bytes on last page of file
    uint16_t e_cp;          // pages in file
    uint16_t e_crlc;        // relocations
    uint16_t e_cparhdr;     // size of header in paragraphs
    uint16_t e_minalloc;    // minimum extra paragraphs needed
    uint16_t e_maxalloc;    // maximum extra paragraphs needed
    uint16_t e_ss;          // initial (relative) SS value
    uint16_t e_sp;          // initial SP value
    uint16_t e_csum;        // checksum
    uint16_t e_ip;          // initial IP value (entrypoint)
    uint16_t e_cs;          // initial (relative) CS value
    uint16_t e_lfarlc;      // file address of relocation table
    uint16_t e_ovno;        // overlay number
    uint16_t e_res[4];      // reserved words
    uint16_t e_oemid;       // OEM identifier (for e_oeminfo)
    uint16_t e_oeminfo;     // OEM information; e_oemid specific
    uint16_t e_res2[10];    // reserved words
    uint32_t e_lfanew;      // file address of new exe header
} IMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER
{
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} IMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY
{
    uint32_t VirtualAddress;
    uint32_t Size;
} IMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

typedef struct _IMAGE_OPTIONAL_HEADER32
{
    uint16_t magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t dll_characteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_OPTIONAL_HEADER64
{
    uint16_t magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t dll_characteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64;

#define IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE 0x0040
#define IMAGE_NT_OPTIONAL_HDR32_MAGIC         0x10b
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC         0x20b

typedef struct _IMAGE_SECTION_HEADER
{
    uint8_t  Name[8];
    union
    {
        uint32_t PhysicalAddress;
        uint32_t VirtualSize;
    } Misc;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} IMAGE_SECTION_HEADER;

// section characteristics
#define IMAGE_SCN_CNT_CODE               0x00000020
#define IMAGE_SCN_CNT_INITIALIZED_DATA   0x00000040
#define IMAGE_SCN_MEM_EXECUTE            0x20000000
#define IMAGE_SCN_MEM_READ               0x40000000

typedef struct _IMAGE_NT_HEADERS32
{
    uint32_t signature;
    IMAGE_FILE_HEADER file_header;              // COFF file header
    IMAGE_OPTIONAL_HEADER32 optional_header;
} IMAGE_NT_HEADERS32;

typedef struct _IMAGE_NT_HEADERS64
{
    uint32_t signature;
    IMAGE_FILE_HEADER file_header;              // COFF file header
    IMAGE_OPTIONAL_HEADER64 optional_header;
} IMAGE_NT_HEADERS64;

#endif