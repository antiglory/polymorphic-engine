// polymorphic engine
// g++ -mrdseed -lssl -lcrypto -O3 -Wall -Wextra -o output/mutate mutate.cpp && ./output/mutate output/sync.exe

// behavior (fix it by TODO 1): after injecting new instructions, all .text layout after that injection point is shifted by 1

// TODO implementar pra ou adicionar e remover instrução sem mudar o tamanho da .text
// TODO também vou implementar pra mutar instrução por instrução equivalente - e.q: NOP -> XCHG eax, eax - mas botar algoritmo pra sempre tentar não mudar muito o tamanho da .text
// TODO find_architecture() e adaptar todas as funcoes pra parsear a arquitetura (32 ou 64)
// TODO find_ghost_code() e find_routine_starts()

// not safe with PIE binaries -> injecting/removing/changing size of instructions may harm relative calculations of other objects made by the binary compiler

// abre o binario (open_binary, detect_binary_format) -> seta a text (find_text, find_text_size) -> procura ghost code nela (find_ghost_code) -> se sim -> remove os old (remove_old_code) -> detecta começos e fim de rotina (find_routine_starts, find_routine_end) -> aleatoriza se vai colocar em lugar aleatorio na rotina ou colocar nos começos ou nos finais (randomize_code_position) -> coloca (new_code)
// abre o binario (open_binary, detect_binary_format) -> seta a text (find_text. find_text_size) -> procura ghost code nela (find_ghost_code) -> se não -> detecta começos e fim de rotina (find_routine_starts, find_routine_end) -> aleatoriza se vai colocar em lugar aleatorio na rotina ou colocar nos começos ou nos finais (randomize_code_position) -> coloca (reorder_code)

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <err.h>
#include <fcntl.h>
#include <elf.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>
#include <immintrin.h>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <cpuid.h>

#include "include/entropy.c"
#include "include/winnt.h"

typedef int file_t;

static int32_t safe_read(file_t file_descriptor, void* buffer, size_t count, off_t offset, off_t file_size)
{
    if (offset < 0 || offset + count > file_size) return -1;
    if (lseek(file_descriptor, offset, SEEK_SET) != offset) return -1;
    if (read(file_descriptor, buffer, count) != count) return -1;

    return 0;
}

int32_t detect_pie(file_t file_descriptor)
{
    /* 
    0  -> non-PIE like
    1  -> PIE like
    -1 -> error
    */

    IMAGE_DOS_HEADER dos_header;
    IMAGE_NT_HEADERS64 nt_headers;
    ssize_t bytes_read;
    
    // read DOS header
    if (lseek(file_descriptor, 0, SEEK_SET) == -1) return -1;
    
    bytes_read = read(file_descriptor, &dos_header, sizeof(IMAGE_DOS_HEADER));
    if (bytes_read != sizeof(IMAGE_DOS_HEADER)) return -1;
    
    // verify DOS signature
    if (dos_header.e_magic != IMAGE_DOS_SIGNATURE) return -1;
    
    // seek to NT headers
    if (lseek(file_descriptor, dos_header.e_lfanew, SEEK_SET) == -1) return -1;
    
    // read NT headers
    bytes_read = read(file_descriptor, &nt_headers, sizeof(IMAGE_NT_HEADERS64));
    if (bytes_read != sizeof(IMAGE_NT_HEADERS64)) return -1;
    
    // verify NT signature
    if (nt_headers.signature != IMAGE_NT_SIGNATURE) return -1; // not a valid PE file
    
    // check if its a 32 bit PE
    if (nt_headers.optional_header.magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        IMAGE_NT_HEADERS32 nt_headers32;
    
        if (lseek(file_descriptor, dos_header.e_lfanew, SEEK_SET) == -1) return -1;
        
        bytes_read = read(file_descriptor, &nt_headers32, sizeof(IMAGE_NT_HEADERS32));
        if (bytes_read != sizeof(IMAGE_NT_HEADERS32)) return -1;
        
        if (!(nt_headers32.optional_header.dll_characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)) return 1; // non-PIE (DYNAMIC_BASE flag not set)
    } else if (nt_headers.optional_header.magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        if (!(nt_headers.optional_header.dll_characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)) return 1; // non-PIE (DYNAMIC_BASE flag not set)
    else return -1;
    
    return 0; // PIE enabled (DYNAMIC_BASE flag is set)
}

file_t open_binary(const char* path)
{
    file_t file_descriptor;
    struct stat file_stat;
    
    if (access(path, F_OK) != 0) { fprintf(stderr, "[!] \"%s\": file not found\n", path); return -1; }
    if (access(path, R_OK) != 0) { fprintf(stderr, "[!] \"%s\" missing read permissions\n", path); return -1;}
    
    file_descriptor = open(path, O_RDONLY);
    if (file_descriptor < 0) { perror("[!] cannot open binary"); return -1; }
    
    if (fstat(file_descriptor, &file_stat) < 0) { perror("[!] cannot get binary stats"); close(file_descriptor); return -1; }
    if (!S_ISREG(file_stat.st_mode)) { fprintf(stderr, "[!] \"%s\" is not a regular binary\n", path); close(file_descriptor); return -1; }
    
    bool non_pie_binary = detect_pie(file_descriptor);
    if (non_pie_binary != 0)
    {
        char user_input[32];

        printf("[#] PIE-like binary detected, mutate anyway? "); 

        fgets(user_input, sizeof(user_input), stdin);
        user_input[strcspn(user_input, "\n")] = 0;

        if (strcmp(user_input, "y") == 0 || strcmp(user_input, "yes") == 0) goto OPEN_BINARY_ENDOF;
        else { close(file_descriptor); return -1; }
    }
OPEN_BINARY_ENDOF:
    printf("[+] opened \"%s\"\n", path);
    printf("[*] this binary is %ld long\n", file_stat.st_size);
    
    return file_descriptor;
}

typedef enum
{
    BIN_UNKNOWN,
    BIN_ELF,
    BIN_PE
} binary_format_t;

binary_format_t detect_binary_format(file_t file_descriptor)
{
    uint8_t magic[4];

    if (lseek(file_descriptor, 0, SEEK_SET) == -1) return BIN_UNKNOWN;

    ssize_t n = read(file_descriptor, magic, sizeof(magic));
    if (n != sizeof(magic)) { printf("[!] unknow binary format\n"); return BIN_UNKNOWN; };

    if (magic[0] == 0x7F && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F') return BIN_ELF;
    if (magic[0] == 'M' && magic[1] == 'Z') return BIN_PE;

    return BIN_UNKNOWN;
}

uintptr_t* find_text(file_t file_descriptor, binary_format_t binary_format)
{
    if (binary_format == BIN_ELF) return NULL; // TODO
    else if (binary_format == BIN_PE)
    {
        /*
        if PE:
            - PE is basically: DOS header (IMAGE_DOS_HEADER), e_lfanew -> NT headers (IMAGE_NT_HEADERS), IMAGE_FILE_HEADER, IMAGE_OPTIONAL_HEADER, IMAGE_SECTION_HEADER, IMAGE_DATA_DIRECTORY
            - there isnt this headers in linux; i can set the structures myself (or copy from winnt.h). needed fields:
                - jumps to e_lfanew (DWORD) and validates "PE\0\0"
                - read IMAGE_FILE_HEADER and IMAGE_OPTIONAL_HEADER (to know if it is 32 or 64 bits)
        */
        struct stat file_stat;
        
        if (fstat(file_descriptor, &file_stat) < 0) { close(file_descriptor); return NULL; }

        off_t file_size = file_stat.st_size;
        
        // read DOS header
        IMAGE_DOS_HEADER dos_header;
        if (safe_read(file_descriptor, &dos_header, sizeof(IMAGE_DOS_HEADER), 0, file_size) < 0) { close(file_descriptor); return NULL; }
        
        // verify DOS signature
        if (dos_header.e_magic != IMAGE_DOS_SIGNATURE) { close(file_descriptor); return NULL; }
        
        // check e_lfanew is within bounds
        if (dos_header.e_lfanew <= 0 || dos_header.e_lfanew + 4 > file_size) { close(file_descriptor); return NULL; }
        
        // read and verify PE signature
        uint32_t pe_signature;
        if (safe_read(file_descriptor, &pe_signature, sizeof(uint32_t), dos_header.e_lfanew, file_size) < 0) { close(file_descriptor); return NULL; }
        
        if (pe_signature != IMAGE_NT_SIGNATURE) { close(file_descriptor); return NULL; }
        
        // read IMAGE_FILE_HEADER
        IMAGE_FILE_HEADER file_header;
        off_t file_header_offset = dos_header.e_lfanew + 4;
        if (safe_read(file_descriptor, &file_header, sizeof(IMAGE_FILE_HEADER), file_header_offset, file_size) < 0) { close(file_descriptor); return NULL; }
        
        // read magic number to determine 32 vs 64 bit
        uint16_t magic;
        off_t optional_header_offset = file_header_offset + sizeof(IMAGE_FILE_HEADER);
        if (safe_read(file_descriptor, &magic, sizeof(uint16_t), optional_header_offset, file_size) < 0) { close(file_descriptor); return NULL; }
        
        off_t section_headers_offset;
        
        if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        {
            // 32-bit PE
            IMAGE_OPTIONAL_HEADER32 opt_header;
            if (safe_read(file_descriptor, &opt_header, sizeof(IMAGE_OPTIONAL_HEADER32), optional_header_offset, file_size) < 0)
            { 
                close(file_descriptor);
                return NULL;
            }

            section_headers_offset = optional_header_offset + file_header.SizeOfOptionalHeader;
        } else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        {
            // 64-bit PE
            IMAGE_OPTIONAL_HEADER64 opt_header;
            if (safe_read(file_descriptor, &opt_header, sizeof(IMAGE_OPTIONAL_HEADER64), optional_header_offset, file_size) < 0)
            {
                close(file_descriptor);
                return NULL;
            }

            section_headers_offset = optional_header_offset + file_header.SizeOfOptionalHeader;
        } else
        {
            close(file_descriptor);
            return NULL;
        }
        
        // look for .text section in section headers
        for (int32_t i = 0; i < file_header.NumberOfSections; i++)
        {
            IMAGE_SECTION_HEADER section;
            off_t section_offset = section_headers_offset + (i * sizeof(IMAGE_SECTION_HEADER));
            
            if (safe_read(file_descriptor, &section, sizeof(IMAGE_SECTION_HEADER), section_offset, file_size) < 0)
                continue;
            
            // check if this is the .text section
            if (strncmp((char*)section.Name, ".text", 5) == 0 ||
               (section.Characteristics & IMAGE_SCN_CNT_CODE) != 0
            ) {
                // allocate memory for return value (physical offset and size)
                uintptr_t* result = (uintptr_t*)malloc(2 * sizeof(uintptr_t));
                if (result == NULL) { close(file_descriptor); return NULL; }
                
                // return the physical file offset and size
                result[0] = section.PointerToRawData;  // physical offset in file
                result[1] = section.SizeOfRawData;     // physical size in file
                
                close(file_descriptor);

                return result;
            }
        }
        
        close(file_descriptor);
        return NULL;
    } else // unreachable
    {
        close(file_descriptor);
        return NULL;
    }
    
    return NULL;
}

size_t find_text_size(file_t file_descriptor)
{
    IMAGE_DOS_HEADER dos_header;
    IMAGE_NT_HEADERS64 nt_headers;
    IMAGE_SECTION_HEADER section_header;
    size_t text_size = 0;
    off_t current_pos;

    current_pos = lseek(file_descriptor, 0, SEEK_CUR);
    if (current_pos < 0) { perror("[!] cannot get current file position"); return 1; }
    
    if (lseek(file_descriptor, 0, SEEK_SET) < 0) { perror("[!] cannot seek to beginning of file"); return 1; }
    
    if (read(file_descriptor, &dos_header, sizeof(IMAGE_DOS_HEADER)) != sizeof(IMAGE_DOS_HEADER)) { fprintf(stderr, "[!] cannot read DOS header\n"); goto cleanup; }
    
    if (dos_header.e_magic != IMAGE_DOS_SIGNATURE) { fprintf(stderr, "[!] invalid DOS signature\n"); goto cleanup; }

    if (lseek(file_descriptor, dos_header.e_lfanew, SEEK_SET) < 0) { perror("[!] cannot seek to NT header"); goto cleanup; } 

    if (read(file_descriptor, &nt_headers, sizeof(IMAGE_NT_HEADERS64)) != sizeof(IMAGE_NT_HEADERS64)) { fprintf(stderr, "[!] cannot read NT headers\n"); goto cleanup; }
    
    if (nt_headers.signature != IMAGE_NT_SIGNATURE) { fprintf(stderr, "[!] invalid PE signature\n"); goto cleanup; }
    
    for (int i = 0; i < nt_headers.file_header.NumberOfSections; i++)
    {
        if (read(file_descriptor, &section_header, sizeof(IMAGE_SECTION_HEADER)) != sizeof(IMAGE_SECTION_HEADER)) { fprintf(stderr, "[!] cannot read section header %d\n", i); goto cleanup; }
        
        if (strncmp((char*)section_header.Name, ".text", 5) == 0)
        {
            text_size = section_header.SizeOfRawData;

            printf("[+] found .text, raw size = %u\n", section_header.SizeOfRawData);

            break;
        }
    }
    
    if (text_size == 0)
        fprintf(stderr, "[!] .text section not found\n");
cleanup:
    lseek(file_descriptor, current_pos, SEEK_SET);
    return text_size;
}

void find_routine_start();
void find_routine_end();

void find_ghost_code(/*text_start, text_size*/)
{
    // recebe o offset que começa a .text no arquivo fisico já aberto
    // itera sobre todos os opcodes buscando por patterns de ghost instruction conhecidos pela engine
    // quando encontrar, salva numa estrutura o endereço onde tá esse opcode, o opcode correspondente e salva uma contagem de todos os encontrados
}

void new_code();
void reorder_code();

typedef struct
{
    file_t file_descriptor;
    binary_format_t binary_format;
    bool binary_arch; // TODO 0 -> 32, 1 -> 64
    uintptr_t* text_start;
    size_t text_size;
} binary_t;

int32_t main(const int argc, const char* argv[])
{
    if (argc < 2) { printf("[!] usage: ./engine <binary>\n"); return 1; }

    clock_t start = clock();

    binary_t* binary = (binary_t*)malloc(sizeof(binary_t));
    if (!binary) return 1;

    binary->file_descriptor = open_binary(argv[1]);
    if (!binary->file_descriptor || binary->file_descriptor == -1) return 1;
    binary->binary_format = detect_binary_format(binary->file_descriptor);
    if (!binary->binary_format || binary->binary_format == BIN_UNKNOWN) { close(binary->file_descriptor); return 1; }

    binary->text_size = find_text_size(binary->file_descriptor);
    if (!binary->text_size) { close(binary->file_descriptor); return 1; }
    binary->text_start = find_text(binary->file_descriptor, binary->binary_format);
    if (!binary->text_start) { close(binary->file_descriptor); return 1; }

    printf("[*] .text is at physical offset <0x%lx>, size <0x%lx>\n", binary->text_start[0], binary->text_start[1]);
    
    // ...
    
    /* 
    // idea - pseudocode:
    routine_starts = find_routine_starts();
    routine_ends = find_routine_end();

    found_ghost_code = find_ghost_code(binary->text_start, binary->text_size); // struct that holds if ghost code was found and all ghost code found
    generated_code_position = randomize_code_position(routine_starts, routine_ends);

    if (found_ghost_code == yes)
    {
        remove_old_code(binary->text_start);
        reorder_code(routine_starts, routine_ends, generated_code_position);
    } else if (found_ghost_code == yes)
        new_code(routine_starts, routine_ends, generated_code_position);
    */

    clock_t end = clock();

    double cpu_time = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("[*] time elapsed: %.3f seconds\n", cpu_time);

    close(binary->file_descriptor);
    free(binary);

    return 0;
}

