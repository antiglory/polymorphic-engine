// polymorphic engine

// TODO terminar de adaptar pra C++ oque tiver

// not safe with PIE binaries -> injecting/removing/changing size of instructions may harm relative calculations of other objects made by the binary compiler, etc

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <err.h>
#include <fcntl.h>
#include <elf.h>
#include <unistd.h>
#include <time.h>
#include <cpuid.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <openssl/sha.h>
#include <nlohmann/json.hpp>
#include <immintrin.h>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <vector>
#include <algorithm>
#include <iostream>

#include "include/entropy.c"
#include "include/winnt.h"

#define MAX_MUTATION_ATTEMPTS 256
#define USER_INPUT_SIZE 32

typedef int32_t file_t;

using json = nlohmann::json;

/* Read <count> bytes from a file in disk
 * @param file_descriptor File descriptor to opened binary
 * @param buffer Output buffer to readed bytes
 * @param count Num of bytes to read 
 * @param offset Where to start reading
 * @param file_size File size to avoid overflow
 * @return int32_t Return code - success (0) or error (-1)
 */
static int32_t safe_read(file_t file_descriptor, void* buffer, off_t count, off_t offset, off_t file_size)
{
    if (offset < 0 || offset + count > file_size) return -1;
    if (lseek(file_descriptor, offset, SEEK_SET) != offset) return -1;
    if (read(file_descriptor, buffer, count) != count) return -1;

    return 0;
}

struct stat file_stat;

/* Opens a binary in disk 
 * @param binary_path Binary path in disk
 * @return file_t (aka int) File descriptor to reference an IO object -> the binary in disk
 */
static file_t open_binary(const char* binary_path)
{
    file_t file_descriptor;
    
    if (access(binary_path, F_OK) != 0) { fprintf(stderr, "[!] \"%s\": file not found\n", binary_path); return -1; }
    if (access(binary_path, R_OK) != 0) { fprintf(stderr, "[!] \"%s\" missing read permissions\n", binary_path); return -1;}
    
    file_descriptor = open(binary_path, O_RDWR);
    if (file_descriptor < 0) { perror("[!] cannot open binary"); return -1; }
    
    if (fstat(file_descriptor, &file_stat) < 0) { perror("[!] cannot get binary stats"); close(file_descriptor); return -1; }
    if (!S_ISREG(file_stat.st_mode)) { fprintf(stderr, "[!] \"%s\" is not a regular binary\n", binary_path); close(file_descriptor); return -1; }

    printf("[*] opened \"%s\", fd <%d>\n", binary_path, file_descriptor);
    printf("[*] this binary is %ld bytes long\n", file_stat.st_size);
    
    return file_descriptor;
}

typedef enum
{
    BIN_UNKNOWN,
    BIN_ELF,
    BIN_PE
} binary_format_t;

typedef enum
{
    ARCH_UNKNOWN = -1,
    ARCH_X86,
    ARCH_X64
} binary_arch_t;

typedef struct
{
    file_t file_descriptor;
    binary_format_t binary_format;
    binary_arch_t binary_arch;
    off_t text_offset;
    uint8_t* text_start;
    uint32_t text_alignment;    // the alignment are by bits
    size_t text_size;
} binary_t;

/* Frees variables used by the hashing utils
 * @param (s)...
 */
static void cleanup_hashes(unsigned char* bin_old, char* str_old, unsigned char* bin_new, char* str_new)
{
    free(bin_old);
    free(str_old);
    free(bin_new);
    free(str_new);
}

/* Performs a cleanup to binary descriptor
 * @param binary Pointer to a binary_t struct instance that holds inferred binary data
 */
static void cleanup_binary(binary_t* binary)
{
    if (binary->file_descriptor >= 0)
    {
        close(binary->file_descriptor);
        binary->file_descriptor = -1;
    }
}

/* Detects binary format - PE or ELF
 * @param binary Pointer to a binary_t struct instance that holds inferred binary data
 * @return binary_format_t Enum structure to reference the detected binary's format
 */
static binary_format_t detect_binary_format(binary_t* binary)
{
    uint8_t magic[4];

    if (lseek(binary->file_descriptor, 0, SEEK_SET) == -1) return BIN_UNKNOWN;

    ssize_t n = read(binary->file_descriptor, magic, sizeof(magic));
    if (n != sizeof(magic))
    {
        printf("[!] unknow binary format\n");
        return BIN_UNKNOWN; 
    }

    if (magic[0] == 0x7F && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F')
    {
        printf("[+] ELF binary detected\n");
        return BIN_ELF;
    }
    else if (magic[0] == 'M' && magic[1] == 'Z')
    {
        printf("[+] PE binary detected\n");
        return BIN_PE;
    }
    else return BIN_UNKNOWN;
}

/* Detects if a binary is PIE-like or not
 * @param binary Pointer to a binary_t struct instance that holds inferred binary data
 * @return int32_t Return code - PIE-like (1), non-PIE-like (0) or error (-1)
 */
static int32_t detect_pie(binary_t* binary)
{
    if (binary->binary_format == BIN_PE)
    {
        IMAGE_DOS_HEADER dos_header;
        ssize_t bytes_read;

        if (lseek(binary->file_descriptor, 0, SEEK_SET) == -1) return -1;

        bytes_read = read(binary->file_descriptor, &dos_header, sizeof(dos_header));
        if (bytes_read != sizeof(dos_header)) return -1;

        if (dos_header.e_magic != IMAGE_DOS_SIGNATURE) return -1;

        if (lseek(binary->file_descriptor, dos_header.e_lfanew, SEEK_SET) == -1) return -1;

        if (binary->binary_arch == ARCH_X86)
        {
            IMAGE_NT_HEADERS32 nt32;

            bytes_read = read(binary->file_descriptor, &nt32, sizeof(nt32));

            if (bytes_read != sizeof(nt32)) return -1;
            if (nt32.Signature != IMAGE_NT_SIGNATURE) return -1;
            if (!(nt32.OptionalHeader.dll_characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)) return 0;
        } else if (binary->binary_arch == ARCH_X64)
        {
            IMAGE_NT_HEADERS64 nt64;

            bytes_read = read(binary->file_descriptor, &nt64, sizeof(nt64));
            
            if (bytes_read != sizeof(nt64)) return -1;
            if (nt64.Signature != IMAGE_NT_SIGNATURE) return -1;
            if (!(nt64.OptionalHeader.dll_characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)) return 0;
        } else return -1;

        return 1;
    } else if (binary->binary_format == BIN_ELF) return -1; // TODO
}

/* Detects the binary's architecture if it is a PE
 * @param binary Pointer to a binary_t struct instance that holds inferred binary data
 * @return binary_arch_t Enum struct to reference the detected architecture - ARCH_X86 (32 bits) or ARCH_X64 (64 bits)
 */
static binary_arch_t detect_pe_arch(binary_t* binary)
{
    if (fstat(binary->file_descriptor, &file_stat) < 0) return ARCH_UNKNOWN;

    off_t file_size = file_stat.st_size;

    IMAGE_DOS_HEADER dos_header;
    if (safe_read(binary->file_descriptor, &dos_header, sizeof(IMAGE_DOS_HEADER), 0, file_size) < 0) return ARCH_UNKNOWN;

    if (dos_header.e_magic != IMAGE_DOS_SIGNATURE) return ARCH_UNKNOWN;

    if (dos_header.e_lfanew <= 0 || dos_header.e_lfanew + 4 > file_size) return ARCH_UNKNOWN;

    uint32_t pe_signature;

    if (safe_read(binary->file_descriptor, &pe_signature, sizeof(uint32_t), dos_header.e_lfanew, file_size) < 0) return ARCH_UNKNOWN;

    if (pe_signature != IMAGE_NT_SIGNATURE) return ARCH_UNKNOWN;

    IMAGE_FILE_HEADER file_header;
    off_t file_header_offset = dos_header.e_lfanew + 4;
    
    if (safe_read(binary->file_descriptor, &file_header, sizeof(IMAGE_FILE_HEADER), file_header_offset, file_size) < 0) return ARCH_UNKNOWN;

    uint16_t magic;
    off_t optional_header_offset = file_header_offset + sizeof(IMAGE_FILE_HEADER);

    if (safe_read(binary->file_descriptor, &magic, sizeof(uint16_t), optional_header_offset, file_size) < 0) return ARCH_UNKNOWN;

    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        IMAGE_OPTIONAL_HEADER32 opt_header;
        
        if (safe_read(binary->file_descriptor, &opt_header, sizeof(IMAGE_OPTIONAL_HEADER32), optional_header_offset, file_size) < 0) return ARCH_UNKNOWN;

        return ARCH_X86;
    }
    else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        IMAGE_OPTIONAL_HEADER64 opt_header;
        
        if (safe_read(binary->file_descriptor, &opt_header, sizeof(IMAGE_OPTIONAL_HEADER64), optional_header_offset, file_size) < 0) return ARCH_UNKNOWN;
        
        return ARCH_X64;
    }

    return ARCH_UNKNOWN;
}

binary_arch_t detect_elf_arch(); // TODO

/* Performs a lookup at binary's headers in disk searching for .text section data
 * @param binary Pointer to a binary_t struct instance that holds inferred binary data
 * @return int32_t (aka int) Return code - success (0) or error (-1)
 */
static int32_t find_text(binary_t* binary)
{
    if (binary->binary_format == BIN_PE)
    {
        off_t file_size = file_stat.st_size;
        if (file_size == 0) return -1;
        
        IMAGE_DOS_HEADER dos_header;
        if (safe_read(binary->file_descriptor, &dos_header, sizeof(IMAGE_DOS_HEADER), 0, file_size) != 0) return -1;

        IMAGE_FILE_HEADER file_header;
        off_t file_header_offset = dos_header.e_lfanew + 4;

        if (safe_read(binary->file_descriptor, &file_header, sizeof(IMAGE_FILE_HEADER), file_header_offset, file_size) != 0) return -1;

        off_t optional_header_offset = file_header_offset + sizeof(IMAGE_FILE_HEADER);
        off_t section_headers_offset = optional_header_offset + file_header.SizeOfOptionalHeader;

        // look for .text section
        for (int32_t i = 0; i < file_header.NumberOfSections; i++)
        {
            IMAGE_SECTION_HEADER section;
            off_t section_offset = section_headers_offset + (i * sizeof(IMAGE_SECTION_HEADER));

            if (safe_read(binary->file_descriptor, &section, sizeof(IMAGE_SECTION_HEADER), section_offset, file_size) != 0)
                continue;

            if (strncmp((char*)section.Name, ".text", 5) == 0 ||
            (section.Characteristics & IMAGE_SCN_CNT_CODE) != 0)
            {
                off_t* result = (off_t*)malloc(2 * sizeof(off_t));
                if (result == NULL) return -1;

                binary->text_offset = section.PointerToRawData;
                binary->text_size = section.SizeOfRawData;

                uint32_t align_flags = section.Characteristics & IMAGE_SCN_ALIGN_MASK;
                switch (align_flags)
                {
                    case IMAGE_SCN_ALIGN_1BYTES:    binary->text_alignment = 8;     break;
                    case IMAGE_SCN_ALIGN_2BYTES:    binary->text_alignment = 16;    break;
                    case IMAGE_SCN_ALIGN_4BYTES:    binary->text_alignment = 32;    break;
                    case IMAGE_SCN_ALIGN_8BYTES:    binary->text_alignment = 64;    break;
                    case IMAGE_SCN_ALIGN_16BYTES:   binary->text_alignment = 128;   break;
                    case IMAGE_SCN_ALIGN_32BYTES:   binary->text_alignment = 256;   break;
                    case IMAGE_SCN_ALIGN_64BYTES:   binary->text_alignment = 512;   break;
                    case IMAGE_SCN_ALIGN_128BYTES:  binary->text_alignment = 1024;  break;
                    case IMAGE_SCN_ALIGN_256BYTES:  binary->text_alignment = 2048;  break;
                    case IMAGE_SCN_ALIGN_512BYTES:  binary->text_alignment = 4096;  break;
                    case IMAGE_SCN_ALIGN_1024BYTES: binary->text_alignment = 8192;  break;
                    case IMAGE_SCN_ALIGN_2048BYTES: binary->text_alignment = 16384; break;
                    case IMAGE_SCN_ALIGN_4096BYTES: binary->text_alignment = 32768; break;
                    case IMAGE_SCN_ALIGN_8192BYTES: binary->text_alignment = 65536; break;

                    // common alignments
                    default: 
                        switch (binary->binary_format)
                        {   
                            case BIN_ELF:
                                switch (binary->binary_arch)
                                {
                                    case ARCH_X86:
                                        binary->text_alignment = 4; break;
                                    case ARCH_X64:
                                        binary->text_alignment = 8; break;
                                }
                            case BIN_PE:
                                switch (binary->binary_arch)
                                {
                                    case ARCH_X86:
                                        binary->text_alignment = 512; break;
                                    case ARCH_X64:
                                        binary->text_alignment = 4096; break;
                                }
                        }
                }

                return 0;
            }
        }

        return -1;
    } else if (binary->binary_format == BIN_ELF) return -1;
    else if (binary->binary_format == BIN_UNKNOWN) return -1; // TODO 
    
    return -1;
}

/* Load a binary's .text in disk to memory
 * @param binary Pointer to a binary_t struct instance that holds inferred binary data
 * @return uint8_t* (aka unsigned char) Pointer to the start of the loaded code in memory
 */
static uint8_t* load_text(binary_t* binary)
{
    if (binary->file_descriptor < 0 || 
        binary->text_offset == 0 || 
        binary->text_size == 0
    ) return nullptr;

    off_t offset = binary->text_offset;

    off_t page_size = sysconf(_SC_PAGE_SIZE);
    off_t aligned_offset = (offset / page_size) * page_size;
    size_t offset_diff = offset - aligned_offset;

    size_t mapped_size = binary->text_size + offset_diff;
    
    void* mapped_addr = mmap(
        nullptr,                    // let kernel set the address
        mapped_size,
        PROT_READ | PROT_WRITE,
        MAP_SHARED,
        binary->file_descriptor,
        aligned_offset
    );
    
    if (mapped_addr == MAP_FAILED) return nullptr;

    return (uint8_t*)(mapped_addr) + offset_diff;
}

/* Performs a writeback from memory to disk - Inverse proccess of load_text()
 * @param binary Pointer to a binary_t struct instance that holds inferred binary data
 */
static void writeback_text(binary_t* binary)
{
    if (binary->file_descriptor < 0 || 
        binary->text_offset == 0 || 
        binary->text_size == 0 ||
        binary->text_start == nullptr
    ) return;

    off_t offset = binary->text_offset;

    off_t page_size = sysconf(_SC_PAGE_SIZE);
    off_t aligned_offset = (offset / page_size) * page_size;
    size_t offset_diff = offset - aligned_offset;

    // Calcula o endereço base do mapeamento (antes do ajuste)
    void* mapped_addr = (void*)(binary->text_start - offset_diff);
    size_t mapped_size = binary->text_size + offset_diff;

    // Sincroniza as mudanças para o arquivo
    msync(mapped_addr, mapped_size, MS_SYNC);

    // Desmapeia a região
    munmap(mapped_addr, mapped_size);
}

#include "include/variant.cpp"

/* Gets a binary's binary SHA256-based hash
 * @param binary Pointer to a binary_t struct instance that holds inferred binary data
 * @return unsigned char* Pointer to the allocated result
 */
static unsigned char* sha256(binary_t* binary)
{
    // set the cursor to the start
    lseek(binary->file_descriptor, 0, SEEK_SET);
    
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    
    unsigned char buffer[4096];
    ssize_t bytes_read;
    
    while ((bytes_read = read(binary->file_descriptor, buffer, sizeof(buffer))) > 0)
    {
        SHA256_Update(&ctx, buffer, bytes_read);
    }
    
    unsigned char* hash = (unsigned char*)malloc(SHA256_DIGEST_LENGTH);
    SHA256_Final(hash, &ctx);
    
    return hash;
}

/*
 * Convets a binary's binary SHA256-based hash to hex string
 * @param input Binarys hash (SHA256_DIGEST_LENGTH bytes)
 * @param output Buffer to string (need to have at least SHA256_DIGEST_LENGTH * 2 + 1 bytes)
 */
void hash_to_string(const unsigned char* input, char* output)
{
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        sprintf(output + (i * 2), "%02x", input[i]);

    output[SHA256_DIGEST_LENGTH * 2] = '\0';
}

/* Load a JSON file in memory
 * @param filename Alias to reference JSON filepath
 * @return json JSON struct to reference a JSON instance
 */
static json load_json(const std::string& path)
{
    std::ifstream file(path);
    json j;

    if (file.is_open())
        file >> j;
    else
        j["known_hashes"] = json::array(); // cria estrutura vazia

    return j;
}

/* Save data to JSON known-hashes database
 * @param filename Alias to reference JSON filepath
 * @param j Alias to reference a JSON instance
 */
static void db_save(const std::string& path, const json& j)
{
    std::ofstream file(path);
    file << j.dump(4); // idented
}

/* Adds a new entry (hash) to "known_hashes"
 * @param filename Alias to reference JSON filepath
 * @param new_hash Alias to reference a string containing the new entry's content
*/
static void db_add_hash(const std::string& filename, const std::string& new_hash)
{
    json j = load_json(filename);

    // garante que seja array
    if (!j.contains("known_hashes") || !j["known_hashes"].is_array())
        j["known_hashes"] = json::array();

    j["known_hashes"].push_back(new_hash);

    db_save(filename, j);
}

/* Verify if is hash a existing entry in database
 * @param filename Alias to reference JSON filepath
 */
static bool db_has_hash(const std::string& filename, const std::string& hash)
{
    json j = load_json(filename);

    if (!j.contains("known_hashes") || !j["known_hashes"].is_array()) return false;

    for (const auto& h : j["known_hashes"])
        if (h == hash) return true;

    return false;
}

/* @brief Helper function to ask user
 */
static bool confirm_pie(void)
{
    char user_input[USER_INPUT_SIZE];
    
    printf("[#] PIE-like binary detected, mutate anyway? ");
    
    if (fgets(user_input, sizeof(user_input), stdin) == NULL)
        return false;
    
    user_input[strcspn(user_input, "\n")] = 0;
    
    return (strcmp(user_input, "y") == 0 || strcmp(user_input, "yes") == 0);
}

/* Initializes a binary's .text in memory for mutation
 * @param binary Pointer to a binary_t struct instance that holds inferred binary data
 * @return int32_t (aka int) Return code - success (0) or error (-1)
 */
static int32_t initialize_text(binary_t* binary)
{
    find_text(binary);
    if (!binary->text_offset || !binary->text_size)
    {
        fprintf(stderr, "[!] failed to find .text -> %p, %ld\n", binary->text_offset, binary->text_size);
        return -1;
    }
    
    binary->text_start = load_text(binary);
    if (!binary->text_start)
    {
        fprintf(stderr, "[!] failed to load .text\n");
        return -1;
    }
    
    printf("[*] .text is at physical offset <0x%lx>, size <0x%lx>\n", binary->text_offset, binary->text_size);
    printf("[*] .text is %d bits aligned\n", binary->text_alignment);
    printf("[*] loaded disk -> memory at %p\n", binary->text_start);
    
    return 0;
}

/* Calculates a binary's SHA256-based hash
 * @param binary Pointer to a binary_t struct instance that holds inferred binary data
 * @param bin_hash Pointer to pointer to the binary hash
 * @param str_hash Pointer to pointer to the hash string buffer
 * @return int32_t (aka int) Return code - success (0) or error (-1)
 */
static int32_t compute_hash(binary_t* binary, unsigned char** bin_hash, char** str_hash)
{
    *bin_hash = sha256(binary);
    if (!(*bin_hash))
    {
        fprintf(stderr, "[!] sha256 failed\n");
        return -1;
    }
    
    *str_hash = (char*)malloc(SHA256_DIGEST_LENGTH * 2 + 1);
    if (!(*str_hash))
    {
        free(*bin_hash);
        *bin_hash = NULL;

        fprintf(stderr, "[!] malloc failed for hash string\n");
        return -1;
    }
    
    hash_to_string(*bin_hash, *str_hash);

    return 0;
}

/* Performs a looping logic to trying mutating a binary based in difference between hashes
 * @param binary Pointer to a binary_t struct instance that holds inferred binary data
 * @param result Pointer to a ghost_code_result structure instance that holds info about of found ghost code patterns
 * @param known_hashes_path Pointer to JSON database string buffer filepath
 * @return int32_t (aka int) Return code - success (0) or error (-1)
 */
static int32_t loop_mutation(binary_t* binary, ghost_code_result* result, const char* known_hashes_path)
{
    unsigned char* bin_old_hash = NULL;
    char* str_old_hash = NULL;
    unsigned char* bin_new_hash = NULL;
    char* str_new_hash = NULL;

    struct stat file_stat;

    int32_t ret = -1;

    if (compute_hash(binary, &bin_old_hash, &str_old_hash) < 0)
        goto cleanup;
    
    printf("[*] original hash: %s\n", str_old_hash);
    
    str_new_hash = (char*)malloc(SHA256_DIGEST_LENGTH * 2 + 1);
    if (!str_new_hash)
    {
        fprintf(stderr, "[!] malloc failed for new hash string\n");
        goto cleanup;
    }
    
    strcpy(str_new_hash, str_old_hash);
    
    // i = attempt
    for (int32_t i = 0; i < MAX_MUTATION_ATTEMPTS; i++)
    {
        if (strcmp(str_old_hash, str_new_hash) != 0)
        {
            ret = 0;
            break;
        }

        if (i != 0)
            printf("[+] try %d: trying new variant\n", i);

        if (fstat(binary->file_descriptor, &file_stat) != 0)
        {
            perror("[!] cannot get binary stats before mutation");
            goto cleanup;
        }
        
        off_t old_size = file_stat.st_size;

        mutate(result);
        writeback_text(binary);
        fsync(binary->file_descriptor);

        if (fstat(binary->file_descriptor, &file_stat) != 0)
        {
            perror("[!] cannot get updated binary stats");
            goto cleanup;
        }

        off_t new_size = file_stat.st_size;

        if (new_size != old_size)
        {
            fprintf(stderr, "[#] binary size changed (%ld -> %ld), reloading...\n", old_size, new_size);
            
            // binary size changed -> reload
            munmap(binary->text_start - (binary->text_offset % sysconf(_SC_PAGE_SIZE)), binary->text_size + (binary->text_offset % sysconf(_SC_PAGE_SIZE)));
            
            binary->text_start = load_text(binary);
            if (!binary->text_start)
            {
                fprintf(stderr, "[!] failed to reload .text after size change\n");
                goto cleanup;
            }
            
            free(result); // free the old patterns
            result = find_ghost_code(binary);
            if (!result)
            {
                fprintf(stderr, "[!] failed to find ghost code patterns after reload\n");
                goto cleanup;
            }
            
            printf("[*] reloaded: found %d patterns\n", result->total_occurrences);
            continue;
        }

        free(bin_new_hash);
        bin_new_hash = NULL;

        if (compute_hash(binary, &bin_new_hash, &str_new_hash) != 0)
            goto cleanup;

        if (db_has_hash(known_hashes_path, str_new_hash))
        {
            printf("[#] hash already in database\n");
            strcpy(str_old_hash, str_new_hash);
            continue;
        }

        db_add_hash(known_hashes_path, str_new_hash);
        printf("[+] unique hash found -> added to database\n");
        printf("[*] new hash: %s\n", str_new_hash);
    }
    
cleanup:
    cleanup_hashes(bin_old_hash, str_old_hash, bin_new_hash, str_new_hash);
    return ret;
}

/* Engine main function that mutates a binary
 * @param binary Pointer to a binary_t struct instance that holds inferred binary data
 * @param known_hashes_path Pointer to JSON database string buffer filepath
 * @return int32_t (aka int) Return code - success (0) or error (-1)
 */
int32_t mutate(binary_t* binary, const char* known_hashes_path)
{
    ghost_code_result* result = NULL;
    int32_t return_code = -1;

    binary->binary_format = detect_binary_format(binary);
    if (binary->binary_format == BIN_ELF)
    {
        return -1;
    }
    else if (binary->binary_format == BIN_UNKNOWN)
    {
        fprintf(stderr, "[!] unknown binary format, aborting\n");
        goto cleanup;
    }
    
    binary->binary_arch = detect_pe_arch(binary);
    if (binary->binary_arch == ARCH_UNKNOWN)
    {
        fprintf(stderr, "[!] failed to detect PE architecture, aborting\n");
        goto cleanup;
    }
    
    if (detect_pie(binary) && !confirm_pie())
    {
        printf("[#] mutation aborted by user\n");
        goto cleanup;
    }
    
    printf("[+] current algorithm: sha256\n");
    
    if (initialize_text(binary) < 0)
        goto cleanup;
    
    result = find_ghost_code(binary);
    if (!result)
    {
        fprintf(stderr, "[!] failed to find ghost code patterns, aborting\n");
        goto cleanup;
    }
    
    printf("[*] found %d total mutable patterns\n", result->total_occurrences);

    return_code = loop_mutation(binary, result, known_hashes_path);

cleanup:
    cleanup_binary(binary);
    return return_code;
}

int main(const int argc, const char* argv[])
{
    if (argc < 1)
    {
        printf("[!] usage: ./%s <binary>", argv[1]);
        return -1;
    }

    clock_t start = clock();

    binary_t* binary = (binary_t*)malloc(sizeof(binary_t));
    if (!binary)
    {
        printf("[!] failed to allocate binary structure\n");
        return -1;
    }

    binary->file_descriptor = open_binary(argv[1]);
    if (binary->file_descriptor == -1)
    {
        perror("[!] failed to open binary\n");
        return -1;
    }

    const char* known_hashes_path = "hashes.json";

    mutate(binary, known_hashes_path);

    clock_t end = clock();

    double cpu_time = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("[*] time elapsed: %.3f seconds\n", cpu_time);

    free(binary);
    return 0;
}
