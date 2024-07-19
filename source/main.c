/* schema:
    ~ antes de tudo, se certificar e assegurar que tem mais ou menos 60 bytes de espaço reservado (zerofilled) no final da .text
    -> cprintf | um "wrapper" pro printf mas acrescenta umas cores diferente se indentificar o caractere ([!] vermelho, [~] roxo, [*] amarelo, [+] ciano, etc)
    -> ft_gt_start_a_callback | helper da find_text pra pegar o start address da section que a 'main' pertence (pra facilitar)
    -> gt_base_a | helper da find_text pra pegar o base address correspondete ao start_address q a 'ft_gt_start_a_callback' retornar
    -> find_text | vai retornar as informações necessárias pra section que a gente vai modificar (as informações tão descritas na struct 'section_t')
    -> crawl_text | copia a .text que a 'find_text' achou pra uma section mapeada na memória ou simplesmente uma chunk RWX na heap
    -> sc_virtual | faz um sanity check pra ver se todos os opcodes da section original são os mesmos opcodes da section mapeada
    -> modifier | finalmente modifica a nova .text e depois faz alguns sanity checks e faz o writeback pro binario no disco
*/

/* abbreviations
- _a: address
- _s: section
- _t: type
- f_: found

- ft: find_text
- sc: sanity check
- gt: get
- og: original
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>

#include <inttypes.h>

#include <sys/mman.h>
#include <sys/auxv.h>
#include <unistd.h>
#include <dlfcn.h>
#include <link.h>
#include <elf.h>

// typedefs
typedef unsigned char byte_t;
typedef signed   char sbyte_t;
typedef unsigned long ulong64_t;

typedef struct {
    void*   start_a;
    void*   base_a;
    size_t* size;
} section_t;

// protytpes
// eu ainda vou fazer essas funções, mas o foco agora é ter certeza que deu pra copiar a .text certa/especifica pra section mapeada
static void  signature_check(void); // TODO
static void  crawled_jmp(void); // TODO
       int   main(void);

// global vars
static pid_t     pid     = 0x0;
static section_t found_s = {0x0, 0x0, 0x0};

static void cprintf(const char* cp_stp, ...)
{
    va_list cp_args;
    va_start(cp_args, cp_stp);
    
    for (int c = 0; cp_stp[c] != '\0'; c++) {
        if (cp_stp[c] == '*')
            printf("\033[1;33m*\033[0m");
        else if (cp_stp[c] == '+')
            printf("\033[1;36m+\033[0m");
        else if (cp_stp[c] == '~')
            printf("\033[1;35m~\033[0m");
        else if (cp_stp[c] == '!')
            printf("\033[1;31m!\033[0m");
        else if (cp_stp[c] == '=') {
            if (cp_stp[c-1] == '[' && cp_stp[c+1] == ']')
                printf("\033[1;35m=\033[0m");
            else
                putchar('R');
        } else if (cp_stp[c] == '%') {
            if (cp_stp[c+1] == 'z') {
                if (cp_stp[c+2] == 'u') {
                    size_t cp_val = va_arg(cp_args, size_t);

                    printf("%zu", cp_val);

                    c += 2;
                } else if (cp_stp[c+2] == 'd') {
                    ssize_t cp_val = va_arg(cp_args, ssize_t);

                    printf("%zd", cp_val);

                    c += 2;
                } else
                    putchar('%');
            } else if (cp_stp[c+1] == 'p') {
                void* cp_val = va_arg(cp_args, void*);

                printf("\033[0;32m%p\033[0m", cp_val);

                c += 1;
            } else if (cp_stp[c+1] == 'l') {
                c += 1;

                if (cp_stp[c+1] == 'x') {
                    unsigned long int* cp_val = va_arg(cp_args, void*);

                    printf("\033[0;32m%lx\033[0m", cp_val);

                    c += 1;
                }
            } else
                putchar('%');
        } else
            putchar(cp_stp[c]);
    }
    
    va_end(cp_args);
}

static uintptr_t ft_gt_start_a_callback(struct dl_phdr_info* c_info, size_t c_size)
{
    for (int j = 0; j < c_info->dlpi_phnum; j++) {
        if (c_info->dlpi_phdr[j].p_type == PT_LOAD && (c_info->dlpi_phdr[j].p_flags & PF_X)) {
            uintptr_t start_a = c_info->dlpi_addr + c_info->dlpi_phdr[j].p_vaddr;
            uintptr_t base_a = start_a + c_info->dlpi_phdr[j].p_memsz;

            if ((uintptr_t)&main >= start_a && (uintptr_t)&main < base_a) {
                if ((void*)start_a) return start_a;
            }
        }
    }

    return 0x0;
}

static uintptr_t gt_base_a(uintptr_t start_a)
{
    FILE* maps;

    sbyte_t dir[64];
    sbyte_t line[512];

    snprintf(dir, sizeof(dir), "/proc/%d/maps", pid);
    maps = fopen(dir, "r");

    if (maps == NULL)
        return 0x0;

    uintptr_t base_a = 0x0;

    while (fgets(line, sizeof(line), maps)) {
        // m_: mapping/mappings
        uintptr_t m_start_a = 0x0;
        uintptr_t m_end_a   = 0x0;
        sbyte_t   m_perms[5];

        if (sscanf(line, "%lx-%lx %4s", &m_start_a, &m_end_a, m_perms) != 3)
            continue;

        if (strchr(m_perms, 'x') && start_a >= m_start_a && start_a < m_end_a) {
            base_a = m_end_a;
            break;
        }
    }

    fclose(maps);

    return base_a; 
}

static section_t find_text(void)
{
    section_t section = {0x0, 0x0, 0x0};

    uintptr_t f_start_a = dl_iterate_phdr(ft_gt_start_a_callback, NULL);

    if ((void*)f_start_a && (uintptr_t)f_start_a != NULL)
        section.start_a = (uintptr_t)f_start_a;

    uintptr_t f_base_a = (uintptr_t)gt_base_a(f_start_a);

    if ((uintptr_t)f_base_a)
        section.base_a = (uintptr_t)f_base_a;

    if (f_start_a && f_base_a && f_start_a < f_base_a)
        section.size = f_base_a - f_start_a;

    return section;
}

static void* crawl_text(void) {
    found_s = find_text();

    // debug
    cprintf("[=] %p\n"   , found_s.start_a);
    cprintf("[=] %p\n"   , found_s.base_a);
    cprintf("[=] 0x%lx\n", found_s.size);

    if (!found_s.start_a || !found_s.base_a || found_s.size == (size_t)0x0)
        return NULL;

    void* mapped_s = (uintptr_t*)mmap(
        NULL, found_s.size,
        PROT_READ   | PROT_WRITE | PROT_EXEC,
        MAP_PRIVATE | MAP_ANONYMOUS, 
        -1,
        0
    );

    if (mapped_s == MAP_FAILED)
        return NULL;

    memcpy(mapped_s, found_s.start_a, found_s.size);

    return mapped_s;
}

// TODO
static void sc_physical(void)
{

}

// TODO
static void wt_back(void)
{

}

static int32_t sc_virtual(byte_t* section, section_t og_section)
{
    for (int i = 0; i < og_section.size; i++) {
        if (section[i] == ((byte_t*)og_section.start_a)[i]) continue;
        else return 1;
    }

    return 0;
}

static void modifier(void) 
{ 
    byte_t* mapped_s = (byte_t*)crawl_text();

    if (sc_virtual(mapped_s, found_s) == 0x1)
        return NULL;

    byte_t* cursor = mapped_s + ((int64_t)found_s.size - (sbyte_t)9); // 9 and not 8 because the last byte is inaccessible
    
    for (int i = 0; i < found_s.size; i++) {
        cursor[i] == 0x90; // 8 NOPs
    }

    wt_back();
}

int main(void)
{
    pid = getpid();

    modifier();

    return 0;
}
