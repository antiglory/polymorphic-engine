/* schema:
    ~ antes de tudo, se certificar e assegurar que tem mais ou menos 60 bytes de espaço reservado (zerofilled) no final da .text
    -> cprintf | um "wrapper" pro printf mas acrescenta umas cores diferente se indentificar o caractere ([!] vermelho, [~] roxo, [*] amarelo, [+] ciano, etc)
    -> ft_gt_start_a_callback | helper da find_text pra pegar o start address da section onde tá a 'main'
    -> gt_base_a | helper da find_text pra pegar o base address correspondete ao start_address q a 'ft_gt_start_a_callback' retornar
    -> find_text | vai retornar as informações necessárias pra section que a gente vai modificar (as informações tão descritas na struct 'stext_t')
    -> crawl_text | copia a .text que a 'find_text' achou pra uma section mapeada na memória ou simplesmente uma chunk RWX na heap
    -> inject | jumpa pra essa .text que foi mapeada (precisa jumpar pra um lugar correspondente, n pode ser random)
    -> inject | escreve na .text original (no binário) adicionando algum código naquele espaço reservado nela (seja uns NOP ou algum código funcional de fato)
    -> singnature_check | faz um check na static signature do binário pra ver se deu tudo certo, e ve se corrompeu algo, se der certo, libera a .text mapeada
    -> crawled_jmp | se deu certo, jumpa de volta pra .text original modificada de forma que nao trunque a execução tb
*/

/* abbreviations
- _a: address
- _s: section
- _t: type
- ft: find_text
- gt: get
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
typedef unsigned long ulong64_t;

typedef struct {
    void*   start_a;
    void*   base_a;
    size_t* size;
} stext_t;

// protytpes
// eu ainda vou fazer essas funções, mas o foco agora é ter certeza que deu pra copiar a .text certa/especifica pra section mapeada
static void  signature_check(void); // TODO
static void  crawled_jmp(void); // TODO
       int   main(void);

// global vars
pid_t pid = 0x0;

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
    uintptr_t base_a = 0x0;

    FILE* maps;

    byte_t dir[64];
    byte_t line[512];

    snprintf(dir, sizeof(dir), "/proc/%d/maps", pid);
    maps = fopen(dir, "r");

    if (maps == NULL)
        return 0x0;

    while (fgets(line, sizeof(line), maps)) {
        // (_m: mapping/mappings)
        // base/end are the same

        uintptr_t m_start_a, m_end_a;
        byte_t m_perms[5];

        if (sscanf(line, "%lx-%lx %4s", &m_start_a, &m_end_a, m_perms) != 3)
            continue;

        if (strchr(m_perms, 'x') && start_a >= m_start_a && start_a < m_end_a) {
            base_a = m_start_a;
            break;
        }
    }

    fclose(maps);
    return base_a;
}

static stext_t find_text(void)
{
    stext_t section = {0x0, 0x0, 0x0};

    uintptr_t start_a = dl_iterate_phdr(ft_gt_start_a_callback, NULL);

    if ((void*)start_a && (uintptr_t)start_a != NULL)
        section.start_a = (uintptr_t)start_a;

    uintptr_t   base_a  = (uintptr_t)gt_base_a(start_a);

    if ((uintptr_t)base_a)
        section.base_a  = (uintptr_t)base_a;

    if (start_a && base_a && start_a < base_a)
        section.size = base_a - start_a;

    return section;

    /*
        TODO corrigir essa porra quando o claude voltar
        ~ gcc -g -o main -ldl -fno-stack-protector -z execstack -no-pie -w main.c && ./main
        [=] 0x401000
        [=] 0x401000
        [=] 0x0
                    */
}

static void* crawl_text(void) {
    stext_t found_text = find_text();

    // debug
    cprintf("[=] %p\n"   , found_text.start_a);
    cprintf("[=] %p\n"   , found_text.base_a);
    cprintf("[=] 0x%lx\n", found_text.size);

    if (found_text.start_a == NULL || found_text.base_a == NULL || found_text.size == (size_t)0x0)
        return NULL;

    uintptr_t* mapped_s = (uintptr_t*)malloc(((int64_t)found_text.size) * sizeof(byte_t));

    if (!mapped_s)
        return NULL;

    if (mprotect(mapped_s, found_text.size, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
        free(mapped_s);
        return NULL;
    }

    memcpy(mapped_s, found_text.start_a, found_text.size);

    return mapped_s;
}

// TODO
static void inject(void) 
{ 
    crawl_text(); 
}

int main(void)
{
    pid = getpid();

    inject();

    return 0;
}
