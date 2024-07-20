#include "include/headers/main.h"

// global vars
static pid_t       pid         =  0x0;
static section_t   fs_virtual  =  {0x0, 0x0, 0x0};
static void*       mapped_s    =  NULL;

static void ohyes(void)
{
    puts("...");

    while (1);
    // trunk
}

static uintptr_t fcv_gt_start_a_callback(struct dl_phdr_info* c_info, size_t c_size)
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

static uintptr_t fcv_gt_base_a(uintptr_t start_a)
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

static section_t fc_virtual(void)
{
    section_t section = {0x0, 0x0, 0x0};

    uintptr_t f_start_a = dl_iterate_phdr(fcv_gt_start_a_callback, NULL);

    if ((void*)f_start_a && (uintptr_t)f_start_a != NULL)
        section.start_a = (uintptr_t)f_start_a;

    uintptr_t f_base_a = (uintptr_t)fcv_gt_base_a(f_start_a);

    if ((uintptr_t)f_base_a)
        section.base_a = (uintptr_t)f_base_a;

    if (f_start_a && f_base_a && f_start_a < f_base_a)
        section.size = f_base_a - f_start_a;

    return section;
}

static int32_t sc_virtual(byte_t* fs_virtual, section_t fs_physical)
{
    for (int i = 0; i < fs_physical.size; i++) {
        if (fs_virtual[i] == ((byte_t*)fs_physical.start_a)[i]) continue;
        else return 1;
    }

    return 0;
}

static void* cc_virtual(void) {
    fs_virtual = fc_virtual();

    cprintf("[+] found virtual section (code)\n\0");
    cprintf("[=] s %p\n\0"   , fs_virtual.start_a);
    cprintf("[=] b %p\n\0"   , fs_virtual.base_a);
    cprintf("[=] z 0x%lx\n\0", fs_virtual.size);

    if (!fs_virtual.start_a ||
        !fs_virtual.base_a  ||
         fs_virtual.size    == (size_t)0x0
    )
        return NULL;

    fs_virtual.size_mk = (size_t)(fs_virtual.size - (sbyte_t)0x1);

    mapped_s = (uintptr_t*)mmap(
        NULL, fs_virtual.size_mk,
        PROT_READ   | PROT_WRITE | PROT_EXEC,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0
    );

    if (mapped_s == MAP_FAILED)
        return NULL;

    memcpy(mapped_s, fs_virtual.start_a, fs_virtual.size);

    return mapped_s;
}

static int32_t wt_back(void)
{
    if (!mapped_s || !fs_virtual.start_a || !fs_virtual.size)
        return;

    if (mprotect(fs_virtual.start_a, fs_virtual.size, PROT_READ | PROT_WRITE | PROT_EXEC) == -1)
        return 0x1;

    memcpy(fs_virtual.start_a, mapped_s, fs_virtual.size);

    cprintf("[*] wrote virtual data to physical section, initializing sync\n\0");

    if (msync(fs_virtual.start_a, fs_virtual.size, MS_SYNC) == -1)
        return 0x1;

    cprintf("[+] synchronized to disk\n\0");

    cprintf("[~] see you next run\n\0");

    ohyes();
}

static void modifier(void)
{
    mapped_s = (byte_t*)cc_virtual();

    const int32_t sc_virtual_ret_code = sc_virtual(mapped_s, fs_virtual);
    cprintf("[+] virtual section sanity check returned with code %lx\n\0", sc_virtual_ret_code);

    if (sc_virtual_ret_code == 0x1)
        return;

    cprintf("[+] reached final lap\n\0");

    byte_t* cursor = mapped_s + ((int64_t)fs_virtual.size - (sbyte_t)8);

    cprintf("[*] modifying virtual section\n\0");

    for (int i = 0; i < 8; i++) {
        cursor[i] = 0x90; // simple nop sleed
    }

    cprintf("[+] success, writebacking to disk's ELF\n\0");

    wt_back();
}

int main(int argc, const char argv[])
{
    pid = getpid();

    modifier();

    return 0;
}
