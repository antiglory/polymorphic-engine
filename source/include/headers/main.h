#ifndef MAIN_H
#define MAIN_H

/* abbreviations
- _a: address
- _s: section
- _t: type
- f_: found

- fc_virtual: find code virtual
- fs_virtual: found section virtual

- fs_physical: found section physical

- cc_virtual: crawl code virtual

- vt: virtual
- ps: phisical

- fcv: find code virtual (ABV of helpers)

- sc: sanity check
- mk: mask
- gt: get
- wt: write
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>

#include <limits.h>
#include <inttypes.h>

#include <sys/mman.h>
#include <sys/auxv.h>
#include <unistd.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <libelf.h>
#include <link.h>
#include <elf.h>

#include "../modules/etc.c"

// typedefs
typedef unsigned char byte_t;
typedef signed   char sbyte_t;
typedef unsigned long ulong64_t;

typedef struct {
    void*    start_a;
    void*    base_a;
    size_t*  size;
    size_t*  size_mk;
} section_t;

// protytpes
int main(int argc, const char argv[]);

#endif
