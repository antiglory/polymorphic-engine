// inject.cpp

typedef struct
{
    uint8_t* address;
    off_t offset;
    size_t size;
} cave_location;

/* Finds NOP caves (NOP sleds) in .text
 * @param binary Pointer to a binary_t struct instance
 * @param min_size Minimum cave size to consider
 * @return std::vector<cave_location> Vector containing all found caves
 */
static std::vector<cave_location> find_caves(binary_t* binary, size_t min_size)
{
    std::vector<cave_location> caves;
    
    size_t cave_start = 0;
    size_t cave_size = 0;
    bool in_cave = false;
    
    for (int32_t offset = 0; offset < binary->text_size; offset++)
    {
        uint8_t byte = binary->text_start[offset];
        
        // check for NOP (0x90) or multi-byte NOPs (0x66 0x90, etc)
        if (byte == 0x90)
        {
            if (!in_cave)
            {
                cave_start = offset;
                cave_size = 1;
                in_cave = true;
            }
            else
                cave_size++;
        }
        else
        {
            if (in_cave && cave_size >= min_size)
            {
                cave_location loc;
                loc.address = &binary->text_start[cave_start];
                loc.offset = cave_start;
                loc.size = cave_size;

                caves.push_back(loc);
            }
            
            in_cave = false;
            cave_size = 0;
        }
    }
    
    // check last cave
    if (in_cave && cave_size >= min_size)
    {
        cave_location loc;
        loc.address = &binary->text_start[cave_start];
        loc.offset = cave_start;
        loc.size = cave_size;
        caves.push_back(loc);
    }
    
    return caves;
}

/* Stuffs caves with ghost patterns
 * @param binary Pointer to a binary_t struct instance
 * @return int32_t Number of patterns injected, or -1 on error
 */
static int32_t cave_stuffing(binary_t* binary)
{
    printf("[+] searching for NOP caves...\n");
    
    // find caves of at least 2 bytes (smallest pattern)
    std::vector<cave_location> caves = find_caves(binary, 2);
    
    if (caves.empty())
        return 0;
    
    printf("[*] found %zu caves\n", caves.size());
    
    int32_t stuffed = 0;
    
    for (auto& cave : caves)
    {
        // find patterns that fit in this cave
        std::vector<ghost_pattern*> fitting_patterns;
        
        for (size_t i = 0; i < NUM_PATTERNS; i++)
        {
            if (known_patterns[i].length <= cave.size)
                fitting_patterns.push_back(&known_patterns[i]);
        }
        
        if (fitting_patterns.empty()) continue;
        
        uint32_t idx = random(fitting_patterns.size() - 1);
        ghost_pattern* pattern = fitting_patterns[idx];
        
        // copy pattern to cave
        memcpy(cave.address, pattern->opcodes, pattern->length);
        
        // fill remaining space with NOPs if needed
        size_t remaining = cave.size - pattern->length;
        if (remaining > 0)
            memset(cave.address + pattern->length, 0x90, remaining);
        
        printf("[*] stuffed cave at offset 0x%lx (size: %zu) with pattern %d <%s>\n",
               binary->text_offset + cave.offset, cave.size, pattern->id, pattern->description);
        
        stuffed++;
    }
    
    return stuffed;
}

/* Injects ghost code patterns in NOP caves (cave stuffing)
 * @param binary Pointer to a binary_t struct instance
 * @return int32_t Return code - success (0) or error (-1)
 */
static int32_t inject(binary_t* binary)
{
    printf("[+] starting injection...\n");

    int32_t stuffed = cave_stuffing(binary);
    
    if (stuffed > 0)
    {
        printf("[+] cave stuffing completed: %d caves stuffed\n", stuffed);
        return 0;
    }
    
    fprintf(stderr, "[!] no caves to stuff -> incompatible binary\n");
    printf("[+] try building it with avaliable patterns\n");
    return -1;
}

/* Performs injection loop
 * @param binary Pointer to a binary_t struct instance
 * @param known_hashes_path Pointer to JSON database string buffer filepath
 * @return int32_t Return code - success (0) or error (-1)
 */
static int32_t loop_injection(binary_t* binary, const char* known_hashes_path)
{
    unsigned char* bin_old_hash = NULL;
    char* str_old_hash = NULL;
    unsigned char* bin_new_hash = NULL;
    char* str_new_hash = NULL;
    ghost_code_result* result = NULL;

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
    
    for (int32_t i = 0; i < MAX_MUTATION_ATTEMPTS; i++)
    {
        if (strcmp(str_old_hash, str_new_hash) != 0)
        {
            ret = 0;
            break;
        }

        if (i != 0)
            printf("[+] try %d: injecting more patterns...\n", i);

        if (inject(binary) != 0)
        {
            fprintf(stderr, "[!] injection failed - any patterns have been mutated or stuffed\n");
            goto cleanup;
        }

        if (result) free(result);
        result = find_ghost_code(binary);
        if (!result || result->total_occurrences == 0)
        {
            fprintf(stderr, "[!] no patterns found after injection\n");
            goto cleanup;
        }

        printf("[*] after injection: found %d patterns\n", result->total_occurrences);

        writeback_text(binary);
        fsync(binary->file_descriptor);

        binary->file_size = get_file_size(binary);

        free(bin_new_hash);
        bin_new_hash = NULL;

        if (compute_hash(binary, &bin_new_hash, &str_new_hash) != 0)
            goto cleanup;

        if (db_has_hash(known_hashes_path, str_new_hash))
        {
            printf("[#] hash already in database, injecting again...\n");
            strcpy(str_old_hash, str_new_hash);
            continue;
        }

        db_add_hash(known_hashes_path, str_new_hash);
        printf("[+] unique hash found -> added to database\n");
        printf("[*] new hash: %s\n", str_new_hash);
    }
    
cleanup:
    if (result) free(result);
    cleanup_hashes(bin_old_hash, str_old_hash, bin_new_hash, str_new_hash);
    free_text(binary);
    return ret;
}
