// variant.cpp

typedef struct
{
    int32_t pattern_id;
    unsigned char* address;
} ghost_occurrence;

typedef struct
{
    ghost_occurrence* occurrences;
    int32_t total_occurrences;
} ghost_code_result;

// pattern 0: xchg rax, rax
static unsigned char pattern_0[] = {0x48, 0x90};

// pattern 1: LEA with zero displacement
static unsigned char pattern_1[] = {0x8D, 0x40, 0x00}; // LEA EAX, [EAX+0]

// pattern_2: two-byte NOP (operand-size prefix + NOP) - used to be for alignment, like NOP
// encoding: 0x66 0x90
static unsigned char pattern_2[] = {0x66, 0x90}; // NOP (66 prefix + NOP)

// pattern_3: MOV RAX, RAX (64-bit register move) - make REX + mov
// encoding: 0x48 0x89 0xC0
static unsigned char pattern_3[] = {0x48, 0x89, 0xC0}; // mov rax, rax

// pattern_4: MOV EAX, EAX (alternative encoding) - equivalent to nop at r32
// encoding: 0x8B 0xC0
static unsigned char pattern_4[] = {0x8B, 0xC0}; // mov eax, eax

// pattern_5: MOV EBX, EBX
// encoding: 0x89 0xDB
static unsigned char pattern_5[] = {0x89, 0xDB}; // mov ebx, ebx

typedef struct
{
    int32_t id;
    unsigned char* opcodes;
    size_t length;
    const char* description;
} ghost_pattern;

static ghost_pattern known_patterns[] =
{
    {0, pattern_0, sizeof(pattern_0), "xchg rax, rax"},
    {1, pattern_1, sizeof(pattern_1), "lea eax, [eax+0]"},
    {2, pattern_2, sizeof(pattern_2), "two-byte NOP"},
    {3, pattern_3, sizeof(pattern_3), "mov eax, eax"},
    {4, pattern_4, sizeof(pattern_4), "mov eax, eax"},
    {5, pattern_5, sizeof(pattern_5), "mov ebx, ebx"}
};

#define NUM_PATTERNS (sizeof(known_patterns) / sizeof(ghost_pattern))

// helper to compare bytes
static int32_t match_pattern(unsigned char* code, ghost_pattern* pattern, size_t remaining)
{
    if (remaining < pattern->length) return 0;
    
    for (size_t i = 0; i < pattern->length; i++)
        if (code[i] != pattern->opcodes[i]) return 0;

    return 1;
}

static int32_t add_occurrence(ghost_code_result* result, int32_t pattern_id, unsigned char* address)
{
    ghost_occurrence* new_occurrences = (ghost_occurrence*)realloc(result->occurrences, (result->total_occurrences + 1) * sizeof(ghost_occurrence));
    
    if (new_occurrences == NULL)
    {
        // TODO
        return -1;
    }
    
    result->occurrences = new_occurrences;

    result->occurrences[result->total_occurrences].pattern_id = pattern_id;
    result->occurrences[result->total_occurrences].address = address;
    result->total_occurrences++;
    
    return 1;
}

static void free_ghost_result(ghost_code_result* result)
{
    if (result)
    {
        if (result->occurrences)
            free(result->occurrences);

        free(result);
    }
}

static ghost_code_result* find_ghost_code(binary_t* binary)
{
    ghost_code_result* result = (ghost_code_result*)malloc(sizeof(ghost_code_result));
    if (result == NULL) return NULL;
    
    result->occurrences = NULL;
    result->total_occurrences = 0;
    
    // iterates over the .text section
    for (size_t offset = 0; offset < binary->text_size; offset++)
    {
        size_t remaining = binary->text_size - offset;
        
        // verify each known pattern
        for (size_t p = 0; p < NUM_PATTERNS; p++)
        {
            if (match_pattern(&binary->text_start[offset], &known_patterns[p], remaining))
            {
                if (!add_occurrence(result, known_patterns[p].id, &binary->text_start[offset]))
                {
                    free_ghost_result(result);
                    return NULL;
                }
                
                // advances the offset by the pattern size to avoid overlaps
                offset += known_patterns[p].length - 1;
                break;
            }
        }
    }
    
    return result;
}

typedef struct
{
    enum mutation_type_t
    {
        DIRECT,      // direct substuition (same size)
        PADDING,     // smaller pattern + NOPs
        COMBO
    } type;
    
    std::vector<int32_t> pattern_ids;
    uint8_t nops_before;               // NOP sled
    uint8_t nops_after;
    uint8_t total_size;
    const char* description;
} mutation_possibility;

// generate all mutation possibilities for a specific size
static std::vector<mutation_possibility> generate_possibilities(size_t target_size)
{
    std::vector<mutation_possibility> possibilities;
    
    // 1. DIRECT
    for (size_t p = 0; p < NUM_PATTERNS; p++)
    {
        if (known_patterns[p].length == target_size)
        {
            mutation_possibility poss;
            poss.type = mutation_possibility::DIRECT;
            poss.pattern_ids.push_back(known_patterns[p].id);
            poss.nops_before = 0;
            poss.nops_after = 0;
            poss.total_size = target_size;
            
            possibilities.push_back(poss);
        }
    }
    
    // 2. PADDING (multiple variations)
    // generate different combinations of NOPs to fill the space
    if (target_size >= 1 && target_size <= 5)
    {
        mutation_possibility nop_fill{};
        nop_fill.type = mutation_possibility::PADDING;
        nop_fill.pattern_ids.clear();
        nop_fill.nops_before = target_size;
        nop_fill.nops_after = 0;
        nop_fill.total_size = target_size;
        
        possibilities.push_back(nop_fill);
    }
    
    // 3. PADDING also
    for (size_t p = 0; p < NUM_PATTERNS; p++)
    {
        if (known_patterns[p].length < target_size)
        {
            size_t nops_needed = target_size - known_patterns[p].length;
            
            // generate ALL possible NOP distributions
            for (size_t nops_before = 0; nops_before <= nops_needed; nops_before++)
            {
                size_t nops_after = nops_needed - nops_before;
                
                mutation_possibility poss;
                poss.type = mutation_possibility::PADDING;
                poss.pattern_ids.push_back(known_patterns[p].id);
                poss.nops_before = nops_before;
                poss.nops_after = nops_after;
                poss.total_size = target_size;
                
                possibilities.push_back(poss);
            }
        }
    }
    
    // 4. COMBO
    for (size_t p1 = 0; p1 < NUM_PATTERNS; p1++)
    {
        for (size_t p2 = 0; p2 < NUM_PATTERNS; p2++)
        {
            size_t combined_size = known_patterns[p1].length + known_patterns[p2].length;
            
            if (combined_size == target_size)
            {
                // Encaixe perfeito
                mutation_possibility poss;
                poss.type = mutation_possibility::COMBO;
                poss.pattern_ids.push_back(known_patterns[p1].id);
                poss.pattern_ids.push_back(known_patterns[p2].id);
                poss.nops_before = 0;
                poss.nops_after = 0;
                poss.total_size = target_size;
                
                possibilities.push_back(poss);
            } else if (combined_size < target_size)
            {
                size_t nops_needed = target_size - combined_size;
                
                // different distributions: before, middle (between patterns), after
                for (size_t nops_before = 0; nops_before <= nops_needed; nops_before++)
                {
                    size_t nops_after = nops_needed - nops_before;
                    
                    mutation_possibility poss;
                    poss.type = mutation_possibility::COMBO;
                    poss.pattern_ids.push_back(known_patterns[p1].id);
                    poss.pattern_ids.push_back(known_patterns[p2].id);
                    poss.nops_before = nops_before;
                    poss.nops_after = nops_after;
                    poss.total_size = target_size;
                    
                    possibilities.push_back(poss);
                }
            }
        }
    }
    
    return possibilities;
}

static void write_nops(uint8_t* dest, size_t count)
{
    for (size_t i = 0; i < count; i++)
        dest[i] = 0x90;
}

static ghost_pattern* get_pattern_by_id(int32_t pattern_id)
{
    for (size_t i = 0; i < NUM_PATTERNS; i++)
        if (known_patterns[i].id == pattern_id) return &known_patterns[i];

    return nullptr;
}

// apply the selected mutation
static int32_t apply_mutation(uint8_t* target_address, const mutation_possibility& mutation)
{
    uint8_t* write_ptr = target_address;

    if (mutation.nops_before > 0)
    {
        write_nops(write_ptr, mutation.nops_before);
        write_ptr += mutation.nops_before;
    }
    
    // patterns (or nothing if just NOPs)
    for (size_t i = 0; i < mutation.pattern_ids.size(); i++)
    {
        ghost_pattern* pattern = get_pattern_by_id(mutation.pattern_ids[i]);
        if (!pattern) return -1;
        
        memcpy(write_ptr, pattern->opcodes, pattern->length);
        write_ptr += pattern->length;
    }
    
    // NOPs after
    if (mutation.nops_after > 0)
    {
        write_nops(write_ptr, mutation.nops_after);
        write_ptr += mutation.nops_after;
    }
    
    return 0;
}

static mutation_possibility select_mutation(const std::vector<mutation_possibility>& possibilities)
{
    if (possibilities.empty())
    {
        mutation_possibility fallback;
        fallback.type = mutation_possibility::DIRECT;
        fallback.pattern_ids.clear();
        fallback.nops_before = 0;
        fallback.nops_after = 0;
        fallback.total_size = 0;
        fallback.description = "DIRECT";

        return fallback;
    }
    
    // separate by types
    std::vector<mutation_possibility> direct_opts;
    std::vector<mutation_possibility> padding_opts;
    std::vector<mutation_possibility> combo_opts;
    
    for (const auto& poss : possibilities)
    {
        switch (poss.type)
        {
            case mutation_possibility::DIRECT:
                direct_opts.push_back(poss);
                break;
            case mutation_possibility::PADDING:
                padding_opts.push_back(poss);
                break;
            case mutation_possibility::COMBO:
                combo_opts.push_back(poss);
                break;
        }
    }
    
    // 25% direct, 40% padding, 35% combo
    uint32_t type_roll = random(99);
    
    std::vector<mutation_possibility>* chosen_pool = nullptr;
    
    if (type_roll < 25 && !direct_opts.empty())
        chosen_pool = &direct_opts;
    else if (type_roll < 65 && !padding_opts.empty())
        chosen_pool = &padding_opts;
    else if (!combo_opts.empty())
        chosen_pool = &combo_opts;
    else
    {
        // hierarchical fallback
        if (!padding_opts.empty()) chosen_pool = &padding_opts;
        else if (!combo_opts.empty()) chosen_pool = &combo_opts;
        else if (!direct_opts.empty()) chosen_pool = &direct_opts;

        else return possibilities[0];
    }
    
    uint32_t index = random(chosen_pool->size() - 1);
    mutation_possibility result = (*chosen_pool)[index];

    switch (result.type)
    {
        case mutation_possibility::DIRECT:
            result.description = "DIRECT";
            break;
        case mutation_possibility::PADDING:
            result.description = "PADDING";
            break;
        case mutation_possibility::COMBO:
            result.description = "COMBO";
            break;
    }

    return result;
}

static void shuffle_possibilities(std::vector<mutation_possibility>& possibilities)
{
    for (size_t i = possibilities.size() - 1; i > 0; i--)
    {
        uint32_t j = random(i);
        std::swap(possibilities[i], possibilities[j]);
    }
}

/*
// Estrutura para variações de registradores
typedef struct
{
    uint8_t opcodes[3];      // Suporta até 3 bytes (REX + opcode + ModR/M)
    uint8_t length;          // Tamanho real da instrução
    const char* description; // Descrição da variante
} register_variant;

// Tabela de variações para MOV reg, reg (2 bytes - 32-bit)
static register_variant mov_reg32_variants[] =
{
    {{0x89, 0xC0, 0x00}, 2, "mov eax, eax"},   // EAX
    {{0x89, 0xC9, 0x00}, 2, "mov ecx, ecx"},   // ECX
    {{0x89, 0xD2, 0x00}, 2, "mov edx, edx"},   // EDX
    {{0x89, 0xDB, 0x00}, 2, "mov ebx, ebx"},   // EBX
    {{0x89, 0xE4, 0x00}, 2, "mov esp, esp"},   // ESP
    {{0x89, 0xED, 0x00}, 2, "mov ebp, ebp"},   // EBP
    {{0x89, 0xF6, 0x00}, 2, "mov esi, esi"},   // ESI
    {{0x89, 0xFF, 0x00}, 2, "mov edi, edi"}    // EDI
};

// Tabela de variações para MOV reg, reg (2 bytes - encoding alternativo)
static register_variant mov_reg32_alt_variants[] =
{
    {{0x8B, 0xC0, 0x00}, 2, "mov eax, eax (alt)"},
    {{0x8B, 0xC9, 0x00}, 2, "mov ecx, ecx (alt)"},
    {{0x8B, 0xD2, 0x00}, 2, "mov edx, edx (alt)"},
    {{0x8B, 0xDB, 0x00}, 2, "mov ebx, ebx (alt)"},
    {{0x8B, 0xE4, 0x00}, 2, "mov esp, esp (alt)"},
    {{0x8B, 0xED, 0x00}, 2, "mov ebp, ebp (alt)"},
    {{0x8B, 0xF6, 0x00}, 2, "mov esi, esi (alt)"},
    {{0x8B, 0xFF, 0x00}, 2, "mov edi, edi (alt)"}
};

// Tabela de variações para MOV reg, reg (3 bytes - 64-bit com REX)
static register_variant mov_reg64_variants[] =
{
    {{0x48, 0x89, 0xC0}, 3, "mov rax, rax"},   // RAX
    {{0x48, 0x89, 0xC9}, 3, "mov rcx, rcx"},   // RCX
    {{0x48, 0x89, 0xD2}, 3, "mov rdx, rdx"},   // RDX
    {{0x48, 0x89, 0xDB}, 3, "mov rbx, rbx"},   // RBX
    {{0x48, 0x89, 0xE4}, 3, "mov rsp, rsp"},   // RSP
    {{0x48, 0x89, 0xED}, 3, "mov rbp, rbp"},   // RBP
    {{0x48, 0x89, 0xF6}, 3, "mov rsi, rsi"},   // RSI
    {{0x48, 0x89, 0xFF}, 3, "mov rdi, rdi"}    // RDI
};

// Tabela de variações para XCHG rax, reg (2 bytes)
static register_variant xchg_rax_variants[] =
{
    {{0x48, 0x90, 0x00}, 2, "xchg rax, rax"},  // NOP equivalente
    {{0x48, 0x91, 0x00}, 2, "xchg rax, rcx"},
    {{0x48, 0x92, 0x00}, 2, "xchg rax, rdx"},
    {{0x48, 0x93, 0x00}, 2, "xchg rax, rbx"},
    {{0x48, 0x94, 0x00}, 2, "xchg rax, rsp"},
    {{0x48, 0x95, 0x00}, 2, "xchg rax, rbp"},
    {{0x48, 0x96, 0x00}, 2, "xchg rax, rsi"},
    {{0x48, 0x97, 0x00}, 2, "xchg rax, rdi"}
};

#define NUM_MOV32_VARIANTS (sizeof(mov_reg32_variants) / sizeof(register_variant))
#define NUM_MOV32_ALT_VARIANTS (sizeof(mov_reg32_alt_variants) / sizeof(register_variant))
#define NUM_MOV64_VARIANTS (sizeof(mov_reg64_variants) / sizeof(register_variant))
#define NUM_XCHG_VARIANTS (sizeof(xchg_rax_variants) / sizeof(register_variant))

// Seleciona uma variante aleatória de um conjunto
register_variant* select_random_variant(register_variant* variants, size_t count)
{
    if (count == 0) return nullptr;
    uint32_t index = random(count - 1);
    return &variants[index];
}

// Aplica uma variante de registrador
int32_t apply_register_variant(uint8_t* target_address, size_t original_size, register_variant* variant)
{
    if (!variant) return -1;
    
    // Verifica compatibilidade de tamanho
    if (variant->length != original_size)
    {
        printf("[!] size mismatch: original=%zu, variant=%d\n", original_size, variant->length);
        return -1;
    }
    
    // Copia a variante para o endereço de destino
    memcpy(target_address, variant->opcodes, variant->length);
    
    return 0;
}

// Função principal de mutação com variações de registrador
int32_t mutate_with_register_variants(ghost_code_result* result)
{
    if (!result || result->total_occurrences == 0)
    {
        printf("[!] no ghost code occurrences to mutate\n");
        return -1;
    }
    
    int mutations_applied = 0;
    
    for (int i = 0; i < result->total_occurrences; i++)
    {
        ghost_occurrence* occ = &result->occurrences[i];
        ghost_pattern* original = get_pattern_by_id(occ->pattern_id);
        
        if (!original)
        {
            printf("[!] invalid pattern id %d at index %d\n", occ->pattern_id, i);
            continue;
        }
        
        register_variant* selected_variant = nullptr;
        bool use_register_variant = false;
        
        // Determina qual tipo de variante usar baseado no padrão original
        switch (occ->pattern_id)
        {
            case 0: // xchg rax, rax (2 bytes)
                if (original->length == 2)
                {
                    selected_variant = select_random_variant(xchg_rax_variants, NUM_XCHG_VARIANTS);
                    use_register_variant = true;
                }
                break;
                
            case 1: // MOV EAX, EAX (2 bytes - 0x89 0xC0)
                selected_variant = select_random_variant(mov_reg32_variants, NUM_MOV32_VARIANTS);
                use_register_variant = true;
                break;
                
            case 4: // MOV RAX, RAX (3 bytes - 0x48 0x89 0xC0)
                selected_variant = select_random_variant(mov_reg64_variants, NUM_MOV64_VARIANTS);
                use_register_variant = true;
                break;
                
            case 5: // MOV EAX, EAX alternativo (2 bytes - 0x8B 0xC0)
                selected_variant = select_random_variant(mov_reg32_alt_variants, NUM_MOV32_ALT_VARIANTS);
                use_register_variant = true;
                break;
                
            default:
                // Para outros padrões (LEA, NOPs), usar mutação normal
                use_register_variant = false;
                break;
        }
        
        if (use_register_variant && selected_variant)
        {
            // Aplica variante de registrador
            if (apply_register_variant(occ->address, original->length, selected_variant) == 0)
            {
                printf("[+] applied register variant at %p: %s\n", 
                       occ->address, selected_variant->description);
                mutations_applied++;
            }
            else
            {
                printf("[!] failed to apply register variant at %p\n", occ->address);
            }
        }
        else
        {
            // Usa mutação padrão para padrões sem variantes de registrador
            std::vector<mutation_possibility> possibilities = generate_possibilities(original->length);
            
            if (possibilities.empty())
            {
                printf("[!] no mutation possibilities for pattern %d\n", occ->pattern_id);
                continue;
            }
            
            shuffle_possibilities(possibilities);
            mutation_possibility selected = select_mutation(possibilities);
            
            if (apply_mutation(occ->address, selected) == 0)
            {
                printf("[+] applied standard mutation at %p: type %d, %zu pattern(s)\n",
                       occ->address, selected.type, selected.pattern_ids.size());
                mutations_applied++;
            else
                printf("[!] failed to apply standard mutation at %p\n", occ->address);
        }
    }
    
    printf("[*] total mutations applied: %d / %d\n", mutations_applied, result->total_occurrences);
    
    return mutations_applied > 0 ? 0 : -1;
}
*/

typedef struct
{
    int32_t direct_count;
    int32_t padding_count;
    int32_t combo_count;
    int32_t total_possibilities;
} mutation_stats;

int32_t mutate(ghost_code_result* result)
{
    if (!result || result->total_occurrences == 0) return 0;
    
    // chooses only 1 pattern
    int32_t chosen_index = random(result->total_occurrences - 1);
    
    printf("[+] mutating 1 of %d ghost code occurrences (index %d)\n", 
           result->total_occurrences, chosen_index);
    
    ghost_occurrence* occ = &result->occurrences[chosen_index];
    
    ghost_pattern* original_pattern = get_pattern_by_id(occ->pattern_id);
    if (!original_pattern)
    {
        printf("[!] invalid pattern id %d\n", occ->pattern_id);
        return -1;
    }
    
    size_t original_size = original_pattern->length;
    
    // generate all possibilities for this pattern
    std::vector<mutation_possibility> possibilities = generate_possibilities(original_size);
    
    printf("[*] generated %zu mutation possibilities for pattern %d <%s> (size: %zu bytes)\n",
           possibilities.size(), occ->pattern_id, known_patterns[occ->pattern_id].description, original_size
    );
    
    // shuffle to avoid bias
    shuffle_possibilities(possibilities);
    
    mutation_possibility selected = select_mutation(possibilities);

    if (apply_mutation(occ->address, selected) == 0)
    {
        printf("[+] mutated pattern %d <%s> at %p -> selected pattern type %d <%s> - %d pattern(s) size, %d for NOP sled, %d NOPs after\n",
               occ->pattern_id,
               known_patterns[occ->pattern_id].description,
               occ->address,
               selected.type,
               selected.description,
               (int)selected.pattern_ids.size(),
               selected.nops_before,
               selected.nops_after
        );
        
        return 0;
    }
    else
    {
        printf("[!] failed to mutate pattern %d at %p\n", occ->pattern_id, occ->address); // TODO
        return -1;
    }
}
