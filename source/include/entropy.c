// no fallback if rdseed isnt avaliable or isnt supported by the hardware (may be a TODO?)

int32_t is_rdseed_supported(void)
{
    uint32_t eax, ebx, ecx, edx;
    
    if (__get_cpuid_max(0, NULL) < 7) return 0;
    if (__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) return (ebx & (1 << 18)) != 0;
    
    return 0;
}

// get a random 64-bit value using RDSEED with retry logic
int32_t get_rdseed64(uint64_t* value)
{
    int32_t retries = 10; // maximum retry attempts
    
    while (retries-- > 0)
    {
        if (_rdseed64_step(reinterpret_cast<unsigned long long*>(value))) return 0;
        usleep(100);
    }
    
    return 1; // failed after all retries
}

uint64_t rdseed_rand(void)
{
    static int32_t rdseed_checked = 0;
    static int32_t rdseed_available = 0;
    
    // check RDSEED support first
    if (!rdseed_checked)
    {
        rdseed_available = is_rdseed_supported();
        rdseed_checked = 1;
        
        if (rdseed_available)
            printf("[+] RDSEED is available -> using hardware entropy\n");
        else
            printf("[!] RDSEED is not available\n");
    }
    
    // try RDSEED if it is available
    if (rdseed_available)
    {
        uint64_t hw_random;
        if (get_rdseed64(&hw_random) == 0) return hw_random;

        printf("[!] RDSEED failed\n");
    }

    return 1;
}

// generate random number in range [0, max_value]
uint32_t random(uint32_t max_value)
{
    if (max_value == 0) { printf("[!] invalid rand() range, aborting\n"); return 1; }
    
    uint64_t raw = rdseed_rand();
    
    // use modulo with bias mitigation
    // for better distribution, i could implement rejection sampling
    // but this is simpler and adequate for most use cases
    return (uint32_t)(raw % (max_value + 1));
}

// generate random number in range [min_value, max_value]
uint32_t random_minmax(uint32_t min_value, uint32_t max_value)
{
    if (min_value > max_value)
    {
        uint32_t temp = min_value;
        
        min_value = max_value;
        max_value = temp;
    }
    
    uint32_t range = max_value - min_value;

    return min_value + random(range);

}
