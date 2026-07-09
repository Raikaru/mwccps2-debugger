unsigned int invariant_mask(const unsigned int *values, int count, unsigned int mask)
{
    unsigned int total = 0;
    unsigned int low_mask = mask & 0xFFFFu;

    while (count > 0) {
        total += *values & low_mask;
        ++values;
        --count;
    }
    return total;
}
