unsigned int invariant_mask(const unsigned int *values, int count, unsigned int mask)
{
    unsigned int total = 0;

    while (count > 0) {
        total += *values & (mask & 0xFFFFu);
        ++values;
        --count;
    }
    return total;
}
