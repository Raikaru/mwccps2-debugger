int commutative_addu(const int *base, int index)
{
    return *(const int *)((const unsigned char *)base + index * (int)sizeof(*base));
}
