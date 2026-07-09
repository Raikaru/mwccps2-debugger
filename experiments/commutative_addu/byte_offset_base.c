int commutative_addu(const int *base, int index)
{
    return *(const int *)(index * (int)sizeof(*base) + (const unsigned char *)base);
}
