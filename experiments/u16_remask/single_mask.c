unsigned int u16_remask(unsigned int value)
{
    unsigned int low = value & 0xFFFFu;

    return (low << 1) | (low >> 15);
}
