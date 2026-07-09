unsigned int u16_remask(unsigned int value)
{
    unsigned int low = value & 0xFFFFu;

    return ((low & 0xFFFFu) << 1) | ((low & 0xFFFFu) >> 15);
}
