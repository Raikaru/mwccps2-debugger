
static int extend_short(short value)
{
    return (int)value;
}


int repeated_sign_extension(int value)
{
    return extend_short((short)value) + extend_short((short)value) + extend_short((short)value);
}
