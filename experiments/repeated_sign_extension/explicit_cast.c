
static int extend_with_cast(int value)
{
    return (int)(short)value;
}


int repeated_sign_extension(int value)
{
    return extend_with_cast(value) + extend_with_cast(value) + extend_with_cast(value);
}
