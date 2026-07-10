typedef struct P3LoopUnit {
    int char_id;
    unsigned char unknown_04[0x44];
    const void *genus_base;
    unsigned char unknown_4c[4];
    const void *model;
    unsigned char unknown_54[0x16c];
} P3LoopUnit;

extern P3LoopUnit gFldUnitsPc[];

int p3_global_base_scaled_index(const void *model)
{
    P3LoopUnit *units;
    int i;

    units = gFldUnitsPc;
    for (i = 0; i < 4; i++)
    {
        if (units[i].genus_base != 0 && units[i].model == model)
        {
            return gFldUnitsPc[i].char_id;
        }
    }

    return -1;
}
