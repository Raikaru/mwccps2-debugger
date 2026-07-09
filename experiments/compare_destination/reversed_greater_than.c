int compare_destination(int left, int right)
{
    int selected = right;

    if (right > left) {
        selected = left;
    }
    return selected;
}
