int compare_destination(int left, int right)
{
    int selected = right;

    if (left < right) {
        selected = left;
    }
    return selected;
}
