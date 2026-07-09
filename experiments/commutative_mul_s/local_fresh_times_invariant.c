float commutative_mul_s(float fresh, float invariant)
{
    volatile float local_fresh = fresh;

    return local_fresh * invariant;
}
