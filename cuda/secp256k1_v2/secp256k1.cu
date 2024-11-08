#include "secp256k1.cuh"
#include "secp256k1_constants.cuh"
#include "../utils.cuh"

__device__ void secp256k1_pubkey_load(secp256k1_ge* ge, const uint8_t* pubkey)
{
    secp256k1_fe x, y;
    secp256k1_fe_set_b32(&x, pubkey);
    secp256k1_fe_set_b32(&y, pubkey + 32);
    secp256k1_ge_set_xy(ge, &x, &y);
}

__device__ void secp256k1_fe_normalize_var(secp256k1_fe* r)
{
    uint32_t t0 = r->n[0];
    uint32_t t1 = r->n[1];
    uint32_t t2 = r->n[2];
    uint32_t t3 = r->n[3];
    uint32_t t4 = r->n[4];
    uint32_t t5 = r->n[5];
    uint32_t t6 = r->n[6];
    uint32_t t7 = r->n[7];
    uint32_t t8 = r->n[8];
    uint32_t t9 = r->n[9];

    /* Reduce t9 at the start so there will be at most a single carry from the first pass */
    uint32_t m;
    uint32_t x = t9 >> 22;

    t9 &= 0x03FFFFFUL;

    /* The first pass ensures the magnitude is 1, ... */
    t0 += x * 0x3D1UL;
    t1 += (x << 6);
    t1 += (t0 >> 26);
    t0 &= 0x3FFFFFFUL;
    t2 += (t1 >> 26);
    t1 &= 0x3FFFFFFUL;
    t3 += (t2 >> 26);
    t2 &= 0x3FFFFFFUL;
    m = t2;
    t4 += (t3 >> 26);
    t3 &= 0x3FFFFFFUL;
    m &= t3;
    t5 += (t4 >> 26);
    t4 &= 0x3FFFFFFUL;
    m &= t4;
    t6 += (t5 >> 26);
    t5 &= 0x3FFFFFFUL;
    m &= t5;
    t7 += (t6 >> 26);
    t6 &= 0x3FFFFFFUL;
    m &= t6;
    t8 += (t7 >> 26);
    t7 &= 0x3FFFFFFUL;
    m &= t7;
    t9 += (t8 >> 26);
    t8 &= 0x3FFFFFFUL;
    m &= t8;

    /* At most a single final reduction is needed; check if the value is >= the field characteristic */
    x = (t9 >> 22) | ((t9 == 0x03FFFFFUL) & (m == 0x3FFFFFFUL) & ((t1 + 0x40UL + ((t0 + 0x3D1UL) >> 26)) > 0x3FFFFFFUL));

    if (x)
    {
        t0 += 0x3D1UL;
        t1 += (x << 6);
        t1 += (t0 >> 26);
        t0 &= 0x3FFFFFFUL;
        t2 += (t1 >> 26);
        t1 &= 0x3FFFFFFUL;
        t3 += (t2 >> 26);
        t2 &= 0x3FFFFFFUL;
        t4 += (t3 >> 26);
        t3 &= 0x3FFFFFFUL;
        t5 += (t4 >> 26);
        t4 &= 0x3FFFFFFUL;
        t6 += (t5 >> 26);
        t5 &= 0x3FFFFFFUL;
        t7 += (t6 >> 26);
        t6 &= 0x3FFFFFFUL;
        t8 += (t7 >> 26);
        t7 &= 0x3FFFFFFUL;
        t9 += (t8 >> 26);
        t8 &= 0x3FFFFFFUL;
        t9 &= 0x03FFFFFUL;
    }

    r->n[0] = t0;
    r->n[1] = t1;
    r->n[2] = t2;
    r->n[3] = t3;
    r->n[4] = t4;
    r->n[5] = t5;
    r->n[6] = t6;
    r->n[7] = t7;
    r->n[8] = t8;
    r->n[9] = t9;
}

__device__ void secp256k1_scalar_set_b32(secp256k1_scalar* r, const uint8_t* b32, int* overflow)
{
    r->d[0] = static_cast<uint32_t>(b32[31]) | static_cast<uint32_t>(b32[30]) << 8 | static_cast<uint32_t>(b32[29]) << 16 | static_cast<uint32_t>(b32[28]) << 24;
    r->d[1] = static_cast<uint32_t>(b32[27]) | static_cast<uint32_t>(b32[26]) << 8 | static_cast<uint32_t>(b32[25]) << 16 | static_cast<uint32_t>(b32[24]) << 24;
    r->d[2] = static_cast<uint32_t>(b32[23]) | static_cast<uint32_t>(b32[22]) << 8 | static_cast<uint32_t>(b32[21]) << 16 | static_cast<uint32_t>(b32[20]) << 24;
    r->d[3] = static_cast<uint32_t>(b32[19]) | static_cast<uint32_t>(b32[18]) << 8 | static_cast<uint32_t>(b32[17]) << 16 | static_cast<uint32_t>(b32[16]) << 24;
    r->d[4] = static_cast<uint32_t>(b32[15]) | static_cast<uint32_t>(b32[14]) << 8 | static_cast<uint32_t>(b32[13]) << 16 | static_cast<uint32_t>(b32[12]) << 24;
    r->d[5] = static_cast<uint32_t>(b32[11]) | static_cast<uint32_t>(b32[10]) << 8 | static_cast<uint32_t>(b32[9]) << 16 | static_cast<uint32_t>(b32[8]) << 24;
    r->d[6] = static_cast<uint32_t>(b32[7]) | static_cast<uint32_t>(b32[6]) << 8 | static_cast<uint32_t>(b32[5]) << 16 | static_cast<uint32_t>(b32[4]) << 24;
    r->d[7] = static_cast<uint32_t>(b32[3]) | static_cast<uint32_t>(b32[2]) << 8 | static_cast<uint32_t>(b32[1]) << 16 | static_cast<uint32_t>(b32[0]) << 24;

    const int over = secp256k1_scalar_reduce(r, secp256k1_scalar_check_overflow(r));
    if (overflow)
    {
        *overflow = over;
    }
}

__device__ int secp256k1_scalar_set_b32_seckey(secp256k1_scalar* r, const uint8_t* bin)
{
    int overflow;
    secp256k1_scalar_set_b32(r, bin, &overflow);
    return (!overflow) & (!secp256k1_scalar_is_zero(r));
}

__device__ int secp256k1_eckey_compressed_pubkey_serialize(secp256k1_ge* elem, uint8_t* pub)
{
    if (secp256k1_ge_is_infinity(elem))
    {
        return 0;
    }

    secp256k1_fe_normalize_var(&elem->x);
    secp256k1_fe_normalize_var(&elem->y);
    secp256k1_fe_get_b32(&pub[1], &elem->x);

    pub[0] = secp256k1_fe_is_odd(&elem->y) ? SECP256K1_TAG_PUBKEY_ODD : SECP256K1_TAG_PUBKEY_EVEN;

    return 1;
}

__device__ int secp256k1_ec_compressed_pubkey_serialize(uint8_t* output, uint32_t outputLen, const uint8_t* pubkey)
{
    cuda_memset(output, 0, outputLen);

    secp256k1_ge Q{};
    secp256k1_pubkey_load(&Q, pubkey);
    return secp256k1_eckey_compressed_pubkey_serialize(&Q, output);
}

__device__ int secp256k1_scalar_add(secp256k1_scalar* r, const secp256k1_scalar* a, const secp256k1_scalar* b)
{
    uint64_t t;
    t = static_cast<uint64_t>(a->d[0]) + b->d[0];
    r->d[0] = t & 0xFFFFFFFFUL;
    t >>= 32;
    t += static_cast<uint64_t>(a->d[1]) + b->d[1];
    r->d[1] = t & 0xFFFFFFFFUL;
    t >>= 32;
    t += static_cast<uint64_t>(a->d[2]) + b->d[2];
    r->d[2] = t & 0xFFFFFFFFUL;
    t >>= 32;
    t += static_cast<uint64_t>(a->d[3]) + b->d[3];
    r->d[3] = t & 0xFFFFFFFFUL;
    t >>= 32;
    t += static_cast<uint64_t>(a->d[4]) + b->d[4];
    r->d[4] = t & 0xFFFFFFFFUL;
    t >>= 32;
    t += static_cast<uint64_t>(a->d[5]) + b->d[5];
    r->d[5] = t & 0xFFFFFFFFUL;
    t >>= 32;
    t += static_cast<uint64_t>(a->d[6]) + b->d[6];
    r->d[6] = t & 0xFFFFFFFFUL;
    t >>= 32;
    t += static_cast<uint64_t>(a->d[7]) + b->d[7];
    r->d[7] = t & 0xFFFFFFFFUL;
    t >>= 32;

    int overflow = t + secp256k1_scalar_check_overflow(r);
    secp256k1_scalar_reduce(r, overflow);
    return overflow;
}

__device__ int secp256k1_eckey_privkey_tweak_add(secp256k1_scalar* key, const secp256k1_scalar* tweak)
{
    secp256k1_scalar_add(key, key, tweak);
    return !secp256k1_scalar_is_zero(key);
}

__device__ int secp256k1_ec_seckey_tweak_add(uint8_t* seckey, const uint8_t* tweak)
{
    secp256k1_scalar term;
    secp256k1_scalar sec;

    int overflow = 0;
    secp256k1_scalar_set_b32(&term, tweak, &overflow);

    int ret = secp256k1_scalar_set_b32_seckey(&sec, seckey);
    ret &= (!overflow) & secp256k1_eckey_privkey_tweak_add(&sec, &term);

    secp256k1_scalar secp256k1_scalar_zero = SECP256K1_SCALAR_CONST(0, 0, 0, 0, 0, 0, 0, 0);
    secp256k1_scalar_cmov(&sec, &secp256k1_scalar_zero, !ret);
    secp256k1_scalar_get_b32(seckey, &sec);

    return ret;
}

__device__ void secp256k1_fe_normalize_weak(secp256k1_fe* r)
{
    uint32_t t0 = r->n[0];
    uint32_t t1 = r->n[1];
    uint32_t t2 = r->n[2];
    uint32_t t3 = r->n[3];
    uint32_t t4 = r->n[4];
    uint32_t t5 = r->n[5];
    uint32_t t6 = r->n[6];
    uint32_t t7 = r->n[7];
    uint32_t t8 = r->n[8];
    uint32_t t9 = r->n[9];

    /* Reduce t9 at the start so there will be at most a single carry from the first pass */
    uint32_t x = t9 >> 22;
    t9 &= 0x03FFFFFUL;

    /* The first pass ensures the magnitude is 1, ... */
    t0 += x * 0x3D1UL;
    t1 += (x << 6);
    t1 += (t0 >> 26);
    t0 &= 0x3FFFFFFUL;
    t2 += (t1 >> 26);
    t1 &= 0x3FFFFFFUL;
    t3 += (t2 >> 26);
    t2 &= 0x3FFFFFFUL;
    t4 += (t3 >> 26);
    t3 &= 0x3FFFFFFUL;
    t5 += (t4 >> 26);
    t4 &= 0x3FFFFFFUL;
    t6 += (t5 >> 26);
    t5 &= 0x3FFFFFFUL;
    t7 += (t6 >> 26);
    t6 &= 0x3FFFFFFUL;
    t8 += (t7 >> 26);
    t7 &= 0x3FFFFFFUL;
    t9 += (t8 >> 26);
    t8 &= 0x3FFFFFFUL;

    r->n[0] = t0;
    r->n[1] = t1;
    r->n[2] = t2;
    r->n[3] = t3;
    r->n[4] = t4;
    r->n[5] = t5;
    r->n[6] = t6;
    r->n[7] = t7;
    r->n[8] = t8;
    r->n[9] = t9;
}

__device__ int secp256k1_fe_normalizes_to_zero(secp256k1_fe* r)
{
    uint32_t t0 = r->n[0];
    uint32_t t1 = r->n[1];
    uint32_t t2 = r->n[2];
    uint32_t t3 = r->n[3];
    uint32_t t4 = r->n[4];
    uint32_t t5 = r->n[5];
    uint32_t t6 = r->n[6];
    uint32_t t7 = r->n[7];
    uint32_t t8 = r->n[8];
    uint32_t t9 = r->n[9];
    /* z0 tracks a possible raw value of 0, z1 tracks a possible raw value of P */
    uint32_t z0, z1;

    /* Reduce t9 at the start so there will be at most a single carry from the first pass */
    uint32_t x = t9 >> 22;
    t9 &= 0x03FFFFFUL;

    /* The first pass ensures the magnitude is 1, ... */
    t0 += x * 0x3D1UL;
    t1 += (x << 6);
    t1 += (t0 >> 26);
    t0 &= 0x3FFFFFFUL;
    z0 = t0;
    z1 = t0 ^ 0x3D0UL;
    t2 += (t1 >> 26);
    t1 &= 0x3FFFFFFUL;
    z0 |= t1;
    z1 &= t1 ^ 0x40UL;
    t3 += (t2 >> 26);
    t2 &= 0x3FFFFFFUL;
    z0 |= t2;
    z1 &= t2;
    t4 += (t3 >> 26);
    t3 &= 0x3FFFFFFUL;
    z0 |= t3;
    z1 &= t3;
    t5 += (t4 >> 26);
    t4 &= 0x3FFFFFFUL;
    z0 |= t4;
    z1 &= t4;
    t6 += (t5 >> 26);
    t5 &= 0x3FFFFFFUL;
    z0 |= t5;
    z1 &= t5;
    t7 += (t6 >> 26);
    t6 &= 0x3FFFFFFUL;
    z0 |= t6;
    z1 &= t6;
    t8 += (t7 >> 26);
    t7 &= 0x3FFFFFFUL;
    z0 |= t7;
    z1 &= t7;
    t9 += (t8 >> 26);
    t8 &= 0x3FFFFFFUL;
    z0 |= t8;
    z1 &= t8;
    z0 |= t9;
    z1 &= t9 ^ 0x3C00000UL;

    return (z0 == 0) | (z1 == 0x3FFFFFFUL);
}

__device__ void secp256k1_fe_sqr_inner(uint32_t* r, const uint32_t* a)
{
    uint64_t c, d;
    uint64_t u0, u1, u2, u3, u4, u5, u6, u7, u8;
    uint32_t t9, t0, t1, t2, t3, t4, t5, t6, t7;

    d = static_cast<uint64_t>(a[0] * 2) * a[9]
        + static_cast<uint64_t>(a[1] * 2) * a[8]
        + static_cast<uint64_t>(a[2] * 2) * a[7]
        + static_cast<uint64_t>(a[3] * 2) * a[6]
        + static_cast<uint64_t>(a[4] * 2) * a[5];
    t9 = d & M;
    d >>= 26;
    c = static_cast<uint64_t>(a[0]) * a[0];
    d += static_cast<uint64_t>(a[1] * 2) * a[9]
         + static_cast<uint64_t>(a[2] * 2) * a[8]
         + static_cast<uint64_t>(a[3] * 2) * a[7]
         + static_cast<uint64_t>(a[4] * 2) * a[6]
         + static_cast<uint64_t>(a[5]) * a[5];
    u0 = d & M;
    d >>= 26;
    c += u0 * R0;
    t0 = c & M;
    c >>= 26;
    c += u0 * R1;
    c += static_cast<uint64_t>(a[0] * 2) * a[1];
    d += static_cast<uint64_t>(a[2] * 2) * a[9]
         + static_cast<uint64_t>(a[3] * 2) * a[8]
         + static_cast<uint64_t>(a[4] * 2) * a[7]
         + static_cast<uint64_t>(a[5] * 2) * a[6];
    u1 = d & M;
    d >>= 26;
    c += u1 * R0;
    t1 = c & M;
    c >>= 26;
    c += u1 * R1;
    c += static_cast<uint64_t>(a[0] * 2) * a[2]
         + static_cast<uint64_t>(a[1]) * a[1];
    d += static_cast<uint64_t>(a[3] * 2) * a[9]
         + static_cast<uint64_t>(a[4] * 2) * a[8]
         + static_cast<uint64_t>(a[5] * 2) * a[7]
         + static_cast<uint64_t>(a[6]) * a[6];
    u2 = d & M;
    d >>= 26;
    c += u2 * R0;
    t2 = c & M;
    c >>= 26;
    c += u2 * R1;
    c += static_cast<uint64_t>(a[0] * 2) * a[3]
         + static_cast<uint64_t>(a[1] * 2) * a[2];
    d += static_cast<uint64_t>(a[4] * 2) * a[9]
         + static_cast<uint64_t>(a[5] * 2) * a[8]
         + static_cast<uint64_t>(a[6] * 2) * a[7];
    u3 = d & M;
    d >>= 26;
    c += u3 * R0;
    t3 = c & M;
    c >>= 26;
    c += u3 * R1;
    c += static_cast<uint64_t>(a[0] * 2) * a[4]
         + static_cast<uint64_t>(a[1] * 2) * a[3]
         + static_cast<uint64_t>(a[2]) * a[2];
    d += static_cast<uint64_t>(a[5] * 2) * a[9]
         + static_cast<uint64_t>(a[6] * 2) * a[8]
         + static_cast<uint64_t>(a[7]) * a[7];
    u4 = d & M;
    d >>= 26;
    c += u4 * R0;
    t4 = c & M;
    c >>= 26;
    c += u4 * R1;
    c += static_cast<uint64_t>(a[0] * 2) * a[5]
         + static_cast<uint64_t>(a[1] * 2) * a[4]
         + static_cast<uint64_t>(a[2] * 2) * a[3];
    d += static_cast<uint64_t>(a[6] * 2) * a[9]
         + static_cast<uint64_t>(a[7] * 2) * a[8];
    u5 = d & M;
    d >>= 26;
    c += u5 * R0;
    t5 = c & M;
    c >>= 26;
    c += u5 * R1;
    c += static_cast<uint64_t>(a[0] * 2) * a[6]
         + static_cast<uint64_t>(a[1] * 2) * a[5]
         + static_cast<uint64_t>(a[2] * 2) * a[4]
         + static_cast<uint64_t>(a[3]) * a[3];
    d += static_cast<uint64_t>(a[7] * 2) * a[9]
         + static_cast<uint64_t>(a[8]) * a[8];
    u6 = d & M;
    d >>= 26;
    c += u6 * R0;
    t6 = c & M;
    c >>= 26;
    c += u6 * R1;
    c += static_cast<uint64_t>(a[0] * 2) * a[7]
         + static_cast<uint64_t>(a[1] * 2) * a[6]
         + static_cast<uint64_t>(a[2] * 2) * a[5]
         + static_cast<uint64_t>(a[3] * 2) * a[4];
    d += static_cast<uint64_t>(a[8] * 2) * a[9];
    u7 = d & M;
    d >>= 26;
    c += u7 * R0;
    t7 = c & M;
    c >>= 26;
    c += u7 * R1;
    c += static_cast<uint64_t>(a[0] * 2) * a[8]
         + static_cast<uint64_t>(a[1] * 2) * a[7]
         + static_cast<uint64_t>(a[2] * 2) * a[6]
         + static_cast<uint64_t>(a[3] * 2) * a[5]
         + static_cast<uint64_t>(a[4]) * a[4];
    d += static_cast<uint64_t>(a[9]) * a[9];
    u8 = d & M;
    d >>= 26;
    c += u8 * R0;
    r[3] = t3;
    r[4] = t4;
    r[5] = t5;
    r[6] = t6;
    r[7] = t7;
    r[8] = c & M;
    c >>= 26;
    c += u8 * R1;
    c += d * R0 + t9;
    r[9] = c & (M >> 4);
    c >>= 22;
    c += d * (R1 << 4);
    d = c * (R0 >> 4) + t0;
    r[0] = d & M;
    d >>= 26;
    d += c * (R1 >> 4) + t1;
    r[1] = d & M;
    d >>= 26;
    d += t2;
    r[2] = d;
}

__device__ void secp256k1_fe_sqr(secp256k1_fe* r, const secp256k1_fe* a)
{
    secp256k1_fe_sqr_inner(r->n, a->n);
}

__device__ void secp256k1_fe_mul_inner(uint32_t* r, const uint32_t* a, const uint32_t* b)
{
    uint64_t c, d;
    uint64_t u0, u1, u2, u3, u4, u5, u6, u7, u8;
    uint32_t t9, t1, t0, t2, t3, t4, t5, t6, t7;
//const uint32_t M = 0x3FFFFFFUL, R0 = 0x3D10UL, R1 = 0x400UL;
    d = static_cast<uint64_t>(a[0]) * b[9]
        + static_cast<uint64_t>(a[1]) * b[8]
        + static_cast<uint64_t>(a[2]) * b[7]
        + static_cast<uint64_t>(a[3]) * b[6]
        + static_cast<uint64_t>(a[4]) * b[5]
        + static_cast<uint64_t>(a[5]) * b[4]
        + static_cast<uint64_t>(a[6]) * b[3]
        + static_cast<uint64_t>(a[7]) * b[2]
        + static_cast<uint64_t>(a[8]) * b[1]
        + static_cast<uint64_t>(a[9]) * b[0];
/* VERIFY_BITS(d, 64); */
/* [d 0 0 0 0 0 0 0 0 0] = [p9 0 0 0 0 0 0 0 0 0] */
    t9 = d & M;
    d >>= 26;

/* [d t9 0 0 0 0 0 0 0 0 0] = [p9 0 0 0 0 0 0 0 0 0] */

    c = (uint64_t) a[0] * b[0];

/* [d t9 0 0 0 0 0 0 0 0 c] = [p9 0 0 0 0 0 0 0 0 p0] */
    d += static_cast<uint64_t>(a[1]) * b[9]
         + static_cast<uint64_t>(a[2]) * b[8]
         + static_cast<uint64_t>(a[3]) * b[7]
         + static_cast<uint64_t>(a[4]) * b[6]
         + static_cast<uint64_t>(a[5]) * b[5]
         + static_cast<uint64_t>(a[6]) * b[4]
         + static_cast<uint64_t>(a[7]) * b[3]
         + static_cast<uint64_t>(a[8]) * b[2]
         + static_cast<uint64_t>(a[9]) * b[1];

/* [d t9 0 0 0 0 0 0 0 0 c] = [p10 p9 0 0 0 0 0 0 0 0 p0] */
    u0 = d & M;
    d >>= 26;
    c += u0 * R0;

/* [d u0 t9 0 0 0 0 0 0 0 0 c-u0*R0] = [p10 p9 0 0 0 0 0 0 0 0 p0] */
    t0 = c & M;
    c >>= 26;
    c += u0 * R1;

/* [d u0 t9 0 0 0 0 0 0 0 c-u0*R1 t0-u0*R0] = [p10 p9 0 0 0 0 0 0 0 0 p0] */
/* [d 0 t9 0 0 0 0 0 0 0 c t0] = [p10 p9 0 0 0 0 0 0 0 0 p0] */

    c += (uint64_t) a[0] * b[1]
         + (uint64_t) a[1] * b[0];

/* [d 0 t9 0 0 0 0 0 0 0 c t0] = [p10 p9 0 0 0 0 0 0 0 p1 p0] */
    d += static_cast<uint64_t>(a[2]) * b[9]
         + static_cast<uint64_t>(a[3]) * b[8]
         + static_cast<uint64_t>(a[4]) * b[7]
         + static_cast<uint64_t>(a[5]) * b[6]
         + static_cast<uint64_t>(a[6]) * b[5]
         + static_cast<uint64_t>(a[7]) * b[4]
         + static_cast<uint64_t>(a[8]) * b[3]
         + static_cast<uint64_t>(a[9]) * b[2];

/* [d 0 t9 0 0 0 0 0 0 0 c t0] = [p11 p10 p9 0 0 0 0 0 0 0 p1 p0] */
    u1 = d & M;
    d >>= 26;
    c += u1 * R0;

/* [d u1 0 t9 0 0 0 0 0 0 0 c-u1*R0 t0] = [p11 p10 p9 0 0 0 0 0 0 0 p1 p0] */
    t1 = c & M;
    c >>= 26;
    c += u1 * R1;

/* [d u1 0 t9 0 0 0 0 0 0 c-u1*R1 t1-u1*R0 t0] = [p11 p10 p9 0 0 0 0 0 0 0 p1 p0] */
/* [d 0 0 t9 0 0 0 0 0 0 c t1 t0] = [p11 p10 p9 0 0 0 0 0 0 0 p1 p0] */

    c += static_cast<uint64_t>(a[0]) * b[2]
         + static_cast<uint64_t>(a[1]) * b[1]
         + static_cast<uint64_t>(a[2]) * b[0];

/* [d 0 0 t9 0 0 0 0 0 0 c t1 t0] = [p11 p10 p9 0 0 0 0 0 0 p2 p1 p0] */
    d += static_cast<uint64_t>(a[3]) * b[9]
         + static_cast<uint64_t>(a[4]) * b[8]
         + static_cast<uint64_t>(a[5]) * b[7]
         + static_cast<uint64_t>(a[6]) * b[6]
         + static_cast<uint64_t>(a[7]) * b[5]
         + static_cast<uint64_t>(a[8]) * b[4]
         + static_cast<uint64_t>(a[9]) * b[3];

/* [d 0 0 t9 0 0 0 0 0 0 c t1 t0] = [p12 p11 p10 p9 0 0 0 0 0 0 p2 p1 p0] */
    u2 = d & M;
    d >>= 26;
    c += u2 * R0;
/* [d u2 0 0 t9 0 0 0 0 0 0 c-u2*R0 t1 t0] = [p12 p11 p10 p9 0 0 0 0 0 0 p2 p1 p0] */
    t2 = c & M;
    c >>= 26;
    c += u2 * R1;

/* [d u2 0 0 t9 0 0 0 0 0 c-u2*R1 t2-u2*R0 t1 t0] = [p12 p11 p10 p9 0 0 0 0 0 0 p2 p1 p0] */
/* [d 0 0 0 t9 0 0 0 0 0 c t2 t1 t0] = [p12 p11 p10 p9 0 0 0 0 0 0 p2 p1 p0] */
    c += static_cast<uint64_t>(a[0]) * b[3]
         + static_cast<uint64_t>(a[1]) * b[2]
         + static_cast<uint64_t>(a[2]) * b[1]
         + static_cast<uint64_t>(a[3]) * b[0];

    d += static_cast<uint64_t>(a[4]) * b[9]
         + static_cast<uint64_t>(a[5]) * b[8]
         + static_cast<uint64_t>(a[6]) * b[7]
         + static_cast<uint64_t>(a[7]) * b[6]
         + static_cast<uint64_t>(a[8]) * b[5]
         + static_cast<uint64_t>(a[9]) * b[4];
    u3 = d & M;
    d >>= 26;
    c += u3 * R0;

/* VERIFY_BITS(c, 64); */
/* [d u3 0 0 0 t9 0 0 0 0 0 c-u3*R0 t2 t1 t0] = [p13 p12 p11 p10 p9 0 0 0 0 0 p3 p2 p1 p0] */
    t3 = c & M;
    c >>= 26;
    c += u3 * R1;

    c += static_cast<uint64_t>(a[0]) * b[4]
         + static_cast<uint64_t>(a[1]) * b[3]
         + static_cast<uint64_t>(a[2]) * b[2]
         + static_cast<uint64_t>(a[3]) * b[1]
         + static_cast<uint64_t>(a[4]) * b[0];

/* [d 0 0 0 0 t9 0 0 0 0 c t3 t2 t1 t0] = [p13 p12 p11 p10 p9 0 0 0 0 p4 p3 p2 p1 p0] */
    d += static_cast<uint64_t>(a[5]) * b[9]
         + static_cast<uint64_t>(a[6]) * b[8]
         + static_cast<uint64_t>(a[7]) * b[7]
         + static_cast<uint64_t>(a[8]) * b[6]
         + static_cast<uint64_t>(a[9]) * b[5];

/* [d 0 0 0 0 t9 0 0 0 0 c t3 t2 t1 t0] = [p14 p13 p12 p11 p10 p9 0 0 0 0 p4 p3 p2 p1 p0] */
    u4 = d & M;
    d >>= 26;
    c += u4 * R0;

/* VERIFY_BITS(c, 64); */
/* [d u4 0 0 0 0 t9 0 0 0 0 c-u4*R0 t3 t2 t1 t0] = [p14 p13 p12 p11 p10 p9 0 0 0 0 p4 p3 p2 p1 p0] */
    t4 = c & M;
    c >>= 26;
    c += u4 * R1;

/* [d u4 0 0 0 0 t9 0 0 0 c-u4*R1 t4-u4*R0 t3 t2 t1 t0] = [p14 p13 p12 p11 p10 p9 0 0 0 0 p4 p3 p2 p1 p0] */
/* [d 0 0 0 0 0 t9 0 0 0 c t4 t3 t2 t1 t0] = [p14 p13 p12 p11 p10 p9 0 0 0 0 p4 p3 p2 p1 p0] */

    c += static_cast<uint64_t>(a[0]) * b[5]
         + static_cast<uint64_t>(a[1]) * b[4]
         + static_cast<uint64_t>(a[2]) * b[3]
         + static_cast<uint64_t>(a[3]) * b[2]
         + static_cast<uint64_t>(a[4]) * b[1]
         + static_cast<uint64_t>(a[5]) * b[0];

/* [d 0 0 0 0 0 t9 0 0 0 c t4 t3 t2 t1 t0] = [p14 p13 p12 p11 p10 p9 0 0 0 p5 p4 p3 p2 p1 p0] */
    d += static_cast<uint64_t>(a[6]) * b[9]
         + static_cast<uint64_t>(a[7]) * b[8]
         + static_cast<uint64_t>(a[8]) * b[7]
         + static_cast<uint64_t>(a[9]) * b[6];

/* [d 0 0 0 0 0 t9 0 0 0 c t4 t3 t2 t1 t0] = [p15 p14 p13 p12 p11 p10 p9 0 0 0 p5 p4 p3 p2 p1 p0] */
    u5 = d & M;
    d >>= 26;
    c += u5 * R0;

/* VERIFY_BITS(c, 64); */
/* [d u5 0 0 0 0 0 t9 0 0 0 c-u5*R0 t4 t3 t2 t1 t0] = [p15 p14 p13 p12 p11 p10 p9 0 0 0 p5 p4 p3 p2 p1 p0] */
    t5 = c & M;
    c >>= 26;
    c += u5 * R1;

/* [d u5 0 0 0 0 0 t9 0 0 c-u5*R1 t5-u5*R0 t4 t3 t2 t1 t0] = [p15 p14 p13 p12 p11 p10 p9 0 0 0 p5 p4 p3 p2 p1 p0] */
/* [d 0 0 0 0 0 0 t9 0 0 c t5 t4 t3 t2 t1 t0] = [p15 p14 p13 p12 p11 p10 p9 0 0 0 p5 p4 p3 p2 p1 p0] */

    c += static_cast<uint64_t>(a[0]) * b[6]
         + static_cast<uint64_t>(a[1]) * b[5]
         + static_cast<uint64_t>(a[2]) * b[4]
         + static_cast<uint64_t>(a[3]) * b[3]
         + static_cast<uint64_t>(a[4]) * b[2]
         + static_cast<uint64_t>(a[5]) * b[1]
         + static_cast<uint64_t>(a[6]) * b[0];

/* [d 0 0 0 0 0 0 t9 0 0 c t5 t4 t3 t2 t1 t0] = [p15 p14 p13 p12 p11 p10 p9 0 0 p6 p5 p4 p3 p2 p1 p0] */
    d += static_cast<uint64_t>(a[7]) * b[9]
         + static_cast<uint64_t>(a[8]) * b[8]
         + static_cast<uint64_t>(a[9]) * b[7];

/* [d 0 0 0 0 0 0 t9 0 0 c t5 t4 t3 t2 t1 t0] = [p16 p15 p14 p13 p12 p11 p10 p9 0 0 p6 p5 p4 p3 p2 p1 p0] */
    u6 = d & M;
    d >>= 26;
    c += u6 * R0;

/* VERIFY_BITS(c, 64); */
/* [d u6 0 0 0 0 0 0 t9 0 0 c-u6*R0 t5 t4 t3 t2 t1 t0] = [p16 p15 p14 p13 p12 p11 p10 p9 0 0 p6 p5 p4 p3 p2 p1 p0] */
    t6 = c & M;
    c >>= 26;
    c += u6 * R1;

/* [d u6 0 0 0 0 0 0 t9 0 c-u6*R1 t6-u6*R0 t5 t4 t3 t2 t1 t0] = [p16 p15 p14 p13 p12 p11 p10 p9 0 0 p6 p5 p4 p3 p2 p1 p0] */
/* [d 0 0 0 0 0 0 0 t9 0 c t6 t5 t4 t3 t2 t1 t0] = [p16 p15 p14 p13 p12 p11 p10 p9 0 0 p6 p5 p4 p3 p2 p1 p0] */

    c += static_cast<uint64_t>(a[0]) * b[7]
         + static_cast<uint64_t>(a[1]) * b[6]
         + static_cast<uint64_t>(a[2]) * b[5]
         + static_cast<uint64_t>(a[3]) * b[4]
         + static_cast<uint64_t>(a[4]) * b[3]
         + static_cast<uint64_t>(a[5]) * b[2]
         + static_cast<uint64_t>(a[6]) * b[1]
         + static_cast<uint64_t>(a[7]) * b[0];
/* VERIFY_BITS(c, 64); */

/* [d 0 0 0 0 0 0 0 t9 0 c t6 t5 t4 t3 t2 t1 t0] = [p16 p15 p14 p13 p12 p11 p10 p9 0 p7 p6 p5 p4 p3 p2 p1 p0] */
    d += (uint64_t) a[8] * b[9]
         + (uint64_t) a[9] * b[8];

/* [d 0 0 0 0 0 0 0 t9 0 c t6 t5 t4 t3 t2 t1 t0] = [p17 p16 p15 p14 p13 p12 p11 p10 p9 0 p7 p6 p5 p4 p3 p2 p1 p0] */
    u7 = d & M;
    d >>= 26;
    c += u7 * R0;

    t7 = c & M;
    c >>= 26;
    c += u7 * R1;

    c += static_cast<uint64_t>(a[0]) * b[8]
         + static_cast<uint64_t>(a[1]) * b[7]
         + static_cast<uint64_t>(a[2]) * b[6]
         + static_cast<uint64_t>(a[3]) * b[5]
         + static_cast<uint64_t>(a[4]) * b[4]
         + static_cast<uint64_t>(a[5]) * b[3]
         + static_cast<uint64_t>(a[6]) * b[2]
         + static_cast<uint64_t>(a[7]) * b[1]
         + static_cast<uint64_t>(a[8]) * b[0];
/* VERIFY_BITS(c, 64); */

/* [d 0 0 0 0 0 0 0 0 t9 c t7 t6 t5 t4 t3 t2 t1 t0] = [p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    d += static_cast<uint64_t>(a[9]) * b[9];

/* [d 0 0 0 0 0 0 0 0 t9 c t7 t6 t5 t4 t3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    u8 = d & M;
    d >>= 26;
    c += u8 * R0;

/* [d u8 0 0 0 0 0 0 0 0 t9 c-u8*R0 t7 t6 t5 t4 t3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */

    r[3] = t3;
    r[4] = t4;
    r[5] = t5;
    r[6] = t6;
    r[7] = t7;
    r[8] = c & M;
    c >>= 26;
    c += u8 * R1;
    c += d * R0 + t9;
    r[9] = c & (M >> 4);
    c >>= 22;
    c += d * (R1 << 4);
    d = c * (R0 >> 4) + t0;
    r[0] = d & M;
    d >>= 26;
    d += c * (R1 >> 4) + t1;
    r[1] = d & M;
    d >>= 26;
    d += t2;
    r[2] = d;
}

__device__ void secp256k1_fe_mul(secp256k1_fe* r, const secp256k1_fe* a, const secp256k1_fe* b)
{
    secp256k1_fe_mul_inner(r->n, a->n, b->n);
}


__device__ void secp256k1_fe_inv(secp256k1_fe* r, const secp256k1_fe* a)
{
    secp256k1_fe x2, x3, x6, x9, x11, x22, x44, x88, x176, x220, x223, t1;
    int j;

    secp256k1_fe_sqr(&x2, a);
    secp256k1_fe_mul(&x2, &x2, a);

    secp256k1_fe_sqr(&x3, &x2);
    secp256k1_fe_mul(&x3, &x3, a);

    x6 = x3;
    for (j = 0; j < 3; j++)
    {
        secp256k1_fe_sqr(&x6, &x6);
    }
    secp256k1_fe_mul(&x6, &x6, &x3);

    x9 = x6;
    for (j = 0; j < 3; j++)
    {
        secp256k1_fe_sqr(&x9, &x9);
    }
    secp256k1_fe_mul(&x9, &x9, &x3);

    x11 = x9;
    for (j = 0; j < 2; j++)
    {
        secp256k1_fe_sqr(&x11, &x11);
    }
    secp256k1_fe_mul(&x11, &x11, &x2);

    x22 = x11;
    for (j = 0; j < 11; j++)
    {
        secp256k1_fe_sqr(&x22, &x22);
    }
    secp256k1_fe_mul(&x22, &x22, &x11);

    x44 = x22;
    for (j = 0; j < 22; j++)
    {
        secp256k1_fe_sqr(&x44, &x44);
    }
    secp256k1_fe_mul(&x44, &x44, &x22);

    x88 = x44;
    for (j = 0; j < 44; j++)
    {
        secp256k1_fe_sqr(&x88, &x88);
    }
    secp256k1_fe_mul(&x88, &x88, &x44);

    x176 = x88;
    for (j = 0; j < 88; j++)
    {
        secp256k1_fe_sqr(&x176, &x176);
    }
    secp256k1_fe_mul(&x176, &x176, &x88);

    x220 = x176;
    for (j = 0; j < 44; j++)
    {
        secp256k1_fe_sqr(&x220, &x220);
    }
    secp256k1_fe_mul(&x220, &x220, &x44);

    x223 = x220;
    for (j = 0; j < 3; j++)
    {
        secp256k1_fe_sqr(&x223, &x223);
    }
    secp256k1_fe_mul(&x223, &x223, &x3);

    t1 = x223;
    for (j = 0; j < 23; j++)
    {
        secp256k1_fe_sqr(&t1, &t1);
    }
    secp256k1_fe_mul(&t1, &t1, &x22);
    for (j = 0; j < 5; j++)
    {
        secp256k1_fe_sqr(&t1, &t1);
    }
    secp256k1_fe_mul(&t1, &t1, a);
    for (j = 0; j < 3; j++)
    {
        secp256k1_fe_sqr(&t1, &t1);
    }
    secp256k1_fe_mul(&t1, &t1, &x2);
    for (j = 0; j < 2; j++)
    {
        secp256k1_fe_sqr(&t1, &t1);
    }
    secp256k1_fe_mul(r, a, &t1);
}

__device__ void secp256k1_ge_set_gej(secp256k1_ge* r, secp256k1_gej* a)
{
    secp256k1_fe z2, z3;
    r->infinity = a->infinity;
    secp256k1_fe_inv(&a->z, &a->z);
    secp256k1_fe_sqr(&z2, &a->z);
    secp256k1_fe_mul(&z3, &a->z, &z2);
    secp256k1_fe_mul(&a->x, &a->x, &z2);
    secp256k1_fe_mul(&a->y, &a->y, &z3);
    secp256k1_fe_set_int(&a->z, 1);
    r->x = a->x;
    r->y = a->y;
}

__device__ void secp256k1_gej_add_ge(secp256k1_gej* r, const secp256k1_gej* a, const secp256k1_ge* b)
{
    secp256k1_fe zz, u1, u2, s1, s2, t, tt, m, n, q, rr;
    secp256k1_fe m_alt, rr_alt;

    secp256k1_fe_sqr(&zz, &a->z);                       /* z = Z1^2 */
    u1 = a->x;
    secp256k1_fe_normalize_weak(&u1);        /* u1 = U1 = X1*Z2^2 (1) */
    secp256k1_fe_mul(&u2, &b->x, &zz);                  /* u2 = U2 = X2*Z1^2 (1) */
    s1 = a->y;
    secp256k1_fe_normalize_weak(&s1);        /* s1 = S1 = Y1*Z2^3 (1) */
    secp256k1_fe_mul(&s2, &b->y, &zz);       /* s2 = Y2*Z1^2 (1) */
    secp256k1_fe_mul(&s2, &s2, &a->z);       /* s2 = S2 = Y2*Z1^3 (1) */
    t = u1;
    secp256k1_fe_add(&t, &u2);                  /* t = T = U1+U2 (2) */
    m = s1;
    secp256k1_fe_add(&m, &s2);                  /* m = M = S1+S2 (2) */
    secp256k1_fe_sqr(&rr, &t);                          /* rr = T^2 (1) */
    secp256k1_fe_negate(&m_alt, &u2, 1);                /* Malt = -X2*Z1^2 */
    secp256k1_fe_mul(&tt, &u1, &m_alt);                 /* tt = -U1*U2 (2) */
    secp256k1_fe_add(&rr, &tt);                         /* rr = R = T^2-U1*U2 (3) */
    /** If lambda = R/M = 0/0 we have a problem (except in the "trivial"
     *  case that Z = z1z2 = 0, and this is special-cased later on). */
    int degenerate = secp256k1_fe_normalizes_to_zero(&m) & secp256k1_fe_normalizes_to_zero(&rr);
    /* This only occurs when y1 == -y2 and x1^3 == x2^3, but x1 != x2.
     * This means either x1 == beta*x2 or beta*x1 == x2, where beta is
     * a nontrivial cube root of one. In either case, an alternate
     * non-indeterminate expression for lambda is (y1 - y2)/(x1 - x2),
     * so we set R/M equal to this. */
    rr_alt = s1;
    secp256k1_fe_mul_int(&rr_alt, 2);       /* rr = Y1*Z2^3 - Y2*Z1^3 (2) */
    secp256k1_fe_add(&m_alt, &u1);          /* Malt = X1*Z2^2 - X2*Z1^2 */

    secp256k1_fe_cmov(&rr_alt, &rr, !degenerate);
    secp256k1_fe_cmov(&m_alt, &m, !degenerate);
    /* Now Ralt / Malt = lambda and is guaranteed not to be 0/0.
     * From here on out Ralt and Malt represent the numerator
     * and denominator of lambda; R and M represent the explicit
     * expressions x1^2 + x2^2 + x1x2 and y1 + y2. */
    secp256k1_fe_sqr(&n, &m_alt);                       /* n = Malt^2 (1) */
    secp256k1_fe_mul(&q, &n, &t);                       /* q = Q = T*Malt^2 (1) */
    /* These two lines use the observation that either M == Malt or M == 0,
     * so M^3 * Malt is either Malt^4 (which is computed by squaring), or
     * zero (which is "computed" by cmov). So the cost is one squaring
     * versus two multiplications. */
    secp256k1_fe_sqr(&n, &n);
    secp256k1_fe_cmov(&n, &m, degenerate);              /* n = M^3 * Malt (2) */
    secp256k1_fe_sqr(&t, &rr_alt);                      /* t = Ralt^2 (1) */
    secp256k1_fe_mul(&r->z, &a->z, &m_alt);             /* r->z = Malt*Z (1) */

    int infinity = secp256k1_fe_normalizes_to_zero(&r->z) * (1 - a->infinity);
    secp256k1_fe_mul_int(&r->z, 2);                     /* r->z = Z3 = 2*Malt*Z (2) */
    secp256k1_fe_negate(&q, &q, 1);                     /* q = -Q (2) */
    secp256k1_fe_add(&t, &q);                           /* t = Ralt^2-Q (3) */
    secp256k1_fe_normalize_weak(&t);
    r->x = t;                                           /* r->x = Ralt^2-Q (1) */
    secp256k1_fe_mul_int(&t, 2);                        /* t = 2*x3 (2) */
    secp256k1_fe_add(&t, &q);                           /* t = 2*x3 - Q: (4) */
    secp256k1_fe_mul(&t, &t, &rr_alt);                  /* t = Ralt*(2*x3 - Q) (1) */
    secp256k1_fe_add(&t, &n);                           /* t = Ralt*(2*x3 - Q) + M^3*Malt (3) */
    secp256k1_fe_negate(&r->y, &t, 3);                  /* r->y = Ralt*(Q - 2x3) - M^3*Malt (4) */
    secp256k1_fe_normalize_weak(&r->y);
    secp256k1_fe_mul_int(&r->x, 4);                     /* r->x = X3 = 4*(Ralt^2-Q) */
    secp256k1_fe_mul_int(&r->y, 4);                     /* r->y = Y3 = 4*Ralt*(Q - 2x3) - 4*M^3*Malt (4) */

    /** In case a->infinity == 1, replace r with (b->x, b->y, 1). */
    secp256k1_fe_cmov(&r->x, &b->x, a->infinity);
    secp256k1_fe_cmov(&r->y, &b->y, a->infinity);
    secp256k1_fe_cmov(&r->z, &fe_1, a->infinity);
    r->infinity = infinity;
}

__device__ void secp256k1_pubkey_save(uint8_t* pubkey, secp256k1_ge* ge)
{
    secp256k1_fe_normalize_var(&ge->x);
    secp256k1_fe_normalize_var(&ge->y);
    secp256k1_fe_get_b32(pubkey, &ge->x);
    secp256k1_fe_get_b32(pubkey + 32, &ge->y);
}

__device__ void secp256k1_ecmult_gen(secp256k1_gej* r, secp256k1_scalar* gn)
{
    secp256k1_ge add;
    secp256k1_ge_storage adds;

    secp256k1_gej_set_infinity(r);

    #pragma unroll
    for (uint32_t j = 0; j < ECMULT_GEN_PREC_N; ++j)
    {
        const uint32_t bits = secp256k1_scalar_get_bits(gn, j * ECMULT_GEN_PREC_B, ECMULT_GEN_PREC_B);
        #pragma unroll
        for (uint32_t i = 0; i < ECMULT_GEN_PREC_G; ++i)
        {
            uint32_t mask0 = (i == bits) + ~0u;
            uint32_t mask1 = ~mask0;

            adds.x.n[0] = (adds.x.n[0] & mask0) | (prec[j][i].x.n[0] & mask1);
            adds.x.n[1] = (adds.x.n[1] & mask0) | (prec[j][i].x.n[1] & mask1);
            adds.x.n[2] = (adds.x.n[2] & mask0) | (prec[j][i].x.n[2] & mask1);
            adds.x.n[3] = (adds.x.n[3] & mask0) | (prec[j][i].x.n[3] & mask1);
            adds.x.n[4] = (adds.x.n[4] & mask0) | (prec[j][i].x.n[4] & mask1);
            adds.x.n[5] = (adds.x.n[5] & mask0) | (prec[j][i].x.n[5] & mask1);
            adds.x.n[6] = (adds.x.n[6] & mask0) | (prec[j][i].x.n[6] & mask1);
            adds.x.n[7] = (adds.x.n[7] & mask0) | (prec[j][i].x.n[7] & mask1);

            adds.y.n[0] = (adds.y.n[0] & mask0) | (prec[j][i].y.n[0] & mask1);
            adds.y.n[1] = (adds.y.n[1] & mask0) | (prec[j][i].y.n[1] & mask1);
            adds.y.n[2] = (adds.y.n[2] & mask0) | (prec[j][i].y.n[2] & mask1);
            adds.y.n[3] = (adds.y.n[3] & mask0) | (prec[j][i].y.n[3] & mask1);
            adds.y.n[4] = (adds.y.n[4] & mask0) | (prec[j][i].y.n[4] & mask1);
            adds.y.n[5] = (adds.y.n[5] & mask0) | (prec[j][i].y.n[5] & mask1);
            adds.y.n[6] = (adds.y.n[6] & mask0) | (prec[j][i].y.n[6] & mask1);
            adds.y.n[7] = (adds.y.n[7] & mask0) | (prec[j][i].y.n[7] & mask1);
        }
        secp256k1_ge_from_storage(&add, &adds);
        secp256k1_gej_add_ge(r, r, &add);
    }
}

__device__ int secp256k1_ec_pubkey_create(uint8_t* pubkey, const uint8_t* seckey)
{
    secp256k1_gej pj;
    secp256k1_ge p;
    secp256k1_scalar sec;
    secp256k1_scalar secp256k1_scalar_one = SECP256K1_SCALAR_CONST(1, 0, 0, 0, 0, 0, 0, 0);

    const int ret = secp256k1_scalar_set_b32_seckey(&sec, seckey);

    secp256k1_scalar_cmov(&sec, &secp256k1_scalar_one, !ret);

    secp256k1_ecmult_gen(&pj, &sec);
    secp256k1_ge_set_gej(&p, &pj);
    secp256k1_pubkey_save(pubkey, &p);
    return ret;
}
