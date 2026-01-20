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

/**
 * Batch inversion using Montgomery's trick
 * Computes inverses of multiple field elements more efficiently than
 * calling secp256k1_fe_inv multiple times.
 * 
 * Algorithm (Montgomery's trick):
 * 1. Compute products[i] = input[0] * input[1] * ... * input[i]
 * 2. Compute inv_total = 1 / products[count-1]
 * 3. For i from count-1 down to 0:
 *    - If i > 0: results[i] = products[i-1] * inv_total
 *    - Update inv_total = inv_total * inputs[i]
 *    - If i == 0: results[0] = inv_total
 * 
 * This reduces N inversions to 1 inversion + 2*(N-1) multiplications.
 * 
 * Example usage:
 *   secp256k1_fe inputs[4], results[4];
 *   // ... initialize inputs ...
 *   secp256k1_fe_batch_inv(results, inputs, 4);
 *   // Now results[i] = 1 / inputs[i] for all i
 * 
 * @param results Output array for inverses (must have space for 'count' elements)
 * @param inputs Input array of field elements to invert
 * @param count Number of elements to invert (must be > 0, max 16 for current implementation)
 */
__device__ void secp256k1_fe_batch_inv(secp256k1_fe* results, const secp256k1_fe* inputs, int count)
{
    // Handle single element case
    if (count == 1) {
        secp256k1_fe_inv(&results[0], &inputs[0]);
        return;
    }

    // Check bounds (current implementation supports up to 16 elements)
    // This can be increased if needed, or use shared memory for larger batches
    constexpr int MAX_BATCH_SIZE = 16;
    if (count > MAX_BATCH_SIZE) {
        // Fallback to individual inversions for batches larger than MAX_BATCH_SIZE
        // In practice, this should rarely happen as typical batch sizes are small
        for (int i = 0; i < count; i++) {
            secp256k1_fe_inv(&results[i], &inputs[i]);
        }
        return;
    }

    // Temporary storage for cumulative products
    // We use a fixed-size array to avoid dynamic allocation
    // For larger batches, this could be optimized to use shared memory
    secp256k1_fe products[MAX_BATCH_SIZE];
    
    // Step 1: Compute cumulative products
    // products[0] = inputs[0]
    // products[1] = inputs[0] * inputs[1]
    // products[2] = inputs[0] * inputs[1] * inputs[2]
    // ...
    products[0] = inputs[0];
    for (int i = 1; i < count; i++) {
        secp256k1_fe_mul(&products[i], &products[i-1], &inputs[i]);
    }

    // Step 2: Compute inverse of the total product
    secp256k1_fe inv_total;
    secp256k1_fe_inv(&inv_total, &products[count - 1]);

    // Step 3: Compute all inverses working backwards
    // This follows the same algorithm as the CPU version in secp256k1.cpp
    for (int i = count - 1; i >= 0; i--) {
        if (i > 0) {
            // results[i] = products[i-1] * inv_total
            secp256k1_fe_mul(&results[i], &products[i - 1], &inv_total);
            // Update inv_total = inv_total * inputs[i] for next iteration
            secp256k1_fe_mul(&inv_total, &inv_total, &inputs[i]);
        } else {
            // results[0] = inv_total (which is now 1/inputs[0])
            results[0] = inv_total;
        }
    }
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

/**
 * Batch version of secp256k1_ge_set_gej using batch inversion optimization
 * Normalizes multiple points from Jacobian to affine coordinates efficiently.
 * 
 * This function is useful when processing multiple points in the same thread,
 * such as in HD wallet derivation or when generating multiple public keys.
 * 
 * Performance: Reduces N inversions to 1 inversion + 2*(N-1) multiplications
 * Expected speedup: 20-30% when processing 4-8 points simultaneously
 * 
 * Example usage:
 *   secp256k1_gej points[4];
 *   secp256k1_ge results[4];
 *   // ... compute points in Jacobian coordinates ...
 *   secp256k1_ge_set_gej_batch(results, points, 4);
 * 
 * @param results Output array of affine points (must have space for 'count' elements)
 * @param points Input array of points in Jacobian coordinates
 * @param count Number of points to normalize (must be > 0, max 16 for current implementation)
 */
__device__ void secp256k1_ge_set_gej_batch(secp256k1_ge* results, secp256k1_gej* points, int count)
{
    if (count == 1) {
        secp256k1_ge_set_gej(&results[0], &points[0]);
        return;
    }

    constexpr int MAX_BATCH_SIZE = 16;
    if (count > MAX_BATCH_SIZE) {
        // Fallback to individual normalization for batches larger than MAX_BATCH_SIZE
        for (int i = 0; i < count; i++) {
            secp256k1_ge_set_gej(&results[i], &points[i]);
        }
        return;
    }

    // Step 1: Collect all z coordinates for batch inversion
    secp256k1_fe z_coords[MAX_BATCH_SIZE];
    secp256k1_fe z_invs[MAX_BATCH_SIZE];
    
    for (int i = 0; i < count; i++) {
        z_coords[i] = points[i].z;
        results[i].infinity = points[i].infinity;
    }

    // Step 2: Batch invert all z coordinates
    secp256k1_fe_batch_inv(z_invs, z_coords, count);

    // Step 3: Normalize each point using the precomputed inverses
    for (int i = 0; i < count; i++) {
        secp256k1_fe z2, z3;
        secp256k1_fe_sqr(&z2, &z_invs[i]);
        secp256k1_fe_mul(&z3, &z_invs[i], &z2);
        secp256k1_fe_mul(&results[i].x, &points[i].x, &z2);
        secp256k1_fe_mul(&results[i].y, &points[i].y, &z3);
    }
}

__device__ void secp256k1_gej_add_ge(secp256k1_gej* r, const secp256k1_gej* a, const secp256k1_ge* b)
{
    // Оптимизация: используем cmov вместо branch для обработки infinity
    // Это избегает branch divergence и работает быстрее
    secp256k1_fe zz, u1, u2, s1, s2, t, tt, m, n, q, rr;
    secp256k1_fe m_alt, rr_alt;

    // Оптимизация: вычисляем zz и используем его сразу для u2 и s2
    secp256k1_fe_sqr(&zz, &a->z);                       /* z = Z1^2 */
    
    // ОПТИМИЗАЦИЯ #1: Убираем ранние нормализации u1 и s1
    // secp256k1_fe_add может работать с ненормализованными значениями, если они не слишком большие
    // Нормализуем только перед операциями, которые критически требуют нормализованного формата
    u1 = a->x;
    secp256k1_fe_mul(&u2, &b->x, &zz);                  /* u2 = U2 = X2*Z1^2 (1) */
    s1 = a->y;
    secp256k1_fe_mul(&s2, &b->y, &zz);       /* s2 = Y2*Z1^2 (1) */
    secp256k1_fe_mul(&s2, &s2, &a->z);       /* s2 = S2 = Y2*Z1^3 (1) */
    
    // НЕ нормализуем u1 и s1 здесь - откладываем до необходимости
    // Это экономит 2 вызова normalize_weak (20 операций)
    
    t = u1;
    secp256k1_fe_add(&t, &u2);                  /* t = T = U1+U2 (2) */
    m = s1;
    secp256k1_fe_add(&m, &s2);                  /* m = M = S1+S2 (2) */
    secp256k1_fe_sqr(&rr, &t);                          /* rr = T^2 (1) */
    secp256k1_fe_negate(&m_alt, &u2, 1);                /* Malt = -X2*Z1^2 */
    // ОПТИМИЗАЦИЯ: нормализуем u1 только перед mul, если необходимо
    // secp256k1_fe_mul может работать с ненормализованными значениями, но для точности нормализуем
    secp256k1_fe_normalize_weak(&u1);                   /* Нормализуем u1 только перед mul */
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
    // ОПТИМИЗАЦИЯ: нормализуем s1 только перед использованием в операциях
    secp256k1_fe_normalize_weak(&s1);                   /* Нормализуем s1 перед операциями */
    rr_alt = s1;
    // Оптимизация: умножение на 2 через сдвиг (быстрее, чем умножение)
    rr_alt.n[0] <<= 1;
    rr_alt.n[1] <<= 1;
    rr_alt.n[2] <<= 1;
    rr_alt.n[3] <<= 1;
    rr_alt.n[4] <<= 1;
    rr_alt.n[5] <<= 1;
    rr_alt.n[6] <<= 1;
    rr_alt.n[7] <<= 1;
    rr_alt.n[8] <<= 1;
    rr_alt.n[9] <<= 1;
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
    // Оптимизация: умножение на 2 через сдвиг
    r->z.n[0] <<= 1;
    r->z.n[1] <<= 1;
    r->z.n[2] <<= 1;
    r->z.n[3] <<= 1;
    r->z.n[4] <<= 1;
    r->z.n[5] <<= 1;
    r->z.n[6] <<= 1;
    r->z.n[7] <<= 1;
    r->z.n[8] <<= 1;
    r->z.n[9] <<= 1;
    secp256k1_fe_negate(&q, &q, 1);                     /* q = -Q (2) */
    secp256k1_fe_add(&t, &q);                           /* t = Ralt^2-Q (3) */
    // ОПТИМИЗАЦИЯ: убираем нормализацию t здесь - она не нужна для присваивания
    // Нормализуем только финальный результат в конце
    r->x = t;                                           /* r->x = Ralt^2-Q (1) */
    // Оптимизация: умножение на 2 через сдвиг
    t.n[0] <<= 1;
    t.n[1] <<= 1;
    t.n[2] <<= 1;
    t.n[3] <<= 1;
    t.n[4] <<= 1;
    t.n[5] <<= 1;
    t.n[6] <<= 1;
    t.n[7] <<= 1;
    t.n[8] <<= 1;
    t.n[9] <<= 1;
    secp256k1_fe_add(&t, &q);                           /* t = 2*x3 - Q: (4) */
    secp256k1_fe_mul(&t, &t, &rr_alt);                  /* t = Ralt*(2*x3 - Q) (1) */
    secp256k1_fe_add(&t, &n);                           /* t = Ralt*(2*x3 - Q) + M^3*Malt (3) */
    secp256k1_fe_negate(&r->y, &t, 3);                  /* r->y = Ralt*(Q - 2x3) - M^3*Malt (4) */
    // ОПТИМИЗАЦИЯ: нормализуем только финальные результаты r->x и r->y
    // Это единственные нормализации, которые действительно нужны для корректности
    secp256k1_fe_normalize_weak(&r->x);                 /* Нормализуем r->x перед финальным умножением */
    secp256k1_fe_normalize_weak(&r->y);                 /* Нормализуем r->y */
    // Оптимизация: умножение на 4 через сдвиг на 2 бита
    r->x.n[0] <<= 2;
    r->x.n[1] <<= 2;
    r->x.n[2] <<= 2;
    r->x.n[3] <<= 2;
    r->x.n[4] <<= 2;
    r->x.n[5] <<= 2;
    r->x.n[6] <<= 2;
    r->x.n[7] <<= 2;
    r->x.n[8] <<= 2;
    r->x.n[9] <<= 2;
    r->y.n[0] <<= 2;
    r->y.n[1] <<= 2;
    r->y.n[2] <<= 2;
    r->y.n[3] <<= 2;
    r->y.n[4] <<= 2;
    r->y.n[5] <<= 2;
    r->y.n[6] <<= 2;
    r->y.n[7] <<= 2;
    r->y.n[8] <<= 2;
    r->y.n[9] <<= 2;

    /** In case a->infinity == 1, replace r with (b->x, b->y, 1). */
    secp256k1_fe_cmov(&r->x, &b->x, a->infinity);
    secp256k1_fe_cmov(&r->y, &b->y, a->infinity);
    secp256k1_fe_cmov(&r->z, &fe_1, a->infinity);
    r->infinity = infinity;
    
    // Оптимизация: если b->infinity == 1, результат = a (обрабатываем через cmov в конце)
    // Это избегает branch divergence и работает быстрее, чем ранний return
    secp256k1_fe_cmov(&r->x, &a->x, b->infinity);
    secp256k1_fe_cmov(&r->y, &a->y, b->infinity);
    secp256k1_fe_cmov(&r->z, &a->z, b->infinity);
    r->infinity = (b->infinity) ? a->infinity : infinity;
}

__device__ void secp256k1_pubkey_save(uint8_t* pubkey, secp256k1_ge* ge)
{
    secp256k1_fe_normalize_var(&ge->x);
    secp256k1_fe_normalize_var(&ge->y);
    secp256k1_fe_get_b32(pubkey, &ge->x);
    secp256k1_fe_get_b32(pubkey + 32, &ge->y);
}


// Глобальная переменная для таблицы (устанавливается из host кода)
__device__ const secp256k1_ge_storage* d_gTable_ptr;

__device__ void secp256k1_ecmult_gen(secp256k1_gej* r, secp256k1_scalar* gn)
{
    secp256k1_ge add;

    secp256k1_gej_set_infinity(r);

    // Используем window size = 16 бит (как в CudaBrainSecp)
    // Приватный ключ разбивается на 16 частей по 16 бит
    #pragma unroll
    for (uint32_t chunk = 0; chunk < ECMULT_GEN_PREC_N; ++chunk)
    {
        // Извлекаем 16 бит из скаляра
        const uint32_t chunkValue = secp256k1_scalar_get_bits(gn, chunk * ECMULT_GEN_PREC_B, ECMULT_GEN_PREC_B);
        
        // Оптимизация: пропускаем нулевые чанки - это экономит ~6 mul + 4 sqr операций
        // Branch divergence не критичен, так как нулевые чанки встречаются редко (~1/65536)
        // И компилятор может оптимизировать это через предикаты
        if (chunkValue != 0)
        {
            // Вычисляем индекс в таблице: chunk * 65536 + (chunkValue - 1)
            // chunkValue - 1 потому что значения в таблице начинаются с 1, а не с 0
            const uint32_t tableIndex = chunk * ECMULT_GEN_PREC_G + (chunkValue - 1);
            
            // Читаем точку из global memory (с __ldg оптимизацией через secp256k1_ge_from_storage)
            // secp256k1_ge_from_storage уже использует векторизованное чтение с __ldg() внутри
            secp256k1_ge_from_storage(&add, &d_gTable_ptr[tableIndex]);
            secp256k1_gej_add_ge(r, r, &add);
        }
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

/**
 * Version of secp256k1_ec_pubkey_create that returns point in Jacobian coordinates
 * (without normalization). Useful for batch normalization optimization.
 * 
 * @param pj Output point in Jacobian coordinates
 * @param seckey Input private key (32 bytes)
 * @return 1 if seckey is valid, 0 otherwise
 */
__device__ int secp256k1_ec_pubkey_create_gej(secp256k1_gej* pj, const uint8_t* seckey)
{
    secp256k1_scalar sec;
    secp256k1_scalar secp256k1_scalar_one = SECP256K1_SCALAR_CONST(1, 0, 0, 0, 0, 0, 0, 0);

    const int ret = secp256k1_scalar_set_b32_seckey(&sec, seckey);

    secp256k1_scalar_cmov(&sec, &secp256k1_scalar_one, !ret);

    secp256k1_ecmult_gen(pj, &sec);
    return ret;
}
