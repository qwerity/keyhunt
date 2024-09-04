#pragma once

#include <cuda.h>
#include <cuda_runtime.h>

#include "ptx.cuh"
#include "defines.cuh"
#include "functors.cuh"

/**
 Prime modulus 2^256 - 2^32 - 977
 */
__constant__ static constexpr uint32_t d_P[8] = {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFC2F};

/**
 Base point X
 */
__constant__ static constexpr uint32_t d_GX[8] = {0x79BE667E, 0xF9DCBBAC, 0x55A06295, 0xCE870B07, 0x029BFCDB, 0x2DCE28D9, 0x59F2815B, 0x16F81798};


/**
 Base point Y
 */
__constant__ static constexpr uint32_t d_GY[8] = {0x483ADA77, 0x26A3C465, 0x5DA4FBFC, 0x0E1108A8, 0xFD17B448, 0xA6855419, 0x9C47D08F, 0xFB10D4B8};


/**
 * Group order
 */
__constant__ static constexpr uint32_t d_N[8] = {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE, 0xBAAEDCE6, 0xAF48A03B, 0xBFD25E8C, 0xD0364141};

// TODO(ksh): not used
// __constant__ static constexpr uint32_t _BETA[8] = {0x7AE96A2B, 0x657C0710, 0x6E64479E, 0xAC3434E9, 0x9CF04975, 0x12F58995, 0xC1396C28, 0x719501EE};
// __constant__ static constexpr uint32_t _LAMBDA[8] = {0x5363AD4C, 0xC05C30E0, 0xA5261C02, 0x8812645A, 0x122E22EA, 0x20816678, 0xDF02967C, 0x1B23BD72};


__device__ __forceinline__ bool isInfinity(const uint32_t x[8])
{
    bool isf = true;
    for (int i = 0; i < 8; i++)
    {
        if (x[i] != 0xffffffff)
        {
            isf = false;
        }
    }
    return isf;
}

/**
 * Subtraction mod p
 */
__device__ static void subModP(const uint32_t a[8], const uint32_t b[8], uint32_t c[8])
{
    sub_cc(c[7], a[7], b[7]);
    subc_cc(c[6], a[6], b[6]);
    subc_cc(c[5], a[5], b[5]);
    subc_cc(c[4], a[4], b[4]);
    subc_cc(c[3], a[3], b[3]);
    subc_cc(c[2], a[2], b[2]);
    subc_cc(c[1], a[1], b[1]);
    subc_cc(c[0], a[0], b[0]);

    uint32_t borrow = 0;
    subc(borrow, 0, 0);
    if (borrow)
    {
        add_cc(c[7], c[7], d_P[7]);
        addc_cc(c[6], c[6], d_P[6]);
        addc_cc(c[5], c[5], d_P[5]);
        addc_cc(c[4], c[4], d_P[4]);
        addc_cc(c[3], c[3], d_P[3]);
        addc_cc(c[2], c[2], d_P[2]);
        addc_cc(c[1], c[1], d_P[1]);
        addc(c[0], c[0], d_P[0]);
    }
}

__device__ static uint32_t add(const uint32_t a[8], const uint32_t b[8], uint32_t c[8])
{
    add_cc(c[7], a[7], b[7]);
    addc_cc(c[6], a[6], b[6]);
    addc_cc(c[5], a[5], b[5]);
    addc_cc(c[4], a[4], b[4]);
    addc_cc(c[3], a[3], b[3]);
    addc_cc(c[2], a[2], b[2]);
    addc_cc(c[1], a[1], b[1]);
    addc_cc(c[0], a[0], b[0]);
    uint32_t carry = 0;
    addc(carry, 0, 0);
    return carry;
}

__device__ static uint32_t sub(const uint32_t a[8], const uint32_t b[8], uint32_t c[8])
{
    sub_cc(c[7], a[7], b[7]);
    subc_cc(c[6], a[6], b[6]);
    subc_cc(c[5], a[5], b[5]);
    subc_cc(c[4], a[4], b[4]);
    subc_cc(c[3], a[3], b[3]);
    subc_cc(c[2], a[2], b[2]);
    subc_cc(c[1], a[1], b[1]);
    subc_cc(c[0], a[0], b[0]);

    uint32_t borrow{0};
    subc(borrow, 0, 0);
    return (borrow & 0x01);
}


__device__ static void addModP(const uint32_t a[8], const uint32_t b[8], uint32_t c[8])
{
    add_cc(c[7], a[7], b[7]);
    addc_cc(c[6], a[6], b[6]);
    addc_cc(c[5], a[5], b[5]);
    addc_cc(c[4], a[4], b[4]);
    addc_cc(c[3], a[3], b[3]);
    addc_cc(c[2], a[2], b[2]);
    addc_cc(c[1], a[1], b[1]);
    addc_cc(c[0], a[0], b[0]);

    uint32_t carry{0};
    addc(carry, 0, 0);

    bool gt = false;
    for (int i = 0; i < 8; i++)
    {
        if (c[i] > d_P[i])
        {
            gt = true;
            break;
        }
        else if (c[i] < d_P[i])
        {
            break;
        }
    }

    if (carry || gt)
    {
        sub_cc(c[7], c[7], d_P[7]);
        subc_cc(c[6], c[6], d_P[6]);
        subc_cc(c[5], c[5], d_P[5]);
        subc_cc(c[4], c[4], d_P[4]);
        subc_cc(c[3], c[3], d_P[3]);
        subc_cc(c[2], c[2], d_P[2]);
        subc_cc(c[1], c[1], d_P[1]);
        subc(c[0], c[0], d_P[0]);
    }
}


__device__ static void mulModP(const uint32_t a[8], const uint32_t b[8], uint32_t c[8])
{
    uint32_t high[8] = {0};
    uint32_t t = a[7];
    // a[7] * b (low)
    for (int i = 7; i >= 0; i--)
    {
        c[i] = t * b[i];
    }
    // a[7] * b (high)
    mad_hi_cc(c[6], t, b[7], c[6]);
    madc_hi_cc(c[5], t, b[6], c[5]);
    madc_hi_cc(c[4], t, b[5], c[4]);
    madc_hi_cc(c[3], t, b[4], c[3]);
    madc_hi_cc(c[2], t, b[3], c[2]);
    madc_hi_cc(c[1], t, b[2], c[1]);
    madc_hi_cc(c[0], t, b[1], c[0]);
    madc_hi(high[7], t, b[0], high[7]);
    // a[6] * b (low)
    t = a[6];
    mad_lo_cc(c[6], t, b[7], c[6]);
    madc_lo_cc(c[5], t, b[6], c[5]);
    madc_lo_cc(c[4], t, b[5], c[4]);
    madc_lo_cc(c[3], t, b[4], c[3]);
    madc_lo_cc(c[2], t, b[3], c[2]);
    madc_lo_cc(c[1], t, b[2], c[1]);
    madc_lo_cc(c[0], t, b[1], c[0]);
    madc_lo_cc(high[7], t, b[0], high[7]);
    addc(high[6], high[6], 0);
    // a[6] * b (high)
    mad_hi_cc(c[5], t, b[7], c[5]);
    madc_hi_cc(c[4], t, b[6], c[4]);
    madc_hi_cc(c[3], t, b[5], c[3]);
    madc_hi_cc(c[2], t, b[4], c[2]);
    madc_hi_cc(c[1], t, b[3], c[1]);
    madc_hi_cc(c[0], t, b[2], c[0]);
    madc_hi_cc(high[7], t, b[1], high[7]);
    madc_hi(high[6], t, b[0], high[6]);
    // a[5] * b (low)
    t = a[5];
    mad_lo_cc(c[5], t, b[7], c[5]);
    madc_lo_cc(c[4], t, b[6], c[4]);
    madc_lo_cc(c[3], t, b[5], c[3]);
    madc_lo_cc(c[2], t, b[4], c[2]);
    madc_lo_cc(c[1], t, b[3], c[1]);
    madc_lo_cc(c[0], t, b[2], c[0]);
    madc_lo_cc(high[7], t, b[1], high[7]);
    madc_lo_cc(high[6], t, b[0], high[6]);
    addc(high[5], high[5], 0);
    // a[5] * b (high)
    mad_hi_cc(c[4], t, b[7], c[4]);
    madc_hi_cc(c[3], t, b[6], c[3]);
    madc_hi_cc(c[2], t, b[5], c[2]);
    madc_hi_cc(c[1], t, b[4], c[1]);
    madc_hi_cc(c[0], t, b[3], c[0]);
    madc_hi_cc(high[7], t, b[2], high[7]);
    madc_hi_cc(high[6], t, b[1], high[6]);
    madc_hi(high[5], t, b[0], high[5]);
    // a[4] * b (low)
    t = a[4];
    mad_lo_cc(c[4], t, b[7], c[4]);
    madc_lo_cc(c[3], t, b[6], c[3]);
    madc_lo_cc(c[2], t, b[5], c[2]);
    madc_lo_cc(c[1], t, b[4], c[1]);
    madc_lo_cc(c[0], t, b[3], c[0]);
    madc_lo_cc(high[7], t, b[2], high[7]);
    madc_lo_cc(high[6], t, b[1], high[6]);
    madc_lo_cc(high[5], t, b[0], high[5]);
    addc(high[4], high[4], 0);
    // a[4] * b (high)
    mad_hi_cc(c[3], t, b[7], c[3]);
    madc_hi_cc(c[2], t, b[6], c[2]);
    madc_hi_cc(c[1], t, b[5], c[1]);
    madc_hi_cc(c[0], t, b[4], c[0]);
    madc_hi_cc(high[7], t, b[3], high[7]);
    madc_hi_cc(high[6], t, b[2], high[6]);
    madc_hi_cc(high[5], t, b[1], high[5]);
    madc_hi(high[4], t, b[0], high[4]);
    // a[3] * b (low)
    t = a[3];
    mad_lo_cc(c[3], t, b[7], c[3]);
    madc_lo_cc(c[2], t, b[6], c[2]);
    madc_lo_cc(c[1], t, b[5], c[1]);
    madc_lo_cc(c[0], t, b[4], c[0]);
    madc_lo_cc(high[7], t, b[3], high[7]);
    madc_lo_cc(high[6], t, b[2], high[6]);
    madc_lo_cc(high[5], t, b[1], high[5]);
    madc_lo_cc(high[4], t, b[0], high[4]);
    addc(high[3], high[3], 0);
    // a[3] * b (high)
    mad_hi_cc(c[2], t, b[7], c[2]);
    madc_hi_cc(c[1], t, b[6], c[1]);
    madc_hi_cc(c[0], t, b[5], c[0]);
    madc_hi_cc(high[7], t, b[4], high[7]);
    madc_hi_cc(high[6], t, b[3], high[6]);
    madc_hi_cc(high[5], t, b[2], high[5]);
    madc_hi_cc(high[4], t, b[1], high[4]);
    madc_hi(high[3], t, b[0], high[3]);
    // a[2] * b (low)
    t = a[2];
    mad_lo_cc(c[2], t, b[7], c[2]);
    madc_lo_cc(c[1], t, b[6], c[1]);
    madc_lo_cc(c[0], t, b[5], c[0]);
    madc_lo_cc(high[7], t, b[4], high[7]);
    madc_lo_cc(high[6], t, b[3], high[6]);
    madc_lo_cc(high[5], t, b[2], high[5]);
    madc_lo_cc(high[4], t, b[1], high[4]);
    madc_lo_cc(high[3], t, b[0], high[3]);
    addc(high[2], high[2], 0);
    // a[2] * b (high)
    mad_hi_cc(c[1], t, b[7], c[1]);
    madc_hi_cc(c[0], t, b[6], c[0]);
    madc_hi_cc(high[7], t, b[5], high[7]);
    madc_hi_cc(high[6], t, b[4], high[6]);
    madc_hi_cc(high[5], t, b[3], high[5]);
    madc_hi_cc(high[4], t, b[2], high[4]);
    madc_hi_cc(high[3], t, b[1], high[3]);
    madc_hi(high[2], t, b[0], high[2]);
    // a[1] * b (low)
    t = a[1];
    mad_lo_cc(c[1], t, b[7], c[1]);
    madc_lo_cc(c[0], t, b[6], c[0]);
    madc_lo_cc(high[7], t, b[5], high[7]);
    madc_lo_cc(high[6], t, b[4], high[6]);
    madc_lo_cc(high[5], t, b[3], high[5]);
    madc_lo_cc(high[4], t, b[2], high[4]);
    madc_lo_cc(high[3], t, b[1], high[3]);
    madc_lo_cc(high[2], t, b[0], high[2]);
    addc(high[1], high[1], 0);
    // a[1] * b (high)
    mad_hi_cc(c[0], t, b[7], c[0]);
    madc_hi_cc(high[7], t, b[6], high[7]);
    madc_hi_cc(high[6], t, b[5], high[6]);
    madc_hi_cc(high[5], t, b[4], high[5]);
    madc_hi_cc(high[4], t, b[3], high[4]);
    madc_hi_cc(high[3], t, b[2], high[3]);
    madc_hi_cc(high[2], t, b[1], high[2]);
    madc_hi(high[1], t, b[0], high[1]);
    // a[0] * b (low)
    t = a[0];
    mad_lo_cc(c[0], t, b[7], c[0]);
    madc_lo_cc(high[7], t, b[6], high[7]);
    madc_lo_cc(high[6], t, b[5], high[6]);
    madc_lo_cc(high[5], t, b[4], high[5]);
    madc_lo_cc(high[4], t, b[3], high[4]);
    madc_lo_cc(high[3], t, b[2], high[3]);
    madc_lo_cc(high[2], t, b[1], high[2]);
    madc_lo_cc(high[1], t, b[0], high[1]);
    addc(high[0], high[0], 0);
    // a[0] * b (high)
    mad_hi_cc(high[7], t, b[7], high[7]);
    madc_hi_cc(high[6], t, b[6], high[6]);
    madc_hi_cc(high[5], t, b[5], high[5]);
    madc_hi_cc(high[4], t, b[4], high[4]);
    madc_hi_cc(high[3], t, b[3], high[3]);
    madc_hi_cc(high[2], t, b[2], high[2]);
    madc_hi_cc(high[1], t, b[1], high[1]);
    madc_hi(high[0], t, b[0], high[0]);
    // At this point we have 16 32-bit words representing a 512-bit value
    // high[0 ... 7] and c[0 ... 7]
    const uint32_t s = 977;
    // Store high[6] and high[7] since they will be overwritten
    uint32_t high7 = high[7];
    uint32_t high6 = high[6];
    // Take high 256 bits, multiply by 2^32, add to low 256 bits
    // That is, take high[0 ... 7], shift it left 1 word and add it to c[0 ... 7]
    add_cc(c[6], high[7], c[6]);
    addc_cc(c[5], high[6], c[5]);
    addc_cc(c[4], high[5], c[4]);
    addc_cc(c[3], high[4], c[3]);
    addc_cc(c[2], high[3], c[2]);
    addc_cc(c[1], high[2], c[1]);
    addc_cc(c[0], high[1], c[0]);
    addc_cc(high[7], high[0], 0);
    addc(high[6], 0, 0);
    // Take high 256 bits, multiply by 977, add to low 256 bits
    // That is, take high[0 ... 5], high6, high7, multiply by 977 and add to c[0 ... 7]
    mad_lo_cc(c[7], high7, s, c[7]);
    madc_lo_cc(c[6], high6, s, c[6]);
    madc_lo_cc(c[5], high[5], s, c[5]);
    madc_lo_cc(c[4], high[4], s, c[4]);
    madc_lo_cc(c[3], high[3], s, c[3]);
    madc_lo_cc(c[2], high[2], s, c[2]);
    madc_lo_cc(c[1], high[1], s, c[1]);
    madc_lo_cc(c[0], high[0], s, c[0]);
    addc_cc(high[7], high[7], 0);
    addc(high[6], high[6], 0);
    mad_hi_cc(c[6], high7, s, c[6]);
    madc_hi_cc(c[5], high6, s, c[5]);
    madc_hi_cc(c[4], high[5], s, c[4]);
    madc_hi_cc(c[3], high[4], s, c[3]);
    madc_hi_cc(c[2], high[3], s, c[2]);
    madc_hi_cc(c[1], high[2], s, c[1]);
    madc_hi_cc(c[0], high[1], s, c[0]);
    madc_hi_cc(high[7], high[0], s, high[7]);
    addc(high[6], high[6], 0);
    // Repeat the same steps, but this time we only need to handle high[6] and high[7]
    high7 = high[7];
    high6 = high[6];
    // Take the high 64 bits, multiply by 2^32 and add to the low 256 bits
    add_cc(c[6], high[7], c[6]);
    addc_cc(c[5], high[6], c[5]);
    addc_cc(c[4], c[4], 0);
    addc_cc(c[3], c[3], 0);
    addc_cc(c[2], c[2], 0);
    addc_cc(c[1], c[1], 0);
    addc_cc(c[0], c[0], 0);
    addc(high[7], 0, 0);
    // Take the high 64 bits, multiply by 977 and add to the low 256 bits
    mad_lo_cc(c[7], high7, s, c[7]);
    madc_lo_cc(c[6], high6, s, c[6]);
    addc_cc(c[5], c[5], 0);
    addc_cc(c[4], c[4], 0);
    addc_cc(c[3], c[3], 0);
    addc_cc(c[2], c[2], 0);
    addc_cc(c[1], c[1], 0);
    addc_cc(c[0], c[0], 0);
    addc(high[7], high[7], 0);
    mad_hi_cc(c[6], high7, s, c[6]);
    madc_hi_cc(c[5], high6, s, c[5]);
    addc_cc(c[4], c[4], 0);
    addc_cc(c[3], c[3], 0);
    addc_cc(c[2], c[2], 0);
    addc_cc(c[1], c[1], 0);
    addc_cc(c[0], c[0], 0);
    addc(high[7], high[7], 0);
    bool overflow = high[7] != 0;
    uint32_t borrow = sub(c, d_P, c);
    if (overflow)
    {
        if (!borrow)
        {
            sub(c, d_P, c);
        }
    }
    else
    {
        if (borrow)
        {
            add(c, d_P, c);
        }
    }
}


/**
 * Square mod P
 * b = a * a
 */
__device__ static void squareModP(const uint32_t a[8], uint32_t b[8])
{
    mulModP(a, a, b);
}

/**
 * Square mod P
 * x = x * x
 */
__device__ static void squareModP(uint32_t x[8])
{
    uint32_t tmp[8];
    squareModP(x, tmp);
    copyBigInt(tmp, x);
}

/**
 * Multiply mod P
 * c = a * c
 */
__device__ static void mulModP(const uint32_t a[8], uint32_t c[8])
{
    uint32_t tmp[8];
    mulModP(a, c, tmp);
    copyBigInt(tmp, c);
}

/**
 * Multiplicative inverse mod P using Fermat's method of x^(p-2) mod p and addition chains
 */
__device__ static void invModP(uint32_t value[8])
{
    uint32_t x[8];
    copyBigInt(value, x);
    uint32_t y[8] = {0, 0, 0, 0, 0, 0, 0, 1};
    // 0xd - 1101
    mulModP(x, y);
    squareModP(x);
    //mulModP(x, y);
    squareModP(x);
    mulModP(x, y);
    squareModP(x);
    mulModP(x, y);
    squareModP(x);
    // 0x2 - 0010
    //mulModP(x, y);
    squareModP(x);
    mulModP(x, y);
    squareModP(x);
    //mulModP(x, y);
    squareModP(x);
    //mulModP(x, y);
    squareModP(x);
    // 0xc = 0x1100
    //mulModP(x, y);
    squareModP(x);
    //mulModP(x, y);
    squareModP(x);
    mulModP(x, y);
    squareModP(x);
    mulModP(x, y);
    squareModP(x);
    // 0xfffff
    for (int i = 0; i < 20; i++)
    {
        mulModP(x, y);
        squareModP(x);
    }
    // 0xe - 1110
    //mulModP(x, y);
    squareModP(x);
    mulModP(x, y);
    squareModP(x);
    mulModP(x, y);
    squareModP(x);
    mulModP(x, y);
    squareModP(x);
    // 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffff
    for (int i = 0; i < 219; i++)
    {
        mulModP(x, y);
        squareModP(x);
    }
    mulModP(x, y);
    copyBigInt(y, value);
}

__device__ static void invModP(const uint32_t *value, uint32_t *inverse)
{
    copyBigInt(value, inverse);
    invModP(inverse);
}

__device__ static void negModP(const uint32_t *value, uint32_t *negative)
{
    sub_cc(negative[0], d_P[0], value[0]);
    subc_cc(negative[1], d_P[1], value[1]);
    subc_cc(negative[2], d_P[2], value[2]);
    subc_cc(negative[3], d_P[3], value[3]);
    subc_cc(negative[4], d_P[4], value[4]);
    subc_cc(negative[5], d_P[5], value[5]);
    subc_cc(negative[6], d_P[6], value[6]);
    subc(negative[7], d_P[7], value[7]);
}

__device__ __forceinline__ static void beginBatchAddWithDouble(const ecpoint_t *gPoint, uint32_t *publicX, uint256_t *chain, int i, int batchIdx, uint32_t inverse[8])
{
    if (equal(gPoint->x, publicX))
    {
        addModP(gPoint->y, gPoint->y, publicX);
    }
    else
    {
        // x = Gx - x
        subModP(gPoint->x, publicX, publicX);
    }

    // Keep a chain of multiples of the diff, i.e. c[0] = diff0, c[1] = diff0 * diff1,
    // c[2] = diff2 * diff1 * diff0, etc
    mulModP(publicX, inverse);
    writeUInt256(inverse, batchIdx, chain);
}

__device__ static void completeBatchAddWithDouble(const ecpoint_t *gPoint, const uint32_t *publicX, const uint32_t *publicY, const int batchIdx, const uint256_t *chain, uint32_t *inverse, uint32_t* newX, uint32_t* newY)
{
    uint32_t s[8]{};
    if (batchIdx >= 1)
    {
        uint32_t c[8];
        readUInt256(chain, batchIdx - 1, c);
        mulModP(inverse, c, s);
        uint32_t diff[8];
        if (equal(gPoint->x, publicX))
        {
            addModP(gPoint->y, gPoint->y, diff);
        }
        else
        {
            subModP(gPoint->x, publicX, diff);
        }
        mulModP(diff, inverse);
    }
    else
    {
        copyBigInt(inverse, s);
    }
    if (equal(gPoint->x, publicX))
    {
        // currently s = 1 / 2y
        uint32_t x2[8];
        uint32_t tx2[8];
        // 3x^2
        mulModP(publicX, publicX, x2);
        addModP(x2, x2, tx2);
        addModP(x2, tx2, tx2);
        // s = 3x^2 * 1/2y
        mulModP(tx2, s);
        // s^2
        uint32_t s2[8];
        mulModP(s, s, s2);
        // Rx = s^2 - 2px
        subModP(s2, publicX, newX);
        subModP(newX, publicX, newX);
        // Ry = s(px - rx) - py
        uint32_t k[8];
        subModP(gPoint->x, newX, k);
        mulModP(s, k, newY);
        subModP(newY, gPoint->y, newY);
    }
    else
    {
        uint32_t rise[8];
        subModP(gPoint->y, publicY, rise);
        mulModP(rise, s);
        // Rx = s^2 - Gx - Qx
        uint32_t s2[8];
        mulModP(s, s, s2);
        subModP(s2, gPoint->x, newX);
        subModP(newX, publicX, newX);
        // Ry = s(px - rx) - py
        uint32_t k[8];
        subModP(gPoint->x, newX, k);
        mulModP(s, k, newY);
        subModP(newY, gPoint->y, newY);
    }
}

__device__ __forceinline__ static void doBatchInverse(uint32_t inverse[8])
{
    invModP(inverse);
}
