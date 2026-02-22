/*
 * ec_4limb_math.cuh - 4-limb (uint64_t[4]) field arithmetic for secp256k1
 * Ported from examples/GPUMath.h for keyhunt performance (~2x vs 10-limb secp256k1_fe).
 *
 * Provides: _ModMult, _ModSqr, _PointAddMixedAffine, _BatchJacobianToAffine,
 * point multiplication (GTable, 16x16-bit chunks).
 */

#pragma once

#include <cstdint>

// ---------------------------------------------------------------------------------
// Configuration (aligned with examples/GPUMath.h)
// ---------------------------------------------------------------------------------
#define EC4LIMB_NBBLOCK 5
#define EC4LIMB_MAX_BATCH_SIZE 64

// secp256k1 prime: p = 2^256 - 2^32 - 977
#define EC4LIMB_P0 0xFFFFFFFEFFFFFC2FULL
#define EC4LIMB_P1 0xFFFFFFFFFFFFFFFFULL
#define EC4LIMB_P2 0xFFFFFFFFFFFFFFFFULL
#define EC4LIMB_P3 0xFFFFFFFFFFFFFFFFULL
#define EC4LIMB_REDUCTION_CONST 0x1000003D1ULL
#define EC4LIMB_MM64 0xD838091DD2253531ULL
#define EC4LIMB_MSK62 0x3FFFFFFFFFFFFFFFULL

// ---------------------------------------------------------------------------------
// PTX assembly (64-bit add/sub/mul with carry)
// ---------------------------------------------------------------------------------
#define EC4LIMB_UADDO(c, a, b) asm volatile ("add.cc.u64 %0, %1, %2;" : "=l"(c) : "l"(a), "l"(b) : "memory");
#define EC4LIMB_UADDC(c, a, b) asm volatile ("addc.cc.u64 %0, %1, %2;" : "=l"(c) : "l"(a), "l"(b) : "memory");
#define EC4LIMB_UADD(c, a, b)  asm volatile ("addc.u64 %0, %1, %2;" : "=l"(c) : "l"(a), "l"(b));
#define EC4LIMB_UADDO1(c, a)  asm volatile ("add.cc.u64 %0, %0, %1;" : "+l"(c) : "l"(a) : "memory");
#define EC4LIMB_UADDC1(c, a)  asm volatile ("addc.cc.u64 %0, %0, %1;" : "+l"(c) : "l"(a) : "memory");
#define EC4LIMB_UADD1(c, a)   asm volatile ("addc.u64 %0, %0, %1;" : "+l"(c) : "l"(a));
#define EC4LIMB_USUBO(c, a, b) asm volatile ("sub.cc.u64 %0, %1, %2;" : "=l"(c) : "l"(a), "l"(b) : "memory");
#define EC4LIMB_USUBC(c, a, b) asm volatile ("subc.cc.u64 %0, %1, %2;" : "=l"(c) : "l"(a), "l"(b) : "memory");
#define EC4LIMB_USUB(c, a, b)  asm volatile ("subc.u64 %0, %1, %2;" : "=l"(c) : "l"(a), "l"(b));
#define EC4LIMB_USUBO1(c, a)  asm volatile ("sub.cc.u64 %0, %0, %1;" : "+l"(c) : "l"(a) : "memory");
#define EC4LIMB_USUBC1(c, a)  asm volatile ("subc.cc.u64 %0, %0, %1;" : "+l"(c) : "l"(a) : "memory");
#define EC4LIMB_USUB1(c, a)   asm volatile ("subc.u64 %0, %0, %1;" : "+l"(c) : "l"(a));
#define EC4LIMB_UMULLO(lo, a, b) asm volatile ("mul.lo.u64 %0, %1, %2;" : "=l"(lo) : "l"(a), "l"(b));
#define EC4LIMB_UMULHI(hi, a, b) asm volatile ("mul.hi.u64 %0, %1, %2;" : "=l"(hi) : "l"(a), "l"(b));
#define EC4LIMB_MADDO(r,a,b,c)  asm volatile ("mad.hi.cc.u64 %0, %1, %2, %3;" : "=l"(r) : "l"(a), "l"(b), "l"(c) : "memory");
#define EC4LIMB_MADDC(r,a,b,c)  asm volatile ("madc.hi.cc.u64 %0, %1, %2, %3;" : "=l"(r) : "l"(a), "l"(b), "l"(c) : "memory");
#define EC4LIMB_MADD(r,a,b,c)   asm volatile ("madc.hi.u64 %0, %1, %2, %3;" : "=l"(r) : "l"(a), "l"(b), "l"(c));
#define EC4LIMB_MADDS(r,a,b,c)  asm volatile ("madc.hi.s64 %0, %1, %2, %3;" : "=l"(r) : "l"(a), "l"(b), "l"(c));

// ---------------------------------------------------------------------------------
// Helpers (256-bit = 4 limbs; 320-bit = 5 limbs for intermediate)
// ---------------------------------------------------------------------------------
#define EC4LIMB_Load(r, a) do { (r)[0]=(a)[0]; (r)[1]=(a)[1]; (r)[2]=(a)[2]; (r)[3]=(a)[3]; (r)[4]=(a)[4]; } while(0)
#define EC4LIMB_Load256(r, a) do { (r)[0]=(a)[0]; (r)[1]=(a)[1]; (r)[2]=(a)[2]; (r)[3]=(a)[3]; } while(0)
#define EC4LIMB_Store256(r, a) do { (r)[0]=(a)[0]; (r)[1]=(a)[1]; (r)[2]=(a)[2]; (r)[3]=(a)[3]; } while(0)
#define EC4LIMB_AddP(r) do { \
    EC4LIMB_UADDO1((r)[0], EC4LIMB_P0); EC4LIMB_UADDC1((r)[1], EC4LIMB_P1); \
    EC4LIMB_UADDC1((r)[2], EC4LIMB_P2); EC4LIMB_UADDC1((r)[3], EC4LIMB_P3); EC4LIMB_UADD1((r)[4], 0ULL); } while(0)
#define EC4LIMB_SubP(r) do { \
    EC4LIMB_USUBO1((r)[0], EC4LIMB_P0); EC4LIMB_USUBC1((r)[1], EC4LIMB_P1); \
    EC4LIMB_USUBC1((r)[2], EC4LIMB_P2); EC4LIMB_USUBC1((r)[3], EC4LIMB_P3); EC4LIMB_USUB1((r)[4], 0ULL); } while(0)
#define EC4LIMB_IsPositive(x) (((int64_t)((x)[4])) >= 0LL)
#define EC4LIMB_IsNegative(x) (((int64_t)((x)[4])) < 0LL)
#define EC4LIMB_IsZero(a)     (((a)[4]|(a)[3]|(a)[2]|(a)[1]|(a)[0]) == 0ULL)
#define EC4LIMB_IsOne(a)      ((a)[4]==0ULL && (a)[3]==0ULL && (a)[2]==0ULL && (a)[1]==0ULL && (a)[0]==1ULL)
#define EC4LIMB_Neg(r) do { \
    EC4LIMB_USUBO((r)[0], 0ULL, (r)[0]); EC4LIMB_USUBC((r)[1], 0ULL, (r)[1]); \
    EC4LIMB_USUBC((r)[2], 0ULL, (r)[2]); EC4LIMB_USUBC((r)[3], 0ULL, (r)[3]); EC4LIMB_USUB((r)[4], 0ULL, (r)[4]); } while(0)
#define EC4LIMB_UMult(r, a, b) do { \
    EC4LIMB_UMULLO((r)[0], (a)[0], b); EC4LIMB_UMULLO((r)[1], (a)[1], b); \
    EC4LIMB_MADDO((r)[1], (a)[0], b, (r)[1]); EC4LIMB_UMULLO((r)[2], (a)[2], b); \
    EC4LIMB_MADDC((r)[2], (a)[1], b, (r)[2]); EC4LIMB_UMULLO((r)[3], (a)[3], b); \
    EC4LIMB_MADDC((r)[3], (a)[2], b, (r)[3]); EC4LIMB_MADD((r)[4], (a)[3], b, 0ULL); } while(0)

// ---------------------------------------------------------------------------------
// Modular Add/Sub/Double (256-bit, result in 4 limbs)
// ---------------------------------------------------------------------------------
__device__ __forceinline__ void ec4limb_ModAdd256(uint64_t *r, const uint64_t *a, const uint64_t *b)
{
    uint64_t rr[5];
    EC4LIMB_UADDO(rr[0], a[0], b[0]); EC4LIMB_UADDC(rr[1], a[1], b[1]);
    EC4LIMB_UADDC(rr[2], a[2], b[2]); EC4LIMB_UADDC(rr[3], a[3], b[3]); EC4LIMB_UADD(rr[4], 0ULL, 0ULL);
    EC4LIMB_Load256(r, rr); EC4LIMB_SubP(rr);
    if (EC4LIMB_IsPositive(rr)) EC4LIMB_Load256(r, rr);
}

__device__ __forceinline__ void ec4limb_ModSub256(uint64_t *r, const uint64_t *a, const uint64_t *b)
{
    uint64_t t;
    EC4LIMB_USUBO(r[0], a[0], b[0]); EC4LIMB_USUBC(r[1], a[1], b[1]);
    EC4LIMB_USUBC(r[2], a[2], b[2]); EC4LIMB_USUBC(r[3], a[3], b[3]); EC4LIMB_USUB(t, 0ULL, 0ULL);
    uint64_t T0 = EC4LIMB_P0 & t, T1 = EC4LIMB_P1 & t, T2 = EC4LIMB_P2 & t, T3 = EC4LIMB_P3 & t;
    EC4LIMB_UADDO1(r[0], T0); EC4LIMB_UADDC1(r[1], T1); EC4LIMB_UADDC1(r[2], T2); EC4LIMB_UADD1(r[3], T3);
}

// In-place: r = r - b
__device__ __forceinline__ void ec4limb_ModSub256(uint64_t *r, const uint64_t *b)
{
    uint64_t t;
    EC4LIMB_USUBO(r[0], r[0], b[0]); EC4LIMB_USUBC(r[1], r[1], b[1]);
    EC4LIMB_USUBC(r[2], r[2], b[2]); EC4LIMB_USUBC(r[3], r[3], b[3]); EC4LIMB_USUB(t, 0ULL, 0ULL);
    uint64_t T0 = EC4LIMB_P0 & t, T1 = EC4LIMB_P1 & t, T2 = EC4LIMB_P2 & t, T3 = EC4LIMB_P3 & t;
    EC4LIMB_UADDO1(r[0], T0); EC4LIMB_UADDC1(r[1], T1); EC4LIMB_UADDC1(r[2], T2); EC4LIMB_UADD1(r[3], T3);
}

__device__ __forceinline__ void ec4limb_ModDouble256(uint64_t *r, const uint64_t *a)
{
    uint64_t rr[5];
    EC4LIMB_UADDO(rr[0], a[0], a[0]); EC4LIMB_UADDC(rr[1], a[1], a[1]);
    EC4LIMB_UADDC(rr[2], a[2], a[2]); EC4LIMB_UADDC(rr[3], a[3], a[3]); EC4LIMB_UADD(rr[4], 0ULL, 0ULL);
    EC4LIMB_Load256(r, rr); EC4LIMB_SubP(rr);
    if (EC4LIMB_IsPositive(rr)) EC4LIMB_Load256(r, rr);
}

// ---------------------------------------------------------------------------------
// Modular Multiplication (256-bit)
// ---------------------------------------------------------------------------------
__device__ void ec4limb_ModMult(uint64_t *r, const uint64_t *a, const uint64_t *b)
{
    uint64_t r512[8];
    uint64_t t[EC4LIMB_NBBLOCK];
    uint64_t ah, al;
    r512[5] = r512[6] = r512[7] = 0;
    EC4LIMB_UMult(r512, a, b[0]);
    EC4LIMB_UMult(t, a, b[1]); EC4LIMB_UADDO1(r512[1], t[0]); EC4LIMB_UADDC1(r512[2], t[1]); EC4LIMB_UADDC1(r512[3], t[2]); EC4LIMB_UADDC1(r512[4], t[3]); EC4LIMB_UADD1(r512[5], t[4]);
    EC4LIMB_UMult(t, a, b[2]); EC4LIMB_UADDO1(r512[2], t[0]); EC4LIMB_UADDC1(r512[3], t[1]); EC4LIMB_UADDC1(r512[4], t[2]); EC4LIMB_UADDC1(r512[5], t[3]); EC4LIMB_UADD1(r512[6], t[4]);
    EC4LIMB_UMult(t, a, b[3]); EC4LIMB_UADDO1(r512[3], t[0]); EC4LIMB_UADDC1(r512[4], t[1]); EC4LIMB_UADDC1(r512[5], t[2]); EC4LIMB_UADDC1(r512[6], t[3]); EC4LIMB_UADD1(r512[7], t[4]);
    EC4LIMB_UMult(t, r512 + 4, EC4LIMB_REDUCTION_CONST);
    EC4LIMB_UADDO1(r512[0], t[0]); EC4LIMB_UADDC1(r512[1], t[1]); EC4LIMB_UADDC1(r512[2], t[2]); EC4LIMB_UADDC1(r512[3], t[3]);
    EC4LIMB_UADD1(t[4], 0ULL);
    EC4LIMB_UMULLO(al, t[4], EC4LIMB_REDUCTION_CONST); EC4LIMB_UMULHI(ah, t[4], EC4LIMB_REDUCTION_CONST);
    EC4LIMB_UADDO(r[0], r512[0], al); EC4LIMB_UADDC(r[1], r512[1], ah); EC4LIMB_UADDC(r[2], r512[2], 0ULL); EC4LIMB_UADD(r[3], r512[3], 0ULL);
}

// ---------------------------------------------------------------------------------
// Modular Squaring (256-bit)
// ---------------------------------------------------------------------------------
__device__ void ec4limb_ModSqr(uint64_t *rp, const uint64_t *up)
{
    uint64_t r512[8];
    uint64_t u10, u11, r0, r1, r3, r4, t1, t2;
    EC4LIMB_UMULLO(r512[0], up[0], up[0]); EC4LIMB_UMULHI(r1, up[0], up[0]);
    EC4LIMB_UMULLO(r3, up[0], up[1]); EC4LIMB_UMULHI(r4, up[0], up[1]);
    EC4LIMB_UADDO1(r3, r3); EC4LIMB_UADDC1(r4, r4); EC4LIMB_UADD(t1, 0ULL, 0ULL);
    EC4LIMB_UADDO1(r3, r1); EC4LIMB_UADDC1(r4, 0ULL); EC4LIMB_UADD1(t1, 0ULL);
    r512[1] = r3;
    EC4LIMB_UMULLO(r0, up[0], up[2]); EC4LIMB_UMULHI(r1, up[0], up[2]);
    EC4LIMB_UADDO1(r0, r0); EC4LIMB_UADDC1(r1, r1); EC4LIMB_UADD(t2, 0ULL, 0ULL);
    EC4LIMB_UMULLO(u10, up[1], up[1]); EC4LIMB_UMULHI(u11, up[1], up[1]);
    EC4LIMB_UADDO1(r0, u10); EC4LIMB_UADDC1(r1, u11); EC4LIMB_UADD1(t2, 0ULL);
    EC4LIMB_UADDO1(r0, r4); EC4LIMB_UADDC1(r1, t1); EC4LIMB_UADD1(t2, 0ULL);
    r512[2] = r0;
    EC4LIMB_UMULLO(r3, up[0], up[3]); EC4LIMB_UMULHI(r4, up[0], up[3]);
    EC4LIMB_UMULLO(u10, up[1], up[2]); EC4LIMB_UMULHI(u11, up[1], up[2]);
    EC4LIMB_UADDO1(r3, u10); EC4LIMB_UADDC1(r4, u11); EC4LIMB_UADD(t1, 0ULL, 0ULL);
    t1 += t1; EC4LIMB_UADDO1(r3, r3); EC4LIMB_UADDC1(r4, r4); EC4LIMB_UADD1(t1, 0ULL);
    EC4LIMB_UADDO1(r3, r1); EC4LIMB_UADDC1(r4, t2); EC4LIMB_UADD1(t1, 0ULL);
    r512[3] = r3;
    EC4LIMB_UMULLO(r0, up[1], up[3]); EC4LIMB_UMULHI(r1, up[1], up[3]);
    EC4LIMB_UADDO1(r0, r0); EC4LIMB_UADDC1(r1, r1); EC4LIMB_UADD(t2, 0ULL, 0ULL);
    EC4LIMB_UMULLO(u10, up[2], up[2]); EC4LIMB_UMULHI(u11, up[2], up[2]);
    EC4LIMB_UADDO1(r0, u10); EC4LIMB_UADDC1(r1, u11); EC4LIMB_UADD1(t2, 0ULL);
    EC4LIMB_UADDO1(r0, r4); EC4LIMB_UADDC1(r1, t1); EC4LIMB_UADD1(t2, 0ULL);
    r512[4] = r0;
    EC4LIMB_UMULLO(r3, up[2], up[3]); EC4LIMB_UMULHI(r4, up[2], up[3]);
    EC4LIMB_UADDO1(r3, r3); EC4LIMB_UADDC1(r4, r4); EC4LIMB_UADD(t1, 0ULL, 0ULL);
    EC4LIMB_UADDO1(r3, r1); EC4LIMB_UADDC1(r4, t2); EC4LIMB_UADD1(t1, 0ULL);
    r512[5] = r3;
    EC4LIMB_UMULLO(r0, up[3], up[3]); EC4LIMB_UMULHI(r1, up[3], up[3]);
    EC4LIMB_UADDO1(r0, r4); EC4LIMB_UADD1(r1, t1);
    r512[6] = r0; r512[7] = r1;
    EC4LIMB_UMULLO(r0, r512[4], EC4LIMB_REDUCTION_CONST); EC4LIMB_UMULLO(r1, r512[5], EC4LIMB_REDUCTION_CONST);
    EC4LIMB_MADDO(r1, r512[4], EC4LIMB_REDUCTION_CONST, r1);
    EC4LIMB_UMULLO(t2, r512[6], EC4LIMB_REDUCTION_CONST); EC4LIMB_MADDC(t2, r512[5], EC4LIMB_REDUCTION_CONST, t2);
    EC4LIMB_UMULLO(r3, r512[7], EC4LIMB_REDUCTION_CONST); EC4LIMB_MADDC(r3, r512[6], EC4LIMB_REDUCTION_CONST, r3);
    EC4LIMB_MADD(r4, r512[7], EC4LIMB_REDUCTION_CONST, 0ULL);
    EC4LIMB_UADDO1(r512[0], r0); EC4LIMB_UADDC1(r512[1], r1); EC4LIMB_UADDC1(r512[2], t2); EC4LIMB_UADDC1(r512[3], r3);
    EC4LIMB_UADD1(r4, 0ULL);
    EC4LIMB_UMULLO(u10, r4, EC4LIMB_REDUCTION_CONST); EC4LIMB_UMULHI(u11, r4, EC4LIMB_REDUCTION_CONST);
    EC4LIMB_UADDO(rp[0], r512[0], u10); EC4LIMB_UADDC(rp[1], r512[1], u11); EC4LIMB_UADDC(rp[2], r512[2], 0ULL); EC4LIMB_UADD(rp[3], r512[3], 0ULL);
}

// ---------------------------------------------------------------------------------
// Shift, IMult, MulP (for ModInv)
// ---------------------------------------------------------------------------------
__device__ __forceinline__ void ec4limb_ShiftR62(uint64_t *r)
{
    r[0] = (r[1] << 2) | (r[0] >> 62);
    r[1] = (r[2] << 2) | (r[1] >> 62);
    r[2] = (r[3] << 2) | (r[2] >> 62);
    r[3] = (r[4] << 2) | (r[3] >> 62);
    r[4] = (int64_t)(r[4]) >> 62;
}

__device__ __forceinline__ void ec4limb_ShiftR62(uint64_t dest[5], uint64_t r[5], uint64_t carry)
{
    dest[0] = (r[1] << 2) | (r[0] >> 62);
    dest[1] = (r[2] << 2) | (r[1] >> 62);
    dest[2] = (r[3] << 2) | (r[2] >> 62);
    dest[3] = (r[4] << 2) | (r[3] >> 62);
    dest[4] = (carry << 2) | (r[4] >> 62);
}

__device__ __forceinline__ void ec4limb_IMult(uint64_t *r, uint64_t *a, int64_t b)
{
    uint64_t t[EC4LIMB_NBBLOCK];
    if (b < 0) {
        b = -b;
        EC4LIMB_USUBO(t[0], 0ULL, a[0]); EC4LIMB_USUBC(t[1], 0ULL, a[1]);
        EC4LIMB_USUBC(t[2], 0ULL, a[2]); EC4LIMB_USUBC(t[3], 0ULL, a[3]); EC4LIMB_USUB(t[4], 0ULL, a[4]);
    } else { EC4LIMB_Load(t, a); }
    EC4LIMB_UMULLO(r[0], t[0], b); EC4LIMB_UMULLO(r[1], t[1], b);
    EC4LIMB_MADDO(r[1], t[0], b, r[1]); EC4LIMB_UMULLO(r[2], t[2], b);
    EC4LIMB_MADDC(r[2], t[1], b, r[2]); EC4LIMB_UMULLO(r[3], t[3], b);
    EC4LIMB_MADDC(r[3], t[2], b, r[3]); EC4LIMB_UMULLO(r[4], t[4], b);
    EC4LIMB_MADD(r[4], t[3], b, r[4]);
}

__device__ __forceinline__ uint64_t ec4limb_IMultC(uint64_t *r, uint64_t *a, int64_t b)
{
    uint64_t t[EC4LIMB_NBBLOCK], carry;
    if (b < 0) {
        b = -b;
        EC4LIMB_USUBO(t[0], 0ULL, a[0]); EC4LIMB_USUBC(t[1], 0ULL, a[1]);
        EC4LIMB_USUBC(t[2], 0ULL, a[2]); EC4LIMB_USUBC(t[3], 0ULL, a[3]); EC4LIMB_USUB(t[4], 0ULL, a[4]);
    } else { EC4LIMB_Load(t, a); }
    EC4LIMB_UMULLO(r[0], t[0], b); EC4LIMB_UMULLO(r[1], t[1], b);
    EC4LIMB_MADDO(r[1], t[0], b, r[1]); EC4LIMB_UMULLO(r[2], t[2], b);
    EC4LIMB_MADDC(r[2], t[1], b, r[2]); EC4LIMB_UMULLO(r[3], t[3], b);
    EC4LIMB_MADDC(r[3], t[2], b, r[3]); EC4LIMB_UMULLO(r[4], t[4], b);
    EC4LIMB_MADDC(r[4], t[3], b, r[4]); EC4LIMB_MADDS(carry, t[4], b, 0ULL);
    return carry;
}

__device__ __forceinline__ void ec4limb_MulP(uint64_t *r, uint64_t a)
{
    uint64_t ah, al;
    EC4LIMB_UMULLO(al, a, EC4LIMB_REDUCTION_CONST);
    EC4LIMB_UMULHI(ah, a, EC4LIMB_REDUCTION_CONST);
    EC4LIMB_USUBO(r[0], 0ULL, al); EC4LIMB_USUBC(r[1], 0ULL, ah);
    EC4LIMB_USUBC(r[2], 0ULL, 0ULL); EC4LIMB_USUBC(r[3], 0ULL, 0ULL); EC4LIMB_USUB(r[4], a, 0ULL);
}

__device__ __forceinline__ uint32_t ec4limb_CTZ(uint64_t x)
{
    uint32_t n;
    asm("{\n\t .reg .u64 tmp;\n\t brev.b64 tmp, %1;\n\t clz.b64 %0, tmp;\n\t}" : "=r"(n) : "l"(x));
    return n;
}

#define EC4LIMB_SWAP(tmp,x,y) do { tmp = x; x = y; y = tmp; } while(0)
#define EC4LIMB_sleft128(a,b,s) (((uint64_t)(b)<<(s))|((a)>>(64-(s))))

__device__ void ec4limb_DivStep62(uint64_t u[5], uint64_t v[5], int32_t *pos,
    int64_t *uu, int64_t *uv, int64_t *vu, int64_t *vv)
{
    *uu = 1; *uv = 0; *vu = 0; *vv = 1;
    uint32_t bitCount = 62, zeros;
    uint64_t u0 = u[0], v0 = v[0], uh, vh;
    int64_t w, x, y, z;
    while (*pos > 0 && (u[*pos] | v[*pos]) == 0) (*pos)--;
    if (*pos == 0) { uh = u[0]; vh = v[0]; }
    else {
        uint32_t s = __clzll(u[*pos] | v[*pos]);
        uh = (s == 0) ? u[*pos] : EC4LIMB_sleft128(u[*pos - 1], u[*pos], s);
        vh = (s == 0) ? v[*pos] : EC4LIMB_sleft128(v[*pos - 1], v[*pos], s);
    }
    while (true) {
        zeros = ec4limb_CTZ(v0 | (1ULL << bitCount));
        v0 >>= zeros; vh >>= zeros; *uu <<= zeros; *uv <<= zeros;
        bitCount -= zeros;
        if (bitCount == 0) break;
        if (vh < uh) { EC4LIMB_SWAP(w, uh, vh); EC4LIMB_SWAP(x, u0, v0); EC4LIMB_SWAP(y, *uu, *vu); EC4LIMB_SWAP(z, *uv, *vv); }
        vh -= uh; v0 -= u0; *vv -= *uv; *vu -= *uu;
    }
}

__device__ void ec4limb_MatrixVecMulHalf(uint64_t dest[5], uint64_t u[5], uint64_t v[5], int64_t _11, int64_t _12, uint64_t *carry)
{
    uint64_t t1[EC4LIMB_NBBLOCK], t2[EC4LIMB_NBBLOCK], c1, c2;
    c1 = ec4limb_IMultC(t1, u, _11); c2 = ec4limb_IMultC(t2, v, _12);
    EC4LIMB_UADDO(dest[0], t1[0], t2[0]); EC4LIMB_UADDC(dest[1], t1[1], t2[1]);
    EC4LIMB_UADDC(dest[2], t1[2], t2[2]); EC4LIMB_UADDC(dest[3], t1[3], t2[3]); EC4LIMB_UADDC(dest[4], t1[4], t2[4]);
    EC4LIMB_UADD(*carry, c1, c2);
}

__device__ void ec4limb_MatrixVecMul(uint64_t u[5], uint64_t v[5], int64_t _11, int64_t _12, int64_t _21, int64_t _22)
{
    uint64_t t1[EC4LIMB_NBBLOCK], t2[EC4LIMB_NBBLOCK], t3[EC4LIMB_NBBLOCK], t4[EC4LIMB_NBBLOCK];
    ec4limb_IMult(t1, u, _11); ec4limb_IMult(t2, v, _12);
    ec4limb_IMult(t3, u, _21); ec4limb_IMult(t4, v, _22);
    EC4LIMB_UADDO(u[0], t1[0], t2[0]); EC4LIMB_UADDC(u[1], t1[1], t2[1]);
    EC4LIMB_UADDC(u[2], t1[2], t2[2]); EC4LIMB_UADDC(u[3], t1[3], t2[3]); EC4LIMB_UADD(u[4], t1[4], t2[4]);
    EC4LIMB_UADDO(v[0], t3[0], t4[0]); EC4LIMB_UADDC(v[1], t3[1], t4[1]);
    EC4LIMB_UADDC(v[2], t3[2], t4[2]); EC4LIMB_UADDC(v[3], t3[3], t4[3]); EC4LIMB_UADD(v[4], t3[4], t4[4]);
}

__device__ uint64_t ec4limb_AddCh(uint64_t r[5], uint64_t a[5], uint64_t carry)
{
    uint64_t carryOut;
    EC4LIMB_UADDO1(r[0], a[0]); EC4LIMB_UADDC1(r[1], a[1]);
    EC4LIMB_UADDC1(r[2], a[2]); EC4LIMB_UADDC1(r[3], a[3]); EC4LIMB_UADDC1(r[4], a[4]);
    EC4LIMB_UADD(carryOut, carry, 0ULL);
    return carryOut;
}

__device__ __noinline__ void ec4limb_ModInv(uint64_t *R)
{
    uint64_t u[EC4LIMB_NBBLOCK], v[EC4LIMB_NBBLOCK], r[EC4LIMB_NBBLOCK], s[EC4LIMB_NBBLOCK];
    uint64_t tr[EC4LIMB_NBBLOCK], ts[EC4LIMB_NBBLOCK], r0[EC4LIMB_NBBLOCK], s0[EC4LIMB_NBBLOCK];
    int64_t uu, uv, vu, vv;
    uint64_t mr0, ms0, carryR, carryS;
    int32_t pos = EC4LIMB_NBBLOCK - 1;
    u[0] = EC4LIMB_P0; u[1] = EC4LIMB_P1; u[2] = EC4LIMB_P2; u[3] = EC4LIMB_P3; u[4] = 0;
    EC4LIMB_Load(v, R);
    r[0] = 0; s[0] = 1; r[1]=r[2]=r[3]=r[4] = 0; s[1]=s[2]=s[3]=s[4] = 0;
    while (true) {
        ec4limb_DivStep62(u, v, &pos, &uu, &uv, &vu, &vv);
        ec4limb_MatrixVecMul(u, v, uu, uv, vu, vv);
        if (EC4LIMB_IsNegative(u)) { EC4LIMB_Neg(u); uu = -uu; uv = -uv; }
        if (EC4LIMB_IsNegative(v)) { EC4LIMB_Neg(v); vu = -vu; vv = -vv; }
        ec4limb_ShiftR62(u); ec4limb_ShiftR62(v);
        ec4limb_MatrixVecMulHalf(tr, r, s, uu, uv, &carryR);
        mr0 = (tr[0] * EC4LIMB_MM64) & EC4LIMB_MSK62;
        ec4limb_MulP(r0, mr0);
        carryR = ec4limb_AddCh(tr, r0, carryR);
        if (EC4LIMB_IsZero(v)) { ec4limb_ShiftR62(r, tr, carryR); break; }
        ec4limb_MatrixVecMulHalf(ts, r, s, vu, vv, &carryS);
        ms0 = (ts[0] * EC4LIMB_MM64) & EC4LIMB_MSK62;
        ec4limb_MulP(s0, ms0);
        carryS = ec4limb_AddCh(ts, s0, carryS);
        ec4limb_ShiftR62(r, tr, carryR);
        ec4limb_ShiftR62(s, ts, carryS);
    }
    if (!EC4LIMB_IsOne(u)) { R[0]=R[1]=R[2]=R[3]=R[4] = 0; return; }
    while (EC4LIMB_IsNegative(r)) EC4LIMB_AddP(r);
    while (!EC4LIMB_IsNegative(r)) EC4LIMB_SubP(r);
    EC4LIMB_AddP(r);
    EC4LIMB_Load(R, r);
}

template<int MAX_COUNT>
__device__ void ec4limb_BatchModInv(uint64_t Z[][4], int count)
{
    if (count <= 0) return;
    if (count == 1) {
        uint64_t tmp[5];
        EC4LIMB_Load256(tmp, Z[0]); tmp[4] = 0;
        ec4limb_ModInv(tmp);
        EC4LIMB_Store256(Z[0], tmp);
        return;
    }
    uint64_t products[MAX_COUNT][4], acc[4];
    EC4LIMB_Load256(acc, Z[0]); EC4LIMB_Store256(products[0], acc);
    for (int i = 1; i < count; i++) {
        ec4limb_ModMult(acc, acc, Z[i]);
        EC4LIMB_Store256(products[i], acc);
    }
    uint64_t accInv[5];
    EC4LIMB_Load256(accInv, acc); accInv[4] = 0;
    ec4limb_ModInv(accInv);
    for (int i = count - 1; i > 0; i--) {
        uint64_t tmp[4];
        ec4limb_ModMult(tmp, accInv, products[i-1]);
        ec4limb_ModMult(accInv, accInv, Z[i]);
        EC4LIMB_Store256(Z[i], tmp);
    }
    EC4LIMB_Store256(Z[0], accInv);
}

// ---------------------------------------------------------------------------------
// Point Add Mixed Jacobian-Affine (8M+3S)
// ---------------------------------------------------------------------------------
__device__ void ec4limb_PointAddMixedAffine(
    uint64_t *X1, uint64_t *Y1, uint64_t *Z1,
    const uint64_t *x2, const uint64_t *y2)
{
    uint64_t Z1Z1[4], U2[4], S2[4], H[4], HH[4], I[4], J[4], r[4], V[4], tmp[4];
    ec4limb_ModSqr(Z1Z1, Z1);
    ec4limb_ModMult(U2, x2, Z1Z1);
    ec4limb_ModMult(S2, Z1, Z1Z1);
    ec4limb_ModMult(S2, y2, S2);
    ec4limb_ModSub256(H, U2, X1);
    ec4limb_ModSub256(r, S2, Y1);
    ec4limb_ModDouble256(r, r);
    ec4limb_ModSqr(HH, H);
    ec4limb_ModDouble256(I, HH);
    ec4limb_ModDouble256(I, I);
    ec4limb_ModMult(J, H, I);
    ec4limb_ModMult(V, X1, I);
    ec4limb_ModSqr(X1, r);
    ec4limb_ModSub256(X1, J);   // X1 = r^2 - J
    ec4limb_ModSub256(X1, V);  // X1 -= V
    ec4limb_ModSub256(X1, V);  // X1 -= 2*V
    ec4limb_ModSub256(tmp, V, X1);
    ec4limb_ModMult(tmp, r, tmp);   // tmp = r * (V - X3)
    uint64_t Y1J[4];
    ec4limb_ModMult(Y1J, Y1, J);
    ec4limb_ModDouble256(Y1J, Y1J); // 2*Y1*J
    ec4limb_ModSub256(Y1, tmp, Y1J); // Y3 = r*(V-X3) - 2*Y1*J
    ec4limb_ModMult(Z1, Z1, H);
    ec4limb_ModDouble256(Z1, Z1);
}

// ---------------------------------------------------------------------------------
// Jacobian to Affine (single), Batch Jacobian to Affine
// ---------------------------------------------------------------------------------
__device__ void ec4limb_JacobianToAffine(uint64_t *X, uint64_t *Y, uint64_t *Z)
{
    uint64_t ZInv[5], ZInv2[4], ZInv3[4];
    EC4LIMB_Load256(ZInv, Z); ZInv[4] = 0;
    ec4limb_ModInv(ZInv);
    ec4limb_ModSqr(ZInv2, ZInv);
    ec4limb_ModMult(ZInv3, ZInv2, ZInv);
    ec4limb_ModMult(X, X, ZInv2);
    ec4limb_ModMult(Y, Y, ZInv3);
    Z[0] = 1; Z[1] = Z[2] = Z[3] = 0;
}

template<int MAX_COUNT>
__device__ void ec4limb_BatchJacobianToAffine(uint64_t X[][4], uint64_t Y[][4], uint64_t Z[][4], int count)
{
    if (count <= 0) return;
    if (count == 1) { ec4limb_JacobianToAffine(X[0], Y[0], Z[0]); return; }
    ec4limb_BatchModInv<MAX_COUNT>(Z, count);
    for (int i = 0; i < count; i++) {
        uint64_t ZInv2[4], ZInv3[4];
        ec4limb_ModSqr(ZInv2, Z[i]);
        ec4limb_ModMult(ZInv3, ZInv2, Z[i]);
        ec4limb_ModMult(X[i], X[i], ZInv2);
        ec4limb_ModMult(Y[i], Y[i], ZInv3);
        Z[i][0] = 1; Z[i][1] = Z[i][2] = Z[i][3] = 0;
    }
}
