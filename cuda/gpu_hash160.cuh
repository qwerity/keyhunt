/*
 * gpu_hash160.cuh - Device Hash160 (SHA256 + RIPEMD160) ported from examples/GPUHash.h
 * Uses __byte_perm for public-key-to-bytes and macro-unrolled SHA256/RIPEMD160 for speed.
 * Input: uint32_t x[8] (public key X as 8 words, v[0]=LSW), optionally y[8] and isOdd for compressed.
 * Output: uint32_t hash[5] (Hash160 digest).
 */
#pragma once

#include <cstdint>

// ---------------------------------------------------------------------------------
// SHA256 (from GPUHash.h, prefixed to avoid clashes)
// ---------------------------------------------------------------------------------
__device__ __constant__ uint32_t gpuHash160_K[] = {
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
};

__device__ __constant__ uint32_t gpuHash160_I[] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
};

#define GPUHASH_ROR(x,n) ((x>>n)|(x<<(32-n)))
#define GPUHASH_S0(x) (GPUHASH_ROR(x,2) ^ GPUHASH_ROR(x,13) ^ GPUHASH_ROR(x,22))
#define GPUHASH_S1(x) (GPUHASH_ROR(x,6) ^ GPUHASH_ROR(x,11) ^ GPUHASH_ROR(x,25))
#define GPUHASH_s0(x) (GPUHASH_ROR(x,7) ^ GPUHASH_ROR(x,18) ^ (x >> 3))
#define GPUHASH_s1(x) (GPUHASH_ROR(x,17) ^ GPUHASH_ROR(x,19) ^ (x >> 10))
#define GPUHASH_Maj(x,y,z) ((x & y) | (z & (x | y)))
#define GPUHASH_Ch(x,y,z) (z ^ (x & (y ^ z)))

#define GPUHASH_S2Round(a, b, c, d, e, f, g, h, k, w) \
    t1 = h + GPUHASH_S1(e) + GPUHASH_Ch(e,f,g) + k + (w); \
    t2 = GPUHASH_S0(a) + GPUHASH_Maj(a,b,c); \
    d += t1; \
    h = t1 + t2;

#define GPUHASH_WMIX() do { \
    w[0] += GPUHASH_s1(w[14]) + w[9] + GPUHASH_s0(w[1]); \
    w[1] += GPUHASH_s1(w[15]) + w[10] + GPUHASH_s0(w[2]); \
    w[2] += GPUHASH_s1(w[0]) + w[11] + GPUHASH_s0(w[3]); \
    w[3] += GPUHASH_s1(w[1]) + w[12] + GPUHASH_s0(w[4]); \
    w[4] += GPUHASH_s1(w[2]) + w[13] + GPUHASH_s0(w[5]); \
    w[5] += GPUHASH_s1(w[3]) + w[14] + GPUHASH_s0(w[6]); \
    w[6] += GPUHASH_s1(w[4]) + w[15] + GPUHASH_s0(w[7]); \
    w[7] += GPUHASH_s1(w[5]) + w[0] + GPUHASH_s0(w[8]); \
    w[8] += GPUHASH_s1(w[6]) + w[1] + GPUHASH_s0(w[9]); \
    w[9] += GPUHASH_s1(w[7]) + w[2] + GPUHASH_s0(w[10]); \
    w[10] += GPUHASH_s1(w[8]) + w[3] + GPUHASH_s0(w[11]); \
    w[11] += GPUHASH_s1(w[9]) + w[4] + GPUHASH_s0(w[12]); \
    w[12] += GPUHASH_s1(w[10]) + w[5] + GPUHASH_s0(w[13]); \
    w[13] += GPUHASH_s1(w[11]) + w[6] + GPUHASH_s0(w[14]); \
    w[14] += GPUHASH_s1(w[12]) + w[7] + GPUHASH_s0(w[15]); \
    w[15] += GPUHASH_s1(w[13]) + w[8] + GPUHASH_s0(w[0]); \
} while(0)

#define GPUHASH_SHA256_RND(k) do { \
    GPUHASH_S2Round(a, b, c, d, e, f, g, h, gpuHash160_K[k], w[0]); \
    GPUHASH_S2Round(h, a, b, c, d, e, f, g, gpuHash160_K[k + 1], w[1]); \
    GPUHASH_S2Round(g, h, a, b, c, d, e, f, gpuHash160_K[k + 2], w[2]); \
    GPUHASH_S2Round(f, g, h, a, b, c, d, e, gpuHash160_K[k + 3], w[3]); \
    GPUHASH_S2Round(e, f, g, h, a, b, c, d, gpuHash160_K[k + 4], w[4]); \
    GPUHASH_S2Round(d, e, f, g, h, a, b, c, gpuHash160_K[k + 5], w[5]); \
    GPUHASH_S2Round(c, d, e, f, g, h, a, b, gpuHash160_K[k + 6], w[6]); \
    GPUHASH_S2Round(b, c, d, e, f, g, h, a, gpuHash160_K[k + 7], w[7]); \
    GPUHASH_S2Round(a, b, c, d, e, f, g, h, gpuHash160_K[k + 8], w[8]); \
    GPUHASH_S2Round(h, a, b, c, d, e, f, g, gpuHash160_K[k + 9], w[9]); \
    GPUHASH_S2Round(g, h, a, b, c, d, e, f, gpuHash160_K[k + 10], w[10]); \
    GPUHASH_S2Round(f, g, h, a, b, c, d, e, gpuHash160_K[k + 11], w[11]); \
    GPUHASH_S2Round(e, f, g, h, a, b, c, d, gpuHash160_K[k + 12], w[12]); \
    GPUHASH_S2Round(d, e, f, g, h, a, b, c, gpuHash160_K[k + 13], w[13]); \
    GPUHASH_S2Round(c, d, e, f, g, h, a, b, gpuHash160_K[k + 14], w[14]); \
    GPUHASH_S2Round(b, c, d, e, f, g, h, a, gpuHash160_K[k + 15], w[15]); \
} while(0)

#define GPUHASH_DEF(x,y) uint32_t x = output[y]

__device__ __forceinline__ void gpuHash160_SHA256Initialize(uint32_t s[8])
{
    #pragma unroll 8
    for (int i = 0; i < 8; i++)
        s[i] = gpuHash160_I[i];
}

__device__ __forceinline__ void gpuHash160_SHA256Transform(uint32_t output[8], uint32_t* w)
{
    uint32_t t1, t2;
    GPUHASH_DEF(a, 0);
    GPUHASH_DEF(b, 1);
    GPUHASH_DEF(c, 2);
    GPUHASH_DEF(d, 3);
    GPUHASH_DEF(e, 4);
    GPUHASH_DEF(f, 5);
    GPUHASH_DEF(g, 6);
    GPUHASH_DEF(h, 7);
    GPUHASH_SHA256_RND(0);
    GPUHASH_WMIX();
    GPUHASH_SHA256_RND(16);
    GPUHASH_WMIX();
    GPUHASH_SHA256_RND(32);
    GPUHASH_WMIX();
    GPUHASH_SHA256_RND(48);
    output[0] += a;
    output[1] += b;
    output[2] += c;
    output[3] += d;
    output[4] += e;
    output[5] += f;
    output[6] += g;
    output[7] += h;
}

#define gpuHash160_bswap32(v) __byte_perm(v, 0, 0x0123)

// ---------------------------------------------------------------------------------
// RIPEMD160 (from GPUHash.h)
// ---------------------------------------------------------------------------------
__device__ __constant__ uint64_t gpuHash160_ripemd160_sizedesc_32 = 32ULL << 3;

#define GPUHASH_ROL(x,n) ((x>>(32-n))|(x<<n))
#define GPUHASH_f1(x,y,z) (x ^ y ^ z)
#define GPUHASH_f2(x,y,z) ((x & y) | (~x & z))
#define GPUHASH_f3(x,y,z) ((x | ~y) ^ z)
#define GPUHASH_f4(x,y,z) ((x & z) | (~z & y))
#define GPUHASH_f5(x,y,z) (x ^ (y | ~z))

#define GPUHASH_RPRound(a,b,c,d,e,f,x,k,r) do { \
    u = a + f + x + k; \
    a = GPUHASH_ROL(u, r) + e; \
    c = GPUHASH_ROL(c, 10); \
} while(0)

#define GPUHASH_R11(a,b,c,d,e,x,r) GPUHASH_RPRound(a, b, c, d, e, GPUHASH_f1(b, c, d), x, 0, r)
#define GPUHASH_R21(a,b,c,d,e,x,r) GPUHASH_RPRound(a, b, c, d, e, GPUHASH_f2(b, c, d), x, 0x5A827999ul, r)
#define GPUHASH_R31(a,b,c,d,e,x,r) GPUHASH_RPRound(a, b, c, d, e, GPUHASH_f3(b, c, d), x, 0x6ED9EBA1ul, r)
#define GPUHASH_R41(a,b,c,d,e,x,r) GPUHASH_RPRound(a, b, c, d, e, GPUHASH_f4(b, c, d), x, 0x8F1BBCDCul, r)
#define GPUHASH_R51(a,b,c,d,e,x,r) GPUHASH_RPRound(a, b, c, d, e, GPUHASH_f5(b, c, d), x, 0xA953FD4Eul, r)
#define GPUHASH_R12(a,b,c,d,e,x,r) GPUHASH_RPRound(a, b, c, d, e, GPUHASH_f5(b, c, d), x, 0x50A28BE6ul, r)
#define GPUHASH_R22(a,b,c,d,e,x,r) GPUHASH_RPRound(a, b, c, d, e, GPUHASH_f4(b, c, d), x, 0x5C4DD124ul, r)
#define GPUHASH_R32(a,b,c,d,e,x,r) GPUHASH_RPRound(a, b, c, d, e, GPUHASH_f3(b, c, d), x, 0x6D703EF3ul, r)
#define GPUHASH_R42(a,b,c,d,e,x,r) GPUHASH_RPRound(a, b, c, d, e, GPUHASH_f2(b, c, d), x, 0x7A6D76E9ul, r)
#define GPUHASH_R52(a,b,c,d,e,x,r) GPUHASH_RPRound(a, b, c, d, e, GPUHASH_f1(b, c, d), x, 0, r)

__device__ __forceinline__ void gpuHash160_RIPEMD160Initialize(uint32_t s[5])
{
    s[0] = 0x67452301ul;
    s[1] = 0xEFCDAB89ul;
    s[2] = 0x98BADCFEul;
    s[3] = 0x10325476ul;
    s[4] = 0xC3D2E1F0ul;
}

__device__ void gpuHash160_RIPEMD160Transform(uint32_t s[5], uint32_t* w)
{
    uint32_t u;
    uint32_t a1 = s[0], b1 = s[1], c1 = s[2], d1 = s[3], e1 = s[4];
    uint32_t a2 = a1, b2 = b1, c2 = c1, d2 = d1, e2 = e1;
    GPUHASH_R11(a1, b1, c1, d1, e1, w[0], 11);
    GPUHASH_R12(a2, b2, c2, d2, e2, w[5], 8);
    GPUHASH_R11(e1, a1, b1, c1, d1, w[1], 14);
    GPUHASH_R12(e2, a2, b2, c2, d2, w[14], 9);
    GPUHASH_R11(d1, e1, a1, b1, c1, w[2], 15);
    GPUHASH_R12(d2, e2, a2, b2, c2, w[7], 9);
    GPUHASH_R11(c1, d1, e1, a1, b1, w[3], 12);
    GPUHASH_R12(c2, d2, e2, a2, b2, w[0], 11);
    GPUHASH_R11(b1, c1, d1, e1, a1, w[4], 5);
    GPUHASH_R12(b2, c2, d2, e2, a2, w[9], 13);
    GPUHASH_R11(a1, b1, c1, d1, e1, w[5], 8);
    GPUHASH_R12(a2, b2, c2, d2, e2, w[2], 15);
    GPUHASH_R11(e1, a1, b1, c1, d1, w[6], 7);
    GPUHASH_R12(e2, a2, b2, c2, d2, w[11], 15);
    GPUHASH_R11(d1, e1, a1, b1, c1, w[7], 9);
    GPUHASH_R12(d2, e2, a2, b2, c2, w[4], 5);
    GPUHASH_R11(c1, d1, e1, a1, b1, w[8], 11);
    GPUHASH_R12(c2, d2, e2, a2, b2, w[13], 7);
    GPUHASH_R11(b1, c1, d1, e1, a1, w[9], 13);
    GPUHASH_R12(b2, c2, d2, e2, a2, w[6], 7);
    GPUHASH_R11(a1, b1, c1, d1, e1, w[10], 14);
    GPUHASH_R12(a2, b2, c2, d2, e2, w[15], 8);
    GPUHASH_R11(e1, a1, b1, c1, d1, w[11], 15);
    GPUHASH_R12(e2, a2, b2, c2, d2, w[8], 11);
    GPUHASH_R11(d1, e1, a1, b1, c1, w[12], 6);
    GPUHASH_R12(d2, e2, a2, b2, c2, w[1], 14);
    GPUHASH_R11(c1, d1, e1, a1, b1, w[13], 7);
    GPUHASH_R12(c2, d2, e2, a2, b2, w[10], 14);
    GPUHASH_R11(b1, c1, d1, e1, a1, w[14], 9);
    GPUHASH_R12(b2, c2, d2, e2, a2, w[3], 12);
    GPUHASH_R11(a1, b1, c1, d1, e1, w[15], 8);
    GPUHASH_R12(a2, b2, c2, d2, e2, w[12], 6);
    GPUHASH_R21(e1, a1, b1, c1, d1, w[7], 7);
    GPUHASH_R22(e2, a2, b2, c2, d2, w[6], 9);
    GPUHASH_R21(d1, e1, a1, b1, c1, w[4], 6);
    GPUHASH_R22(d2, e2, a2, b2, c2, w[11], 13);
    GPUHASH_R21(c1, d1, e1, a1, b1, w[13], 8);
    GPUHASH_R22(c2, d2, e2, a2, b2, w[3], 15);
    GPUHASH_R21(b1, c1, d1, e1, a1, w[1], 13);
    GPUHASH_R22(b2, c2, d2, e2, a2, w[7], 7);
    GPUHASH_R21(a1, b1, c1, d1, e1, w[10], 11);
    GPUHASH_R22(a2, b2, c2, d2, e2, w[0], 12);
    GPUHASH_R21(e1, a1, b1, c1, d1, w[6], 9);
    GPUHASH_R22(e2, a2, b2, c2, d2, w[13], 8);
    GPUHASH_R21(d1, e1, a1, b1, c1, w[15], 7);
    GPUHASH_R22(d2, e2, a2, b2, c2, w[5], 9);
    GPUHASH_R21(c1, d1, e1, a1, b1, w[3], 15);
    GPUHASH_R22(c2, d2, e2, a2, b2, w[10], 11);
    GPUHASH_R21(b1, c1, d1, e1, a1, w[12], 7);
    GPUHASH_R22(b2, c2, d2, e2, a2, w[14], 7);
    GPUHASH_R21(a1, b1, c1, d1, e1, w[0], 12);
    GPUHASH_R22(a2, b2, c2, d2, e2, w[15], 7);
    GPUHASH_R21(e1, a1, b1, c1, d1, w[9], 15);
    GPUHASH_R22(e2, a2, b2, c2, d2, w[8], 12);
    GPUHASH_R21(d1, e1, a1, b1, c1, w[5], 9);
    GPUHASH_R22(d2, e2, a2, b2, c2, w[12], 7);
    GPUHASH_R21(c1, d1, e1, a1, b1, w[2], 11);
    GPUHASH_R22(c2, d2, e2, a2, b2, w[4], 6);
    GPUHASH_R21(b1, c1, d1, e1, a1, w[14], 7);
    GPUHASH_R22(b2, c2, d2, e2, a2, w[9], 15);
    GPUHASH_R21(a1, b1, c1, d1, e1, w[11], 13);
    GPUHASH_R22(a2, b2, c2, d2, e2, w[1], 13);
    GPUHASH_R31(d1, e1, a1, b1, c1, w[3], 11);
    GPUHASH_R32(d2, e2, a2, b2, c2, w[15], 9);
    GPUHASH_R31(c1, d1, e1, a1, b1, w[10], 13);
    GPUHASH_R32(c2, d2, e2, a2, b2, w[5], 7);
    GPUHASH_R31(b1, c1, d1, e1, a1, w[14], 6);
    GPUHASH_R32(b2, c2, d2, e2, a2, w[1], 15);
    GPUHASH_R31(a1, b1, c1, d1, e1, w[4], 7);
    GPUHASH_R32(a2, b2, c2, d2, e2, w[3], 11);
    GPUHASH_R31(e1, a1, b1, c1, d1, w[9], 14);
    GPUHASH_R32(e2, a2, b2, c2, d2, w[7], 8);
    GPUHASH_R31(d1, e1, a1, b1, c1, w[15], 9);
    GPUHASH_R32(d2, e2, a2, b2, c2, w[14], 6);
    GPUHASH_R31(c1, d1, e1, a1, b1, w[8], 13);
    GPUHASH_R32(c2, d2, e2, a2, b2, w[6], 6);
    GPUHASH_R31(b1, c1, d1, e1, a1, w[1], 15);
    GPUHASH_R32(b2, c2, d2, e2, a2, w[9], 14);
    GPUHASH_R31(a1, b1, c1, d1, e1, w[2], 14);
    GPUHASH_R32(a2, b2, c2, d2, e2, w[11], 12);
    GPUHASH_R31(e1, a1, b1, c1, d1, w[7], 8);
    GPUHASH_R32(e2, a2, b2, c2, d2, w[8], 13);
    GPUHASH_R31(d1, e1, a1, b1, c1, w[0], 13);
    GPUHASH_R32(d2, e2, a2, b2, c2, w[12], 5);
    GPUHASH_R31(c1, d1, e1, a1, b1, w[6], 6);
    GPUHASH_R32(c2, d2, e2, a2, b2, w[2], 14);
    GPUHASH_R31(b1, c1, d1, e1, a1, w[13], 5);
    GPUHASH_R32(b2, c2, d2, e2, a2, w[10], 13);
    GPUHASH_R31(a1, b1, c1, d1, e1, w[11], 12);
    GPUHASH_R32(a2, b2, c2, d2, e2, w[0], 13);
    GPUHASH_R31(e1, a1, b1, c1, d1, w[5], 7);
    GPUHASH_R32(e2, a2, b2, c2, d2, w[4], 7);
    GPUHASH_R31(d1, e1, a1, b1, c1, w[12], 5);
    GPUHASH_R32(d2, e2, a2, b2, c2, w[13], 5);
    GPUHASH_R41(c1, d1, e1, a1, b1, w[1], 11);
    GPUHASH_R42(c2, d2, e2, a2, b2, w[8], 15);
    GPUHASH_R41(b1, c1, d1, e1, a1, w[9], 12);
    GPUHASH_R42(b2, c2, d2, e2, a2, w[6], 5);
    GPUHASH_R41(a1, b1, c1, d1, e1, w[11], 14);
    GPUHASH_R42(a2, b2, c2, d2, e2, w[4], 8);
    GPUHASH_R41(e1, a1, b1, c1, d1, w[10], 15);
    GPUHASH_R42(e2, a2, b2, c2, d2, w[1], 11);
    GPUHASH_R41(d1, e1, a1, b1, c1, w[0], 14);
    GPUHASH_R42(d2, e2, a2, b2, c2, w[3], 14);
    GPUHASH_R41(c1, d1, e1, a1, b1, w[8], 15);
    GPUHASH_R42(c2, d2, e2, a2, b2, w[11], 14);
    GPUHASH_R41(b1, c1, d1, e1, a1, w[12], 9);
    GPUHASH_R42(b2, c2, d2, e2, a2, w[15], 6);
    GPUHASH_R41(a1, b1, c1, d1, e1, w[4], 8);
    GPUHASH_R42(a2, b2, c2, d2, e2, w[0], 14);
    GPUHASH_R41(e1, a1, b1, c1, d1, w[13], 9);
    GPUHASH_R42(e2, a2, b2, c2, d2, w[5], 6);
    GPUHASH_R41(d1, e1, a1, b1, c1, w[3], 14);
    GPUHASH_R42(d2, e2, a2, b2, c2, w[12], 9);
    GPUHASH_R41(c1, d1, e1, a1, b1, w[7], 5);
    GPUHASH_R42(c2, d2, e2, a2, b2, w[2], 12);
    GPUHASH_R41(b1, c1, d1, e1, a1, w[15], 6);
    GPUHASH_R42(b2, c2, d2, e2, a2, w[13], 9);
    GPUHASH_R41(a1, b1, c1, d1, e1, w[14], 8);
    GPUHASH_R42(a2, b2, c2, d2, e2, w[9], 12);
    GPUHASH_R41(e1, a1, b1, c1, d1, w[5], 6);
    GPUHASH_R42(e2, a2, b2, c2, d2, w[7], 5);
    GPUHASH_R41(d1, e1, a1, b1, c1, w[6], 5);
    GPUHASH_R42(d2, e2, a2, b2, c2, w[10], 15);
    GPUHASH_R41(c1, d1, e1, a1, b1, w[2], 12);
    GPUHASH_R42(c2, d2, e2, a2, b2, w[14], 8);
    GPUHASH_R51(b1, c1, d1, e1, a1, w[4], 9);
    GPUHASH_R52(b2, c2, d2, e2, a2, w[12], 8);
    GPUHASH_R51(a1, b1, c1, d1, e1, w[0], 15);
    GPUHASH_R52(a2, b2, c2, d2, e2, w[15], 5);
    GPUHASH_R51(e1, a1, b1, c1, d1, w[5], 5);
    GPUHASH_R52(e2, a2, b2, c2, d2, w[10], 12);
    GPUHASH_R51(d1, e1, a1, b1, c1, w[9], 11);
    GPUHASH_R52(d2, e2, a2, b2, c2, w[4], 9);
    GPUHASH_R51(c1, d1, e1, a1, b1, w[7], 6);
    GPUHASH_R52(c2, d2, e2, a2, b2, w[1], 12);
    GPUHASH_R51(b1, c1, d1, e1, a1, w[12], 8);
    GPUHASH_R52(b2, c2, d2, e2, a2, w[5], 5);
    GPUHASH_R51(a1, b1, c1, d1, e1, w[2], 13);
    GPUHASH_R52(a2, b2, c2, d2, e2, w[8], 14);
    GPUHASH_R51(e1, a1, b1, c1, d1, w[10], 12);
    GPUHASH_R52(e2, a2, b2, c2, d2, w[7], 6);
    GPUHASH_R51(d1, e1, a1, b1, c1, w[14], 5);
    GPUHASH_R52(d2, e2, a2, b2, c2, w[6], 8);
    GPUHASH_R51(c1, d1, e1, a1, b1, w[1], 12);
    GPUHASH_R52(c2, d2, e2, a2, b2, w[2], 13);
    GPUHASH_R51(b1, c1, d1, e1, a1, w[3], 13);
    GPUHASH_R52(b2, c2, d2, e2, a2, w[13], 6);
    GPUHASH_R51(a1, b1, c1, d1, e1, w[8], 14);
    GPUHASH_R52(a2, b2, c2, d2, e2, w[14], 5);
    GPUHASH_R51(e1, a1, b1, c1, d1, w[11], 11);
    GPUHASH_R52(e2, a2, b2, c2, d2, w[0], 15);
    GPUHASH_R51(d1, e1, a1, b1, c1, w[6], 8);
    GPUHASH_R52(d2, e2, a2, b2, c2, w[3], 13);
    GPUHASH_R51(c1, d1, e1, a1, b1, w[15], 5);
    GPUHASH_R52(c2, d2, e2, a2, b2, w[9], 11);
    GPUHASH_R51(b1, c1, d1, e1, a1, w[13], 6);
    GPUHASH_R52(b2, c2, d2, e2, a2, w[11], 11);
    uint32_t t = s[0];
    s[0] = s[1] + c1 + d2;
    s[1] = s[2] + d1 + e2;
    s[2] = s[3] + e1 + a2;
    s[3] = s[4] + a1 + b2;
    s[4] = t + b1 + c2;
}

// ---------------------------------------------------------------------------------
// Hash160 from public key (compressed: 0x02|0x03 || x; uncompressed: 0x04 || x || y)
// x32[0]=LSW .. x32[7]=MSW (same as uint256_t.v)
// ---------------------------------------------------------------------------------
__device__ __forceinline__ void gpuHash160Comp(const uint32_t* x32, uint8_t isOdd, uint32_t hash[5])
{
    uint32_t publicKeyBytes[16];
    uint32_t s[16];
    publicKeyBytes[0] = __byte_perm(x32[7], 0x2 + isOdd, 0x4321);
    publicKeyBytes[1] = __byte_perm(x32[7], x32[6], 0x0765);
    publicKeyBytes[2] = __byte_perm(x32[6], x32[5], 0x0765);
    publicKeyBytes[3] = __byte_perm(x32[5], x32[4], 0x0765);
    publicKeyBytes[4] = __byte_perm(x32[4], x32[3], 0x0765);
    publicKeyBytes[5] = __byte_perm(x32[3], x32[2], 0x0765);
    publicKeyBytes[6] = __byte_perm(x32[2], x32[1], 0x0765);
    publicKeyBytes[7] = __byte_perm(x32[1], x32[0], 0x0765);
    publicKeyBytes[8] = __byte_perm(x32[0], 0x80, 0x0456);
    publicKeyBytes[9] = 0;
    publicKeyBytes[10] = 0;
    publicKeyBytes[11] = 0;
    publicKeyBytes[12] = 0;
    publicKeyBytes[13] = 0;
    publicKeyBytes[14] = 0;
    publicKeyBytes[15] = 0x108;
    gpuHash160_SHA256Initialize(s);
    gpuHash160_SHA256Transform(s, publicKeyBytes);
    #pragma unroll 8
    for (int i = 0; i < 8; i++)
        s[i] = gpuHash160_bswap32(s[i]);
    *(uint64_t*)(s + 8) = 0x80ULL;
    *(uint64_t*)(s + 10) = 0ULL;
    *(uint64_t*)(s + 12) = 0ULL;
    *(uint64_t*)(s + 14) = static_cast<uint32_t>(gpuHash160_ripemd160_sizedesc_32);
    gpuHash160_RIPEMD160Initialize(hash);
    gpuHash160_RIPEMD160Transform(hash, s);
}

__device__ __forceinline__ void gpuHash160Uncomp(const uint32_t* x32, const uint32_t* y32, uint32_t hash[5])
{
    uint32_t publicKeyBytes[32];
    uint32_t s[16];
    publicKeyBytes[0] = __byte_perm(x32[7], 0x04, 0x4321);
    publicKeyBytes[1] = __byte_perm(x32[7], x32[6], 0x0765);
    publicKeyBytes[2] = __byte_perm(x32[6], x32[5], 0x0765);
    publicKeyBytes[3] = __byte_perm(x32[5], x32[4], 0x0765);
    publicKeyBytes[4] = __byte_perm(x32[4], x32[3], 0x0765);
    publicKeyBytes[5] = __byte_perm(x32[3], x32[2], 0x0765);
    publicKeyBytes[6] = __byte_perm(x32[2], x32[1], 0x0765);
    publicKeyBytes[7] = __byte_perm(x32[1], x32[0], 0x0765);
    publicKeyBytes[8] = __byte_perm(x32[0], y32[7], 0x0765);
    publicKeyBytes[9] = __byte_perm(y32[7], y32[6], 0x0765);
    publicKeyBytes[10] = __byte_perm(y32[6], y32[5], 0x0765);
    publicKeyBytes[11] = __byte_perm(y32[5], y32[4], 0x0765);
    publicKeyBytes[12] = __byte_perm(y32[4], y32[3], 0x0765);
    publicKeyBytes[13] = __byte_perm(y32[3], y32[2], 0x0765);
    publicKeyBytes[14] = __byte_perm(y32[2], y32[1], 0x0765);
    publicKeyBytes[15] = __byte_perm(y32[1], y32[0], 0x0765);
    publicKeyBytes[16] = __byte_perm(y32[0], 0x80, 0x0456);
    publicKeyBytes[17] = 0;
    publicKeyBytes[18] = 0;
    publicKeyBytes[19] = 0;
    publicKeyBytes[20] = 0;
    publicKeyBytes[21] = 0;
    publicKeyBytes[22] = 0;
    publicKeyBytes[23] = 0;
    publicKeyBytes[24] = 0;
    publicKeyBytes[25] = 0;
    publicKeyBytes[26] = 0;
    publicKeyBytes[27] = 0;
    publicKeyBytes[28] = 0;
    publicKeyBytes[29] = 0;
    publicKeyBytes[30] = 0;
    publicKeyBytes[31] = 0x208;
    gpuHash160_SHA256Initialize(s);
    gpuHash160_SHA256Transform(s, publicKeyBytes);
    gpuHash160_SHA256Transform(s, publicKeyBytes + 16);
    #pragma unroll 8
    for (int i = 0; i < 8; i++)
        s[i] = gpuHash160_bswap32(s[i]);
    *(uint64_t*)(s + 8) = 0x80ULL;
    *(uint64_t*)(s + 10) = 0ULL;
    *(uint64_t*)(s + 12) = 0ULL;
    *(uint64_t*)(s + 14) = static_cast<uint32_t>(gpuHash160_ripemd160_sizedesc_32);
    gpuHash160_RIPEMD160Initialize(hash);
    gpuHash160_RIPEMD160Transform(hash, s);
}
