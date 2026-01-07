#pragma once

#include "secp256k1_defines.cuh"
#include "bip32.cuh"
#include "../defines.h"


__device__ __forceinline__ int secp256k1_scalar_is_zero(const secp256k1_scalar* a)
{
    const auto* vec = reinterpret_cast<const uint4*>(a->d);
    return ((vec[0].x | vec[0].y | vec[0].z | vec[0].w) |
            (vec[1].x | vec[1].y | vec[1].z | vec[1].w)) == 0;
}

__device__ __forceinline__ void secp256k1_fe_cmov(secp256k1_fe* r, const secp256k1_fe* a, int flag)
{
    uint32_t mask0 = flag + ~0u;
    uint32_t mask1 = ~mask0;
    r->n[0] = (r->n[0] & mask0) | (a->n[0] & mask1);
    r->n[1] = (r->n[1] & mask0) | (a->n[1] & mask1);
    r->n[2] = (r->n[2] & mask0) | (a->n[2] & mask1);
    r->n[3] = (r->n[3] & mask0) | (a->n[3] & mask1);
    r->n[4] = (r->n[4] & mask0) | (a->n[4] & mask1);
    r->n[5] = (r->n[5] & mask0) | (a->n[5] & mask1);
    r->n[6] = (r->n[6] & mask0) | (a->n[6] & mask1);
    r->n[7] = (r->n[7] & mask0) | (a->n[7] & mask1);
    r->n[8] = (r->n[8] & mask0) | (a->n[8] & mask1);
    r->n[9] = (r->n[9] & mask0) | (a->n[9] & mask1);
}

__device__ __forceinline__ int secp256k1_scalar_reduce(secp256k1_scalar* r, int overflow)
{
    uint64_t t = static_cast<uint64_t>(r->d[0]) + overflow * SECP256K1_N_C_0;
    r->d[0] = t & 0xFFFFFFFFUL;
    t >>= 32;
    t += static_cast<uint64_t>(r->d[1]) + overflow * SECP256K1_N_C_1;
    r->d[1] = t & 0xFFFFFFFFUL;
    t >>= 32;
    t += static_cast<uint64_t>(r->d[2]) + overflow * SECP256K1_N_C_2;
    r->d[2] = t & 0xFFFFFFFFUL;
    t >>= 32;
    t += static_cast<uint64_t>(r->d[3]) + overflow * SECP256K1_N_C_3;
    r->d[3] = t & 0xFFFFFFFFUL;
    t >>= 32;
    t += static_cast<uint64_t>(r->d[4]) + overflow * SECP256K1_N_C_4;
    r->d[4] = t & 0xFFFFFFFFUL;
    t >>= 32;
    t += static_cast<uint64_t>(r->d[5]);
    r->d[5] = t & 0xFFFFFFFFUL;
    t >>= 32;
    t += static_cast<uint64_t>(r->d[6]);
    r->d[6] = t & 0xFFFFFFFFUL;
    t >>= 32;
    t += static_cast<uint64_t>(r->d[7]);
    r->d[7] = t & 0xFFFFFFFFUL;
    return overflow;
}

__device__ __forceinline__ int secp256k1_scalar_check_overflow(const secp256k1_scalar* a)
{
    int yes = 0;
    int no = 0;

    no  |= (a->d[7] < SECP256K1_N_7); /* No need for a > check. */
    no  |= (a->d[6] < SECP256K1_N_6); /* No need for a > check. */
    no  |= (a->d[5] < SECP256K1_N_5); /* No need for a > check. */
    no  |= (a->d[4] < SECP256K1_N_4);
    yes |= (a->d[4] > SECP256K1_N_4) & ~no;
    no  |= (a->d[3] < SECP256K1_N_3) & ~yes;
    yes |= (a->d[3] > SECP256K1_N_3) & ~no;
    no  |= (a->d[2] < SECP256K1_N_2) & ~yes;
    yes |= (a->d[2] > SECP256K1_N_2) & ~no;
    no  |= (a->d[1] < SECP256K1_N_1) & ~yes;
    yes |= (a->d[1] > SECP256K1_N_1) & ~no;
    yes |= (a->d[0] >= SECP256K1_N_0) & ~no;
    return yes;
}

__device__ __forceinline__ void secp256k1_scalar_cmov(secp256k1_scalar* r, const secp256k1_scalar* a, int flag)
{
    uint32_t mask0 = flag + ~0u;
    uint32_t mask1 = ~mask0;
    r->d[0] = (r->d[0] & mask0) | (a->d[0] & mask1);
    r->d[1] = (r->d[1] & mask0) | (a->d[1] & mask1);
    r->d[2] = (r->d[2] & mask0) | (a->d[2] & mask1);
    r->d[3] = (r->d[3] & mask0) | (a->d[3] & mask1);
    r->d[4] = (r->d[4] & mask0) | (a->d[4] & mask1);
    r->d[5] = (r->d[5] & mask0) | (a->d[5] & mask1);
    r->d[6] = (r->d[6] & mask0) | (a->d[6] & mask1);
    r->d[7] = (r->d[7] & mask0) | (a->d[7] & mask1);
}

__device__ __forceinline__ int secp256k1_fe_set_b32(secp256k1_fe* r, const uint8_t* a)
{
    r->n[0] = static_cast<uint32_t>(a[31])                | (static_cast<uint32_t>(a[30]) << 8) | (static_cast<uint32_t>(a[29]) << 16) | (static_cast<uint32_t>(a[28] & 0x3) << 24);
    r->n[1] = static_cast<uint32_t>((a[28] >> 2) & 0x3f)  | (static_cast<uint32_t>(a[27]) << 6) | (static_cast<uint32_t>(a[26]) << 14) | (static_cast<uint32_t>(a[25] & 0xf) << 22);
    r->n[2] = static_cast<uint32_t>((a[25] >> 4) & 0xf)   | (static_cast<uint32_t>(a[24]) << 4) | (static_cast<uint32_t>(a[23]) << 12) | (static_cast<uint32_t>(a[22] & 0x3f) << 20);
    r->n[3] = static_cast<uint32_t>((a[22] >> 6) & 0x3)   | (static_cast<uint32_t>(a[21]) << 2) | (static_cast<uint32_t>(a[20]) << 10) | (static_cast<uint32_t>(a[19]) << 18);
    r->n[4] = static_cast<uint32_t>(a[18])                | (static_cast<uint32_t>(a[17]) << 8) | (static_cast<uint32_t>(a[16]) << 16) | (static_cast<uint32_t>(a[15] & 0x3) << 24);
    r->n[5] = static_cast<uint32_t>((a[15] >> 2) & 0x3f)  | (static_cast<uint32_t>(a[14]) << 6) | (static_cast<uint32_t>(a[13]) << 14) | (static_cast<uint32_t>(a[12] & 0xf) << 22);
    r->n[6] = static_cast<uint32_t>((a[12] >> 4) & 0xf)   | (static_cast<uint32_t>(a[11]) << 4) | (static_cast<uint32_t>(a[10]) << 12) | (static_cast<uint32_t>(a[9] & 0x3f) << 20);
    r->n[7] = static_cast<uint32_t>((a[9] >> 6) & 0x3)    | (static_cast<uint32_t>(a[8]) << 2)  | (static_cast<uint32_t>(a[7]) << 10)  | (static_cast<uint32_t>(a[6]) << 18);
    r->n[8] = static_cast<uint32_t>(a[5])                 | (static_cast<uint32_t>(a[4]) << 8)  | (static_cast<uint32_t>(a[3]) << 16)  | (static_cast<uint32_t>(a[2] & 0x3) << 24);
    r->n[9] = static_cast<uint32_t>((a[2] >> 2) & 0x3f)   | (static_cast<uint32_t>(a[1]) << 6)  | (static_cast<uint32_t>(a[0]) << 14);

    return !((r->n[9] == 0x3FFFFFUL) & ((r->n[8] & r->n[7] & r->n[6] & r->n[5] & r->n[4] & r->n[3] & r->n[2]) == 0x3FFFFFFUL) & ((r->n[1] + 0x40UL + ((r->n[0] + 0x3D1UL) >> 26)) > 0x3FFFFFFUL));
}

__device__ __forceinline__ void secp256k1_ge_set_xy(secp256k1_ge* r, const secp256k1_fe* x, const secp256k1_fe* y)
{
    r->infinity = 0;
    r->x = *x;
    r->y = *y;
}

__device__ void secp256k1_pubkey_load(secp256k1_ge* ge, const uint8_t* pubkey);

__device__ __forceinline__ bool secp256k1_ge_is_infinity(const secp256k1_ge* a)
{
    return a->infinity;
}

__device__ __forceinline__ bool secp256k1_fe_is_odd(const secp256k1_fe* a)
{
    return a->n[0] & 1u;
}

__device__ void secp256k1_fe_normalize_var(secp256k1_fe* r);

__device__ __forceinline__ void secp256k1_fe_get_b32(uint8_t* r, const secp256k1_fe* a)
{
    r[0] = (a->n[9] >> 14) & 0xff;
    r[1] = (a->n[9] >> 6) & 0xff;
    r[2] = ((a->n[9] & 0x3F) << 2) | ((a->n[8] >> 24) & 0x3);
    r[3] = (a->n[8] >> 16) & 0xff;
    r[4] = (a->n[8] >> 8) & 0xff;
    r[5] = a->n[8] & 0xff;
    r[6] = (a->n[7] >> 18) & 0xff;
    r[7] = (a->n[7] >> 10) & 0xff;
    r[8] = (a->n[7] >> 2) & 0xff;
    r[9] = ((a->n[7] & 0x3) << 6) | ((a->n[6] >> 20) & 0x3f);
    r[10] = (a->n[6] >> 12) & 0xff;
    r[11] = (a->n[6] >> 4) & 0xff;
    r[12] = ((a->n[6] & 0xf) << 4) | ((a->n[5] >> 22) & 0xf);
    r[13] = (a->n[5] >> 14) & 0xff;
    r[14] = (a->n[5] >> 6) & 0xff;
    r[15] = ((a->n[5] & 0x3f) << 2) | ((a->n[4] >> 24) & 0x3);
    r[16] = (a->n[4] >> 16) & 0xff;
    r[17] = (a->n[4] >> 8) & 0xff;
    r[18] = a->n[4] & 0xff;
    r[19] = (a->n[3] >> 18) & 0xff;
    r[20] = (a->n[3] >> 10) & 0xff;
    r[21] = (a->n[3] >> 2) & 0xff;
    r[22] = ((a->n[3] & 0x3) << 6) | ((a->n[2] >> 20) & 0x3f);
    r[23] = (a->n[2] >> 12) & 0xff;
    r[24] = (a->n[2] >> 4) & 0xff;
    r[25] = ((a->n[2] & 0xf) << 4) | ((a->n[1] >> 22) & 0xf);
    r[26] = (a->n[1] >> 14) & 0xff;
    r[27] = (a->n[1] >> 6) & 0xff;
    r[28] = ((a->n[1] & 0x3f) << 2) | ((a->n[0] >> 24) & 0x3);
    r[29] = (a->n[0] >> 16) & 0xff;
    r[30] = (a->n[0] >> 8) & 0xff;
    r[31] = a->n[0] & 0xff;
}

__device__ void secp256k1_scalar_set_b32(secp256k1_scalar* r, const uint8_t* b32, int* overflow);
__device__ int secp256k1_scalar_set_b32_seckey(secp256k1_scalar* r, const uint8_t* bin);
__device__ int secp256k1_ec_compressed_pubkey_serialize(uint8_t* output, uint32_t outputLen, const uint8_t* pubkey);

__device__ __forceinline__ void serialized_compressed_public_key(const HDExtendedPublicKey* pub, uint8_t* serialized_key)
{
    secp256k1_ec_compressed_pubkey_serialize(serialized_key, 33, pub->key);
}

__device__ int secp256k1_scalar_add(secp256k1_scalar* r, const secp256k1_scalar* a, const secp256k1_scalar* b);

__device__ int secp256k1_eckey_privkey_tweak_add(secp256k1_scalar* key, const secp256k1_scalar* tweak);

__device__ __forceinline__ void secp256k1_scalar_get_b32(uint8_t* bin, const secp256k1_scalar* a)
{
    auto* out = reinterpret_cast<uint32_t*>(bin);
    out[0] = SWAP32(a->d[7]);
    out[1] = SWAP32(a->d[6]);
    out[2] = SWAP32(a->d[5]);
    out[3] = SWAP32(a->d[4]);
    out[4] = SWAP32(a->d[3]);
    out[5] = SWAP32(a->d[2]);
    out[6] = SWAP32(a->d[1]);
    out[7] = SWAP32(a->d[0]);
}

__device__ int secp256k1_ec_seckey_tweak_add(uint8_t* seckey, const uint8_t* tweak);

__device__ __forceinline__ void secp256k1_fe_clear(secp256k1_fe* a)
{
    auto* vec = reinterpret_cast<uint4*>(a->n);
    vec[0] = {};
    vec[1] = {};
    a->n[8] = 0;
    a->n[9] = 0;
}

__device__ __forceinline__ uint32_t secp256k1_scalar_get_bits(const secp256k1_scalar* a, uint32_t offset, uint32_t count)
{
    return (a->d[offset >> 5] >> (offset & 0x1F)) & ((1 << count) - 1);
}

__device__ __forceinline__ void secp256k1_gej_set_infinity(secp256k1_gej* r)
{
    r->infinity = 1;
    secp256k1_fe_clear(&r->x);
    secp256k1_fe_clear(&r->y);
    secp256k1_fe_clear(&r->z);
}

__device__ __forceinline__ void secp256k1_fe_from_storage(secp256k1_fe* r, const secp256k1_fe_storage* a)
{
    // Используем __ldg() для read-only memory - ускоряет доступ через read-only cache
    const uint32_t n0 = __ldg(&a->n[0]);
    const uint32_t n1 = __ldg(&a->n[1]);
    const uint32_t n2 = __ldg(&a->n[2]);
    const uint32_t n3 = __ldg(&a->n[3]);
    const uint32_t n4 = __ldg(&a->n[4]);
    const uint32_t n5 = __ldg(&a->n[5]);
    const uint32_t n6 = __ldg(&a->n[6]);
    const uint32_t n7 = __ldg(&a->n[7]);
    
    r->n[0] = n0 & 0x3FFFFFFUL;
    r->n[1] = n0 >> 26 | ((n1 << 6) & 0x3FFFFFFUL);
    r->n[2] = n1 >> 20 | ((n2 << 12) & 0x3FFFFFFUL);
    r->n[3] = n2 >> 14 | ((n3 << 18) & 0x3FFFFFFUL);
    r->n[4] = n3 >> 8 | ((n4 << 24) & 0x3FFFFFFUL);
    r->n[5] = (n4 >> 2) & 0x3FFFFFFUL;
    r->n[6] = n4 >> 28 | ((n5 << 4) & 0x3FFFFFFUL);
    r->n[7] = n5 >> 22 | ((n6 << 10) & 0x3FFFFFFUL);
    r->n[8] = n6 >> 16 | ((n7 << 16) & 0x3FFFFFFUL);
    r->n[9] = n7 >> 10;
}

__device__ __forceinline__ void secp256k1_ge_from_storage(secp256k1_ge* r, const secp256k1_ge_storage* a)
{
    secp256k1_fe_from_storage(&r->x, &a->x);
    secp256k1_fe_from_storage(&r->y, &a->y);
    r->infinity = 0;
}

__device__ void secp256k1_fe_normalize_weak(secp256k1_fe* r);

__device__ __forceinline__ void secp256k1_fe_add(secp256k1_fe* r, const secp256k1_fe* a)
{
    r->n[0] += a->n[0];
    r->n[1] += a->n[1];
    r->n[2] += a->n[2];
    r->n[3] += a->n[3];
    r->n[4] += a->n[4];
    r->n[5] += a->n[5];
    r->n[6] += a->n[6];
    r->n[7] += a->n[7];
    r->n[8] += a->n[8];
    r->n[9] += a->n[9];
}

__device__ __forceinline__ void secp256k1_fe_negate(secp256k1_fe* r, const secp256k1_fe* a, int m)
{
    r->n[0] = 0x3FFFC2FUL * 2 * (m + 1) - a->n[0];
    r->n[1] = 0x3FFFFBFUL * 2 * (m + 1) - a->n[1];
    r->n[2] = 0x3FFFFFFUL * 2 * (m + 1) - a->n[2];
    r->n[3] = 0x3FFFFFFUL * 2 * (m + 1) - a->n[3];
    r->n[4] = 0x3FFFFFFUL * 2 * (m + 1) - a->n[4];
    r->n[5] = 0x3FFFFFFUL * 2 * (m + 1) - a->n[5];
    r->n[6] = 0x3FFFFFFUL * 2 * (m + 1) - a->n[6];
    r->n[7] = 0x3FFFFFFUL * 2 * (m + 1) - a->n[7];
    r->n[8] = 0x3FFFFFFUL * 2 * (m + 1) - a->n[8];
    r->n[9] = 0x03FFFFFUL * 2 * (m + 1) - a->n[9];
}

__device__ int secp256k1_fe_normalizes_to_zero(secp256k1_fe* r);

__device__ __forceinline__ void secp256k1_fe_mul_int(secp256k1_fe* r, int a)
{
    r->n[0] *= a;
    r->n[1] *= a;
    r->n[2] *= a;
    r->n[3] *= a;
    r->n[4] *= a;
    r->n[5] *= a;
    r->n[6] *= a;
    r->n[7] *= a;
    r->n[8] *= a;
    r->n[9] *= a;
}

__device__ __forceinline__ void secp256k1_ge_clear(secp256k1_ge* r)
{
    r->infinity = 0;
    secp256k1_fe_clear(&r->x);
    secp256k1_fe_clear(&r->y);
}

__device__ void secp256k1_fe_sqr_inner(uint32_t* r, const uint32_t* a);
__device__ void secp256k1_fe_sqr(secp256k1_fe* r, const secp256k1_fe* a);
__device__ void secp256k1_fe_mul(secp256k1_fe* r, const secp256k1_fe* a, const secp256k1_fe* b);

__device__ __forceinline__ void secp256k1_fe_set_int(secp256k1_fe* r, int a)
{
    r->n[0] = a;
    r->n[1] = r->n[2] = r->n[3] = r->n[4] = r->n[5] = r->n[6] = r->n[7] = r->n[8] = r->n[9] = 0;
}

__device__ void secp256k1_fe_inv(secp256k1_fe* r, const secp256k1_fe* a);
/**
 * Batch inversion using Montgomery's trick
 * Computes inverses of multiple field elements efficiently.
 * @param results Output array for inverses
 * @param inputs Input array of field elements to invert
 * @param count Number of elements to invert (must be > 0, max 16 for current implementation)
 */
__device__ void secp256k1_fe_batch_inv(secp256k1_fe* results, const secp256k1_fe* inputs, int count);
__device__ void secp256k1_ge_set_gej(secp256k1_ge* r, secp256k1_gej* a);
/**
 * Batch version of secp256k1_ge_set_gej using batch inversion optimization
 * Normalizes multiple points from Jacobian to affine coordinates efficiently.
 * @param results Output array of affine points
 * @param points Input array of points in Jacobian coordinates
 * @param count Number of points to normalize (must be > 0, max 16 for current implementation)
 */
__device__ void secp256k1_ge_set_gej_batch(secp256k1_ge* results, secp256k1_gej* points, int count);
__device__ void secp256k1_gej_add_ge(secp256k1_gej* r, const secp256k1_gej* a, const secp256k1_ge* b);
__device__ void secp256k1_pubkey_save(uint8_t* pubkey, secp256k1_ge* ge);
// Глобальная переменная для таблицы (устанавливается из host кода)
extern __device__ const secp256k1_ge_storage* d_gTable_ptr;

__device__ void secp256k1_ecmult_gen(secp256k1_gej* r, secp256k1_scalar* gn);
__device__ int secp256k1_ec_pubkey_create(uint8_t* pubkey, const uint8_t* seckey);
/**
 * Version of secp256k1_ec_pubkey_create that returns point in Jacobian coordinates
 * (without normalization). Useful for batch normalization optimization.
 */
__device__ int secp256k1_ec_pubkey_create_gej(secp256k1_gej* pj, const uint8_t* seckey);
