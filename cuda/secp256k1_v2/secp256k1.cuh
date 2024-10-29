#pragma once

#include "bip32.cuh"

#include <cuda_runtime.h>
#include <cstdint>

struct secp256k1_fe
{
    uint32_t n[10]{};
};

struct secp256k1_scalar
{
    uint32_t d[8]{};
};

struct secp256k1_ge
{
    secp256k1_fe x;
    secp256k1_fe y;
    int infinity{0};
};

struct secp256k1_gej
{
    secp256k1_fe x;
    secp256k1_fe y;
    secp256k1_fe z;
    int infinity{0};
};

struct secp256k1_fe_storage
{
    uint32_t n[8]{};
};

struct secp256k1_ge_storage
{
    secp256k1_fe_storage x;
    secp256k1_fe_storage y;
};


__device__ int secp256k1_ec_pubkey_create(uint8_t* pubkey, const uint8_t* seckey);
__device__ void secp256k1_pubkey_save(uint8_t* pubkey, secp256k1_ge* ge);
__device__ void secp256k1_fe_get_b32(uint8_t* r, const secp256k1_fe* a);
__device__ void secp256k1_ge_set_gej(secp256k1_ge* r, secp256k1_gej* a);
__device__ void secp256k1_fe_normalize_var(secp256k1_fe* r);
__device__ void secp256k1_fe_inv(secp256k1_fe* r, const secp256k1_fe* a);
__device__ void secp256k1_fe_set_int(secp256k1_fe* r, int a);
__device__ void secp256k1_fe_mul(secp256k1_fe* r, const secp256k1_fe* a, const secp256k1_fe* b);
__device__ void secp256k1_fe_mul_inner(uint32_t* r, const uint32_t* a, const uint32_t* b);
__device__ void secp256k1_fe_sqr(secp256k1_fe* r, const secp256k1_fe* a);
__device__ void secp256k1_fe_sqr_inner(uint32_t* r, const uint32_t* a);
__device__ void secp256k1_scalar_cmov(secp256k1_scalar* r, const secp256k1_scalar* a, int flag);
__device__ void secp256k1_ge_clear(secp256k1_ge* r);
__device__ void secp256k1_gej_add_ge(secp256k1_gej* r, const secp256k1_gej* a, const secp256k1_ge* b);
__device__ void secp256k1_ecmult_gen(secp256k1_gej* r, secp256k1_scalar* gn);
__device__ void secp256k1_ge_from_storage(secp256k1_ge* r, const secp256k1_ge_storage* a);
__device__ void secp256k1_fe_from_storage(secp256k1_fe* r, const secp256k1_fe_storage* a);
__device__ void secp256k1_gej_set_infinity(secp256k1_gej* r);
__device__ uint32_t secp256k1_scalar_get_bits(const secp256k1_scalar* a, uint32_t offset, uint32_t count);
__device__ void secp256k1_fe_clear(secp256k1_fe* a);
__device__ int secp256k1_scalar_set_b32_seckey(secp256k1_scalar* r, const uint8_t* bin);
__device__ int secp256k1_scalar_is_zero(const secp256k1_scalar* a);
__device__ void secp256k1_scalar_set_b32(secp256k1_scalar* r, const uint8_t* b32, int* overflow);
__device__ int secp256k1_scalar_check_overflow(const secp256k1_scalar* a);
__device__ int secp256k1_scalar_reduce(secp256k1_scalar* r, int overflow);
__device__ void secp256k1_fe_cmov(secp256k1_fe* r, const secp256k1_fe* a, int flag);
__device__ void secp256k1_fe_mul_int(secp256k1_fe* r, int a);
__device__ int secp256k1_fe_normalizes_to_zero(secp256k1_fe* r);
__device__ void secp256k1_fe_negate(secp256k1_fe* r, const secp256k1_fe* a, int m);
__device__ void secp256k1_fe_add(secp256k1_fe* r, const secp256k1_fe* a);
__device__ void secp256k1_fe_normalize_weak(secp256k1_fe* r);
__device__ int secp256k1_fe_set_b32(secp256k1_fe* r, const uint8_t* a);
__device__ void secp256k1_ge_set_xy(secp256k1_ge* r, const secp256k1_fe* x, const secp256k1_fe* y);
__device__ int secp256k1_pubkey_load(secp256k1_ge* ge, const uint8_t* pubkey);
__device__ bool secp256k1_ge_is_infinity(const secp256k1_ge* a);
__device__ bool secp256k1_fe_is_odd(const secp256k1_fe* a);
__device__ int secp256k1_eckey_pubkey_serialize(secp256k1_ge* elem, uint8_t* pub);
__device__ int secp256k1_ec_pubkey_serialize(uint8_t* output, uint32_t outputLen, const uint8_t* pubkey);
__device__ void serialized_public_key(extended_public_key_t* pub, uint8_t* serialized_key);
__device__ int secp256k1_scalar_add(secp256k1_scalar* r, const secp256k1_scalar* a, const secp256k1_scalar* b);
__device__ int secp256k1_eckey_privkey_tweak_add(secp256k1_scalar* key, const secp256k1_scalar* tweak);
__device__ void secp256k1_scalar_get_b32(uint8_t* bin, const secp256k1_scalar* a);
__device__ int secp256k1_ec_seckey_tweak_add(uint8_t* seckey, const uint8_t* tweak);