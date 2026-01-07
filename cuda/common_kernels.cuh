#pragma once

#include "atomic_list.cuh"
#include "ripemd160.cuh"
#include "sha256.cuh"
#include "hash160_lookup.cuh"

#include "defines.h"

__device__ __forceinline__ void hashPublicKey(const uint256_t& x, const uint256_t& y, uint32_t *digestOut)
{
    uint256_t hash;
    sha256PublicKey(x, y, hash);

    // sha256PublicKey возвращает результат в little-endian формате
    // ripemd160sha256 ожидает little-endian формат
    ripemd160sha256(hash.v, digestOut);
}

__device__ __forceinline__ void hashPublicKeyCompressed(const uint256_t& x, const uint32_t yParity, uint32_t *digestOut)
{
    uint256_t hash;
    sha256PublicKeyCompressed(x, yParity, hash);

    // sha256PublicKeyCompressed возвращает результат в little-endian формате
    // ripemd160sha256 ожидает little-endian формат
    ripemd160sha256(hash.v, digestOut);
}

__device__ __forceinline__ void setResultFound(const uint32_t idx, const bool compressed, const uint8_t privateKey[32], const uint32_t digest[5])
{
    Hash160SearchResult r;
    r.block = blockIdx.x;
    r.thread = threadIdx.x;
    r.idx = idx;
    r.compressed = compressed;

    // privateKey приходит в формате secp256k1 (big-endian байты)
    // Конвертируем в uint256_t формат (little-endian слова)
    const uint8_t* src = privateKey;
    for (int i = 0; i < 8; ++i)
    {
        const int byte_idx = 7 - i; // Инвертируем порядок слов
        r.privateKey[i] = (static_cast<uint32_t>(src[byte_idx * 4 + 0]) << 24) |
                         (static_cast<uint32_t>(src[byte_idx * 4 + 1]) << 16) |
                         (static_cast<uint32_t>(src[byte_idx * 4 + 2]) << 8) |
                         (static_cast<uint32_t>(src[byte_idx * 4 + 3]));
    }

    // digest приходит в little-endian формате (из ripemd160sha256)
    // Копируем как есть
    #pragma unroll
    for (uint32_t i = 0; i < 5; ++i)
    {
        r.digest[i] = digest[i];
    }

    atomicListAdd(&r, sizeof(r));
}

__device__ __forceinline__ void setResultFound(const uint32_t idx, const bool compressed, const uint256_t& privateKey, const uint32_t digest[5])
{
    setResultFound(idx, compressed, reinterpret_cast<const uint8_t*>(privateKey.v), digest);
}