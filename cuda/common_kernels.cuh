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

    uint32_t swapped[8];
    #pragma unroll
    for (int j = 0; j < 8; ++j)
    {
        uint32_t x = hash.v[j];
        swapped[j] = (x << 24) | ((x << 8) & 0x00ff0000) | ((x >> 8) & 0x0000ff00) | (x >> 24);
    }

    ripemd160sha256(swapped, digestOut);
}

__device__ __forceinline__ void hashPublicKeyCompressed(const uint256_t& x, const uint32_t yParity, uint32_t *digestOut)
{
    uint256_t hash;
    sha256PublicKeyCompressed(x, yParity, hash);

    uint32_t swapped[8];
    #pragma unroll
    for (int j = 0; j < 8; ++j)
    {
        uint32_t x = hash.v[j];
        swapped[j] = (x << 24) | ((x << 8) & 0x00ff0000) | ((x >> 8) & 0x0000ff00) | (x >> 24);
    }
    
    ripemd160sha256(swapped, digestOut);
}

__device__ __forceinline__ void setResultFound(const uint32_t idx, const bool compressed, const uint8_t privateKey[32], const uint32_t digest[5])
{
    Hash160SearchResult r;
    r.block = blockIdx.x;
    r.thread = threadIdx.x;
    r.idx = idx;
    r.compressed = compressed;

    const uint8_t* src = privateKey;
    for (int i = 0; i < 8; ++i)
    {
        const int byte_idx = 7 - i;
        r.privateKey[i] = (static_cast<uint32_t>(src[byte_idx * 4 + 0]) << 24) |
                         (static_cast<uint32_t>(src[byte_idx * 4 + 1]) << 16) |
                         (static_cast<uint32_t>(src[byte_idx * 4 + 2]) << 8) |
                         (static_cast<uint32_t>(src[byte_idx * 4 + 3]));
    }

    #pragma unroll
    for (uint32_t i = 0; i < 5; ++i)
    {
        r.digest[i] = digest[i];
    }

    // Inline atomic add + copy to avoid atomicListAdd (70 regs) in fused kernel call tree
    const uint32_t slot = atomicAdd(d_atomicListSize[0], 1);
    uint8_t* const ptr = static_cast<uint8_t*>(d_atomicListBuf[0]) + slot * sizeof(Hash160SearchResult);
    constexpr uint32_t n = sizeof(Hash160SearchResult) / sizeof(uint32_t);
    const uint32_t* rWords = reinterpret_cast<const uint32_t*>(&r);
    uint32_t* dst = reinterpret_cast<uint32_t*>(ptr);
#pragma unroll
    for (uint32_t i = 0; i < n; ++i)
        dst[i] = rWords[i];
}

__device__ __forceinline__ void setResultFound(const uint32_t idx, const bool compressed, const uint256_t& privateKey, const uint32_t digest[5])
{
    setResultFound(idx, compressed, reinterpret_cast<const uint8_t*>(privateKey.v), digest);
}