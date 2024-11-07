#pragma once

#include "atomic_list.cuh"
#include "ripemd160.cuh"
#include "sha256.cuh"
#include "utils.cuh"
#include "hash160_lookup.cuh"

#include "util/common.h"

__device__ __forceinline__ void hashPublicKey(const uint256_t& x, const uint256_t& y, uint32_t *digestOut)
{
    uint256_t hash;
    sha256PublicKey(x, y, hash);

    // Swap to little-endian
    #pragma unroll
    for (uint32_t i = 0; i < 8; ++i)
    {
        hash[i] = SWAP32(hash[i]);
    }
    ripemd160sha256NoFinal(hash, digestOut);
}

__device__ __forceinline__ void hashPublicKeyCompressed(const uint256_t& x, const uint32_t yParity, uint32_t *digestOut)
{
    uint256_t hash;
    sha256PublicKeyCompressed(x, yParity, hash);

    // Swap to little-endian
    #pragma unroll
    for (uint32_t i = 0; i < 8; ++i)
    {
        hash[i] = SWAP32(hash[i]);
    }
    ripemd160sha256NoFinal(hash, digestOut);
}

__device__ __forceinline__ void setResultFound(const uint32_t idx, const bool compressed, const uint8_t privateKey[32], const uint32_t digest[5])
{
    Hash160SearchResult r;
    r.block = blockIdx.x;
    r.thread = threadIdx.x;
    r.idx = idx;
    r.compressed = compressed;

    auto* privateKeyU = reinterpret_cast<const uint32_t*>(privateKey);

    #pragma unroll
    for (uint32_t i = 0; i < 8; ++i)
    {
        r.privateKey[i] = SWAP32(privateKeyU[i]);
    }
    doRMD160FinalRound(digest, r.digest);

    atomicListAdd(&r, sizeof(r));
}

__device__ __forceinline__ void setResultFound(const uint32_t idx, const bool compressed, const uint256_t& privateKey, const uint32_t digest[5])
{
    setResultFound(idx, compressed, reinterpret_cast<const uint8_t*>(privateKey.v), digest);
}