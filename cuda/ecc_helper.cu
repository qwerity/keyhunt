#include "ecc_helper.cuh"
#include "atomic_list.cuh"
#include "ripemd160.cuh"
#include "sha256.cuh"
#include "ptx.cuh"
#include "hash160_lookup.cuh"

#include "secp256k1_v2/bip32.cuh"

#include "util/common.h"

// Check public key hash160 compressed/uncompressed/both
__constant__ int d_publicKeyCompressionTypeToCheck{PointCompressionType::BOTH};


__device__ void hashPublicKey(const uint256_t& x, const uint256_t& y, uint32_t *digestOut)
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

__device__ void hashPublicKeyCompressed(const uint256_t& x, const uint32_t yParity, uint32_t *digestOut)
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

__device__ void setResultFound(const uint32_t idx, const bool compressed, const uint256_t& privateKey, const uint256_t& publicX, const uint32_t digest[5])
{
    Hash160SearchResult r;
    r.block = blockIdx.x;
    r.thread = threadIdx.x;
    r.idx = idx;
    r.compressed = compressed;

    #pragma unroll
    for (uint32_t i = 0; i < 8; ++i)
    {
        r.privateKey[i] = SWAP32(privateKey[i]);
        r.publicXKey[i] = SWAP32(publicX[i]);
    }
    doRMD160FinalRound(digest, r.digest);

    atomicListAdd(&r, sizeof(r));
}

__device__ void print(uint256_t& x, uint32_t step, uint32_t idx, char op)
{
    if (idx != 0)
        return;

    printf("op: %c step: %u, idx: %u, x: ", op, step, idx);
    for (size_t i = 0; i < 8; ++i)
    {
        // Print the 4 bytes of each uint32_t directly
        printf("%02x %02x %02x %02x ",
               (x[i] & 0x000000FF),        // Least significant byte
               (x[i] & 0x0000FF00) >> 8,   // Second byte
               (x[i] & 0x00FF0000) >> 16,  // Third byte
               (x[i] & 0xFF000000) >> 24   // Most significant byte
        );
    }
    printf("\n");
}

__global__ void checkHashKernel(const uint256_t *privateKeys)
{
    const uint32_t totalThreads = gridDim.x * blockDim.x;
    const uint32_t threadId = blockDim.x * blockIdx.x + threadIdx.x;

    uint256_t privateKey;

    #pragma unroll
    for(uint32_t i = 0; i < d_pointsPerThread; ++i)
    {
        readUInt256(privateKeys, i, privateKey);

        uint256_t publicX;
        readUInt256(d_publicKeyXPtr, i, publicX);

        const uint32_t base = i * totalThreads;
        const uint32_t index = base + threadId;
        hash160 hash160;

        if (d_publicKeyCompressionTypeToCheck == PointCompressionType::COMPRESSED || d_publicKeyCompressionTypeToCheck == PointCompressionType::BOTH)
        {
            hashPublicKeyCompressed(publicX, readUInt256LSW(d_publicKeyYPtr, i), hash160.h);
            if (checkHash(hash160))
            {
                setResultFound(index, true, privateKey, publicX, hash160.h);
            }
        }

        if (d_publicKeyCompressionTypeToCheck == PointCompressionType::UNCOMPRESSED || d_publicKeyCompressionTypeToCheck == PointCompressionType::BOTH)
        {
            uint256_t publicY;
            readUInt256(d_publicKeyYPtr, i, publicY);

            hashPublicKey(publicX, publicY, hash160.h);
            if (checkHash(hash160))
            {
                setResultFound(index, false, privateKey, publicX, hash160.h);
            }
        }
    }
}

__global__ void publicKeyGenerationKernel(const uint256_t *privateKeys)
{
    for(uint32_t i = 0; i < d_pointsPerThread; ++i)
    {
        extended_private_key_t privateExKey;
        extended_public_key_t publicEXKey;

        auto* privateKey = reinterpret_cast<uint256_t*>(privateExKey.key);
        readUInt256(privateKeys, i, *privateKey);

        /// TODO: optimize this
        for (uint32_t j = 0; j < 8; ++j)
        {
            privateKey->v[j] = SWAP32(privateKey->v[j]);
        }
        generatePublicFromPrivateKey(&privateExKey, &publicEXKey);

        auto* newX = reinterpret_cast<uint256_t*>(publicEXKey.key);
        auto* newY = reinterpret_cast<uint256_t*>(publicEXKey.key + 32);

        for (uint32_t j = 0; j < 8; ++j)
        {
            newX->v[j] = SWAP32(newX->v[j]);
            newY->v[j] = SWAP32(newY->v[j]);
        }

        writeUInt256(*newX, i, d_publicKeyXPtr);
        writeUInt256(*newY, i, d_publicKeyYPtr);
    }
}
