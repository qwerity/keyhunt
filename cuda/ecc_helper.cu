#include "ecc_helper.cuh"
#include "atomic_list.cuh"
#include "ripemd160.cuh"
#include "sha256.cuh"
#include "ptx.cuh"
#include "hash160_lookup.cuh"
#include "secp256k1.cuh"


__device__ void hashPublicKey(const uint256_t& x, const uint256_t& y, uint32_t *digestOut)
{
    uint256_t hash;
    sha256PublicKey(x, y, hash);

    // Swap to little-endian
    for (uint32_t i = 0; i < 8; ++i)
    {
        hash[i] = endian(hash[i]);
    }
    ripemd160sha256NoFinal(hash, digestOut);
}

__device__ void hashPublicKeyCompressed(const uint256_t& x, const uint32_t yParity, uint32_t *digestOut)
{
    uint256_t hash;
    sha256PublicKeyCompressed(x, yParity, hash);

    // Swap to little-endian
    for (uint32_t i = 0; i < 8; ++i)
    {
        hash[i] = endian(hash[i]);
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

    for (uint32_t i = 0; i < 8; ++i)
    {
        r.privateKey[i] = endian(privateKey[i]);
    }

    for (uint32_t i = 0; i < 8; ++i)
    {
        r.publicXKey[i] = endian(publicX[i]);
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

__global__ void multiplyStepKernel(const uint256_t *privateKeys)
{
    // 256 is a 256 bit in a private key
    constexpr uint32_t bitsNumber{256};

    uint256_t privateKey;

    for (uint32_t step{0}; step < bitsNumber; ++step)
    {
        const ecpoint_t& stepGPoint = d_gPointsPtr[step];

        // Multiply together all (_Gx - x) and then invert
        uint256_t inverse{0, 0, 0, 0, 0, 0, 0, 1};
        int batchIdx{0};

        for(uint32_t i = 0; i < d_pointsPerThread; ++i)
        {
            uint256_t publicX;
            readUInt256(d_publicKeyXPtr, i, publicX);

            readUInt256(privateKeys, i, privateKey);
            if (const uint32_t bit = privateKey[7 - step / 32] & 1 << (step % 32); bit != 0 && !isInfinity(publicX))
            {
                beginBatchAddWithDouble(&stepGPoint, publicX, d_multChainPtr, batchIdx, inverse);
                batchIdx++;
            }
        }

        doBatchInverse(inverse);

        for(int i = d_pointsPerThread - 1; i >= 0; --i)
        {
            readUInt256(privateKeys, i, privateKey);
            if (const uint32_t bit = privateKey[7 - step / 32] & 1 << (step % 32); bit != 0)
            {
                uint256_t newX;
                uint256_t newY;

                uint256_t publicX;
                readUInt256(d_publicKeyXPtr, i, publicX);

                if (!isInfinity(publicX))
                {
                    uint256_t publicY;
                    readUInt256(d_publicKeyYPtr, i, publicY);

                    batchIdx--;
                    completeBatchAddWithDouble(&stepGPoint, publicX, publicY, batchIdx, d_multChainPtr, inverse, newX, newY);
                }
                else
                {
                    newX = stepGPoint.x;
                    newY = stepGPoint.y;
                }

                writeUInt256(newX, i, d_publicKeyXPtr);
                writeUInt256(newY, i, d_publicKeyYPtr);
            }
        }
    }

    const uint32_t totalThreads = gridDim.x * blockDim.x;
    const uint32_t threadId = blockDim.x * blockIdx.x + threadIdx.x;

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
