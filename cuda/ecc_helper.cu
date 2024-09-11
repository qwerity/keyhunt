#include "ecc_helper.cuh"

#include "common.h"
#include "ripemd160.cuh"
#include "sha256.cuh"
#include "ptx.cuh"

#include "hash160_lookup.cuh"
#include "secp256k1.cuh"

__device__ void hashPublicKey(const uint256_t& x, const uint256_t& y, uint *digestOut)
{
    uint256_t hash;
    sha256PublicKey(x, y, hash);
    // Swap to little-endian
    for (int i = 0; i < 8; i++)
    {
        hash[i] = endian(hash[i]);
    }
    ripemd160sha256NoFinal(hash, digestOut);
}

__device__ void hashPublicKeyCompressed(const uint256_t& x, const uint yParity, uint *digestOut)
{
    uint256_t hash;
    sha256PublicKeyCompressed(x, yParity, hash);
    // Swap to little-endian
    for (int i = 0; i < 8; i++)
    {
        hash[i] = endian(hash[i]);
    }
    ripemd160sha256NoFinal(hash, digestOut);
}

__global__ void multiplyStepKernel(const uint256_t *privateKeys)
{
    // 256 is a 256 bit in a private key
    constexpr uint bitsNumber{256};

    uint256_t p;

    uint *xPtr = d_publicKeyXPtr;
    uint *yPtr = d_publicKeyYPtr;

    for (int step{0}; step < bitsNumber; ++step)
    {
        const ecpoint_t& stepGPoint = d_gPointsPtr[step];

        // Multiply together all (_Gx - x) and then invert
        uint256_t inverse{0, 0, 0, 0, 0, 0, 0, 1};
        int batchIdx{0};

        for(uint i = 0; i < d_pointsPerThread; ++i)
        {
            uint256_t x;
            readInt(xPtr, i, x);

            readUInt256(privateKeys, i, p);
            if (const uint bit = p[7 - step / 32] & 1 << (step % 32); bit != 0 && !isInfinity(x))
            {
                beginBatchAddWithDouble(&stepGPoint, x, d_multChainPtr, batchIdx, inverse);
                batchIdx++;
            }
        }

        doBatchInverse(inverse);

        for(int i = d_pointsPerThread - 1; i >= 0; --i)
        {
            readUInt256(privateKeys, i, p);
            if (const uint bit = p[7 - step / 32] & 1 << (step % 32); bit != 0)
            {
                uint256_t newX;
                uint256_t newY;

                uint256_t x;
                readInt(xPtr, i, x);

                if (!isInfinity(x))
                {
                    uint256_t y;
                    readInt(yPtr, i, y);

                    batchIdx--;
                    completeBatchAddWithDouble(&stepGPoint, x, y, batchIdx, d_multChainPtr, inverse, newX, newY);
                }
                else
                {
                    newX = stepGPoint.x;
                    newY = stepGPoint.y;
                }

                writeInt(newX, i, xPtr);
                writeInt(newY, i, yPtr);
            }
        }
    }

    const uint totalThreads = gridDim.x * blockDim.x;
    const uint threadId = blockDim.x * blockIdx.x + threadIdx.x;

    for(uint i = 0; i < d_pointsPerThread; ++i)
    {
        uint256_t x;
        readInt(xPtr, i, x);

        const uint base = i * totalThreads;
        const uint index = base + threadId;
        hash160 hash160;

        if (d_publicKeyCompressionTypeToCheck == PointCompressionType::COMPRESSED || d_publicKeyCompressionTypeToCheck == PointCompressionType::BOTH)
        {
            hashPublicKeyCompressed(x, readIntLSW(yPtr, i), hash160.h);
            if (checkHash(hash160))
            {
                printf("found match %u\n", index);
                // setResultFound(i, true, x, y, digest);
            }
        }
        if (d_publicKeyCompressionTypeToCheck == PointCompressionType::UNCOMPRESSED || d_publicKeyCompressionTypeToCheck == PointCompressionType::BOTH)
        {
            uint256_t y;
            readInt(yPtr, i, y);

            hashPublicKey(x, y, hash160.h);
            if (checkHash(hash160))
            {
                printf("found match %u\n", index);
            }
        }
    }
}
