#include "ecc_helper.cuh"
#include "ripemd160.cuh"
#include "sha256.cuh"
#include "ptx.cuh"

#include "hash160_lookup.cuh"
#include "secp256k1.cuh"

__device__ void hashPublicKey(const uint32_t *x, const uint32_t *y, uint32_t *digestOut)
{
    uint32_t hash[8];
    sha256PublicKey(x, y, hash);
    // Swap to little-endian
    for (int i = 0; i < 8; i++)
    {
        hash[i] = endian(hash[i]);
    }
    ripemd160sha256NoFinal(hash, digestOut);
}

__device__ void hashPublicKeyCompressed(const uint32_t *x, const uint32_t yParity, uint32_t *digestOut)
{
    uint32_t hash[8];
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
    constexpr uint32_t bitsNumber{256};

    uint32_t p[8]{};

    uint32_t *xPtr = d_publicKeyXPtr;
    uint32_t *yPtr = d_publicKeyYPtr;

    for (int step{0}; step < bitsNumber; ++step)
    {
        const ecpoint_t& stepGPoint = d_gPointsPtr[step];

        // Multiply together all (_Gx - x) and then invert
        uint32_t inverse[8]{0, 0, 0, 0, 0, 0, 0, 1};
        int batchIdx{0};

        for(uint32_t i = 0; i < d_pointsPerThread; ++i)
        {
            uint32_t x[8];
            readInt(xPtr, i, x);

            readUInt256(privateKeys, i, p);
            if (const uint32_t bit = p[7 - step / 32] & 1 << (step % 32); bit != 0 && !isInfinity(x))
            {
                beginBatchAddWithDouble(&stepGPoint, x, d_multChainPtr, batchIdx, inverse);
                batchIdx++;
            }
        }

        doBatchInverse(inverse);

        for(int i = d_pointsPerThread - 1; i >= 0; --i)
        {
            readUInt256(privateKeys, i, p);
            if (const uint32_t bit = p[7 - step / 32] & 1 << (step % 32); bit != 0)
            {
                uint32_t newX[8];
                uint32_t newY[8];

                uint32_t x[8];
                readInt(xPtr, i, x);

                if (!isInfinity(x))
                {
                    uint32_t y[8];
                    readInt(yPtr, i, y);

                    batchIdx--;
                    completeBatchAddWithDouble(&stepGPoint, x, y, batchIdx, d_multChainPtr, inverse, newX, newY);
                }
                else
                {
                    copyBigInt(stepGPoint.x, newX);
                    copyBigInt(stepGPoint.y, newY);
                }

                writeInt(newX, i, xPtr);
                writeInt(newY, i, yPtr);
            }
        }
    }

    for(uint32_t i = 0; i < d_pointsPerThread; ++i)
    {
        readUInt256(privateKeys, i, p);
        uint32_t x[8];
        readInt(xPtr, i, x);

        hash160 hash160Compressed;
        hashPublicKeyCompressed(x, readIntLSW(yPtr, i), hash160Compressed.h);
        if (checkHash(hash160Compressed))
        {
            const uint32_t totalThreads = gridDim.x * blockDim.x;
            const uint32_t base = i * totalThreads;
            const uint32_t threadId = blockDim.x * blockIdx.x + threadIdx.x;
            const uint32_t index = base + threadId;
            printf("found match %u\n", index);
            // setResultFound(i, true, x, y, digest);
        }

        // uint32_t hash160[5];
        // hashPublicKey(newX, newY, hash160);
    }
}
