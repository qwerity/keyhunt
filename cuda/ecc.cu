#include <cuda_runtime.h>
#include <thrust/host_vector.h>

#include "ecc.cuh"

#include "secp256k1.cuh"
// #include "defines.cuh"
#include "functors.cuh"

#include "common.h"
#include "cuda_util.h"

__global__ void multiplyStepKernel(const uint32_t *privateKeys);

__constant__ uint32_t d_pointsPerThread{};

__constant__ uint32_t *d_publicKeyXPtr{};
__constant__ uint32_t *d_publicKeyYPtr{};
__constant__ uint32_t *d_multChainPtr{};
__constant__ uint32_t* d_gPointsPtr;

struct ECC::Impl
{
    uint32_t mGridSize{32};
    uint32_t mBlockSize{896};
    uint32_t mPointsPerThread{32};

    thrust::udevice_vector<uint32_t> d_publicKeysX;
    thrust::udevice_vector<uint32_t> d_publicKeysY;

    thrust::udevice_vector<uint32_t> d_privateKeys;
    thrust::udevice_vector<uint32_t> d_multChain;
    thrust::udevice_vector<uint32_t> d_gPoints;

    Impl()
    {
        initializeGPoints();
    }

    ~Impl()
    {
        clearPublicKeys();
        clearPrivateKeys();

        release(d_gPoints);
    }

    uint32_t getIndex(const uint32_t grid, const uint32_t block, const uint32_t idx) const
    {
        // Total number of threads
        const uint32_t totalThreads = mGridSize * mBlockSize;
        const uint32_t base = idx * totalThreads;

        // Global ID of the current thread
        const uint32_t threadId = grid * mBlockSize + block;
        return base + threadId;
    }

    void splatBigInt(uint32_t *dest, const uint32_t grid, const uint32_t block, const uint32_t idx, const secp256k1::uint256 &i) const
    {
        uint32_t value[8];
        i.exportWords(value, 8, secp256k1::uint256::BigEndian);

        const uint32_t totalThreads = mGridSize * mBlockSize;
        const uint32_t threadId = grid * mBlockSize * 4 + block * 4;
        const uint32_t base = idx * mGridSize * mBlockSize * 8;

        uint32_t index = base + threadId;
        for (uint32_t k = 0; k < 4; k++)
        {
            dest[index] = value[k];
            index++;
        }

        index = base + totalThreads * 4 + threadId;
        for (uint32_t k = 4; k < 8; k++)
        {
            dest[index] = value[k];
            index++;
        }
    }

    secp256k1::uint256 readBigInt(const uint32_t *src, const uint32_t grid, const uint32_t block, const uint32_t idx) const
    {
        uint32_t value[8];
        const uint32_t totalThreads = mGridSize * mBlockSize;
        const uint32_t threadId = grid * mBlockSize * 4 + block * 4;
        const uint32_t base = idx * mGridSize * mBlockSize * 8;

        uint32_t index = base + threadId;
        for (uint32_t k = 0; k < 4; k++)
        {
            value[k] = src[index];
            index++;
        }

        index = base + totalThreads * 4 + threadId;
        for (uint32_t k = 4; k < 8; k++)
        {
            value[k] = src[index];
            index++;
        }

        return {value, secp256k1::uint256::BigEndian};
    }

    // TODO:move calculation to functor
    // generate a table of points G, 2G, 4G, 8G...(2^255)G
    void initializeGPoints()
    {
        constexpr uint32_t gPointsNumber{256};
        d_gPoints.resize(gPointsNumber * 16);

        secp256k1::ecpoint p{secp256k1::G()};
        for (uint32_t i = 0; i < gPointsNumber; i++)
        {
            if (!pointExists(p))
            {
                throw std::runtime_error("Point does not exist!");
            }

            d_gPoints[i * 16 + 7] = p.x.v[0];
            d_gPoints[i * 16 + 6] = p.x.v[1];
            d_gPoints[i * 16 + 5] = p.x.v[2];
            d_gPoints[i * 16 + 4] = p.x.v[3];
            d_gPoints[i * 16 + 3] = p.x.v[4];
            d_gPoints[i * 16 + 2] = p.x.v[5];
            d_gPoints[i * 16 + 1] = p.x.v[6];
            d_gPoints[i * 16 + 0] = p.x.v[7];

            d_gPoints[i * 16 + 8 + 7] = p.y.v[0];
            d_gPoints[i * 16 + 8 + 6] = p.y.v[1];
            d_gPoints[i * 16 + 8 + 5] = p.y.v[2];
            d_gPoints[i * 16 + 8 + 4] = p.y.v[3];
            d_gPoints[i * 16 + 8 + 3] = p.y.v[4];
            d_gPoints[i * 16 + 8 + 2] = p.y.v[5];
            d_gPoints[i * 16 + 8 + 1] = p.y.v[6];
            d_gPoints[i * 16 + 8 + 0] = p.y.v[7];

            // ... 2G, 4G, 8G...(2^255)G
            p = doublePoint(p);
        }

        const uint32_t* d_gPointsRawPtr = thrust::raw_pointer_cast(d_gPoints.data());
        cu::cudaSafeCall(cudaMemcpyToSymbol(d_gPointsPtr, &d_gPointsRawPtr, sizeof(uint32_t*)));
    }

    void allocatePrivateKeysDeviceMemoryAndLoad(const thrust::host_vector<secp256k1::uint256> &privateKeys)
    {
        const uint32_t keysNumber = privateKeys.size();

        // Allocate private keys on device
        d_privateKeys.resize(keysNumber * 8);

        // Copy private keys to system memory buffer
        thrust::host_vector<uint32_t> tmp(keysNumber * 8, 0);
        for (uint32_t block = 0; block < mGridSize; block++)
        {
            for (uint32_t thread = 0; thread < mBlockSize; thread++)
            {
                for (uint32_t idx = 0; idx < mPointsPerThread; idx++)
                {
                    const int index = getIndex(block, thread, idx);
                    splatBigInt(tmp.data(), block, thread, idx, privateKeys[index]);
                }
            }
        }

        // Copy private keys to device memory
        d_privateKeys = tmp;
    }

    void allocatePublicKeysDeviceMemory(const uint32_t keysNumber)
    {
        d_publicKeysX.resize(keysNumber * 8);
        thrust::fill(d_publicKeysX.begin(), d_publicKeysX.end(), 0xFFFFFFFF);

        const uint32_t* d_publicKeysXRawPtr = thrust::raw_pointer_cast(d_publicKeysX.data());
        cu::cudaSafeCall(cudaMemcpyToSymbol(d_publicKeyXPtr, &d_publicKeysXRawPtr, sizeof(uint32_t *)));

        d_publicKeysY.resize(keysNumber * 8);
        thrust::fill(d_publicKeysY.begin(), d_publicKeysY.end(), 0xFFFFFFFF);

        const uint32_t* d_publicKeysYRawPtr = thrust::raw_pointer_cast(d_publicKeysY.data());
        cu::cudaSafeCall(cudaMemcpyToSymbol(d_publicKeyYPtr, &d_publicKeysYRawPtr, sizeof(uint32_t *)));
    }

    void allocateMultChainDeviceMemory()
    {
        d_multChain.resize(mBlockSize * mGridSize * mPointsPerThread * 8);
        const uint32_t* d_multChainRawPtr = thrust::raw_pointer_cast(d_multChain.data());
        cu::cudaSafeCall(cudaMemcpyToSymbol(d_multChainPtr, &d_multChainRawPtr, sizeof(uint32_t*)));
    }

    void init(const thrust::host_vector<secp256k1::uint256> &privateKeys)
    {
        const uint32_t keysNumber = privateKeys.size();

        int minGridSize{};
        int blockSize{};
        cudaOccupancyMaxPotentialBlockSize(&minGridSize, &blockSize, multiplyStepKernel);
        std::cout << "minGridSize: " << minGridSize << ", blockSize: " << blockSize << std::endl;

        if (keysNumber < static_cast<uint32_t>(blockSize))
        {
            mBlockSize = keysNumber;
            mGridSize = 1;
            mPointsPerThread = 1;
        }
        else
        {
            mPointsPerThread = 32;

            if (keysNumber / mPointsPerThread < static_cast<uint32_t>(blockSize))
            {
                mBlockSize = keysNumber / mPointsPerThread;
            }
            else
            {
                mBlockSize = blockSize;
            }

            mGridSize = std::max(keysNumber / (blockSize * mPointsPerThread), 1U);
        }
        cu::cudaSafeCall(cudaMemcpyToSymbol(d_pointsPerThread, &mPointsPerThread, sizeof(uint32_t)));

        const auto totalKeysPerStep = mGridSize * mBlockSize * mPointsPerThread;

        std::cout << "Keys will be generated: " << totalKeysPerStep << ", requested: " << keysNumber << ", skipped: " << std::abs(static_cast<int>(totalKeysPerStep) - static_cast<int>(keysNumber)) << std::endl;
        std::cout << "mGridSize: " << mGridSize << ", mBlockSize: " << mBlockSize  << ", mPointsPerThread: " << mPointsPerThread << std::endl;

        // Allocate private keys on device
        allocatePrivateKeysDeviceMemoryAndLoad(privateKeys);

        // Allocate space for public keys on device
        allocatePublicKeysDeviceMemory(keysNumber);

        // Allocates device memory for storing the multiplication chain used in the batch inversion operation
        allocateMultChainDeviceMemory();
    }

    cudaError_t getResults(thrust::host_vector<std::pair<uint32_t, secp256k1::ecpoint>> &results) const
    {
        thrust::host_vector<uint32_t> h_publicKeysX = d_publicKeysX;
        thrust::host_vector<uint32_t> h_publicKeysY = d_publicKeysY;

        for (uint32_t grid = 0; grid < mGridSize; grid++)
        {
            for (uint32_t block = 0; block < mBlockSize; block++)
            {
                for (uint32_t idx = 0; idx < mPointsPerThread; idx++)
                {
                    secp256k1::uint256 x = readBigInt(h_publicKeysX.data(), grid, block, idx);
                    secp256k1::uint256 y = readBigInt(h_publicKeysY.data(), grid, block, idx);

                    const auto privateKeyIndex = getIndex(grid, block, idx);
                    results.push_back({privateKeyIndex, {x, y}});
                }
            }
        }

        return cudaSuccess;
    }

    cudaError_t generatePublicKeys()
    {
        multiplyStepKernel <<<mGridSize, mBlockSize>>>(thrust::raw_pointer_cast(d_privateKeys.data()));

        // Wait for kernel to complete
        const cudaError_t err = cudaDeviceSynchronize();

        fflush(stdout);

        return err;
    }

    void clearPrivateKeys()
    {
        release(d_privateKeys);
        release(d_multChain);
    }

    void clearPublicKeys()
    {
        release(d_publicKeysX);
        release(d_publicKeysY);
    }

    bool selfTest(const thrust::host_vector<secp256k1::uint256> &privateKeys) const
    {
        thrust::host_vector<uint32_t> h_publicKeysX = d_publicKeysX;
        thrust::host_vector<uint32_t> h_publicKeysY = d_publicKeysY;

        bool result{true};
        for (uint32_t grid = 0; grid < mGridSize; grid++)
        {
            for (uint32_t block = 0; block < mBlockSize; block++)
            {
                for (uint32_t idx = 0; idx < mPointsPerThread; idx++)
                {
                    const auto index = getIndex(grid, block, idx);
                    const secp256k1::uint256 privateKey = privateKeys[index];

                    secp256k1::uint256 x = readBigInt(h_publicKeysX.data(), grid, block, idx);
                    secp256k1::uint256 y = readBigInt(h_publicKeysY.data(), grid, block, idx);

                    const secp256k1::ecpoint pGPU(x, y);
                    if (!secp256k1::pointExists(pGPU))
                    {
                        std::cout << "Validation failed (pGPU): invalid point, for privateKey: " << privateKey.toString() << std::endl;
                        std::cout << "GPU: " << pGPU.toString(false) << std::endl;
                        result = false;
                    }

                    secp256k1::ecpoint pCPU = secp256k1::multiplyPoint(privateKey, secp256k1::G());
                    if (!secp256k1::pointExists(pCPU))
                    {
                        std::cout << "Validation failed (pCPU): invalid point, for privateKey: " << privateKey.toString() << std::endl;
                        std::cout << "CPU: " << pCPU.toString(false) << std::endl;
                        std::cout << "GPU: " << pGPU.toString(false) << std::endl;
                        result = false;
                    }

                    if (pGPU != pCPU)
                    {
                        std::cout << "Validation failed: points do not match, for privateKey: " << privateKey.toString() << std::endl;
                        std::cout << "CPU: " << pCPU.toString(false) << std::endl;
                        std::cout << "GPU: " << pGPU.toString(false) << std::endl;
                        result = false;
                    }
                }
            }
        }

        return result;
    }
};

__global__ void multiplyStepKernel(const uint32_t *privateKeys)
{
    // 256 is a 256 bit in a private key
    constexpr uint32_t bitsNumber{256};

    uint32_t p[8]{};

    uint32_t *xPtr = d_publicKeyXPtr;
    uint32_t *yPtr = d_publicKeyYPtr;

    for (int step{0}; step < bitsNumber; step++)
    {
        const uint32_t *stepGPoint = d_gPointsPtr + step * 16;

        // Multiply together all (_Gx - x) and then invert
        uint32_t inverse[8]{0, 0, 0, 0, 0, 0, 0, 1};
        int batchIdx{0};

        for(uint32_t i = 0; i < d_pointsPerThread; i++)
        {
            uint32_t x[8];
            readInt(xPtr, i, x);

            readInt(privateKeys, i, p);
            if (const uint32_t bit = p[7 - step / 32] & 1 << (step % 32); bit != 0 && !isInfinity(x))
            {
                beginBatchAddWithDouble(stepGPoint, xPtr, d_multChainPtr, i, batchIdx, inverse);
                batchIdx++;
            }
        }

        doBatchInverse(inverse);
        for(int i = d_pointsPerThread - 1; i >= 0; i--)
        {
            readInt(privateKeys, i, p);
            if (const uint32_t bit = p[7 - step / 32] & 1 << (step % 32); bit != 0)
            {
                uint32_t newX[8];
                uint32_t newY[8];

                uint32_t x[8];
                readInt(xPtr, i, x);

                if (!isInfinity(x))
                {
                    batchIdx--;
                    completeBatchAddWithDouble(stepGPoint, xPtr, yPtr, i, batchIdx, d_multChainPtr, inverse, newX, newY);
                }
                else
                {
                    copyBigInt(stepGPoint, newX);
                    copyBigInt(stepGPoint + 8, newY);
                }

                writeInt(xPtr, i, newX);
                writeInt(yPtr, i, newY);
            }
        }
    }
}

ECC::ECC() : mImpl(std::make_unique<Impl>()) {}
ECC::~ECC() = default;

ECC::ECC(ECC&& rhs) noexcept = default;
ECC& ECC::operator=(ECC &&rhs) noexcept = default;

void ECC::init(const thrust::host_vector<secp256k1::uint256> &privateKeys) const
{
    mImpl->init(privateKeys);
}

cudaError_t ECC::getResults(thrust::host_vector<std::pair<uint32_t, secp256k1::ecpoint>> &results) const
{
    return mImpl->getResults(results);
}

cudaError_t ECC::generatePublicKeys() const
{
    return mImpl->generatePublicKeys();
}

bool ECC::selfTest(const thrust::host_vector<secp256k1::uint256> &privateKeys) const
{
    return mImpl->selfTest(privateKeys);
}