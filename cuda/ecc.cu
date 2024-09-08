#include <cuda_runtime.h>
#include <thrust/host_vector.h>
#include <thrust/sequence.h>
#include <thrust/iterator/constant_iterator.h>

#include "ecc.cuh"
#include "ecc_helper.cuh"
#include "functors.cuh"

#include "common.h"
#include "cuda_util.h"

struct ECC::Impl
{
    cudaStream_t mGeneratorStream{};
    cudaStream_t mInitStream{};

    uint32_t mGridSize{32};
    uint32_t mBlockSize{512};
    uint32_t mPointsPerThread{32};

    uint32_t mKeysNumberPerIteration{mGridSize * mBlockSize * mPointsPerThread};

    thrust::udevice_vector<uint32_t> d_publicKeysX;
    thrust::udevice_vector<uint32_t> d_publicKeysY;

    thrust::udevice_vector<uint256_t> d_privateKeys;

    thrust::udevice_vector<uint256_t> d_multChain;
    thrust::udevice_vector<ecpoint_t> d_gPoints;

    Impl()
    {
        cudaStreamCreate(&mGeneratorStream);
        cudaStreamCreate(&mInitStream);

        initializeGPoints();

        setPointsPerThread(128);
    }

    ~Impl()
    {
        clearPublicKeys();
        clearPrivateKeys();

        release(d_gPoints);

        cudaStreamDestroy(mGeneratorStream);
        cudaStreamDestroy(mInitStream);
    }

    void setPointsPerThread(const uint32_t value)
    {
        mPointsPerThread = value;
        cu::safeCall(cudaMemcpyToSymbol(d_pointsPerThread, &mPointsPerThread, sizeof(uint32_t)));
    }

    void computeResolutionForMaxOccupancy(const uint32_t pointsPerThread, const uint32_t blockSize = 0)
    {
        int minGridSize{};
        int recommendedBlockSize;
        cudaOccupancyMaxPotentialBlockSize(&minGridSize, &recommendedBlockSize, multiplyStepKernel);

        mBlockSize = (blockSize != 0) ? blockSize : recommendedBlockSize;
        printf("minGridSize: %d, recommendedBlockSize: %d, set blockSize; %u\n", minGridSize, recommendedBlockSize, mBlockSize);

        setPointsPerThread(pointsPerThread);
        mGridSize = minGridSize;

        mKeysNumberPerIteration = mGridSize * mBlockSize * mPointsPerThread;
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

    uint32_t getKeysNumberPerIteration() const
    {
        return mKeysNumberPerIteration;
    }

    // TODO:move calculation to functor
    // generate a table of points G, 2G, 4G, 8G...(2^255)G
    void initializeGPoints()
    {
        constexpr uint32_t gPointsNumber{256};
        d_gPoints.resize(gPointsNumber);

        secp256k1::ecpoint p{secp256k1::G()};
        for (uint32_t i = 0; i < gPointsNumber; ++i)
        {
            if (!pointExists(p))
            {
                throw std::runtime_error("Point does not exist!");
            }

            // set as BigEndian to device memory
            d_gPoints[i] = {p.x.v, p.y.v};

            // ... 2G, 4G, 8G...(2^255)G
            p = secp256k1::doublePoint(p);
        }

        const auto* d_gPointsRawPtr = thrust::raw_pointer_cast(d_gPoints.data());
        cu::safeCall(cudaMemcpyToSymbol(d_gPointsPtr, &d_gPointsRawPtr, sizeof(ecpoint_t*)));
    }

    void allocatePrivateKeysDeviceMemoryAndLoad(const thrust::host_vector<secp256k1::uint256>& privateKeys)
    {
        thrust::host_vector<uint256_t> h_privateKeys;
        h_privateKeys.resize(privateKeys.size());

        // Copy private keys to system memory buffer
        for (uint32_t grid = 0; grid < mGridSize; ++grid)
        {
            for (uint32_t block = 0; block < mBlockSize; ++block)
            {
                for (uint32_t idx = 0; idx < mPointsPerThread; ++idx)
                {
                    const int index = getIndex(grid, block, idx);
                    h_privateKeys[index] = privateKeys[index].v;
                }
            }
        }
        d_privateKeys = h_privateKeys;
    }

    void allocatePublicKeysDeviceMemory()
    {
        const uint32_t keysNumber = getKeysNumberPerIteration();

        d_publicKeysX.resize(keysNumber * 8);
        thrust::fill(thrust::cuda_cub::par.on(mInitStream), d_publicKeysX.begin(), d_publicKeysX.end(), 0xFFFFFFFF);

        const uint32_t* d_publicKeysXRawPtr = thrust::raw_pointer_cast(d_publicKeysX.data());
        cu::safeCall(cudaMemcpyToSymbol(d_publicKeyXPtr, &d_publicKeysXRawPtr, sizeof(uint32_t *)));

        d_publicKeysY.resize(keysNumber * 8);
        thrust::fill(thrust::cuda_cub::par.on(mInitStream), d_publicKeysY.begin(), d_publicKeysY.end(), 0xFFFFFFFF);

        const uint32_t* d_publicKeysYRawPtr = thrust::raw_pointer_cast(d_publicKeysY.data());
        cu::safeCall(cudaMemcpyToSymbol(d_publicKeyYPtr, &d_publicKeysYRawPtr, sizeof(uint32_t *)));
    }

    void allocateMultChainDeviceMemory()
    {
        d_multChain.resize(getKeysNumberPerIteration());

        const uint256_t* d_multChainRawPtr = thrust::raw_pointer_cast(d_multChain.data());
        cu::safeCall(cudaMemcpyToSymbol(d_multChainPtr, &d_multChainRawPtr, sizeof(uint256_t*)));
    }

    void allocatePrivateKeysDeviceMemory()
    {
        const uint keysNumberPerIteration = getKeysNumberPerIteration();
        d_privateKeys.resize(keysNumberPerIteration);
    }

    void getPrivateKeys(thrust::host_vector<uint256_t>& h_privateKeys) const
    {
        h_privateKeys = d_privateKeys;
    }

    void generatePrivateKeysForXPerIteration(const uint privateXPart, const uint iteration)
    {
        const uint keysNumberPerIteration = getKeysNumberPerIteration();

        if (d_privateKeys.size() != keysNumberPerIteration)
        {
            throw std::runtime_error("Private keys device storage has wrong size");
        }

        /// TODO: check for uint overflow
        const uint increment = iteration * keysNumberPerIteration;

        // {x, 0}, {x, 1}, ... , {x, keysNumberPerIteration - 1}
        thrust::transform(thrust::cuda::par.on(mInitStream),
                  thrust::counting_iterator(0u),
                  thrust::counting_iterator(keysNumberPerIteration),
                  d_privateKeys.begin(),
                  PrivateKeyForXWithRandomYFunctor(privateXPart, increment)
        );
    }

    void initWithPrivateDefinedXRandomY(const uint32_t pointsPerThread, const uint32_t blockSize)
    {
        computeResolutionForMaxOccupancy(pointsPerThread, blockSize);

        allocatePrivateKeysDeviceMemory();

        // Allocate space for public keys on device
        allocatePublicKeysDeviceMemory();

        // Allocates device memory for storing the multiplication chain used in the batch inversion operation
        allocateMultChainDeviceMemory();
    }

    void init(const uint32_t pointsPerThread, const thrust::host_vector<secp256k1::uint256> &privateKeys)
    {
        const uint32_t keysNumber = privateKeys.size();

        int minGridSize{};
        int blockSize{};
        cudaOccupancyMaxPotentialBlockSize(&minGridSize, &blockSize, multiplyStepKernel);
        std::cout << "minGridSize: " << minGridSize << ", blockSize: " << blockSize << std::endl;

        if (keysNumber < static_cast<uint32_t>(blockSize))
        {
            setPointsPerThread(1);

            mBlockSize = keysNumber;
            mGridSize = 1;
        }
        else
        {
            setPointsPerThread(pointsPerThread);

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
        mKeysNumberPerIteration = mGridSize * mBlockSize * mPointsPerThread;

        std::cout << "Keys will be generated: " << mKeysNumberPerIteration << ", requested: " << keysNumber << ", skipped: " << std::abs(static_cast<int>(mKeysNumberPerIteration) - static_cast<int>(keysNumber)) << std::endl;
        std::cout << "mGridSize: " << mGridSize << ", mBlockSize: " << mBlockSize  << ", mPointsPerThread: " << mPointsPerThread << std::endl;

        // Allocate private keys on device
        allocatePrivateKeysDeviceMemoryAndLoad(privateKeys);

        // Allocate space for public keys on device
        allocatePublicKeysDeviceMemory();

        // Allocates device memory for storing the multiplication chain used in the batch inversion operation
        allocateMultChainDeviceMemory();
    }

    cudaError_t getResults(thrust::host_vector<std::pair<uint256_t, secp256k1::ecpoint>> &results) const
    {
        thrust::host_vector<uint32_t> h_publicKeysX = d_publicKeysX;
        thrust::host_vector<uint32_t> h_publicKeysY = d_publicKeysY;
        thrust::host_vector<uint256_t> h_privateKeys = d_privateKeys;

        for (uint32_t grid = 0; grid < mGridSize; ++grid)
        {
            for (uint32_t block = 0; block < mBlockSize; ++block)
            {
                for (uint32_t idx = 0; idx < mPointsPerThread; ++idx)
                {
                    secp256k1::uint256 x = readBigInt(h_publicKeysX.data(), grid, block, idx);
                    secp256k1::uint256 y = readBigInt(h_publicKeysY.data(), grid, block, idx);

                    const auto privateKeyIndex = getIndex(grid, block, idx);
                    results.push_back({h_privateKeys[privateKeyIndex], {x, y}});
                }
            }
        }

        return cudaSuccess;
    }

    cudaError_t calculatePublicKeys()
    {
        thrust::fill(thrust::cuda_cub::par.on(mInitStream), d_publicKeysX.begin(), d_publicKeysX.end(), 0xFFFFFFFF);
        thrust::fill(thrust::cuda_cub::par.on(mInitStream), d_publicKeysY.begin(), d_publicKeysY.end(), 0xFFFFFFFF);

        constexpr uint32_t mSharedMemSize{0};
        multiplyStepKernel <<<mGridSize, mBlockSize, mSharedMemSize, mGeneratorStream>>>(thrust::raw_pointer_cast(d_privateKeys.data()));

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
        for (uint32_t grid = 0; grid < mGridSize; ++grid)
        {
            for (uint32_t block = 0; block < mBlockSize; ++block)
            {
                for (uint32_t idx = 0; idx < mPointsPerThread; ++idx)
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

ECC::ECC() : mImpl(std::make_unique<Impl>()) {}
ECC::~ECC() = default;

ECC::ECC(ECC&& rhs) noexcept = default;
ECC& ECC::operator=(ECC &&rhs) noexcept = default;

void ECC::init(const uint32_t pointsPerThread, const thrust::host_vector<secp256k1::uint256> &privateKeys) const
{
    mImpl->init(pointsPerThread, privateKeys);
}

void ECC::initWithPrivateDefinedXRandomY(const uint32_t pointsPerThread, const uint32_t blockSize) const
{
    mImpl->initWithPrivateDefinedXRandomY(pointsPerThread, blockSize);
}

uint32_t ECC::getKeysNumberPerIteration() const
{
    return mImpl->getKeysNumberPerIteration();
}

cudaError_t ECC::getResults(thrust::host_vector<std::pair<uint256_t, secp256k1::ecpoint>> &results) const
{
    return mImpl->getResults(results);
}

cudaError_t ECC::calculatePublicKeys() const
{
    return mImpl->calculatePublicKeys();
}

void ECC::generatePrivateKeysForXPerIteration(const uint privateXPart, const uint iteration) const
{
    mImpl->generatePrivateKeysForXPerIteration(privateXPart, iteration);
}

void ECC::getPrivateKeys(thrust::host_vector<uint256_t> &h_privateKeys) const
{
    mImpl->getPrivateKeys(h_privateKeys);
}

bool ECC::selfTest(const thrust::host_vector<secp256k1::uint256> &privateKeys) const
{
    return mImpl->selfTest(privateKeys);
}
