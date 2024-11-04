#include "ecc.cuh"

#include "udevice_vector.cuh"
#include "ecc_helper.cuh"
#include "functors.cuh"

#include "util/cuda_util.h"
#include "util/common.h"

// Check public key hash160 compressed/uncompressed/both
__constant__ int d_publicKeyCompressionTypeToCheck{PointCompressionType::BOTH};

__constant__ uint32_t d_pointsPerThread{};

__constant__ uint256_t *d_publicKeyXPtr{};
__constant__ uint256_t *d_publicKeyYPtr{};

struct ECC::Impl
{
    cudaStream_t mGeneratorStream{};
    cudaStream_t mInitStream{};

    uint32_t mGridSize{32};
    uint32_t mBlockSize{512};
    uint32_t mPointsPerThread{32};

    uint32_t mKeysNumberPerIteration{mGridSize * mBlockSize * mPointsPerThread};

    thrust::udevice_vector<uint256_t> d_publicKeysX;
    thrust::udevice_vector<uint256_t> d_publicKeysY;

    thrust::udevice_vector<uint256_t> d_privateKeys;

    Impl()
    {
        cudaStreamCreate(&mGeneratorStream);
        cudaStreamCreate(&mInitStream);

        setPointsPerThread(mPointsPerThread);
    }

    ~Impl()
    {
        release(d_privateKeys);
        release(d_publicKeysX);
        release(d_publicKeysY);

        cudaStreamDestroy(mGeneratorStream);
        cudaStreamDestroy(mInitStream);
    }

    void setPointsPerThread(const uint32_t value)
    {
        mPointsPerThread = value;
        cudaCheckError(cudaMemcpyToSymbol(d_pointsPerThread, &mPointsPerThread, sizeof(uint32_t)));
    }

    void computeResolutionForMaxOccupancy(const uint32_t pointsPerThread, const uint32_t blockSize = 0)
    {
        int minGridSize{};
        int recommendedBlockSize{};
        cudaCheckError(cudaOccupancyMaxPotentialBlockSize(&minGridSize, &recommendedBlockSize, publicKeyGenerationKernel));

        mBlockSize = (blockSize != 0) ? blockSize : recommendedBlockSize;

        setPointsPerThread(pointsPerThread);
        mGridSize = minGridSize;

        mKeysNumberPerIteration = mGridSize * mBlockSize * mPointsPerThread;
        std::fprintf(stderr, "minGridSize: %d, recommendedBlockSize: %d, set blockSize: %u, mKeysNumberPerIteration: %u\n", minGridSize, recommendedBlockSize, mBlockSize, mKeysNumberPerIteration);
    }

    [[nodiscard]] uint32_t getIndex(const uint32_t grid, const uint32_t block, const uint32_t idx) const
    {
        // Total number of threads
        const uint32_t totalThreads = mGridSize * mBlockSize;
        // Global ID of the current thread
        const uint32_t threadId = grid * mBlockSize + block;

        const uint32_t base = idx * totalThreads;
        return base + threadId;
    }

    [[nodiscard]] uint32_t getKeysNumberPerIteration() const
    {
        return mKeysNumberPerIteration;
    }

    void allocatePublicKeysDeviceMemory()
    {
        const uint32_t keysNumber = getKeysNumberPerIteration();

        d_publicKeysX.resize(keysNumber);

        const uint256_t* d_publicKeysXRawPtr = thrust::raw_pointer_cast(d_publicKeysX.data());
        cudaCheckError(cudaMemcpyToSymbol(d_publicKeyXPtr, &d_publicKeysXRawPtr, sizeof(uint256_t *)));

        d_publicKeysY.resize(keysNumber);

        const uint256_t* d_publicKeysYRawPtr = thrust::raw_pointer_cast(d_publicKeysY.data());
        cudaCheckError(cudaMemcpyToSymbol(d_publicKeyYPtr, &d_publicKeysYRawPtr, sizeof(uint256_t *)));
    }

    void allocatePrivateKeysDeviceMemory()
    {
        const uint32_t keysNumberPerIteration = getKeysNumberPerIteration();
        d_privateKeys.resize(keysNumberPerIteration);
    }

    void getPrivateKeys(thrust::host_vector<uint256_t>& h_privateKeys) const
    {
        h_privateKeys = d_privateKeys;
    }

    void generatePrivateKeysForXPerIteration(const uint32_t privateXPart, const uint32_t iteration)
    {
        const uint32_t keysNumberPerIteration = getKeysNumberPerIteration();

        if (d_privateKeys.size() != keysNumberPerIteration)
        {
            throw std::runtime_error("Private keys device storage has wrong size");
        }

        /// TODO: check for uint32_t overflow
        const uint32_t increment = iteration * keysNumberPerIteration;

        // {x, 0}, {x, 1}, ... , {x, keysNumberPerIteration - 1}
        cudaCheckError(cudaKernelSyncLaunch(mInitStream, [&]()
        {
            thrust::transform(thrust::cuda::par.on(mInitStream),
                              thrust::counting_iterator<uint32_t>(0u),
                              thrust::counting_iterator<uint32_t>(keysNumberPerIteration),
                              d_privateKeys.begin(),
                              PrivateKeyForXWithRandomYFunctor(privateXPart, increment)
            );
        }, "generatePrivateKeysForXPerIteration"));
    }

    void init(const uint32_t pointsPerThread, const uint32_t publicKeyCompressionTypeToCheck, const uint32_t blockSize)
    {
        computeResolutionForMaxOccupancy(pointsPerThread, blockSize);

        cudaCheckError(cudaMemcpyToSymbol(d_publicKeyCompressionTypeToCheck, &publicKeyCompressionTypeToCheck, sizeof(uint32_t)));

        // Allocate space for private keys on device
        allocatePrivateKeysDeviceMemory();

        // Allocate space for public keys on device
        allocatePublicKeysDeviceMemory();
    }

    void calculatePublicKeysAndCheckHash160()
    {
        /// TODO(ksh): check do this block needed here?
        cudaCheckError(cudaKernelSyncLaunch(mGeneratorStream, [&]()
        {
            constexpr uint256_t infinite{0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF};
            thrust::fill(thrust::cuda_cub::par.on(mGeneratorStream), d_publicKeysX.begin(), d_publicKeysX.end(), infinite);
            thrust::fill(thrust::cuda_cub::par.on(mGeneratorStream), d_publicKeysY.begin(), d_publicKeysY.end(), infinite);
        }, "Initialize public keys"));

        constexpr uint32_t mSharedMemSize{0};
        const uint256_t *privateKeysPtr = thrust::raw_pointer_cast(d_privateKeys.data());
        cudaCheckError(cudaKernelSyncLaunch(mGeneratorStream, [&]()
        {
            publicKeyGenerationKernel <<<mGridSize, mBlockSize, mSharedMemSize, mGeneratorStream>>>(privateKeysPtr);
        }, "publicKeyGenerationKernel"));

        cudaCheckError(cudaKernelSyncLaunch(mGeneratorStream, [&]()
        {
            checkHashKernel <<<mGridSize, mBlockSize, mSharedMemSize, mGeneratorStream>>>(privateKeysPtr);
        }, "checkHashKernel"));
    }
};

ECC::ECC() : mImpl(std::make_unique<Impl>()) {}
ECC::~ECC() = default;

ECC::ECC(ECC&& rhs) noexcept = default;
ECC& ECC::operator=(ECC &&rhs) noexcept = default;

void ECC::init(const uint32_t pointsPerThread, const uint32_t publicKeyCompressionTypeToCheck, const uint32_t blockSize) const
{
    mImpl->init(pointsPerThread, publicKeyCompressionTypeToCheck, blockSize);
}

uint32_t ECC::getKeysNumberPerIteration() const
{
    return mImpl->getKeysNumberPerIteration();
}

void ECC::calculatePublicKeysAndCheckHash160() const
{
    mImpl->calculatePublicKeysAndCheckHash160();
}

void ECC::generatePrivateKeysForXPerIteration(const uint32_t privateXPart, const uint32_t iteration) const
{
    mImpl->generatePrivateKeysForXPerIteration(privateXPart, iteration);
}

void ECC::getPrivateKeys(std::vector<uint256_t>& h_privateKeys) const
{
    thrust::host_vector<uint256_t> thrust_keys;
    mImpl->getPrivateKeys(thrust_keys);

    h_privateKeys.assign(thrust_keys.begin(), thrust_keys.end());
}