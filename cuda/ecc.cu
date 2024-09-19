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

__constant__ uint256_t *d_multChainPtr{};
__constant__ ecpoint_t *d_gPointsPtr{};

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

    thrust::udevice_vector<uint256_t> d_multChain;
    thrust::udevice_vector<ecpoint_t> d_gPoints;

    Impl()
    {
        cudaStreamCreate(&mGeneratorStream);
        cudaStreamCreate(&mInitStream);

        setPointsPerThread(mPointsPerThread);
    }

    ~Impl()
    {
        release(d_privateKeys);
        release(d_multChain);
        release(d_publicKeysX);
        release(d_publicKeysY);
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
        int recommendedBlockSize{};
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
        // Global ID of the current thread
        const uint32_t threadId = grid * mBlockSize + block;

        const uint32_t base = idx * totalThreads;
        return base + threadId;
    }

    uint32_t getKeysNumberPerIteration() const
    {
        return mKeysNumberPerIteration;
    }

    // generate a table of points G, 2G, 4G, 8G...(2^255)G
    void setGPoints(const std::vector<ecpoint_t>& gPoints)
    {
        thrust::host_vector<ecpoint_t> h_gPoints(gPoints.begin(), gPoints.end());

        d_gPoints = h_gPoints;
        const auto* d_gPointsRawPtr = thrust::raw_pointer_cast(d_gPoints.data());
        cu::safeCall(cudaMemcpyToSymbol(d_gPointsPtr, &d_gPointsRawPtr, sizeof(ecpoint_t*)));
    }

    void allocatePublicKeysDeviceMemory()
    {
        const uint32_t keysNumber = getKeysNumberPerIteration();

        d_publicKeysX.resize(keysNumber);

        const uint256_t* d_publicKeysXRawPtr = thrust::raw_pointer_cast(d_publicKeysX.data());
        cu::safeCall(cudaMemcpyToSymbol(d_publicKeyXPtr, &d_publicKeysXRawPtr, sizeof(uint256_t *)));

        d_publicKeysY.resize(keysNumber);

        const uint256_t* d_publicKeysYRawPtr = thrust::raw_pointer_cast(d_publicKeysY.data());
        cu::safeCall(cudaMemcpyToSymbol(d_publicKeyYPtr, &d_publicKeysYRawPtr, sizeof(uint256_t *)));
    }

    void allocateMultChainDeviceMemory()
    {
        d_multChain.resize(getKeysNumberPerIteration());

        const uint256_t* d_multChainRawPtr = thrust::raw_pointer_cast(d_multChain.data());
        cu::safeCall(cudaMemcpyToSymbol(d_multChainPtr, &d_multChainRawPtr, sizeof(uint256_t*)));
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
        thrust::transform(thrust::cuda::par.on(mInitStream),
                  thrust::counting_iterator<uint32_t>(0u),
                  thrust::counting_iterator<uint32_t>(keysNumberPerIteration),
                  d_privateKeys.begin(),
                  PrivateKeyForXWithRandomYFunctor(privateXPart, increment)
        );
    }

    void initWithPrivateDefinedXRandomY(const uint32_t pointsPerThread, const uint32_t publicKeyCompressionTypeToCheck, const uint32_t blockSize)
    {
        computeResolutionForMaxOccupancy(pointsPerThread, blockSize);

        cu::safeCall(cudaMemcpyToSymbol(d_publicKeyCompressionTypeToCheck, &publicKeyCompressionTypeToCheck, sizeof(uint32_t)));

        // Allocate space for private keys on device
        allocatePrivateKeysDeviceMemory();

        // Allocate space for public keys on device
        allocatePublicKeysDeviceMemory();

        // Allocates device memory for storing the multiplication chain used in the batch inversion operation
        allocateMultChainDeviceMemory();
    }

    cudaError_t calculatePublicKeys()
    {
        uint256_t infinite{0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF};
        thrust::fill(thrust::cuda_cub::par.on(mGeneratorStream), d_publicKeysX.begin(), d_publicKeysX.end(), infinite);
        thrust::fill(thrust::cuda_cub::par.on(mGeneratorStream), d_publicKeysY.begin(), d_publicKeysY.end(), infinite);

        constexpr uint32_t mSharedMemSize{0};
        multiplyStepKernel <<<mGridSize, mBlockSize, mSharedMemSize, mGeneratorStream>>>(thrust::raw_pointer_cast(d_privateKeys.data()));

        // Wait for kernel to complete
        const cudaError_t err = cudaStreamSynchronize(mGeneratorStream);

        fflush(stdout);

        return err;
    }

    cudaError_t getResults(const thrust::host_vector<std::pair<uint256_t, ecpoint_t>> & pairs)
    {
       return cudaSuccess;
    }
};

ECC::ECC() : mImpl(std::make_unique<Impl>()) {}
ECC::~ECC() = default;

ECC::ECC(ECC&& rhs) noexcept = default;
ECC& ECC::operator=(ECC &&rhs) noexcept = default;

void ECC::setGPoints(const std::vector<ecpoint_t>& h_GPoints) const
{
    mImpl->setGPoints(h_GPoints);
}

void ECC::initWithPrivateDefinedXRandomY(const uint32_t pointsPerThread, const uint32_t publicKeyCompressionTypeToCheck, const uint32_t blockSize) const
{
    mImpl->initWithPrivateDefinedXRandomY(pointsPerThread, publicKeyCompressionTypeToCheck, blockSize);
}

uint32_t ECC::getKeysNumberPerIteration() const
{
    return mImpl->getKeysNumberPerIteration();
}

cudaError_t ECC::getResults(thrust::host_vector<std::pair<uint256_t, ecpoint_t>> &results) const
{
    return mImpl->getResults(results);
}

cudaError_t ECC::calculatePublicKeys() const
{
    return mImpl->calculatePublicKeys();
}

void ECC::generatePrivateKeysForXPerIteration(const uint32_t privateXPart, const uint32_t iteration) const
{
    mImpl->generatePrivateKeysForXPerIteration(privateXPart, iteration);
}

void ECC::getPrivateKeys(thrust::host_vector<uint256_t> &h_privateKeys) const
{
    mImpl->getPrivateKeys(h_privateKeys);
}
