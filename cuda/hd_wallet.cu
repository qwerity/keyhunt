#include "hd_wallet.cuh"
#include "hd_wallet_kernels.cuh"
#include "ecc_helper.cuh"
#include "udevice_vector.cuh"

#include "defines.h"

struct CUHDWallet::Impl
{
    cudaStream_t mGeneratorStream{};

    uint32_t mGridSize{32};
    uint32_t mBlockSize{512};
    uint32_t mnemonicsPerIteration{mGridSize * mBlockSize};

    thrust::udevice_vector<extended_public_key_t> d_publicKeys;
    thrust::udevice_vector<extended_private_key_t> d_privateKeys;
    thrust::udevice_vector<uint8_t> d_mnemonics;
    thrust::udevice_vector<uint32_t> d_mnemonicsSeeds;
    thrust::udevice_vector<extended_private_key_t> d_mnemonicsSeedsMasterKeys;

    std::vector<std::vector<uint32_t>> h_derivationPaths;
    thrust::udevice_vector<uint32_t> d_flattenedDerivationPaths;
    thrust::udevice_vector<uint32_t> d_derivationPathsLengths;

    Impl()
    {
        cudaStreamCreate(&mGeneratorStream);
    }
    ~Impl()
    {
        cudaStreamDestroy(mGeneratorStream);
    }

    [[nodiscard]] inline uint32_t getMnemonicsPerIteration() const
    {
        return mnemonicsPerIteration;
    }

    void computeResolutionForMaxOccupancy(const uint32_t gridSize, const uint32_t blockSize)
    {
        int minGridSize{};
        int recommendedBlockSize{};
        cudaCheckError(cudaOccupancyMaxPotentialBlockSize(&minGridSize, &recommendedBlockSize, hdWalletKernel));

        mBlockSize = (blockSize != 0) ? blockSize : recommendedBlockSize;
        mGridSize = (gridSize != 0) ? gridSize : minGridSize;

        mnemonicsPerIteration = mGridSize * mBlockSize;
        std::fprintf(stderr, "minGridSize: %d, recommendedBlockSize: %d, set blockSize: %u, gridSize: %u, mnemonicsPerIteration: %u\n", minGridSize, recommendedBlockSize, mBlockSize, mGridSize, mnemonicsPerIteration);
    }

    void allocatePrivateAndPublicKeysDeviceMemory(const uint32_t derivationPathsNumber)
    {
        const uint32_t mnemonicsNumber = getMnemonicsPerIteration();
        d_publicKeys.resize(mnemonicsNumber * derivationPathsNumber);
        d_privateKeys.resize(mnemonicsNumber * derivationPathsNumber);

        const extended_public_key_t* d_publicKeysRawPtr = thrust::raw_pointer_cast(d_publicKeys.data());
        cudaCheckError(cudaMemcpyToSymbol(d_mnemonicsPublicKeysPtr, &d_publicKeysRawPtr, sizeof(extended_public_key_t *)));

        const extended_private_key_t* d_privateKeysRawPtr = thrust::raw_pointer_cast(d_privateKeys.data());
        cudaCheckError(cudaMemcpyToSymbol(d_mnemonicsPrivateKeysPtr, &d_privateKeysRawPtr, sizeof(extended_public_key_t *)));
    }

    void allocateMnemonicsDeviceMemory()
    {
        const uint32_t mnemonicsNumber = getMnemonicsPerIteration();
        d_mnemonics.resize(mnemonicsNumber * SIZE_MNEMONIC_FRAME_12);

        d_mnemonicsSeeds.resize(mnemonicsNumber * (64 / 4));

        const uint32_t* d_mnemonicsSeedsRawPtr = thrust::raw_pointer_cast(d_mnemonicsSeeds.data());
        cudaCheckError(cudaMemcpyToSymbol(d_mnemonicsSeedsPtr, &d_mnemonicsSeedsRawPtr, sizeof(uint32_t *)));

        d_mnemonicsSeedsMasterKeys.resize(mnemonicsNumber);
        const extended_private_key_t* d_mnemonicsSeedsMasterKeysRawPtr = thrust::raw_pointer_cast(d_mnemonicsSeedsMasterKeys.data());
        cudaCheckError(cudaMemcpyToSymbol(d_mnemonicsMasterKeysPtr, &d_mnemonicsSeedsMasterKeysRawPtr, sizeof(extended_private_key_t *)));
    }

    void allocateDerivationPathsDeviceMemory(const std::vector<std::vector<uint32_t>>& derivationPaths)
    {
        h_derivationPaths = derivationPaths;

        // Prepare path data for GPU
        thrust::host_vector<uint32_t> h_derivationPathsLengths;
        thrust::host_vector<uint32_t> h_flattenedDerivationPaths;
        uint32_t maxPathLength = 0;

        for (const auto& path : h_derivationPaths)
        {
            h_derivationPathsLengths.push_back(path.size());
            maxPathLength = std::max(maxPathLength, static_cast<uint32_t>(path.size()));
            h_flattenedDerivationPaths.insert(h_flattenedDerivationPaths.end(), path.begin(), path.end());
        }

        // Create device vectors
        d_flattenedDerivationPaths = h_flattenedDerivationPaths;
        const uint32_t* d_flattenedDerivationPathsRawPtr = thrust::raw_pointer_cast(d_flattenedDerivationPaths.data());
        cudaCheckError(cudaMemcpyToSymbol(d_hdWalletFlattenedDerivationPathsPtr, &d_flattenedDerivationPathsRawPtr, sizeof(uint32_t *)));

        d_derivationPathsLengths = h_derivationPathsLengths;
        const uint32_t* d_derivationPathsLengthsRawPtr = thrust::raw_pointer_cast(d_derivationPathsLengths.data());
        cudaCheckError(cudaMemcpyToSymbol(d_hdWalletDerivationPathsLengthsPtr, &d_derivationPathsLengthsRawPtr, sizeof(uint32_t *)));

        const uint32_t derivationPathsNumber = h_derivationPaths.size();
        cudaCheckError(cudaMemcpyToSymbol(d_hdWalletDerivationPathsNumber, &derivationPathsNumber, sizeof(uint32_t)));
    }

    void init(const std::vector<std::vector<uint32_t>>& derivationPaths, const uint32_t publicKeyCompressionTypeToCheck, const uint32_t gridSize, const uint32_t blockSize)
    {
        computeResolutionForMaxOccupancy(gridSize, blockSize);

        cudaCheckError(cudaMemcpyToSymbol(d_publicKeyCompressionTypeToCheck, &publicKeyCompressionTypeToCheck, sizeof(uint32_t)));

        // Allocate space for derivation paths on device
        allocateDerivationPathsDeviceMemory(derivationPaths);

        // Allocate space for private keys on device
        allocateMnemonicsDeviceMemory();

        // Allocate space for public keys on device
        allocatePrivateAndPublicKeysDeviceMemory(derivationPaths.size());
    }

    void getPublicKeys(std::vector<extended_public_key_t>& publicKeys)
    {
        const uint32_t mnemonicsNumber = getMnemonicsPerIteration();
        publicKeys.resize(mnemonicsNumber * h_derivationPaths.size());

        thrust::copy(d_publicKeys.begin(), d_publicKeys.end(), publicKeys.begin());
    }

    void generatePublicKeysForMnemonics(const uint8_t* mnemonics, const uint32_t mnemonicsNumber)
    {
        constexpr uint32_t mSharedMemSize{0};
        const auto* d_mnemonicsPtr = thrust::raw_pointer_cast(d_mnemonics.data());

        thrust::copy(mnemonics, mnemonics + mnemonicsNumber * SIZE_MNEMONIC_FRAME_12, d_mnemonics.begin());

        cudaCheckError(cudaKernelSyncLaunch(mGeneratorStream, [&]()
        {
            hdWalletKernel<<<mGridSize, mBlockSize, mSharedMemSize, mGeneratorStream>>>(d_mnemonicsPtr);
        }, "hdWalletKernel"));

        cudaCheckError(cudaKernelSyncLaunch(mGeneratorStream, [&]()
        {
            checkExtendedPublicHashKernel <<<mGridSize, mBlockSize, mSharedMemSize, mGeneratorStream>>>();
        }, "checkHashKernel"));
    }

    void generatePublicKeysForMnemonics2(const uint8_t* mnemonics, const uint32_t mnemonicsNumber)
    {
        constexpr uint32_t mSharedMemSize{0};
        const auto* d_mnemonicsPtr = thrust::raw_pointer_cast(d_mnemonics.data());

        thrust::copy(mnemonics, mnemonics + mnemonicsNumber * SIZE_MNEMONIC_FRAME_12, d_mnemonics.begin());

        cudaCheckError(cudaKernelSyncLaunch(mGeneratorStream, [&]()
        {
            mnemonicsToExtendedMasterKeys<<<mGridSize, mBlockSize, mSharedMemSize, mGeneratorStream>>>(d_mnemonicsPtr);
        }, "mnemonicsToExtendedMasterKeys"));

        cudaCheckError(cudaKernelSyncLaunch(mGeneratorStream, [&]()
        {
            extendedMasterKeysToDerivatedPublicKeys<<<mGridSize, mBlockSize, mSharedMemSize, mGeneratorStream>>>();
        }, "extendedMasterKeysToDerivatedPublicKeys"));

        cudaCheckError(cudaKernelSyncLaunch(mGeneratorStream, [&]()
        {
            checkExtendedPublicHashKernel <<<mGridSize, mBlockSize, mSharedMemSize, mGeneratorStream>>>();
        }, "checkHashKernel"));
    }
};

CUHDWallet::CUHDWallet() : mImpl(std::make_unique<Impl>()) {}
CUHDWallet::~CUHDWallet() = default;

CUHDWallet::CUHDWallet(CUHDWallet&& rhs) noexcept = default;
CUHDWallet& CUHDWallet::operator=(CUHDWallet &&rhs) noexcept = default;

void CUHDWallet::init(const std::vector<std::vector<uint32_t>>& derivationPaths, uint32_t publicKeyCompressionTypeToCheck, const uint32_t gridSize, uint32_t blockSize) const
{
    mImpl->init(derivationPaths, publicKeyCompressionTypeToCheck, gridSize, blockSize);
}

void CUHDWallet::generatePublicKeysForMnemonics(const uint8_t* mnemonics, uint32_t mnemonicsNumber) const
{
    mImpl->generatePublicKeysForMnemonics(mnemonics, mnemonicsNumber);
}

uint32_t CUHDWallet::getMnemonicsPerIteration() const
{
    return mImpl->getMnemonicsPerIteration();
}

void CUHDWallet::getPublicKeys(std::vector<extended_public_key_t>& publicKeys) const
{
    return mImpl->getPublicKeys(publicKeys);
}
