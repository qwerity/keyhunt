#include "hd_wallet.cuh"
#include "hd_wallet_kernels.cuh"
#include "ecc_helper.cuh"
#include "udevice_vector.cuh"

#include "defines.h"

struct CUHDWallet::Impl
{
    HDWalletGenerationMode mGenerationMode{HDWalletGenerationMode::MnemonicMasterKey};

    cudaStream_t mGeneratorStream{};

    uint32_t mGridSize{32};
    uint32_t mBlockSize{512};
    uint32_t maxDataPerIteration{mGridSize * mBlockSize};

    thrust::udevice_vector<HDExtendedPublicKey> d_publicKeys;
    thrust::udevice_vector<HDExtendedPrivateKey> d_privateKeys;
    thrust::udevice_vector<uint8_t> d_mnemonics;
    thrust::udevice_vector<uint32_t> d_mnemonicsSeeds;
    thrust::udevice_vector<HDExtendedPrivateKey> d_mnemonicsMasterKeys;

    std::vector<std::vector<uint32_t>> h_derivationPaths;
    thrust::udevice_vector<uint32_t> d_flattenedDerivationPaths;
    thrust::udevice_vector<uint32_t> d_derivationPathsLengths;

    thrust::udevice_vector<HDExtendedPrivateKey> d_intermediatePrivateKeys;

    Impl()
    {
        cudaStreamCreate(&mGeneratorStream);
    }
    ~Impl()
    {
        cudaStreamDestroy(mGeneratorStream);
    }

    [[nodiscard]] uint32_t getMaxDataPerIteration() const
    {
        return maxDataPerIteration;
    }

    void computeResolutionForMaxOccupancy(const uint32_t gridSize, const uint32_t blockSize)
    {
        int minGridSize{};
        int recommendedBlockSize{};

        switch (mGenerationMode)
        {
            case HDWalletGenerationMode::Mnemonic:
                cudaCheckError(cudaOccupancyMaxPotentialBlockSize(&minGridSize, &recommendedBlockSize, hdWalletKernel));
            break;
            case HDWalletGenerationMode::MnemonicsStepByStep:
                cudaCheckError(cudaOccupancyMaxPotentialBlockSize(&minGridSize, &recommendedBlockSize, extendedMasterKeysToDerivatedPublicKeysKernel));
            break;
            case HDWalletGenerationMode::MnemonicsBTC:
                cudaCheckError(cudaOccupancyMaxPotentialBlockSize(&minGridSize, &recommendedBlockSize, hdWalletBTCKernel));
            break;
            case HDWalletGenerationMode::MnemonicMasterKey:
                cudaCheckError(cudaOccupancyMaxPotentialBlockSize(&minGridSize, &recommendedBlockSize, extendedMasterKeysToDerivatedPublicKeysKernel));
            break;
            default:
                printf("CUHDWallet: generation mode is wrong: %d", static_cast<int>(mGenerationMode));
        }

        mBlockSize = (blockSize != 0) ? blockSize : recommendedBlockSize;
        mGridSize = (gridSize != 0) ? gridSize : minGridSize;

        maxDataPerIteration = mGridSize * mBlockSize;
        std::fprintf(stderr, "minGridSize: %d, recommendedBlockSize: %d, set blockSize: %u, gridSize: %u, mnemonicsPerIteration: %u\n", minGridSize, recommendedBlockSize, mBlockSize, mGridSize, maxDataPerIteration);
    }

    void allocatePrivateAndPublicKeysDeviceMemory(const uint32_t derivationPathsNumber)
    {
        const uint32_t mnemonicsNumber = getMaxDataPerIteration();
        d_publicKeys.resize(mnemonicsNumber * derivationPathsNumber);
        d_privateKeys.resize(mnemonicsNumber * derivationPathsNumber);

        const HDExtendedPublicKey* d_publicKeysRawPtr = thrust::raw_pointer_cast(d_publicKeys.data());
        cudaCheckError(cudaMemcpyToSymbol(d_mnemonicsPublicKeysPtr, &d_publicKeysRawPtr, sizeof(HDExtendedPublicKey *)));

        const HDExtendedPrivateKey* d_privateKeysRawPtr = thrust::raw_pointer_cast(d_privateKeys.data());
        cudaCheckError(cudaMemcpyToSymbol(d_mnemonicsPrivateKeysPtr, &d_privateKeysRawPtr, sizeof(HDExtendedPublicKey *)));
    }

    void allocateMnemonicsDeviceMemory()
    {
        const uint32_t mnemonicsNumber = getMaxDataPerIteration();
        d_mnemonics.resize(mnemonicsNumber * SIZE_MNEMONIC_FRAME_12);

        d_mnemonicsSeeds.resize(mnemonicsNumber * SIZE32_SHA512_HMAC);

        const uint32_t* d_mnemonicsSeedsRawPtr = thrust::raw_pointer_cast(d_mnemonicsSeeds.data());
        cudaCheckError(cudaMemcpyToSymbol(d_mnemonicsSeedsPtr, &d_mnemonicsSeedsRawPtr, sizeof(uint32_t *)));

        d_mnemonicsMasterKeys.resize(mnemonicsNumber);
        const HDExtendedPrivateKey* d_mnemonicsMasterKeysRawPtr = thrust::raw_pointer_cast(d_mnemonicsMasterKeys.data());
        cudaCheckError(cudaMemcpyToSymbol(d_mnemonicsMasterKeysPtr, &d_mnemonicsMasterKeysRawPtr, sizeof(HDExtendedPrivateKey *)));
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

    void init(const HDWalletGenerationMode generationMode, const std::vector<std::vector<uint32_t>>& derivationPaths, const uint32_t accountsToGenerate, const uint32_t addressesToGenerate, const uint32_t publicKeyCompressionTypeToCheck, const uint32_t gridSize, const uint32_t blockSize)
    {
        mGenerationMode = generationMode;

        computeResolutionForMaxOccupancy(gridSize, blockSize);

        if (mGenerationMode == HDWalletGenerationMode::MnemonicsBTC)
        {
            cudaCheckError(cudaMemcpyToSymbol(d_hdWalletAccountsToGenerate, &accountsToGenerate, sizeof(uint32_t)));
            cudaCheckError(cudaMemcpyToSymbol(d_hdWalletAddressesToGenerate, &addressesToGenerate, sizeof(uint32_t)));

            const uint32_t mnemonicsNumber = getMaxDataPerIteration();
            d_intermediatePrivateKeys.resize(mnemonicsNumber * accountsToGenerate * addressesToGenerate);
            const HDExtendedPrivateKey* d_mnemonicsIntermediatePrivateKeysRawPtr = thrust::raw_pointer_cast(d_intermediatePrivateKeys.data());
            cudaCheckError(cudaMemcpyToSymbol(d_mnemonicsIntermediatePrivateKeysPtr, &d_mnemonicsIntermediatePrivateKeysRawPtr, sizeof(HDExtendedPrivateKey *)));
        }

        cudaCheckError(cudaMemcpyToSymbol(d_publicKeyCompressionTypeToCheck, &publicKeyCompressionTypeToCheck, sizeof(uint32_t)));

        // Allocate space for derivation paths on device
        allocateDerivationPathsDeviceMemory(derivationPaths);

        // Allocate space for private keys on device
        allocateMnemonicsDeviceMemory();

        // Allocate space for public keys on device
        allocatePrivateAndPublicKeysDeviceMemory(derivationPaths.size());
    }

    void getPublicKeys(std::vector<HDExtendedPublicKey>& publicKeys)
    {
        const uint32_t mnemonicsNumber = getMaxDataPerIteration();
        publicKeys.resize(mnemonicsNumber * h_derivationPaths.size());

        thrust::copy(d_publicKeys.begin(), d_publicKeys.end(), publicKeys.begin());
    }

    void searchPublicHashFromMnemonics(const uint8_t* mnemonics, const uint32_t mnemonicsNumber)
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

    void searchPublicHashFromMnemonicsStepByStep(const uint8_t* mnemonics, const uint32_t mnemonicsNumber)
    {
        constexpr uint32_t mSharedMemSize{0};
        const auto* d_mnemonicsPtr = thrust::raw_pointer_cast(d_mnemonics.data());

        thrust::copy(mnemonics, mnemonics + mnemonicsNumber * SIZE_MNEMONIC_FRAME_12, d_mnemonics.begin());

        cudaCheckError(cudaKernelSyncLaunch(mGeneratorStream, [&]()
        {
            mnemonicsToExtendedMasterKeysKernel<<<mGridSize, mBlockSize, mSharedMemSize, mGeneratorStream>>>(d_mnemonicsPtr);
        }, "mnemonicsToExtendedMasterKeys"));

        cudaCheckError(cudaKernelSyncLaunch(mGeneratorStream, [&]()
        {
            extendedMasterKeysToDerivatedPublicKeysKernel<<<mGridSize, mBlockSize, mSharedMemSize, mGeneratorStream>>>();
        }, "extendedMasterKeysToDerivatedPublicKeys"));

        cudaCheckError(cudaKernelSyncLaunch(mGeneratorStream, [&]()
        {
            checkExtendedPublicHashKernel <<<mGridSize, mBlockSize, mSharedMemSize, mGeneratorStream>>>();
        }, "checkHashKernel"));
    }

    void masterKeysFromMnemonics(const std::vector<uint8_t>& mnemonics)
    {
        constexpr uint32_t mSharedMemSize{0};
        const auto* d_mnemonicsPtr = thrust::raw_pointer_cast(d_mnemonics.data());

        thrust::copy(mnemonics.begin(), mnemonics.end(), d_mnemonics.begin());

        cudaCheckError(cudaKernelSyncLaunch(mGeneratorStream, [&]()
        {
            mnemonicsToExtendedMasterKeysKernel<<<mGridSize, mBlockSize, mSharedMemSize, mGeneratorStream>>>(d_mnemonicsPtr);
        }, "mnemonicsToExtendedMasterKeys"));
    }

    void searchBTCPublicHashFromMnemonics(const uint8_t* mnemonics, const uint32_t mnemonicsNumber)
    {
        constexpr uint32_t mSharedMemSize{0};
        const auto* d_mnemonicsPtr = thrust::raw_pointer_cast(d_mnemonics.data());

        thrust::copy(mnemonics, mnemonics + mnemonicsNumber * SIZE_MNEMONIC_FRAME_12, d_mnemonics.begin());

        cudaCheckError(cudaKernelSyncLaunch(mGeneratorStream, [&]()
        {
            hdWalletBTCKernel<<<mGridSize, mBlockSize, mSharedMemSize, mGeneratorStream>>>(d_mnemonicsPtr);
        }, "hdWalletKernel"));

        cudaCheckError(cudaKernelSyncLaunch(mGeneratorStream, [&]()
        {
            checkExtendedPublicHashKernel <<<mGridSize, mBlockSize, mSharedMemSize, mGeneratorStream>>>();
        }, "checkHashKernel"));
    }

    void searchPublicHashFromMnemonicsMasterKeys()
    {
        constexpr uint32_t mSharedMemSize{0};
        cudaCheckError(cudaKernelSyncLaunch(mGeneratorStream, [&]()
        {
            extendedMasterKeysToDerivatedPublicKeysKernel<<<mGridSize, mBlockSize, mSharedMemSize, mGeneratorStream>>>();
        }, "extendedMasterKeysToDerivatedPublicKeys"));

        cudaCheckError(cudaKernelSyncLaunch(mGeneratorStream, [&]()
        {
            checkExtendedPublicHashKernel <<<mGridSize, mBlockSize, mSharedMemSize, mGeneratorStream>>>();
        }, "checkHashKernel"));
    }

    void searchPublicHashFromMnemonicsMasterKeys(const std::vector<HDExtendedPrivateKey>& masterKeys)
    {
        auto* mnemonicsMasterKeysPtr = thrust::reinterpret_pointer_cast<uint8_t*>(d_mnemonicsMasterKeys.data());
        cudaMemcpyAsync(mnemonicsMasterKeysPtr, masterKeys.data(), masterKeys.size() * sizeof(HDExtendedPrivateKey), cudaMemcpyHostToDevice, mGeneratorStream);

        searchPublicHashFromMnemonicsMasterKeys();
    }
};

CUHDWallet::CUHDWallet() : mImpl(std::make_unique<Impl>()) {}
CUHDWallet::~CUHDWallet() = default;

CUHDWallet::CUHDWallet(CUHDWallet&& rhs) noexcept = default;
CUHDWallet& CUHDWallet::operator=(CUHDWallet &&rhs) noexcept = default;

void CUHDWallet::init(const HDWalletGenerationMode generationMode, const std::vector<std::vector<uint32_t>>& derivationPaths, const uint32_t accountsToGenerate, const uint32_t addressesToGenerate, uint32_t publicKeyCompressionTypeToCheck, const uint32_t gridSize, uint32_t blockSize) const
{
    mImpl->init(generationMode, derivationPaths, accountsToGenerate, addressesToGenerate, publicKeyCompressionTypeToCheck, gridSize, blockSize);
}

void CUHDWallet::masterKeysFromMnemonics(const std::vector<uint8_t>& mnemonics) const
{
    mImpl->masterKeysFromMnemonics(mnemonics);
}

void CUHDWallet::searchPublicHashFromMnemonics(const uint8_t* mnemonics, const uint32_t mnemonicsNumber) const
{
    switch (mImpl->mGenerationMode)
    {
        case HDWalletGenerationMode::Mnemonic:
            mImpl->searchPublicHashFromMnemonics(mnemonics, mnemonicsNumber);
        break;
        case HDWalletGenerationMode::MnemonicsStepByStep:
            mImpl->searchPublicHashFromMnemonicsStepByStep(mnemonics, mnemonicsNumber);
        break;
        case HDWalletGenerationMode::MnemonicsBTC:
            mImpl->searchBTCPublicHashFromMnemonics(mnemonics, mnemonicsNumber);
        break;
        default:
            printf("CUHDWallet: generation mode is wrong: %d", static_cast<int>(mImpl->mGenerationMode));
    }
}

void CUHDWallet::searchPublicHashFromMnemonicsMasterKeys() const
{
    mImpl->searchPublicHashFromMnemonicsMasterKeys();
}

void CUHDWallet::searchPublicHashFromMnemonicsMasterKeys(const std::vector<HDExtendedPrivateKey>& masterKeys) const
{
    mImpl->searchPublicHashFromMnemonicsMasterKeys(masterKeys);
}

uint32_t CUHDWallet::getMaxDataPerIteration() const
{
    return mImpl->getMaxDataPerIteration();
}

void CUHDWallet::getPublicKeys(std::vector<HDExtendedPublicKey>& publicKeys) const
{
    return mImpl->getPublicKeys(publicKeys);
}
