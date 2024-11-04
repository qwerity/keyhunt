#include "hd_wallet.cuh"
#include "udevice_vector.cuh"
#include "defines.cuh"

#include "secp256k1_v2/bip39.cuh"

#include "util/common.h"

#include <cstdint>

#include <cuda_runtime.h>

extern __constant__ int d_publicKeyCompressionTypeToCheck;

__constant__ extended_public_key_t* d_publicKeysPtr{};

__constant__ uint32_t* d_flattenedDerivationPathsPtr{};
__constant__ uint32_t* d_derivationPathsLengthsPtr{};
__constant__ uint32_t  d_derivationPathsNumber{};


struct HDWalletFunctor
{
    const uint8_t* mnemonics;

    __host__ __device__
    explicit HDWalletFunctor(const uint8_t* _mnemonics): mnemonics(_mnemonics)
    {}

    __device__
    void operator()(const uint32_t mnemonicIdx) const
    {
        // Get pointer to this thread's mnemonic and output area
        const uint8_t* mnemonic = mnemonics + (mnemonicIdx * SIZE_MNEMONIC_FRAME);
        extended_public_key_t* threadOutputs = d_publicKeysPtr + (mnemonicIdx * d_derivationPathsNumber);

        // Generate master key once for this mnemonic
        uint32_t seed[64 / 4]{};
        extended_private_key_t masterKey;
        mnemonicToExtendedMasterKey(mnemonic, seed, reinterpret_cast<uint8_t*>(&masterKey));

        // Process all paths for this mnemonic
        uint32_t pathOffset = 0;
        for (uint32_t pathIdx = 0; pathIdx < d_derivationPathsNumber; pathIdx++)
        {
            extended_private_key_t privateKey = masterKey;  // Start from master key
            extended_private_key_t tempKey;

            // Derive through current path
            for (uint32_t i = 0; i < d_derivationPathsLengthsPtr[pathIdx]; ++i)
            {
                uint32_t childIndex = d_flattenedDerivationPathsPtr[pathOffset + i];
                if (childIndex & 0x80000000)
                {
                    hardenedPrivateChildFromPrivate(&privateKey, &tempKey, childIndex & 0x7FFFFFFF);
                }
                else
                {
                    normalPrivateChildFromPrivate(&privateKey, &tempKey, childIndex);
                }
                privateKey = tempKey;
            }

            // Generate public key for this path
            generatePublicFromPrivateKey(&privateKey, &threadOutputs[pathIdx]);

            // Move to next path
            pathOffset += d_derivationPathsLengthsPtr[pathIdx];
        }
    }
};

__global__ void hdWalletKernel(const uint8_t* mnemonics, const uint32_t numMnemonics)
{
    uint32_t mnemonicIdx = blockDim.x * blockIdx.x + threadIdx.x;
    //if (mnemonicIdx >= numMnemonics) return;

    // Get pointer to this thread's mnemonic and output area
    const uint8_t* mnemonic = mnemonics + (mnemonicIdx * SIZE_MNEMONIC_FRAME);
    extended_public_key_t* mnemonicPublicKeys = d_publicKeysPtr + (mnemonicIdx * d_derivationPathsNumber);

    // Generate master key once for this mnemonic
    uint32_t seed[64 / 4]{};
    extended_private_key_t masterKey;
    mnemonicToExtendedMasterKey(mnemonic, seed, reinterpret_cast<uint8_t*>(&masterKey));

    // Process all paths for this mnemonic
    uint32_t pathOffset = 0;
    for (uint32_t pathIdx = 0; pathIdx < d_derivationPathsNumber; ++pathIdx)
    {
        extended_private_key_t privateKey = masterKey;  // Start from master key
        extended_private_key_t tempKey;

        // Derive through current path
        for (uint32_t i = 0; i < d_derivationPathsLengthsPtr[pathIdx]; ++i)
        {
            uint32_t childIndex = d_flattenedDerivationPathsPtr[pathOffset + i];
            if (childIndex & 0x80000000)
            {
                hardenedPrivateChildFromPrivate(&privateKey, &tempKey, childIndex & 0x7FFFFFFF);
            }
            else
            {
                normalPrivateChildFromPrivate(&privateKey, &tempKey, childIndex);
            }
            privateKey = tempKey;
        }

        // Generate public key for this path
        generatePublicFromPrivateKey(&privateKey, &mnemonicPublicKeys[pathIdx]);

        // Move to next path
        pathOffset += d_derivationPathsLengthsPtr[pathIdx];
    }
}

struct CUHDWallet::Impl
{
    cudaStream_t mGeneratorStream{};

    uint32_t mGridSize{32};
    uint32_t mBlockSize{512};
    uint32_t mnemonicsPerIteration{mGridSize * mBlockSize};

    thrust::udevice_vector<extended_public_key_t> d_publicKeys;
    thrust::udevice_vector<uint8_t> d_mnemonics;

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

    void allocatePublicKeysDeviceMemory(const uint32_t derivationPathsNumber)
    {
        const uint32_t mnemonicsNumber = getMnemonicsPerIteration();
        d_publicKeys.resize(mnemonicsNumber * derivationPathsNumber);

        const extended_public_key_t* d_publicKeysRawPtr = thrust::raw_pointer_cast(d_publicKeys.data());
        cudaCheckError(cudaMemcpyToSymbol(d_publicKeysPtr, &d_publicKeysRawPtr, sizeof(extended_public_key_t *)));
    }

    void allocateMnemonicsDeviceMemory()
    {
        const uint32_t mnemonicsNumber = getMnemonicsPerIteration();
        d_mnemonics.resize(mnemonicsNumber * SIZE_MNEMONIC_FRAME);
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
        cudaCheckError(cudaMemcpyToSymbol(d_flattenedDerivationPathsPtr, &d_flattenedDerivationPathsRawPtr, sizeof(uint32_t *)));

        d_derivationPathsLengths = h_derivationPathsLengths;
        const uint32_t* d_derivationPathsLengthsRawPtr = thrust::raw_pointer_cast(d_derivationPathsLengths.data());
        cudaCheckError(cudaMemcpyToSymbol(d_derivationPathsLengthsPtr, &d_derivationPathsLengthsRawPtr, sizeof(uint32_t *)));

        const uint32_t derivationPathsNumber = h_derivationPaths.size();
        cudaCheckError(cudaMemcpyToSymbol(d_derivationPathsNumber, &derivationPathsNumber, sizeof(uint32_t)));
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
        allocatePublicKeysDeviceMemory(derivationPaths.size());
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

        thrust::copy(mnemonics, mnemonics + mnemonicsNumber * SIZE_MNEMONIC_FRAME, d_mnemonics.begin());

        cudaCheckError(cudaKernelSyncLaunch(mGeneratorStream, [&]()
        {
            hdWalletKernel<<<mGridSize, mBlockSize, mSharedMemSize, mGeneratorStream>>>(d_mnemonicsPtr, mnemonicsNumber);
        }, "hdWalletKernel"));
    }

    void generatePublicKeysForMnemonicsThrust(const uint8_t* mnemonics, const uint32_t mnemonicsNumber)
    {
        // Create device vectors
        thrust::copy(mnemonics, mnemonics + mnemonicsNumber * SIZE_MNEMONIC_FRAME, d_mnemonics.begin());

        const auto* d_mnemonicsPtr = thrust::raw_pointer_cast(d_mnemonics.data());
        cudaCheckError(cudaKernelSyncLaunch(mGeneratorStream, [&]()
        {
            // Create counting iterator for mnemonic indices
            thrust::counting_iterator<uint32_t> indexBegin(0);

            // Create functor and run it using thrust::for_each
            thrust::for_each(thrust::cuda_cub::par,
                             indexBegin,
                             indexBegin + mnemonicsNumber,
                             HDWalletFunctor(thrust::raw_pointer_cast(d_mnemonics.data()))
            );
        }, "HDWalletFunctor"));
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

void CUHDWallet::generatePublicKeysForMnemonicsThrust(const uint8_t* mnemonics, uint32_t mnemonicsNumber) const
{
    mImpl->generatePublicKeysForMnemonicsThrust(mnemonics, mnemonicsNumber);
}

uint32_t CUHDWallet::getMnemonicsPerIteration() const
{
    return mImpl->getMnemonicsPerIteration();
}

void CUHDWallet::getPublicKeys(std::vector<extended_public_key_t>& publicKeys)
{
    return mImpl->getPublicKeys(publicKeys);
}
