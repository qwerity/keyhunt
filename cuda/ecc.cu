#include "ecc.cuh"

#include "udevice_vector.cuh"
#include "ecc_helper.cuh"
#include "functors.cuh"
#include "secp256k1_v2/secp256k1_defines.cuh"

#include "defines.h"
#include "../util/secp256k1.h"

#include <fstream>
#include <string>
#include <algorithm>
#include <cstdio>
#include <cuda_runtime.h>

extern __constant__ int d_publicKeyCompressionTypeToCheck;

__constant__ uint32_t d_pointsPerThread{};

__constant__ uint256_t *d_publicKeyXPtr{};
__constant__ uint256_t *d_publicKeyYPtr{};

// External declaration of secp256k1_N defined in ecc_helper.cu
extern __constant__ uint256_t secp256k1_N;

extern __device__ const secp256k1_ge_storage* d_gTable_ptr;

extern __constant__ const uint64_t* d_gTableX_4limb_ptr;
extern __constant__ const uint64_t* d_gTableY_4limb_ptr;

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

    thrust::udevice_vector<secp256k1_ge_storage> d_gTable;
    thrust::udevice_vector<uint64_t> d_gTableX_4limb;
    thrust::udevice_vector<uint64_t> d_gTableY_4limb;

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

    void computeResolutionForMaxOccupancy(const uint32_t pointsPerThread, const uint32_t gridSize, const uint32_t blockSize = 0)
    {
        setPointsPerThread(pointsPerThread);

        // Use the kernel we actually run (fused) for occupancy — it uses more registers than publicKeyGenerationKernel
        int minGridSizeFused{};
        int recommendedBlockSizeFused{};
        cudaCheckError(cudaOccupancyMaxPotentialBlockSize(&minGridSizeFused, &recommendedBlockSizeFused, publicKeyAndCheckHash160FusedKernel));

        const uint32_t actualBlockSize = (blockSize != 0) ? blockSize : static_cast<uint32_t>(recommendedBlockSizeFused);

        if (gridSize != 0)
        {
            mGridSize = gridSize;
            mBlockSize = actualBlockSize;
        }
        else
        {
            mBlockSize = actualBlockSize;

            cudaDeviceProp deviceProp{};
            int deviceId{};
            cudaCheckError(cudaGetDevice(&deviceId));
            cudaCheckError(cudaGetDeviceProperties(&deviceProp, deviceId));

            int numBlocksPerSM{};
            const int dynamicSMemSize = 0;
            cudaCheckError(cudaOccupancyMaxActiveBlocksPerMultiprocessor(
                &numBlocksPerSM,
                publicKeyAndCheckHash160FusedKernel,
                mBlockSize,
                dynamicSMemSize));

            const int optimalGridSize = deviceProp.multiProcessorCount * numBlocksPerSM;
            mGridSize = static_cast<uint32_t>(std::max(minGridSizeFused, optimalGridSize));

            fprintf(stdout, "[GPU %d] Device: %s, SMs: %d, Blocks/SM: %d (fused kernel), minGridSize: %d, optimalGridSize: %d, using gridSize: %u, blockSize: %u\n",
                    deviceId, deviceProp.name, deviceProp.multiProcessorCount, numBlocksPerSM,
                    minGridSizeFused, optimalGridSize, mGridSize, mBlockSize);
        }

        mKeysNumberPerIteration = mGridSize * mBlockSize * mPointsPerThread;
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

    [[nodiscard]] inline uint32_t getKeysNumberPerIteration() const
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

    void getPublicKeys(std::vector<uint256_t>& h_publicKeysX, std::vector<uint256_t>& h_publicKeysY) const
    {
        thrust::host_vector<uint256_t> thrust_x = d_publicKeysX;
        thrust::host_vector<uint256_t> thrust_y = d_publicKeysY;
        
        h_publicKeysX.assign(thrust_x.begin(), thrust_x.end());
        h_publicKeysY.assign(thrust_y.begin(), thrust_y.end());
    }

    void setPrivateKeys(const std::vector<uint256_t>& h_privateKeys)
    {
        if (h_privateKeys.size() != d_privateKeys.size())
        {
            throw std::runtime_error("Private keys size mismatch");
        }
        
        thrust::copy(h_privateKeys.begin(), h_privateKeys.end(), d_privateKeys.begin());
    }

    void generatePrivateKeysForXPerIteration(const uint32_t privateXPart, const uint32_t iteration)
    {
        const uint32_t keysNumberPerIteration = getKeysNumberPerIteration();

        if (d_privateKeys.size() != keysNumberPerIteration)
        {
            throw std::runtime_error("Private keys device storage has wrong size");
        }

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

    static void convertUint256ToFeStorage(const secp256k1::uint256& src, secp256k1_fe_storage& dst)
    {
        for (int i = 0; i < 8; ++i)
        {
            dst.n[i] = src.v[i];
        }
    }

    static void convertEcpointToGeStorage(const secp256k1::ecpoint& src, secp256k1_ge_storage& dst)
    {
        convertUint256ToFeStorage(src.x, dst.x);
        convertUint256ToFeStorage(src.y, dst.y);
    }

    // Convert one GTable point (secp256k1_ge_storage) to 4-limb format: 4 uint64_t for X, 4 for Y (fe_storage n[0]..n[7] = LSW..MSW)
    static void convertGeStorageTo4limb(const secp256k1_ge_storage& st, uint64_t xOut[4], uint64_t yOut[4])
    {
        for (int j = 0; j < 4; j++) {
            xOut[j] = static_cast<uint64_t>(st.x.n[2 * j]) | (static_cast<uint64_t>(st.x.n[2 * j + 1]) << 32);
            yOut[j] = static_cast<uint64_t>(st.y.n[2 * j]) | (static_cast<uint64_t>(st.y.n[2 * j + 1]) << 32);
        }
    }

    void uploadGTable4limb(const std::vector<secp256k1_ge_storage>& h_gTable)
    {
        const uint32_t tableSize = static_cast<uint32_t>(h_gTable.size());
        const size_t limbsPerPoint = 4;
        std::vector<uint64_t> h_x(tableSize * limbsPerPoint);
        std::vector<uint64_t> h_y(tableSize * limbsPerPoint);
        for (uint32_t i = 0; i < tableSize; i++) {
            uint64_t x4[4], y4[4];
            convertGeStorageTo4limb(h_gTable[i], x4, y4);
            for (int j = 0; j < 4; j++) {
                h_x[i * 4 + j] = x4[j];
                h_y[i * 4 + j] = y4[j];
            }
        }
        thrust::copy(h_x.begin(), h_x.end(), d_gTableX_4limb.begin());
        thrust::copy(h_y.begin(), h_y.end(), d_gTableY_4limb.begin());
    }

    bool loadGTableFromFile(const std::string& filename)
    {
        constexpr uint32_t tableSize = ECMULT_GEN_PREC_N * ECMULT_GEN_PREC_G;
        constexpr size_t expectedFileSize = tableSize * sizeof(secp256k1_ge_storage);
        
        std::ifstream file(filename, std::ios::binary | std::ios::ate);
        if (!file.is_open())
        {
            return false;
        }
        
        // Check file size
        const size_t fileSize = file.tellg();
        if (fileSize != expectedFileSize)
        {
            fprintf(stderr, "Warning: gTable file size mismatch. Expected %zu bytes, got %zu bytes. Will regenerate.\n", 
                    expectedFileSize, fileSize);
            file.close();
            return false;
        }
        
        // Read the table
        file.seekg(0, std::ios::beg);
        std::vector<secp256k1_ge_storage> h_gTable(tableSize);
        file.read(reinterpret_cast<char*>(h_gTable.data()), expectedFileSize);
        
        if (!file.good() || file.gcount() != static_cast<std::streamsize>(expectedFileSize))
        {
            fprintf(stderr, "Warning: Failed to read gTable from file. Will regenerate.\n");
            file.close();
            return false;
        }
        
        file.close();
        
        // Copy to device memory
        thrust::copy(h_gTable.begin(), h_gTable.end(), d_gTable.begin());
        uploadGTable4limb(h_gTable);
        fprintf(stdout, "Successfully loaded gTable from file: %s (%zu bytes)\n", filename.c_str(), fileSize);
        return true;
    }

    void generateGTable()
    {
        constexpr uint32_t tableSize = ECMULT_GEN_PREC_N * ECMULT_GEN_PREC_G;
        std::vector<secp256k1_ge_storage> h_gTable(tableSize);
        
        fprintf(stdout, "Generating gTable (this may take a while)...\n");
        
        secp256k1::ecpoint basePoint = secp256k1::G();
        
        for (uint32_t chunk = 0; chunk < ECMULT_GEN_PREC_N; ++chunk)
        {
            if (chunk % 2 == 0)
            {
                fprintf(stdout, "Generating chunk %u/%u\n", chunk, ECMULT_GEN_PREC_N);
            }
            
            secp256k1::ecpoint chunkBasePoint = basePoint;
            
            for (uint32_t i = 0; i < chunk * ECMULT_GEN_PREC_B; ++i)
            {
                chunkBasePoint = secp256k1::doublePoint(chunkBasePoint);
            }
            
            secp256k1::ecpoint currentPoint = chunkBasePoint;
            const uint32_t chunkOffset = chunk * ECMULT_GEN_PREC_G;
            
            convertEcpointToGeStorage(currentPoint, h_gTable[chunkOffset + 0]);
            
            for (uint32_t k = 2; k <= ECMULT_GEN_PREC_G; ++k)
            {
                currentPoint = secp256k1::addPoints(currentPoint, chunkBasePoint);
                convertEcpointToGeStorage(currentPoint, h_gTable[chunkOffset + (k - 1)]);
            }
        }
        
        thrust::copy(h_gTable.begin(), h_gTable.end(), d_gTable.begin());
        uploadGTable4limb(h_gTable);
        fprintf(stdout, "gTable generation completed!\n");
    }

    void allocateGTableDeviceMemory()
    {
        constexpr uint32_t tableSize = ECMULT_GEN_PREC_N * ECMULT_GEN_PREC_G;
        constexpr uint32_t limbsPerPoint = 4;
        d_gTable.resize(tableSize);
        d_gTableX_4limb.resize(tableSize * limbsPerPoint);
        d_gTableY_4limb.resize(tableSize * limbsPerPoint);
        // Try to load from file first
        const std::string defaultFilename = "gtables.bin";
        if (!loadGTableFromFile(defaultFilename))
        {
            // If loading failed, generate the table
            generateGTable();
        }
    }

    void init(const uint32_t pointsPerThread, const uint32_t publicKeyCompressionTypeToCheck, const uint32_t gridSize, const uint32_t blockSize)
    {
        // From examples: L1 cache helps random GTable access; larger stack for deep kernel frames
        cudaCheckError(cudaDeviceSetCacheConfig(cudaFuncCachePreferL1));
        cudaCheckError(cudaDeviceSetLimit(cudaLimitStackSize, 32768));

        computeResolutionForMaxOccupancy(pointsPerThread, gridSize, blockSize);

        cudaCheckError(cudaMemcpyToSymbol(d_publicKeyCompressionTypeToCheck, &publicKeyCompressionTypeToCheck, sizeof(uint32_t)));

        // Initialize secp256k1 group order N
        constexpr uint256_t secp256k1_N_host = {
            SECP256K1_N_0, SECP256K1_N_1, SECP256K1_N_2, SECP256K1_N_3,
            SECP256K1_N_4, SECP256K1_N_5, SECP256K1_N_6, SECP256K1_N_7
        };
        cudaCheckError(cudaMemcpyToSymbol(secp256k1_N, &secp256k1_N_host, sizeof(uint256_t)));

        allocateGTableDeviceMemory();
        allocatePrivateKeysDeviceMemory();
        allocatePublicKeysDeviceMemory();
    }

    void calculatePublicKeysAndCheckHash160()
    {
        // Copy gTable pointer for fillPublicKeys (secp256k1 path)
        const secp256k1_ge_storage* d_gTableRawPtr = thrust::raw_pointer_cast(d_gTable.data());
        cudaCheckError(cudaMemcpyToSymbol(d_gTable_ptr, &d_gTableRawPtr, sizeof(secp256k1_ge_storage*)));
        // 4-limb GTable pointers for fused kernel
        const uint64_t* d_gTableXRaw = thrust::raw_pointer_cast(d_gTableX_4limb.data());
        const uint64_t* d_gTableYRaw = thrust::raw_pointer_cast(d_gTableY_4limb.data());
        cudaCheckError(cudaMemcpyToSymbol(d_gTableX_4limb_ptr, &d_gTableXRaw, sizeof(uint64_t*)));
        cudaCheckError(cudaMemcpyToSymbol(d_gTableY_4limb_ptr, &d_gTableYRaw, sizeof(uint64_t*)));

        // Fused kernel (4-limb): public key + hash + check in one pass
        constexpr uint32_t mSharedMemSize{0};
        const uint256_t *privateKeysPtr = thrust::raw_pointer_cast(d_privateKeys.data());
        publicKeyAndCheckHash160FusedKernel <<<mGridSize, mBlockSize, mSharedMemSize, mGeneratorStream>>>(privateKeysPtr);
        cudaError_t err = cudaGetLastError();
        if (err != cudaSuccess)
        {
            fprintf(stderr, "publicKeyAndCheckHash160FusedKernel: CUDA error: %s\n", cudaGetErrorString(err));
        }
        cudaError_t syncErr = cudaStreamSynchronize(mGeneratorStream);
        if (syncErr != cudaSuccess)
        {
            fprintf(stderr, "calculatePublicKeysAndCheckHash160: CUDA sync error: %s\n", cudaGetErrorString(syncErr));
            cudaCheckError(syncErr);
        }
    }

    void fillPublicKeys()
    {
        constexpr uint256_t infinite{0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF};
        thrust::fill(thrust::cuda_cub::par.on(mGeneratorStream), d_publicKeysX.begin(), d_publicKeysX.end(), infinite);
        thrust::fill(thrust::cuda_cub::par.on(mGeneratorStream), d_publicKeysY.begin(), d_publicKeysY.end(), infinite);
        const secp256k1_ge_storage* d_gTableRawPtr = thrust::raw_pointer_cast(d_gTable.data());
        cudaCheckError(cudaMemcpyToSymbol(d_gTable_ptr, &d_gTableRawPtr, sizeof(secp256k1_ge_storage*)));
        constexpr uint32_t mSharedMemSize{0};
        const uint256_t *privateKeysPtr = thrust::raw_pointer_cast(d_privateKeys.data());
        publicKeyGenerationKernel <<<mGridSize, mBlockSize, mSharedMemSize, mGeneratorStream>>>(privateKeysPtr);
        cudaCheckError(cudaStreamSynchronize(mGeneratorStream));
    }
};

ECC::ECC() : mImpl(std::make_unique<Impl>()) {}
ECC::~ECC() = default;

ECC::ECC(ECC&& rhs) noexcept = default;
ECC& ECC::operator=(ECC &&rhs) noexcept = default;

void ECC::init(const uint32_t pointsPerThread, const uint32_t publicKeyCompressionTypeToCheck, const uint32_t gridSize, const uint32_t blockSize) const
{
    mImpl->init(pointsPerThread, publicKeyCompressionTypeToCheck, gridSize, blockSize);
}

uint32_t ECC::getKeysNumberPerIteration() const
{
    return mImpl->getKeysNumberPerIteration();
}

void ECC::calculatePublicKeysAndCheckHash160() const
{
    mImpl->calculatePublicKeysAndCheckHash160();
}

void ECC::fillPublicKeys() const
{
    mImpl->fillPublicKeys();
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

void ECC::getPublicKeys(std::vector<uint256_t>& h_publicKeysX, std::vector<uint256_t>& h_publicKeysY) const
{
    mImpl->getPublicKeys(h_publicKeysX, h_publicKeysY);
}

void ECC::setPrivateKeys(const std::vector<uint256_t>& h_privateKeys) const
{
    mImpl->setPrivateKeys(h_privateKeys);
}
