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
__constant__ uint32_t d_seedPairsPerThread{};

__constant__ uint256_t *d_publicKeyXPtr{};
__constant__ uint256_t *d_publicKeyYPtr{};

// External declaration of secp256k1_N defined in ecc_helper.cu
extern __constant__ uint256_t secp256k1_N;

extern __device__ const secp256k1_ge_storage* d_gTable_ptr;

extern __constant__ const uint64_t* d_gTableX_4limb_ptr;
extern __constant__ const uint64_t* d_gTableY_4limb_ptr;

/** Async keygen: same logic as Thrust transform, no host sync. Use in pregenerateKeysAsync. */
__global__ void privateKeysForXKernel(uint32_t xPart, uint32_t yPartIncrementBy, uint256_t* __restrict__ out, uint32_t n)
{
    uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= n) return;
    PrivateKeyForXWithRandomYFunctor f(xPart, yPartIncrementBy);
    out[i] = f(i);
}

/** Async keygen: writes first/original key to out[i] and second key to out[n+i].
 *  Buffer must be sized 2n. Use when generator mode selects generatePrivateKeyBase2. */
__global__ void privateKeysForXKernel2(uint32_t xPart, uint32_t yPartIncrementBy, uint256_t* __restrict__ out, uint32_t n)
{
    uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= n) return;
    uint2 p;
    p.x = xPart;
    p.y = i + yPartIncrementBy;
    generatePrivateKeyBase2(p, out[i], out[n + i]);
}

struct ECC::Impl
{
    struct SeedLaunchMeta
    {
        uint32_t privateXPart{0};
        uint32_t yPartIncrementBy{0};
        bool valid{false};
    };

    cudaStream_t mGeneratorStream{};
    cudaStream_t mInitStream{};

    uint32_t mGridSize{32};
    uint32_t mBlockSize{512};
    uint32_t mPointsPerThread{32};
    uint32_t mGeneratorMode{1};

    uint32_t mKeysNumberPerIteration{mGridSize * mBlockSize * mPointsPerThread};

    thrust::udevice_vector<uint256_t> d_publicKeysX;
    thrust::udevice_vector<uint256_t> d_publicKeysY;

    // Double-buffer: kernel reads from d_privateKeys[mCurBuf],
    // key-gen writes to d_privateKeys[1 - mCurBuf].
    thrust::udevice_vector<uint256_t> d_privateKeys[2];
    int mCurBuf{0};  // index currently in use by the kernel
    SeedLaunchMeta mSeedLaunchMeta[2];

    // Legacy alias for old single-buffer path (points to d_privateKeys[mCurBuf])
    thrust::udevice_vector<uint256_t>& d_privateKeysCur() { return d_privateKeys[mCurBuf]; }
    thrust::udevice_vector<uint256_t>& d_privateKeysNext() { return d_privateKeys[1 - mCurBuf]; }

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
        release(d_privateKeys[0]);
        release(d_privateKeys[1]);
        release(d_publicKeysX);
        release(d_publicKeysY);

        cudaStreamDestroy(mGeneratorStream);
        cudaStreamDestroy(mInitStream);
    }

    [[nodiscard]] uint32_t generatedKeysMultiplier() const
    {
        return (mGeneratorMode == 2) ? 2u : 1u;
    }

    void setPointsPerThread(const uint32_t value)
    {
        mPointsPerThread = value;
        const uint32_t effectivePPT = generatedKeysMultiplier() * mPointsPerThread;
        cudaCheckError(cudaMemcpyToSymbol(d_seedPairsPerThread, &mPointsPerThread, sizeof(uint32_t)));
        cudaCheckError(cudaMemcpyToSymbol(d_pointsPerThread, &effectivePPT, sizeof(uint32_t)));
    }

    void computeResolutionForMaxOccupancy(const uint32_t pointsPerThread, const uint32_t gridSize, const uint32_t blockSize = 0)
    {
        setPointsPerThread(pointsPerThread);

        // Use the kernel we actually run (fused) for occupancy — it uses more registers than publicKeyGenerationKernel
        int minGridSizeFused{};
        int recommendedBlockSizeFused{};
        auto* fusedKernel = (mGeneratorMode == 2) ? publicKeyAndCheckHash160FusedKernel2 : publicKeyAndCheckHash160FusedKernel;
        cudaCheckError(cudaOccupancyMaxPotentialBlockSize(&minGridSizeFused, &recommendedBlockSizeFused, fusedKernel));

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
                fusedKernel,
                mBlockSize,
                dynamicSMemSize));

            cudaFuncAttributes attr{};
            cudaCheckError(cudaFuncGetAttributes(&attr, fusedKernel));
            const int warpsPerBlock = (mBlockSize + 31) / 32;
            const int activeWarpsPerSM = numBlocksPerSM * warpsPerBlock;
            const int maxWarpsPerSM = deviceProp.maxThreadsPerMultiProcessor / 32;
            const int occupancyPct = (maxWarpsPerSM > 0) ? (activeWarpsPerSM * 100 / maxWarpsPerSM) : 0;

            const int optimalGridSize = deviceProp.multiProcessorCount * numBlocksPerSM;
            mGridSize = static_cast<uint32_t>(std::max(minGridSizeFused, optimalGridSize));

#ifdef KEYHUNT_CUDA_VERBOSE
            fprintf(stdout, "[GPU %d] %s | SMs %d Blocks/SM %d | grid %u block %u | occupancy %d%%\n",
                    deviceId, deviceProp.name, deviceProp.multiProcessorCount, numBlocksPerSM,
                    mGridSize, mBlockSize, occupancyPct);
#endif
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
        const uint32_t totalKeys = keysNumberPerIteration * generatedKeysMultiplier();
        d_privateKeys[0].resize(totalKeys);
        d_privateKeys[1].resize(totalKeys);
    }

    void getPrivateKeys(thrust::host_vector<uint256_t>& h_privateKeys) const
    {
        h_privateKeys = d_privateKeys[mCurBuf];
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
        if (h_privateKeys.size() != d_privateKeys[mCurBuf].size())
        {
            throw std::runtime_error("Private keys size mismatch");
        }
        thrust::copy(h_privateKeys.begin(), h_privateKeys.end(), d_privateKeys[mCurBuf].begin());
    }

    // Legacy sync path — writes one or two keys per y seed depending on generator mode and waits.
    void generatePrivateKeysForXPerIteration(const uint32_t privateXPart, const uint32_t iteration)
    {
        const uint32_t keysNumberPerIteration = getKeysNumberPerIteration();

        if (d_privateKeys[mCurBuf].size() != keysNumberPerIteration * generatedKeysMultiplier())
        {
            throw std::runtime_error("Private keys device storage has wrong size");
        }

        const uint32_t increment = iteration * keysNumberPerIteration;
        mSeedLaunchMeta[mCurBuf] = {};

        cudaCheckError(cudaKernelSyncLaunch(mInitStream, [&]()
        {
            if (mGeneratorMode == 2) {
                uint256_t* ptr = thrust::raw_pointer_cast(d_privateKeys[mCurBuf].data());
                constexpr uint32_t block = 256u;
                const uint32_t grid = (keysNumberPerIteration + block - 1u) / block;
                privateKeysForXKernel2<<<grid, block, 0, mInitStream>>>(privateXPart, increment, ptr, keysNumberPerIteration);
            } else {
                thrust::transform(thrust::cuda::par.on(mInitStream),
                                  thrust::counting_iterator<uint32_t>(0u),
                                  thrust::counting_iterator<uint32_t>(keysNumberPerIteration),
                                  d_privateKeys[mCurBuf].begin(),
                                  PrivateKeyForXWithRandomYFunctor(privateXPart, increment)
                );
            }
        }, "generatePrivateKeysForXPerIteration"));
    }

    // Pipeline step 1: write private keys into the STAGING (next) buffer, async.
    // Returns immediately; mInitStream runs concurrently with mGeneratorStream.
    // Explicit kernel launch (no Thrust) to avoid any implicit stream sync in Thrust backend.
    void pregenerateKeysAsync(const uint32_t privateXPart, const uint32_t iteration)
    {
        const uint32_t keysNumberPerIteration = getKeysNumberPerIteration();
        const uint32_t increment = iteration * keysNumberPerIteration;
        const int nextBuf = 1 - mCurBuf;

        if (mGeneratorMode == 2) {
            mSeedLaunchMeta[nextBuf] = {
                .privateXPart = privateXPart,
                .yPartIncrementBy = increment,
                .valid = true,
            };
            return;
        }

        mSeedLaunchMeta[nextBuf] = {};

        uint256_t* ptr = thrust::raw_pointer_cast(d_privateKeys[nextBuf].data());
        constexpr uint32_t block = 256u;
        const uint32_t grid = (keysNumberPerIteration + block - 1u) / block;
        privateKeysForXKernel<<<grid, block, 0, mInitStream>>>(privateXPart, increment, ptr, keysNumberPerIteration);
        // No sync — caller is responsible for synchronizing mInitStream before launchKernelAsync.
    }

    // Pipeline step 2: sync key-gen, swap buffers, launch kernel async.
    void launchKernelAsync()
    {
        // Promote staging buffer → current.
        const int nextBuf = 1 - mCurBuf;
        if (mGeneratorMode != 2 || !mSeedLaunchMeta[nextBuf].valid) {
            // Wait for the key-gen (mInitStream) to finish writing to the staging buffer.
            cudaCheckError(cudaStreamSynchronize(mInitStream));
        }
        mCurBuf = nextBuf;

        constexpr uint32_t sharedMem = 0;
        if (mGeneratorMode == 2)
        {
            const auto meta = mSeedLaunchMeta[mCurBuf];
            if (meta.valid) {
                publicKeyAndCheckHash160FusedKernel2Seed<<<mGridSize, mBlockSize, sharedMem, mGeneratorStream>>>(
                    meta.privateXPart, meta.yPartIncrementBy);
            } else {
                const uint256_t* privateKeysPtr = thrust::raw_pointer_cast(d_privateKeys[mCurBuf].data());
                publicKeyAndCheckHash160FusedKernel2<<<mGridSize, mBlockSize, sharedMem, mGeneratorStream>>>(privateKeysPtr);
            }
        }
        else
        {
            const uint256_t* privateKeysPtr = thrust::raw_pointer_cast(d_privateKeys[mCurBuf].data());
            publicKeyAndCheckHash160FusedKernel<<<mGridSize, mBlockSize, sharedMem, mGeneratorStream>>>(privateKeysPtr);
        }
        cudaError_t err = cudaGetLastError();
        if (err != cudaSuccess)
        {
#ifdef KEYHUNT_CUDA_VERBOSE
            fprintf(stderr, "launchKernelAsync: CUDA error: %s\n", cudaGetErrorString(err));
#endif
        }
        // No stream sync — caller calls syncKernel() when it needs results.
    }

    // Pipeline step 3: wait for the running kernel to finish.
    void syncKernel()
    {
        cudaError_t err = cudaStreamSynchronize(mGeneratorStream);
        if (err != cudaSuccess)
        {
#ifdef KEYHUNT_CUDA_VERBOSE
            fprintf(stderr, "syncKernel: CUDA sync error: %s\n", cudaGetErrorString(err));
#endif
            cudaCheckError(err);
        }
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
#ifdef KEYHUNT_CUDA_VERBOSE
            fprintf(stderr, "Warning: gTable file size mismatch. Expected %zu bytes, got %zu bytes. Will regenerate.\n",
                    expectedFileSize, fileSize);
#endif
            file.close();
            return false;
        }

        // Read the table
        file.seekg(0, std::ios::beg);
        std::vector<secp256k1_ge_storage> h_gTable(tableSize);
        file.read(reinterpret_cast<char*>(h_gTable.data()), expectedFileSize);

        if (!file.good() || file.gcount() != static_cast<std::streamsize>(expectedFileSize))
        {
#ifdef KEYHUNT_CUDA_VERBOSE
            fprintf(stderr, "Warning: Failed to read gTable from file. Will regenerate.\n");
#endif
            file.close();
            return false;
        }

        file.close();

        // Copy to device memory
        thrust::copy(h_gTable.begin(), h_gTable.end(), d_gTable.begin());
        uploadGTable4limb(h_gTable);
#ifdef KEYHUNT_CUDA_VERBOSE
        fprintf(stdout, "Successfully loaded gTable from file: %s (%zu bytes)\n", filename.c_str(), fileSize);
#endif
        return true;
    }

    void generateGTable()
    {
        constexpr uint32_t tableSize = ECMULT_GEN_PREC_N * ECMULT_GEN_PREC_G;
        std::vector<secp256k1_ge_storage> h_gTable(tableSize);

#ifdef KEYHUNT_CUDA_VERBOSE
        fprintf(stdout, "Generating gTable (this may take a while)...\n");
#endif
        secp256k1::ecpoint basePoint = secp256k1::G();

        for (uint32_t chunk = 0; chunk < ECMULT_GEN_PREC_N; ++chunk)
        {
#ifdef KEYHUNT_CUDA_VERBOSE
            if (chunk % 2 == 0)
            {
                fprintf(stdout, "Generating chunk %u/%u\n", chunk, ECMULT_GEN_PREC_N);
            }
#endif

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
#ifdef KEYHUNT_CUDA_VERBOSE
        fprintf(stdout, "gTable generation completed!\n");
#endif
    }

    // Upload gTable pointers to constant memory once (never changes after init).
    void uploadGTablePointersToConstMem()
    {
        const secp256k1_ge_storage* d_gTableRawPtr = thrust::raw_pointer_cast(d_gTable.data());
        cudaCheckError(cudaMemcpyToSymbol(d_gTable_ptr, &d_gTableRawPtr, sizeof(secp256k1_ge_storage*)));
        const uint64_t* d_gTableXRaw = thrust::raw_pointer_cast(d_gTableX_4limb.data());
        const uint64_t* d_gTableYRaw = thrust::raw_pointer_cast(d_gTableY_4limb.data());
        cudaCheckError(cudaMemcpyToSymbol(d_gTableX_4limb_ptr, &d_gTableXRaw, sizeof(uint64_t*)));
        cudaCheckError(cudaMemcpyToSymbol(d_gTableY_4limb_ptr, &d_gTableYRaw, sizeof(uint64_t*)));
    }

    void allocateGTableDeviceMemory()
    {
        constexpr uint32_t tableSize = ECMULT_GEN_PREC_N * ECMULT_GEN_PREC_G;
        constexpr uint32_t limbsPerPoint = 4;
        d_gTable.resize(tableSize);
        d_gTableX_4limb.resize(tableSize * limbsPerPoint);
        d_gTableY_4limb.resize(tableSize * limbsPerPoint);
        // Try to load from file first
        const std::string defaultFilename = "clip.bin";
        if (!loadGTableFromFile(defaultFilename))
        {
            // If loading failed, generate the table
            generateGTable();
        }
        // Upload gTable pointers to constant memory once — avoids per-iteration memcpy.
        uploadGTablePointersToConstMem();
    }

    void init(const uint32_t pointsPerThread, const uint32_t publicKeyCompressionTypeToCheck, const uint32_t generatorMode, const uint32_t gridSize, const uint32_t blockSize)
    {
        // From examples: L1 cache helps random GTable access; larger stack for deep kernel frames
        cudaCheckError(cudaDeviceSetCacheConfig(cudaFuncCachePreferL1));
        cudaCheckError(cudaDeviceSetLimit(cudaLimitStackSize, 32768));

        mGeneratorMode = (generatorMode == 2) ? 2u : 1u;

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
        // gTable pointers are set once in uploadGTablePointersToConstMem() during init.
        // No per-iteration copies needed.

        constexpr uint32_t mSharedMemSize{0};
        const uint256_t *privateKeysPtr = thrust::raw_pointer_cast(d_privateKeys[mCurBuf].data());
        if (mGeneratorMode == 2)
        {
            publicKeyAndCheckHash160FusedKernel2<<<mGridSize, mBlockSize, mSharedMemSize, mGeneratorStream>>>(privateKeysPtr);
        }
        else
        {
            publicKeyAndCheckHash160FusedKernel<<<mGridSize, mBlockSize, mSharedMemSize, mGeneratorStream>>>(privateKeysPtr);
        }
        cudaError_t err = cudaGetLastError();
        if (err != cudaSuccess)
        {
#ifdef KEYHUNT_CUDA_VERBOSE
            fprintf(stderr, "publicKeyAndCheckHash160FusedKernel: CUDA error: %s\n", cudaGetErrorString(err));
#endif
        }
        cudaError_t syncErr = cudaStreamSynchronize(mGeneratorStream);
        if (syncErr != cudaSuccess)
        {
#ifdef KEYHUNT_CUDA_VERBOSE
            fprintf(stderr, "calculatePublicKeysAndCheckHash160: CUDA sync error: %s\n", cudaGetErrorString(syncErr));
#endif
            cudaCheckError(syncErr);
        }
    }

    void fillPublicKeys()
    {
        constexpr uint256_t infinite{0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF};
        thrust::fill(thrust::cuda_cub::par.on(mGeneratorStream), d_publicKeysX.begin(), d_publicKeysX.end(), infinite);
        thrust::fill(thrust::cuda_cub::par.on(mGeneratorStream), d_publicKeysY.begin(), d_publicKeysY.end(), infinite);
        // gTable pointer already in constant memory from uploadGTablePointersToConstMem().
        constexpr uint32_t mSharedMemSize{0};
        const uint256_t *privateKeysPtr = thrust::raw_pointer_cast(d_privateKeys[mCurBuf].data());
        publicKeyGenerationKernel <<<mGridSize, mBlockSize, mSharedMemSize, mGeneratorStream>>>(privateKeysPtr);
        cudaCheckError(cudaStreamSynchronize(mGeneratorStream));
    }
};

ECC::ECC() : mImpl(std::make_unique<Impl>()) {}
ECC::~ECC() = default;

ECC::ECC(ECC&& rhs) noexcept = default;
ECC& ECC::operator=(ECC &&rhs) noexcept = default;

void ECC::init(const uint32_t pointsPerThread, const uint32_t publicKeyCompressionTypeToCheck, const uint32_t generatorMode, const uint32_t gridSize, const uint32_t blockSize) const
{
    mImpl->init(pointsPerThread, publicKeyCompressionTypeToCheck, generatorMode, gridSize, blockSize);
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

void ECC::pregenerateKeysAsync(const uint32_t privateXPart, const uint32_t iteration) const
{
    mImpl->pregenerateKeysAsync(privateXPart, iteration);
}

void ECC::launchKernelAsync() const
{
    mImpl->launchKernelAsync();
}

void ECC::syncKernel() const
{
    mImpl->syncKernel();
}
