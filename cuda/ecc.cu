#include "ecc.cuh"

#include "udevice_vector.cuh"
#include "ecc_helper.cuh"
#include "functors.cuh"
#include "secp256k1_v2/secp256k1_defines.cuh"

#include "defines.h"
#include "../util/secp256k1.h"

// Check publickey hash160 compressed/uncompressed/both
extern __constant__ int d_publicKeyCompressionTypeToCheck;

__constant__ uint32_t d_pointsPerThread{};

__constant__ uint256_t *d_publicKeyXPtr{};
__constant__ uint256_t *d_publicKeyYPtr{};

// Глобальная переменная для таблицы (объявлена в secp256k1.cu)
extern __device__ const secp256k1_ge_storage* d_gTable_ptr;

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

    // GTable в global memory (как в CudaBrainSecp)
    // Размер: ECMULT_GEN_PREC_N (16) × ECMULT_GEN_PREC_G (65536) = 1,048,576 точек
    thrust::udevice_vector<secp256k1_ge_storage> d_gTable;

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
        int minGridSize{};
        int recommendedBlockSize{};
        cudaCheckError(cudaOccupancyMaxPotentialBlockSize(&minGridSize, &recommendedBlockSize, publicKeyGenerationKernel));

        setPointsPerThread(pointsPerThread);

        mBlockSize = (blockSize != 0) ? blockSize : recommendedBlockSize;
        mGridSize = (gridSize != 0) ? gridSize : minGridSize;

        mKeysNumberPerIteration = mGridSize * mBlockSize * mPointsPerThread;
        std::fprintf(stderr, "minGridSize: %d, recommendedBlockSize: %d, set blockSize: %u, mnemonicsPerIteration: %u\n", minGridSize, recommendedBlockSize, mBlockSize, mKeysNumberPerIteration);
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

    // Конвертирует uint256 (8 uint32_t little-endian) в secp256k1_fe_storage (8 uint32_t little-endian)
    static void convertUint256ToFeStorage(const secp256k1::uint256& src, secp256k1_fe_storage& dst)
    {
        // Оба формата используют 8 uint32_t в little-endian, просто копируем
        for (int i = 0; i < 8; ++i)
        {
            dst.n[i] = src.v[i];
        }
    }

    // Конвертирует ecpoint в secp256k1_ge_storage
    static void convertEcpointToGeStorage(const secp256k1::ecpoint& src, secp256k1_ge_storage& dst)
    {
        convertUint256ToFeStorage(src.x, dst.x);
        convertUint256ToFeStorage(src.y, dst.y);
    }

    void generateGTable()
    {
        fprintf(stderr, "[INFO] Generating GTable... This may take a while (1,048,576 points to compute)...\n");
        
        constexpr uint32_t tableSize = ECMULT_GEN_PREC_N * ECMULT_GEN_PREC_G;
        std::vector<secp256k1_ge_storage> h_gTable(tableSize);
        
        // Получаем базовую точку G
        secp256k1::ecpoint basePoint = secp256k1::G();
        
        // Для каждого чанка (0-15)
        // Важно: secp256k1_scalar_get_bits извлекает биты от младших к старшим:
        // - chunk 0 = биты 0-15 (младшие 16 бит)
        // - chunk 15 = биты 240-255 (старшие 16 бит)
        // Поэтому таблица должна быть сгенерирована так:
        // - chunk 0 = G * 2^0 = G (младшие биты)
        // - chunk 15 = G * 2^240 (старшие биты)
        for (uint32_t chunk = 0; chunk < ECMULT_GEN_PREC_N; ++chunk)
        {
            // Вычисляем базовую точку для этого чанка: G * 2^(chunk * 16)
            // chunk 0 -> G * 2^0 = G (младшие биты)
            // chunk 15 -> G * 2^240 (старшие биты)
            secp256k1::ecpoint chunkBasePoint = basePoint;
            
            // Умножаем точку на 2^(chunk * 16) используя doublePoint
            for (uint32_t i = 0; i < chunk * ECMULT_GEN_PREC_B; ++i)
            {
                chunkBasePoint = secp256k1::doublePoint(chunkBasePoint);
            }
            
            // Теперь для каждого значения k от 1 до 65536 вычисляем точку chunkBasePoint * k
            // Используем последовательное сложение для оптимизации
            secp256k1::ecpoint currentPoint = chunkBasePoint; // k=1
            
            // Индекс в таблице для этого чанка
            const uint32_t chunkOffset = chunk * ECMULT_GEN_PREC_G;
            
            // k=1 (индекс 0 в таблице, так как chunkValue - 1)
            convertEcpointToGeStorage(currentPoint, h_gTable[chunkOffset + 0]);
            
            // k=2 до 65536: используем последовательное сложение
            // Индексы: 1, 2, ..., 65535 (соответствуют chunkValue 2, 3, ..., 65536)
            for (uint32_t k = 2; k <= ECMULT_GEN_PREC_G; ++k)
            {
                currentPoint = secp256k1::addPoints(currentPoint, chunkBasePoint);
                convertEcpointToGeStorage(currentPoint, h_gTable[chunkOffset + (k - 1)]);
            }
            
            if ((chunk + 1) % 4 == 0)
            {
                fprintf(stderr, "[INFO] Generated chunk %u/%u (%.1f%%)\n", 
                        chunk + 1, ECMULT_GEN_PREC_N, 
                        100.0f * (chunk + 1) / ECMULT_GEN_PREC_N);
            }
        }
        
        // Копируем таблицу в device memory
        fprintf(stderr, "[INFO] Copying GTable to device memory...\n");
        thrust::copy(h_gTable.begin(), h_gTable.end(), d_gTable.begin());
        
        fprintf(stderr, "[INFO] GTable generated successfully! Size: %u points, %.2f MB\n",
                tableSize, (tableSize * sizeof(secp256k1_ge_storage)) / (1024.0 * 1024.0));
    }

    void allocateGTableDeviceMemory()
    {
        // Размер таблицы: 16 чанков × 65536 значений = 1,048,576 точек
        constexpr uint32_t tableSize = ECMULT_GEN_PREC_N * ECMULT_GEN_PREC_G;
        d_gTable.resize(tableSize);
        
        // Генерируем таблицу
        generateGTable();
    }

    void init(const uint32_t pointsPerThread, const uint32_t publicKeyCompressionTypeToCheck, const uint32_t gridSize, const uint32_t blockSize)
    {
        computeResolutionForMaxOccupancy(pointsPerThread, gridSize, blockSize);

        cudaCheckError(cudaMemcpyToSymbol(d_publicKeyCompressionTypeToCheck, &publicKeyCompressionTypeToCheck, sizeof(uint32_t)));

        // Allocate GTable in global memory (как в CudaBrainSecp)
        allocateGTableDeviceMemory();

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

        // Устанавливаем указатель на таблицу в глобальную __device__ переменную
        const secp256k1_ge_storage* d_gTableRawPtr = thrust::raw_pointer_cast(d_gTable.data());
        cudaCheckError(cudaMemcpyToSymbol(d_gTable_ptr, &d_gTableRawPtr, sizeof(secp256k1_ge_storage*)));
        
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