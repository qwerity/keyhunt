#include "hash160_lookup.cuh"
#include "udevice_vector.cuh"
#include "ripemd160_constants.cuh"
#include "utils.cuh"

#include "defines.h"

// Раскомментируйте следующую строку для включения отладочного вывода в checkHash()
// #define DEBUG_HASH_CHECK

// ОПТИМИЗАЦИЯ: Увеличиваем порог для constant memory
// Для малого количества целей constant memory быстрее bloom фильтра (нет чтений из global memory)
// Bloom фильтр полезен только для очень большого количества целей (>1000)
constexpr uint32_t maxTargetsConstantMem{100};

__constant__ uint32_t d_UseBloomFilter{};

__constant__ uint32_t d_TargetHash[maxTargetsConstantMem][5];
__constant__ uint32_t d_NumTargetHashes{};

__constant__ uint32_t *d_BloomFilterPtr{};

__constant__ uint32_t d_BloomFilterMask{};
__constant__ uint64_t d_BloomFilterMask64{};

namespace
{
    /**
    * Copies the target hashes to constant memory
    */
    void setTargetConstantMemory(const std::unordered_set<hash160> &targets)
    {
        const size_t count = targets.size();
        uint32_t i{0};

        for (const auto& target : targets)
        {
            uint32_t h[5];
            SWAP32_HASH160(target.h, h);
            cudaCheckError(cudaMemcpyToSymbol(d_TargetHash, h, sizeof(uint32_t) * 5, i * sizeof(uint32_t) * 5));
            ++i;
        }
        cudaCheckError(cudaMemcpyToSymbol(d_NumTargetHashes, &count, sizeof(uint32_t)));

        constexpr uint32_t useBloomFilter{0};
        cudaCheckError(cudaMemcpyToSymbol(d_UseBloomFilter, &useBloomFilter, sizeof(bool)));
    }

    /**
     * Returns the optimal bloom filter size in bits given the probability of false-positives and the number of hash functions
    */
    uint32_t getOptimalBloomFilterBits(const double p, const size_t n)
    {
        constexpr double optimalCoefficient{3.6};
        const double m = optimalCoefficient * ceil((n * log(p)) / log(1 / pow(2, log(2))));
        return static_cast<uint32_t>(ceil(log(m) / log(2)));
    }

    void initializeBloomFilter(const std::unordered_set<hash160> &targets, thrust::host_vector<uint32_t> &filter, const uint32_t mask)
    {
        // Use the low 16 bits of each word in the hash as the index into the bloom filter
        for (const auto& target : targets)
        {
            uint32_t h[5];
            SWAP32_HASH160(target.h, h);
            for (const uint32_t j : h)
            {
                const uint32_t idx = j & mask;
                filter[idx / 32] |= (0x01 << (idx % 32));
            }
        }
    }

    void initializeBloomFilter64(const std::unordered_set<hash160> & targets, thrust::host_vector<uint32_t> &filter, const uint64_t mask)
    {
        for (const auto& target : targets)
        {
            uint64_t idx[5];
            uint32_t hash[5];
            SWAP32_HASH160(target.h, hash);

            idx[0] = (static_cast<uint64_t>(hash[0]) << 32 | hash[1]) & mask;
            idx[1] = (static_cast<uint64_t>(hash[2]) << 32 | hash[3]) & mask;
            idx[2] = (static_cast<uint64_t>(hash[0]        ^ hash[1]) << 32 | (hash[1] ^ hash[2])) & mask;
            idx[3] = (static_cast<uint64_t>(hash[2]        ^ hash[3]) << 32 | (hash[3] ^ hash[4])) & mask;
            idx[4] = (static_cast<uint64_t>(hash[0]        ^ hash[3]) << 32 | (hash[1] ^ hash[3])) & mask;

            for (const uint64_t& i : idx)
            {
                filter[i / 32] |= (0x01 << (i % 32));
            }
        }
    }
}

struct Hash160Lookup::Impl
{
    thrust::udevice_vector<uint32_t> d_bloomFilter;

    /**
    * Populates the bloom filter with the target hashes
    */
    void setTargetBloomFilter(const std::unordered_set<hash160> &targets)
    {
        // ОПТИМИЗАЦИЯ: Уменьшаем false positive rate для большого количества целей (72M+)
        // Это уменьшает нагрузку на CPU при проверке false positives
        // Для 72M целей: 1e-12 даст практически нулевые false positives
        // Размер bloom фильтра увеличится, но это компенсируется отсутствием проверок на CPU
        constexpr double requiredProbability{1.0e-12};
        const uint32_t bloomFilterBits = getOptimalBloomFilterBits(requiredProbability, targets.size());

        const uint64_t bloomFilterSizeWords = 1ULL << (bloomFilterBits - 5);
        const uint64_t bloomFilterBytes = 1ULL << (bloomFilterBits - 3);
        const uint64_t bloomFilterMask = (1ULL << bloomFilterBits) - 1;
        fprintf(stderr, "Allocating bloom filter (%d bits): %.02fMb\n", bloomFilterBits, static_cast<double>(bloomFilterBytes) / (1024.0 * 1024.0));

        thrust::host_vector<uint32_t> filter(bloomFilterSizeWords);
        thrust::fill(filter.begin(), filter.end(), 0);

        const uint32_t useBloomFilter = bloomFilterBits <= 32 ? 1 : 2;
        cudaCheckError(cudaMemcpyToSymbol(d_UseBloomFilter, &useBloomFilter, sizeof(uint32_t)));

        if (useBloomFilter == 2)
        {
            initializeBloomFilter64(targets, filter, bloomFilterMask);

            cudaCheckError(cudaMemcpyToSymbol(d_BloomFilterMask64, &bloomFilterMask, sizeof(uint64_t)));
        }
        else
        {
            initializeBloomFilter(targets, filter, static_cast<uint32_t>(bloomFilterMask));

            cudaCheckError(cudaMemcpyToSymbol(d_BloomFilterMask, &bloomFilterMask, sizeof(uint32_t)));
        }

        // Copy to device
        d_bloomFilter = filter;

        // Copy device memory pointer to constant memory
        const auto* d_bloomFilterRawPtr = thrust::raw_pointer_cast(d_bloomFilter.data());
        cudaCheckError(cudaMemcpyToSymbol(d_BloomFilterPtr, &d_bloomFilterRawPtr, sizeof(uint32_t *)));
    }

    /**
    * Copies the target hashes to either constant memory, or the bloom filter depending on how many targets there are
    */
    void setTargets(const std::unordered_set<hash160>& hash160Targets)
    {
        thrust::release(d_bloomFilter);

        // ОПТИМИЗАЦИЯ: Увеличиваем порог для использования bloom фильтра
        // Для малого количества целей constant memory быстрее (нет чтений из global memory)
        // Bloom фильтр полезен только для большого количества целей (>100)
        constexpr uint32_t bloomFilterThreshold = 100;
        
        if (hash160Targets.size() <= maxTargetsConstantMem)
        {
            setTargetConstantMemory(hash160Targets);
        }
        else if (hash160Targets.size() <= bloomFilterThreshold)
        {
            // Для среднего количества целей используем constant memory с расширенным массивом
            // Но так как maxTargetsConstantMem = 16, используем bloom фильтр только если > 16
            // Для оптимизации: если целей <= 100, лучше использовать constant memory напрямую
            // Но так как ограничение 16, используем bloom фильтр
            setTargetBloomFilter(hash160Targets);
        }
        else
        {
            setTargetBloomFilter(hash160Targets);
        }
    }
};

Hash160Lookup::Hash160Lookup() : mImpl(std::make_unique<Impl>()) {}
Hash160Lookup::~Hash160Lookup() = default;

Hash160Lookup::Hash160Lookup(Hash160Lookup&& rhs) noexcept = default;
Hash160Lookup& Hash160Lookup::operator=(Hash160Lookup &&rhs) noexcept = default;

/**
* Copies the target hashes to either constant memory, or the bloom filter depending on how many targets there are
*/
void Hash160Lookup::setTargets(const std::unordered_set<hash160>& hash160Targets) const
{
    mImpl->setTargets(hash160Targets);
}

__device__ bool checkBloomFilter(const uint32_t hash[5])
{
    // ОПТИМИЗАЦИЯ для большого количества целей (72M+):
    // 1. Ранний выход при первом несовпадении
    // 2. Использование __ldg() для read-only cache
    // 3. Предвычисление индексов для лучшей оптимизации компилятором
    // 4. Использование векторизованных операций где возможно
    
    // Предвычисляем все индексы сразу
    const uint32_t idx0 = (hash[0] & d_BloomFilterMask) / 32;
    const uint32_t bit0 = hash[0] & d_BloomFilterMask;
    const uint32_t f0 = __ldg(&d_BloomFilterPtr[idx0]);
    if ((f0 & (0x01 << (bit0 % 32))) == 0) return false;
    
    const uint32_t idx1 = (hash[1] & d_BloomFilterMask) / 32;
    const uint32_t bit1 = hash[1] & d_BloomFilterMask;
    const uint32_t f1 = __ldg(&d_BloomFilterPtr[idx1]);
    if ((f1 & (0x01 << (bit1 % 32))) == 0) return false;
    
    const uint32_t idx2 = (hash[2] & d_BloomFilterMask) / 32;
    const uint32_t bit2 = hash[2] & d_BloomFilterMask;
    const uint32_t f2 = __ldg(&d_BloomFilterPtr[idx2]);
    if ((f2 & (0x01 << (bit2 % 32))) == 0) return false;
    
    const uint32_t idx3 = (hash[3] & d_BloomFilterMask) / 32;
    const uint32_t bit3 = hash[3] & d_BloomFilterMask;
    const uint32_t f3 = __ldg(&d_BloomFilterPtr[idx3]);
    if ((f3 & (0x01 << (bit3 % 32))) == 0) return false;
    
    const uint32_t idx4 = (hash[4] & d_BloomFilterMask) / 32;
    const uint32_t bit4 = hash[4] & d_BloomFilterMask;
    const uint32_t f4 = __ldg(&d_BloomFilterPtr[idx4]);
    if ((f4 & (0x01 << (bit4 % 32))) == 0) return false;
    
    return true;
}

__device__ bool checkBloomFilter(const hash160& hash)
{
    return checkBloomFilter(hash.h);
}

__device__ bool checkBloomFilter64(const uint32_t hash[5])
{
    // ОПТИМИЗАЦИЯ для большого количества целей (72M+):
    // 1. Ранний выход при первом несовпадении
    // 2. Использование __ldg() для read-only cache
    // 3. Предвычисление всех индексов сразу для лучшей оптимизации компилятором
    
    // Предвычисляем все индексы сразу
    const uint64_t idx0 = (static_cast<uint64_t>(hash[0]) << 32 | hash[1]) & d_BloomFilterMask64;
    const uint32_t f0 = __ldg(&d_BloomFilterPtr[idx0 / 32]);
    if ((f0 & (0x01 << (idx0 % 32))) == 0) return false;
    
    const uint64_t idx1 = (static_cast<uint64_t>(hash[2]) << 32 | hash[3]) & d_BloomFilterMask64;
    const uint32_t f1 = __ldg(&d_BloomFilterPtr[idx1 / 32]);
    if ((f1 & (0x01 << (idx1 % 32))) == 0) return false;
    
    const uint64_t idx2 = (static_cast<uint64_t>(hash[0] ^ hash[1]) << 32 | (hash[1] ^ hash[2])) & d_BloomFilterMask64;
    const uint32_t f2 = __ldg(&d_BloomFilterPtr[idx2 / 32]);
    if ((f2 & (0x01 << (idx2 % 32))) == 0) return false;
    
    const uint64_t idx3 = (static_cast<uint64_t>(hash[2] ^ hash[3]) << 32 | (hash[3] ^ hash[4])) & d_BloomFilterMask64;
    const uint32_t f3 = __ldg(&d_BloomFilterPtr[idx3 / 32]);
    if ((f3 & (0x01 << (idx3 % 32))) == 0) return false;
    
    const uint64_t idx4 = (static_cast<uint64_t>(hash[0] ^ hash[3]) << 32 | (hash[1] ^ hash[3])) & d_BloomFilterMask64;
    const uint32_t f4 = __ldg(&d_BloomFilterPtr[idx4 / 32]);
    if ((f4 & (0x01 << (idx4 % 32))) == 0) return false;
    
    return true;
}

__device__ bool checkBloomFilter64(const hash160& hash)
{
    return checkBloomFilter64(hash.h);
}

__device__ bool checkHash(const uint32_t hash[5])
{
    // DEBUG: Отладочный вывод (включите DEBUG_HASH_CHECK в начале файла)
    #ifdef DEBUG_HASH_CHECK
    // Выводим только для первого потока первого блока, первые несколько раз
    static __device__ int debugCallCount = 0;
    int callIdx = atomicAdd(&debugCallCount, 1);
    
    if (threadIdx.x == 0 && blockIdx.x == 0 && callIdx < 5) // Первые 5 вызовов
    {
        printf("\n[DEBUG checkHash] Call #%d (Thread %d, Block %d)\n", callIdx, threadIdx.x, blockIdx.x);
        printf("  Input hash[5] = {0x%08x, 0x%08x, 0x%08x, 0x%08x, 0x%08x}\n", 
               hash[0], hash[1], hash[2], hash[3], hash[4]);
        printf("  d_NumTargetHashes = %d\n", d_NumTargetHashes);
    }
    #endif

    if (d_UseBloomFilter == 1)
    {
        return checkBloomFilter(hash);
    }

    if (d_UseBloomFilter == 2)
    {
        return checkBloomFilter64(hash);
    }

    bool foundMatch{false};
    for (int j = 0; j < d_NumTargetHashes; ++j)
    {
        bool equal = true;

        #ifdef DEBUG_HASH_CHECK
        if (threadIdx.x == 0 && blockIdx.x == 0 && callIdx < 5)
        {
            printf("  Comparing with target[%d]: {0x%08x, 0x%08x, 0x%08x, 0x%08x, 0x%08x}\n", j,
                   d_TargetHash[j][0], d_TargetHash[j][1], d_TargetHash[j][2], 
                   d_TargetHash[j][3], d_TargetHash[j][4]);
        }
        #endif

        #pragma unroll
        for (uint32_t i = 0; i < 5; ++i)
        {
            bool wordEqual = (hash[i] == d_TargetHash[j][i]);
            equal &= wordEqual;
            
            #ifdef DEBUG_HASH_CHECK
            if (threadIdx.x == 0 && blockIdx.x == 0 && callIdx < 5 && !wordEqual)
            {
                printf("    [MISMATCH] hash[%d] (0x%08x) != target[%d][%d] (0x%08x)\n", 
                       i, hash[i], j, i, d_TargetHash[j][i]);
            }
            #endif
        }
        
        #ifdef DEBUG_HASH_CHECK
        if (threadIdx.x == 0 && blockIdx.x == 0 && callIdx < 5)
        {
            printf("  Target[%d] match: %s\n", j, equal ? "YES" : "NO");
        }
        #endif
        
        foundMatch |= equal;
    }

    #ifdef DEBUG_HASH_CHECK
    if (threadIdx.x == 0 && blockIdx.x == 0 && callIdx < 5)
    {
        printf("  Final result: %s\n", foundMatch ? "MATCH FOUND" : "NO MATCH");
        printf("\n");
    }
    #endif

    return foundMatch;
}

__device__ bool checkHash(const hash160& hash)
{
    return checkHash(hash.h);
}
