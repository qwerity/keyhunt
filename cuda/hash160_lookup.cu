#include "hash160_lookup.cuh"
#include "udevice_vector.cuh"
#include "ptx.cuh"

#include "util/common.h"

constexpr uint32_t maxTargetsConstantMem{16};

__constant__ uint32_t d_UseBloomFilter{};

__constant__ uint32_t d_TargetHash[maxTargetsConstantMem][5];
__constant__ uint32_t d_NumTargetHashes{};

__constant__ uint32_t *d_BloomFilterPtr{};

__constant__ uint32_t d_BloomFilterMask{};
__constant__ uint64_t d_BloomFilterMask64{};

namespace
{
    inline uint32_t swp(const uint32_t x)
    {
        return (x << 24) | ((x << 8) & 0x00ff0000) | ((x >> 8) & 0x0000ff00) | (x >> 24);
    }

    void undoRMD160FinalRound(const uint32_t hIn[5], uint32_t hOut[5])
    {
        constexpr uint32_t iv[5] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0};
        for (int i = 0; i < 5; i++)
        {
            hOut[i] = swp(hIn[i]) - iv[(i + 1) % 5];
        }
    }

    /**
    * Copies the target hashes to constant memory
    */
    void setTargetConstantMemory(const std::unordered_set<hash160> &targets)
    {
        const size_t count = targets.size();
        uint32_t h[5];
        uint32_t i{0};

        for (const auto& target : targets)
        {
            undoRMD160FinalRound(target.h, h);
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
            undoRMD160FinalRound(target.h, h);
            for (unsigned int j : h)
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
            uint32_t hash[5];
            uint64_t idx[5];
            undoRMD160FinalRound(target.h, hash);

            idx[0] = (static_cast<uint64_t>(hash[0]) << 32 | hash[1]) & mask;
            idx[1] = (static_cast<uint64_t>(hash[2]) << 32 | hash[3]) & mask;
            idx[2] = (static_cast<uint64_t>(hash[0] ^ hash[1]) << 32 | (hash[1] ^ hash[2])) & mask;
            idx[3] = (static_cast<uint64_t>(hash[2] ^ hash[3]) << 32 | (hash[3] ^ hash[4])) & mask;
            idx[4] = (static_cast<uint64_t>(hash[0] ^ hash[3]) << 32 | (hash[1] ^ hash[3])) & mask;

            for (unsigned long long i : idx)
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
        constexpr double requiredProbability{1.0e-9};
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

        if (hash160Targets.size() <= maxTargetsConstantMem)
        {
            setTargetConstantMemory(hash160Targets);
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
void Hash160Lookup::setTargets(const std::unordered_set<hash160>& hash160Targets)
{
    mImpl->setTargets(hash160Targets);
}

__device__ void doRMD160FinalRound(const uint32_t hIn[5], uint32_t hOut[5])
{
    constexpr uint32_t iv[5] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0};

    #pragma unroll
    for (int i = 0; i < 5; i++)
    {
        hOut[i] = endian(hIn[i] + iv[(i + 1) % 5]);
    }
}

__device__ bool checkBloomFilter(const hash160& hash)
{
    bool foundMatch = true;

    #pragma unroll
    for (unsigned int i : hash.h)
    {
        const uint32_t idx = i & d_BloomFilterMask;
        const uint32_t f = d_BloomFilterPtr[idx / 32];
        if ((f & (0x01 << (idx % 32))) == 0)
        {
            foundMatch = false;
        }
    }
    return foundMatch;
}

__device__ bool checkBloomFilter64(const hash160& hash)
{
    bool foundMatch = true;
    uint64_t idx[5];
    idx[0] = (static_cast<uint64_t>(hash.h[0]) << 32 | hash.h[1]) & d_BloomFilterMask64;
    idx[1] = (static_cast<uint64_t>(hash.h[2]) << 32 | hash.h[3]) & d_BloomFilterMask64;
    idx[2] = (static_cast<uint64_t>(hash.h[0] ^ hash.h[1]) << 32 | (hash.h[1] ^ hash.h[2])) & d_BloomFilterMask64;
    idx[3] = (static_cast<uint64_t>(hash.h[2] ^ hash.h[3]) << 32 | (hash.h[3] ^ hash.h[4])) & d_BloomFilterMask64;
    idx[4] = (static_cast<uint64_t>(hash.h[0] ^ hash.h[3]) << 32 | (hash.h[1] ^ hash.h[3])) & d_BloomFilterMask64;

    #pragma unroll
    for (unsigned long long i : idx)
    {
        const uint32_t f = d_BloomFilterPtr[i / 32];
        if ((f & (0x01 << (i % 32))) == 0)
        {
            foundMatch = false;
        }
    }
    return foundMatch;
}

__device__ bool checkHash(const hash160& hash)
{
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

        #pragma unroll
        for (uint32_t i = 0; i < 5; ++i)
        {
            equal &= (hash.h[i] == d_TargetHash[j][i]);
        }
        foundMatch |= equal;
    }

    return foundMatch;
}
