#include "hash160_lookup.cuh"

#include "cuda_util.h"
#include "ptx.cuh"

constexpr uint32_t MAX_TARGETS_CONSTANT_MEM{16};

__constant__ uint32_t d_UseBloomFilter{};

__constant__ uint32_t _TARGET_HASH[MAX_TARGETS_CONSTANT_MEM][5];
__constant__ uint32_t d_NumTargetHashes{};

__constant__ uint32_t *d_BloomFilterPtr{};

__constant__ uint32_t d_BloomFilterMask{};
__constant__ uint64_t d_BloomFilterMask64{};


static uint32_t swp(const uint32_t x)
{
    return (x << 24) | ((x << 8) & 0x00ff0000) | ((x >> 8) & 0x0000ff00) | (x >> 24);
}

static void undoRMD160FinalRound(const uint32_t hIn[5], uint32_t hOut[5])
{
    constexpr uint32_t iv[5] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0};
    for (int i = 0; i < 5; i++)
    {
        hOut[i] = swp(hIn[i]) - iv[(i + 1) % 5];
    }
}

/**
Copies the target hashes to constant memory
*/
cudaError_t Hash160Lookup::setTargetConstantMemory(const std::vector<hash160> &targets)
{
    const size_t count = targets.size();
    cudaError_t err{cudaSuccess};
    try
    {
        uint32_t h[5];
        for (size_t i = 0; i < count; i++)
        {
            undoRMD160FinalRound(targets[i].h, h);
            cu::safeCall(cudaMemcpyToSymbol(_TARGET_HASH, h, sizeof(uint32_t) * 5, i * sizeof(uint32_t) * 5));
        }
        cu::safeCall(cudaMemcpyToSymbol(d_NumTargetHashes, &count, sizeof(uint32_t)));

        constexpr uint32_t useBloomFilter{0};
        cu::safeCall(cudaMemcpyToSymbol(d_UseBloomFilter, &useBloomFilter, sizeof(bool)));
    }
    catch (const cu::CudaException& e)
    {
        err = e.getCudaError();
        std::printf("%s\n", e.what());
    }

    return err;
}

/**
Returns the optimal bloom filter size in bits given the probability of false-positives and the
number of hash functions
*/
uint32_t Hash160Lookup::getOptimalBloomFilterBits(const double p, const size_t n)
{
    const double m = 3.6 * ceil((n * log(p)) / log(1 / pow(2, log(2))));
    return static_cast<uint32_t>(ceil(log(m) / log(2)));
}

void Hash160Lookup::initializeBloomFilter(const std::vector<hash160> &targets, thrust::host_vector<uint32_t> &filter, const uint32_t mask)
{
    // Use the low 16 bits of each word in the hash as the index into the bloom filter
    for (uint32_t i = 0; i < targets.size(); i++)
    {
        uint32_t h[5];
        undoRMD160FinalRound(targets[i].h, h);
        for (int j = 0; j < 5; j++)
        {
            const uint32_t idx = h[j] & mask;
            filter[idx / 32] |= (0x01 << (idx % 32));
        }
    }
}

void Hash160Lookup::initializeBloomFilter64(const std::vector<hash160> &targets, thrust::host_vector<uint32_t> &filter, const uint64_t mask)
{
    for (uint32_t k = 0; k < targets.size(); k++)
    {
        uint32_t hash[5];
        uint64_t idx[5];
        undoRMD160FinalRound(targets[k].h, hash);

        idx[0] = (static_cast<uint64_t>(hash[0]) << 32 | hash[1]) & mask;
        idx[1] = (static_cast<uint64_t>(hash[2]) << 32 | hash[3]) & mask;
        idx[2] = (static_cast<uint64_t>(hash[0] ^ hash[1]) << 32 | (hash[1] ^ hash[2])) & mask;
        idx[3] = (static_cast<uint64_t>(hash[2] ^ hash[3]) << 32 | (hash[3] ^ hash[4])) & mask;
        idx[4] = (static_cast<uint64_t>(hash[0] ^ hash[3]) << 32 | (hash[1] ^ hash[3])) & mask;

        for (int i = 0; i < 5; ++i)
        {
            filter[idx[i] / 32] |= (0x01 << (idx[i] % 32));
        }
    }
}

/**
Populates the bloom filter with the target hashes
*/
cudaError_t Hash160Lookup::setTargetBloomFilter(const std::vector<hash160> &targets)
{
    const uint32_t bloomFilterBits = getOptimalBloomFilterBits(1.0e-9, targets.size());
    const uint64_t bloomFilterSizeWords = 1ULL << (bloomFilterBits - 5);
    const uint64_t bloomFilterBytes = 1ULL << (bloomFilterBits - 3);
    const uint64_t bloomFilterMask = (1ULL << bloomFilterBits) - 1;
    fprintf(stderr, "Allocating bloom filter: %.1fMB", static_cast<double>(bloomFilterBytes) / (1024.0 * 1024.0));

    cudaError_t err{cudaSuccess};
    try
    {
        thrust::host_vector<uint32_t> filter(bloomFilterSizeWords);
        thrust::fill(filter.begin(), filter.end(), 0);

        const uint32_t useBloomFilter = bloomFilterBits <= 32 ? 1 : 2;
        cu::safeCall(cudaMemcpyToSymbol(d_UseBloomFilter, &useBloomFilter, sizeof(uint32_t)));

        if (useBloomFilter == 2)
        {
            initializeBloomFilter64(targets, filter, bloomFilterMask);

            cu::safeCall(cudaMemcpyToSymbol(d_BloomFilterMask64, &bloomFilterMask, sizeof(uint64_t)));
        }
        else
        {
            initializeBloomFilter(targets, filter, static_cast<uint32_t>(bloomFilterMask));

            cu::safeCall(cudaMemcpyToSymbol(d_BloomFilterMask, &bloomFilterMask, sizeof(uint32_t)));
        }

        // Copy to device
        d_bloomFilter = filter;

        // Copy device memory pointer to constant memory
        const auto* d_bloomFilterRawPtr = thrust::raw_pointer_cast(d_bloomFilter.data());
        cu::safeCall(cudaMemcpyToSymbol(d_BloomFilterPtr, &d_bloomFilterRawPtr, sizeof(uint32_t *)));
    }
    catch (const cu::CudaException& e)
    {
        err = e.getCudaError();
        std::printf("%s\n", e.what());
    }

    return err;
}

/**
*Copies the target hashes to either constant memory, or the bloom filter depending
on how many targets there are
*/
cudaError_t Hash160Lookup::setTargets(const std::vector<hash160>& hash160Targets)
{
    thrust::release(d_bloomFilter);

    if (hash160Targets.size() <= MAX_TARGETS_CONSTANT_MEM)
    {
        return setTargetConstantMemory(hash160Targets);
    }

    return setTargetBloomFilter(hash160Targets);
}

__device__ void doRMD160FinalRound(const uint32_t hIn[5], uint32_t hOut[5])
{
    constexpr uint32_t iv[5] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0};
    for (int i = 0; i < 5; i++)
    {
        hOut[i] = endian(hIn[i] + iv[(i + 1) % 5]);
    }
}

__device__ bool checkBloomFilter(const hash160& hash)
{
    bool foundMatch = true;
    for (int i = 0; i < 5; ++i)
    {
        const uint32_t idx = hash.h[i] & d_BloomFilterMask;
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

    for (int i = 0; i < 5; i++)
    {
        const uint32_t f = d_BloomFilterPtr[idx[i] / 32];
        if ((f & (0x01 << (idx[i] % 32))) == 0)
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
        for (int i = 0; i < 5; ++i)
        {
            equal &= (hash.h[i] == _TARGET_HASH[j][i]);
        }
        foundMatch |= equal;
    }

    return foundMatch;
}
