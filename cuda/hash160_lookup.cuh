#pragma once

#include "defines.cuh"
#include "udevice_vector.cuh"

#include <unordered_set>

__device__ bool checkHash(const hash160& hash);
__device__ void doRMD160FinalRound(const uint32_t hIn[5], uint32_t hOut[5]);

class Hash160Lookup
{
public:
    Hash160Lookup() = default;
    ~Hash160Lookup() = default;

    cudaError_t setTargets(const std::unordered_set<hash160> &hash160Targets);

private:
    thrust::udevice_vector<uint32_t> d_bloomFilter;

    cudaError_t setTargetBloomFilter(const std::unordered_set<hash160> &targets);

    static cudaError_t setTargetConstantMemory(const std::unordered_set<hash160> &targets);

    // todo btree

    static uint32_t getOptimalBloomFilterBits(double p, size_t n);

    static void initializeBloomFilter(const std::unordered_set<hash160> &targets, thrust::host_vector<uint32_t> &filter, uint32_t mask);
    static void initializeBloomFilter64(const std::unordered_set<hash160> & targets, thrust::host_vector<uint32_t> &filter, uint64_t mask);
};
