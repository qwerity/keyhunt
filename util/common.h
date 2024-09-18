#pragma once

#include <boost/lockfree/spsc_queue.hpp>

#include "cuda_util.h"
#include "secp256k1.h"
#include "config.h"

/*################################################################################################################################################################################*/
constexpr uint32_t MB{1024 * 1024};

/*################################################################################################################################################################################*/
namespace PointCompressionType
{
    enum Value
    {
        COMPRESSED = 0,
        UNCOMPRESSED = 1,
        BOTH = 2
    };
}

/*################################################################################################################################################################################*/
struct StatusInfo
{
    double pointsPerSecond{};
    double seconds{};
    uint64_t total{};
    uint64_t totalTime{};

    int device{};
    std::string deviceName;
    uint64_t freeDeviceMemory{};
    uint64_t totalDeviceMemory{};

    uint32_t iteration{};
    uint32_t remainsIterations{};
};

/*################################################################################################################################################################################*/
struct Hash160SearchResult
{
    int thread{0};
    int block{0};
    int idx{0};

    bool compressed{false};
    uint32_t privateKey[8]{};
    uint32_t publicXKey[8]{};
    uint32_t publicYKey[8]{};
    uint32_t digest[5]{};
};

/*################################################################################################################################################################################*/
struct Secp256k1KeyPair
{
    secp256k1::uint256 privateKey{};
    secp256k1::ecpoint publicKey{};
};
using Secp256k1KeyPairs = std::vector<Secp256k1KeyPair>;

/*################################################################################################################################################################################*/
using DataQueue = boost::lockfree::spsc_queue<Secp256k1KeyPairs*, boost::lockfree::capacity<1024>>;
using Hash160SearchResultsQueue = boost::lockfree::spsc_queue<Hash160SearchResult, boost::lockfree::capacity<1024>>;

/*################################################################################################################################################################################*/
struct GlobalContext
{
    Config config;
    cu::CudaDeviceInfo cudaInfo;
    std::shared_ptr<DataQueue> dataQueue;
    std::shared_ptr<Hash160SearchResultsQueue> hash160SearchResultsQueue;
    std::function<void(StatusInfo)> statusCallback;
};

/*################################################################################################################################################################################*/