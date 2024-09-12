#pragma once

#include <boost/lockfree/spsc_queue.hpp>
#include <thrust/host_vector.h>

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
struct Secp256k1KeyPair
{
    secp256k1::uint256 privateKey{};
    secp256k1::ecpoint publicKey{};
};
using Secp256k1KeyPairs = std::vector<Secp256k1KeyPair>;

/*################################################################################################################################################################################*/
using DataQueue = boost::lockfree::spsc_queue<Secp256k1KeyPairs*, boost::lockfree::capacity<1024>>;

/*################################################################################################################################################################################*/
struct GlobalContext
{
    Config config;
    cu::CudaDeviceInfo cudaInfo;
    std::shared_ptr<DataQueue> dataQueue;
    std::function<void(StatusInfo)> statusCallback;
};

/*################################################################################################################################################################################*/