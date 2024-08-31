#pragma once

#include <boost/lockfree/spsc_queue.hpp>
#include <thrust/host_vector.h>

#include "cuda_util.h"
#include "secp256k1.h"

struct StatusInfo
{
    int device{};
    double speed{};
    double seconds{};
    uint64_t total{};
    uint64_t totalTime{};
    std::string deviceName;
    uint64_t freeMemory{};
    uint64_t deviceMemory{};
    uint64_t targets{};
};

struct Secp256k1KeyPair
{
    secp256k1::uint256 privateKey{};
    secp256k1::ecpoint publicKey{};
};

using Secp256k1KeyPairs = thrust::host_vector<Secp256k1KeyPair>;
using DataQueue = boost::lockfree::spsc_queue<Secp256k1KeyPairs*, boost::lockfree::capacity<32*256*32>>;

struct Context
{
    std::shared_ptr<DataQueue> dataQueue;
    std::function<void(StatusInfo)> statusCallback;
};
