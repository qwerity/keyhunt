#pragma once

#include <iomanip>
#include <sstream>
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

inline std::string convertToHexString(const uint32_t* arr, const uint32_t size)
{
    std::stringstream ss;
    // Iterate through each byte of the array
    for (uint32_t i = 0; i < size; ++i)
    {
        const auto *bytePtr = reinterpret_cast<const uint8_t *>(&arr[i]);
        for (std::size_t j = 0; j < sizeof(uint32_t); ++j)
        {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(bytePtr[j]);
        }
    }
    return ss.str();
}