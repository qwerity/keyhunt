#pragma once

#include "common.h"

#include <boost/lockfree/spsc_queue.hpp>

#include "cuda_util.h"
#include "secp256k1.h"
#include "config.h"

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
    Config config{"config.json"};
    cu::CudaDeviceInfo cudaInfo;
    std::shared_ptr<DataQueue> dataQueue;
    std::shared_ptr<Hash160SearchResultsQueue> hash160SearchResultsQueue;
    std::function<void(StatusInfo)> statusCallback;
};

/*################################################################################################################################################################################*/