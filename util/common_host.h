#pragma once

#include "common.h"

#include "http_client.h"
#include "secp256k1.h"
#include "config.h"
#include "cuda/defines.cuh"

#include <boost/lockfree/queue.hpp>

#include <unordered_set>

/*################################################################################################################################################################################*/
struct Secp256k1KeyPair
{
    secp256k1::uint256 privateKey{};
    secp256k1::ecpoint publicKey{};
};
using Secp256k1KeyPairs = std::vector<Secp256k1KeyPair>;

/*################################################################################################################################################################################*/
using Hash160SearchResultsQueue = boost::lockfree::queue<Hash160SearchResult, boost::lockfree::capacity<1024>>;

/*################################################################################################################################################################################*/
struct GlobalContext
{
    Config config{"config.json"};
    std::unordered_set<hash160> hash160Targets;
    std::shared_ptr<Hash160SearchResultsQueue> hash160SearchResultsQueue;
    std::function<void(StatusInfo)> statusCallback;
};

/*################################################################################################################################################################################*/