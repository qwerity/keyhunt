#pragma once

#include "common.h"
#include "config.h"
#include "http_client.h"
#include "cuda/defines.cuh"

#include <boost/lockfree/queue.hpp>

#include <unordered_set>

/*################################################################################################################################################################################*/
using Hash160SearchResultsQueue = boost::lockfree::queue<Hash160SearchResult, boost::lockfree::capacity<1024>>;

/*################################################################################################################################################################################*/
struct GlobalContext
{
    Config config{"config.json"};
    std::shared_ptr<HttpClient> httpClient;
    std::unordered_set<hash160> hash160Targets;
    std::shared_ptr<Hash160SearchResultsQueue> hash160SearchResultsQueue;
    std::function<void(StatusInfo)> statusCallback;
};

/*################################################################################################################################################################################*/