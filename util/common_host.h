#pragma once

#include "common.h"
#include "config.h"
#include "http_client.h"
#include "cuda/defines.h"
#include "cuda/defines.cuh"

#include <boost/lockfree/queue.hpp>

class XPartManager;

/*################################################################################################################################################################################*/
using Hash160SearchResultsQueue = boost::lockfree::queue<Hash160SearchResult, boost::lockfree::capacity<1024>>;
using MnemonicMasterKeyHash160SearchResultsQueue = boost::lockfree::queue<Hash160MnemonicSearchResult, boost::lockfree::capacity<1024>>;
using MnemonicMasterKeysQueue = boost::lockfree::queue<HDExtendedPrivateKey, boost::lockfree::capacity<2 * 10000>>;

/*################################################################################################################################################################################*/
struct GlobalContext
{
    Config config{"config.json"};
    std::shared_ptr<HttpClient> httpClient;
    std::shared_ptr<XPartManager> xPartManager;
    Hash160Set hash160Targets;
    std::shared_ptr<Hash160SearchResultsQueue> hash160SearchResultsQueue;
    std::shared_ptr<MnemonicMasterKeyHash160SearchResultsQueue> mnemonicMasterKeyHash160SearchResultsQueue;
    std::shared_ptr<MnemonicMasterKeysQueue> mnemonicMasterKeysQueue;
    std::function<void(StatusInfo)> statusCallback;
};

/*################################################################################################################################################################################*/
