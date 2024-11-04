#include "hd_wallet.h"
#include "util/results_processor.h"

#include "util/utils.h"
#include "cuda/secp256k1_v2/bip32.cuh"

#include <wally_bip32.h>
#include <wally_bip39.h>
#include <wally_crypto.h>

#include <thread>
#include <format>
#include <future>

#include <boost/log/trivial.hpp>

using namespace std;

void setupMnemonics(const std::shared_ptr<GlobalContext>& context)
{
    const HDWalletConfig& hdWallet = context->config.hdWallet();

    const bool devMode = context->config.devMode();
    BOOST_LOG_TRIVIAL(info) << std::format("{} Mode ON [forceMnemonic: {}]", (devMode ? "Dev" : "Prod"), hdWallet.forceMnemonic);

    if (devMode && hdWallet.forceMnemonic)
    {
        BOOST_LOG_TRIVIAL(info) << "Using mnemonic: " << hdWallet.mnemonic;
        return;
    }

    BOOST_LOG_TRIVIAL(info) <<  std::format("Checking connection with the host ({})...", context->httpClient->hostConfig());
    const bool hostIsAlive = context->httpClient->hostAlive();

    if (devMode && !hdWallet.forceMnemonic && hostIsAlive)
    {
        BOOST_LOG_TRIVIAL(info) << "Host is alive";
        return;
    }

    if (!hostIsAlive)
    {
        BOOST_LOG_TRIVIAL(info) << "Host is NOT alive";
    }
    else
    {
        BOOST_LOG_TRIVIAL(info) << "Host is alive";
    }
}

int main()
{
    // Config will initialize here
    auto context = std::make_shared<GlobalContext>();
    if (!context->config.isLoaded())
    {
        return 1;
    }

    context->httpClient = std::make_shared<HttpClient>(context->config.server());
    context->hash160SearchResultsQueue = std::make_shared<Hash160SearchResultsQueue>();
    context->statusCallback = utils::statusCallback;

    utils::initLogging(context->config.log());

    utils::initOpenssl();

    constexpr int wallyInitFlags{0};

    // Initialize the Wally core library
    if (wally_init(wallyInitFlags) != WALLY_OK)
    {
        BOOST_LOG_TRIVIAL(error) << "Failed to initialize Wally";
        return 1;
    }
    utils::ScopeOutRunner outRunner([]() {
        wally_cleanup(wallyInitFlags);
        utils::releaseOpenssl();
    });

    setupMnemonics(context);

    // load hash160 targets to memory
    utils::readHash160Targets(context->config.hunter().ripemd160TargetsFilePaths, context->hash160Targets);
    if (context->hash160Targets.empty())
    {
        BOOST_LOG_TRIVIAL(info) << "Stopping application as hash160 targets are not set";
        return 2;
    }

    // Start generation checking and results processing
    const ResultsProcessor resultProcessor(context);
    resultProcessor.startHash160ResultsQueueProcessing();

    const int gpuDevicesCount = cu::getDeviceCount();
    std::vector<std::thread> threads;
    std::vector<std::future<void>> futures;

    threads.reserve(gpuDevicesCount);
    futures.reserve(gpuDevicesCount);

    for (int cudaDeviceId = 0; cudaDeviceId < gpuDevicesCount; ++cudaDeviceId)
    {
        std::promise<void> promise;
        futures.push_back(promise.get_future());

        threads.emplace_back([&context, cudaDeviceId, promise = std::move(promise)]() mutable
        {
            // For using concrete CUDA device
            auto cudaInfo = cu::cudaInit(cudaDeviceId);
            HDWallet hdWallet(context, std::move(cudaInfo));
            hdWallet.startSearchPublicHash();

            // Signal that the thread has finished
            promise.set_value();
        });
    }

    // Wait for all threads to finish
    for (auto& future: futures)
    {
        future.wait();// Wait for the promise to be fulfilled
    }

    // Join all the threads manually
    for (auto& thread: threads)
    {
        if (thread.joinable())
        {
            thread.join();
        }
    }

    return 0;
}