#include "hd_wallet.h"
#include "zmq_client.h"

#include "util/results_processor.h"
#include "util/utils.h"

#include <wally_core.h>

#include <thread>
#include <future>

#include <boost/log/trivial.hpp>

void statusCallback(const StatusInfo& info)
{
    const std::string speedStr = std::format("{:.3f} MKey/s", info.dataPerSecond);
    const std::string totalStr = std::format(std::locale("en_US.UTF-8"), "({:L}/{:L} total)", info.total, info.derivationsPerIteration * info.total);
    const std::string timeStr = std::format("[{:.3f}s | {}]", info.seconds, utils::formatSeconds(static_cast<uint32_t>(info.totalTime / 1000)));
    const uint64_t usedDeviceMemoryMb = (info.totalDeviceMemory - info.freeDeviceMemory) / MB;
    const uint64_t totalDeviceMemoryMb = info.totalDeviceMemory / MB;

    const std::string statusStr = std::format("[{} | {} | {}/{}MB] [{}/{}] {} {} {}"
        , info.device, info.deviceName, usedDeviceMemoryMb, totalDeviceMemoryMb
        , info.iteration, info.totalIterations
        , speedStr, totalStr, timeStr);

    // fprintf(stderr, "\r%s", statusStr.c_str());
    BOOST_LOG_TRIVIAL(fatal) << statusStr;
}

void setupMnemonics(const std::shared_ptr<GlobalContext>& context)
{
    const HDWalletConfig& hdWallet = context->config.hdWallet();

    const bool devMode = (hdWallet.forceMnemonic && !hdWallet.mnemonic.empty()) || (hdWallet.mnemonicsToGenerate != 0);
    context->config.setDevMode(devMode);
    
    BOOST_LOG_TRIVIAL(info) << std::format("{} Mode ON [forceMnemonic: {}, mnemonicsToGenerate: {}, test mnemonic: {}]", (devMode ? "Dev" : "Prod"), hdWallet.forceMnemonic, hdWallet.mnemonicsToGenerate, hdWallet.mnemonic);

    if (devMode)
    {
        if (hdWallet.forceMnemonic && !hdWallet.mnemonic.empty())
        {
            BOOST_LOG_TRIVIAL(info) << "Using mnemonic: " << hdWallet.mnemonic;
        }
        else
        {
            context->config.setRandomGeneration(true);
            BOOST_LOG_TRIVIAL(info) << "Will generate random mnemonic";
        }
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

    context->mnemonicMasterKeyHash160SearchResultsQueue = std::make_shared<MnemonicMasterKeyHash160SearchResultsQueue>();
    context->mnemonicMasterKeysQueue = std::make_shared<MnemonicMasterKeysQueue>();
    context->statusCallback = statusCallback;

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
    resultProcessor.startMnemonicsMasterKeyHash160ResultsQueueProcessing();

    const MasterKeysZMQClient masterKeysZmqClient(context);
    masterKeysZmqClient.start();

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
            const HDWallet hdWallet(context, std::move(cudaInfo));
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