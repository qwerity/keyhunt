#include "key_hunter.h"
#include "util/results_processor.h"

#include "util/common_host.h"
#include "util/utils.h"

#include <thread>
#include <format>
#include <future>

#include <boost/log/trivial.hpp>

void setupPrivateXPart(const std::shared_ptr<GlobalContext>& context)
{
    const HunterConfig& hunter = context->config.hunter();

    const bool devMode = context->config.devMode();
    BOOST_LOG_TRIVIAL(info) << std::format(std::locale("en_US.UTF-8"), "{} Mode ON [forcePrivateXPart: {} | keysNumberToGenerate: {:L}]", (devMode ? "Dev" : "Prod"), hunter.forcePrivateXPart, hunter.keysNumberToGenerate);

    if (devMode && hunter.forcePrivateXPart)
    {
        BOOST_LOG_TRIVIAL(info) << "Using private X part: " << hunter.privateXPart;
        return;
    }

    BOOST_LOG_TRIVIAL(info) <<  std::format("Checking connection with the host ({})...", context->httpClient->hostConfig());
    const bool hostIsAlive = context->httpClient->hostAlive();

    if (devMode && !hunter.forcePrivateXPart && hostIsAlive)
    {
        BOOST_LOG_TRIVIAL(info) << "Host is alive, will get private x from http service";
        return;
    }

    if (!hostIsAlive)
    {
        BOOST_LOG_TRIVIAL(info) << "Host is NOT alive, continue with random private X part";
        context->config.setPrivateXPartRandom();
    }
    else
    {
        BOOST_LOG_TRIVIAL(info) << "Host is alive, will get private x from http service";
    }
}

int main()
{
    utils::initOpenssl();
    utils::ScopeOutRunner outRunner([]() {
        utils::releaseOpenssl();
    });

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

    setupPrivateXPart(context);

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
            const KeyHunter hunter(context, std::move(cudaInfo));
            hunter.startSearchPublicHash();

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