#include "key_hunter.h"
#include "results_processor.h"

#include "util/utils.h"

#include <thread>
#include <format>
#include <future>

#include <boost/log/trivial.hpp>

namespace
{
    void statusCallback(const StatusInfo& info)
    {
        const std::string speedStr = (info.pointsPerSecond < 0.01) ? "< 0.01 MKey/s" : std::format("{:.3f} MKey/s", info.pointsPerSecond);

        const std::string totalStr = std::format(std::locale("en_US.UTF-8"), "({:L} total)", info.total);
        const std::string timeStr = std::format("[{:.2f}s | {}]", info.seconds, utils::formatSeconds(static_cast<uint32_t>(info.totalTime / 1000)));
        const uint64_t usedDeviceMemoryMb = (info.totalDeviceMemory - info.freeDeviceMemory) / MB;
        const uint64_t totalDeviceMemoryMb = info.totalDeviceMemory / MB;

        const std::string statusStr = std::format("[{} | {} | {}/{}MB] [{}/{}] {} {} {}"
            , info.device, info.deviceName, usedDeviceMemoryMb, totalDeviceMemoryMb
            , info.iteration, info.totalIterations
            , speedStr, totalStr, timeStr);

        // fprintf(stderr, "\r%s", statusStr.c_str());
        BOOST_LOG_TRIVIAL(info) << statusStr;
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
    context->statusCallback = statusCallback;

    utils::initLogging(context->config.log());

    const bool devMode = context->config.devMode();
    if (devMode)
    {
        BOOST_LOG_TRIVIAL(info) << "Dev Mode ON";
    }

    if (context->httpClient->hostAlive())
    {
        BOOST_LOG_TRIVIAL(info) << std::format("Http Server ({}) is alive", context->httpClient->hostConfig());
    }
    else if(!devMode)
    {
        BOOST_LOG_TRIVIAL(info) << std::format("Http Server ({}) is NOT alive and in production", context->httpClient->hostConfig());
        return 2;
    }

    // load hash160 targets to memory
    utils::readHash160Targets(context->config.hunter().ripemd160TargetsFilePaths, context->hash160Targets);

    if (context->hash160Targets.empty())
    {
        BOOST_LOG_TRIVIAL(info) << "Stopping application as hash160 targets are not set";
        return 3;
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