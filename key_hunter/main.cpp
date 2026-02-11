#include "key_hunter.h"
#include "util/results_processor.h"

#include "util/common_host.h"
#include "util/utils.h"
#include "util/xpart_manager.h"

#include <thread>
#include <format>
#include <future>

#include <boost/log/trivial.hpp>

static std::string formatMKeys(double mkeys)
{
    return (mkeys < 0.01) ? "< 0.01" : std::format("{:.2f}", mkeys);
}

void statusCallback(const StatusInfo& info)
{
    double avgMKeys = info.dataPerSecond;
    if (info.totalTime > 0 && info.totalKeysSinceStart > 0)
    {
        const double totalSec = static_cast<double>(info.totalTime) / 1000.0;
        avgMKeys = (static_cast<double>(info.totalKeysSinceStart) / totalSec) / 1e6;
    }

    const std::string curStr = formatMKeys(info.dataPerSecond);
    const std::string minStr = formatMKeys(info.minDataPerSecond);
    const std::string avgStr = formatMKeys(avgMKeys);
    const std::string speedStr = std::format("cur {} min {} avg {} MKey/s", curStr, minStr, avgStr);

    const std::string totalStr = std::format(std::locale("en_US.UTF-8"), "({:L} total)", info.totalKeysSinceStart);
    const std::string timeStr = std::format("[{:.3f}s | {}]", info.seconds, utils::formatSeconds(static_cast<uint32_t>(info.totalTime / 1000)));
    const uint64_t usedDeviceMemoryMb = (info.totalDeviceMemory - info.freeDeviceMemory) / MB;
    const uint64_t totalDeviceMemoryMb = info.totalDeviceMemory / MB;

    const std::string statusStr = std::format("[{} | {} | {}/{}MB] [{}/{}] {} {} {}"
        , info.device, info.deviceName, usedDeviceMemoryMb, totalDeviceMemoryMb
        , info.iteration, info.totalIterations
        , speedStr, totalStr, timeStr);

    BOOST_LOG_TRIVIAL(fatal) << statusStr;
}

void setupPrivateXPart(const std::shared_ptr<GlobalContext>& context)
{
    const HunterConfig& hunter = context->config.hunter();

    const bool devMode = hunter.forcePrivateXPart || (hunter.keysNumberToGenerate != 0);
    context->config.setDevMode(devMode);

    BOOST_LOG_TRIVIAL(info) << std::format(std::locale("en_US.UTF-8"), "{} Mode ON [forcePrivateXPart: {} | keysNumberToGenerate: {:L}]", (devMode ? "Dev" : "Prod"), hunter.forcePrivateXPart, hunter.keysNumberToGenerate);

    // Don't check host if using forcePrivateXPart or specificXValues - these are local values, not from server
    if (hunter.forcePrivateXPart || !hunter.specificXValues.empty())
    {
        if (hunter.forcePrivateXPart)
        {
            BOOST_LOG_TRIVIAL(info) << "Using private X part: " << hunter.privateXPart;
        }
        else
        {
            BOOST_LOG_TRIVIAL(info) << std::format("Using specific X values mode: {:L} values (skipping host check)", hunter.specificXValues.size());
        }
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
        context->config.setRandomGeneration(true);
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
    context->statusCallback = statusCallback;

    utils::initLogging(context->config.log());

    setupPrivateXPart(context);

    // Get GPU count early for XPartManager initialization
    const int gpuDevicesCount = cu::getDeviceCount();
    BOOST_LOG_TRIVIAL(info) << std::format("Detected {} GPU device(s)", gpuDevicesCount);

    // Initialize XPartManager for async non-blocking X part distribution (improves multi-GPU performance)
    // Only use it if not in forcePrivateXPart mode, not using specificXValues, and HTTP is available
    const bool useXPartManager = !context->config.hunter().forcePrivateXPart && 
                                  context->config.hunter().specificXValues.empty() &&
                                  !context->config.dataGenerationIsRandom() &&
                                  context->httpClient->hostAlive();
    if (useXPartManager)
    {
        BOOST_LOG_TRIVIAL(info) << std::format("Initializing XPartManager for async X part distribution (multi-GPU optimized, queue size: {})", gpuDevicesCount);
        auto fetcherClient = std::make_shared<HttpClient>(context->config.server(), 5, 5);  // strict 5s timeout for get_number
        context->xPartManager = std::make_shared<XPartManager>(fetcherClient, context->httpClient, context->config.dataGenerationIsRandom(), static_cast<size_t>(gpuDevicesCount));
    }
    else
    {
        BOOST_LOG_TRIVIAL(info) << "XPartManager disabled (using synchronous mode)";
    }

    // load hash160 targets to memory
    utils::readHash160Targets(context->config.hunter().ripemd160TargetsFilePaths, context->hash160Targets);
    if (context->hash160Targets.empty())
    {
        BOOST_LOG_TRIVIAL(info) << "Stopping application as hash160 targets are not set";
        return 2;
    }
    BOOST_LOG_TRIVIAL(info) << std::format(std::locale("en_US.UTF-8"), "Loaded {:L} hash160 targets", context->hash160Targets.size());

    // Start generation checking and results processing
    const ResultsProcessor resultProcessor(context);
    resultProcessor.startHash160ResultsQueueProcessing();
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