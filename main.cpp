#include "key_hunter.h"
#include "results_processor.h"

#include "util/utils.h"

#include <thread>
#include <format>

#include <boost/log/trivial.hpp>

void statusCallback(const StatusInfo &info)
{
    const std::string speedStr = (info.pointsPerSecond < 0.01) ? "< 0.01 MKey/s" : std::format("{:.3} MKey/s", info.pointsPerSecond) ;

    const std::string totalStr = std::format(std::locale("en_US.UTF-8"), "({:L} total)", info.total);
    const std::string timeStr = std::format("[{:.2}s | {}]", info.seconds, utils::formatSeconds(static_cast<uint32_t>(info.totalTime / 1000)));
    const uint64_t usedDeviceMemoryMb = (info.totalDeviceMemory - info.freeDeviceMemory) / MB;
    const uint64_t totalDeviceMemoryMb = info.totalDeviceMemory / MB;

    const std::string statusStr = std::format("[{}] {} | {}/{}MB | [{}/{}] {} {} {}"
        , info.device, info.deviceName, usedDeviceMemoryMb, totalDeviceMemoryMb
        , info.iteration
        , info.totalIterations
        , speedStr, totalStr, timeStr);

//    fprintf(stderr, "\r%s", statusStr.c_str());
    BOOST_LOG_TRIVIAL(info) << statusStr;
}

int main()
{
    // Config will initialized here
    std::shared_ptr<GlobalContext> context = std::make_shared<GlobalContext>();
    if (!context->config.isLoaded())
    {
        return -1;
    }

    context->dataQueue = std::make_shared<DataQueue>();
    context->hash160SearchResultsQueue = std::make_shared<Hash160SearchResultsQueue>();
    context->statusCallback = statusCallback;

    utils::initLogging(context->config.log());

    utils::readHash160Targets(context->config.hunter().ripemd160TargetsFilePaths, context->targets);

    // Start generation checking and results processing
    const KeyHunter keyHunter(context);
    const ResultsProcessor resultProcessor(context);
    resultProcessor.startHash160ResultsQueueProcessing();

    constexpr uint32_t cudaDeviceId = 0;
    keyHunter.startSearchPublicHashThread(cudaDeviceId);

    // Giving some time to process, otherwise main thread will force stop the processing
    while (!keyHunter.isDone())
    {
        std::this_thread::yield(); // If the queue is full, yield to avoid busy-wait
    }

    return 0;
}