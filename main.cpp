#include "key_hunter.h"
#include "key_processor.h"

#include "util/utils.h"

#include <thread>
#include <boost/log/trivial.hpp>

void statusCallback(const StatusInfo &info)
{
    const std::string speedStr = (info.pointsPerSecond < 0.01) ? "< 0.01 MKey/s" : utils::format("%.3f", info.pointsPerSecond) + " MKey/s";

    const std::string totalStr = utils::format("(%s total)", utils::formatThousands(info.total).c_str());
    const std::string timeStr = utils::format("[%0.2fs | %s]", info.seconds, utils::formatSeconds(static_cast<uint32_t>(info.totalTime / 1000)).c_str());
    const uint32_t usedDeviceMemoryMb = (info.totalDeviceMemory - info.freeDeviceMemory) / MB;
    const uint32_t totalDeviceMemoryMb = info.totalDeviceMemory / MB;

    const std::string statusStr = utils::format("[%d] %s | %d/%dMB | [%d/%d] %s %s %s"
        , info.device, info.deviceName.c_str(), usedDeviceMemoryMb, totalDeviceMemoryMb
        , info.iteration
        , info.totalIterations
        , speedStr.c_str(), totalStr.c_str(), timeStr.c_str());

    // fprintf(stderr, "\r%s", statusStr.c_str());
    BOOST_LOG_TRIVIAL(info) << statusStr;
}

int main()
{
    const Config config;
    utils::initLogging(config.log);

    const auto sharedDataQueue = std::make_shared<DataQueue>();
    const auto sharedHash160SearchResultsQueue = std::make_shared<Hash160SearchResultsQueue>();
    const auto cudaInfo = cu::getDeviceInfo(config.cudaDeviceId);
    // printDeviceInfo(cudaInfo);

    const KeyHunter keyHunter({config, cudaInfo, sharedDataQueue, sharedHash160SearchResultsQueue, statusCallback});
    const KeyProcessor keyProcessor(sharedDataQueue);

    keyHunter.findPublicHashWithPrivateDefinedXRandomY();
    // keyHunter.startWithRandomPrivateKeys();
    // keyProcessor.start();

    // Giving some time to process, otherwise main thread will force stop the processing
    while (!keyHunter.isDone() && sharedDataQueue->empty())
    {
        // fmt::print("Remain data to process: {}\n", sharedDataQueue->empty());
        std::this_thread::yield(); // If the queue is full, yield to avoid busy-wait
    }

    keyHunter.stop();
    // keyProcessor.stop();

    return 0;
}