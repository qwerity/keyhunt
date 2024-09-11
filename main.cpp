#include "key_hunter.h"
#include "key_processor.h"

#include "util/utils.h"

#include <boost/log/trivial.hpp>
#include <CLI/CLI.hpp>

void statusCallback(const StatusInfo &info)
{
    constexpr uint32_t MB{1024 * 1024};

    const std::string speedStr = (info.pointsPerSecond < 0.01) ? "< 0.01 MKey/s" : utils::format("%.2f", info.pointsPerSecond) + " MKey/s";

    const std::string totalStr = utils::format("(%s total)", utils::formatThousands(info.total).c_str());
    const std::string timeStr = utils::format("[%0.2fs | %s]", info.seconds, utils::formatSeconds(static_cast<uint32_t>(info.totalTime / 1000)).c_str());
    const uint32_t usedDeviceMemoryMb = (info.totalDeviceMemory - info.freeDeviceMemory) / MB;
    const uint32_t totalDeviceMemoryMb = info.totalDeviceMemory / MB;

    BOOST_LOG_TRIVIAL(info) << utils::format("[%d] %s | %d/%dMB | [%d/%d] %s %s %s"
        , info.device, info.deviceName.c_str(), usedDeviceMemoryMb, totalDeviceMemoryMb
        , info.iteration
        , info.remainsIterations
        , speedStr.c_str(), totalStr.c_str(), timeStr.c_str());
}

void parseArguments(const int argc, const char **argv, CLI::App &app, Settings &params)
{
    app.add_option("-t,--targets", params.ripemd160TargetsFilePath, "File path with target RipeMD-160 hash list")->check(CLI::ExistingFile);

    app.add_option("-d,--cudaDeviceId", params.cudaDeviceId, "Cuda device ID")->default_val(0);
    app.add_option("-p,--pointsPerThread", params.pointsPerThread, "How many keys will be generated per each cuda thread")->default_val(128);
    app.add_option("-k,--keysNumberToGenerate", params.keysNumberToGenerate, "Number of keys to generate")->default_val(900);
    app.add_option("-x,--privateX", params.privateXPart, "Private x part for random generation")->default_val(1);
    app.add_option("-c,--publicKeyCompressionTypeToCheck", params.publicKeyCompressionTypeToCheck, "Public key compression type to check")->default_val(2);
    app.add_option("-s,--status-period-ms", params.statusCallbackPeriodMs, "Status callback period in milliseconds")->default_val(1000);

    try
    {
        app.parse(argc, argv);
    }
    catch (const CLI::CallForHelp &e)
    {
        std::cerr << app.help() << std::endl;
        std::exit(EXIT_SUCCESS);
    }
    catch (const CLI::ParseError &e)
    {
        std::cerr << app.help() << std::endl;
        std::exit(app.exit(e));
    }
}

int main(const int argc, const char **argv)
{
    CLI::App app{"cuda-keyhunt-pvk"};
    Settings settings;
    parseArguments(argc, argv, app, settings);

    utils::initLogging();

    const auto sharedDataQueue = std::make_shared<DataQueue>();
    const auto cudaInfo = cu::getDeviceInfo(settings.cudaDeviceId);
    // printDeviceInfo(cudaInfo);

    const KeyHunter keyHunter({settings, cudaInfo, sharedDataQueue, statusCallback});
    const KeyProcessor keyProcessor(sharedDataQueue);

    keyHunter.findPublicHashWithPrivateDefinedXRandomY();
    // keyHunter.startWithRandomPrivateKeys();
    keyProcessor.start();

    // Giving some time to process, otherwise main thread will force stop the processing
    while (!keyHunter.isDone() && sharedDataQueue->empty())
    {
        // fmt::print("Remain data to process: {}\n", sharedDataQueue->empty());
        std::this_thread::yield(); // If the queue is full, yield to avoid busy-wait
    }

    keyHunter.stop();
    keyProcessor.stop();

    return 0;
}