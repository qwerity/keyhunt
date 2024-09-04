#include "key_hunter.h"
#include "key_processor.h"

#include "util/utils.h"

#include <CLI/CLI.hpp>

#include <format>

void statusCallback(StatusInfo info)
{
    BOOST_LOG_TRIVIAL(info) << std::format("total: {}, seconds: {}, speed: {} points/sec\n", info.total, info.seconds, info.speed);
}

void parseArguments(const int argc, const char **argv, CLI::App &app, ApplicationParameters &params)
{
    app.add_option("-t,--targets", params.ripemd160TargetsFilePath, "File path with target RipeMD-160 hash list")
        /*->required()*/->check(CLI::ExistingFile);

    app.add_option("-d,--cudaDeviceId", params.cudaDeviceId, "Cuda device ID")->default_val(0);
    app.add_option("-p,--pointsPerThread", params.pointsPerThread, "How many keys will be generated per each cuda thread")->default_val(128);
    app.add_option("-k,--keysNumberToGenerate", params.keysNumberToGenerate, "Number of keys to generate")->default_val(900);

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
        std::exit(app.exit(e));
    }
}

int main(const int argc, const char **argv)
{
    CLI::App app{"cuda-keyhunt-pvk"};
    ApplicationParameters params;
    parseArguments(argc, argv, app, params);

    utils::initLogging();

    const auto sharedDataQueue = std::make_shared<DataQueue>();

    const KeyHunter keyHunter({params, sharedDataQueue, statusCallback});
    const KeyProcessor keyProcessor(sharedDataQueue);

    keyHunter.startWithRandomPrivateKeys();
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