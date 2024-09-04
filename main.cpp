#include "key_generator.h"
#include "key_processor.h"

#include "util/log.h"

#include <format>

constexpr int cudaDeviceId{0};

void statusCallback(StatusInfo info)
{
    BOOST_LOG_TRIVIAL(info) << std::format("total: {}, seconds: {}, speed: {} points/sec\n", info.total, info.seconds, info.speed);
}

int main()
{
    initLogging();

    const auto sharedDataQueue = std::make_shared<DataQueue>();

    const KeyGenerator keyGenerator({sharedDataQueue, statusCallback});
    const KeyProcessor keyProcessor(sharedDataQueue);

    keyGenerator.startRandom(10'000, 128);
    keyProcessor.start();

    // Giving some time to process, otherwise main thread will force stop the processing
    while (!keyGenerator.isDone() && sharedDataQueue->empty())
    {
        // fmt::print("Remain data to process: {}\n", sharedDataQueue->empty());
        std::this_thread::yield(); // If the queue is full, yield to avoid busy-wait
    }

    keyGenerator.stop();
    keyProcessor.stop();

    return 0;
}