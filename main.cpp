#include <iostream>
#include <fstream>
#include <thread>

#include <fmt/core.h>

#include "key_generator.h"
#include "key_processor.h"

using namespace std;

constexpr int cudaDeviceId{0};

void statusCallback(StatusInfo info)
{
    fmt::print("total: {}, speed: {} points/sec, elapsed: {}\n", info.total, info.speed, info.freeMemory);
}

int main()
{
    std::cout << "Main Thread ID: " << std::this_thread::get_id() << std::endl;

    const auto sharedDataQueue = make_shared<DataQueue>();

    const KeyGenerator keyGenerator({sharedDataQueue, statusCallback});
    const KeyProcessor keyProcessor(sharedDataQueue);
    // keyGenerator.selfTest(896);

    keyGenerator.startRandom(10);
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