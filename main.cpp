#include <format>
#include <iostream>
#include <fstream>
#include <thread>

#include "key_generator.h"
#include "key_processor.h"

#include <boost/log/trivial.hpp>
#include <boost/log/utility/setup.hpp>

using namespace std;

constexpr int cudaDeviceId{0};

void initLogging(const std::string& logFile = "app.log")
{
    // Setting up a simple console logger
    boost::log::add_console_log(std::cerr);
    // boost::log::add_console_log(std::cerr, boost::log::keywords::format = "[%TimeStamp%] [%ThreadID%]: %Message%");

    // // Setting up a file logger
    // boost::log::add_file_log(logFile, boost::log::keywords::format = "[%TimeStamp%] [%ThreadID%]: %Message%");
    //
    // // Enable logging for all levels
    // boost::log::core::get()->set_filter(boost::log::trivial::severity >= boost::log::trivial::trace);

    // Add attributes like timestamp and thread id
    boost::log::add_common_attributes();
}

void statusCallback(StatusInfo info)
{
    BOOST_LOG_TRIVIAL(info) << std::format("total: {}, seconds: {}, speed: {} points/sec\n", info.total, info.seconds, info.speed);
}

int main()
{
    initLogging();

    const auto sharedDataQueue = make_shared<DataQueue>();

    const KeyGenerator keyGenerator({sharedDataQueue, statusCallback});
    const KeyProcessor keyProcessor(sharedDataQueue);
    // keyGenerator.selfTest(896);

    keyGenerator.startRandom(10'000'000, 128);
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