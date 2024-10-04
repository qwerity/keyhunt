#include "results_processor.h"
#include "util/utils.h"

#include <thread>
#include <format>

#include <boost/log/trivial.hpp>

struct ResultsProcessor::Impl
{
    std::shared_ptr<GlobalContext> gContext;

    std::atomic<bool> stopFlag{false};

    std::thread thread;

    explicit Impl(const std::shared_ptr<GlobalContext>& context) : gContext(context) {}
    ~Impl()
    {
        stop();
    }

    Impl(const Impl& other) = delete;
    Impl& operator=(const Impl& other) = delete;

    void startHash160ResultsQueueProcessing()
    {
        thread = std::thread([this]()
        {
            BOOST_LOG_TRIVIAL(trace) << "ResultsProcessor Thread running: " << std::this_thread::get_id();

            while (!stopFlag)
            {
                Hash160SearchResult result;

                while (!gContext->hash160SearchResultsQueue->pop(result))
                {
                    if (stopFlag)
                    {
                        return;
                    }

                    std::this_thread::yield(); // If the queue is empty, yield to avoid busy-wait
                }

                /// TODO(ksh): commented as it is not needed, only useful for debugging purposes
                //const std::string publicXStr{utils::convertToHexString(result.publicXKey, 8)};
                const std::string privateStr{utils::convertToHexString(result.privateKey, 8)};
                const std::string hash160Str{utils::convertToHexString(result.digest, 5)};

                const std::string resultsStr = std::format("[{}][({:>10}, {:>10}) | {:<12}] private: {}, hash160: {}",
                                                           result.cudaDeviceId, result.privateXPart, result.privateYPart, (result.compressed ? "compressed" : "uncompressed"),
                                                           privateStr, hash160Str);

                // if it is not test: set_found for privateXPart
                if (!gContext->config.devMode())
                {
                    gContext->httpClient->setFound(result.privateXPart, privateStr);
                    utils::backupToTGAsync(resultsStr);
                }

                utils::appendToFile("results.txt", resultsStr);
                //BOOST_LOG_TRIVIAL(trace) << resultsStr;
            }

            BOOST_LOG_TRIVIAL(info) << "ResultsProcessor: done";
        });
    }

    void stop()
    {
        BOOST_LOG_TRIVIAL(trace) << "ResultsProcessor stopping";

        stopFlag = true;
        if (thread.joinable())
        {
            thread.join();
        }

        BOOST_LOG_TRIVIAL(trace) << "ResultsProcessor stopped";
    }
};

ResultsProcessor::ResultsProcessor(const std::shared_ptr<GlobalContext>& context) : mImpl(std::make_unique<Impl>(context)) {}
ResultsProcessor::~ResultsProcessor() = default;

void ResultsProcessor::startHash160ResultsQueueProcessing() const
{
    mImpl->startHash160ResultsQueueProcessing();
}

void ResultsProcessor::stop() const
{
    mImpl->stop();
}
