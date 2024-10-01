#include "results_processor.h"
#include "util/utils.h"

#include <thread>
#include <format>

#include <boost/log/trivial.hpp>

struct ResultsProcessor::Impl
{
    std::shared_ptr<GlobalContext> mgContext;
    std::unique_ptr<HttpClient> httpClient;

    std::atomic<bool> mStopFlag{false};

    std::thread mThread;

    explicit Impl(const std::shared_ptr<GlobalContext>& context) : mgContext(context), httpClient{std::make_unique<HttpClient>(context->config.server())} {}
    ~Impl()
    {
        stop();
    }

    void startHash160ResultsQueueProcessing()
    {
        mThread = std::thread([this]()
        {
            BOOST_LOG_TRIVIAL(trace) << "ResultsProcessor Thread running: " << std::this_thread::get_id();

            while (!mStopFlag)
            {
                Hash160SearchResult result;

                while (!mgContext->hash160SearchResultsQueue->pop(result))
                {
                    if (mStopFlag)
                    {
                        return;
                    }

                    std::this_thread::yield(); // If the queue is empty, yield to avoid busy-wait
                }

                /// TODO(ksh): commented as it is not needed, only useful for debugging purposes
                //const std::string publicXStr{utils::convertToHexString(result.publicXKey, 8)};
                const std::string privateStr{utils::convertToHexString(result.privateKey, 8)};
                const std::string hash160Str{utils::convertToHexString(result.digest, 5)};

                // if it is not test: set_found for privateXPart
                if (!mgContext->config.hunter().forcePrivateXPart && mgContext->config.hunter().keysNumberToGenerate == 0)
                {
                    httpClient->setFound(result.privateXPart, privateStr);
                }

                const std::string resultsStr = std::format("[{}][({:>10}, {:>10}) | {:<12}] private: {}, hash160: {}",
                                                           result.cudaDeviceId, result.privateXPart, result.privateYPart, (result.compressed ? "compressed" : "uncompressed"),
                                                           privateStr, hash160Str);

                utils::appendToFile("results.txt", resultsStr);
                //BOOST_LOG_TRIVIAL(info) << resultsStr;
            }

            BOOST_LOG_TRIVIAL(info) << "ResultsProcessor: done";
        });
    }

    void stop()
    {
        BOOST_LOG_TRIVIAL(trace) << "ResultsProcessor stopping";

        mStopFlag = true;
        if (mThread.joinable())
        {
            mThread.join();
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
