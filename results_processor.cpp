#include "results_processor.h"
#include "util/utils.h"

#include <thread>
#include <format>

#include <boost/log/trivial.hpp>

struct ResultsProcessor::Impl
{
    GlobalContext mgContext;

    std::atomic<bool> mStopFlag{false};

    std::thread mThread;

    explicit Impl(GlobalContext context) : mgContext(std::move(context)) {}
    ~Impl()
    {
        stop();
    }

    void start()
    {
        mThread = std::thread([this]()
        {
            BOOST_LOG_TRIVIAL(info) << "ResultsProcessor Thread running: " << std::this_thread::get_id();

            while (!mStopFlag || !mgContext.dataQueue->empty())
            {
                Secp256k1KeyPairs* keyPairs{nullptr};

                while (!mgContext.dataQueue->pop(keyPairs))
                {
                    if (mStopFlag)
                        return;

                    std::this_thread::yield(); // If the queue is empty, yield to avoid busy-wait
                }

                if (!keyPairs)
                {
                    BOOST_LOG_TRIVIAL(info) << "ResultsProcessor: someone added nullptr item to queue";
                    continue;
                }

                std::ranges::for_each(*keyPairs, [&](const Secp256k1KeyPair& keyPair)
                {
                    constexpr bool compressed{false};
                    const secp256k1::ecpoint pCPU = secp256k1::multiplyPoint(keyPair.privateKey, secp256k1::G());
                    if (pCPU != keyPair.publicKey)
                    {
                        BOOST_LOG_TRIVIAL(info) << "ResultsProcessor: gen key is not correct";
                        BOOST_LOG_TRIVIAL(info) << keyPair.privateKey.toString(compressed) << " " << keyPair.publicKey.toString(compressed);
                    }
                });

                delete keyPairs;
            }

            BOOST_LOG_TRIVIAL(info) << "ResultsProcessor: done";
        });
    }

    void startHash160ResultsQueueProcessing()
    {
        mThread = std::thread([this]()
        {
            BOOST_LOG_TRIVIAL(info) << "ResultsProcessor Thread running: " << std::this_thread::get_id();

            while (!mStopFlag)
            {
                Hash160SearchResult result;

                while (!mgContext.hash160SearchResultsQueue->pop(result))
                {
                    if (mStopFlag)
                        return;

                    std::this_thread::yield(); // If the queue is empty, yield to avoid busy-wait
                }

                const std::string privateStr{utils::convertToHexString(result.privateKey, 8)};
                const std::string publicXStr{utils::convertToHexString(result.publicXKey, 8)};
                const std::string hash160Str{utils::convertToHexString(result.digest, 5)};

                const std::string resultsStr = std::format("private: {}, publicX: {}, hash160: {}, iteration: {}, index: {}, compressed: {}",
                                                           privateStr, publicXStr, hash160Str, result.iteration, result.idx, result.compressed);

                utils::appendToFile("results.txt", resultsStr);
                // BOOST_LOG_TRIVIAL(info) << resultsStr;
            }

            BOOST_LOG_TRIVIAL(info) << "ResultsProcessor: done";
        });
    }

    void stop()
    {
        mStopFlag = true;
        if (mThread.joinable())
        {
            mThread.join();
        }
    }
};

ResultsProcessor::ResultsProcessor(const GlobalContext& context) : mImpl(std::make_unique<Impl>(context)) {}
ResultsProcessor::~ResultsProcessor() = default;

void ResultsProcessor::start() const
{
    mImpl->start();
}

void ResultsProcessor::startHash160ResultsQueueProcessing() const
{
    mImpl->startHash160ResultsQueueProcessing();
}

void ResultsProcessor::stop() const
{
    mImpl->stop();
}
