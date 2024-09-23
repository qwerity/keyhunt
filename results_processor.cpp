#include "results_processor.h"
#include "util/utils.h"

#include <thread>
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

                BOOST_LOG_TRIVIAL(info) << " private key: " << utils::convertToHexString(result.privateKey, 8)
                                        << ", public X key: " << utils::convertToHexString(result.publicXKey, 8)
                                        << ", hash: " << utils::convertToHexString(result.digest, 5)
                                        << ", iteration: " << result.iteration << ", index: " << result.idx << ", compressed: " << result.compressed;
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
