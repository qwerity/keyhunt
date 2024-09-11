#include "key_processor.h"
#include "util/utils.h"

#include <thread>
#include <boost/log/trivial.hpp>

struct KeyProcessor::Impl
{
    std::shared_ptr<DataQueue> mDataQueue;
    std::atomic<bool> mStopFlag{false};

    std::thread mThread;

    explicit Impl(const std::shared_ptr<DataQueue> &dataQueue) : mDataQueue(dataQueue) {}
    ~Impl()
    {
        stop();
    }

    void start()
    {
        mThread = std::thread([this]()
        {
            BOOST_LOG_TRIVIAL(info) << "KeyProcessor Thread running: " << std::this_thread::get_id();

            while (!mStopFlag || !mDataQueue->empty())
            {
                Secp256k1KeyPairs* keyPairs{nullptr};

                while (!mDataQueue->pop(keyPairs))
                {
                    if (mStopFlag)
                        return;

                    std::this_thread::yield(); // If the queue is empty, yield to avoid busy-wait
                }

                if (!keyPairs)
                {
                    BOOST_LOG_TRIVIAL(info) << "KeyProcessor: someone added nullptr item to queue";
                    continue;
                }

                std::ranges::for_each(*keyPairs, [&](const Secp256k1KeyPair& keyPair)
                {
                    constexpr bool compressed{false};
                    const secp256k1::ecpoint pCPU = secp256k1::multiplyPoint(keyPair.privateKey, secp256k1::G());
                    if (pCPU != keyPair.publicKey)
                    {
                        BOOST_LOG_TRIVIAL(info) << "KeyProcessor: gen key is not correct";
                        BOOST_LOG_TRIVIAL(info) << utils::format("{} {}\n", keyPair.privateKey.toString(compressed), keyPair.publicKey.toString(compressed));
                    }
                });

                delete keyPairs;
            }

            BOOST_LOG_TRIVIAL(info) << "KeyProcessor: done";
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

KeyProcessor::KeyProcessor(const std::shared_ptr<DataQueue>& dataQueue) : mImpl(std::make_unique<Impl>(dataQueue)) {}
KeyProcessor::~KeyProcessor() = default;

void KeyProcessor::start() const
{
    mImpl->start();
}

void KeyProcessor::stop() const
{
    mImpl->stop();
}
