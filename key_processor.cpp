#include "key_processor.h"

#include <format>
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
            std::cout << "KeyProcessor Thread ID: " << std::this_thread::get_id() << std::endl;

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

                // BOOST_LOG_TRIVIAL(info) << "KeyProcessor: New data to process";

                constexpr bool compressed{false};
                // std::string address = Address::fromPublicKey(publicKeys[i], compressed);

                for (const auto& [gpuPrivateKey, gpuPublicKey] : *keyPairs)
                {
                    const secp256k1::ecpoint pCPU = secp256k1::multiplyPoint(gpuPrivateKey, secp256k1::G());
                    if (pCPU != gpuPublicKey)
                    {
                       BOOST_LOG_TRIVIAL(info) << "KeyProcessor: gen key is not correct";
                       BOOST_LOG_TRIVIAL(info) << std::format("{} {}\n", gpuPrivateKey.toString(compressed), gpuPublicKey.toString(compressed));
                    }
                    BOOST_LOG_TRIVIAL(info) << std::format("{} {}\n", gpuPrivateKey.toString(compressed), gpuPublicKey.toString(compressed));
                }

                delete keyPairs;
            }
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
