#include "key_processor.h"

#include <thread>
#include <fmt/os.h>
#include <fmt/core.h>

struct KeyProcessor::Impl
{
    std::shared_ptr<DataQueue> mDataQueue;
    std::atomic<bool> mStopFlag{false};

    std::thread mThread;

    const std::string mOutputPath{"output.txt"};
    fmt::ostream mResultOutFile = fmt::output_file(mOutputPath);

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
                    fmt::print("KeyProcessor: someone added nullptr item to queue\n");
                    continue;
                }

                fmt::print("KeyProcessor: New data to process\n");

                constexpr bool compressed{false};
                for (const auto& [privateKey, publicKey] : *keyPairs)
                {
                    // std::string address = Address::fromPublicKey(publicKeys[i], compressed);
                    mResultOutFile.print("{} {}\n", privateKey.toString(compressed), publicKey.toString(compressed));
                    mResultOutFile.flush();
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
