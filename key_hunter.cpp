#include "key_hunter.h"

#include <format>
#include <utility>
#include <functional>
#include <boost/log/trivial.hpp>

#include "cuda/ecc.cuh"
#include "util/cuda_util.h"
#include "util/utils.h"


struct KeyHunter::Impl
{
    const AppConfig& mAppConfig;

    std::thread mThread;

    thrust::host_vector<secp256k1::uint256> mCurrentPrivateKeys;
    std::unique_ptr<ECC> mCuECC;

    mutable utils::Timer mTimer;

    std::shared_ptr<DataQueue> mDataQueue;
    std::atomic<bool> mStopFlag{false};
    mutable std::atomic<bool> mDone{false};

    std::function<void(StatusInfo)> mStatusCallback;

    // Implementation
    explicit Impl(const AppConfig& config)
    : mAppConfig(config)
    , mCuECC(std::make_unique<ECC>())
    , mDataQueue(config.dataQueue)
    , mStatusCallback(config.statusCallback)
    {
        cu::cudaInit(config.appParams.cudaDeviceId);
    }

    ~Impl()
    {
        stop();
    }

    void start(const thrust::host_vector<secp256k1::uint256>& privateKeys, const uint32_t pointsPerThread)
    {
        mCurrentPrivateKeys = privateKeys;
        mCuECC->init(pointsPerThread, privateKeys);

        mThread = std::thread(&Impl::run, this);
    }

    void startWithRandomPrivateKeys()
    {
        mCurrentPrivateKeys = utils::generateRandomPrivateKeys(mAppConfig.appParams.keysNumberToGenerate);
        mCuECC->init(mAppConfig.appParams.pointsPerThread, mCurrentPrivateKeys);

        mThread = std::thread(&Impl::run, this);
    }

    void stop()
    {
        mStopFlag = true;
        if (mThread.joinable())
        {
            mThread.join();
        }
    }

    bool isDone() const { return mDone; }

    void selfTest(const uint32_t keysNumberToGenerate) const
    {
        BOOST_LOG_TRIVIAL(info) << "KeyGenerator::selfTest started";

        const thrust::host_vector<secp256k1::uint256> privateKeys = utils::generateRandomPrivateKeys(keysNumberToGenerate);

        mCuECC->init(32, privateKeys);

        cu::safeCall(mCuECC->generatePublicKeys());

        if (mCuECC->selfTest(privateKeys))
        {
            BOOST_LOG_TRIVIAL(info) << "KeyGenerator::selfTest done";
        }
        else
        {
            BOOST_LOG_TRIVIAL(info) << "KeyGenerator::selfTest fails";
        }

        thrust::host_vector<std::pair<uint32_t, secp256k1::ecpoint>> results;
        cu::safeCall(mCuECC->getResults(results));

        // bool compressed{false};
        // for (uint32_t i = 0; i < publicKeys.size(); i++)
        // {
        //    std::string address = Address::fromPublicKey(publicKeys[i], compressed);
        //     BOOST_LOG_TRIVIAL(info) << privateKeys[i].toString(compressed) << " ";
        //                             << publicKeys[i].toString(compressed) << " "
        //                             << address;
        // }
    }

    void run() const
    {
        std::cout << "KeyGenerator Thread ID: " << std::this_thread::get_id() << std::endl;

        uint64_t generatedPointsCounter{0};
        while (!mStopFlag && !mDone)
        {
            mTimer.start();
            cu::safeCall(mCuECC->generatePublicKeys());
            generatedPointsCounter += mCurrentPrivateKeys.size();

            const auto seconds = static_cast<double>(mTimer.getTime()) / 1000.0;
            // if (seconds >= 1000.0)
            {
                StatusInfo info;
                info.total = generatedPointsCounter;
                info.seconds = seconds;
                info.speed = static_cast<double>(generatedPointsCounter) / seconds;
                generatedPointsCounter = 0;
                mStatusCallback(info);
            }

            BOOST_LOG_TRIVIAL(info) << "KeyGenerator: generated done";

            thrust::host_vector<std::pair<uint32_t, secp256k1::ecpoint>> results;
            cu::safeCall(mCuECC->getResults(results));

            BOOST_LOG_TRIVIAL(info) << std::format("KeyGenerator: generated {} keys\n", results.size());

            // to be deleted in KeyProcessor
            auto* pairs = new Secp256k1KeyPairs;
            for (const auto &[privateKeyIndex, publicKey] : results)
            {
                pairs->push_back({mCurrentPrivateKeys[privateKeyIndex], publicKey});
            }

            while (!mDataQueue->push(pairs))
            {
                if (mStopFlag)
                    return;

                // If the queue is full, yield to avoid busy-wait
                std::this_thread::yield();
            }


            mDone = true;
            BOOST_LOG_TRIVIAL(info) << "KeyGenerator: done";
        }
    }
};

KeyHunter::KeyHunter(const AppConfig& config) : mImpl(std::make_unique<Impl>(config)) {}

KeyHunter::~KeyHunter() = default;

KeyHunter::KeyHunter(KeyHunter &&rhs) noexcept = default;

KeyHunter& KeyHunter::operator=(KeyHunter &&rhs) noexcept = default;

void KeyHunter::start(const thrust::host_vector<secp256k1::uint256>& privateKeys, const uint32_t pointsPerThread) const
{
    mImpl->start(privateKeys, pointsPerThread);
}

void KeyHunter::startWithRandomPrivateKeys() const
{
    mImpl->startWithRandomPrivateKeys();
}

void KeyHunter::stop() const
{
    mImpl->stop();
}

bool KeyHunter::isDone() const
{
    return mImpl->isDone();
}

void KeyHunter::selfTest(const uint32_t keysNumberToGenerate) const
{
    mImpl->selfTest(keysNumberToGenerate);
}
