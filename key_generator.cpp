#include "key_generator.h"

#include <utility>
#include <functional>
#include <fmt/core.h>

#include "cuda/ecc.cuh"
#include "util/cuda_util.h"
#include "util/utils.h"

namespace
{
    thrust::host_vector<secp256k1::uint256> generateRandomPrivateKeys(const uint32_t keysNumberToGenerate = 5)
    {
        thrust::host_vector<secp256k1::uint256> privateKeys;

        const std::string k{"f71485d0bff28cf3a9f1b6c2b65b03729f42f9818fb497c6fae7268bb124f263"};
        constexpr uint32_t testKey[8]{0x55c1df29, 0x32e27f37, 0x4b90fe20, 0x6d3b44ce, 0x1f95782b, 0x0345c17c, 0xff10a32d, 0x3f795bef};
        privateKeys.push_back({testKey, secp256k1::uint256::BigEndian});
        privateKeys.push_back(std::string("0100000000000000000000000000000000000000000000000000000000000000"));
        privateKeys.push_back(std::string("0100000000000000000000000000000000000000000000000000000000000200"));
        privateKeys.push_back(std::string("d7ae6ac85e67dfe75b3a42c6453abed4bb34a26d2988481fc134b2d845976a56"));
        privateKeys.push_back(k);

        for (uint32_t i = 0; i < keysNumberToGenerate; i++)
        {
            privateKeys.push_back(secp256k1::generatePrivateKey());
        }

        return privateKeys;
    }
}

struct KeyGenerator::Impl
{
    std::thread mThread;

    thrust::host_vector<secp256k1::uint256> mCurrentPrivateKeys;
    std::unique_ptr<ECC> mCuECC;

    std::shared_ptr<DataQueue> mDataQueue;
    std::atomic<bool> mStopFlag{false};
    mutable std::atomic<bool> mDone{false};

    std::function<void(StatusInfo)> mStatusCallback;

    // Implementation
    explicit Impl(const Context& context)
    : mCuECC(std::make_unique<ECC>())
    , mDataQueue(context.dataQueue)
    , mStatusCallback(context.statusCallback)
    {}

    ~Impl()
    {
        stop();
    }

    void start(const thrust::host_vector<secp256k1::uint256>& privateKeys)
    {
        mCurrentPrivateKeys = privateKeys;
        mCuECC->init(privateKeys);

        mThread = std::thread(&Impl::run, this);
    }

    void startRandom(const uint32_t keysNumberToGenerate)
    {
        mCurrentPrivateKeys = generateRandomPrivateKeys(keysNumberToGenerate);
        mCuECC->init(mCurrentPrivateKeys);

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
        fmt::print("KeyGenerator::selfTest started\n");
        const thrust::host_vector<secp256k1::uint256> privateKeys = generateRandomPrivateKeys(keysNumberToGenerate);

        mCuECC->init(privateKeys);

        cu::cudaSafeCall(mCuECC->generatePublicKeys());

        if (mCuECC->selfTest(privateKeys))
        {
            fmt::print("KeyGenerator::selfTest done\n");
        }
        else
        {
            fmt::print("KeyGenerator::selfTest fails\n");
        }

        thrust::host_vector<secp256k1::ecpoint> publicKeys;
        cu::cudaSafeCall(mCuECC->getResults(publicKeys));

        // bool compressed{false};
        // for (uint32_t i = 0; i < publicKeys.size(); i++)
        // {
        //     std::cout << privateKeys[i].toString(compressed) << " ";
        //     std::cout << publicKeys[i].toString(compressed) << " " << std::endl;
        //     // std::string address = Address::fromPublicKey(publicKeys[i], compressed);
        //     // std::cout << address << endl;
        // }
    }

    void run() const
    {
        std::cout << "KeyGenerator Thread ID: " << std::this_thread::get_id() << std::endl;

        utils::Timer timer;

        uint64_t generatedPointsCounter{0};
        while (!mStopFlag && !mDone)
        {
            timer.start();
            cu::cudaSafeCall(mCuECC->generatePublicKeys());
            generatedPointsCounter += mCurrentPrivateKeys.size();

            const uint64_t t = timer.getTime();
            const auto seconds = static_cast<double>(t) / 1000.0;
            // if (seconds >= 1000.0)
            {
                StatusInfo info;
                info.total = generatedPointsCounter;
                info.speed = static_cast<double>(generatedPointsCounter) / seconds;
                generatedPointsCounter = 0;
                mStatusCallback(info);

                fmt::print("KeyGenerator: generated done, speed: {}, seconds: {}\n", info.speed, seconds);
            }

            fmt::print("KeyGenerator: generated done\n");

            thrust::host_vector<secp256k1::ecpoint> publicKeys;
            cu::cudaSafeCall(mCuECC->getResults(publicKeys));

            fmt::print("KeyGenerator: generated {} keys\n", publicKeys.size());

            // to be deleted in KeyProcessor
            auto* pairs = new Secp256k1KeyPairs;
            for (uint32_t i = 0; i < publicKeys.size(); i++)
            {
                pairs->push_back({mCurrentPrivateKeys[i], publicKeys[i]});
            }

            while (!mDataQueue->push(pairs))
            {
                if (mStopFlag)
                    return;

                // If the queue is full, yield to avoid busy-wait
                std::this_thread::yield();
            }

            mDone = true;
            fmt::print("KeyGenerator: done\n");
        }
    }
};

KeyGenerator::KeyGenerator(const Context& context) : mImpl(std::make_unique<Impl>(context))
{}

KeyGenerator::~KeyGenerator() = default;

KeyGenerator::KeyGenerator(KeyGenerator &&rhs) noexcept = default;

KeyGenerator& KeyGenerator::operator=(KeyGenerator &&rhs) noexcept = default;

void KeyGenerator::start(const thrust::host_vector<secp256k1::uint256>& privateKeys) const
{
    mImpl->start(privateKeys);
}

void KeyGenerator::startRandom(const uint32_t keysNumberToGenerate) const
{
    mImpl->startRandom(keysNumberToGenerate);
}

void KeyGenerator::stop() const
{
    mImpl->stop();
}

bool KeyGenerator::isDone() const
{
    return mImpl->isDone();
}

void KeyGenerator::selfTest(const uint32_t keysNumberToGenerate) const
{
    mImpl->selfTest(keysNumberToGenerate);
}
