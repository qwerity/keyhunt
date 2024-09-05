#include "key_hunter.h"

#include <format>
#include <fstream>
#include <utility>
#include <functional>
#include <set>

#include <boost/log/trivial.hpp>

#include "cuda/defines.cuh"
#include "cuda/ecc.cuh"
#include "cuda/hash160_lookup.cuh"
#include "util/cuda_util.h"
#include "util/utils.h"


struct KeyHunter::Impl
{
    const AppConfig mAppConfig;

    std::thread mThread;

    thrust::host_vector<secp256k1::uint256> mCurrentPrivateKeys;
    std::unique_ptr<ECC> mCuECC;

    mutable utils::Timer mTimer;

    std::shared_ptr<DataQueue> mDataQueue;

    std::atomic<bool> mStopFlag{false};
    mutable std::atomic<bool> mDone{false};


    Hash160Lookup mhash160Lookup;
    std::vector<hash160> mHash160Targets;

    // callbacks
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

    void start(const thrust::host_vector<secp256k1::uint256>& privateKeys)
    {
        if (!mAppConfig.appParams.ripemd160TargetsFilePath.empty())
        {
            setHash160Targets(mAppConfig.appParams.ripemd160TargetsFilePath);
        }

        mCurrentPrivateKeys = privateKeys;
        mCuECC->init(mAppConfig.appParams.pointsPerThread, mCurrentPrivateKeys);

        mThread = std::thread(&Impl::run, this);
    }

    void startWithRandomPrivateKeys()
    {
        start(utils::generateRandomPrivateKeys(mAppConfig.appParams.keysNumberToGenerate));
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

    void setHash160Targets(const std::string &hash160TargetsFile)
    {
        std::ifstream inFile(hash160TargetsFile);
        if (!inFile.is_open())
        {
            BOOST_LOG_TRIVIAL(error) << "Unable to open " << hash160TargetsFile;
            throw std::runtime_error(std::string("Unable to open ") + hash160TargetsFile);
        }
        mHash160Targets.clear();

        BOOST_LOG_TRIVIAL(info) << "Loading RipeMD-160 hashes from: " << hash160TargetsFile;

        std::set<hash160> hash160Targets;
        std::string line;
        while (std::getline(inFile, line))
        {
            utils::removeNewline(line);
            line = utils::trim(line);
            if (!line.empty())
            {
                hash160Targets.insert(utils::toHash160(line));
            }
        }

        // mHash160Targets.reserve(hash160Targets.size());
        mHash160Targets.assign(std::make_move_iterator(hash160Targets.begin()), std::make_move_iterator(hash160Targets.end()));

        BOOST_LOG_TRIVIAL(info) << utils::formatThousands(mHash160Targets.size()) << " hashes loaded " << static_cast<double>(sizeof(hash160) * mHash160Targets.size()) / (1024.0 * 1024.0) << "MB";
        mhash160Lookup.setTargets(mHash160Targets);
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

void KeyHunter::start(const thrust::host_vector<secp256k1::uint256>& privateKeys) const
{
    mImpl->start(privateKeys);
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
