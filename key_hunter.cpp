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
#include "util/crypto_util.h"
#include "util/cuda_util.h"
#include "util/utils.h"


struct KeyHunter::Impl
{
    const AppConfig mAppConfig;

    std::thread mThread;

    std::unique_ptr<ECC> mCuECC;

    mutable utils::Timer mTimer;

    std::shared_ptr<DataQueue> mDataQueue;

    std::atomic<bool> mStopFlag{false};
    mutable std::atomic<bool> mDone{false};

    Hash160Lookup mhash160Lookup;
    std::vector<hash160> mHash160Targets;

    // callbacks
    std::function<void(StatusInfo)> mStatusCallback;

    mutable uint32_t mIteration{0};

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

    void stop()
    {
        std::cout << "KeyGenerator stopping" << std::endl;
        mStopFlag = true;
        // mDone = true;

        if (mThread.joinable())
        {
            mThread.join();
        }
    }

    bool isDone() const { return mDone; }

    void start(const thrust::host_vector<secp256k1::uint256>& privateKeys)
    {
        if (!mAppConfig.appParams.ripemd160TargetsFilePath.empty())
        {
            setHash160Targets(mAppConfig.appParams.ripemd160TargetsFilePath);
        }

        mCuECC->init(mAppConfig.appParams.pointsPerThread, privateKeys);

        mThread = std::thread([&privateKeys, this]()
        {
            std::cout << "KeyGenerator Thread ID: " << std::this_thread::get_id() << std::endl;

            uint64_t generatedPointsCounter{0};
            mTimer.start();
            cu::safeCall(mCuECC->calculatePublicKeys());
            generatedPointsCounter += privateKeys.size();

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

            thrust::host_vector<std::pair<uint256_t, secp256k1::ecpoint>> results;
            cu::safeCall(mCuECC->getResults(results));

            BOOST_LOG_TRIVIAL(info) << std::format("KeyGenerator: generated {} keys\n", results.size());

            // to be deleted in KeyProcessor
            auto* pairs = new Secp256k1KeyPairs;
            for (const auto &[privateKey, publicKey] : results)
            {
                const auto p = secp256k1::uint256(privateKey.v, secp256k1::uint256::BigEndian);
                pairs->emplace_back(p, publicKey);
            }

            while (!mDataQueue->push(pairs))
            {
                if (mStopFlag)
                    return;

                // If the queue is full, yield to avoid busy-wait
                std::this_thread::yield();
            }
            mDone = true;
        });
    }

    void startWithRandomPrivateKeys()
    {
        start(utils::generateRandomPrivateKeys(mAppConfig.appParams.keysNumberToGenerate));
    }

    void findPublicHashWithPrivateDefinedXRandomY(const uint32_t privateXPart)
    {
        if (!mAppConfig.appParams.ripemd160TargetsFilePath.empty())
        {
            setHash160Targets(mAppConfig.appParams.ripemd160TargetsFilePath);
        }

        mCuECC->initWithPrivateDefinedXRandomY(mAppConfig.appParams.pointsPerThread);

        uint64_t totalGeneratedPublicKeys{0};
        mThread = std::thread([privateXPart, &totalGeneratedPublicKeys, this]()
        {
            const uint32_t totalKeysToGenerate = (mAppConfig.appParams.keysNumberToGenerate == 0) ? std::numeric_limits<uint32_t>::max() : mAppConfig.appParams.keysNumberToGenerate;

            const uint32_t keysNumberPerIteration = mCuECC->getKeysNumberPerIteration();
            const uint32_t iterationsCount = totalKeysToGenerate / keysNumberPerIteration;
            const uint32_t remainder = totalKeysToGenerate - (iterationsCount * keysNumberPerIteration);

            BOOST_LOG_TRIVIAL(info) << "KeyGenerator: totalKeysToGenerate: " << totalKeysToGenerate << ", keysNumberPerIteration: " << keysNumberPerIteration;

            const uint32_t finalIterationsCount = iterationsCount + (remainder > 0 ? 1 : 0);
            BOOST_LOG_TRIVIAL(info) << "KeyGenerator: total iterations: " << finalIterationsCount << ", remaining data: " << remainder;

            while (!mStopFlag && mIteration < finalIterationsCount)
            {
                BOOST_LOG_TRIVIAL(info) << "KeyGenerator: iteration: " << mIteration << ", remains " << (finalIterationsCount - mIteration - 1) << " iterations";

                mTimer.start();

                mCuECC->generatePrivateKeysForXPerIteration(privateXPart, mIteration);

                cu::safeCall(mCuECC->calculatePublicKeys());

                totalGeneratedPublicKeys += keysNumberPerIteration;
                if (const auto seconds = static_cast<double>(mTimer.getTime()) / 1000.0; seconds >= 1.0)
                {
                    StatusInfo info;
                    info.total = totalGeneratedPublicKeys;
                    info.seconds = seconds;
                    info.speed = static_cast<double>(keysNumberPerIteration) / seconds;
                    mStatusCallback(info);
                }

                thrust::host_vector<std::pair<uint256_t, secp256k1::ecpoint>> results;
                cu::safeCall(mCuECC->getResults(results));

                BOOST_LOG_TRIVIAL(info) << std::format("KeyGenerator: done {} keys\n", results.size());

                // to be deleted in KeyProcessor
                auto* pairs = new Secp256k1KeyPairs;
                for (const auto &[privateKey, publicKey] : results)
                {
                    const auto p = secp256k1::uint256(privateKey.v, secp256k1::uint256::BigEndian);
                    pairs->emplace_back(p, publicKey);
                }

                while (!mDataQueue->push(pairs))
                {
                    if (mStopFlag)
                        return;

                    // If the queue is full, yield to avoid busy-wait
                    std::this_thread::yield();
                }

                ++mIteration;
            }
            BOOST_LOG_TRIVIAL(info) << std::format("KeyGenerator: done, generated {} keys\n", totalGeneratedPublicKeys);
            mIteration = 0;
            mDone = true;
        });
    }

    void selfTest(const uint32_t keysNumberToGenerate) const
    {
        BOOST_LOG_TRIVIAL(info) << "KeyGenerator::selfTest started";

        const thrust::host_vector<secp256k1::uint256> privateKeys = utils::generateRandomPrivateKeys(keysNumberToGenerate);

        mCuECC->init(32, privateKeys);

        cu::safeCall(mCuECC->calculatePublicKeys());

        if (mCuECC->selfTest(privateKeys))
        {
            BOOST_LOG_TRIVIAL(info) << "KeyGenerator::selfTest done";
        }
        else
        {
            BOOST_LOG_TRIVIAL(info) << "KeyGenerator::selfTest fails";
        }

        thrust::host_vector<std::pair<uint256_t, secp256k1::ecpoint>> results;
        cu::safeCall(mCuECC->getResults(results));
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

void KeyHunter::findPublicHashWithPrivateDefinedXRandomY(const uint32_t privateXPart) const
{
    mImpl->findPublicHashWithPrivateDefinedXRandomY(privateXPart);
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
