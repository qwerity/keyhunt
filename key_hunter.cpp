#include "key_hunter.h"

#include <fstream>
#include <utility>
#include <functional>
#include <unordered_set>

#include <boost/log/trivial.hpp>
#include <boost/algorithm/string.hpp>

#include "cuda/atomic_list.cuh"
#include "cuda/defines.cuh"
#include "cuda/ecc.cuh"
#include "cuda/hash160_lookup.cuh"

#include "util/cuda_util.h"
#include "util/utils.h"


struct KeyHunter::Impl
{
    GlobalContext mgContext;

    std::thread mThread;

    std::unique_ptr<ECC> mCuECC;

    mutable utils::Timer mTimer;

    std::atomic<bool> mStopFlag{false};
    mutable std::atomic<bool> mDone{false};

    Hash160Lookup mHash160Lookup;
    std::unordered_set<hash160> mHash160Targets;

    CudaAtomicList mResultAtomicList;

    mutable uint32_t mIteration{0};

    // Implementation
    explicit Impl(const GlobalContext& context)
    : mgContext(context)
    , mCuECC(std::make_unique<ECC>())
    {
        cu::cudaInit(context.config.cudaDeviceId);
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

    void signalStatusInfo(const uint64_t totalGeneratedPointsCounter, const uint64_t generatedPointsCounter, const uint32_t iteration, const uint32_t remainsIterations) const
    {
        static uint64_t elapsedTimeMs{0};
        elapsedTimeMs += mTimer.getTime();

        static uint64_t totalTime{0};
        totalTime += elapsedTimeMs;

        if (elapsedTimeMs >= mgContext.config.statusCallbackPeriodMs)
        {
            const auto seconds = static_cast<double>(elapsedTimeMs) / 1000.0;

            StatusInfo info;
            info.pointsPerSecond = (static_cast<double>(generatedPointsCounter) / seconds) / 1e6; // Mpoints per second
            info.seconds = seconds;
            info.total = totalGeneratedPointsCounter;
            info.totalTime = totalTime;
            info.device = mgContext.cudaInfo.id;
            info.deviceName = mgContext.cudaInfo.name;
            info.iteration = iteration;
            info.remainsIterations = remainsIterations;
            cu::safeCall(cudaMemGetInfo(&info.freeDeviceMemory, &info.totalDeviceMemory));

            mgContext.statusCallback(info);

            elapsedTimeMs = 0;
            mTimer.start();
        }
    }

    /// TODO: to be optimized
    void pushResultsToQueue() const
    {
        thrust::host_vector<std::pair<uint256_t, secp256k1::ecpoint>> results;
        cu::safeCall(mCuECC->getResults(results));

        BOOST_LOG_TRIVIAL(info) << utils::format("KeyGenerator: generated %s keys\n", results.size());

        // to be deleted in KeyProcessor
        auto* pairs = new Secp256k1KeyPairs;
        for (const auto &[privateKey, publicKey] : results)
        {
            const auto p = secp256k1::uint256(privateKey.v, secp256k1::uint256::BigEndian);
            pairs->emplace_back(p, publicKey);
        }

        while (!mgContext.dataQueue->push(pairs))
        {
            if (mStopFlag)
                return;

            // If the queue is full, yield to avoid busy-wait
            std::this_thread::yield();
        }
    }

    void start(const thrust::host_vector<secp256k1::uint256>& privateKeys)
    {
        setHash160Targets(mgContext.config.ripemd160TargetsFilePaths);

        mCuECC->init(mgContext.config.pointsPerThread, privateKeys);

        mThread = std::thread([&privateKeys, this]()
        {
            std::cout << "KeyGenerator Thread ID: " << std::this_thread::get_id() << std::endl;

            mTimer.start();
            cu::safeCall(mCuECC->calculatePublicKeys());

            const uint64_t generatedPointsCounter = privateKeys.size();
            signalStatusInfo(generatedPointsCounter, generatedPointsCounter, 0, 0);

            BOOST_LOG_TRIVIAL(info) << "KeyGenerator: done, generated " << utils::formatThousands(generatedPointsCounter) << "keys";

            mDone = true;
            pushResultsToQueue();
        });
    }

    void startWithRandomPrivateKeys()
    {
        start(utils::generateRandomPrivateKeys(mgContext.config.keysNumberToGenerate));
    }

    bool isTargetInList(const uint32_t hash[5]) const
    {
        return mHash160Targets.contains(hash160(hash));
    }

    void pushResultsToQueue2(const uint32_t iteration) const
    {
        const auto count = mResultAtomicList.size();

        Hash160SearchResult results[count];
        mResultAtomicList.read(&results, count);
        mResultAtomicList.clear();

        for (uint32_t i = 0; i < count; i++)
        {
            // might be false-positive
            if (!mHash160Targets.contains(hash160(results[i].digest)))
            {
                continue;
            }

            BOOST_LOG_TRIVIAL(info) << "hash: " << utils::convertToHexString(results[i].digest, 5)
                                    << ", private key: " << utils::convertToHexString(results[i].privateKey, 8)
                                    << ", iteration: " << iteration << ", index: " << results[i].idx << ", compressed: " << results[i].compressed;
        }
    }


    void findPublicHashWithPrivateDefinedXRandomY()
    {
        setHash160Targets(mgContext.config.ripemd160TargetsFilePaths);
        mResultAtomicList.init(sizeof(Hash160SearchResult), 16);

        mCuECC->initWithPrivateDefinedXRandomY(mgContext.config.pointsPerThread, mgContext.config.publicKeyCompressionTypeToCheck);

        mThread = std::thread([&]()
        {
            uint64_t totalGeneratedPublicKeys{0};
            const uint32_t totalKeysToGenerate = (mgContext.config.keysNumberToGenerate == 0) ? std::numeric_limits<uint32_t>::max() : mgContext.config.keysNumberToGenerate;

            const uint32_t keysNumberPerIteration = mCuECC->getKeysNumberPerIteration();
            const uint32_t iterationsCount = totalKeysToGenerate / keysNumberPerIteration;
            const uint32_t remainder = totalKeysToGenerate - (iterationsCount * keysNumberPerIteration);

            BOOST_LOG_TRIVIAL(info) << "KeyGenerator: totalKeysToGenerate: " << totalKeysToGenerate << ", keysNumberPerIteration: " << keysNumberPerIteration;

            const uint32_t finalIterationsCount = iterationsCount + (remainder > 0 ? 1 : 0);
            BOOST_LOG_TRIVIAL(info) << "KeyGenerator: total iterations: " << finalIterationsCount << ", remaining data: " << remainder;

            while (!mStopFlag && mIteration < finalIterationsCount)
            {
                const uint32_t remainsIterations{finalIterationsCount - mIteration - 1};

                mTimer.start();
                {
                    mCuECC->generatePrivateKeysForXPerIteration(mgContext.config.privateXPart, mIteration);

                    cu::safeCall(mCuECC->calculatePublicKeys());
                }

                totalGeneratedPublicKeys += keysNumberPerIteration;
                signalStatusInfo(totalGeneratedPublicKeys, keysNumberPerIteration, mIteration, remainsIterations);

                // pushResultsToQueue();
                pushResultsToQueue2(mIteration);

                ++mIteration;
            }

            BOOST_LOG_TRIVIAL(info) << "KeyGenerator: done, generated " << utils::formatThousands(totalGeneratedPublicKeys) << " keys";
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

    void setHash160Targets(const std::vector<std::string>& ripemd160TargetsFilePaths)
    {
        if (ripemd160TargetsFilePaths.empty())
            return;

        utils::Timer timer;
        for (const auto& hash160TargetsFile : mgContext.config.ripemd160TargetsFilePaths)
        {
            if (hash160TargetsFile.empty())
                continue;

            timer.start();
            std::ifstream inFile(hash160TargetsFile);
            if (!inFile.is_open())
            {
                BOOST_LOG_TRIVIAL(warning) << "Unable to open " << hash160TargetsFile;
                continue;
            }

            BOOST_LOG_TRIVIAL(info) << "Loading RipeMD-160 hashes from: " << hash160TargetsFile;

            uint32_t insertedTargetsCount{0};
            std::string line;
            while (std::getline(inFile, line))
            {
                if (line.empty())
                    continue;

                boost::algorithm::trim(line);
                if (!line.empty())
                {
                    mHash160Targets.insert(utils::toHash160(line));
                    ++insertedTargetsCount;
                }
            }

            const auto fileReadTimeS = static_cast<float>(timer.getTime()) / 1000;
            BOOST_LOG_TRIVIAL(info) << "Loaded " << utils::formatThousands(insertedTargetsCount)
                                    << " hashes, (" << utils::format("%.02fs | %.02f", fileReadTimeS, static_cast<double>(sizeof(hash160) * insertedTargetsCount) / MB) << " Mb)";
        }

        // mHash160Targets.assign(std::make_move_iterator(hash160Targets.begin()), std::make_move_iterator(hash160Targets.end()));
        mHash160Lookup.setTargets(mHash160Targets);
    }
};

KeyHunter::KeyHunter(const GlobalContext& context) : mImpl(std::make_unique<Impl>(context)) {}

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

void KeyHunter::findPublicHashWithPrivateDefinedXRandomY() const
{
    mImpl->findPublicHashWithPrivateDefinedXRandomY();
}

void KeyHunter::stop() const
{
    mImpl->stop();
}

bool KeyHunter::isDone() const
{
    return mImpl->mDone;
}

void KeyHunter::selfTest(const uint32_t keysNumberToGenerate) const
{
    mImpl->selfTest(keysNumberToGenerate);
}
