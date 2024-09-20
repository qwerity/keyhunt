#include "key_hunter.h"

#include <thread>
#include <utility>
#include <functional>
#include <unordered_set>

#include <boost/log/trivial.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/iostreams/device/mapped_file.hpp>

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

    void initializeGPoints() const
    {
        constexpr uint32_t gPointsNumber{256};

        std::vector<ecpoint_t> h_gPointsTmp;
        h_gPointsTmp.resize(gPointsNumber);

        secp256k1::ecpoint p{secp256k1::G()};
        for (uint32_t i = 0; i < gPointsNumber; ++i)
        {
            if (!pointExists(p))
            {
                throw std::runtime_error("Point does not exist!");
            }

            // set as BigEndian to device memory
            h_gPointsTmp[i] = {p.x.v, p.y.v, Endianness::BigEndian};

            // ... 2G, 4G, 8G...(2^255)G
            p = secp256k1::doublePoint(p);
        }

        mCuECC->setGPoints(h_gPointsTmp);
    }

    void signalStatusInfo(const uint64_t keysNumberPerIteration, const uint32_t iteration, const uint32_t remainsIterations, const uint64_t elapsedTimeMs) const
    {
        static uint64_t periodElapsedTimeMS{0};
        static uint64_t periodKeysNumber{0};
        static uint64_t totalTime{0};
        totalTime += elapsedTimeMs;

        if (periodElapsedTimeMS >= mgContext.config.statusCallbackPeriodMs)
        {
            const auto periodElapsedTimeS = static_cast<double>(periodElapsedTimeMS) / 1000.0;

            StatusInfo info;
            info.pointsPerSecond = (static_cast<double>(periodKeysNumber) / periodElapsedTimeS) / 1e6; // Mpoints per second
            info.seconds = periodElapsedTimeS;
            info.total = keysNumberPerIteration * iteration;
            info.totalTime = totalTime;
            info.device = mgContext.cudaInfo.id;
            info.deviceName = mgContext.cudaInfo.name;
            info.iteration = iteration;
            info.remainsIterations = remainsIterations;
            cu::safeCall(cudaMemGetInfo(&info.freeDeviceMemory, &info.totalDeviceMemory));

            mgContext.statusCallback(info);

            periodElapsedTimeMS = 0;
            periodKeysNumber = 0;
        }
        else
        {
            periodElapsedTimeMS += elapsedTimeMs;
            periodKeysNumber += keysNumberPerIteration;
        }
    }

    /// TODO: to be fixed
    void pushResultsToQueue() const
    {
        thrust::host_vector<std::pair<uint256_t, secp256k1::ecpoint>> results;
        // cu::safeCall(mCuECC->getResults(results));

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

    ///todo: to be fixed
    void start(const thrust::host_vector<secp256k1::uint256>& privateKeys)
    {
        setHash160Targets(mgContext.config.ripemd160TargetsFilePaths);

        // mCuECC->init(mgContext.config.pointsPerThread, privateKeys);

        mThread = std::thread([&privateKeys, this]()
        {
            std::cout << "KeyGenerator Thread ID: " << std::this_thread::get_id() << std::endl;

            mTimer.start();
            cu::safeCall(mCuECC->calculatePublicKeys());

            signalStatusInfo(privateKeys.size(), 0, 0, mTimer.getTime());

            BOOST_LOG_TRIVIAL(info) << "KeyGenerator: done, generated " << utils::formatThousands(privateKeys.size()) << "keys";

            mDone = true;
            pushResultsToQueue();
        });
    }

    ///todo: to be fixed
    void startWithRandomPrivateKeys()
    {
        // start(utils::generateRandomPrivateKeys(mgContext.config.keysNumberToGenerate));
    }

    bool isTargetInList(const uint32_t hash[5]) const
    {
        return mHash160Targets.contains(hash160(hash));
    }

    void pushResultsToQueue2(const uint32_t iteration) const
    {
        const uint32_t count = mResultAtomicList.size();

        std::vector<Hash160SearchResult> results;
        results.resize(count);

        mResultAtomicList.read(results.data(), count);
        mResultAtomicList.clear();

        for (uint32_t i = 0; i < count; i++)
        {
            // recheck the false-positive
            if (!mHash160Targets.contains(hash160(results[i].digest)))
            {
                continue;
            }

            for (uint32_t k{0}; k < 5; ++k)
            {
                results[i].digest[k] = utils::endian(results[i].digest[k]);
            }

            BOOST_LOG_TRIVIAL(info) << " private key: " << utils::convertToHexString(results[i].privateKey, 8)
                                    << ", public X key: " << utils::convertToHexString(results[i].publicXKey, 8)
                                    << ", hash: " << utils::convertToHexString(results[i].digest, 5)
                                    << ", iteration: " << iteration << ", index: " << results[i].idx << ", compressed: " << results[i].compressed;
        }
    }

    void findPublicHashWithPrivateDefinedXRandomY()
    {
        setHash160Targets(mgContext.config.ripemd160TargetsFilePaths);
        mResultAtomicList.init(sizeof(Hash160SearchResult), 16);

        initializeGPoints();
        mCuECC->initWithPrivateDefinedXRandomY(mgContext.config.pointsPerThread, mgContext.config.publicKeyCompressionTypeToCheck);

        mThread = std::thread([&]()
        {
            const uint32_t totalKeysToGenerate = (mgContext.config.keysNumberToGenerate == 0) ? std::numeric_limits<uint32_t>::max() : mgContext.config.keysNumberToGenerate;

            const uint32_t keysNumberPerIteration = mCuECC->getKeysNumberPerIteration();
            const uint32_t iterationsCount = totalKeysToGenerate / keysNumberPerIteration;
            const uint32_t remainder = totalKeysToGenerate - (iterationsCount * keysNumberPerIteration);

            BOOST_LOG_TRIVIAL(info) << "KeyGenerator: totalKeysToGenerate: " << utils::formatThousands(totalKeysToGenerate) << ", keysNumberPerIteration: " << utils::formatThousands(keysNumberPerIteration);

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

                signalStatusInfo(keysNumberPerIteration, mIteration, remainsIterations, mTimer.getTime());

                // pushResultsToQueue();
                pushResultsToQueue2(mIteration);

                ++mIteration;
            }

            BOOST_LOG_TRIVIAL(info) << "KeyGenerator: done, generated " << utils::formatThousands(keysNumberPerIteration * (mIteration - 1)) << " keys";
            mIteration = 0;
            mDone = true;
        });
    }

    /// todo: to be fixed
    void selfTest(const uint32_t keysNumberToGenerate) const
    {
        // BOOST_LOG_TRIVIAL(info) << "KeyGenerator::selfTest started";
        //
        // const thrust::host_vector<secp256k1::uint256> privateKeys = utils::generateRandomPrivateKeys(keysNumberToGenerate);
        //
        // mCuECC->init(32, privateKeys);
        //
        // cu::safeCall(mCuECC->calculatePublicKeys());
        //
        // if (mCuECC->selfTest(privateKeys))
        // {
        //     BOOST_LOG_TRIVIAL(info) << "KeyGenerator::selfTest done";
        // }
        // else
        // {
        //     BOOST_LOG_TRIVIAL(info) << "KeyGenerator::selfTest fails";
        // }
        //
        // thrust::host_vector<std::pair<uint256_t, secp256k1::ecpoint>> results;
        // cu::safeCall(mCuECC->getResults(results));
    }

    void setHash160Targets(const std::vector<std::string>& ripemd160TargetsFilePaths)
    {
        if (ripemd160TargetsFilePaths.empty())
            return;

        utils::Timer timer;
        for (const auto& hash160TargetsFile : mgContext.config.ripemd160TargetsFilePaths)
        {
            boost::iostreams::mapped_file_source file;

            if (hash160TargetsFile.empty())
                continue;

            timer.start();

            file.open(hash160TargetsFile);
            if (!file.is_open())
            {
                BOOST_LOG_TRIVIAL(warning) << "Unable to open " << hash160TargetsFile;
                continue;
            }

            BOOST_LOG_TRIVIAL(info) << "Loading RipeMD-160 hashes from: " << hash160TargetsFile;

            const char* data = file.data();
            const size_t size = file.size();
            constexpr size_t chunkSize = 40;  // Each chunk is 20 bytes (without newlines)

            uint64_t insertedTargetsCount{0};
            // Read the file in fixed-size chunks of 20 bytes
            for (size_t i = 0; i < size;)
            {
                if (i + chunkSize <= size)
                {
                    // Convert the 20-byte chunk into an array of uint32_t[5]
                    mHash160Targets.insert(utils::hexToHash160(data + i));
                    ++insertedTargetsCount;

                    // Move to the next chunk
                    i += chunkSize;
                }

                // Skip any newlines or whitespace characters
                while (i < size && (data[i] == '\n' || data[i] == '\r' || data[i] == ' '))
                {
                    ++i;
                }
            }

            // Close the file
            file.close();

            const auto fileReadTimeS = static_cast<float>(timer.getTime()) / 1000;
            BOOST_LOG_TRIVIAL(info) << "Loaded " << utils::formatThousands(insertedTargetsCount)
                                    << " hashes, (" << utils::format("%.02fs | %.02f", fileReadTimeS, static_cast<double>(sizeof(hash160) * insertedTargetsCount) / MB) << " Mb)";
        }

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
