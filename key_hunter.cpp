#include "key_hunter.h"

#include <thread>
#include <utility>
#include <format>
#include <unordered_set>

#include <boost/log/trivial.hpp>
#include <boost/iostreams/device/mapped_file.hpp>

#include "cuda/atomic_list.cuh"
#include "cuda/defines.cuh"
#include "cuda/ecc.cuh"
#include "cuda/hash160_lookup.cuh"

#include "util/cuda_util.h"
#include "util/utils.h"
#include "util/http_client.h"


struct KeyHunter::Impl
{
    std::shared_ptr<GlobalContext> mgContext;

    std::thread mThread;

    std::unique_ptr<ECC> mCuECC;

    mutable utils::Timer mTimer;

    std::shared_ptr<HttpClient> mHttpClient;

    std::atomic<bool> mStopFlag{false};
    mutable std::atomic<bool> mDone{false};

    Hash160Lookup mHash160Lookup;
    std::unordered_set<hash160> mHash160Targets;

    CudaAtomicList mResultAtomicList;

    mutable uint32_t mIteration{0};

    // Implementation
    explicit Impl(const std::shared_ptr<GlobalContext>& context)
        : mgContext(context)
        , mCuECC(std::make_unique<ECC>())
        , mHttpClient(std::make_shared<HttpClient>(context->config.server()))
    {
        cu::cudaInit(mgContext->config.hunter().cudaDeviceId);
    }

    ~Impl()
    {
        stop();
    }

    void stop()
    {
        BOOST_LOG_TRIVIAL(trace) << "KeyHunter stopping" << std::endl;

        mStopFlag = true;
        // mDone = true;

        if (mThread.joinable())
        {
            mThread.join();
        }

        BOOST_LOG_TRIVIAL(trace) << "KeyHunter stopping" << std::endl;
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

    void signalStatusInfo(const uint64_t keysNumberPerIteration, const uint32_t iteration, const uint32_t totalIterations, const uint64_t elapsedTimeMs) const
    {
        static uint64_t periodElapsedTimeMS{0};
        static uint64_t periodKeysNumber{0};
        static uint64_t totalTime{0};

        totalTime += elapsedTimeMs;
        periodElapsedTimeMS += elapsedTimeMs;
        periodKeysNumber += keysNumberPerIteration;

        if (periodElapsedTimeMS >= mgContext->config.hunter().statusCallbackPeriodMs)
        {
            const double periodElapsedTimeS = static_cast<double>(periodElapsedTimeMS) / 1000.0;

            StatusInfo info;
            info.pointsPerSecond = (static_cast<double>(periodKeysNumber) / periodElapsedTimeS) / 1e6; // Mpoints per second
            info.seconds = periodElapsedTimeS;
            info.total = keysNumberPerIteration * iteration;
            info.totalTime = totalTime;
            info.device = mgContext->cudaInfo.id;
            info.deviceName = mgContext->cudaInfo.name;
            info.iteration = iteration;
            info.totalIterations = totalIterations;
            cu::safeCall(cudaMemGetInfo(&info.freeDeviceMemory, &info.totalDeviceMemory));

            mgContext->statusCallback(info);

            periodElapsedTimeMS = 0;
            periodKeysNumber = 0;
        }
    }

    void pushResultsToQueue2(const uint32_t iteration) const
    {
        const uint32_t count = mResultAtomicList.size();

        std::vector<Hash160SearchResult> results;
        results.resize(count);

        mResultAtomicList.read(results.data(), count);
        mResultAtomicList.clear();

        for (uint32_t i = 0; i < count; ++i)
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

            results[i].iteration = iteration;
            while (!mgContext->hash160SearchResultsQueue->push(results[i]))
            {
                if (mStopFlag)
                    return;

                // If the queue is full, yield to avoid busy-wait
                std::this_thread::yield();
            }
        }
    }

    void findPublicHashWithPrivateDefinedXRandomY()
    {
        setHash160Targets(mgContext->config.hunter().ripemd160TargetsFilePaths);
        mResultAtomicList.init(sizeof(Hash160SearchResult), 16);

        initializeGPoints();
        mCuECC->initWithPrivateDefinedXRandomY(mgContext->config.hunter().pointsPerThread, mgContext->config.hunter().publicKeyCompressionTypeToCheck);

        mThread = std::thread([&]()
        {
            BOOST_LOG_TRIVIAL(trace) << "KeyHunter Thread ID: " << std::this_thread::get_id();

            const uint32_t totalKeysToGenerate = (mgContext->config.hunter().keysNumberToGenerate == 0) ? std::numeric_limits<uint32_t>::max() : mgContext->config.hunter().keysNumberToGenerate;

            const uint32_t keysNumberPerIteration = mCuECC->getKeysNumberPerIteration();
            const uint32_t iterationsCount = totalKeysToGenerate / keysNumberPerIteration;
            const uint32_t remainder = totalKeysToGenerate - (iterationsCount * keysNumberPerIteration);

            BOOST_LOG_TRIVIAL(info) << std::format(std::locale("en_US.UTF-8"), "KeyHunter: totalKeysToGenerate: {:L}, keysNumberPerIteration: {:L}", totalKeysToGenerate, keysNumberPerIteration);

            const uint32_t finalIterationsCount = iterationsCount + (remainder > 0 ? 1 : 0);
            BOOST_LOG_TRIVIAL(info) << std::format(std::locale("en_US.UTF-8"), "KeyHunter: total iterations: {:L}, remaining data: {:L}", finalIterationsCount, remainder);

            mIteration = 0;
            while (!mStopFlag && mIteration < finalIterationsCount)
            {
                mTimer.start();
                {
                    cu::safeCall(mCuECC->generatePrivateKeysForXPerIteration(mgContext->config.hunter().privateXPart, mIteration));

                    cu::safeCall(mCuECC->calculatePublicKeys());
                }
                //const uint64_t nextY = mIteration * mCuECC->getKeysNumberPerIteration() + 1;
                mgContext->config.calculationIteration(mIteration);

                pushResultsToQueue2(mIteration);

                ++mIteration;

                signalStatusInfo(keysNumberPerIteration, mIteration, finalIterationsCount, mTimer.getTime());
            }

            assert(mIteration == finalIterationsCount);

            BOOST_LOG_TRIVIAL(info) << std::format(std::locale("en_US.UTF-8"), "KeyHunter: done, generated: {:L} keys", keysNumberPerIteration * finalIterationsCount);
            mIteration = 0;
            mDone = true;
        });
    }

    void setHash160Targets(const std::vector<std::string>& ripemd160TargetsFilePaths)
    {
        if (ripemd160TargetsFilePaths.empty())
            return;

        for (const auto& hash160TargetsFile : mgContext->config.hunter().ripemd160TargetsFilePaths)
        {
            if (hash160TargetsFile.substr(hash160TargetsFile.size() - 3) == "bin")
            {
                utils::readSetFromHash160BinaryFile(hash160TargetsFile, mHash160Targets);
            }
            else
            {
                utils::readHash160HexStrFileToSet(hash160TargetsFile, mHash160Targets);
            }
        }

        mHash160Lookup.setTargets(mHash160Targets);
    }
};

KeyHunter::KeyHunter(const std::shared_ptr<GlobalContext>& context) : mImpl(std::make_unique<Impl>(context)) {}
KeyHunter::~KeyHunter() = default;

KeyHunter::KeyHunter(KeyHunter &&rhs) noexcept = default;

KeyHunter& KeyHunter::operator=(KeyHunter &&rhs) noexcept = default;

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
