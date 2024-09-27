#include "key_hunter.h"

#include <thread>
#include <utility>
#include <format>
#include <unordered_set>

#include <boost/log/trivial.hpp>
#include <boost/iostreams/device/mapped_file.hpp>

#include "cuda/atomic_list.cuh"
//#include "cuda/defines.cuh"
#include "cuda/ecc.cuh"
#include "cuda/hash160_lookup.cuh"

#include "util/cuda_util.h"
#include "util/utils.h"
#include "util/http_client.h"


struct KeyHunter::Impl
{
    std::shared_ptr<GlobalContext> mgContext;
    cu::CudaDeviceInfo cudaInfo;

    std::thread mThread;
    std::unique_ptr<HttpClient> httpClient;

    std::unique_ptr<ECC> mCuECC;

    mutable utils::Timer mTimer;

    std::atomic<bool> mStopFlag{false};
    mutable std::atomic<bool> mDone{false};

    Hash160Lookup mHash160Lookup;

    CudaAtomicList mResultAtomicList;

    // Implementation
    explicit Impl(const std::shared_ptr<GlobalContext>& context)
        : mgContext(context)
        , httpClient{std::make_unique<HttpClient>(context->config.server())}
        , mCuECC(std::make_unique<ECC>())
    {
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

        BOOST_LOG_TRIVIAL(trace) << "KeyHunter stopped" << std::endl;
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
            info.device = cudaInfo.id;
            info.deviceName = cudaInfo.name;
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
            results[i].cudaDeviceId = cudaInfo.id;

            // recheck the false-positive
            if (!mgContext->hash160Targets.contains(hash160(results[i].digest)))
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

    void startSearchPublicHashWithPrivateDefinedXRandomYThread(const uint32_t privateXPart)
    {
        const uint32_t keysNumberToGenerate = mgContext->config.hunter().keysNumberToGenerate;
        const uint32_t totalKeysToGenerate = (keysNumberToGenerate == 0) ? std::numeric_limits<uint32_t>::max() : keysNumberToGenerate;

        const uint32_t keysNumberPerIteration = mCuECC->getKeysNumberPerIteration();
        const uint32_t iterationsCount = totalKeysToGenerate / keysNumberPerIteration;
        const uint32_t remainder = totalKeysToGenerate - (iterationsCount * keysNumberPerIteration);

        BOOST_LOG_TRIVIAL(info) << std::format(std::locale("en_US.UTF-8"), "KeyHunter: totalKeysToGenerate: {:L}, keysNumberPerIteration: {:L}", totalKeysToGenerate, keysNumberPerIteration);

        const uint32_t finalIterationsCount = iterationsCount + (remainder > 0 ? 1 : 0);
        BOOST_LOG_TRIVIAL(info) << std::format(std::locale("en_US.UTF-8"), "KeyHunter: total iterations: {:L}, remaining data: {:L}", finalIterationsCount, remainder);

        uint32_t iteration{0};
        while (!mStopFlag && iteration < finalIterationsCount)
        {
            mTimer.start();
            {
                cu::safeCall(mCuECC->generatePrivateKeysForXPerIteration(privateXPart, iteration));

                cu::safeCall(mCuECC->calculatePublicKeys());
            }
            //const uint64_t nextY = iteration * mCuECC->getKeysNumberPerIteration() + 1;
            mgContext->config.setCalculationIteration(iteration);

            pushResultsToQueue2(iteration);

            ++iteration;

            signalStatusInfo(keysNumberPerIteration, iteration, finalIterationsCount, mTimer.elapsedMs());
        }

        assert(iteration == finalIterationsCount);

        BOOST_LOG_TRIVIAL(info) << std::format(std::locale("en_US.UTF-8"), "KeyHunter: done, generated: {:L} keys", keysNumberPerIteration * finalIterationsCount);
    }

    void startSearchPublicHashThread(const int cudaDeviceId)
    {
        mDone = false;
        mThread = std::thread([&, cudaDeviceId]()
        {   BOOST_LOG_TRIVIAL(trace) << "KeyHunter Thread ID: " << std::this_thread::get_id();

            // For using concrete CUDA device
            cudaInfo = cu::cudaInit(cudaDeviceId);

            // Preparing Public, Private, Results buffers
            mHash160Lookup.setTargets(mgContext->hash160Targets);
            mResultAtomicList.init(sizeof(Hash160SearchResult), 16);

            initializeGPoints();
            mCuECC->initWithPrivateDefinedXRandomY(mgContext->config.hunter().pointsPerThread, mgContext->config.hunter().publicKeyCompressionTypeToCheck);

            // Getting from http service the next private key x part, generating public and checking targets hashes
            uint32_t privateXPart{0};

            http::status responseCode{http::status::unknown};
            do
            {
                if (!mgContext->config.hunter().forcePrivateXPart)
                {
                    responseCode = httpClient->getNumber(privateXPart);
                    if (responseCode != http::status::ok)
                    {
                        BOOST_LOG_TRIVIAL(error) << responseCode;
                        break;
                    }
                }
                else
                {
                    privateXPart = mgContext->config.hunter().privateXPart;
                }

                BOOST_LOG_TRIVIAL(trace) << std::format("\n[{}] Generating for privateXPart: {}", cudaInfo.id, privateXPart);
                startSearchPublicHashWithPrivateDefinedXRandomYThread(privateXPart);
            }
            while (!mStopFlag && responseCode == http::status::ok);

            mDone = true;
        });
    }
};

KeyHunter::KeyHunter(const std::shared_ptr<GlobalContext>& context) : mImpl(std::make_unique<Impl>(context)) {}
KeyHunter::~KeyHunter() = default;

KeyHunter::KeyHunter(KeyHunter &&rhs) noexcept = default;

KeyHunter& KeyHunter::operator=(KeyHunter &&rhs) noexcept = default;

void KeyHunter::startSearchPublicHashThread(const int cudaDeviceId) const
{
    mImpl->startSearchPublicHashThread(cudaDeviceId);
}

void KeyHunter::stop() const
{
    mImpl->stop();
}

bool KeyHunter::isDone() const
{
    return mImpl->mDone;
}
