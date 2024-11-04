#include "key_hunter.h"

#include <thread>
#include <format>

#include <boost/log/trivial.hpp>

#include "cuda/atomic_list.cuh"
#include "cuda/ecc.cuh"
#include "cuda/hash160_lookup.cuh"
#include "util/utils.h"
#include "util/secp256k1.h"
#include "util/http_client.h"


struct KeyHunter::Impl
{
    std::shared_ptr<GlobalContext> gContext;
    cu::CudaDeviceInfo cudaInfo;

    std::unique_ptr<ECC> cuECC;

    std::atomic<bool> stopFlag{false};

    Hash160Lookup hash160Lookup;

    CudaAtomicList resultAtomicList;

    // Implementation
    explicit Impl(const std::shared_ptr<GlobalContext>& context, cu::CudaDeviceInfo&& cudaInfo)
        : gContext(context)
        , cudaInfo(std::move(cudaInfo))
        , cuECC(std::make_unique<ECC>())
    {
    }

    ~Impl()
    {
        stop();
    }

    void stop()
    {
        stopFlag = true;

        BOOST_LOG_TRIVIAL(trace) << "KeyHunter stopped";
    }

    void signalStatusInfo(const uint64_t keysNumberPerIteration, const uint32_t iteration, const uint32_t totalIterations, const uint64_t elapsedTimeMs) const
    {
        static uint64_t periodElapsedTimeMS{0};
        static uint64_t periodKeysNumber{0};
        static uint64_t totalTime{0};

        totalTime += elapsedTimeMs;
        periodElapsedTimeMS += elapsedTimeMs;
        periodKeysNumber += keysNumberPerIteration;

        if (periodElapsedTimeMS >= gContext->config.hunter().statusCallbackPeriodMs)
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
            cudaCheckError(cudaMemGetInfo(&info.freeDeviceMemory, &info.totalDeviceMemory));

            gContext->statusCallback(info);

            periodElapsedTimeMS = 0;
            periodKeysNumber = 0;
        }
    }

    void pushResultsToQueue2(const uint32_t privateXPart, const uint32_t keysNumberPerIteration, const uint32_t iteration) const
    {
        utils::Timer t;
        const uint32_t count = resultAtomicList.size();

        std::vector<Hash160SearchResult> results;
        results.resize(count);

        resultAtomicList.read(results.data(), count);
        resultAtomicList.clear();

        uint32_t falsePositiveCount{0};
        for (uint32_t i = 0; i < count; ++i)
        {
            results[i].cudaDeviceId = cudaInfo.id;

            // recheck the false-positive
            if (!gContext->hash160Targets.contains(hash160(results[i].digest)))
            {
                ++falsePositiveCount;
                continue;
            }

            for (uint32_t k{0}; k < 5; ++k)
            {
                results[i].digest[k] = utils::endian(results[i].digest[k]);
            }

            results[i].iteration = iteration;
            results[i].privateXPart = privateXPart;
            results[i].privateYPart = (iteration * keysNumberPerIteration) + results[i].idx;

            while (!gContext->hash160SearchResultsQueue->push(results[i]))
            {
                if (stopFlag)
                    return;

                // If the queue is full, yield to avoid busy-wait
                std::this_thread::yield();
            }
        }

        if (falsePositiveCount)
        {
            BOOST_LOG_TRIVIAL(trace) << "False positives count: " << falsePositiveCount;
        }

        BOOST_LOG_TRIVIAL(trace) << std::format("[{}] pushResultsToQueue2: {} ms", cudaInfo.id, t.elapsedMs());
    }

    void startSearchPublicHashWithPrivateDefinedXRandomY(const uint32_t privateXPart) const
    {
        const uint32_t keysNumberToGenerate = gContext->config.hunter().keysNumberToGenerate;
        const uint32_t totalKeysToGenerate = (keysNumberToGenerate == 0) ? std::numeric_limits<uint32_t>::max() : keysNumberToGenerate;

        const uint32_t keysNumberPerIteration = cuECC->getKeysNumberPerIteration();
        const uint32_t iterationsCount = totalKeysToGenerate / keysNumberPerIteration;
        const uint32_t remainder = totalKeysToGenerate - (iterationsCount * keysNumberPerIteration);
        const uint32_t finalIterationsCount = iterationsCount + (remainder > 0 ? 1 : 0);

        BOOST_LOG_TRIVIAL(fatal) << std::format(std::locale("en_US.UTF-8"), "[{}] KeyHunter: total iterations: {:L} totalKeysToGenerate: {:L}, keysNumberPerIteration: {:L}",
                                                cudaInfo.id, finalIterationsCount, totalKeysToGenerate, keysNumberPerIteration);

        utils::Timer timer;
        uint32_t iteration{0};
        while (!stopFlag && iteration < finalIterationsCount)
        {
            timer.start();
            {
                utils::Timer t;
                cuECC->generatePrivateKeysForXPerIteration(privateXPart, iteration);
                BOOST_LOG_TRIVIAL(trace) << std::format("[{}] generatePrivateKeysForXPerIteration: {} ms", cudaInfo.id, t.elapsedMs());

                t.start();
                cuECC->calculatePublicKeysAndCheckHash160();
                BOOST_LOG_TRIVIAL(trace) << std::format("[{}] calculatePublicKeysAndCheckHash160: {} ms", cudaInfo.id, t.elapsedMs());
            }
            //const uint64_t nextY = iteration * cuECC->getKeysNumberPerIteration() + 1;
            /// TODO(ksh): to be used later
            // gContext->config.setCalculationIteration(iteration);

            pushResultsToQueue2(privateXPart, keysNumberPerIteration, iteration);

            ++iteration;

            signalStatusInfo(keysNumberPerIteration, iteration, finalIterationsCount, timer.elapsedMs());
        }

        assert(iteration == finalIterationsCount);

        BOOST_LOG_TRIVIAL(fatal) << std::format(std::locale("en_US.UTF-8"), "[{}] KeyHunter: done, generated: {:L} keys", cudaInfo.id, keysNumberPerIteration * finalIterationsCount);
    }

    uint32_t getPrivateXPart() const
    {
        uint32_t privateXPart{0};
        if (gContext->config.isPrivateXPartRandom())
        {
            privateXPart = utils::randomUINT32_t();
        }
        else if (!gContext->config.hunter().forcePrivateXPart)
        {
            http::status responseCode{http::status::unknown};
            responseCode = gContext->httpClient->getNumber(privateXPart);
            if (responseCode != http::status::ok)
            {
                privateXPart = utils::randomUINT32_t();
            }
        }
        else
        {
            privateXPart = gContext->config.hunter().privateXPart;
        }

        return privateXPart;
    }

    void startSearchPublicHash()
    {
        utils::Timer t;
        BOOST_LOG_TRIVIAL(trace) << std::format("[{}] KeyHunter Thread ID: ", cudaInfo.id) << std::this_thread::get_id();

        // Preparing Public, Private, Results buffers
        hash160Lookup.setTargets(gContext->hash160Targets);
        BOOST_LOG_TRIVIAL(trace) << std::format("[{}] hash160Lookup.setTargets: {} ms", cudaInfo.id, t.elapsedMs());

        t.start();
        resultAtomicList.init(sizeof(Hash160SearchResult), 256);
        BOOST_LOG_TRIVIAL(trace) << std::format("[{}] resultAtomicList.init: {} ms", cudaInfo.id, t.elapsedMs());

        t.start();
        cuECC->init(gContext->config.hunter().pointsPerThread, gContext->config.hunter().publicKeyCompressionTypeToCheck);
        BOOST_LOG_TRIVIAL(trace) << std::format("[{}] init: {} ms", cudaInfo.id, t.elapsedMs());

        // Getting from http service the next private key x part, generating public and checking targets hashes
        do
        {
            const uint32_t privateXPart = getPrivateXPart();
            BOOST_LOG_TRIVIAL(fatal) << std::format(std::locale("en_US.UTF-8"), "[{}] Generating for privateXPart: {:#x} [{:L} | {:L}]",
                                                    cudaInfo.id, privateXPart, privateXPart, static_cast<int>(privateXPart));

            startSearchPublicHashWithPrivateDefinedXRandomY(privateXPart);

            // if it is not test we are setting search over privateXPart done
            if (!gContext->config.devMode())
            {
                const std::string postString = std::format("markDone for privateXPart: {}", privateXPart);
                utils::backupToTGAsync(postString);
                (void) gContext->httpClient->markDone(privateXPart);

                BOOST_LOG_TRIVIAL(fatal) << postString;
            }
        }
        while (!stopFlag && !gContext->config.hunter().forcePrivateXPart); // if force private X part is set, one iteration is enough
    }
};

KeyHunter::KeyHunter(const std::shared_ptr<GlobalContext>& context, cu::CudaDeviceInfo&& cudaInfo) : mImpl(std::make_unique<Impl>(context, std::move(cudaInfo))) {}
KeyHunter::~KeyHunter() = default;

KeyHunter::KeyHunter(KeyHunter &&rhs) noexcept = default;

KeyHunter& KeyHunter::operator=(KeyHunter &&rhs) noexcept = default;

void KeyHunter::startSearchPublicHash() const
{
    mImpl->startSearchPublicHash();
}

void KeyHunter::stop() const
{
    mImpl->stop();
}
