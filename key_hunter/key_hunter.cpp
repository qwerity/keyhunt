#include "key_hunter.h"

#include <thread>
#include <format>

#include <boost/log/trivial.hpp>

#include "cuda/hash160_lookup.cuh"
#include "cuda/atomic_list.cuh"
#include "cuda/ecc.cuh"
#include "cuda/defines.h"

#include "util/utils.h"
#include "util/secp256k1.h"
#include "util/http_client.h"
#include "util/xpart_manager.h"


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
    }

    void signalStatusInfo(const uint64_t keysNumberPerIteration, const uint32_t iteration, const uint32_t totalIterations, const uint64_t elapsedTimeMs) const
    {
        static uint64_t periodElapsedTimeMS{0};
        static uint64_t periodKeysNumber{0};
        static uint64_t totalTime{0};

        totalTime += elapsedTimeMs;
        periodElapsedTimeMS += elapsedTimeMs;
        periodKeysNumber += keysNumberPerIteration;

        if (periodElapsedTimeMS >= gContext->config.statusCallbackPeriodMs())
        {
            const double periodElapsedTimeS = static_cast<double>(periodElapsedTimeMS) / 1000.0;

            StatusInfo info;
            info.dataPerSecond = (static_cast<double>(periodKeysNumber) / periodElapsedTimeS) / 1e6; // Mpoints per second
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

    void pushResultsToQueue(const uint32_t privateXPart, const uint32_t keysNumberPerIteration, const uint32_t iteration) const
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

            hash160 resultHashBE;
            for (uint32_t j = 0; j < 5; ++j)
            {
                resultHashBE.h[j] = ((results[i].digest[j] & 0x000000FF) << 24) |
                                    ((results[i].digest[j] & 0x0000FF00) << 8) |
                                    ((results[i].digest[j] & 0x00FF0000) >> 8) |
                                    ((results[i].digest[j] & 0xFF000000) >> 24);
            }
            bool found = gContext->hash160Targets.contains(resultHashBE);
            
            if (!found)
            {
                ++falsePositiveCount;
                continue;
            }

            for (uint32_t j = 0; j < 5; ++j)
            {
                results[i].digest[j] = resultHashBE.h[j];
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

                t.start();
                cuECC->calculatePublicKeysAndCheckHash160();
            }

            pushResultsToQueue(privateXPart, keysNumberPerIteration, iteration);

            ++iteration;

            signalStatusInfo(keysNumberPerIteration, iteration, finalIterationsCount, timer.elapsedMs());
        }

        // Calculate actual keys generated (may be less than planned if stopped early)
        const uint64_t actualKeysGenerated = static_cast<uint64_t>(keysNumberPerIteration) * iteration;
        BOOST_LOG_TRIVIAL(fatal) << std::format(std::locale("en_US.UTF-8"), "[{}] KeyHunter: done, generated: {:L} keys (iterations: {:L}, planned: {:L})", cudaInfo.id, actualKeysGenerated, iteration, finalIterationsCount);
    }

    uint32_t getPrivateXPart() const
    {
        // Use XPartManager if available (for async non-blocking X part distribution)
        if (gContext->xPartManager)
        {
            return gContext->xPartManager->getNextXPart();
        }

        // Fallback to old synchronous method
        uint32_t privateXPart{0};
        if (gContext->config.dataGenerationIsRandom())
        {
            privateXPart = utils::randomUINT32_t();
        }
        else if (!gContext->config.hunter().forcePrivateXPart)
        {
            http::status responseCode{http::status::unknown};
            responseCode = gContext->httpClient->getXPartNumber(privateXPart);
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
        hash160Lookup.setTargets(gContext->hash160Targets);
        resultAtomicList.init(sizeof(Hash160SearchResult), 256);
        cuECC->init(gContext->config.pointsPerThread(), gContext->config.publicKeyCompressionTypeToCheck(), gContext->config.gridSize(), gContext->config.blockSize());

        const HunterConfig& hunter = gContext->config.hunter();

        // Check if we should use specific X values mode
        if (!hunter.specificXValues.empty())
        {
            BOOST_LOG_TRIVIAL(fatal) << std::format(std::locale("en_US.UTF-8"), "[{}] Using specific X values mode: {:L} values to check",
                                                    cudaInfo.id, hunter.specificXValues.size());

            // Iterate through all specific X values
            for (size_t i = 0; i < hunter.specificXValues.size() && !stopFlag; ++i)
            {
                const uint32_t privateXPart = hunter.specificXValues[i];
                BOOST_LOG_TRIVIAL(fatal) << std::format(std::locale("en_US.UTF-8"), "[{}] [{}/{}] Generating for privateXPart: {:#x} [{:L} | {:L}]",
                                                        cudaInfo.id, i + 1, hunter.specificXValues.size(), privateXPart, privateXPart, static_cast<int>(privateXPart));

                startSearchPublicHashWithPrivateDefinedXRandomY(privateXPart);

                // Don't mark X part as done when using specificXValues - these are local values, not from server
                // No need to communicate with server in this mode
            }

            BOOST_LOG_TRIVIAL(fatal) << std::format(std::locale("en_US.UTF-8"), "[{}] Finished checking all {:L} specific X values", cudaInfo.id, hunter.specificXValues.size());
            return;
        }

        // Original logic for normal mode
        do
        {
            const uint32_t privateXPart = getPrivateXPart();
            BOOST_LOG_TRIVIAL(fatal) << std::format(std::locale("en_US.UTF-8"), "[{}] Generating for privateXPart: {:#x} [{:L} | {:L}]",
                                                    cudaInfo.id, privateXPart, privateXPart, static_cast<int>(privateXPart));

            startSearchPublicHashWithPrivateDefinedXRandomY(privateXPart);

            // Don't mark X part as done when using forcePrivateXPart - this is a local fixed value, not from server
            if (!gContext->config.devMode() && !hunter.forcePrivateXPart)
            {
                // Use async marking if XPartManager is available (recommended for multi-GPU)
                if (gContext->xPartManager)
                {
                    // XPartManager handles logging internally
                    gContext->xPartManager->markXPartDoneAsync(privateXPart);
                }
                else
                {
                    // Fallback to synchronous method (may block GPU threads)
                    const std::string postString = std::format("markXPartDone for privateXPart: {}", privateXPart);
                    utils::backupToTGAsync(postString);
                    (void) gContext->httpClient->markXPartDone(privateXPart);
#ifdef KEYHUNT_DEBUG_LOGS
                    BOOST_LOG_TRIVIAL(fatal) << postString;
#endif
                }
            }
        }
        while (!stopFlag && !hunter.forcePrivateXPart);
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
