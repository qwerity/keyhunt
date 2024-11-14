#include "hd_wallet.h"

#include "cuda/hash160_lookup.cuh"
#include "cuda/atomic_list.cuh"
#include "cuda/hd_wallet.cuh"
#include "cuda/defines.h"

#include "util/utils.h"

#include <wally_bip39.h>

#include <random>
#include <thread>

#include <boost/log/trivial.hpp>

struct HDWallet::Impl
{
    std::shared_ptr<GlobalContext> gContext;
    cu::CudaDeviceInfo cudaInfo;

    std::unique_ptr<CUHDWallet> cuhdWallet;

    std::vector<std::string> expandedDerivationPaths;
    std::vector<std::vector<uint32_t>> derivationPaths;

    std::atomic<bool> stopFlag{false};

    Hash160Lookup hash160Lookup;
    CudaAtomicList resultAtomicList;

    explicit Impl(const std::shared_ptr<GlobalContext>& context, cu::CudaDeviceInfo&& cudaInfo) : gContext(context), cudaInfo(std::move(cudaInfo)), cuhdWallet(std::make_unique<CUHDWallet>())
    {

    }

    ~Impl()
    {
        stopFlag = true;
    }

    void signalStatusInfo(const uint64_t mnemonicsPerIteration, const uint32_t iteration, const uint32_t totalIterations, const uint64_t elapsedTimeMs) const
    {
        static uint64_t periodElapsedTimeMS{0};
        static uint64_t periodMnemonicsNumber{0};
        static uint64_t totalTime{0};

        totalTime += elapsedTimeMs;
        periodElapsedTimeMS += elapsedTimeMs;
        periodMnemonicsNumber += mnemonicsPerIteration;

        if (periodElapsedTimeMS >= gContext->config.statusCallbackPeriodMs())
        {
            const double periodElapsedTimeS = static_cast<double>(periodElapsedTimeMS) / 1000.0;

            StatusInfo info;
            info.dataPerSecond = (static_cast<double>(periodMnemonicsNumber) / periodElapsedTimeS) / 1e6; // mega points per second
            info.seconds = periodElapsedTimeS;
            info.total = mnemonicsPerIteration * iteration;
            info.totalTime = totalTime;
            info.device = cudaInfo.id;
            info.deviceName = cudaInfo.name;
            info.iteration = iteration;
            info.totalIterations = totalIterations;
            info.derivationsPerIteration = expandedDerivationPaths.size();
            cudaCheckError(cudaMemGetInfo(&info.freeDeviceMemory, &info.totalDeviceMemory));

            gContext->statusCallback(info);

            periodElapsedTimeMS = 0;
            periodMnemonicsNumber = 0;
        }
    }

    void pushResultsToQueue(const uint32_t keysNumberPerIteration, const uint32_t iteration) const
    {
        const utils::Timer t;
        const uint32_t count = resultAtomicList.size();

        std::vector<Hash160MnemonicSearchCudaResult> cudaResults;
        cudaResults.resize(count);

        resultAtomicList.read(cudaResults.data(), count);
        resultAtomicList.clear();

        uint32_t falsePositiveCount{0};
        for (uint32_t i = 0; i < count; ++i)
        {
            cudaResults[i].cudaDeviceId = cudaInfo.id;

            // recheck the false-positive
            if (!gContext->hash160Targets.contains(hash160(cudaResults[i].digest)))
            {
                ++falsePositiveCount;
                continue;
            }

            SWAP32_HASH160(cudaResults[i].digest, cudaResults[i].digest);

            Hash160MnemonicSearchResult result(cudaResults[i], expandedDerivationPaths[cudaResults[i].derivedPathIndex]);
            while (!gContext->mnemonicMasterKeyHash160SearchResultsQueue->push(result))
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

        BOOST_LOG_TRIVIAL(trace) << std::format("[{}] pushResultsToQueue: {} ms", cudaInfo.id, t.elapsedMs());
    }

    void generateMnemonics(const uint32_t mnemonicsNumber, std::vector<uint8_t>& mnemonics) const
    {
        std::vector<uint8_t> entropy(BIP39_ENTROPY_LEN_128);
        for (uint32_t i = 0; i < mnemonicsNumber; ++i)
        {
            if (gContext->config.devMode() && gContext->config.dataGenerationIsRandom())
            {
                utils::generateEntropy(entropy);
                utils::generateMnemonic(entropy, mnemonics.data() + i);
            }
            else if (gContext->config.devMode())
            {
                const std::string& mnemonic = gContext->config.hdWallet().mnemonic;
                strncpy_s(reinterpret_cast<char *>(mnemonics.data() + i * SIZE_MNEMONIC_FRAME_12), SIZE_MNEMONIC_FRAME_12, mnemonic.c_str(), mnemonic.size());
            }
        }
    }

    void startSearchPublicHashFromMnemonics() const
    {
        const auto& config = gContext->config.hdWallet();

        const uint32_t mnemonicsToGenerate = config.mnemonicsToGenerate;
        const uint32_t totalMnemonicsToProcess = (mnemonicsToGenerate == 0) ? std::numeric_limits<uint32_t>::max() : mnemonicsToGenerate;
        const uint32_t totalKeysToGenerate = totalMnemonicsToProcess * derivationPaths.size();

        const uint32_t mnemonicsPerIteration = cuhdWallet->getMaxDataPerIteration();
        const uint32_t publicKeysPerIteration = mnemonicsPerIteration * derivationPaths.size();
        const uint32_t iterationsCount = totalMnemonicsToProcess / mnemonicsPerIteration;
        const uint32_t remainder = totalMnemonicsToProcess - (iterationsCount * mnemonicsPerIteration);
        const uint32_t finalIterationsCount = iterationsCount + (remainder > 0 ? 1 : 0);

        BOOST_LOG_TRIVIAL(fatal) << std::format(std::locale("en_US.UTF-8"), "[{}] HDWallet: total iterations: {:L} totalMnemonicsToProcess: {:L}, mnemonicsPerIteration: {:L}, publicKeysPerIteration: {:L}, totalKeysToGenerate: {:L}",
                                                cudaInfo.id, finalIterationsCount, totalMnemonicsToProcess, mnemonicsPerIteration, publicKeysPerIteration, totalKeysToGenerate);

        std::vector<uint8_t> mnemonics(mnemonicsPerIteration * SIZE_MNEMONIC_FRAME_12, 0);

        utils::Timer timer;
        uint32_t iteration{0};
        while (!stopFlag && iteration < finalIterationsCount)
        {
            timer.start();
            {
                utils::Timer t;

                t.start();
                generateMnemonics(mnemonicsPerIteration, mnemonics);
                BOOST_LOG_TRIVIAL(trace) << std::format("generateMnemonics: {}ms {}s", t.elapsedMs(), t.elapsedS());

                t.start();
                cuhdWallet->searchPublicHashFromMnemonics(mnemonics.data(), mnemonicsPerIteration);
                BOOST_LOG_TRIVIAL(trace) << std::format("generatePublicKeys: {}ms {}s", t.elapsedMs(), t.elapsedS());
            }

            pushResultsToQueue(mnemonicsPerIteration, iteration);

            ++iteration;

            signalStatusInfo(mnemonicsPerIteration, iteration, finalIterationsCount, timer.elapsedMs());
        }

        assert(iteration == finalIterationsCount);

        BOOST_LOG_TRIVIAL(fatal) << std::format(std::locale("en_US.UTF-8"), "[{}] HDWallet: done, generated: {:L} keys", cudaInfo.id, mnemonicsPerIteration * finalIterationsCount * derivationPaths.size());
    }

    void getMnemonicMasterKeys(const uint32_t masterKeysNumber, std::vector<HDExtendedPrivateKey>& masterKeys) const
    {
        for (uint32_t i = 0; i < masterKeysNumber && !stopFlag; ++i)
        {
            gContext->mnemonicMasterKeysQueue->pop(masterKeys[i]);
        }
    }

    void startSearchPublicHashForMnemonicsMasterKeys() const
    {
        const auto& config = gContext->config.hdWallet();

        const uint32_t mnemonicsToGenerate = config.mnemonicsToGenerate;
        const uint32_t totalMnemonicsToProcess = (mnemonicsToGenerate == 0) ? std::numeric_limits<uint32_t>::max() : mnemonicsToGenerate;
        const uint32_t totalKeysToGenerate = totalMnemonicsToProcess * derivationPaths.size();

        const uint32_t mnemonicsPerIteration = cuhdWallet->getMaxDataPerIteration();
        const uint32_t publicKeysPerIteration = mnemonicsPerIteration * derivationPaths.size();
        const uint32_t iterationsCount = totalMnemonicsToProcess / mnemonicsPerIteration;
        const uint32_t remainder = totalMnemonicsToProcess - (iterationsCount * mnemonicsPerIteration);
        const uint32_t finalIterationsCount = iterationsCount + (remainder > 0 ? 1 : 0);

        BOOST_LOG_TRIVIAL(fatal) << std::format(std::locale("en_US.UTF-8"), "[{}] HDWallet: total iterations: {:L} totalMnemonicsToProcess: {:L}, mnemonicsPerIteration: {:L}, publicKeysPerIteration: {:L}, totalKeysToGenerate: {:L}",
                                                cudaInfo.id, finalIterationsCount, totalMnemonicsToProcess, mnemonicsPerIteration, publicKeysPerIteration, totalKeysToGenerate);

        utils::Timer timer;
        uint32_t iteration{0};

        std::vector<uint8_t> mnemonics(mnemonicsPerIteration * SIZE_MNEMONIC_FRAME_12);

        while (!stopFlag && iteration < finalIterationsCount)
        {
            timer.start();
            {
                utils::Timer t;

                if (gContext->config.dataGenerationIsRandom())
                {
                    t.start();
                    utils::generateMnemonics(mnemonics, 12);
                    BOOST_LOG_TRIVIAL(trace) << std::format("utils::generateMnemonics: {}ms {}s", t.elapsedMs(), t.elapsedS());
                    t.start();
                    cuhdWallet->masterKeysFromMnemonics(mnemonics);
                    BOOST_LOG_TRIVIAL(trace) << std::format("cuhdWallet->masterKeysFromMnemonics: {}ms {}s", t.elapsedMs(), t.elapsedS());

                    t.start();
                    cuhdWallet->searchPublicHashFromMnemonicsMasterKeys();
                    BOOST_LOG_TRIVIAL(trace) << std::format("searchPublicHashForMnemonicsMasterKeys: {}ms {}s", t.elapsedMs(), t.elapsedS());
                }
                else
                {
                    std::vector<HDExtendedPrivateKey> masterKeys(mnemonicsPerIteration);

                    t.start();
                    getMnemonicMasterKeys(mnemonicsPerIteration, masterKeys);
                    BOOST_LOG_TRIVIAL(trace) << std::format("getMnemonicMasterKeys: {}ms {}s", t.elapsedMs(), t.elapsedS());

                    t.start();
                    cuhdWallet->searchPublicHashFromMnemonicsMasterKeys(masterKeys);
                    BOOST_LOG_TRIVIAL(trace) << std::format("searchPublicHashForMnemonicsMasterKeys: {}ms {}s", t.elapsedMs(), t.elapsedS());
                }
            }

            pushResultsToQueue(mnemonicsPerIteration, iteration);

            ++iteration;

            signalStatusInfo(mnemonicsPerIteration, iteration, finalIterationsCount, timer.elapsedMs());
        }

        BOOST_LOG_TRIVIAL(fatal) << std::format(std::locale("en_US.UTF-8"), "[{}] HDWallet: done, generated: {:L} keys", cudaInfo.id, mnemonicsPerIteration * finalIterationsCount * derivationPaths.size());
    }

    void startSearchPublicHash()
    {
        utils::Timer t;
        BOOST_LOG_TRIVIAL(trace) << std::format("[{}] HDWallet Thread ID: ", cudaInfo.id) << std::this_thread::get_id();

        // Preparing Public, Mnemonic, Results buffers
        hash160Lookup.setTargets(gContext->hash160Targets);
        BOOST_LOG_TRIVIAL(trace) << std::format("[{}] hash160Lookup.setTargets: {} ms", cudaInfo.id, t.elapsedMs());

        const auto& config = gContext->config.hdWallet();

        derivationPaths = utils::bip32GetDerivationPathsFromPatterns(config.derivationPathsPatters, config.accountsToGenerate, config.addressesToGenerate, expandedDerivationPaths);
        cuhdWallet->init(config.generationMode, derivationPaths, config.accountsToGenerate, config.addressesToGenerate,
                         gContext->config.publicKeyCompressionTypeToCheck(), gContext->config.gridSize(), gContext->config.blockSize());

        // should be called after cuhdWallet->init to have valid cuhdWallet->getMaxDataPerIteration()
        resultAtomicList.init(sizeof(Hash160MnemonicSearchCudaResult), cuhdWallet->getMaxDataPerIteration());

        if (config.generationMode == HDWalletGenerationMode::MnemonicMasterKey)
        {
            startSearchPublicHashForMnemonicsMasterKeys();
        }
        else
        {
            startSearchPublicHashFromMnemonics();
        }
    }
};

HDWallet::HDWallet(const std::shared_ptr<GlobalContext>& context, cu::CudaDeviceInfo&& cudaInfo) : mImpl(std::make_unique<Impl>(context, std::move(cudaInfo))) {}
HDWallet::~HDWallet() = default;

HDWallet::HDWallet(HDWallet&& rhs) noexcept = default;
HDWallet& HDWallet::operator=(HDWallet &&rhs) noexcept = default;

void HDWallet::startSearchPublicHash() const
{
    return mImpl->startSearchPublicHash();
}
