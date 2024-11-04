#include "hd_wallet.h"

#include "cuda/hd_wallet.cuh"
#include "cuda/atomic_list.cuh"
#include "cuda/hash160_lookup.cuh"

#include "util/utils.h"

#include <wally_bip32.h>
#include <wally_bip39.h>

#include <random>
#include <thread>

#include <boost/log/trivial.hpp>

struct HDWallet::Impl
{
    std::shared_ptr<GlobalContext> gContext;
    cu::CudaDeviceInfo cudaInfo;

    std::unique_ptr<CUHDWallet> cuhdWallet;

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
            info.pointsPerSecond = (static_cast<double>(periodMnemonicsNumber) / periodElapsedTimeS) / 1e6; // Mpoints per second
            info.seconds = periodElapsedTimeS;
            info.total = mnemonicsPerIteration * iteration;
            info.totalTime = totalTime;
            info.device = cudaInfo.id;
            info.deviceName = cudaInfo.name;
            info.iteration = iteration;
            info.totalIterations = totalIterations;
            cudaCheckError(cudaMemGetInfo(&info.freeDeviceMemory, &info.totalDeviceMemory));

            gContext->statusCallback(info);

            periodElapsedTimeMS = 0;
            periodMnemonicsNumber = 0;
        }
    }

    void pushResultsToQueue(const uint32_t keysNumberPerIteration, const uint32_t iteration) const
    {
        uint32_t privateXPart{0};

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

    static void generateMnemonics(const uint32_t mnemonicsNumber, std::vector<uint8_t>& mnemonics)
    {
        for (uint32_t i = 0; i < mnemonicsNumber; ++i)
        {
            // Specify entropy length for mnemonic (128 bits for 12 words, 256 bits for 24 words)
            std::vector<uint8_t> entropy = HDWallet::generateEntropy(BIP39_ENTROPY_LEN_128);

            std::string mnemonic = HDWallet::generateMnemonic(entropy);
            mnemonic.resize(SIZE_MNEMONIC_FRAME);

            mnemonics.insert(mnemonics.end(), mnemonic.begin(), mnemonic.end());
        }
    }

    void startSearchPublicHashForMnemonics() const
    {
        const auto& config = gContext->config.hdWallet();

        const uint32_t mnemonicsToGenerate = config.mnemonicsToGenerate;
        const uint32_t totalMnemonicsToProcess = (mnemonicsToGenerate == 0) ? std::numeric_limits<uint32_t>::max() : mnemonicsToGenerate;
        const uint32_t totalKeysToGenerate = totalMnemonicsToProcess * derivationPaths.size();

        const uint32_t mnemonicsPerIteration = cuhdWallet->getMnemonicsPerIteration();
        const uint32_t iterationsCount = totalMnemonicsToProcess / mnemonicsPerIteration;
        const uint32_t remainder = totalMnemonicsToProcess - (iterationsCount * mnemonicsPerIteration);
        const uint32_t finalIterationsCount = iterationsCount + (remainder > 0 ? 1 : 0);

        BOOST_LOG_TRIVIAL(fatal) << std::format(std::locale("en_US.UTF-8"), "[{}] HDWallet: total iterations: {:L} totalMnemonicsToProcess: {:L}, mnemonicsPerIteration: {:L}, totalKeysToGenerate: {:L}",
                                                cudaInfo.id, finalIterationsCount, totalMnemonicsToProcess, mnemonicsPerIteration, totalKeysToGenerate);

        utils::Timer timer;
        uint32_t iteration{0};
        while (!stopFlag && iteration < finalIterationsCount)
        {
            timer.start();
            {
                utils::Timer t;

                t.start();
                std::vector<uint8_t> mnemonics;
                generateMnemonics(mnemonicsPerIteration, mnemonics);
                BOOST_LOG_TRIVIAL(info) << std::format("generateMnemonics: {}ms {}s", t.elapsedMs(), t.elapsedS());

                t.start();
                cuhdWallet->generatePublicKeysForMnemonics(mnemonics.data(), mnemonicsPerIteration);
                BOOST_LOG_TRIVIAL(info) << std::format("generatePublicKeysForMnemonics: {}ms {}s", t.elapsedMs(), t.elapsedS());
            }

            pushResultsToQueue(mnemonicsPerIteration, iteration);

            ++iteration;

            signalStatusInfo(mnemonicsPerIteration, iteration, finalIterationsCount, timer.elapsedMs());
        }

        assert(iteration == finalIterationsCount);

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
        derivationPaths = utils::bip32GetDerivationPathsFromPatterns(config.derivationPathsPatters, config.accountsToGenerate, config.addressesToGenerate);

        t.start();
        resultAtomicList.init(sizeof(Hash160SearchResult), 256);
        BOOST_LOG_TRIVIAL(trace) << std::format("[{}] resultAtomicList.init: {} ms", cudaInfo.id, t.elapsedMs());

        t.start();
        cuhdWallet->init(derivationPaths, gContext->config.publicKeyCompressionTypeToCheck(), gContext->config.gridSize(), gContext->config.blockSize());
        BOOST_LOG_TRIVIAL(trace) << std::format("[{}] init: {} ms", cudaInfo.id, t.elapsedMs());

        do
        {
            startSearchPublicHashForMnemonics();
        }
        while (!stopFlag && !gContext->config.hdWallet().forceMnemonic); // if force mnemonic is set, one iteration is enough
    }
};

HDWallet::HDWallet(const std::shared_ptr<GlobalContext>& context, cu::CudaDeviceInfo&& cudaInfo) : mImpl(std::make_unique<Impl>(context, std::move(cudaInfo))) {}
HDWallet::~HDWallet() = default;

HDWallet::HDWallet(HDWallet&& rhs) noexcept = default;
HDWallet& HDWallet::operator=(HDWallet &&rhs) noexcept = default;

// Function to generate entropy of desired bit length (multiples of 32)
std::vector<uint8_t> HDWallet::generateEntropy(size_t bytes)
{
    // Ensure bytes is a multiple of 32
    if ((bytes * 8) % 32 != 0)
    {
        BOOST_LOG_TRIVIAL(error) << "Entropy bit length must be a multiple of 32.";
        return {};
    }

    std::vector<uint8_t> entropy(bytes);

    std::random_device rd;
    std::mt19937_64 rng(rd()); // 64-bit Mersenne Twister RNG

    for (size_t i = 0; i < bytes; i += 8)
    {
        // Generate 64-bit random value
        uint64_t randomValue = rng();
        for (size_t j = 0; j < 8 && i + j < bytes; ++j)
        {
            entropy[i + j] = (randomValue >> (8 * j)) & 0xFF;
        }
    }

    return entropy;
}

// Function to convert entropy to a BIP39 mnemonic
std::string HDWallet::generateMnemonic(const std::vector<uint8_t>& entropy)
{
    char* mnemonic = nullptr;

    // Convert entropy to BIP39 mnemonic
    if (bip39_mnemonic_from_bytes(nullptr, entropy.data(), entropy.size(), &mnemonic) != WALLY_OK)
    {
        BOOST_LOG_TRIVIAL(error) << "Failed to generate mnemonic from entropy.";
        return {};
    }

    std::string result(mnemonic);
    wally_free_string(mnemonic); // Free allocated mnemonic string

    return result;
}

void HDWallet::startSearchPublicHash() const
{
    return mImpl->startSearchPublicHash();
}
