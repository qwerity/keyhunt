#define CATCH_CONFIG_MAIN
#include <catch2/catch_all.hpp>

#include "util/bitcoin_utils.h"
#include "util/crypto_util.h"
#include "util/utils.h"

#include "cuda/ecc.cuh"
#include "cuda/defines.h"

#include <wally_core.h>

#include <iostream>
#include <thread>

TEST_CASE("check private key generation")
{
    std::unique_ptr cuEcc(std::make_unique<ECC>());
    cuEcc->init(32, PointCompressionType::COMPRESSED, 0, 2);
    const uint32_t keysNumberPerIteration = cuEcc->getKeysNumberPerIteration();
    const uint32_t privateXPart{1};
    const uint32_t iterationsNumber{2};
    for (uint32_t iteration = 0; iteration < iterationsNumber; ++iteration)
    {
        cuEcc->generatePrivateKeysForXPerIteration(privateXPart, iteration);
        std::vector<uint256_t> h_privateKeys;
        cuEcc->getPrivateKeys(h_privateKeys);
        REQUIRE(h_privateKeys.size() == keysNumberPerIteration);
        for (uint32_t i = 0; i < h_privateKeys.size(); ++i)
        {
            uint32_t msg[16]{};
            uint32_t digest[8]{};
            msg[0] = SWAP32(privateXPart);
            msg[1] = SWAP32(i + (iteration * keysNumberPerIteration));
            msg[2] = 0x80000000;
            msg[15] = 8 * sizeof(uint2);
            crypto::sha256Init(digest);
            crypto::sha256(msg, digest);
            std::array<uint32_t, 8> actualSha256{};
            std::ranges::transform(digest, actualSha256.data(), utils::endian);
            const auto p = h_privateKeys[i];
            for (uint32_t k = 0; k < 8; ++k)
            {
                REQUIRE(actualSha256[k] == utils::endian(p.v[k]));
            }
        }
    }
}

TEST_CASE("check public key generation")
{
    printf("TODO: add tests for checking public keys");
}

TEST_CASE("Openssl extended master key generation tests")
{
    try
    {
        constexpr size_t ENTROPY_BITS = 128; // 128 bits for a 12-word mnemonic

        // Step 1: Generate entropy
        std::vector<uint8_t> entropy(ENTROPY_BITS / 8);
        utils::generateEntropy(entropy);
        std::cout << "Entropy: " << utils::toHex(entropy) << std::endl;

        // Step 2: Generate mnemonic
        auto mnemonic = bitcoin::generateMnemonic(entropy);
        mnemonic = "tennis hero student waste adapt where fall call amused mandate hat panel";
        std::cout << "Mnemonic: " << mnemonic << std::endl;

        // Step 3: Generate seed
        const auto seed = bitcoin::mnemonicToSeed(mnemonic, "");
        std::cout << "Seed: " << utils::toHex(seed) << std::endl;

        // Step 4: Derive master key and chain code
        const HDExtendedPrivateKey extendedMasterKey = bitcoin::mnemonicSeedToExMasterKey(seed);
        std::cout << "Master Private Key: " << utils::toHex(extendedMasterKey.key, 32) << std::endl;
        std::cout << "Master Chain Code: " << utils::toHex(extendedMasterKey.chainCode, 32) << std::endl;

        // Step 5: Encode extended private key
        const auto xprv = bitcoin::exMasterKeyToXPRV(extendedMasterKey);
        std::cout << "Extended Private Key (XPRV): " << xprv << std::endl;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

TEST_CASE("Single Performance test for generateRandomExMasterKey")
{
    constexpr int targetDurationSeconds = 1;

    const auto start = std::chrono::high_resolution_clock::now();
    const auto end = start + std::chrono::seconds(targetDurationSeconds);

    uint32_t callCount = 0;
    while (std::chrono::high_resolution_clock::now() < end)
    {
        bitcoin::generateRandomExMasterKey();
        ++callCount;
    }

    REQUIRE(callCount > 0); // Ensure the function was called
    std::cout << "One CPU: Calls in " << targetDurationSeconds << " second(s): " << callCount << "\n";
}

TEST_CASE("Parallel performance test for generateRandomExMasterKey")
{
    constexpr int targetDurationSeconds = 1;

    // Determine the number of threads (cores) available
    const unsigned int numThreads = std::thread::hardware_concurrency();
    std::cout << "Using " << numThreads << " threads for the test.\n";

    // Atomic counter to aggregate calls across all threads
    std::atomic<uint32_t> totalCallCount(0);

    // Function for each thread to execute
    auto worker = [&totalCallCount, targetDurationSeconds]()
    {
        const auto start = std::chrono::high_resolution_clock::now();
        const auto end = start + std::chrono::seconds(targetDurationSeconds);
        uint32_t localCallCount = 0;
        while (std::chrono::high_resolution_clock::now() < end)
        {
            bitcoin::generateRandomExMasterKey();
            ++localCallCount;
        }
        totalCallCount += localCallCount;
    };

    // Create and start threads
    std::vector<std::thread> threads;
    for (unsigned int i = 0; i < numThreads; ++i)
    {
        threads.emplace_back(worker);
    }
    // Wait for all threads to complete
    for (auto &t: threads)
    {
        t.join();
    }

    REQUIRE(totalCallCount > 0); // Ensure the function was called
    std::cout << "ALL CPUs: calls in " << targetDurationSeconds << " second(s): " << totalCallCount << "\n";
}
