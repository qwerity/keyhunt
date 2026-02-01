#define CATCH_CONFIG_MAIN
#include <catch2/catch_all.hpp>

#include "util/bitcoin_utils.h"
#include "util/crypto_util.h"
#include "util/utils.h"
#include "util/secp256k1.h"
#include "util/address_util.h"

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
            // sha256PrivateKeyBase использует little-endian формат
            msg[0] = privateXPart;
            msg[1] = i + (iteration * keysNumberPerIteration);
            msg[2] = 0x80000000;
            msg[15] = 8 * sizeof(uint2);
            crypto::sha256Init(digest);
            crypto::sha256(msg, digest);
            // digest уже в little-endian формате
            const auto p = h_privateKeys[i];
            for (uint32_t k = 0; k < 8; ++k)
            {
                REQUIRE(digest[k] == p.v[k]);
            }
        }
    }
}

TEST_CASE("check public key generation")
{
    // Тестовые векторы: приватный ключ -> ожидаемый hash160
    struct TestVector
    {
        std::string privateKeyHex;
        std::string expectedHash160Uncompressed;
        std::string expectedHash160Compressed;
    };
    
    std::vector<TestVector> testVectors = {
        {"0100000000000000000000000000000000000000000000000000000000000000", 
         "8e7682b1c4af85f1ecd61ab2288be0d54d0444df", 
         "60afcdec519698a263417ddfe7cea936737a0ee7"},
        {"0100000000000000000000000000000000000000000000000000000000000200", 
         "9f26a1af08f366906410ccdfca03d79f7e414eab", 
         "0ea31dba6f1a8ae6499943d5581bf88e274881be"},
    };

    // Проверяем CPU реализацию (эталон)
    for (const auto& test : testVectors)
    {
        secp256k1::uint256 privateKey(test.privateKeyHex);
        const auto cpuPublicKey = secp256k1::multiplyPoint(privateKey, secp256k1::G());
        
        uint32_t cpuXWords[8]{};
        uint32_t cpuYWords[8]{};
        cpuPublicKey.x.exportWords(cpuXWords, 8, secp256k1::uint256::BigEndian);
        cpuPublicKey.y.exportWords(cpuYWords, 8, secp256k1::uint256::BigEndian);

        uint32_t cpuHash160Uncompressed[5]{};
        uint32_t cpuHash160Compressed[5]{};
        Hash::hashPublicKey(cpuXWords, cpuYWords, cpuHash160Uncompressed);
        Hash::hashPublicKeyCompressed(cpuXWords, cpuYWords, cpuHash160Compressed);
        
        uint32_t cpuHash160UncompressedLE[5]{};
        uint32_t cpuHash160CompressedLE[5]{};
        std::ranges::transform(cpuHash160Uncompressed, cpuHash160UncompressedLE, utils::endian);
        std::ranges::transform(cpuHash160Compressed, cpuHash160CompressedLE, utils::endian);

        const std::string cpuHash160UncompressedStr = utils::toHex(cpuHash160UncompressedLE, 5);
        const std::string cpuHash160CompressedStr = utils::toHex(cpuHash160CompressedLE, 5);

        std::cout << "\nPrivate Key: " << test.privateKeyHex << std::endl;
        std::cout << "Expected Hash160 (uncompressed): " << test.expectedHash160Uncompressed << std::endl;
        std::cout << "CPU Hash160 (uncompressed):      " << cpuHash160UncompressedStr << std::endl;
        std::cout << "Expected Hash160 (compressed):   " << test.expectedHash160Compressed << std::endl;
        std::cout << "CPU Hash160 (compressed):        " << cpuHash160CompressedStr << std::endl;

        REQUIRE(cpuHash160UncompressedStr == test.expectedHash160Uncompressed);
        REQUIRE(cpuHash160CompressedStr == test.expectedHash160Compressed);
    }
    
    std::cout << "\n✓ CPU public key generation is correct" << std::endl;
}

TEST_CASE("check CUDA public key generation")
{
    std::cout << "\n=== Testing CUDA hash160 generation ===" << std::endl;
    
    // Инициализируем CUDA ECC
    std::unique_ptr<ECC> cuEcc(std::make_unique<ECC>());
    cuEcc->init(1, PointCompressionType::BOTH, 0, 256); // 1 точка на поток для простоты
    
    // Генерируем приватные ключи через CUDA (как в реальном использовании)
    const uint32_t privateXPart = 1;
    const uint32_t iteration = 0;
    cuEcc->generatePrivateKeysForXPerIteration(privateXPart, iteration);
    
    // Получаем приватные ключи из CUDA
    std::vector<uint256_t> h_privateKeys;
    cuEcc->getPrivateKeys(h_privateKeys);
    
    REQUIRE(h_privateKeys.size() > 0);
    
    // Заполняем публичные ключи (для теста; поиск использует fused kernel без записи в global)
    cuEcc->fillPublicKeys();
    
    // Получаем публичные ключи из CUDA
    std::vector<uint256_t> h_publicKeysX, h_publicKeysY;
    cuEcc->getPublicKeys(h_publicKeysX, h_publicKeysY);
    
    REQUIRE(h_publicKeysX.size() == h_privateKeys.size());
    REQUIRE(h_publicKeysY.size() == h_privateKeys.size());
    
    // Проверяем первые несколько ключей
    const uint32_t keysToCheck = std::min(static_cast<uint32_t>(h_privateKeys.size()), 10u);
    
    for (uint32_t i = 0; i < keysToCheck; ++i)
    {
        // Конвертируем CUDA приватный ключ в secp256k1::uint256 для CPU вычисления
        // CUDA хранит приватный ключ в little-endian формате (v[0] - младшие 32 бита)
        secp256k1::uint256 cudaPrivateKeyLE;
        for (int j = 0; j < 8; ++j)
        {
            cudaPrivateKeyLE.v[j] = h_privateKeys[i].v[j];
        }
        
        // Вычисляем ожидаемый публичный ключ через CPU
        // secp256k1::multiplyPoint ожидает приватный ключ в little-endian формате
        const auto cpuPublicKey = secp256k1::multiplyPoint(cudaPrivateKeyLE, secp256k1::G());
        uint32_t cpuXWords[8]{};
        uint32_t cpuYWords[8]{};
        cpuPublicKey.x.exportWords(cpuXWords, 8, secp256k1::uint256::BigEndian);
        cpuPublicKey.y.exportWords(cpuYWords, 8, secp256k1::uint256::BigEndian);
        
        // Конвертируем CUDA публичный ключ в формат для hash160
        // CUDA хранит в little-endian (v[0] - младшие 32 бита, v[7] - старшие 32 бита)
        // Hash::hashPublicKey ожидает big-endian (words[0] - старшие 32 бита, words[7] - младшие 32 бита)
        // Нужно инвертировать порядок слов и применить endian к каждому слову
        uint32_t cudaXWords[8]{};
        uint32_t cudaYWords[8]{};
        for (int j = 0; j < 8; ++j)
        {
            cudaXWords[j] = utils::endian(h_publicKeysX[i].v[7 - j]);
            cudaYWords[j] = utils::endian(h_publicKeysY[i].v[7 - j]);
        }
        
        // Вычисляем hash160 через CPU от CUDA публичного ключа
        uint32_t cudaHash160Uncompressed[5]{};
        uint32_t cudaHash160Compressed[5]{};
        Hash::hashPublicKey(cudaXWords, cudaYWords, cudaHash160Uncompressed);
        Hash::hashPublicKeyCompressed(cudaXWords, cudaYWords, cudaHash160Compressed);
        
        // Вычисляем ожидаемый hash160 через CPU
        uint32_t cpuHash160Uncompressed[5]{};
        uint32_t cpuHash160Compressed[5]{};
        Hash::hashPublicKey(cpuXWords, cpuYWords, cpuHash160Uncompressed);
        Hash::hashPublicKeyCompressed(cpuXWords, cpuYWords, cpuHash160Compressed);
        
        // Hash::hashPublicKey возвращает результат в big-endian формате
        // Конвертируем в little-endian для сравнения (как в CUDA)
        uint32_t cudaHash160UncompressedLE[5]{};
        uint32_t cudaHash160CompressedLE[5]{};
        uint32_t cpuHash160UncompressedLE[5]{};
        uint32_t cpuHash160CompressedLE[5]{};
        std::ranges::transform(cudaHash160Uncompressed, cudaHash160UncompressedLE, utils::endian);
        std::ranges::transform(cudaHash160Compressed, cudaHash160CompressedLE, utils::endian);
        std::ranges::transform(cpuHash160Uncompressed, cpuHash160UncompressedLE, utils::endian);
        std::ranges::transform(cpuHash160Compressed, cpuHash160CompressedLE, utils::endian);
        
        const std::string cudaHash160UncompressedStr = utils::toHex(cudaHash160UncompressedLE, 5);
        const std::string cudaHash160CompressedStr = utils::toHex(cudaHash160CompressedLE, 5);
        const std::string cpuHash160UncompressedStr = utils::toHex(cpuHash160UncompressedLE, 5);
        const std::string cpuHash160CompressedStr = utils::toHex(cpuHash160CompressedLE, 5);
        
        if (i == 0)
        {
            std::cout << "\nChecking key #" << i << ":" << std::endl;
            // Конвертируем uint256_t в байты в big-endian порядке для правильного вывода
            uint8_t privateKeyBytes[32] = {0};
            for (int j = 0; j < 8; j++)
            {
                const int byte_idx = 7 - j; // Reverse word order
                privateKeyBytes[byte_idx * 4 + 0] = static_cast<uint8_t>((h_privateKeys[i].v[j] >> 24) & 0xFF);
                privateKeyBytes[byte_idx * 4 + 1] = static_cast<uint8_t>((h_privateKeys[i].v[j] >> 16) & 0xFF);
                privateKeyBytes[byte_idx * 4 + 2] = static_cast<uint8_t>((h_privateKeys[i].v[j] >> 8) & 0xFF);
                privateKeyBytes[byte_idx * 4 + 3] = static_cast<uint8_t>(h_privateKeys[i].v[j] & 0xFF);
            }
            std::cout << "CUDA Private Key: " << utils::toHex(privateKeyBytes, 32) << std::endl;
            std::cout << "CPU Public Key X: " << utils::toHex(cpuXWords, 8) << std::endl;
            std::cout << "CUDA Public Key X: " << utils::toHex(cudaXWords, 8) << std::endl;
            std::cout << "CPU Hash160 (uncompressed): " << cpuHash160UncompressedStr << std::endl;
            std::cout << "CUDA Hash160 (uncompressed): " << cudaHash160UncompressedStr << std::endl;
            std::cout << "CPU Hash160 (compressed): " << cpuHash160CompressedStr << std::endl;
            std::cout << "CUDA Hash160 (compressed): " << cudaHash160CompressedStr << std::endl;
        }
        
        // Проверяем, что CUDA генерирует правильный публичный ключ
        // (сравниваем координаты X и Y)
        for (int j = 0; j < 8; ++j)
        {
            REQUIRE(cpuXWords[j] == cudaXWords[j]);
            REQUIRE(cpuYWords[j] == cudaYWords[j]);
        }
        
        // Проверяем, что CUDA генерирует правильный hash160
        REQUIRE(cpuHash160UncompressedStr == cudaHash160UncompressedStr);
        REQUIRE(cpuHash160CompressedStr == cudaHash160CompressedStr);
    }
    
    std::cout << "\n✓ CUDA hash160 generation is correct for " << keysToCheck << " keys!" << std::endl;
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
