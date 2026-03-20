#define CATCH_CONFIG_MAIN
#include <catch2/catch_all.hpp>

#include "cuda/sha1.cuh"
#include "cuda/defines.h"
#include "util/crypto_util.h"
#include "util/utils.h"
#include "util/cuda_util.h"
#include "util/secp256k1.h"
#include "util/address_util.h"

#include <thrust/host_vector.h>
#include <thrust/device_vector.h>
#include <array>
#include <limits>
#include <vector>
#include <iostream>
#include <ranges>

namespace
{
std::array<uint8_t, 32> toBigEndianBytes(const uint256_t& words)
{
    std::array<uint8_t, 32> bytes{};
    for (int i = 0; i < 8; ++i)
    {
        const int byte_idx = 7 - i;
        const uint32_t word = words.v[i];
        bytes[byte_idx * 4 + 0] = static_cast<uint8_t>((word >> 24) & 0xFF);
        bytes[byte_idx * 4 + 1] = static_cast<uint8_t>((word >> 16) & 0xFF);
        bytes[byte_idx * 4 + 2] = static_cast<uint8_t>((word >> 8) & 0xFF);
        bytes[byte_idx * 4 + 3] = static_cast<uint8_t>(word & 0xFF);
    }
    return bytes;
}
}

// CUDA kernel для тестирования generatePrivateKeyBase
__global__ void testGeneratePrivateKeyBaseKernel(const uint2* inputs, uint256_t* outputs, int count)
{
    unsigned int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx < count)
    {
        generatePrivateKeyBase(inputs[idx], outputs[idx]);
    }
}

// New generator kernel: emits two keys for the same (x, y).
__global__ void testGeneratePrivateKeyBase2Kernel(const uint2* inputs, uint256_t* outputs1, uint256_t* outputs2, int count)
{
    unsigned int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx < count)
    {
        generatePrivateKeyBase2(inputs[idx], outputs1[idx], outputs2[idx]);
    }
}

TEST_CASE("Test generatePrivateKeyBase CUDA vs CPU generatePrivateKey")
{
    constexpr int defaultCudaDeviceID{0};
    cu::cudaInit(defaultCudaDeviceID);

    // Тестовые векторы: (x, y) -> ожидаемый приватный ключ
    std::vector<std::pair<uint32_t, uint32_t>> testCases = {
        {1, 0},
        {1, 1},
        {1, 1024},
        {0x12345678, 0xABCDEF00},
        {std::numeric_limits<uint32_t>::max(), 0},
        {0, std::numeric_limits<uint32_t>::max()},
    };

    for (const auto& [x, y] : testCases)
    {
        // CPU версия
        uint8_t cpuOutput[32] = {0};
        crypto::generatePrivateKey2(static_cast<int32_t>(x), static_cast<int32_t>(y), cpuOutput);

        // Выводим результат для (1, 1)
        if (x == 1 && y == 1)
        {
            std::cout << "\nPrivate key for (1, 1) in hex: " << utils::toHex(cpuOutput, 32) << std::endl;
        }

        // CUDA версия
        thrust::host_vector<uint2> h_inputs(1);
        h_inputs[0].x = x;
        h_inputs[0].y = y;

        thrust::device_vector<uint2> d_inputs = h_inputs;
        thrust::device_vector<uint256_t> d_outputs(1);

        // Запускаем kernel
        testGeneratePrivateKeyBaseKernel<<<1, 1>>>(thrust::raw_pointer_cast(d_inputs.data()),
                                                   thrust::raw_pointer_cast(d_outputs.data()),
                                                   1);
        cudaDeviceSynchronize();

        // Проверяем ошибки CUDA
        cudaError_t err = cudaGetLastError();
        REQUIRE(err == cudaSuccess);

        // Копируем результат обратно на host
        thrust::host_vector<uint256_t> h_outputs = d_outputs;

        // Конвертируем CUDA результат в байты для сравнения
        // CUDA результат в little-endian словах, нужно конвертировать в big-endian байты
        uint8_t cudaOutputBytes[32] = {0};
        for (int i = 0; i < 8; i++)
        {
            const int byte_idx = 7 - i; // Reverse word order
            uint32_t word = h_outputs[0].v[i];
            cudaOutputBytes[byte_idx * 4 + 0] = static_cast<uint8_t>((word >> 24) & 0xFF);
            cudaOutputBytes[byte_idx * 4 + 1] = static_cast<uint8_t>((word >> 16) & 0xFF);
            cudaOutputBytes[byte_idx * 4 + 2] = static_cast<uint8_t>((word >> 8) & 0xFF);
            cudaOutputBytes[byte_idx * 4 + 3] = static_cast<uint8_t>(word & 0xFF);
        }

        // Сравниваем результаты
        bool match = true;
        for (int i = 0; i < 32; i++)
        {
            if (cpuOutput[i] != cudaOutputBytes[i])
            {
                match = false;
                break;
            }
        }

        if (!match)
        {
            std::cout << "\nMismatch for x=" << std::hex << x << ", y=" << y << std::dec << std::endl;
            std::cout << "CPU output: " << utils::toHex(cpuOutput, 32) << std::endl;
            std::cout << "CUDA output: " << utils::toHex(cudaOutputBytes, 32) << std::endl;
        }

        REQUIRE(match);
    }

    std::cout << "\n✓ All generatePrivateKeyBase tests passed!" << std::endl;
}

TEST_CASE("Test generatePrivateKeyBase with multiple inputs")
{
    constexpr int defaultCudaDeviceID{0};
    cu::cudaInit(defaultCudaDeviceID);

    constexpr int testCount = 100;
    std::vector<std::pair<uint32_t, uint32_t>> testCases;
    testCases.reserve(testCount);

    // Генерируем тестовые случаи
    for (int i = 0; i < testCount; i++)
    {
        testCases.emplace_back(static_cast<uint32_t>(i), static_cast<uint32_t>(i * 2));
    }

    // CPU версия
    std::vector<std::vector<uint8_t>> cpuOutputs(testCount);
    for (int i = 0; i < testCount; i++)
    {
        cpuOutputs[i].resize(32);
        crypto::generatePrivateKey2(static_cast<int32_t>(testCases[i].first),
                                     static_cast<int32_t>(testCases[i].second),
                                     cpuOutputs[i].data());
    }

    // CUDA версия
    thrust::host_vector<uint2> h_inputs(testCount);
    for (int i = 0; i < testCount; i++)
    {
        h_inputs[i].x = testCases[i].first;
        h_inputs[i].y = testCases[i].second;
    }

    thrust::device_vector<uint2> d_inputs = h_inputs;
    thrust::device_vector<uint256_t> d_outputs(testCount);

    // Запускаем kernel с несколькими потоками
    constexpr int threadsPerBlock = 256;
    constexpr int blocks = (testCount + threadsPerBlock - 1) / threadsPerBlock;
    testGeneratePrivateKeyBaseKernel<<<blocks, threadsPerBlock>>>(
        thrust::raw_pointer_cast(d_inputs.data()),
        thrust::raw_pointer_cast(d_outputs.data()),
        testCount);
    cudaDeviceSynchronize();

    // Проверяем ошибки CUDA
    cudaError_t err = cudaGetLastError();
    REQUIRE(err == cudaSuccess);

    // Копируем результаты обратно на host
    thrust::host_vector<uint256_t> h_outputs = d_outputs;

    // Сравниваем результаты
    int mismatchCount = 0;
    for (int i = 0; i < testCount; i++)
    {
        // Конвертируем CUDA результат в байты
        uint8_t cudaOutputBytes[32] = {0};
        for (int j = 0; j < 8; j++)
        {
            const int byte_idx = 7 - j;
            uint32_t word = h_outputs[i].v[j];
            cudaOutputBytes[byte_idx * 4 + 0] = static_cast<uint8_t>((word >> 24) & 0xFF);
            cudaOutputBytes[byte_idx * 4 + 1] = static_cast<uint8_t>((word >> 16) & 0xFF);
            cudaOutputBytes[byte_idx * 4 + 2] = static_cast<uint8_t>((word >> 8) & 0xFF);
            cudaOutputBytes[byte_idx * 4 + 3] = static_cast<uint8_t>(word & 0xFF);
        }

        // Сравниваем
        bool match = true;
        for (int j = 0; j < 32; j++)
        {
            if (cpuOutputs[i][j] != cudaOutputBytes[j])
            {
                match = false;
                break;
            }
        }

        if (!match)
        {
            mismatchCount++;
            if (mismatchCount <= 5) // Показываем только первые 5 несовпадений
            {
                std::cout << "\nMismatch #" << mismatchCount << " for x=" << std::hex << testCases[i].first
                          << ", y=" << testCases[i].second << std::dec << std::endl;
                std::cout << "CPU output:  " << utils::toHex(cpuOutputs[i].data(), 32) << std::endl;
                std::cout << "CUDA output: " << utils::toHex(cudaOutputBytes, 32) << std::endl;
            }
        }
    }

    REQUIRE(mismatchCount == 0);
    std::cout << "\n✓ All " << testCount << " generatePrivateKeyBase tests passed!" << std::endl;
}

TEST_CASE("Test generatePrivateKeyBase output format")
{
    constexpr int defaultCudaDeviceID{0};
    cu::cudaInit(defaultCudaDeviceID);

    // Тестируем, что результат имеет правильный размер (32 байта)
    uint2 input;
    input.x = 1;
    input.y = 0;

    thrust::device_vector<uint2> d_inputs(1);
    d_inputs[0] = input;
    thrust::device_vector<uint256_t> d_outputs(1);

    testGeneratePrivateKeyBaseKernel<<<1, 1>>>(thrust::raw_pointer_cast(d_inputs.data()),
                                               thrust::raw_pointer_cast(d_outputs.data()),
                                               1);
    cudaDeviceSynchronize();

    thrust::host_vector<uint256_t> h_outputs = d_outputs;

    // Проверяем, что результат не нулевой (вероятность нулевого результата очень мала)
    bool allZero = true;
    for (const unsigned int i : h_outputs[0].v)
    {
        if (i != 0)
        {
            allZero = false;
            break;
        }
    }
    REQUIRE(!allZero);

    // Проверяем, что результат детерминированный (одинаковый вход -> одинаковый выход)
    thrust::device_vector<uint256_t> d_outputs2(1);
    testGeneratePrivateKeyBaseKernel<<<1, 1>>>(thrust::raw_pointer_cast(d_inputs.data()),
                                               thrust::raw_pointer_cast(d_outputs2.data()),
                                               1);
    cudaDeviceSynchronize();

    thrust::host_vector<uint256_t> h_outputs2 = d_outputs2;

    for (int i = 0; i < 8; i++)
    {
        REQUIRE(h_outputs[0].v[i] == h_outputs2[0].v[i]);
    }

    std::cout << "\n✓ generatePrivateKeyBase output format test passed!" << std::endl;
}

TEST_CASE("Test hash160 for (1, 1)")
{
    constexpr int defaultCudaDeviceID{0};
    cu::cudaInit(defaultCudaDeviceID);

    // Генерируем приватный ключ для (1, 1)
    uint8_t privateKeyBytes[32] = {0};
    crypto::generatePrivateKey2(1, 1, privateKeyBytes);

    std::cout << "\n=== Testing (1, 1) ===" << std::endl;
    std::cout << "Private key (hex): " << utils::toHex(privateKeyBytes, 32) << std::endl;

    // Конвертируем в secp256k1::uint256 (big-endian байты -> little-endian слова)
    secp256k1::uint256 privateKey;
    for (int i = 0; i < 8; i++)
    {
        const int byte_idx = 7 - i; // Reverse word order
        privateKey.v[i] = (static_cast<uint32_t>(privateKeyBytes[byte_idx * 4 + 0]) << 24) |
                          (static_cast<uint32_t>(privateKeyBytes[byte_idx * 4 + 1]) << 16) |
                          (static_cast<uint32_t>(privateKeyBytes[byte_idx * 4 + 2]) << 8) |
                          (static_cast<uint32_t>(privateKeyBytes[byte_idx * 4 + 3]));
    }

    std::cout << "Private key (uint256): " << privateKey.toString() << std::endl;

    // Вычисляем публичный ключ
    secp256k1::ecpoint publicKey = secp256k1::multiplyPoint(privateKey, secp256k1::G());

    uint32_t xWords[8]{};
    uint32_t yWords[8]{};
    publicKey.x.exportWords(xWords, 8, secp256k1::uint256::BigEndian);
    publicKey.y.exportWords(yWords, 8, secp256k1::uint256::BigEndian);

    std::cout << "Public key X: " << publicKey.x.toString() << std::endl;
    std::cout << "Public key Y: " << publicKey.y.toString() << std::endl;

    // Вычисляем hash160
    uint32_t hash160Uncompressed[5]{};
    uint32_t hash160Compressed[5]{};
    Hash::hashPublicKey(xWords, yWords, hash160Uncompressed);
    Hash::hashPublicKeyCompressed(xWords, yWords, hash160Compressed);

    // Конвертируем в little-endian для вывода
    uint32_t hash160UncompressedLE[5]{};
    uint32_t hash160CompressedLE[5]{};
    std::ranges::transform(hash160Uncompressed, hash160UncompressedLE, utils::endian);
    std::ranges::transform(hash160Compressed, hash160CompressedLE, utils::endian);

    std::cout << "\n--- Hash160 Formats ---" << std::endl;
    std::cout << "Uncompressed (big-endian words, little-endian bytes): " << utils::toHex(hash160UncompressedLE, 5) << std::endl;
    std::cout << "Compressed (big-endian words, little-endian bytes):   " << utils::toHex(hash160CompressedLE, 5) << std::endl;

    // Выводим также в формате, как хранится в структуре hash160 (little-endian слова)
    hash160 hash160UncompressedStruct;
    hash160 hash160CompressedStruct;
    for (int i = 0; i < 5; ++i)
    {
        hash160UncompressedStruct.h[i] = hash160UncompressedLE[i];
        hash160CompressedStruct.h[i] = hash160CompressedLE[i];
    }

    std::cout << "\n--- Hash160 in hash160 struct format (little-endian words) ---" << std::endl;
    std::cout << "Uncompressed struct format: " << utils::toHex(hash160UncompressedStruct.h, 5) << std::endl;
    std::cout << "Compressed struct format:   " << utils::toHex(hash160CompressedStruct.h, 5) << std::endl;

    // Выводим также в формате big-endian слов (как может быть в файле)
    std::cout << "\n--- Hash160 in big-endian word format (as might be in file) ---" << std::endl;
    std::cout << "Uncompressed (big-endian words): " << utils::toHex(hash160Uncompressed, 5) << std::endl;
    std::cout << "Compressed (big-endian words):   " << utils::toHex(hash160Compressed, 5) << std::endl;

    // Выводим внутреннее представление для диагностики
    std::cout << "\n--- Internal representation (uint32_t array) ---" << std::endl;
    std::cout << "Uncompressed LE words: ";
    for (unsigned int & i : hash160UncompressedLE)
    {
        std::cout << std::format("{:08x} ", i);
    }
    std::cout << std::endl;

    std::cout << "Compressed LE words:   ";
    for (unsigned int & i : hash160CompressedLE)
    {
        std::cout << std::format("{:08x} ", i);
    }
    std::cout << std::endl;

    std::cout << "\n✓ Hash160 test for (1, 1) completed!" << std::endl;
}

TEST_CASE("Test generatePrivateKeyBase2 first key and digest match generatePrivateKeyBase")
{
    constexpr int defaultCudaDeviceID{0};
    cu::cudaInit(defaultCudaDeviceID);

    std::vector<std::pair<uint32_t, uint32_t>> testCases = {
        {1, 1},
        {1, 1024},
        {0x12345678, 0xABCDEF00},
        {std::numeric_limits<uint32_t>::max(), 0},
        {0, std::numeric_limits<uint32_t>::max()},
    };

    thrust::host_vector<uint2> h_inputs(testCases.size());
    for (size_t i = 0; i < testCases.size(); ++i)
    {
        h_inputs[i].x = testCases[i].first;
        h_inputs[i].y = testCases[i].second;
    }

    thrust::device_vector<uint2> d_inputs = h_inputs;
    thrust::device_vector<uint256_t> d_base_outputs(testCases.size());
    thrust::device_vector<uint256_t> d_base2_first_outputs(testCases.size());
    thrust::device_vector<uint256_t> d_base2_second_outputs(testCases.size());

    constexpr int threadsPerBlock = 256;
    const int blocks = (static_cast<int>(testCases.size()) + threadsPerBlock - 1) / threadsPerBlock;

    testGeneratePrivateKeyBaseKernel<<<blocks, threadsPerBlock>>>(
        thrust::raw_pointer_cast(d_inputs.data()),
        thrust::raw_pointer_cast(d_base_outputs.data()),
        static_cast<int>(testCases.size()));
    testGeneratePrivateKeyBase2Kernel<<<blocks, threadsPerBlock>>>(
        thrust::raw_pointer_cast(d_inputs.data()),
        thrust::raw_pointer_cast(d_base2_first_outputs.data()),
        thrust::raw_pointer_cast(d_base2_second_outputs.data()),
        static_cast<int>(testCases.size()));
    cudaDeviceSynchronize();

    REQUIRE(cudaGetLastError() == cudaSuccess);

    thrust::host_vector<uint256_t> base_outputs = d_base_outputs;
    thrust::host_vector<uint256_t> base2_first_outputs = d_base2_first_outputs;

    for (size_t i = 0; i < testCases.size(); ++i)
    {
        INFO("x=" << std::hex << testCases[i].first << " y=" << testCases[i].second << std::dec);

        for (int j = 0; j < 8; ++j)
        {
            REQUIRE(base_outputs[i].v[j] == base2_first_outputs[i].v[j]);
        }

        auto toPrivateKey = [](const uint256_t& words)
        {
            uint8_t privateKeyBytes[32]{};
            for (int j = 0; j < 8; ++j)
            {
                const int byte_idx = 7 - j;
                const uint32_t word = words.v[j];
                privateKeyBytes[byte_idx * 4 + 0] = static_cast<uint8_t>((word >> 24) & 0xFF);
                privateKeyBytes[byte_idx * 4 + 1] = static_cast<uint8_t>((word >> 16) & 0xFF);
                privateKeyBytes[byte_idx * 4 + 2] = static_cast<uint8_t>((word >> 8) & 0xFF);
                privateKeyBytes[byte_idx * 4 + 3] = static_cast<uint8_t>(word & 0xFF);
            }

            secp256k1::uint256 privateKey;
            for (int j = 0; j < 8; ++j)
            {
                const int byte_idx = 7 - j;
                privateKey.v[j] = (static_cast<uint32_t>(privateKeyBytes[byte_idx * 4 + 0]) << 24) |
                                  (static_cast<uint32_t>(privateKeyBytes[byte_idx * 4 + 1]) << 16) |
                                  (static_cast<uint32_t>(privateKeyBytes[byte_idx * 4 + 2]) << 8) |
                                  (static_cast<uint32_t>(privateKeyBytes[byte_idx * 4 + 3]));
            }
            return privateKey;
        };

        const secp256k1::uint256 basePrivateKey = toPrivateKey(base_outputs[i]);
        const secp256k1::uint256 base2PrivateKey = toPrivateKey(base2_first_outputs[i]);
        const secp256k1::ecpoint basePublicKey = secp256k1::multiplyPoint(basePrivateKey, secp256k1::G());
        const secp256k1::ecpoint base2PublicKey = secp256k1::multiplyPoint(base2PrivateKey, secp256k1::G());

        uint32_t baseXWords[8]{};
        uint32_t baseYWords[8]{};
        uint32_t base2XWords[8]{};
        uint32_t base2YWords[8]{};
        basePublicKey.x.exportWords(baseXWords, 8, secp256k1::uint256::BigEndian);
        basePublicKey.y.exportWords(baseYWords, 8, secp256k1::uint256::BigEndian);
        base2PublicKey.x.exportWords(base2XWords, 8, secp256k1::uint256::BigEndian);
        base2PublicKey.y.exportWords(base2YWords, 8, secp256k1::uint256::BigEndian);

        uint32_t baseDigestUncompressed[5]{};
        uint32_t base2DigestUncompressed[5]{};
        uint32_t baseDigestCompressed[5]{};
        uint32_t base2DigestCompressed[5]{};

        Hash::hashPublicKey(baseXWords, baseYWords, baseDigestUncompressed);
        Hash::hashPublicKey(base2XWords, base2YWords, base2DigestUncompressed);
        Hash::hashPublicKeyCompressed(baseXWords, baseYWords, baseDigestCompressed);
        Hash::hashPublicKeyCompressed(base2XWords, base2YWords, base2DigestCompressed);

        for (int j = 0; j < 5; ++j)
        {
            REQUIRE(baseDigestUncompressed[j] == base2DigestUncompressed[j]);
            REQUIRE(baseDigestCompressed[j] == base2DigestCompressed[j]);
        }
    }
}

TEST_CASE("gen-mode 1 digest matches gen-mode 2 digest1")
{
    constexpr int defaultCudaDeviceID{0};
    cu::cudaInit(defaultCudaDeviceID);

    // These cases cover small seeds, asymmetric values, and uint32 boundaries.
    const std::vector<std::pair<uint32_t, uint32_t>> testCases = {
        {0, 0},
        {1, 0},
        {1, 1},
        {1, 1024},
        {0x12345678u, 0xABCDEF00u},
        {std::numeric_limits<uint32_t>::max(), 0},
        {0, std::numeric_limits<uint32_t>::max()},
        {std::numeric_limits<uint32_t>::max(), std::numeric_limits<uint32_t>::max()},
    };

    thrust::host_vector<uint2> h_inputs(testCases.size());
    for (size_t i = 0; i < testCases.size(); ++i)
    {
        h_inputs[i].x = testCases[i].first;
        h_inputs[i].y = testCases[i].second;
    }

    thrust::device_vector<uint2> d_inputs = h_inputs;
    thrust::device_vector<uint256_t> d_gen1_outputs(testCases.size());
    thrust::device_vector<uint256_t> d_gen2_digest1_outputs(testCases.size());
    thrust::device_vector<uint256_t> d_gen2_digest2_outputs(testCases.size());

    constexpr int threadsPerBlock = 256;
    const int blocks = (static_cast<int>(testCases.size()) + threadsPerBlock - 1) / threadsPerBlock;

    testGeneratePrivateKeyBaseKernel<<<blocks, threadsPerBlock>>>(
        thrust::raw_pointer_cast(d_inputs.data()),
        thrust::raw_pointer_cast(d_gen1_outputs.data()),
        static_cast<int>(testCases.size()));
    testGeneratePrivateKeyBase2Kernel<<<blocks, threadsPerBlock>>>(
        thrust::raw_pointer_cast(d_inputs.data()),
        thrust::raw_pointer_cast(d_gen2_digest1_outputs.data()),
        thrust::raw_pointer_cast(d_gen2_digest2_outputs.data()),
        static_cast<int>(testCases.size()));
    cudaDeviceSynchronize();

    REQUIRE(cudaGetLastError() == cudaSuccess);

    const thrust::host_vector<uint256_t> gen1_outputs = d_gen1_outputs;
    const thrust::host_vector<uint256_t> gen2_digest1_outputs = d_gen2_digest1_outputs;

    for (size_t i = 0; i < testCases.size(); ++i)
    {
        INFO("x=" << std::hex << testCases[i].first << " y=" << testCases[i].second << std::dec);

        for (int j = 0; j < 8; ++j)
        {
            REQUIRE(gen1_outputs[i].v[j] == gen2_digest1_outputs[i].v[j]);
        }

        const auto gen1Bytes = toBigEndianBytes(gen1_outputs[i]);
        const auto gen2Digest1Bytes = toBigEndianBytes(gen2_digest1_outputs[i]);
        REQUIRE(gen1Bytes == gen2Digest1Bytes);
    }
}

TEST_CASE("Benchmark generatePrivateKeyBase vs generatePrivateKeyBase2 [.]")
{
    constexpr int defaultCudaDeviceID{0};
    cu::cudaInit(defaultCudaDeviceID);

    constexpr int testCount = 10000;
    constexpr int threadsPerBlock = 256;
    const int blocks = (testCount + threadsPerBlock - 1) / threadsPerBlock;

    thrust::host_vector<uint2> h_inputs(testCount);
    for (int i = 0; i < testCount; ++i)
    {
        h_inputs[i].x = 1;
        h_inputs[i].y = static_cast<uint32_t>(i + 1);
    }

    thrust::device_vector<uint2> d_inputs = h_inputs;
    thrust::device_vector<uint256_t> d_base_outputs(testCount);
    thrust::device_vector<uint256_t> d_base2_outputs1(testCount);
    thrust::device_vector<uint256_t> d_base2_outputs2(testCount);

    cudaEvent_t start{};
    cudaEvent_t stop{};
    cudaEventCreate(&start);
    cudaEventCreate(&stop);

    // Warm up both kernels so the printed timings reflect steady-state work.
    testGeneratePrivateKeyBaseKernel<<<blocks, threadsPerBlock>>>(
        thrust::raw_pointer_cast(d_inputs.data()),
        thrust::raw_pointer_cast(d_base_outputs.data()),
        testCount);
    testGeneratePrivateKeyBase2Kernel<<<blocks, threadsPerBlock>>>(
        thrust::raw_pointer_cast(d_inputs.data()),
        thrust::raw_pointer_cast(d_base2_outputs1.data()),
        thrust::raw_pointer_cast(d_base2_outputs2.data()),
        testCount);
    cudaDeviceSynchronize();

    float baseMs = 0.0f;
    float base2Ms = 0.0f;
    const double baseKeys = static_cast<double>(testCount);
    const double base2Keys = static_cast<double>(testCount) * 2.0;

    cudaEventRecord(start);
    testGeneratePrivateKeyBaseKernel<<<blocks, threadsPerBlock>>>(
        thrust::raw_pointer_cast(d_inputs.data()),
        thrust::raw_pointer_cast(d_base_outputs.data()),
        testCount);
    cudaEventRecord(stop);
    cudaEventSynchronize(stop);
    cudaEventElapsedTime(&baseMs, start, stop);

    cudaEventRecord(start);
    testGeneratePrivateKeyBase2Kernel<<<blocks, threadsPerBlock>>>(
        thrust::raw_pointer_cast(d_inputs.data()),
        thrust::raw_pointer_cast(d_base2_outputs1.data()),
        thrust::raw_pointer_cast(d_base2_outputs2.data()),
        testCount);
    cudaEventRecord(stop);
    cudaEventSynchronize(stop);
    cudaEventElapsedTime(&base2Ms, start, stop);

    cudaEventDestroy(start);
    cudaEventDestroy(stop);

    REQUIRE(cudaGetLastError() == cudaSuccess);

    // Throughput is reported in millions of generated private keys per second.
    const double baseMks = (baseMs > 0.0f) ? (baseKeys / (static_cast<double>(baseMs) * 1000.0)) : 0.0;
    const double base2Mks = (base2Ms > 0.0f) ? (base2Keys / (static_cast<double>(base2Ms) * 1000.0)) : 0.0;

    std::cout << "\nBenchmark x=1, y=1..10000" << std::endl;
    std::cout << "generatePrivateKeyBase time: " << baseMs << " ms" << std::endl;
    std::cout << "generatePrivateKeyBase throughput: " << baseMks << " MK/s" << std::endl;
    std::cout << "generatePrivateKeyBase2 time: " << base2Ms << " ms" << std::endl;
    std::cout << "generatePrivateKeyBase2 throughput: " << base2Mks << " MK/s" << std::endl;
}

TEST_CASE("Throughput generatePrivateKeyBase vs generatePrivateKeyBase2 [.]")
{
    constexpr int defaultCudaDeviceID{0};
    cu::cudaInit(defaultCudaDeviceID);

    constexpr int testCount = 10000;
    constexpr int threadsPerBlock = 256;
    constexpr double targetSeconds = 30.0;
    const int blocks = (testCount + threadsPerBlock - 1) / threadsPerBlock;

    thrust::host_vector<uint2> h_inputs(testCount);
    for (int i = 0; i < testCount; ++i)
    {
        h_inputs[i].x = 1;
        h_inputs[i].y = static_cast<uint32_t>(i + 1);
    }

    thrust::device_vector<uint2> d_inputs = h_inputs;
    thrust::device_vector<uint256_t> d_base_outputs(testCount);
    thrust::device_vector<uint256_t> d_base2_outputs1(testCount);
    thrust::device_vector<uint256_t> d_base2_outputs2(testCount);

    cudaEvent_t start{};
    cudaEvent_t stop{};
    cudaEventCreate(&start);
    cudaEventCreate(&stop);

    testGeneratePrivateKeyBaseKernel<<<blocks, threadsPerBlock>>>(
        thrust::raw_pointer_cast(d_inputs.data()),
        thrust::raw_pointer_cast(d_base_outputs.data()),
        testCount);
    testGeneratePrivateKeyBase2Kernel<<<blocks, threadsPerBlock>>>(
        thrust::raw_pointer_cast(d_inputs.data()),
        thrust::raw_pointer_cast(d_base2_outputs1.data()),
        thrust::raw_pointer_cast(d_base2_outputs2.data()),
        testCount);
    cudaDeviceSynchronize();

    auto runForTargetSeconds = [&](auto kernelLaunch, double keysPerLaunch, const char* label)
    {
        uint64_t launches = 0;
        float totalMs = 0.0f;

        // Measure steady-state kernel time until the accumulated GPU work reaches 30 s.
        while (static_cast<double>(totalMs) < targetSeconds * 1000.0)
        {
            cudaEventRecord(start);
            kernelLaunch();
            cudaEventRecord(stop);
            cudaEventSynchronize(stop);

            float iterMs = 0.0f;
            cudaEventElapsedTime(&iterMs, start, stop);
            totalMs += iterMs;
            ++launches;
        }

        const double totalKeys = static_cast<double>(launches) * keysPerLaunch;
        const double throughputMks = (totalMs > 0.0f) ? (totalKeys / (static_cast<double>(totalMs) * 1000.0)) : 0.0;

        std::cout << label << " duration: " << totalMs << " ms" << std::endl;
        std::cout << label << " throughput: " << throughputMks << " MK/s" << std::endl;
    };

    std::cout << "\nSustained throughput benchmark x=1, y=1..10000" << std::endl;
    runForTargetSeconds([&]()
    {
        testGeneratePrivateKeyBaseKernel<<<blocks, threadsPerBlock>>>(
            thrust::raw_pointer_cast(d_inputs.data()),
            thrust::raw_pointer_cast(d_base_outputs.data()),
            testCount);
    }, static_cast<double>(testCount), "generatePrivateKeyBase");

    runForTargetSeconds([&]()
    {
        testGeneratePrivateKeyBase2Kernel<<<blocks, threadsPerBlock>>>(
            thrust::raw_pointer_cast(d_inputs.data()),
            thrust::raw_pointer_cast(d_base2_outputs1.data()),
            thrust::raw_pointer_cast(d_base2_outputs2.data()),
            testCount);
    }, static_cast<double>(testCount) * 2.0, "generatePrivateKeyBase2");

    cudaEventDestroy(start);
    cudaEventDestroy(stop);

    REQUIRE(cudaGetLastError() == cudaSuccess);
}
