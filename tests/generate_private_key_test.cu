#define CATCH_CONFIG_MAIN
#include <catch2/catch_all.hpp>

#include "cuda/sha1.cuh"
#include "cuda/defines.h"
#include "util/crypto_util.h"
#include "util/utils.h"
#include "util/cuda_util.h"
#include "util/secp256k1.h"
#include "util/bitcoin_utils.h"
#include "util/address_util.h"

#include <thrust/host_vector.h>
#include <thrust/device_vector.h>
#include <vector>
#include <iostream>
#include <ranges>

// CUDA kernel для тестирования generatePrivateKeyBase
__global__ void testGeneratePrivateKeyBaseKernel(const uint2* inputs, uint256_t* outputs, int count)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx < count)
    {
        generatePrivateKeyBase(inputs[idx], outputs[idx]);
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
        crypto::generatePrivateKey(static_cast<int32_t>(x), static_cast<int32_t>(y), cpuOutput);
        
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
        testCases.push_back({static_cast<uint32_t>(i), static_cast<uint32_t>(i * 2)});
    }

    // CPU версия
    std::vector<std::vector<uint8_t>> cpuOutputs(testCount);
    for (int i = 0; i < testCount; i++)
    {
        cpuOutputs[i].resize(32);
        crypto::generatePrivateKey(static_cast<int32_t>(testCases[i].first),
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
    const int blocks = (testCount + threadsPerBlock - 1) / threadsPerBlock;
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
    for (int i = 0; i < 8; i++)
    {
        if (h_outputs[0].v[i] != 0)
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
    crypto::generatePrivateKey(1, 1, privateKeyBytes);
    
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
    
    std::cout << "Hash160 (uncompressed): " << utils::toHex(hash160UncompressedLE, 5) << std::endl;
    std::cout << "Hash160 (compressed):   " << utils::toHex(hash160CompressedLE, 5) << std::endl;
    
    std::cout << "\n✓ Hash160 test for (1, 1) completed!" << std::endl;
}
