/**
 * Тест gpuHash160Comp / gpuHash160Uncomp: проверяет, что GPU hash160 совпадает с CPU.
 * Раньше баг: порядок байт — gpuHash160_bswap32 был 0x0123 (identity), а нужен 0x3210 (swap);
 *             финальный digest не переводился в формат CPU (без bswap по словам).
 */
#define CATCH_CONFIG_MAIN
#include <catch2/catch_all.hpp>

#include "cuda/gpu_hash160.cuh"
#include "cuda/defines.h"
#include "util/address_util.h"
#include "util/utils.h"
#include "util/secp256k1.h"

#include <vector>
#include <iostream>

__global__ void runGpuHash160Kernel(
    const uint32_t* __restrict__ x32,
    const uint32_t* __restrict__ y32,
    uint32_t* __restrict__ hashComp,
    uint32_t* __restrict__ hashUncomp)
{
    uint8_t isOdd = static_cast<uint8_t>(y32[0] & 1);
    gpuHash160Comp(x32, isOdd, hashComp);
    gpuHash160Uncomp(x32, y32, hashUncomp);
}

TEST_CASE("gpuHash160Comp and gpuHash160Uncomp match CPU Hash160")
{
    // Точка из приватного ключа 1 (известный вектор)
    secp256k1::uint256 privateKey("0100000000000000000000000000000000000000000000000000000000000000");
    const auto pub = secp256k1::multiplyPoint(privateKey, secp256k1::G());

    uint32_t cpuXWords[8]{};
    uint32_t cpuYWords[8]{};
    pub.x.exportWords(cpuXWords, 8, secp256k1::uint256::BigEndian);
    pub.y.exportWords(cpuYWords, 8, secp256k1::uint256::BigEndian);

    // GPU формат: v[0]=LSW .. v[7]=MSW (как uint256_t.v)
    uint32_t gpuX[8], gpuY[8];
    for (int j = 0; j < 8; ++j) {
        gpuX[j] = cpuXWords[7 - j];
        gpuY[j] = cpuYWords[7 - j];
    }

    uint32_t* d_x = nullptr;
    uint32_t* d_y = nullptr;
    uint32_t* d_hashComp = nullptr;
    uint32_t* d_hashUncomp = nullptr;
    cudaMalloc(&d_x, 8 * sizeof(uint32_t));
    cudaMalloc(&d_y, 8 * sizeof(uint32_t));
    cudaMalloc(&d_hashComp, 5 * sizeof(uint32_t));
    cudaMalloc(&d_hashUncomp, 5 * sizeof(uint32_t));
    cudaMemcpy(d_x, gpuX, 8 * sizeof(uint32_t), cudaMemcpyHostToDevice);
    cudaMemcpy(d_y, gpuY, 8 * sizeof(uint32_t), cudaMemcpyHostToDevice);

    runGpuHash160Kernel<<<1, 1>>>(d_x, d_y, d_hashComp, d_hashUncomp);
    cudaDeviceSynchronize();

    uint32_t gpuHashComp[5]{};
    uint32_t gpuHashUncomp[5]{};
    cudaMemcpy(gpuHashComp, d_hashComp, 5 * sizeof(uint32_t), cudaMemcpyDeviceToHost);
    cudaMemcpy(gpuHashUncomp, d_hashUncomp, 5 * sizeof(uint32_t), cudaMemcpyDeviceToHost);

    cudaFree(d_x);
    cudaFree(d_y);
    cudaFree(d_hashComp);
    cudaFree(d_hashUncomp);

    uint32_t cpuHashComp[5]{};
    uint32_t cpuHashUncomp[5]{};
    Hash::hashPublicKeyCompressed(cpuXWords, cpuYWords, cpuHashComp);
    Hash::hashPublicKey(cpuXWords, cpuYWords, cpuHashUncomp);

    for (int i = 0; i < 5; ++i) {
        REQUIRE(gpuHashComp[i] == cpuHashComp[i]);
        REQUIRE(gpuHashUncomp[i] == cpuHashUncomp[i]);
    }

    std::cout << "GPU Hash160 (compressed):   " << utils::toHex(gpuHashComp, 5) << std::endl;
    std::cout << "CPU Hash160 (compressed):   " << utils::toHex(cpuHashComp, 5) << std::endl;
    std::cout << "GPU Hash160 (uncompressed): " << utils::toHex(gpuHashUncomp, 5) << std::endl;
    std::cout << "CPU Hash160 (uncompressed): " << utils::toHex(cpuHashUncomp, 5) << std::endl;
}
