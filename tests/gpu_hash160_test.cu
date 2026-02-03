/**
 * Тест gpuHash160Comp / gpuHash160Uncomp: проверяет, что GPU hash160 совпадает с CPU.
 * Используем ту же точку, что и в приложении — из ECC (v[0]=LSW .. v[7]=MSW).
 */
#define CATCH_CONFIG_MAIN
#include <catch2/catch_all.hpp>

#include "cuda/gpu_hash160.cuh"
#include "cuda/defines.cuh"
#include "cuda/ecc.cuh"
#include "util/address_util.h"
#include "util/utils.h"

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
    std::unique_ptr<ECC> cuEcc(std::make_unique<ECC>());
    cuEcc->init(1, PointCompressionType::BOTH, 0, 256);
    cuEcc->generatePrivateKeysForXPerIteration(1, 0);
    cuEcc->fillPublicKeys();

    std::vector<uint256_t> h_publicKeysX, h_publicKeysY;
    cuEcc->getPublicKeys(h_publicKeysX, h_publicKeysY);
    REQUIRE(h_publicKeysX.size() >= 1);
    REQUIRE(h_publicKeysY.size() >= 1);

    // Формат для CPU Hash: words[0]=MSW .. words[7]=LSW, каждый word в big-endian (через endian)
    uint32_t cpuXWords[8]{};
    uint32_t cpuYWords[8]{};
    for (int j = 0; j < 8; ++j) {
        cpuXWords[j] = utils::endian(h_publicKeysX[0].v[7 - j]);
        cpuYWords[j] = utils::endian(h_publicKeysY[0].v[7 - j]);
    }

    // На GPU передаём v[] как есть (x32[0]=LSW .. x32[7]=MSW)
    const uint32_t* gpuX = h_publicKeysX[0].v;
    const uint32_t* gpuY = h_publicKeysY[0].v;

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
