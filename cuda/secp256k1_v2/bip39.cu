#include "bip39.cuh"
#include "bip32.cuh"
#include "sha.cuh"
#include "../utils.cuh"
#include "../defines.h"

[[maybe_unused]] __constant__ constexpr uint8_t salt[12] = {'m', 'n', 'e', 'm', 'o', 'n', 'i', 'c', 0, 0, 0, 1}; // "mnemonic\0\0\0\1"
__constant__ constexpr uint8_t salt_swap[16] = {'c', 'i', 'n', 'o', 'm', 'e', 'n', 'm', 0, 0, 0, 0, 1, 0, 0, 0}; // "cinomenm\0\0\0\0\1\0\0\0"
[[maybe_unused]] __constant__ constexpr uint8_t key[12] = {'B', 'i', 't', 'c', 'o', 'i', 'n', ' ', 's', 'e', 'e', 'd'}; // "Bitcoin seed"
__constant__ constexpr uint8_t key_swap[16] = {' ', 'n', 'i', 'o', 'c', 't', 'i', 'B', 0, 0, 0, 0, 'd', 'e', 'e', 's'}; // " nioctiBseed"

__device__ void mnemonicToExtendedMasterKey(const uint8_t* mnemonic, uint32_t* seed, uint8_t* extendedMasterKey)
{
    alignas(32) uint32_t ipad[512 / 4]{}; // 512 bytes = 128 uint32_t blocks
    alignas(32) uint32_t opad[512 / 4]{};

    #pragma unroll
    for (uint32_t x = 0; x < 120 / 8; ++x) // 15
    {
        *(reinterpret_cast<uint64_t*>(ipad) + x) = 0x3636363636363636ULL ^ SWAP64(*(reinterpret_cast<const uint64_t*> (mnemonic) + x));
    }

    #pragma unroll
    for (uint32_t x = 0; x < 120 / 8; ++x)
    {
        *(reinterpret_cast<uint64_t*>(opad) + x) = 0x5C5C5C5C5C5C5C5CULL ^ SWAP64(*(reinterpret_cast<const uint64_t*>(mnemonic) + x));
    }

    #pragma unroll
    for (uint32_t x = 120 / 4; x < 128 / 4; ++x)
    {
        ipad[x] = 0x36363636;
    }

    #pragma unroll
    for (uint32_t x = 120 / 4; x < 128 / 4; ++x)
    {
        opad[x] = 0x5C5C5C5C;
    }

    #pragma unroll
    for (uint32_t x = 0; x < 16 / 4; ++x)
    {
        ipad[x + 128 / 4] = *(reinterpret_cast<const uint32_t*>(&salt_swap) + x);
    }
    sha512_swap(reinterpret_cast<uint64_t*>(ipad), 140, reinterpret_cast<uint64_t*>(&opad[128 / 4]));
    sha512_swap(reinterpret_cast<uint64_t*>(opad), 192, reinterpret_cast<uint64_t*>(&ipad[128 / 4]));

    #pragma unroll
    for (uint32_t x = 0; x < 64 / 4; ++x)
    {
        seed[x] = ipad[128 / 4 + x];
    }
    #pragma unroll
    for (uint32_t x = 1; x < 2048; ++x)
    {
        sha512_swap(reinterpret_cast<uint64_t*>(ipad), 192, reinterpret_cast<uint64_t*>(&opad[128 / 4]));
        sha512_swap(reinterpret_cast<uint64_t*>(opad), 192, reinterpret_cast<uint64_t*>(&ipad[128 / 4]));

        #pragma unroll
        for (uint32_t i = 0; i < SIZE32_SEED; i++)
        {
            seed[i] = seed[i] ^ ipad[128 / 4 + i];
        }
    }

    #pragma unroll
    for (uint32_t x = 0; x < 16 / 4; ++x)
    {
        ipad[x] = 0x36363636 ^ *(reinterpret_cast<const uint32_t*>(&key_swap) + x);
    }

    #pragma unroll
    for (uint32_t x = 0; x < 16 / 4; ++x)
    {
        opad[x] = 0x5C5C5C5C ^ *(reinterpret_cast<const uint32_t*>(&key_swap) + x);
    }

    #pragma unroll
    for (uint32_t x = 16 / 4; x < 128 / 4; ++x)
    {
        ipad[x] = 0x36363636;
    }

    #pragma unroll
    for (uint32_t x = 16 / 4; x < 128 / 4; ++x)
    {
        opad[x] = 0x5C5C5C5C;
    }

    #pragma unroll
    for (uint32_t x = 0; x < SIZE32_SEED; ++x)
    {
        ipad[x + 128 / 4] = seed[x];
    }

    sha512_swap(reinterpret_cast<uint64_t*>(ipad), 192, reinterpret_cast<uint64_t*>(&opad[128 / 4]));
    sha512_swap(reinterpret_cast<uint64_t*>(opad), 192, reinterpret_cast<uint64_t*>(&ipad[128 / 4]));

    #pragma unroll
    for (uint32_t x = 0; x < 128 / 8; ++x)
    {
        *(reinterpret_cast<uint64_t*>(&ipad[128 / 4]) + x) = SWAP64(*(reinterpret_cast<uint64_t*>(&ipad[128 / 4]) + x));
    }

    const auto* exMasterPrivateKey = reinterpret_cast<const uint8_t*>(&ipad[128 / 4]);
    cuda_memcpy(extendedMasterKey, exMasterPrivateKey, sizeof(extended_private_key_t));
}
