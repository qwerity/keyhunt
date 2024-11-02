#include "bip39.cuh"
#include "bip32.cuh"
#include "sha.cuh"
#include "utils.cuh"

[[maybe_unused]] __constant__ constexpr uint8_t salt[12] = {109, 110, 101, 109, 111, 110, 105, 99, 0, 0, 0, 1};
__constant__ constexpr uint8_t salt_swap[16] = {99, 105, 110, 111, 109, 101, 110, 109, 0, 0, 0, 0, 1, 0, 0, 0};
[[maybe_unused]] __constant__ constexpr uint8_t key[12] = {0x42, 0x69, 0x74, 0x63, 0x6f, 0x69, 0x6e, 0x20, 0x73, 0x65, 0x65, 0x64};
__constant__ constexpr uint8_t key_swap[16] = {0x20, 0x6e, 0x69, 0x6f, 0x63, 0x74, 0x69, 0x42, 0, 0, 0, 0, 0x64, 0x65, 0x65, 0x73};

__device__ void mnemonicToExtendedPrivateKey(const uint8_t* mnemonic, uint32_t seed[64 / 4], uint8_t* extended_private_key)
{
    uint32_t ipad[512 / 4]{}; // 512 bytes = 128 uint32_t blocks
    uint32_t opad[512 / 4]{};

#pragma unroll
    for (int x = 0; x < 120 / 8; x++) // 15
    {
        *(uint64_t*) ((uint64_t*) ipad + x) = 0x3636363636363636ULL ^ SWAP512(*(uint64_t*) ((uint64_t*) mnemonic + x));
    }
#pragma unroll
    for (int x = 0; x < 120 / 8; x++)
    {
        *(uint64_t*) ((uint64_t*) opad + x) = 0x5C5C5C5C5C5C5C5CULL ^ SWAP512(*(uint64_t*) ((uint64_t*) mnemonic + x));
    }
#pragma unroll
    for (int x = 120 / 4; x < 128 / 4; x++)
    {
        ipad[x] = 0x36363636;
    }
#pragma unroll
    for (int x = 120 / 4; x < 128 / 4; x++)
    {
        opad[x] = 0x5C5C5C5C;
    }
#pragma unroll
    for (int x = 0; x < 16 / 4; x++)
    {
        ipad[x + 128 / 4] = *(uint32_t*) ((uint32_t*) &salt_swap + x);
    }
    sha512_swap((uint64_t*) ipad, 140, (uint64_t*) &opad[128 / 4]);
    sha512_swap((uint64_t*) opad, 192, (uint64_t*) &ipad[128 / 4]);
#pragma unroll
    for (int x = 0; x < 64 / 4; x++)
    {
        seed[x] = ipad[128 / 4 + x];
    }
    for (int x = 1; x < 2048; x++)
    {
        sha512_swap((uint64_t*) ipad, 192, (uint64_t*) &opad[128 / 4]);
        sha512_swap((uint64_t*) opad, 192, (uint64_t*) &ipad[128 / 4]);
#pragma unroll
        for (int i = 0; i < 64 / 4; i++)
        {
            seed[i] = seed[i] ^ ipad[128 / 4 + i];
        }
    }
#pragma unroll
    for (int x = 0; x < 16 / 4; x++)
    {
        ipad[x] = 0x36363636 ^ *(uint32_t*) ((uint32_t*) &key_swap + x);
    }
#pragma unroll
    for (int x = 0; x < 16 / 4; x++)
    {
        opad[x] = 0x5C5C5C5C ^ *(uint32_t*) ((uint32_t*) &key_swap + x);
    }
#pragma unroll
    for (int x = 16 / 4; x < 128 / 4; x++)
    {
        ipad[x] = 0x36363636;
    }
#pragma unroll
    for (int x = 16 / 4; x < 128 / 4; x++)
    {
        opad[x] = 0x5C5C5C5C;
    }
#pragma unroll
    for (int x = 0; x < 64 / 4; x++)
    {
        ipad[x + 128 / 4] = seed[x];
    }
    //ipad[192 / 4] = 0;
    //opad[192 / 4] = 0;
    sha512_swap((uint64_t*) ipad, 192, (uint64_t*) &opad[128 / 4]);
    sha512_swap((uint64_t*) opad, 192, (uint64_t*) &ipad[128 / 4]);
#pragma unroll
    for (int x = 0; x < 128 / 8; x++)
    {
        *(uint64_t*) ((uint64_t*) &ipad[128 / 4] + x) = SWAP512(*(uint64_t*) ((uint64_t*) &ipad[128 / 4] + x));
    }

    const extended_private_key_t* master_private = reinterpret_cast<extended_private_key_t*>(&ipad[128 / 4]);
    cuda_memcpy(extended_private_key, reinterpret_cast<const uint8_t*>(master_private), sizeof(extended_private_key_t));
}
