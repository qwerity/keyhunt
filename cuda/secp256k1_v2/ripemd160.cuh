#pragma once

#include <cuda_runtime.h>
#include <cstdint>

struct alignas(32) RIPEMD160_CTX
{
    uint32_t total[2]{};
    uint32_t state[5]{};
    uint8_t buffer[64]{};
    [[maybe_unused]] uint8_t _padding[4]{};  // Padding to make the total size 96 bytes
};

__device__ void ripemd160Init(RIPEMD160_CTX* ctx);
__device__ void ripemd160Update(RIPEMD160_CTX* ctx, const uint8_t* input, uint32_t inputMaxLen);
__device__ void ripemd160Final(RIPEMD160_CTX* ctx, uint32_t output[5]);

__device__ void ripemd160(const uint8_t* msg, uint32_t msg_len, uint32_t hash[5]);
__device__ void hash160(const uint8_t* input, int input_len, uint32_t* output);
