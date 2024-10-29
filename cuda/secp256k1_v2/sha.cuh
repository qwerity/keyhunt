#pragma once

#include <cuda_runtime.h>
#include <cstdint>

__device__ void sha256(const uint32_t* pass, int pass_len, uint32_t* hash);

__device__ uint32_t SWAP256(uint32_t val);
__device__ uint64_t SWAP512(uint64_t val);

__device__ void sha512(uint64_t* input, uint32_t length, uint64_t* hash);
__device__ void sha512_swap(uint64_t* input, uint32_t length, uint64_t* hash);
