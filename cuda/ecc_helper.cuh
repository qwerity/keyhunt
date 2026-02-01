#pragma once

#include "defines.cuh"

__global__ void publicKeyGenerationKernel(const uint256_t *privateKeys);
__global__ void checkHashKernel(const uint256_t *privateKeys);

/** Fused kernel: compute public keys and check hash in one pass without writing public keys to global memory. ~2x faster than separate kernels.
 *  __launch_bounds__(256, 4) — 4 blocks/SM; MAX_BATCH_SIZE 8 для меньшего давления на регистры. */
__global__ __launch_bounds__(256, 4) void publicKeyAndCheckHash160FusedKernel(const uint256_t *privateKeys);
