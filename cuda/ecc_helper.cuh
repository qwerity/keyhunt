#pragma once

#include "defines.cuh"

__global__ void publicKeyGenerationKernel(const uint256_t *privateKeys);
__global__ void checkHashKernel(const uint256_t *privateKeys);

/** Fused kernel: compute public keys and check hash in one pass. (256,2), MAX_BATCH 8 — быстрее чем (256,4)+batch4. */
__global__ void __launch_bounds__(256, 2) publicKeyAndCheckHash160FusedKernel(const uint256_t *privateKeys);
__global__ void __launch_bounds__(256, 2) publicKeyAndCheckHash160FusedKernel2(const uint256_t *privateKeys);
