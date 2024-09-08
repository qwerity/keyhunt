#pragma once
#include "defines.cuh"

__global__ void multiplyStepKernel(const uint256_t *privateKeys);

__constant__ inline uint d_pointsPerThread{};

__constant__ inline uint *d_publicKeyXPtr{};
__constant__ inline uint *d_publicKeyYPtr{};

__constant__ inline uint256_t *d_multChainPtr{};
__constant__ inline ecpoint_t *d_gPointsPtr{};
