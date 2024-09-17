#pragma once
#include "defines.cuh"
#include "common.h"

__global__ void multiplyStepKernel(const uint256_t *privateKeys);

// Check publickey hash160 compressed/uncompressed/both
__constant__ inline int d_publicKeyCompressionTypeToCheck{PointCompressionType::BOTH};

__constant__ inline uint d_pointsPerThread{};

__constant__ inline uint256_t *d_publicKeyXPtr{};
__constant__ inline uint256_t *d_publicKeyYPtr{};

__constant__ inline uint256_t *d_multChainPtr{};
__constant__ inline ecpoint_t *d_gPointsPtr{};
