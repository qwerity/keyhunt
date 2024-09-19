#pragma once
#include "defines.cuh"

__global__ void multiplyStepKernel(const uint256_t *privateKeys);

// Check publickey hash160 compressed/uncompressed/both
extern __constant__ int d_publicKeyCompressionTypeToCheck;

extern __constant__ uint32_t d_pointsPerThread;

extern __constant__ uint256_t *d_publicKeyXPtr;
extern __constant__ uint256_t *d_publicKeyYPtr;

extern __constant__ uint256_t *d_multChainPtr;
extern __constant__ ecpoint_t *d_gPointsPtr;
