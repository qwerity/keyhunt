#pragma once

#include "defines.cuh"
#include "sha256.cuh"
#include "ptx.cuh"

#include <curand_kernel.h>

struct PrivateKeyForXWithRandomYFunctor
{
    uint32_t xPart{};
    uint32_t yPartIncrementBy{};

    __host__ __device__
     explicit PrivateKeyForXWithRandomYFunctor(const uint32_t x, const uint32_t yPartInc) : xPart{x}, yPartIncrementBy{yPartInc} {}

    __device__
    uint256_t operator()(const uint32_t& i) const
    {
        uint2 p;
        p.x = endian(xPart);
        p.y = endian(i + yPartIncrementBy);

        uint256_t digest;
        sha256PrivateKeyBase(p, digest);

        return digest;
    }
};

struct random_uint256_generator
{
    unsigned long long seed{};

    // Constructor to initialize the random generator with a seed
    explicit random_uint256_generator(const unsigned long long seed) : seed(seed) {}

    __device__ uint256_t operator()(const int &idx) const
    {
        // Initialize CURAND state with the given seed and idx
        curandState state;
        curand_init(seed, idx, 0, &state);

        uint256_t result;

        result[0] = curand(&state);
        result[1] = curand(&state);
        result[2] = curand(&state);
        result[3] = curand(&state);
        result[4] = curand(&state);
        result[5] = curand(&state);
        result[6] = curand(&state);
        result[7] = curand(&state);

        return result;
    }
};
