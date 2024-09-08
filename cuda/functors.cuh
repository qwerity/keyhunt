#pragma once

#include "defines.cuh"
#include "sha256.cuh"
#include "ptx.cuh"

#include <curand_kernel.h>

struct PrivateKeyForXWithRandomYFunctor
{
    uint xPart{};
    uint yPartIncrementBy{};

    __host__ __device__
     explicit PrivateKeyForXWithRandomYFunctor(const uint x, const uint yPartInc) : xPart{x}, yPartIncrementBy{yPartInc} {}

    __host__ __device__
    uint256_t operator()(const uint& i) const
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

        result.v[0] = curand(&state);
        result.v[1] = curand(&state);
        result.v[2] = curand(&state);
        result.v[3] = curand(&state);
        result.v[4] = curand(&state);
        result.v[5] = curand(&state);
        result.v[6] = curand(&state);
        result.v[7] = curand(&state);

        return result;
    }
};
