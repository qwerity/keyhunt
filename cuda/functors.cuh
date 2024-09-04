#pragma once

#include <cstdint>
#include <device_launch_parameters.h>
#include <curand_kernel.h>

// thrust::transform(
//     thrust::counting_iterator<int>(0),  // Begin iterator
//     thrust::counting_iterator<int>(keysNumber),  // End iterator
//     d_privateKeys.begin(),              // Output iterator (device vector)
//     random_uint256_generator(time(0))   // Functor for random generation
// );

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

__device__ __forceinline__ static void copyBigInt(const uint32_t src[8], uint32_t dest[8])
{
    for (int i = 0; i < 8; ++i)
    {
        dest[i] = src[i];
    }
}

__device__ static bool equal(const uint32_t *a, const uint32_t *b)
{
    bool eq = true;
    for (int i = 0; i < 8; i++)
    {
        eq &= (a[i] == b[i]);
    }
    return eq;
}

/**
 * Reads an 8-word big integer from device memory
 */
__device__ static void readInt(const uint32_t *ara, const uint32_t idx, uint32_t* x)
{
    auto araTmp = reinterpret_cast<const uint4 *>(ara);
    const uint32_t totalThreads = gridDim.x * blockDim.x;
    const uint32_t base = idx * totalThreads * 2;
    const uint32_t threadId = blockDim.x * blockIdx.x + threadIdx.x;
    uint32_t index = base + threadId;

    uint4 xTmp = araTmp[index];
    x[0] = xTmp.x;
    x[1] = xTmp.y;
    x[2] = xTmp.z;
    x[3] = xTmp.w;
    index += totalThreads;

    xTmp = araTmp[index];
    x[4] = xTmp.x;
    x[5] = xTmp.y;
    x[6] = xTmp.z;
    x[7] = xTmp.w;
}

__device__ static void readUInt256(const uint256_t *data, const uint32_t idx, uint32_t* x)
{
    const uint32_t totalThreads = gridDim.x * blockDim.x;
    const uint32_t base = idx * totalThreads;
    const uint32_t threadId = blockDim.x * blockIdx.x + threadIdx.x;
    const uint32_t index = base + threadId;

    x[0] = data[index].v[0];
    x[1] = data[index].v[1];
    x[2] = data[index].v[2];
    x[3] = data[index].v[3];
    x[4] = data[index].v[4];
    x[5] = data[index].v[5];
    x[6] = data[index].v[6];
    x[7] = data[index].v[7];
}

__device__ static uint32_t readIntLSW(const uint32_t *ara, const uint32_t idx)
{
    const auto araTmp = reinterpret_cast<const uint4 *>(ara);
    const uint32_t totalThreads = gridDim.x * blockDim.x;
    const uint32_t base = idx * totalThreads * 2;
    const uint32_t threadId = blockDim.x * blockIdx.x + threadIdx.x;
    const uint32_t index = base + threadId + totalThreads;

    return araTmp[index].w;
}

/**
 * Writes an 8-word big integer to device memory
 */
__device__ static void writeInt(const uint32_t x[8], const uint32_t idx, uint32_t *ara)
{
    const auto araTmp = reinterpret_cast<uint4 *>(ara);
    const uint32_t totalThreads = gridDim.x * blockDim.x;
    const uint32_t base = idx * totalThreads * 2;
    const uint32_t threadId = blockDim.x * blockIdx.x + threadIdx.x;

    uint32_t index = base + threadId;
    uint4 xTmp;
    xTmp.x = x[0];
    xTmp.y = x[1];
    xTmp.z = x[2];
    xTmp.w = x[3];
    araTmp[index] = xTmp;

    index += totalThreads;
    xTmp.x = x[4];
    xTmp.y = x[5];
    xTmp.z = x[6];
    xTmp.w = x[7];
    araTmp[index] = xTmp;
}

__device__ static void writeUInt256(const uint32_t x[8], const uint32_t idx, uint256_t *data)
{
    const uint32_t totalThreads = gridDim.x * blockDim.x;
    const uint32_t base = idx * totalThreads;
    const uint32_t threadId = blockDim.x * blockIdx.x + threadIdx.x;
    const uint32_t index = base + threadId;

    data[index].v[0] = x[0];
    data[index].v[1] = x[1];
    data[index].v[2] = x[2];
    data[index].v[3] = x[3];
    data[index].v[4] = x[4];
    data[index].v[5] = x[5];
    data[index].v[6] = x[6];
    data[index].v[7] = x[7];
}
