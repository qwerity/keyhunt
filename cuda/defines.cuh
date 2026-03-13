#pragma once

#include <cstdint>
#include <cassert>
#include <cstdio>

#include <cuda_runtime.h>
#include <device_launch_parameters.h>

enum class Endianness
{
    BigEndian = 0,
    LittleEndian = 1
};

struct alignas(4 * 8) uint256_t
{
    alignas(4 * 8) uint32_t v[8]{};

    __forceinline__
    uint256_t() = default;

    __host__ __device__ __forceinline__
    static void to_uint256(const uint32_t src[8], uint256_t& dst, const Endianness endian = Endianness::LittleEndian)
    {
        if (endian == Endianness::LittleEndian)
        {
            for (int i = 0; i < 8; ++i)
            {
                dst.v[i] = src[i];
            }
        }
        else
        {
            for (int i = 0; i < 8; ++i)
            {
                dst.v[i] = src[7 - i];
            }
        }
    }

    __host__ __device__ __forceinline__
    explicit uint256_t(const uint32_t src[8], const Endianness endian = Endianness::LittleEndian)
    {
        if (endian == Endianness::LittleEndian)
        {
            for (int i = 0; i < 8; ++i)
            {
                v[i] = src[i];
            }
        }
        else
        {
            for (int i = 0; i < 8; ++i)
            {
                v[i] = src[7 - i];
            }
        }
    }

    __host__ __device__ __forceinline__
    constexpr uint256_t(const std::initializer_list<uint32_t>& list) noexcept
    {
        assert(list.size() <= 8 && "Too many initializers");

        size_t i = 0;
        for (const uint32_t value : list)
        {
            v[i++] = value;
        }
    }

    __host__ __device__ __forceinline__
    bool operator==(const uint256_t& other) const noexcept
    {
        bool eq = true;
        for (int i = 0; i < 8; i++)
        {
            eq &= (v[i] == other.v[i]);
        }
        return eq;
    }

    __host__ __device__ __forceinline__
    const uint32_t& operator[](const std::size_t index) const
    {
        assert(index <= 8 && "index should be less than 8");

        const auto dataPtr = reinterpret_cast<const uint32_t*>(this);
        return *(dataPtr + index);
    }

    __host__ __device__ __forceinline__
    uint32_t& operator[](const std::size_t index)
    {
        assert(index <= 8 && "index should be less than 8");

        const auto dataPtr = reinterpret_cast<uint32_t*>(this);
        return *(dataPtr + index);
    }
};

constexpr uint32_t hash160Size{20};
struct alignas(32) hash160
{
    uint32_t h[5]{};
    [[maybe_unused]] uint32_t _padding[3]{};

    hash160() = default;

    __host__ __device__
    explicit hash160(const uint32_t hash[5])
    {
        for (uint32_t i = 0; i < 5; ++i)
        {
            h[i] = hash[i];
        }
    }

    __host__ __device__
    bool operator<(const hash160& other) const
    {
        for (uint32_t i = 0; i < 5; ++i)
        {
            if (h[i] < other.h[i])
            {
                return true;
            }

            if (h[i] > other.h[i])
            {
                return false;
            }
        }

        return false;  // Return false if all elements are equal
    }

    bool operator==(const hash160& other) const
    {
        bool eq = true;
        for (int i = 0; i < 5; i++)
        {
            eq &= (h[i] == other.h[i]);
        }
        return eq;
    }
};

#ifndef __CUDA_ARCH__
#include <functional>

// std::hash specialization for hash160
template<>
struct std::hash<hash160>
{
    std::size_t operator()(const hash160& h) const noexcept
    {
        std::size_t seed = 0;
        for (unsigned int hi : h.h)
        {
            seed ^= std::hash<uint32_t>{}(hi) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
        }
        return seed;
    }
};
#endif

template <typename LambdaFunc>
cudaError_t cudaKernelSyncLaunch(const cudaStream_t& stream, LambdaFunc&& kernelLambda, const char* origin = "kernel")
{
    // Call the lambda function that launches the kernel
    kernelLambda();

    // Synchronize the stream
    cudaError_t err = cudaStreamSynchronize(stream);
    if (err != cudaSuccess)
    {
#ifdef KEYHUNT_CUDA_VERBOSE
        fprintf(stderr, "%s: CUDA error: %s\n", origin, cudaGetErrorString(err));
#endif
    }

    return err;
}

template <typename LambdaFunc>
cudaError_t cudaKernelSyncLaunchWithTiming(const cudaStream_t& stream, LambdaFunc&& kernelLambda, const char* origin = "kernel")
{
    // Create events for timing
    cudaEvent_t startEvent, stopEvent;
    cudaEventCreate(&startEvent);
    cudaEventCreate(&stopEvent);

    // Record the start event
    cudaEventRecord(startEvent, stream);

    cudaError_t err = cudaKernelSyncLaunch(stream, kernelLambda, origin);

    // Calculate and print elapsed time
    float milliseconds = 0;
    cudaEventElapsedTime(&milliseconds, startEvent, stopEvent);
#ifdef KEYHUNT_CUDA_VERBOSE
    fprintf(stderr, "%s: kernel took %f ms.\n", origin, milliseconds);
#endif

    // Clean up events
    cudaEventDestroy(startEvent);
    cudaEventDestroy(stopEvent);

    return err;
}

/**
 * Reads an 8-word big integer from device memory
 */
__device__ __forceinline__ void readInt(const uint32_t *data, const uint32_t depth, uint256_t& x)
{
    const uint32_t totalThreads = gridDim.x * blockDim.x;
    const uint32_t threadId = blockDim.x * blockIdx.x + threadIdx.x;

    const uint32_t base = depth * totalThreads;
    const uint32_t index = base + threadId;

    const auto x_uint4 = reinterpret_cast<uint4 *>(x.v);
    const auto data_uint4 = reinterpret_cast<const uint4 *>(data);
    x_uint4[0] = data_uint4[index*2];
    x_uint4[1] = data_uint4[index*2 + 1];
}

__device__ __forceinline__ uint32_t readIntLSW(const uint32_t *data, const uint32_t depth)
{
    const uint32_t totalThreads = gridDim.x * blockDim.x;
    const uint32_t threadId = blockDim.x * blockIdx.x + threadIdx.x;

    const uint32_t base = depth * totalThreads;
    const uint32_t index = base + threadId;

    const auto data_uint4 = reinterpret_cast<const uint4 *>(data);
    return data_uint4[index*2 + 1].w;
}

/**
 * Writes an 8-word big integer to device memory
 */
__device__ __forceinline__ void writeInt(const uint256_t& x, const uint32_t depth, uint32_t *data)
{
    const uint32_t totalThreads = gridDim.x * blockDim.x;
    const uint32_t threadId = blockDim.x * blockIdx.x + threadIdx.x;

    const uint32_t base = depth * totalThreads;
    const uint32_t index = base + threadId;

    const auto x_uint4 = reinterpret_cast<const uint4 *>(x.v);
    const auto data_uint4 = reinterpret_cast<uint4 *>(data);

    data_uint4[index*2] = x_uint4[0];
    data_uint4[index*2 + 1] = x_uint4[1];
}

__device__ __forceinline__ uint32_t readUInt256LSW(const uint256_t *data, const uint32_t depth)
{
    const uint32_t totalThreads = gridDim.x * blockDim.x;
    const uint32_t threadId = blockDim.x * blockIdx.x + threadIdx.x;

    const uint32_t base = depth * totalThreads;
    const uint32_t index = base + threadId;

    return data[index].v[0];
}

__device__ __forceinline__ void readUInt256(const uint256_t *data, const uint32_t depth, uint256_t& x)
{
    const uint32_t totalThreads = gridDim.x * blockDim.x;
    const uint32_t threadId = blockDim.x * blockIdx.x + threadIdx.x;

    const uint32_t base = depth * totalThreads;
    const uint32_t index = base + threadId;

    // Use vectorized load for better memory throughput
    const uint4* data_vec = reinterpret_cast<const uint4*>(data);
    uint4* x_vec = reinterpret_cast<uint4*>(x.v);
    #if defined(__CUDA_ARCH__)
    // Use __ldg() for read-only cache optimization in device code
    x_vec[0] = __ldg(&data_vec[index * 2]);     // Load first 16 bytes with read-only cache
    x_vec[1] = __ldg(&data_vec[index * 2 + 1]); // Load second 16 bytes with read-only cache
    #else
    // Host code path (should not be called, but needed for compilation)
    x_vec[0] = data_vec[index * 2];
    x_vec[1] = data_vec[index * 2 + 1];
    #endif
}

__device__ __forceinline__ void writeUInt256(const uint256_t& x, const uint32_t depth, uint256_t *data)
{
    const uint32_t totalThreads = gridDim.x * blockDim.x;
    const uint32_t threadId = blockDim.x * blockIdx.x + threadIdx.x;

    const uint32_t base = depth * totalThreads;
    const uint32_t index = base + threadId;

    // Use vectorized store for better memory throughput
    const uint4* x_vec = reinterpret_cast<const uint4*>(x.v);
    uint4* data_vec = reinterpret_cast<uint4*>(data);
    data_vec[index * 2] = x_vec[0];     // Store first 16 bytes
    data_vec[index * 2 + 1] = x_vec[1];  // Store second 16 bytes
}