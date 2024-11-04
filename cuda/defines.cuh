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
    uint4* uint4Ptr()
    {
        return reinterpret_cast<uint4*>(v);
    }

    __host__ __device__ __forceinline__
    const uint4* uint4CPtr() const
    {
        return reinterpret_cast<const uint4*>(v);
    }

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

struct alignas(2 * 4 * 8) ecpoint_t
{
    uint256_t x;
    uint256_t y;

    __forceinline__
    constexpr ecpoint_t() = default;

    // assign as big endian
    __host__ __device__ __forceinline__
    ecpoint_t(const uint32_t _x[8], const uint32_t _y[8], const Endianness endian = Endianness::LittleEndian) noexcept : x(_x, endian), y(_y, endian) {}
};

struct hash160
{
    uint32_t h[5]{};

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
        fprintf(stderr, "%s: CUDA error: %s\n", origin, cudaGetErrorString(err));
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
    fprintf(stderr, "%s: kernel took %f ms.\n", origin, milliseconds);

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

    return data[index].v[7];
}

__device__ __forceinline__ void readUInt256(const uint256_t *data, const uint32_t depth, uint256_t& x)
{
    const uint32_t totalThreads = gridDim.x * blockDim.x;
    const uint32_t threadId = blockDim.x * blockIdx.x + threadIdx.x;

    const uint32_t base = depth * totalThreads;
    const uint32_t index = base + threadId;

    x = data[index];
}

__device__ __forceinline__ void writeUInt256(const uint256_t& x, const uint32_t depth, uint256_t *data)
{
    const uint32_t totalThreads = gridDim.x * blockDim.x;
    const uint32_t threadId = blockDim.x * blockIdx.x + threadIdx.x;

    const uint32_t base = depth * totalThreads;
    const uint32_t index = base + threadId;

    data[index] = x;
}