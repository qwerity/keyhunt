#pragma once
#include <cstdint>

#include <cuda_runtime.h>

struct alignas(4 * 8) uint256_t
{
    uint32_t v[8]{};

    __host__ __device__ __forceinline__
    uint256_t() = default;

    // assign as big endian
    __host__ __device__ __forceinline__
    uint256_t(const uint32_t _v[8])
    {
        for (int i = 0; i < 8; ++i)
        {
            v[i] = _v[7 - i];
        }
    }

    const uint32_t& operator[](const std::size_t index) const
    {
        const auto dataPtr = reinterpret_cast<const uint32_t*>(this);
        return *(dataPtr + index);
    }

    uint32_t& operator[](const std::size_t index)
    {
        const auto dataPtr = reinterpret_cast<uint32_t*>(this);
        return *(dataPtr + index);
    }
};

struct alignas(2 * 4 * 8) ecpoint_t
{
    uint32_t x[8];
    uint32_t y[8];

    __host__ __device__ __forceinline__ ecpoint_t() = default;

    // assign as big endian
    __host__ __device__ __forceinline__ ecpoint_t(const uint32_t _x[8], const uint32_t _y[8])
    {
        for (int i = 0; i < 8; ++i)
        {
            x[i] = _x[7 - i];
            y[i] = _y[7 - i];
        }
    }
};

struct hash160
{
    uint32_t h[5];

    __host__ __device__  hash160() = default;

    __host__ __device__
    explicit hash160(const uint32_t hash[5])
    {
        for (int i = 0; i < 5; ++i)
        {
            h[i] = hash[i];
        }
    }

    __host__ __device__
    bool operator<(const hash160& other) const
    {
        for (int i = 0; i < 5; ++i)
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
};