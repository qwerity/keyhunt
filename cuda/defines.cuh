#pragma once
#include <cstdint>
#include <cassert>

#include <cuda_runtime.h>

enum class Endianness
{
    BigEndian = 0,
    LittleEndian = 1
};

struct alignas(4 * 8) uint256_t
{
    alignas(4 * 8) uint v[8]{};

    __host__ __device__ __forceinline__
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
    static void to_uint256(const uint src[8], uint256_t& dst, const Endianness endian = Endianness::LittleEndian)
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
    explicit uint256_t(const uint src[8], const Endianness endian = Endianness::LittleEndian)
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
    constexpr explicit uint256_t(const std::initializer_list<uint>& list) noexcept
    {
        assert(list.size() <= 8 && "Too many initializers");

        size_t i = 0;
        for (const uint value : list)
        {
            v[i++] = value;
        }
    }

    __host__ __device__ __forceinline__
    uint256_t& operator=(const uint256_t& other) noexcept
    {
        if (this != &other)
        {
            const auto other_uint4 = reinterpret_cast<const uint4 *>(other.v);
            const auto v_uint4 = reinterpret_cast<uint4 *>(v);
            v_uint4[0] = other_uint4[0];
            v_uint4[1] = other_uint4[1];
        }
        return *this;
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
    const uint& operator[](const std::size_t index) const
    {
        assert(index <= 8 && "index should be less than 8");

        const auto dataPtr = reinterpret_cast<const uint*>(this);
        return *(dataPtr + index);
    }

    __host__ __device__ __forceinline__
    uint& operator[](const std::size_t index)
    {
        assert(index <= 8 && "index should be less than 8");

        const auto dataPtr = reinterpret_cast<uint*>(this);
        return *(dataPtr + index);
    }
};

struct alignas(2 * 4 * 8) ecpoint_t
{
    uint256_t x;
    uint256_t y;

    __host__ __device__ __forceinline__
    constexpr ecpoint_t() = default;

    // assign as big endian
    __host__ __device__ __forceinline__
    ecpoint_t(const uint _x[8], const uint _y[8], const Endianness endian = Endianness::LittleEndian) noexcept : x(_x, endian), y(_y, endian) {}
};

struct hash160
{
    uint h[5]{};

    __host__ __device__  hash160() = default;

    __host__ __device__
    explicit hash160(const uint hash[5])
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