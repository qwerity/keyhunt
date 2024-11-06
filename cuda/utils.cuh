#pragma once

#include <cuda_runtime.h>
#include <cstdint>

// Big-Endian <-> Little-Endian
// swaps the bytes of a uint32_t value and returns a single integer with the swapped byte order.
__host__ __device__ __forceinline__ uint32_t SWAP32(uint32_t x)
{
    return (((x & 0x000000FF) << 24) |
            ((x & 0x0000FF00) << 8) |
            ((x & 0x00FF0000) >> 8) |
            ((x & 0xFF000000) >> 24));
}

__host__ __device__ __forceinline__ uint64_t SWAP64(uint64_t x)
{
    return ((((x & 0x00000000000000FFUL) << 56) |
             ((x & 0x000000000000FF00UL) << 40) |
             ((x & 0x0000000000FF0000UL) << 24) |
             ((x & 0x00000000FF000000UL) << 8)  |
             ((x & 0x000000FF00000000UL) >> 8)  |
             ((x & 0x0000FF0000000000UL) >> 24) |
             ((x & 0x00FF000000000000UL) >> 40) |
             ((x & 0xFF00000000000000UL) >> 56)));
}

// reads a 4-byte sequence from a byte array in little-endian order and assembles it into a uint32_t
#define GET_UINT32_LE(n, b, i) { (n) = ((uint32_t) (b)[(i)])| (uint32_t((b)[(i) + 1]) << 8)| (uint32_t((b)[(i) + 2]) << 16 ) | (uint32_t((b)[(i) + 3]) << 24 ); }
// writes each byte of a uint32_t value into a uint8_t array in little-endian order without changing the original uint32_t
#define PUT_UINT32_LE(n, b, i) \
    { \
        (b)[(i)]     = uint8_t((n) & 0xFF ); \
        (b)[(i) + 1] = uint8_t(((n) >> 8) & 0xFF); \
        (b)[(i) + 2] = uint8_t(((n) >> 16) & 0xFF); \
        (b)[(i) + 3] = (uint8_t) (((n) >> 24) & 0xFF); \
    }

__device__ __forceinline__ void cuda_memcpy(uint8_t* dest, const uint8_t* src, uint32_t n)
{
    #pragma unroll
    for (uint32_t i = 0; i < n; ++i)
    {
        dest[i] = src[i];
    }
}

__device__ __forceinline__ void cuda_memcpy_offset(uint8_t* dest, const uint8_t* src, int offset, uint8_t n)
{
    #pragma unroll
    for (uint32_t i = 0; i < n; ++i)
    {
        dest[i] = src[offset + i];
    }
}

__device__ __forceinline__ void cuda_memset(uint8_t* str, int c, uint32_t n)
{
    #pragma unroll
    for (uint32_t i = 0; i < n; ++i)
    {
        str[i] = c;
    }
}