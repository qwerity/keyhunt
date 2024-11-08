#pragma once

#include <cuda_runtime.h>
#include <cstdint>

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

__device__ __forceinline__ void cuda_memcpy(uint32_t* dest, const uint32_t* src, uint32_t n)
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