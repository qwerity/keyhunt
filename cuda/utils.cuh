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
    // Check alignment before using vectorized operations
    // uint4 requires 16-byte alignment
    const bool dest_aligned = (reinterpret_cast<unsigned long long>(dest) & 0xF) == 0;
    const bool src_aligned = (reinterpret_cast<unsigned long long>(src) & 0xF) == 0;
    
    if (dest_aligned && src_aligned && n >= 16)
    {
        // Both addresses are aligned - use vectorized operations
        uint4* dest_vec = reinterpret_cast<uint4*>(dest);
        const uint4* src_vec = reinterpret_cast<const uint4*>(src);
        const uint32_t vec_count = n / 16;
        const uint32_t remainder = n % 16;
        
        for (uint32_t i = 0; i < vec_count; ++i)
        {
            dest_vec[i] = src_vec[i];
        }
        
        // Copy remainder
        if (remainder > 0)
        {
            for (uint32_t i = 0; i < remainder; ++i)
            {
                dest[vec_count * 16 + i] = src[vec_count * 16 + i];
            }
        }
    }
    else
    {
        // Not aligned or small size - use byte-by-byte copy
        // Manual unroll for small sizes
        if (n <= 8)
        {
            if (n >= 1) dest[0] = src[0];
            if (n >= 2) dest[1] = src[1];
            if (n >= 3) dest[2] = src[2];
            if (n >= 4) dest[3] = src[3];
            if (n >= 5) dest[4] = src[4];
            if (n >= 6) dest[5] = src[5];
            if (n >= 7) dest[6] = src[6];
            if (n >= 8) dest[7] = src[7];
        }
        else
        {
            for (uint32_t i = 0; i < n; ++i)
            {
                dest[i] = src[i];
            }
        }
    }
}

__device__ __forceinline__ void cuda_memcpy(uint32_t* dest, const uint32_t* src, uint32_t n)
{
    // Check alignment before using vectorized operations
    // uint4 requires 16-byte alignment, uint32_t* is naturally 4-byte aligned
    // So we need to check if it's also 16-byte aligned
    const bool dest_aligned = (reinterpret_cast<unsigned long long>(dest) & 0xF) == 0;
    const bool src_aligned = (reinterpret_cast<unsigned long long>(src) & 0xF) == 0;
    
    if (dest_aligned && src_aligned && n >= 4)
    {
        // Both addresses are 16-byte aligned - use vectorized operations
        uint4* dest_vec = reinterpret_cast<uint4*>(dest);
        const uint4* src_vec = reinterpret_cast<const uint4*>(src);
        const uint32_t vec_count = n / 4;
        const uint32_t remainder = n % 4;
        
        for (uint32_t i = 0; i < vec_count; ++i)
        {
            dest_vec[i] = src_vec[i];
        }
        
        // Copy remainder
        if (remainder > 0)
        {
            for (uint32_t i = 0; i < remainder; ++i)
            {
                dest[vec_count * 4 + i] = src[vec_count * 4 + i];
            }
        }
    }
    else
    {
        // Not aligned or small size - use word-by-word copy
        if (n <= 4)
        {
            if (n >= 1) dest[0] = src[0];
            if (n >= 2) dest[1] = src[1];
            if (n >= 3) dest[2] = src[2];
            if (n >= 4) dest[3] = src[3];
        }
        else
        {
            for (uint32_t i = 0; i < n; ++i)
            {
                dest[i] = src[i];
            }
        }
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