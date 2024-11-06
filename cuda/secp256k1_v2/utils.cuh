#pragma once

#include <cuda_runtime.h>
#include <cstdint>

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