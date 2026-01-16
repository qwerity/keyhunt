#pragma once

#include <cuda_runtime.h>
#include "defines.cuh"

// SHA1 constants
constexpr uint32_t d_SHA1_K0_19{0x5A827999};
constexpr uint32_t d_SHA1_K20_39{0x6ED9EBA1};
constexpr uint32_t d_SHA1_K40_59{0x8F1BBCDC};
constexpr uint32_t d_SHA1_K60_79{0xCA62C1D6};

// SHA1 initial values
constexpr uint32_t d_SHA1_H0{0x67452301};
constexpr uint32_t d_SHA1_H1{0xEFCDAB89};
constexpr uint32_t d_SHA1_H2{0x98BADCFE};
constexpr uint32_t d_SHA1_H3{0x10325476};
constexpr uint32_t d_SHA1_H4{0xC3D2E1F0};

// SHA1 constants for Android KeyStore-like algorithm
constexpr int32_t HASH_OFFSET = 82;      // Hash state starts at index 0
constexpr int32_t BYTES_OFFSET = 81;     // Byte count at index 5
constexpr int32_t EXTRAFRAME_OFFSET = 5; // Extra frame size (5 words = 20 bytes)
constexpr uint32_t END_FLAG = 0x80000000;

__device__ __forceinline__ uint32_t rotl_sha1(const uint32_t x, const int n)
{
    return (x << n) | (x >> (32 - n));
}

__device__ __forceinline__ uint32_t f_sha1_0_19(const uint32_t b, const uint32_t c, const uint32_t d)
{
    return (b & c) | (~b & d);
}

__device__ __forceinline__ uint32_t f_sha1_20_39(const uint32_t b, const uint32_t c, const uint32_t d)
{
    return b ^ c ^ d;
}

__device__ __forceinline__ uint32_t f_sha1_40_59(const uint32_t b, const uint32_t c, const uint32_t d)
{
    return (b & c) | (b & d) | (c & d);
}

__device__ __forceinline__ uint32_t f_sha1_60_79(const uint32_t b, const uint32_t c, const uint32_t d)
{
    return b ^ c ^ d;
}

// SHA1 transform for a single 512-bit block
__device__ __forceinline__ void sha1Transform(uint32_t* h, const uint32_t* w)
{
    uint32_t a = h[0];
    uint32_t b = h[1];
    uint32_t c = h[2];
    uint32_t d = h[3];
    uint32_t e = h[4];
    
    uint32_t w_ext[80];
    
    // Copy first 16 words
    #pragma unroll
    for (int i = 0; i < 16; i++)
    {
        w_ext[i] = w[i];
    }
    
    // Expand to 80 words
    #pragma unroll
    for (int i = 16; i < 80; i++)
    {
        w_ext[i] = rotl_sha1(w_ext[i-3] ^ w_ext[i-8] ^ w_ext[i-14] ^ w_ext[i-16], 1);
    }
    
    // Main loop
    #pragma unroll
    for (int i = 0; i < 20; i++)
    {
        uint32_t temp = rotl_sha1(a, 5) + f_sha1_0_19(b, c, d) + e + d_SHA1_K0_19 + w_ext[i];
        e = d;
        d = c;
        c = rotl_sha1(b, 30);
        b = a;
        a = temp;
    }
    
    #pragma unroll
    for (int i = 20; i < 40; i++)
    {
        uint32_t temp = rotl_sha1(a, 5) + f_sha1_20_39(b, c, d) + e + d_SHA1_K20_39 + w_ext[i];
        e = d;
        d = c;
        c = rotl_sha1(b, 30);
        b = a;
        a = temp;
    }
    
    #pragma unroll
    for (int i = 40; i < 60; i++)
    {
        uint32_t temp = rotl_sha1(a, 5) + f_sha1_40_59(b, c, d) + e + d_SHA1_K40_59 + w_ext[i];
        e = d;
        d = c;
        c = rotl_sha1(b, 30);
        b = a;
        a = temp;
    }
    
    #pragma unroll
    for (int i = 60; i < 80; i++)
    {
        uint32_t temp = rotl_sha1(a, 5) + f_sha1_60_79(b, c, d) + e + d_SHA1_K60_79 + w_ext[i];
        e = d;
        d = c;
        c = rotl_sha1(b, 30);
        b = a;
        a = temp;
    }
    
    // Add to hash
    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
}

// SHA1 compute hash for Android KeyStore-like algorithm
// Processes seed[0-15] as message (512 bits) and updates hash state in seed[HASH_OFFSET to HASH_OFFSET+4]
// Optimized version based on generate_d_cuda.cpp
__device__ __forceinline__ void computeHash(uint32_t* arrW)
{
    uint32_t a = arrW[HASH_OFFSET];
    uint32_t b = arrW[HASH_OFFSET + 1];
    uint32_t c = arrW[HASH_OFFSET + 2];
    uint32_t d = arrW[HASH_OFFSET + 3];
    uint32_t e = arrW[HASH_OFFSET + 4];
    
    // Expand message schedule (words 16-79) - optimized loop
    // Partial unroll to balance performance and register usage
    uint32_t* w = arrW;
    #pragma unroll 4
    for (int t = 16; t < 80; ++t)
    {
        uint32_t temp = w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16];
        w[t] = rotl_sha1(temp, 1);
    }
    
    // Round 1: 0-19 - optimized with helper functions
    #pragma unroll
    for (int t = 0; t < 20; ++t)
    {
        uint32_t temp = rotl_sha1(a, 5) + f_sha1_0_19(b, c, d) + e + w[t] + d_SHA1_K0_19;
        e = d;
        d = c;
        c = rotl_sha1(b, 30);
        b = a;
        a = temp;
    }
    
    // Round 2: 20-39
    #pragma unroll
    for (int t = 20; t < 40; ++t)
    {
        uint32_t temp = rotl_sha1(a, 5) + f_sha1_20_39(b, c, d) + e + w[t] + d_SHA1_K20_39;
        e = d;
        d = c;
        c = rotl_sha1(b, 30);
        b = a;
        a = temp;
    }
    
    // Round 3: 40-59
    #pragma unroll
    for (int t = 40; t < 60; ++t)
    {
        uint32_t temp = rotl_sha1(a, 5) + f_sha1_40_59(b, c, d) + e + w[t] + d_SHA1_K40_59;
        e = d;
        d = c;
        c = rotl_sha1(b, 30);
        b = a;
        a = temp;
    }
    
    // Round 4: 60-79
    #pragma unroll
    for (int t = 60; t < 80; ++t)
    {
        uint32_t temp = rotl_sha1(a, 5) + f_sha1_60_79(b, c, d) + e + w[t] + d_SHA1_K60_79;
        e = d;
        d = c;
        c = rotl_sha1(b, 30);
        b = a;
        a = temp;
    }
    
    // Update hash state
    arrW[HASH_OFFSET] += a;
    arrW[HASH_OFFSET + 1] += b;
    arrW[HASH_OFFSET + 2] += c;
    arrW[HASH_OFFSET + 3] += d;
    arrW[HASH_OFFSET + 4] += e;
}

// Generate next bytes for PVK generation - optimized (inline version for CUDA)
__device__ __forceinline__ void engineNextBytes(
    uint8_t* output,
    int outputSize,
    int64_t& counter,
    uint32_t seed3,
    uint32_t seed4)
{
    constexpr int32_t SEED_SIZE = HASH_OFFSET + EXTRAFRAME_OFFSET;
    uint32_t seed[SEED_SIZE] = {0};
    
    // Initialize hash state (only what's needed)
    seed[HASH_OFFSET] = d_SHA1_H0;
    seed[HASH_OFFSET + 1] = d_SHA1_H1;
    seed[HASH_OFFSET + 2] = d_SHA1_H2;
    seed[HASH_OFFSET + 3] = d_SHA1_H3;
    seed[HASH_OFFSET + 4] = d_SHA1_H4;
    seed[3] = seed3;
    seed[4] = seed4;
    
    int offset = 0;
    while (offset < outputSize)
    {
        uint8_t temp[32];
        
        // Generate 32 bytes (2 iterations)
        #pragma unroll
        for (int iter = 0; iter < 2; ++iter)
        {
            seed[0] = static_cast<uint32_t>(counter >> 32);
            seed[1] = static_cast<uint32_t>(counter & 0xFFFFFFFF);
            seed[2] = END_FLAG;
            
            // Compute hash
            computeHash(seed);
            ++counter;
            
            // Extract bytes from hash state - optimized
            int wordsToWrite = (iter == 0) ? EXTRAFRAME_OFFSET : 3;
            int baseOffset = iter * 20;
            #pragma unroll
            for (int i = 0; i < 5; ++i)
            {
                if (i < wordsToWrite)
                {
                    uint32_t k = seed[HASH_OFFSET + i];
                    int byteOffset = baseOffset + (i << 2);
                    temp[byteOffset] = static_cast<uint8_t>(k >> 24);
                    temp[byteOffset + 1] = static_cast<uint8_t>(k >> 16);
                    temp[byteOffset + 2] = static_cast<uint8_t>(k >> 8);
                    temp[byteOffset + 3] = static_cast<uint8_t>(k);
                }
            }
        }
        
        // Copy to output - optimized
        int toCopy = (outputSize - offset < 32) ? (outputSize - offset) : 32;
        #pragma unroll
        for (int i = 0; i < 32 && (offset + i) < outputSize; ++i)
        {
            output[offset + i] = temp[i];
        }
        offset += toCopy;
    }
}

// Generate next 32-bit random integer - optimized
__device__ __forceinline__ uint32_t nextInt(int64_t& counter, uint32_t seed3, uint32_t seed4)
{
    uint8_t nextBytes[4];
    engineNextBytes(nextBytes, 4, counter, seed3, seed4);
    return (static_cast<uint32_t>(nextBytes[0]) << 24) |
           (static_cast<uint32_t>(nextBytes[1]) << 16) |
           (static_cast<uint32_t>(nextBytes[2]) << 8) |
           static_cast<uint32_t>(nextBytes[3]);
}

// Generate private key using Android SHA1PRNG mycelium
// Exact implementation matching generate_d_cuda.cpp logic
__device__ __forceinline__ void generatePrivateKeyBase(const uint2& p, uint256_t& digest)
{
    constexpr int numBits = 256;
    constexpr int numberLength = (numBits + 31) >> 5; // 8 words for 256 bits
    
    uint32_t digits[numberLength];
    int64_t counter = 0;
    
    // Generate 8 words (256 bits) - optimized
    #pragma unroll
    for (int i = 0; i < numberLength; ++i)
    {
        digits[i] = nextInt(counter, p.x, p.y);
    }
    
    // Right-shift the most significant word to align bits
    digits[numberLength - 1] >>= ((-numBits) & 31);
    
    // Remove leading zeros - optimized (matching generate_d_cuda.cpp logic)
    int actualLength = numberLength;
    while (actualLength > 0 && digits[actualLength - 1] == 0)
    {
        --actualLength;
    }
    
    // Convert to uint256_t (little-endian format) - optimized
    uint8_t outputBytes[32] = {0};
    if (actualLength > 0)
    {
        // Pack digits into bytes (big-endian) - optimized (matching generate_d_cuda.cpp)
        for (int i = actualLength - 1; i >= 0; --i)
        {
            int byteOffset = (actualLength - 1 - i) << 2;
            uint32_t d = digits[i];
            outputBytes[byteOffset] = static_cast<uint8_t>(d >> 24);
            outputBytes[byteOffset + 1] = static_cast<uint8_t>(d >> 16);
            outputBytes[byteOffset + 2] = static_cast<uint8_t>(d >> 8);
            outputBytes[byteOffset + 3] = static_cast<uint8_t>(d);
        }
        
        // Convert to uint256_t (little-endian words, big-endian bytes within words) - optimized
        #pragma unroll
        for (int i = 0; i < 8; ++i)
        {
            const int byte_idx = 7 - i; // Reverse word order
            const int base = byte_idx << 2;
            digest.v[i] = (static_cast<uint32_t>(outputBytes[base]) << 24) |
                         (static_cast<uint32_t>(outputBytes[base + 1]) << 16) |
                         (static_cast<uint32_t>(outputBytes[base + 2]) << 8) |
                         static_cast<uint32_t>(outputBytes[base + 3]);
        }
    }
    else
    {
        // Zero key - optimized
        #pragma unroll
        for (int i = 0; i < 8; ++i)
        {
            digest.v[i] = 0;
        }
    }
}
