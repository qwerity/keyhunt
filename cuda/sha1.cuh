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
// This matches the working implementation exactly
__device__ __forceinline__ void computeHash(uint32_t* arrW)
{
    uint32_t a = arrW[HASH_OFFSET];
    uint32_t b = arrW[HASH_OFFSET + 1];
    uint32_t c = arrW[HASH_OFFSET + 2];
    uint32_t d = arrW[HASH_OFFSET + 3];
    uint32_t e = arrW[HASH_OFFSET + 4];
    uint32_t temp;
    
    // Expand message schedule
    for (int t = 16; t < 80; t++)
    {
        temp = arrW[t - 3] ^ arrW[t - 8] ^ arrW[t - 14] ^ arrW[t - 16];
        arrW[t] = (temp << 1) | (temp >> 31);
    }
    
    // Round 1: 0-19
    for (int t = 0; t < 20; t++)
    {
        temp = ((a << 5) | (a >> 27)) +
               ((b & c) | ((~b) & d)) +
               (e + arrW[t] + 0x5A827999);
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;
    }
    
    // Round 2: 20-39
    for (int t = 20; t < 40; t++)
    {
        temp = ((a << 5) | (a >> 27)) + (b ^ c ^ d) + (e + arrW[t] + 0x6ED9EBA1);
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;
    }
    
    // Round 3: 40-59
    for (int t = 40; t < 60; t++)
    {
        temp = ((a << 5) | (a >> 27)) + ((b & c) | (b & d) | (c & d)) +
               (e + arrW[t] + 0x8F1BBCDC);
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;
    }
    
    // Round 4: 60-79
    for (int t = 60; t < 80; t++)
    {
        temp = ((a << 5) | (a >> 27)) + (b ^ c ^ d) + (e + arrW[t] + 0xCA62C1D6);
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;
    }
    
    arrW[HASH_OFFSET] += a;
    arrW[HASH_OFFSET + 1] += b;
    arrW[HASH_OFFSET + 2] += c;
    arrW[HASH_OFFSET + 3] += d;
    arrW[HASH_OFFSET + 4] += e;
}

// Generate private key using Android SHA1PRNG mycelium
// Similar to sha256PrivateKeyBase, but bytes[0] &= 0x7F (make positive)
__device__ __forceinline__ void generatePrivateKeyBase(const uint2& p, uint256_t& digest)
{
    constexpr int32_t SEED_SIZE = HASH_OFFSET + EXTRAFRAME_OFFSET;
    uint32_t seed[SEED_SIZE] = {0};
    
    seed[HASH_OFFSET] = d_SHA1_H0;
    seed[HASH_OFFSET + 1] = d_SHA1_H1;
    seed[HASH_OFFSET + 2] = d_SHA1_H2;
    seed[HASH_OFFSET + 3] = d_SHA1_H3;
    seed[HASH_OFFSET + 4] = d_SHA1_H4;
    seed[BYTES_OFFSET] = 0;
    seed[3] = p.x;
    seed[4] = p.y;
    
    uint64_t counter = 0;
    uint8_t output[32] = {0};
    
    for (int iter = 0; iter < 2; iter++)
    {
        seed[0] = static_cast<uint32_t>(counter >> 32);
        seed[1] = static_cast<uint32_t>(counter & 0xFFFFFFFF);
        seed[2] = END_FLAG;
        computeHash(seed);
        counter++;
        
        int offset = iter * 20;
        int wordsToWrite = (iter == 0) ? EXTRAFRAME_OFFSET : 3; // 20 bytes first, 12 bytes second
        for (int i = 0; i < wordsToWrite; i++)
        {
            uint32_t k = seed[HASH_OFFSET + i];
            output[offset++] = static_cast<uint8_t>(k >> 24);
            output[offset++] = static_cast<uint8_t>(k >> 16);
            output[offset++] = static_cast<uint8_t>(k >> 8);
            output[offset++] = static_cast<uint8_t>(k);
        }
    }
    
    // Clear the most significant bit of the first byte
    output[0] &= 0x7F;
    
    // Convert output bytes to uint256_t (little-endian words)
    // output is in big-endian byte order, need to convert to little-endian words
    for (int i = 0; i < 8; i++)
    {
        const int byte_idx = 7 - i; // Reverse word order
        digest.v[i] = (static_cast<uint32_t>(output[byte_idx * 4 + 0]) << 24) |
                      (static_cast<uint32_t>(output[byte_idx * 4 + 1]) << 16) |
                      (static_cast<uint32_t>(output[byte_idx * 4 + 2]) << 8) |
                      (static_cast<uint32_t>(output[byte_idx * 4 + 3]));
    }

}
