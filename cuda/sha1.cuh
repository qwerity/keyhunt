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
// Optimized version matching generate_d_cuda.cpp exactly
__device__ __forceinline__ void computeHash(uint32_t* arrW)
{
    // Use local variables for fast access (matching generate_d_cuda.cpp)
    uint32_t* w = arrW;
    uint32_t* h = arrW + HASH_OFFSET;
    
    uint32_t a = h[0];
    uint32_t b = h[1];
    uint32_t c = h[2];
    uint32_t d = h[3];
    uint32_t e = h[4];
    
    // Expand message schedule (words 16-79) - optimized loop matching generate_d_cuda.cpp
    for (int t = 16; t < 80; t++)
    {
        w[t] = rotl_sha1(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1);
    }
    
    // Rounds 0-19 - matching generate_d_cuda.cpp exactly
    for (int t = 0; t < 20; t++)
    {
        uint32_t temp = rotl_sha1(a, 5) + f_sha1_0_19(b, c, d) + e + w[t] + d_SHA1_K0_19;
        e = d;
        d = c;
        c = rotl_sha1(b, 30);  // rotr32(b, 2) equivalent to rotl32(b, 30)
        b = a;
        a = temp;
    }
    
    // Rounds 20-39
    for (int t = 20; t < 40; t++)
    {
        uint32_t temp = rotl_sha1(a, 5) + f_sha1_20_39(b, c, d) + e + w[t] + d_SHA1_K20_39;
        e = d;
        d = c;
        c = rotl_sha1(b, 30);
        b = a;
        a = temp;
    }
    
    // Rounds 40-59
    for (int t = 40; t < 60; t++)
    {
        uint32_t temp = rotl_sha1(a, 5) + f_sha1_40_59(b, c, d) + e + w[t] + d_SHA1_K40_59;
        e = d;
        d = c;
        c = rotl_sha1(b, 30);
        b = a;
        a = temp;
    }
    
    // Rounds 60-79
    for (int t = 60; t < 80; t++)
    {
        uint32_t temp = rotl_sha1(a, 5) + f_sha1_60_79(b, c, d) + e + w[t] + d_SHA1_K60_79;
        e = d;
        d = c;
        c = rotl_sha1(b, 30);
        b = a;
        a = temp;
    }
    
    // Update hash state
    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
}

// SecureRandomState structure matching generate_d_cuda.cpp exactly
struct SecureRandomState
{
    uint32_t seed[HASH_OFFSET + EXTRAFRAME_OFFSET];
    uint8_t nextBytes[20];
    int nextBIndex;
    uint64_t counter;  // uint64_t as in generate_d_cuda.cpp (not int64_t)
    int firstCall;
    uint32_t seed3;  // Сохраняем для установки в nextBytes
    uint32_t seed4;  // Сохраняем для установки в nextBytes
};

// Initialize SecureRandom state (matching generate_d_cuda.cpp initSecureRandom)
__device__ __forceinline__ void initSecureRandomState(SecureRandomState* state, uint32_t x, uint32_t y)
{
    constexpr int32_t SEED_SIZE = HASH_OFFSET + EXTRAFRAME_OFFSET;
    constexpr int32_t DIGEST_LENGTH = 20;
    constexpr int32_t HASHBYTES_TO_USE = 20;
    
    // Fast zeroing of needed fields (matching generate_d_cuda.cpp)
    state->nextBIndex = HASHBYTES_TO_USE;
    state->counter = 0;
    state->firstCall = 1;
    
    // Zero arrays
    for (int i = 0; i < SEED_SIZE; i++)
    {
        state->seed[i] = 0;
    }
    for (int i = 0; i < DIGEST_LENGTH; i++)
    {
        state->nextBytes[i] = 0;
    }
    
    // Initialize SHA-1 hash state
    state->seed[BYTES_OFFSET] = 0;
    state->seed[HASH_OFFSET] = d_SHA1_H0;
    state->seed[HASH_OFFSET + 1] = d_SHA1_H1;
    state->seed[HASH_OFFSET + 2] = d_SHA1_H2;
    state->seed[HASH_OFFSET + 3] = d_SHA1_H3;
    state->seed[HASH_OFFSET + 4] = d_SHA1_H4;
    
    state->seed3 = x;
    state->seed4 = y;
}

// Generate next bytes (matching generate_d_cuda.cpp nextBytes exactly)
__device__ __forceinline__ void nextBytes(SecureRandomState* state, uint8_t* bytes, int bytesLen)
{
    if (bytesLen == 0) return;
    
    constexpr int32_t HASHBYTES_TO_USE = 20;
    constexpr int32_t extrabytes = 7;
    
    // Precompute lastWord once (matching generate_d_cuda.cpp bug - preserved for compatibility)
    const int lastWord = (state->seed[BYTES_OFFSET] == 0) ? 0 
                        : ((state->seed[BYTES_OFFSET] + extrabytes) >> 3 - 1);  // БАГ!
    
    if (state->firstCall)
    {
        state->seed[81] = 20;
        state->firstCall = 0;
    }
    
    int nextByteToReturn = 0;
    
    // Use remaining bytes from previous call
    if (state->nextBIndex < HASHBYTES_TO_USE)
    {
        int remaining = HASHBYTES_TO_USE - state->nextBIndex;
        int n = (remaining < bytesLen - nextByteToReturn) ? remaining : (bytesLen - nextByteToReturn);
        if (n > 0)
        {
            // For small sizes use direct assignments instead of memcpy
            if (n <= 8)
            {
                uint8_t* src = state->nextBytes + state->nextBIndex;
                uint8_t* dst = bytes + nextByteToReturn;
                for (int i = 0; i < n; i++)
                {
                    dst[i] = src[i];
                }
            }
            else
            {
                // For larger sizes, use loop (memcpy equivalent in CUDA)
                for (int i = 0; i < n; i++)
                {
                    bytes[nextByteToReturn + i] = state->nextBytes[state->nextBIndex + i];
                }
            }
            state->nextBIndex += n;
            nextByteToReturn += n;
        }
    }
    
    if (nextByteToReturn >= bytesLen) return;
    
    state->seed[3] = state->seed3;
    state->seed[4] = state->seed4;
    
    // Main loop to generate bytes (optimized, matching generate_d_cuda.cpp)
    uint32_t* seed = state->seed;
    uint64_t counter = state->counter;  // uint64_t as in generate_d_cuda.cpp
    
    while (nextByteToReturn < bytesLen)
    {
        // Insert counter into frame (using local variables)
        seed[lastWord] = static_cast<uint32_t>(counter >> 32);
        seed[lastWord + 1] = static_cast<uint32_t>(counter & 0xFFFFFFFF);
        seed[lastWord + 2] = END_FLAG;
        
        computeHash(seed);
        counter++;
        
        // Extract bytes from hash (big-endian as in Java) - unrolled loop for speed (matching generate_d_cuda.cpp)
        uint32_t* h = state->seed + HASH_OFFSET;
        uint8_t* nb = state->nextBytes;
        uint32_t k0 = h[0];
        uint32_t k1 = h[1];
        uint32_t k2 = h[2];
        uint32_t k3 = h[3];
        uint32_t k4 = h[4];
        nb[0] = static_cast<uint8_t>(k0 >> 24);
        nb[1] = static_cast<uint8_t>(k0 >> 16);
        nb[2] = static_cast<uint8_t>(k0 >> 8);
        nb[3] = static_cast<uint8_t>(k0);
        nb[4] = static_cast<uint8_t>(k1 >> 24);
        nb[5] = static_cast<uint8_t>(k1 >> 16);
        nb[6] = static_cast<uint8_t>(k1 >> 8);
        nb[7] = static_cast<uint8_t>(k1);
        nb[8] = static_cast<uint8_t>(k2 >> 24);
        nb[9] = static_cast<uint8_t>(k2 >> 16);
        nb[10] = static_cast<uint8_t>(k2 >> 8);
        nb[11] = static_cast<uint8_t>(k2);
        nb[12] = static_cast<uint8_t>(k3 >> 24);
        nb[13] = static_cast<uint8_t>(k3 >> 16);
        nb[14] = static_cast<uint8_t>(k3 >> 8);
        nb[15] = static_cast<uint8_t>(k3);
        nb[16] = static_cast<uint8_t>(k4 >> 24);
        nb[17] = static_cast<uint8_t>(k4 >> 16);
        nb[18] = static_cast<uint8_t>(k4 >> 8);
        nb[19] = static_cast<uint8_t>(k4);
        
        state->nextBIndex = 0;
        int bytesToCopy = (HASHBYTES_TO_USE < bytesLen - nextByteToReturn) 
                         ? HASHBYTES_TO_USE 
                         : bytesLen - nextByteToReturn;
        if (bytesToCopy > 0)
        {
            // For small sizes use direct assignments
            if (bytesToCopy <= 8)
            {
                uint8_t* src = state->nextBytes;
                uint8_t* dst = bytes + nextByteToReturn;
                for (int i = 0; i < bytesToCopy; i++)
                {
                    dst[i] = src[i];
                }
            }
            else
            {
                // For larger sizes, use loop (memcpy equivalent in CUDA)
                for (int i = 0; i < bytesToCopy; i++)
                {
                    bytes[nextByteToReturn + i] = state->nextBytes[i];
                }
            }
            nextByteToReturn += bytesToCopy;
            state->nextBIndex += bytesToCopy;
        }
        
        if (nextByteToReturn >= bytesLen)
        {
            break;
        }
    }
    
    // Save updated counter
    state->counter = counter;
}

// Legacy function for backward compatibility - now uses state
__device__ __forceinline__ void engineNextBytes(
    uint8_t* output,
    int outputSize,
    int64_t& counter,  // Keep int64_t for backward compatibility
    uint32_t seed3,
    uint32_t seed4)
{
    SecureRandomState state;
    initSecureRandomState(&state, seed3, seed4);
    state.counter = static_cast<uint64_t>(counter);
    nextBytes(&state, output, outputSize);
    counter = static_cast<int64_t>(state.counter);
}

// Generate next 32-bit random integer (matching generate_d_cuda.cpp nextInt)
__device__ __forceinline__ uint32_t nextInt(SecureRandomState* state)
{
    uint8_t bytes[4];
    nextBytes(state, bytes, 4);
    // Java next() collects: ret = (next[i] & 0xFF) | (ret << 8)
    // Result: next[0] << 24 | next[1] << 16 | next[2] << 8 | next[3]
    // Use direct operations for speed
    return (static_cast<uint32_t>(bytes[0]) << 24) |
           (static_cast<uint32_t>(bytes[1]) << 16) |
           (static_cast<uint32_t>(bytes[2]) << 8) |
           static_cast<uint32_t>(bytes[3]);
}

// Legacy function for backward compatibility
__device__ __forceinline__ uint32_t nextInt(int64_t& counter, uint32_t seed3, uint32_t seed4)
{
    SecureRandomState state;
    initSecureRandomState(&state, seed3, seed4);
    state.counter = counter;
    uint32_t result = nextInt(&state);
    counter = state.counter;
    return result;
}

// Generate private key using Android SHA1PRNG mycelium
// Exact implementation matching generate_d_cuda.cpp logic
// State is preserved between nextInt calls for the same x/y (matching generate_d_cuda.cpp)
__device__ __forceinline__ void generatePrivateKeyBase(const uint2& p, uint256_t& digest)
{
    constexpr int numBits = 256;
    constexpr int numberLength = (numBits + 31) >> 5; // 8 words for 256 bits
    
    // Initialize state once for this x/y (matching generate_d_cuda.cpp initSecureRandom)
    SecureRandomState state;
    initSecureRandomState(&state, p.x, p.y);
    
    uint32_t digits[numberLength];
    
    // Generate 8 words (256 bits) - matching generate_d_cuda.cpp main()
    // State is preserved between calls (matching generate_d_cuda.cpp)
    #pragma unroll
    for (int i = 0; i < numberLength; ++i)
    {
        digits[i] = nextInt(&state);
    }
    
    // Using only the necessary bits (matching generate_d_cuda.cpp)
    digits[numberLength - 1] >>= ((-numBits) & 31);
    
    // Convert to bytes (big-endian, as in Java setJavaRepresentation) - matching generate_d_cuda.cpp exactly
    uint8_t bytes[32];
    for (int i = 0; i < numberLength; i++)
    {
        int offset = (numberLength - 1 - i) * 4;
        bytes[offset] = static_cast<uint8_t>(digits[i] >> 24);
        bytes[offset + 1] = static_cast<uint8_t>(digits[i] >> 16);
        bytes[offset + 2] = static_cast<uint8_t>(digits[i] >> 8);
        bytes[offset + 3] = static_cast<uint8_t>(digits[i]);
    }
    
екн    // Handle negative numbers (matching generate_d_cuda.cpp)
    if (bytes[0] & 0x80)
    {
        uint8_t abs_bytes[32];
        int carry = 1;
        for (int i = 31; i >= 0; i--)
        {
            int sum = ((~bytes[i]) & 0xFF) + carry;
            abs_bytes[i] = static_cast<uint8_t>(sum);
            carry = sum >> 8;
        }
        // Copy abs_bytes back to bytes
        #pragma unroll
        for (int i = 0; i < 32; i++)
        {
            bytes[i] = abs_bytes[i];
        }
    }
    
    // Convert to uint256_t (little-endian words format used in the codebase)
    // bytes[0..31] is big-endian representation, convert to little-endian words
    #pragma unroll
    for (int i = 0; i < 8; ++i)
    {
        const int byte_idx = 7 - i; // Reverse word order for little-endian
        const int base = byte_idx << 2;
        digest.v[i] = (static_cast<uint32_t>(bytes[base]) << 24) |
                     (static_cast<uint32_t>(bytes[base + 1]) << 16) |
                     (static_cast<uint32_t>(bytes[base + 2]) << 8) |
                     static_cast<uint32_t>(bytes[base + 3]);
    }
}
