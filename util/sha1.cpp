#include "crypto_util.h"
#include <cstring>
#include <vector>

namespace
{
    // Constants - these need to match the Java implementation
    // Based on typical Android KeyStore structure:
    // In Java: seed[HASH_OFFSET] = H0, seed[BYTES_OFFSET] = 0, seed[3] = x, seed[4] = y
    // If HASH_OFFSET = 0, then seed[0-4] = H0-H4, seed[3] = x (overwrites H3), seed[4] = y (overwrites H4)
    // But x and y are set AFTER hash initialization, so they might be used differently
    // Let's try HASH_OFFSET = 0 first
    constexpr int32_t HASH_OFFSET = 82;      // Hash state starts at index 0
    constexpr int32_t BYTES_OFFSET = 81;     // Byte count at index 5
    constexpr int32_t EXTRAFRAME_OFFSET = 5; // Extra frame size (5 words = 20 bytes)
    
    // SHA1 initial hash values
    constexpr uint32_t H0 = 0x67452301;
    constexpr uint32_t H1 = 0xEFCDAB89;
    constexpr uint32_t H2 = 0x98BADCFE;
    constexpr uint32_t H3 = 0x10325476;
    constexpr uint32_t H4 = 0xC3D2E1F0;
    
    // End flag for padding
    constexpr uint32_t END_FLAG = 0x80000000;
    
    // SHA1 helper functions
    static uint32_t rotl_sha1(uint32_t x, int n)
    {
        return (x << n) | (x >> (32 - n));
    }
    
    static uint32_t f_sha1_0_19(uint32_t b, uint32_t c, uint32_t d)
    {
        return (b & c) | (~b & d);
    }
    
    static uint32_t f_sha1_20_39(uint32_t b, uint32_t c, uint32_t d)
    {
        return b ^ c ^ d;
    }
    
    static uint32_t f_sha1_40_59(uint32_t b, uint32_t c, uint32_t d)
    {
        return (b & c) | (b & d) | (c & d);
    }
    
    static uint32_t f_sha1_60_79(uint32_t b, uint32_t c, uint32_t d)
    {
        return b ^ c ^ d;
    }
    
    // SHA1 transform for a single 512-bit block
    static void sha1Transform(uint32_t* h, const uint32_t* w)
    {
        constexpr uint32_t K0_19 = 0x5A827999;
        constexpr uint32_t K20_39 = 0x6ED9EBA1;
        constexpr uint32_t K40_59 = 0x8F1BBCDC;
        constexpr uint32_t K60_79 = 0xCA62C1D6;
        
        uint32_t a = h[0];
        uint32_t b = h[1];
        uint32_t c = h[2];
        uint32_t d = h[3];
        uint32_t e = h[4];
        
        uint32_t w_ext[80];
        
        // Copy first 16 words (convert from big-endian bytes to words)
        // w[0-15] are already in correct format (big-endian 32-bit words)
        for (int i = 0; i < 16; i++)
        {
            w_ext[i] = w[i];
        }
        
        // Expand to 80 words
        for (int i = 16; i < 80; i++)
        {
            w_ext[i] = rotl_sha1(w_ext[i-3] ^ w_ext[i-8] ^ w_ext[i-14] ^ w_ext[i-16], 1);
        }
        
        // Main loop
        for (int i = 0; i < 20; i++)
        {
            uint32_t temp = rotl_sha1(a, 5) + f_sha1_0_19(b, c, d) + e + K0_19 + w_ext[i];
            e = d;
            d = c;
            c = rotl_sha1(b, 30);
            b = a;
            a = temp;
        }
        
        for (int i = 20; i < 40; i++)
        {
            uint32_t temp = rotl_sha1(a, 5) + f_sha1_20_39(b, c, d) + e + K20_39 + w_ext[i];
            e = d;
            d = c;
            c = rotl_sha1(b, 30);
            b = a;
            a = temp;
        }
        
        for (int i = 40; i < 60; i++)
        {
            uint32_t temp = rotl_sha1(a, 5) + f_sha1_40_59(b, c, d) + e + K40_59 + w_ext[i];
            e = d;
            d = c;
            c = rotl_sha1(b, 30);
            b = a;
            a = temp;
        }
        
        for (int i = 60; i < 80; i++)
        {
            uint32_t temp = rotl_sha1(a, 5) + f_sha1_60_79(b, c, d) + e + K60_79 + w_ext[i];
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
    
    // SHA1 implementation that works with seed array structure
    // Processes seed[0-15] as message (512 bits) and updates hash state in seed[HASH_OFFSET to HASH_OFFSET+4]
    // This matches the working implementation exactly
    void computeHash(uint32_t* arrW)
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
}

void crypto::generatePrivateKey(int32_t x, int32_t y, uint8_t* output)
{
    std::vector<uint32_t> seed(HASH_OFFSET + EXTRAFRAME_OFFSET, 0);
    seed[HASH_OFFSET] = H0;
    seed[HASH_OFFSET + 1] = H1;
    seed[HASH_OFFSET + 2] = H2;
    seed[HASH_OFFSET + 3] = H3;
    seed[HASH_OFFSET + 4] = H4;
    seed[BYTES_OFFSET] = 0;
    seed[3] = static_cast<uint32_t>(x);
    seed[4] = static_cast<uint32_t>(y);
    
    uint64_t counter = 0;
    
    for (int iter = 0; iter < 2; iter++)
    {
        seed[0] = static_cast<uint32_t>(counter >> 32);
        seed[1] = static_cast<uint32_t>(counter & 0xFFFFFFFF);
        seed[2] = END_FLAG;
        computeHash(seed.data());
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
}
