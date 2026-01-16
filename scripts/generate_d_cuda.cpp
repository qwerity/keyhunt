#include <cstdint>
#include <cstdio>
#include <cstring>
#include <algorithm>

// SHA-1 constants
constexpr uint32_t SHA1_K0_19 = 0x5A827999;
constexpr uint32_t SHA1_K20_39 = 0x6ED9EBA1;
constexpr uint32_t SHA1_K40_59 = 0x8F1BBCDC;
constexpr uint32_t SHA1_K60_79 = 0xCA62C1D6;

// SHA-1 initial hash values
constexpr uint32_t SHA1_H0 = 0x67452301;
constexpr uint32_t SHA1_H1 = 0xEFCDAB89;
constexpr uint32_t SHA1_H2 = 0x98BADCFE;
constexpr uint32_t SHA1_H3 = 0x10325476;
constexpr uint32_t SHA1_H4 = 0xC3D2E1F0;

// Algorithm constants
constexpr int32_t HASH_OFFSET = 82;
constexpr int32_t BYTES_OFFSET = 81;
constexpr int32_t EXTRAFRAME_OFFSET = 5;
constexpr uint32_t END_FLAG = 0x80000000;

// Simple uint2 structure (like CUDA uint2)
struct uint2 {
    uint32_t x;
    uint32_t y;
};

// Simple uint256_t structure
struct uint256_t {
    uint32_t v[8] = {0};
    
    bool operator==(const uint256_t& other) const {
        for (int i = 0; i < 8; i++) {
            if (v[i] != other.v[i]) return false;
        }
        return true;
    }
};

// Rotate left - optimized
inline uint32_t rotl_sha1(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

// SHA-1 round functions
inline uint32_t f_sha1_0_19(uint32_t b, uint32_t c, uint32_t d) {
    return (b & c) | ((~b) & d);
}

inline uint32_t f_sha1_20_39(uint32_t b, uint32_t c, uint32_t d) {
    return b ^ c ^ d;
}

inline uint32_t f_sha1_40_59(uint32_t b, uint32_t c, uint32_t d) {
    return (b & c) | (b & d) | (c & d);
}

inline uint32_t f_sha1_60_79(uint32_t b, uint32_t c, uint32_t d) {
    return b ^ c ^ d;
}

// Compute SHA-1 hash - optimized
inline void computeHash(uint32_t* arrW) {
    uint32_t a = arrW[HASH_OFFSET];
    uint32_t b = arrW[HASH_OFFSET + 1];
    uint32_t c = arrW[HASH_OFFSET + 2];
    uint32_t d = arrW[HASH_OFFSET + 3];
    uint32_t e = arrW[HASH_OFFSET + 4];
    
    // Expand message schedule (words 16-79) - optimized loop
    uint32_t* w = arrW;
    for (int t = 16; t < 80; ++t) {
        uint32_t temp = w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16];
        w[t] = (temp << 1) | (temp >> 31);
    }
    
    // Round 1: 0-19
    for (int t = 0; t < 20; ++t) {
        uint32_t temp = rotl_sha1(a, 5) + f_sha1_0_19(b, c, d) + e + w[t] + SHA1_K0_19;
        e = d;
        d = c;
        c = rotl_sha1(b, 30);
        b = a;
        a = temp;
    }
    
    // Round 2: 20-39
    for (int t = 20; t < 40; ++t) {
        uint32_t temp = rotl_sha1(a, 5) + f_sha1_20_39(b, c, d) + e + w[t] + SHA1_K20_39;
        e = d;
        d = c;
        c = rotl_sha1(b, 30);
        b = a;
        a = temp;
    }
    
    // Round 3: 40-59
    for (int t = 40; t < 60; ++t) {
        uint32_t temp = rotl_sha1(a, 5) + f_sha1_40_59(b, c, d) + e + w[t] + SHA1_K40_59;
        e = d;
        d = c;
        c = rotl_sha1(b, 30);
        b = a;
        a = temp;
    }
    
    // Round 4: 60-79
    for (int t = 60; t < 80; ++t) {
        uint32_t temp = rotl_sha1(a, 5) + f_sha1_60_79(b, c, d) + e + w[t] + SHA1_K60_79;
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

// Generate next bytes for PVK generation - optimized
inline void engineNextBytes(
    uint8_t* output,
    size_t outputSize,
    int64_t& counter,
    uint32_t seed3,
    uint32_t seed4)
{
    constexpr int32_t SEED_SIZE = HASH_OFFSET + EXTRAFRAME_OFFSET;
    uint32_t seed[SEED_SIZE] = {0};
    
    // Initialize hash state (only what's needed)
    seed[HASH_OFFSET] = SHA1_H0;
    seed[HASH_OFFSET + 1] = SHA1_H1;
    seed[HASH_OFFSET + 2] = SHA1_H2;
    seed[HASH_OFFSET + 3] = SHA1_H3;
    seed[HASH_OFFSET + 4] = SHA1_H4;
    seed[3] = seed3;
    seed[4] = seed4;
    
    size_t offset = 0;
    while (offset < outputSize) {
        uint8_t temp[32];
        
        // Generate 32 bytes (2 iterations)
        for (int iter = 0; iter < 2; ++iter) {
            seed[0] = static_cast<uint32_t>(counter >> 32);
            seed[1] = static_cast<uint32_t>(counter & 0xFFFFFFFF);
            seed[2] = END_FLAG;
            
            // Compute hash
            computeHash(seed);
            ++counter;
            
            // Extract bytes from hash state - optimized
            int wordsToWrite = (iter == 0) ? EXTRAFRAME_OFFSET : 3;
            int baseOffset = iter * 20;
            for (int i = 0; i < wordsToWrite; ++i) {
                uint32_t k = seed[HASH_OFFSET + i];
                int byteOffset = baseOffset + (i << 2);
                temp[byteOffset] = static_cast<uint8_t>(k >> 24);
                temp[byteOffset + 1] = static_cast<uint8_t>(k >> 16);
                temp[byteOffset + 2] = static_cast<uint8_t>(k >> 8);
                temp[byteOffset + 3] = static_cast<uint8_t>(k);
            }
        }
        
        // Copy to output - optimized
        size_t toCopy = (outputSize - offset < 32) ? (outputSize - offset) : 32;
        std::memcpy(output + offset, temp, toCopy);
        offset += toCopy;
    }
}

// Generate next random integer with specified bit count - optimized
inline uint32_t next(int numBits, int64_t& counter, uint32_t seed3, uint32_t seed4) {
    int bits = (numBits < 0) ? 0 : (numBits > 32 ? 32 : numBits);
    int bytes = (bits + 7) >> 3;
    
    uint8_t nextBytes[4] = {0};
    engineNextBytes(nextBytes, bytes, counter, seed3, seed4);
    
    uint32_t ret = 0;
    for (int i = 0; i < bytes; ++i) {
        ret = (ret << 8) | nextBytes[i];
    }
    
    return ret >> ((bytes << 3) - bits);
}

// Generate next 32-bit random integer - optimized
inline uint32_t nextInt(int64_t& counter, uint32_t seed3, uint32_t seed4) {
    uint8_t nextBytes[4];
    engineNextBytes(nextBytes, 4, counter, seed3, seed4);
    return (static_cast<uint32_t>(nextBytes[0]) << 24) |
           (static_cast<uint32_t>(nextBytes[1]) << 16) |
           (static_cast<uint32_t>(nextBytes[2]) << 8) |
           static_cast<uint32_t>(nextBytes[3]);
}

// Generate a random 256-bit private key
void generatePrivateKeyBase(
    const uint2& p,
    uint256_t& digest)
{
    constexpr int numBits = 256;
    constexpr int numberLength = (numBits + 31) >> 5; // 8 words for 256 bits
    
    uint32_t digits[numberLength];
    int64_t counter = 0;
    
    // Generate 8 words (256 bits) - optimized
    for (int i = 0; i < numberLength; ++i) {
        digits[i] = nextInt(counter, p.x, p.y);
    }
    
    // Right-shift the most significant word to align bits
    digits[numberLength - 1] >>= ((-numBits) & 31);
    
    // Remove leading zeros - optimized
    int actualLength = numberLength;
    while (actualLength > 0 && digits[actualLength - 1] == 0) {
        --actualLength;
    }
    
    // Convert to uint256_t (little-endian format) - optimized
    uint8_t outputBytes[32];
    if (actualLength > 0) {
        // Pack digits into bytes (big-endian) - optimized
        for (int i = actualLength - 1; i >= 0; --i) {
            int byteOffset = (actualLength - 1 - i) << 2;
            uint32_t d = digits[i];
            outputBytes[byteOffset] = static_cast<uint8_t>(d >> 24);
            outputBytes[byteOffset + 1] = static_cast<uint8_t>(d >> 16);
            outputBytes[byteOffset + 2] = static_cast<uint8_t>(d >> 8);
            outputBytes[byteOffset + 3] = static_cast<uint8_t>(d);
        }
        
        // Convert to uint256_t (little-endian words, big-endian bytes within words) - optimized
        for (int i = 0; i < 8; ++i) {
            const int byte_idx = 7 - i; // Reverse word order
            const int base = byte_idx << 2;
            digest.v[i] = (static_cast<uint32_t>(outputBytes[base]) << 24) |
                         (static_cast<uint32_t>(outputBytes[base + 1]) << 16) |
                         (static_cast<uint32_t>(outputBytes[base + 2]) << 8) |
                         static_cast<uint32_t>(outputBytes[base + 3]);
        }
    } else {
        // Zero key - optimized with memset
        std::memset(digest.v, 0, sizeof(digest.v));
    }
}

// Print uint256_t in hex format - optimized
void printUint256(const uint256_t& value) {
    for (int i = 7; i >= 0; --i) {
        printf("%08x", value.v[i]);
    }
    printf("\n");
}

int main() {
    uint2 p;
    p.x = 1;
    p.y = 1;
    
    uint256_t privateKey;
    generatePrivateKeyBase(p, privateKey);
    
    printf("Generated private key (seed3=%u, seed4=%u):\n", p.x, p.y);
    printUint256(privateKey);
    
    return 0;
}
