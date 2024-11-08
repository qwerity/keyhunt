#pragma once

#include <cuda_runtime.h>
#include <cstdio>

/*################################################################################################################################################################################*/
#define cudaCheckError(err) \
    do \
    { \
        if ((err) != cudaSuccess) \
        { \
            const auto errStr = cudaGetErrorString(err); \
            fprintf(stderr, "[%d] %s at {%s:%d}\n", err, errStr, __FILE__, __LINE__); \
            fflush(stderr); \
            fflush(stdout); \
            exit(13); \
        } \
    } \
    while(0)

/*################################################################################################################################################################################*/
// Big-Endian <-> Little-Endian
// Macro to swap bytes of a uint32_t value (Big-Endian <-> Little-Endian)
#define SWAP32(x) ( \
    (((x) & 0x000000FF) << 24) | \
    (((x) & 0x0000FF00) << 8)  | \
    (((x) & 0x00FF0000) >> 8)  | \
    (((x) & 0xFF000000) >> 24) \
)

// Macro to swap bytes of a uint64_t value (Big-Endian <-> Little-Endian)
#define SWAP64(x) ( \
    (((x) & 0x00000000000000FFUL) << 56) | \
    (((x) & 0x000000000000FF00UL) << 40) | \
    (((x) & 0x0000000000FF0000UL) << 24) | \
    (((x) & 0x00000000FF000000UL) << 8)  | \
    (((x) & 0x000000FF00000000UL) >> 8)  | \
    (((x) & 0x0000FF0000000000UL) >> 24) | \
    (((x) & 0x00FF000000000000UL) >> 40) | \
    (((x) & 0xFF00000000000000UL) >> 56) \
)

// Macro to swap bytes of a 160-bit hash (array of 5 uint32_t values)
#define SWAP32_HASH160(src, dest) { \
    (dest)[0] = SWAP32((src)[0]); \
    (dest)[1] = SWAP32((src)[1]); \
    (dest)[2] = SWAP32((src)[2]); \
    (dest)[3] = SWAP32((src)[3]); \
    (dest)[4] = SWAP32((src)[4]); \
}

/*################################################################################################################################################################################*/
namespace PointCompressionType
{
    enum Value
    {
        COMPRESSED = 0,
        UNCOMPRESSED = 1,
        BOTH = 2
    };
}

/*################################################################################################################################################################################*/
struct Hash160SearchResult
{
    int cudaDeviceId{0};

    uint32_t thread{0};
    uint32_t block{0};
    uint32_t idx{0};

    uint32_t iteration{0};

    uint32_t privateXPart{0};
    uint32_t privateYPart{0};

    bool compressed{false};
    uint32_t privateKey[8]{};
    uint32_t digest[5]{};
};

/*################################################################################################################################################################################*/
