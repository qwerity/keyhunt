#pragma once

#include <cstdint>
#include <string>

/*################################################################################################################################################################################*/
#define cudaCheckError(err) \
    do \
    { \
        if (err != cudaSuccess) \
        { \
            const auto errStr = cudaGetErrorString(err); \
            fprintf(stderr, "[%d] %s at {%s:%d}\n", err, errStr, __FILE__, __LINE__); \
            fflush(stderr); \
            fflush(stdout); \
            exit(13); \
        } \
    } \
    while(0);

/*################################################################################################################################################################################*/
constexpr uint32_t MB{1024u * 1024u};

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
struct StatusInfo
{
    double pointsPerSecond{};
    double seconds{};
    uint64_t total{};
    uint64_t totalTime{};

    int device{};
    std::string deviceName;
    uint64_t freeDeviceMemory{};
    uint64_t totalDeviceMemory{};

    uint32_t iteration{};
    uint32_t totalIterations{};
};

/*################################################################################################################################################################################*/
struct Hash160SearchResult
{
    int cudaDeviceId{0};

    int thread{0};
    int block{0};
    int idx{0};

    uint32_t iteration{0};

    uint32_t privateXPart{0};
    uint32_t privateYPart{0};

    bool compressed{false};
    uint32_t privateKey[8]{};
    uint32_t publicXKey[8]{};
    uint32_t publicYKey[8]{};
    uint32_t digest[5]{};
};

/*################################################################################################################################################################################*/