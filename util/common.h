#pragma once

#include <cstdint>
#include <string>

/*################################################################################################################################################################################*/
constexpr uint32_t MB{1024u * 1024u};

/*################################################################################################################################################################################*/
struct StatusInfo
{
    double dataPerSecond{};   // current MKey/s (last period)
    double minDataPerSecond{}; // min MKey/s seen (per GPU)
    double seconds{};
    uint64_t total{};
    uint64_t totalTime{};

    int device{};
    std::string deviceName;
    uint64_t freeDeviceMemory{};
    uint64_t totalDeviceMemory{};

    uint32_t iteration{};
    uint32_t totalIterations{};
    uint32_t derivationsPerIteration{};
};

/*################################################################################################################################################################################*/