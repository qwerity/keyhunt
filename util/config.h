#pragma once
#include <cstdint>
#include <string>
#include <vector>

struct Config
{
    Config();
    void load(const std::string& configJsonFileName = "config.json");
    void print();

    // GPU device params
    int cudaDeviceId{0};
    std::string cudaDeviceName;

    // Cuda key generation params
    uint32_t pointsPerThread{128};

    // Private Keys generation
    uint32_t keysNumberToGenerate{0};

    // Input data
    std::vector<std::string> ripemd160TargetsFilePaths;

    int privateXPart{1};

    uint32_t publicKeyCompressionTypeToCheck{2};

    uint32_t statusCallbackPeriodMs{1000};

    bool selftest{false};
};
