#pragma once
#include <cstdint>
#include <string>
#include <vector>

struct LogConfig
{
    enum class LogType
    {
        file,
        console
    };

    LogType type{LogType::console};
    std::string logFilePath;
    uint32_t severity{0};
};

struct ServerConfig
{
    std::string url;
    std::string apiKey;
};

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

    [[maybe_unused]] bool selftest{false};

    ServerConfig server;
    LogConfig log;
};
