#pragma once
#include <cstdint>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

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
    std::string port;
    std::string authorisationHeader;
};

struct HunterConfig
{
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
    int privateYOffset{0};

    uint32_t publicKeyCompressionTypeToCheck{2};

    uint32_t statusCallbackPeriodMs{1000};
};

class Config
{
public:
    explicit Config(const std::string& jsonConfigFilepath);
    ~Config();

    bool setPrivateKeyXPart(uint32_t xPart) const;
    bool calculationIteration(uint32_t iteration) const;
    [[nodiscard]] bool isLoaded() const;

    HunterConfig&& hunter();
    ServerConfig&& server();
    LogConfig&& log();

private:
    struct Impl;
    std::unique_ptr<Impl> mImpl;
};
