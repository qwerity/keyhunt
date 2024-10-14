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
    std::string host;
    std::string port;
    std::string authorisationHeader;
};

struct HunterConfig
{
    // Cuda key generation params
    uint32_t pointsPerThread{128};

    // Private Keys generation
    uint32_t keysNumberToGenerate{0};

    // Input data
    std::vector<std::string> ripemd160TargetsFilePaths;

    bool forcePrivateXPart{false};
    uint32_t privateXPart{1};
    uint32_t privateYOffset{0};

    uint32_t publicKeyCompressionTypeToCheck{2};

    uint32_t statusCallbackPeriodMs{1000};
};

class Config
{
public:
    explicit Config(const std::string& jsonConfigFilepath);
    ~Config();

    Config(const Config& other) = delete;
    Config& operator=(const Config& other) = delete;

    [[nodiscard]] bool setPrivateKeyXPart(uint32_t xPart) const;
    [[nodiscard]] bool setCalculationIteration(uint32_t iteration) const;
    [[nodiscard]] bool isLoaded() const;
    [[nodiscard]] bool devMode() const;
    [[nodiscard]] bool isPrivateXPartRandom() const;
    void setPrivateXPartRandom() const;

    std::string jsonStr();

    HunterConfig& hunter();
    ServerConfig& server();
    LogConfig& log();

    // hardcoded
    const std::string aesKey{"CB4BBEDF03DA589798E997D86027DE755F33D226AEF90F395539DA4C08EF65B3"};
    const std::string aesIV{"7E1AAE9BAE242FC510D5619B"};

private:
    struct Impl;
    std::unique_ptr<Impl> mImpl;
};
