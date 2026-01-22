#pragma once

#include "cuda/hd_wallet_defines.h"

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
    // Private Keys generation
    uint32_t keysNumberToGenerate{0};

    // Input data
    std::vector<std::string> ripemd160TargetsFilePaths;

    bool forcePrivateXPart{false};
    uint32_t privateXPart{1};
    uint32_t privateYOffset{0};

    // Specific X values mode - if array is not empty, will check only these X values
    std::vector<uint32_t> specificXValues;
};

struct HDWalletConfig
{
    HDWalletGenerationMode generationMode{HDWalletGenerationMode::MnemonicMasterKey};

    std::string mnemonicMasterKeyProvider{"tcp://localhost:5555"};

    bool forceMnemonic{false};
    std::string mnemonic;
    uint32_t mnemonicsToGenerate{1000};

    std::vector<std::string> derivationPathsPatters{
        "m/addr",
        "m/acc/addr",
        "m/acc/0/addr",
        "m/acc'/addr",
        "m/acc'/0/addr",
        "m/44'/acc'/0/addr",
        "m/44'/0'/acc'/0/addr",
        "m/49'/0'/acc'/0/addr",
        "m/84'/0'/acc'/0/addr",
        "m/86'/0'/acc'/0/addr"
    };
    uint32_t accountsToGenerate{1};
    uint32_t addressesToGenerate{1};
};

class Config
{
public:
    explicit Config(const std::string& jsonConfigFilepath);
    ~Config();

    Config(const Config& other) = delete;
    Config& operator=(const Config& other) = delete;

    [[nodiscard]] bool isLoaded() const;
    [[nodiscard]] bool devMode() const;
    void setDevMode(bool enable) const;
    [[nodiscard]] bool dataGenerationIsRandom() const;
    void setRandomGeneration(bool enable) const;

    [[nodiscard]] std::string jsonStr() const;

    [[nodiscard]] HunterConfig& hunter() const;
    [[nodiscard]] ServerConfig& server() const;
    [[nodiscard]] LogConfig& log() const;
    [[nodiscard]] HDWalletConfig& hdWallet() const;

    [[nodiscard]] uint32_t statusCallbackPeriodMs() const;
    [[nodiscard]] uint32_t publicKeyCompressionTypeToCheck() const;
    [[nodiscard]] uint32_t pointsPerThread() const;
    [[nodiscard]] uint32_t blockSize() const;
    [[nodiscard]] uint32_t gridSize() const;

    // hardcoded
    static constexpr const char* aesKey{"CB4BBEDF03DA589798E997D86027DE755F33D226AEF90F395539DA4C08EF65B3"};
    static constexpr const char* aesIV{"7E1AAE9BAE242FC510D5619B"};

private:
    struct Impl;
    std::unique_ptr<Impl> mImpl;
};
