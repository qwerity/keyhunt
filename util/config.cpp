#include "config.h"
#include "utils.h"

#include <filesystem>
#include <fstream>

#include <boost/algorithm/string/join.hpp>
#include <boost/log/trivial.hpp>

struct Config::Impl
{
    nlohmann::json configJson;
    std::string jsonConfigFilepath;

    bool loaded{false};
    bool dataGenerationIsRandom{false};
    bool devMode{false};

    HunterConfig hunter;
    ServerConfig server;
    LogConfig log;
    HDWalletConfig hdWallet;

    uint32_t statusCallbackPeriodMs{1000};
    uint32_t publicKeyCompressionTypeToCheck{2};
    uint32_t pointsPerThread{128};
    uint32_t blockSize{0}; // if 0 - will be calculated on fly
    uint32_t gridSize{0}; // if 0 - will be calculated on fly

    explicit Impl(std::string configFilepath) : jsonConfigFilepath{std::move(configFilepath)}
    {
        load(jsonConfigFilepath);
    }

    void loadLogConfig()
    {
        if (!configJson.contains("log") || !configJson["log"].is_object())
        {
            return;
        }

        const auto& logConfig = configJson["log"];

        if (logConfig.contains("type") && logConfig["type"].is_string())
        {
            log.type = (logConfig["type"] == "file") ? LogConfig::LogType::file : LogConfig::LogType::console;
        }

        if (log.type == LogConfig::LogType::file)
        {
            const std::string binaryDir = std::filesystem::current_path().string();
            const std::string logDir = binaryDir + "/logs/";

            std::error_code ec;
            std::filesystem::create_directory(logDir, binaryDir, ec);

            log.logFilePath = std::format("{}keyhunter_{}_{}", logDir, utils::getTimestampStr(), "%N.log");
            fprintf(stderr, "Logging to file.. %s\n", log.logFilePath.c_str());
        }

        if (logConfig.contains("severity") && logConfig["severity"].is_number())
        {
            uint32_t logSeverity = logConfig["severity"];
            if (logSeverity > boost::log::trivial::fatal)
            {
                logSeverity = boost::log::trivial::fatal;
            }
            log.severity = logSeverity;
        }
    }

    void loadServerConfig()
    {
        if (!configJson.contains("server") || !configJson["server"].is_object())
        {
            return;
        }

        const auto& serverConfig = configJson["server"];

        if (serverConfig.contains("url") && serverConfig["url"].is_string() && !serverConfig["url"].empty())
        {
            server.host = serverConfig["url"];
        }

        if (serverConfig.contains("authorisationHeader") && serverConfig["authorisationHeader"].is_string() && !serverConfig["authorisationHeader"].empty())
        {
            server.authorisationHeader = serverConfig["authorisationHeader"];
        }

        if (serverConfig.contains("port"))
        {
            if (serverConfig["port"].is_string() && !serverConfig["port"].empty())
            {
                server.port = serverConfig["port"];
            }
            else if (serverConfig["port"].is_number())
            {
                server.port = std::to_string(serverConfig["port"].get<uint32_t>());
            }
        }
    }

    void loadHDWalletConfig()
    {
        if (!configJson.contains("hd_wallet") || !configJson["hd_wallet"].is_object())
        {
            return;
        }

        const auto& hdWalletConfig = configJson["hd_wallet"];

        if (hdWalletConfig.contains("generationMode") && hdWalletConfig["generationMode"].is_number_unsigned())
        {
            const auto generationMode = static_cast<HDWalletGenerationMode>(hdWalletConfig["generationMode"].get<uint32_t>());
            if (generationMode < HDWalletGenerationMode::MaxMode)
            {
                hdWallet.generationMode = generationMode;
            }
        }

        if (hdWalletConfig.contains("forceMnemonic") && hdWalletConfig["forceMnemonic"].is_boolean() && hdWalletConfig["forceMnemonic"] == true)
        {
            hdWallet.forceMnemonic = true;
            if (hdWalletConfig.contains("mnemonic") && hdWalletConfig["mnemonic"].is_string() && !hdWalletConfig["mnemonic"].empty())
            {
                hdWallet.mnemonic = hdWalletConfig["mnemonic"].get<std::string>();
                hdWallet.mnemonic.resize(128);
            }
        }

        if (hdWalletConfig.contains("mnemonicMasterKeyProvider") && hdWalletConfig["mnemonicMasterKeyProvider"].is_string() && !hdWalletConfig["mnemonicMasterKeyProvider"].empty())
        {
            hdWallet.mnemonicMasterKeyProvider = hdWalletConfig["mnemonicMasterKeyProvider"].get<std::string>();
        }

        if (hdWalletConfig.contains("mnemonicsToGenerate") && hdWalletConfig["mnemonicsToGenerate"].is_number_unsigned())
        {
            hdWallet.mnemonicsToGenerate = hdWalletConfig["mnemonicsToGenerate"].get<uint32_t>();
        }

        // Parse path patterns
        if (hdWalletConfig.contains("path_patters") && hdWalletConfig["path_patters"].is_array() && !hdWalletConfig["path_patters"].empty())
        {
            std::vector<std::string> patterns;
            for (const auto& pattern : hdWalletConfig["path_patters"])
            {
                if (pattern.is_string() && !pattern.empty())
                {
                    const auto& pathStr = pattern.get<std::string>();
                    patterns.push_back(pathStr);
                }
            }
            if (!patterns.empty())
            {
                hdWallet.derivationPathsPatters = patterns;
            }
            else
            {
                BOOST_LOG_TRIVIAL(warning) << "Invalid configuration: hd_wallet.path_patters using default patters";
            }
        }
        else
        {
            BOOST_LOG_TRIVIAL(warning) << "Using default 'hd_wallet.path_patters' value: " << boost::algorithm::join(hdWallet.derivationPathsPatters, ",");
        }

        if (hdWalletConfig.contains("accounts_to_generate") && hdWalletConfig["accounts_to_generate"].is_number_unsigned())
        {
            const auto accounts = hdWalletConfig["accounts_to_generate"].get<uint32_t>();
            if (accounts > 0)
            {
                hdWallet.accountsToGenerate = accounts;
            }
            else
            {
                BOOST_LOG_TRIVIAL(warning) << "Invalid configuration: hd_wallet.accounts_to_generate should be non 0 value";
            }
        }
        else
        {
            BOOST_LOG_TRIVIAL(warning) << "Using default 'hd_wallet.accounts_to_generate' value: " << hdWallet.accountsToGenerate;
        }

        if (hdWalletConfig.contains("addresses_to_generate") && hdWalletConfig["addresses_to_generate"].is_number_unsigned())
        {
            const auto addressesToGenerate = hdWalletConfig["addresses_to_generate"].get<uint32_t>();
            if (addressesToGenerate > 0)
            {
                hdWallet.addressesToGenerate = addressesToGenerate;
            }
            else
            {
                BOOST_LOG_TRIVIAL(warning) << "Invalid configuration: hd_wallet.addresses_to_generate should be non 0 value";
            }
        }
        else
        {
            BOOST_LOG_TRIVIAL(warning) << "Using default 'hd_wallet.addresses_to_generate' value: " << hdWallet.addressesToGenerate;
        }
    }

    void load(const std::string &configFilepath)
    {
        loaded = false;

        if (!std::filesystem::exists(configFilepath))
        {
            BOOST_LOG_TRIVIAL(error) << "Config file config.json is not present in binary directory, using default values";
            return;
        }

        std::ifstream configFile(configFilepath);
        utils::ScopeOutRunner outRunner([&configFile](){ configFile.close(); });

        try
        {
            // Attempt to parse the JSON file
            configFile >> configJson;
        }
        catch (const nlohmann::json::parse_error& e)
        {
            BOOST_LOG_TRIVIAL(error) << "JSON parsing error: " << e.what();
            return;
        }

        // Validate that "hash160_targets" is an array and has at least one element
        if (!configJson.contains("hash160_targets") || !configJson["hash160_targets"].is_array() || configJson["hash160_targets"].empty())
        {
            BOOST_LOG_TRIVIAL(warning) << "Targets are not set";
        }
        else
        {
            for (const auto &target: configJson["hash160_targets"])
            {
                if (!target.is_string())
                {
                    BOOST_LOG_TRIVIAL(warning) << "Invalid configuration: each target must be a string (file path), ignored targets list: " << target;
                }
                hunter.ripemd160TargetsFilePaths.push_back(target);
            }
        }

        if (configJson.contains("pointsPerThread") && configJson["pointsPerThread"].is_number_unsigned())
        {
            pointsPerThread = configJson["pointsPerThread"].get<uint32_t>();
        }
        else
        {
            BOOST_LOG_TRIVIAL(warning) << "using default 'pointsPerThread' value: " << pointsPerThread;
        }

        if (configJson.contains("blockSize") && configJson["blockSize"].is_number_unsigned())
        {
            blockSize = configJson["blockSize"].get<uint32_t>();
        }

        if (configJson.contains("gridSize") && configJson["gridSize"].is_number_unsigned())
        {
            gridSize = configJson["gridSize"].get<uint32_t>();
        }

        if (configJson.contains("keysNumberToGenerate") && configJson["keysNumberToGenerate"].is_number_unsigned())
        {
            hunter.keysNumberToGenerate = configJson["keysNumberToGenerate"].get<uint32_t>();
        }
        else
        {
            BOOST_LOG_TRIVIAL(warning) << "Using default 'keysNumberToGenerate' value: " << hunter.keysNumberToGenerate;
        }

        if (configJson.contains("forcePrivateXPart") && configJson["forcePrivateXPart"].is_boolean() && configJson["forcePrivateXPart"] == true)
        {
            hunter.forcePrivateXPart = true;
            // Support both "privateXPart" and "privateX" for backward compatibility
            if (configJson.contains("privateXPart") && configJson["privateXPart"].is_number_unsigned())
            {
                hunter.privateXPart = configJson["privateXPart"].get<uint32_t>();
            }
            else if (configJson.contains("privateX") && configJson["privateX"].is_number_unsigned())
            {
                hunter.privateXPart = configJson["privateX"].get<uint32_t>();
            }
        }

        if (configJson.contains("privateYOffset") && configJson["privateYOffset"].is_number_unsigned())
        {
            hunter.privateYOffset = configJson["privateYOffset"].get<uint32_t>();
        }

        if (configJson.contains("publicKeyCompressionTypeToCheck") && configJson["publicKeyCompressionTypeToCheck"].is_number_unsigned())
        {
            if (const uint32_t compressionType = configJson["publicKeyCompressionTypeToCheck"].get<uint32_t>(); compressionType <= 2)
            {
                publicKeyCompressionTypeToCheck = compressionType;
            }
            else
            {
                BOOST_LOG_TRIVIAL(warning) << "Invalid configuration: 'publicKeyCompressionTypeToCheck' must be 0 (UNCOMPRESSED), 1 (COMPRESSED), or 2 (BOTH), using default value: " << publicKeyCompressionTypeToCheck;
            }
        }
        else
        {
            BOOST_LOG_TRIVIAL(warning) << "Using default 'publicKeyCompressionTypeToCheck' value: " << publicKeyCompressionTypeToCheck;
        }

        if (configJson.contains("statusCallbackPeriodMs") && configJson["statusCallbackPeriodMs"].is_number_unsigned())
        {
            statusCallbackPeriodMs = configJson["statusCallbackPeriodMs"].get<uint32_t>();
        }
        else
        {
            BOOST_LOG_TRIVIAL(warning) << "Using default 'statusCallbackPeriodMs' value: " << statusCallbackPeriodMs;
        }

        loadLogConfig();
        loadServerConfig();
        loadHDWalletConfig();

        loaded = true;
    }

    bool save()
    {
        // Open the file for writing (this will overwrite the file)
        std::ofstream outFile(jsonConfigFilepath);
        utils::ScopeOutRunner outRunner([&outFile](){ outFile.close(); });

        if (!outFile.is_open())
        {
            BOOST_LOG_TRIVIAL(error) << "Error: Could not open file for writing: " << jsonConfigFilepath;
            return false;
        }

        // Write the modified JSON to the file
        outFile << configJson.dump(2);

        //BOOST_LOG_TRIVIAL(trace) << std::format("{} modified and saved to file successfully.", jsonConfigFilepath );
        return true;
    }

    template <typename T>
    bool setValue(const std::string& key, T value)
    {
        configJson[key] = value;

        return save();
    }
};

Config::Config(const std::string& configFilepath) : mImpl(std::make_unique<Impl>(configFilepath)) {}
Config::~Config() = default;

bool Config::isLoaded() const
{
    return mImpl->loaded;
}

bool Config::devMode() const
{
    return mImpl->devMode;
}

void Config::setDevMode(const bool enable) const
{
    mImpl->devMode = enable;
}

bool Config::dataGenerationIsRandom() const
{
    return mImpl->dataGenerationIsRandom;
}

void Config::setRandomGeneration(const bool enable) const
{
    mImpl->dataGenerationIsRandom = enable;
}

HunterConfig& Config::hunter() const
{
    return mImpl->hunter;
}

ServerConfig& Config::server() const
{
    return mImpl->server;
}

LogConfig& Config::log() const
{
    return mImpl->log;
}

HDWalletConfig& Config::hdWallet() const
{
    return mImpl->hdWallet;
}

std::string Config::jsonStr() const
{
    return mImpl->configJson.dump();
}

uint32_t Config::statusCallbackPeriodMs() const
{
    return mImpl->statusCallbackPeriodMs;
}

uint32_t Config::publicKeyCompressionTypeToCheck() const
{
    return mImpl->publicKeyCompressionTypeToCheck;
}

uint32_t Config::pointsPerThread() const
{
    return mImpl->pointsPerThread;
}

uint32_t Config::blockSize() const
{
    return mImpl->blockSize;
}

uint32_t Config::gridSize() const
{
    return mImpl->gridSize;
}
