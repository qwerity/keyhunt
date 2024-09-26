#include "config.h"
#include "utils.h"

#include <filesystem>
#include <fstream>
#include <boost/log/trivial.hpp>

struct Config::Impl
{
    nlohmann::json configJson;
    std::string jsonConfigFilepath;
    bool loaded{false};

    HunterConfig hunter;
    ServerConfig server;
    LogConfig log;

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

        if (logConfig.contains("file") && logConfig["file"].is_string() && !logConfig["file"].empty())
        {
            log.logFilePath = logConfig["file"];
        }

        if (logConfig.contains("severity") && logConfig["severity"].is_number())
        {
            uint32_t logSeverity = logConfig["severity"];
            if (logSeverity > 5) // fatal
            {
                logSeverity = 5;
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
            server.url = serverConfig["url"];
        }

        if (serverConfig.contains("authorisationHeader") && serverConfig["authorisationHeader"].is_string() && !serverConfig["authorisationHeader"].empty())
        {
            server.authorisationHeader = serverConfig["authorisationHeader"];
        }

        if (serverConfig.contains("port") && serverConfig["port"].is_string() && !serverConfig["port"].empty())
        {
            server.port = serverConfig["port"];
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

        // Validate that "targets" is an array and has at least one element
        if (!configJson.contains("targets") || !configJson["targets"].is_array() || configJson["targets"].empty())
        {
            BOOST_LOG_TRIVIAL(warning) << "Targets are not set, running without them";
        }
        else
        {
            for (const auto &target: configJson["targets"])
            {
                if (!target.is_string())
                {
                    BOOST_LOG_TRIVIAL(warning) << "Invalid configuration: each target must be a string (file path), ignored targets list: " << target;
                }
                hunter.ripemd160TargetsFilePaths.push_back(target);
            }
        }

        // Validate and load other fields
        if (configJson.contains("cudaDeviceId") && configJson["cudaDeviceId"].is_number_integer())
        {
            hunter.cudaDeviceId = configJson["cudaDeviceId"];
        }
        else
        {
            BOOST_LOG_TRIVIAL(warning) << "Invalid configuration: 'cudaDeviceId' must be an integer, using default value: " << hunter.cudaDeviceId;
        }

        if (configJson.contains("pointsPerThread") && configJson["pointsPerThread"].is_number_unsigned())
        {
            hunter.pointsPerThread = configJson["pointsPerThread"];
        }
        else
        {
            BOOST_LOG_TRIVIAL(warning) << "Invalid configuration: 'pointsPerThread' must be an integer, using default value: " << hunter.pointsPerThread;
        }

        if (configJson.contains("keysNumberToGenerate") && configJson["keysNumberToGenerate"].is_number_unsigned())
        {
            hunter.keysNumberToGenerate = configJson["keysNumberToGenerate"];
        }
        else
        {
            BOOST_LOG_TRIVIAL(warning) << "Invalid configuration: 'keysNumberToGenerate' must be an integer, using default value: " << hunter.keysNumberToGenerate;
        }

        if (configJson.contains("privateXPart") && configJson["privateXPart"].is_number_integer())
        {
            hunter.privateXPart = configJson["privateXPart"];
        }
        else
        {
            BOOST_LOG_TRIVIAL(warning) << "Invalid configuration: 'privateXPart' must be an integer, using default value: " << hunter.privateXPart;
        }

        if (configJson.contains("privateYOffset") && configJson["privateYOffset"].is_number_integer())
        {
            hunter.privateYOffset = configJson["privateYOffset"];
        }

        if (configJson.contains("publicKeyCompressionTypeToCheck") && configJson["publicKeyCompressionTypeToCheck"].is_number_integer())
        {
            if (int compressionType = configJson["publicKeyCompressionTypeToCheck"]; compressionType >= 0 && compressionType <= 2)
            {
                hunter.publicKeyCompressionTypeToCheck = compressionType;
            }
            else
            {
                BOOST_LOG_TRIVIAL(warning) << "Invalid configuration: 'publicKeyCompressionTypeToCheck' must be 0 (UNCOMPRESSED), 1 (COMPRESSED), or 2 (BOTH), using default value: " << hunter.publicKeyCompressionTypeToCheck;
            }
        }
        else
        {
            BOOST_LOG_TRIVIAL(warning) << "Invalid configuration: 'publicKeyCompressionTypeToCheck' must be an integer, using default value: " << hunter.publicKeyCompressionTypeToCheck;
        }

        if (configJson.contains("statusCallbackPeriodMs") && configJson["statusCallbackPeriodMs"].is_number_unsigned())
        {
            hunter.statusCallbackPeriodMs = configJson["statusCallbackPeriodMs"];
        }
        else
        {
            BOOST_LOG_TRIVIAL(warning) << "Invalid configuration: 'statusCallbackPeriodMs' must be an unsigned integer, using default value: " << hunter.statusCallbackPeriodMs;
        }

        loadLogConfig();
        loadServerConfig();

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

HunterConfig&& Config::hunter()
{
    return std::forward<HunterConfig>(mImpl->hunter);
}

ServerConfig&& Config::server()
{
    return std::forward<ServerConfig>(mImpl->server);
}

LogConfig&& Config::log()
{
    return std::forward<LogConfig>(mImpl->log);
}

bool Config::setPrivateKeyXPart(const uint32_t xPart) const
{
    return mImpl->setValue("privateXPart", xPart);
}

bool Config::calculationIteration(const uint32_t iteration) const
{
    return mImpl->setValue("calculationIteration", iteration);
}
