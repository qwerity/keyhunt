#include "config.h"

#include <nlohmann/json.hpp>

#include <filesystem>
#include <fstream>
#include <boost/log/trivial.hpp>

Config::Config()
{
    load();
}

void Config::load(const std::string &configJsonFileName)
{
    if(!std::filesystem::exists(configJsonFileName))
    {
        BOOST_LOG_TRIVIAL(warning) << "Config file config.json is not present in binary directory, using default values";
        print();

        return;
    }

    std::ifstream configFile(configJsonFileName);
    nlohmann::json configJson;
    configFile >> configJson;

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
            ripemd160TargetsFilePaths.push_back(target);
        }
    }

    // Validate and load other fields
    if (configJson.contains("cudaDeviceId") && configJson["cudaDeviceId"].is_number_integer())
    {
        cudaDeviceId = configJson["cudaDeviceId"];
    }
    else
    {
        BOOST_LOG_TRIVIAL(warning) << "Invalid configuration: 'cudaDeviceId' must be an integer, using default value: " << cudaDeviceId;
    }

    if (configJson.contains("pointsPerThread") && configJson["pointsPerThread"].is_number_unsigned())
    {
        pointsPerThread = configJson["pointsPerThread"];
    }
    else
    {
        BOOST_LOG_TRIVIAL(warning) << "Invalid configuration: 'cudaDeviceId' must be an integer, using default value: " << pointsPerThread;
    }

    if (configJson.contains("keysNumberToGenerate") && configJson["keysNumberToGenerate"].is_number_unsigned())
    {
        keysNumberToGenerate = configJson["keysNumberToGenerate"];
    }
    else
    {
        BOOST_LOG_TRIVIAL(warning) << "Invalid configuration: 'cudaDeviceId' must be an integer, using default value: " << keysNumberToGenerate;
    }

    if (configJson.contains("privateX") && configJson["privateX"].is_number_integer())
    {
        privateXPart = configJson["privateX"];
    }
    else
    {
        BOOST_LOG_TRIVIAL(warning) << "Invalid configuration: 'cudaDeviceId' must be an integer, using default value: " << privateXPart;
    }

    if (configJson.contains("publicKeyCompressionTypeToCheck") && configJson["publicKeyCompressionTypeToCheck"].is_number_integer())
    {
        if (int compressionType = configJson["publicKeyCompressionTypeToCheck"]; compressionType >= 0 && compressionType <= 2)
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
        BOOST_LOG_TRIVIAL(warning) << "Invalid configuration: 'publicKeyCompressionTypeToCheck' must be an integer, using default value: " << publicKeyCompressionTypeToCheck;
    }

    if (configJson.contains("statusCallbackPeriodMs") && configJson["statusCallbackPeriodMs"].is_number_unsigned())
    {
        statusCallbackPeriodMs = configJson["statusCallbackPeriodMs"];
    }
    else
    {
        BOOST_LOG_TRIVIAL(warning) << "Invalid configuration: 'statusCallbackPeriodMs' must be an unsigned integer, using default value: " << statusCallbackPeriodMs;
    }

    // Validate the JSON structure
    if (configJson.contains("log") && configJson["log"].is_object())
    {
        const auto& logConfig = configJson["log"];

        // Check for required fields and their types
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
}

void Config::print()
{

}
