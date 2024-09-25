#include "utils.h"
#include "common.h"
#include "secp256k1.h"
#include "config.h"

#include "cuda/defines.cuh"

#include <cstdio>
#include <string>
#include <fstream>
#include <utility>
#include <vector>
#include <algorithm>
#include <iomanip>
#include <format>

#include <boost/regex.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/utility/setup.hpp>
#include <boost/iostreams/device/mapped_file.hpp>

#ifdef _WIN32
    #include<windows.h>
#else
    #include<unistd.h>
    #include<sys/stat.h>
    #include<sys/time.h>
#endif

namespace utils
{
    uint64_t getSystemTime()
    {
#ifdef _WIN32
        return GetTickCount64();
#else
        timeval t{};
        gettimeofday(&t, nullptr);
        return static_cast<uint64_t>(t.tv_sec) * 1000 + t.tv_usec / 1000;
#endif
    }

    Timer::Timer()
    {
        _startTime = 0;
    }

    void Timer::start()
    {
        _startTime = getSystemTime();
    }

    uint64_t Timer::getTime() const
    {
        return getSystemTime() - _startTime;
    }

    uint32_t parseUInt32(std::string s)
    {
        return static_cast<uint32_t>(parseUInt64(std::move(s)));
    }

    uint64_t parseUInt64(std::string s)
    {
        uint64_t val = 0;
        bool isHex = false;
        if (s[0] == '0' && s[1] == 'x')
        {
            isHex = true;
            s = s.substr(2);
        }
        if (s[s.length() - 1] == 'h')
        {
            isHex = true;
            s = s.substr(0, s.length() - 1);
        }

        if (isHex)
        {
            if (std::sscanf(s.c_str(), "%I64u", &val) != 1)
            {
                throw std::string("Expected an integer");
            }
        }
        else
        {
            if (std::sscanf(s.c_str(), "%I64u", &val) != 1)
            {
                throw std::string("Expected an integer");
            }
        }
        return val;
    }

    bool isHex(const std::string &s)
    {
        return std::ranges::all_of(s, [](const char c) { return std::isxdigit(c); });
    }

    std::string formatSeconds(const uint32_t seconds)
    {
        const uint32_t days = seconds / 86400;
        const uint32_t hours = (seconds % 86400) / 3600;
        const uint32_t minutes = (seconds % 3600) / 60;
        const uint32_t sec = seconds % 60;

        if (days > 0)
        {
            return std::format("{}:{:02}:{:02}:{:02}", days, hours, minutes, sec);
        }

        return std::format("{:02}:{:02}:{:02}", hours, minutes, sec);
    }

    long getFileSize(const std::string &fileName)
    {
        FILE *fp = fopen(fileName.c_str(), "rb");
        if (fp == nullptr)
        {
            return -1;
        }
        fseek(fp, 0, SEEK_END);
        long pos = ftell(fp);
        fclose(fp);
        return pos;
    }

    bool appendToFile(const std::string &fileName, const std::string &s)
    {
        std::ofstream outFile;
        bool newline = false;
        if (getFileSize(fileName) > 0)
        {
            newline = true;
        }
        outFile.open(fileName.c_str(), std::ios::app);
        if (!outFile.is_open())
        {
            return false;
        }
        // Add newline following previous line
        if (newline)
        {
            outFile << std::endl;
        }
        outFile << s;
        return true;
    }

    std::string convertToHexString(const uint32_t* arr, const uint32_t size)
    {
        std::stringstream ss;
        // Iterate through each byte of the array
        for (uint32_t i = 0; i < size; ++i)
        {
            const auto *bytePtr = reinterpret_cast<const uint8_t *>(&arr[i]);
            for (std::size_t j = 0; j < sizeof(uint32_t); ++j)
            {
                ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(bytePtr[j]);
            }
        }
        return ss.str();
    }

    void initLogging([[maybe_unused]] const LogConfig& log)
    {
        if (log.type == LogConfig::LogType::console)
        {
            boost::log::add_console_log(std::cerr, boost::log::keywords::auto_flush = true);
            // boost::log::add_console_log(std::cerr, boost::log::keywords::format = "[%TimeStamp%] [%ThreadID%]: %Message%");
        }
        else
        {
            // boost::log::add_file_log(log.logFilePath, boost::log::keywords::auto_flush = true);
            // boost::log::add_file_log(log.logFilePath, boost::log::keywords::format = "[%TimeStamp%] [%ThreadID%]: %Message%");
        }

        // Add attributes like timestamp and thread id
        // boost::log::add_common_attributes();

         boost::log::core::get()->set_filter(boost::log::trivial::severity >= static_cast<boost::log::trivial::severity_level>(log.severity));
    }

    std::vector<secp256k1::uint256> generateRandomPrivateKeys(const uint32_t keysNumberToGenerate)
    {
        std::vector<secp256k1::uint256> privateKeys;

        constexpr uint32_t testKey[8]{0x3d52d30a, 0x720debe8, 0x4fc939bb, 0xf806a1de, 0x3cee918e, 0x99fafd29, 0xe9a2e3fa, 0x2c478ee7};
        privateKeys.emplace_back(testKey, secp256k1::uint256::BigEndian);
        privateKeys.emplace_back(std::string("0100000000000000000000000000000000000000000000000000000000000000"));
        privateKeys.emplace_back(std::string("0100000000000000000000000000000000000000000000000000000000000200"));
        privateKeys.emplace_back(std::string("d7ae6ac85e67dfe75b3a42c6453abed4bb34a26d2988481fc134b2d845976a56"));
        privateKeys.emplace_back(std::string{"f71485d0bff28cf3a9f1b6c2b65b03729f42f9818fb497c6fae7268bb124f263"});

        std::generate_n(std::back_inserter(privateKeys), keysNumberToGenerate, secp256k1::generatePrivateKey);
        return privateKeys;
    }

    hash160 toHash160(const std::string& hexString)
    {
        hash160 hash;
        if (hexString.length() != sizeof(hash160) * 2)
        {
            fprintf(stderr,  "RIPEMD-160 hex string must be exactly 40 characters long!\n");
            return hash;
        }

        for (int i = 0; i < 5; ++i)
        {
            std::stringstream ss;
            ss << std::hex << hexString.substr(i * 8, 8);
            ss >> hash.h[i];
        }

        return hash;
    }

    // Function to convert 20 bytes (40 hex characters) to uint32_t[5]
    hash160 hexToHash160(const char *data)
    {
        hash160 hash;
        for (size_t i = 0; i < 5; ++i)
        {
            std::string hex_str(data + i * 8, 8);  // Create a string from 8 characters
            hash.h[i] = std::stoul(hex_str, nullptr, 16);
        }

        return hash;
    }

    bool readHash160HexStrFileToSet(const std::string& hash160TargetsFile, std::unordered_set<hash160> &hashSet)
    {
        try
        {
            Timer timer;
            boost::iostreams::mapped_file_source file;

            if (hash160TargetsFile.empty())
            {
                BOOST_LOG_TRIVIAL(error) << "Filename is empty: " << hash160TargetsFile;
                return false;
            }

            timer.start();

            file.open(hash160TargetsFile);
            if (!file.is_open())
            {
                BOOST_LOG_TRIVIAL(error) << "Unable to open " << hash160TargetsFile;
                return false;
            }

            const char *data = file.data();
            const size_t fileSize = file.size();
            constexpr size_t hash160StrSize = 2 * sizeof(hash160);  // Each chunk is 20 bytes (without newlines)

            // reserving memory to avoid memory allocation during insertion
            hashSet.reserve(hashSet.size() + fileSize / (hash160StrSize + 1)); // +1 is new line

            BOOST_LOG_TRIVIAL(trace) << std::format("Loading RipeMD-160 hashes from: {}, fileSize: {:.02}Mb", hash160TargetsFile, static_cast<double>(fileSize) / MB);

            uint64_t insertedTargetsCount{0};
            // Read the file in fixed-fileSize chunks of 20 bytes
            for (size_t i = 0; i < fileSize;)
            {
                // Skip any newlines or whitespace characters
                while (i < fileSize && (data[i] == '\n' || data[i] == '\r' || data[i] == ' '))
                {
                    ++i;
                }

                if (i + hash160StrSize <= fileSize)
                {
                    // Convert the 20-byte chunk into an array of uint32_t[5]
                    hashSet.insert(utils::hexToHash160(data + i));
                    ++insertedTargetsCount;

                    // Move to the next chunk
                    i += hash160StrSize;
                }
            }

            file.close();

            const auto fileReadTimeS = static_cast<float>(timer.getTime()) / 1000;
            BOOST_LOG_TRIVIAL(trace) << std::format(std::locale("en_US.UTF-8"), "Read {:L} unique hashes, from: {:L}, ({:.03}s | {:02}Mb)",
                                                    hashSet.size(), insertedTargetsCount,
                                                    fileReadTimeS, static_cast<double>(sizeof(hash160) * insertedTargetsCount) / MB);
        }
        catch(const std::exception& e)
        {
            BOOST_LOG_TRIVIAL(trace) << e.what();
            return false;
        }

        return true;
    }

    bool writeHash160SetToBinaryFile(const std::string& filename, const std::unordered_set<hash160>& hashSet)
    {
        try
        {
            Timer timer;

            std::ofstream ofs(filename, std::ios::binary | std::ios::trunc);
            if (!ofs.is_open())
            {
                std::cerr << "Error opening file for writing: " << filename << std::endl;
                return false;
            }

            timer.start();

            for (const auto &h: hashSet)
            {
                ofs.write(reinterpret_cast<const char *>(&h), sizeof(hash160));
            }

            const auto fileWriteTimeS = static_cast<float>(timer.getTime()) / 1000;
            BOOST_LOG_TRIVIAL(trace) << std::format(std::locale("en_US.UTF-8"), "Written {:L} hashes to {} as a binary, in {:.03}s | {:.02}Mb",
                                                    hashSet.size(), filename, fileWriteTimeS, static_cast<double>(ofs.tellp()) / MB);

            ofs.close();
        }
        catch (const std::exception& e)
        {
            BOOST_LOG_TRIVIAL(error) << e.what();
            return false;
        }

        return true;
    }

    bool readSetFromHash160BinaryFile(const std::string& filename, std::unordered_set<hash160>& hashSet)
    {
        try
        {
            Timer timer;

            boost::iostreams::mapped_file_source file;
            file.open(filename);

            if (!file.is_open())
            {
                BOOST_LOG_TRIVIAL(error) << "Error opening file: " << filename;
                return false;
            }

            timer.start();

            // Pointer to the start of the file data
            const char *data = file.data();
            size_t fileSize = file.size();

            // Make sure the file size is a multiple of sizeof(hash160)
            if (fileSize % sizeof(hash160) != 0)
            {
                BOOST_LOG_TRIVIAL(error) << "File size is not aligned with hash160 structure!";
                return false;
            }

            const size_t numEntries = fileSize / sizeof(hash160);

            BOOST_LOG_TRIVIAL(trace) << std::format("Loading RipeMD-160 hashes from: {}, size: {:.02}Mb", filename, static_cast<double>(fileSize) / MB);

            hashSet.reserve(numEntries);
            for (size_t i = 0; i < numEntries; ++i)
            {
                hash160 h;
                std::memcpy(&h, data + i * sizeof(hash160), sizeof(hash160));
                hashSet.insert(h);
            }

            file.close();

            const auto fileReadTimeS = static_cast<float>(timer.getTime()) / 1000;
            BOOST_LOG_TRIVIAL(info) << std::format(std::locale("en_US.UTF-8"), "Read {:L} hashes from {} binary file: {:.03}s", hashSet.size(), filename, fileReadTimeS);
        }
        catch (const std::exception& e)
        {
            BOOST_LOG_TRIVIAL(error) << e.what();
            return false;
        }

        return true;
    }

    bool validateUUID(const std::string& uuid)
    {
        const boost::regex uuid_regex(R"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})");
        return boost::regex_match(uuid, uuid_regex);
    }

    bool validateUrl(const std::string& url)
    {
        // Basic check for host and port format
        const boost::regex url_regex(R"((http://|https://)?([a-zA-Z0-9\.-]+)(:[0-9]+)?)");
        return boost::regex_match(url, url_regex);
    }
}

